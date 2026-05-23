package core

import (
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

type EpPing struct {
	TimeSent time.Time
	LinkID   state.LinkID
}

func (n *Nylon) Probe(node state.NodeId, ep *state.NylonEndpoint, waitErr bool) error {
	link := n.RouterState.GetLinkForEndpoint(node, ep)
	if link == nil {
		link = n.RouterState.AddLink(node, ep)
	}
	return n.ProbeLink(link.ID, waitErr)
}

func (n *Nylon) ProbeLink(linkID state.LinkID, waitErr bool) error {
	link := n.RouterState.GetLink(linkID)
	if link == nil {
		return nil
	}
	ep := link.Endpoint.AsNylonEndpoint()
	if ep == nil {
		return nil
	}
	token := rand.Uint64()
	ping := &protocol.Ny{
		Type: &protocol.Ny_ProbeOp{
			ProbeOp: &protocol.Ny_Probe{
				Token:         token,
				ResponseToken: nil,
			},
		},
	}
	peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(link.Peer).PubKey))
	nep, err := ep.GetWgEndpoint(n.Device)
	if err != nil {
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	var sendErr error
	go func() {
		defer wg.Done()
		sendErr = n.SendNylon(ping, nep, peer)
		if sendErr != nil {
			return
		}

		n.PingBuf.Set(token, EpPing{
			TimeSent: time.Now(),
			LinkID:   linkID,
		}, ttlcache.DefaultTTL)
	}()

	if waitErr {
		wg.Wait()
		return sendErr
	}
	return nil
}

func (n *Nylon) ResolveIncomingLink(peer state.NodeId, endpoint conn.Endpoint) (state.LinkID, bool) {
	if endpoint == nil {
		return state.LinkID{}, false
	}
	for _, link := range n.RouterState.GetPeerLinks(peer) {
		nep := link.Endpoint.AsNylonEndpoint()
		if nep == nil || nep.DynEP == nil {
			continue
		}
		if nep.WgEndpoint != nil && nep.WgEndpoint.DstIPPort() == endpoint.DstIPPort() {
			return link.ID, true
		}
		if ap, err := nep.DynEP.Get(); err == nil && ap == endpoint.DstIPPort() {
			return link.ID, true
		}
	}
	return state.LinkID{}, false
}

func handleProbe(n *Nylon, pkt *protocol.Ny_Probe, endpoint conn.Endpoint, peer *device.Peer, node state.NodeId) {
	if pkt.ResponseToken == nil {
		// ping
		// build pong response
		res := pkt
		res.ResponseToken = new(rand.Uint64())

		// send pong
		err := n.SendNylon(&protocol.Ny{Type: &protocol.Ny_ProbeOp{ProbeOp: pkt}}, endpoint, peer)
		if err != nil {
			n.Log.Error("Failed to send nylon packet to node", "node", node, "error", err)
			return
		}

		n.Dispatch(func() error {
			handleProbePing(n, node, endpoint)
			return nil
		})
	} else {
		// pong
		n.Dispatch(func() error {
			handleProbePong(n, node, pkt.Token, endpoint)
			return nil
		})
	}
}

func handleProbePing(n *Nylon, node state.NodeId, wgEndpoint conn.Endpoint) {
	if node == n.LocalCfg.Id {
		return
	}
	if linkID, ok := n.ResolveIncomingLink(node, wgEndpoint); ok {
		link := n.RouterState.GetLink(linkID)
		dep := link.Endpoint.AsNylonEndpoint()
		dep.WgEndpoint = wgEndpoint
		if !dep.IsActive() {
			PushFullTable(n.RouterState, n, linkID)
		}
		dep.Renew()
		if n.DBG_log_probe {
			n.Log.Debug("probe from", "addr", wgEndpoint.DstToString(), "link", linkID.String())
		}
		return
	}
	// create a new link if we dont have a link
	if n.RouterState.GetNeighbour(node) != nil {
		newEp := state.NewEndpoint(state.NewDynamicEndpoint(wgEndpoint.DstIPPort().String()), true, wgEndpoint, &n.RouterTunables)
		newEp.Renew()
		link := n.RouterState.AddLink(node, newEp)
		// push route update to improve convergence time
		PushFullTable(n.RouterState, n, link.ID)
		return
	}
}

func handleProbePong(n *Nylon, node state.NodeId, token uint64, ep conn.Endpoint) {
	linkHealth, ok := n.PingBuf.GetAndDelete(token)
	if ok {
		health := linkHealth.Value()
		link := n.RouterState.GetLink(health.LinkID)
		if link != nil && link.Peer == node {
			dpLink := link.Endpoint.AsNylonEndpoint()
			latency := time.Since(health.TimeSent)
			if n.DBG_log_probe {
				n.Log.Debug("probe back", "peer", node, "link", link.ID.String(), "ping", latency)
			}
			dpLink.Renew()
			dpLink.UpdatePing(latency)
			dpLink.WgEndpoint = ep
			ComputeRoutes(n.RouterState, n)
			return
		}
	}
	n.Log.Warn("probe came back and couldn't find link", "from", ep.DstToString(), "node", node)
}

func (n *Nylon) probeLinks(active bool) error {
	// probe links
	for _, link := range n.RouterState.LinkList() {
		if link.Endpoint != nil && link.Endpoint.IsActive() == active {
			err := n.ProbeLink(link.ID, false)
			if err != nil {
				n.Log.Debug("probe failed", "err", err.Error())
			}
		}
	}
	return nil
}

func (n *Nylon) probeNew() error {
	// probe for new dp links
	for _, peer := range n.GetPeers(n.LocalCfg.Id) {
		if !n.IsRouter(peer) {
			continue
		}
		neigh := n.RouterState.GetNeighbour(peer)
		if neigh == nil {
			continue
		}
		cfg := n.GetRouter(peer)
		// assumption: we don't need to connect to the same endpoint again within the scope of the same node
		for _, ep := range cfg.Endpoints {
			ap, err := ep.Get()
			if err != nil {
				continue
			}
			idx := slices.IndexFunc(n.RouterState.GetPeerLinks(peer), func(link *state.Link) bool {
				lap, err := link.Endpoint.AsNylonEndpoint().DynEP.Get()
				if err != nil {
					return false
				}
				return !link.Endpoint.IsRemote() && lap == ap
			})
			if idx == -1 {
				// add the link to the neighbour
				dpl := state.NewEndpoint(ep, false, nil, &n.RouterTunables)
				link := n.RouterState.AddLink(peer, dpl)
				err := n.ProbeLink(link.ID, false)
				if err != nil {
					//n.Log.Debug("discovery probe failed", "err", err.Error())
				}
			}
		}
	}
	return nil
}
