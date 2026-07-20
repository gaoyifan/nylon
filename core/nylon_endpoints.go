package core

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

// probeEpoch anchors the fallback probe timebase (see probe_clock_*.go for
// the primary probeNowNs implementations). The epoch is arbitrary: probes
// only ever compare timestamps from the same process, or combine timestamps
// from two processes in ways where the unknown offset cancels (see
// protocol.Ny_Probe).
var probeEpoch = time.Now()

func probeNowNsFallback() int64 {
	return int64(time.Since(probeEpoch))
}

// probeTimestampAllocator assigns strictly increasing transmit timestamps.
// Clock precision is not guaranteed to distinguish probes sent in rapid
// succession, but OriginTxTs is also used to associate replies with IPC
// probe futures, so duplicates would overwrite that association.
type probeTimestampAllocator struct {
	last atomic.Int64
}

func (a *probeTimestampAllocator) next(now int64) int64 {
	for {
		last := a.last.Load()
		next := max(now, last+1)
		if a.last.CompareAndSwap(last, next) {
			return next
		}
	}
}

var outgoingProbeTimestamps probeTimestampAllocator

func nextProbeTxNs() int64 {
	return outgoingProbeTimestamps.next(probeNowNs())
}

type EpPing struct {
	TimeSent  time.Time
	Peer      state.NodeId
	Endpoint  *state.NylonEndpoint
	Discovery bool
	Complete  func(protocol.EndpointProbeStatus, time.Duration)
}

func (n *Nylon) sendEndpointProbes(peer state.NodeId, timeout time.Duration) ([]Future[*protocol.EndpointProbeResult], error) {
	neigh := n.RouterState.GetNeighbour(peer)
	if neigh == nil {
		return nil, fmt.Errorf("peer %q is not a neighbour", peer)
	}
	eps := slices.Clone(neigh.Eps)
	slices.SortFunc(eps, func(a, b state.Endpoint) int {
		return cmp.Compare(a.AsNylonEndpoint().DynEP.Value, b.AsNylonEndpoint().DynEP.Value)
	})
	probes := make([]Future[*protocol.EndpointProbeResult], 0, len(eps))
	for _, ep := range eps {
		result, _ := n.sendEndpointProbe(neigh.Id, ep.AsNylonEndpoint(), timeout)
		probes = append(probes, result)
	}
	return probes, nil
}

func (n *Nylon) Probe(node state.NodeId, ep *state.NylonEndpoint) error {
	_, err := n.sendEndpointProbe(node, ep, 0)
	return err
}

// sendEndpointProbe sends a timestamped probe and returns a Future for the
// IPC-facing result. The echoed OriginTxTs identifies the Future while
// ReplyLinkId identifies the exact link for directional delay accounting.
func (n *Nylon) sendEndpointProbe(node state.NodeId, ep *state.NylonEndpoint, timeout time.Duration) (Future[*protocol.EndpointProbeResult], error) {
	return n.sendEndpointProbeWithDiscovery(node, ep, timeout, false)
}

func (n *Nylon) sendDiscoveryEndpointProbe(node state.NodeId, ep *state.NylonEndpoint, timeout time.Duration) (Future[*protocol.EndpointProbeResult], error) {
	return n.sendEndpointProbeWithDiscovery(node, ep, timeout, true)
}

func (n *Nylon) sendEndpointProbeWithDiscovery(node state.NodeId, ep *state.NylonEndpoint, timeout time.Duration, discovery bool) (Future[*protocol.EndpointProbeResult], error) {
	address := ep.DynEP.Value
	resolved := ""
	resultFuture, completeResult := NewFuture[*protocol.EndpointProbeResult]()
	completeEndpoint := func(status protocol.EndpointProbeStatus, latency time.Duration, err error) {
		result := &protocol.EndpointProbeResult{
			Address:   address,
			Status:    status,
			LatencyNs: int64(latency),
		}
		if resolved != "" {
			result.Resolved = new(resolved)
		}
		completeResult(result, err)
	}
	fail := func(status protocol.EndpointProbeStatus, err error) (Future[*protocol.EndpointProbeResult], error) {
		completeEndpoint(status, 0, err)
		return resultFuture, err
	}

	peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(node).PubKey))
	if peer == nil {
		return fail(protocol.EndpointProbeStatus_ENDPOINT_PROBE_SEND_ERROR, fmt.Errorf("wireguard peer %q is not configured", node))
	}
	nep, err := ep.GetWgEndpoint(n.Device)
	if err != nil {
		if errors.Is(err, conn.ErrFakeTCPNotEstablished) {
			return fail(protocol.EndpointProbeStatus_ENDPOINT_PROBE_SEND_ERROR, err)
		}
		return fail(protocol.EndpointProbeStatus_ENDPOINT_PROBE_RESOLVE_ERROR, err)
	}
	resolved = nep.DstIPPort().String()

	txTs := nextProbeTxNs()
	probe := &protocol.Ny_Probe{TxTs: txTs, LinkId: ep.LinkId, Discovery: discovery}
	if originTx, originRx, ok := ep.EchoInfo(txTs); ok {
		probe.OriginTxTs = &originTx
		probe.OriginRxTs = &originRx
	}
	ping := &protocol.Ny{Type: &protocol.Ny_ProbeOp{ProbeOp: probe}}

	// Register before sending so that an echo can never race registration, and
	// expire probes that have exceeded the directional-loss timeout.
	ep.RegisterProbe(txTs)
	ep.SweepProbes(txTs)

	probeKey := uint64(txTs)
	sentAt := time.Now()
	var timeoutTimer *time.Timer
	if timeout > 0 {
		timeoutTimer = time.AfterFunc(timeout, func() {
			n.PingBuf.Delete(probeKey)
			completeEndpoint(protocol.EndpointProbeStatus_ENDPOINT_PROBE_TIMEOUT, 0, nil)
		})
	}
	n.PingBuf.Set(probeKey, EpPing{
		TimeSent:  sentAt,
		Peer:      node,
		Endpoint:  ep,
		Discovery: discovery,
		Complete: func(status protocol.EndpointProbeStatus, latency time.Duration) {
			if timeoutTimer != nil {
				timeoutTimer.Stop()
			}
			completeEndpoint(status, latency, nil)
		},
	}, ttlcache.DefaultTTL)

	go func() {
		if err := n.SendNylon(ping, nep, peer); err != nil {
			// A local send failure is not packet loss.
			ep.CancelProbe(txTs)
			if timeoutTimer != nil {
				timeoutTimer.Stop()
			}
			n.PingBuf.Delete(probeKey)
			completeEndpoint(protocol.EndpointProbeStatus_ENDPOINT_PROBE_SEND_ERROR, 0, err)
		}
	}()

	return resultFuture, nil
}

func handleProbe(n *Nylon, pkt *protocol.Ny_Probe, endpoint conn.Endpoint, peer *device.Peer, node state.NodeId) {
	rxTs := probeNowNs()
	if pkt.TxTs == 0 {
		return // legacy or malformed probe, cannot be measured
	}
	if stdEndpoint, ok := endpoint.(*conn.StdNetEndpoint); ok && stdEndpoint.Transport() == conn.TransportFakeTCP {
		peers := n.fakeTCPPeers.Load()
		if pkt.Discovery || peers == nil {
			return
		}
		if _, ok := (*peers)[node]; !ok {
			return
		}
	}
	if !pkt.Reply {
		// ping: answer immediately in-dataplane, echoing the ping's
		// timestamps so the sender can compute its outbound relative
		// one-way delay and the hold-time-corrected RTT.
		origin := pkt.TxTs
		originRx := rxTs
		res := &protocol.Ny_Probe{
			Reply:       true,
			ReplyLinkId: pkt.LinkId,
			OriginTxTs:  &origin,
			OriginRxTs:  &originRx,
		}
		res.TxTs = nextProbeTxNs()

		err := n.SendNylon(&protocol.Ny{Type: &protocol.Ny_ProbeOp{ProbeOp: res}}, endpoint, peer)
		if err != nil {
			n.Log.Error("Failed to send nylon packet to node", "node", node, "error", err)
			return
		}

		n.Dispatch(func() error {
			handleProbePing(n, node, pkt, endpoint, rxTs)
			return nil
		})
	} else {
		n.Dispatch(func() error {
			handleProbePong(n, node, pkt, endpoint, rxTs)
			return nil
		})
	}
}

// observeProbe folds the timestamps of a received probe into the endpoint's
// delay filters.
func observeProbe(dep *state.NylonEndpoint, pkt *protocol.Ny_Probe, rxTs int64) {
	dep.ObserveInbound(pkt.TxTs, rxTs)
	if pkt.OriginTxTs != nil && pkt.OriginRxTs != nil {
		dep.ObserveEcho(*pkt.OriginTxTs, *pkt.OriginRxTs)
	}
}

func handleProbePing(n *Nylon, node state.NodeId, pkt *protocol.Ny_Probe, wgEndpoint conn.Endpoint, rxTs int64) {
	if node == n.LocalCfg.Id {
		return
	}
	neigh := n.RouterState.GetNeighbour(node)
	if neigh == nil {
		return
	}
	receivedTransport := conn.TransportUDP
	if stdEndpoint, ok := wgEndpoint.(*conn.StdNetEndpoint); ok {
		receivedTransport = stdEndpoint.Transport()
	}
	receivedInterface := ""
	receivedIfIndex := 0
	if indexed, ok := wgEndpoint.(interface{ SrcIfidx() int32 }); ok {
		receivedIfIndex = int(indexed.SrcIfidx())
	}
	if pkt.Discovery {
		if n.lanDiscovery == nil {
			return
		}
		iface, ok := n.lanDiscovery.socket.interfaces[receivedIfIndex]
		if !ok || !iface.contains(wgEndpoint.DstIPPort().Addr()) {
			return
		}
		receivedInterface = iface.name
	} else if receivedIfIndex != 0 {
		if iface, err := net.InterfaceByIndex(receivedIfIndex); err == nil {
			receivedInterface = iface.Name
		}
	}

	if receivedTransport == conn.TransportFakeTCP && receivedInterface == "" {
		return
	}
	receivedSource := wgEndpoint.SrcIP()
	var existing, fallback *state.NylonEndpoint
	for _, endpoint := range neigh.Eps {
		dep := endpoint.AsNylonEndpoint()
		ap, err := dep.DynEP.Get()
		if err != nil || ap != wgEndpoint.DstIPPort() || dep.Transport != receivedTransport {
			continue
		}
		if receivedTransport == conn.TransportFakeTCP {
			if dep.Bind.Interface != receivedInterface {
				continue
			}
			if dep.Bind.Source.IsValid() && dep.Bind.Source == receivedSource {
				existing = dep
				break
			}
			if !dep.Bind.Source.IsValid() && fallback == nil {
				fallback = dep
			}
			continue
		}
		if dep.IsRemote() && dep.Bind.Interface != "" && dep.Bind.Interface == receivedInterface {
			existing = dep
			break
		}
		if !pkt.Discovery && fallback == nil {
			fallback = dep
		}
	}
	if existing == nil {
		existing = fallback
	}
	if existing != nil {
		existing.WgEndpoint = wgEndpoint
		wasInactive := !existing.IsActive()
		existing.Renew()
		observeProbe(existing, pkt, rxTs)
		if wasInactive {
			ComputeRoutes(n.RouterState, n)
			n.UpdateNeighbour(node)
		}
		if n.DBG_log_probe {
			n.Log.Debug("probe from", "addr", wgEndpoint.DstIPPort().String())
		}
		return
	}

	newEp := state.NewEndpoint(state.NewDynamicEndpoint(wgEndpoint.DstIPPort().String()), true, wgEndpoint, &n.RouterTunables)
	newEp.Transport = receivedTransport
	if pkt.Discovery || receivedTransport == conn.TransportFakeTCP {
		newEp.Bind.Interface = receivedInterface
	}
	if receivedTransport == conn.TransportFakeTCP {
		newEp.Bind.Source = receivedSource
	}
	newEp.Renew()
	observeProbe(newEp, pkt, rxTs)
	neigh.Eps = append(neigh.Eps, newEp)
	// push route update to improve convergence time
	ComputeRoutes(n.RouterState, n)
	n.UpdateNeighbour(node)
}

func handleProbePong(n *Nylon, node state.NodeId, pkt *protocol.Ny_Probe, ep conn.Endpoint, rxTs int64) {
	var discoveryEndpoint *state.NylonEndpoint
	if pkt.OriginTxTs != nil {
		if linkHealth, ok := n.PingBuf.GetAndDelete(uint64(*pkt.OriginTxTs)); ok {
			health := linkHealth.Value()
			if health.Peer != "" && health.Peer != node {
				n.Log.Warn("probe came back from wrong peer", "expected", health.Peer, "actual", node)
			} else if health.Endpoint == nil || health.Endpoint.LinkId != pkt.ReplyLinkId {
				n.Log.Warn("probe reply did not match its recorded endpoint", "from", ep.DstToString(), "node", node, "linkId", pkt.ReplyLinkId)
			} else {
				if health.Discovery {
					discoveryEndpoint = health.Endpoint
				}
				health.Complete(protocol.EndpointProbeStatus_ENDPOINT_PROBE_REPLIED, time.Since(health.TimeSent))
			}
		}
	}

	neigh := n.RouterState.GetNeighbour(node)
	if neigh == nil {
		n.Log.Warn("probe reply from unknown neighbour", "from", ep.DstToString(), "node", node)
		return
	}
	if discoveryEndpoint != nil {
		promoteLANDiscoveryEndpoint(n, node, pkt, ep, discoveryEndpoint, rxTs)
		return
	}
	idx := slices.IndexFunc(neigh.Eps, func(link state.Endpoint) bool {
		nep := link.AsNylonEndpoint()
		return nep != nil && nep.LinkId == pkt.ReplyLinkId
	})
	if idx == -1 {
		n.Log.Warn("probe reply for unknown link", "from", ep.DstToString(), "node", node, "linkId", pkt.ReplyLinkId)
		return
	}
	dpLink := neigh.Eps[idx].AsNylonEndpoint()
	if n.DBG_log_probe {
		n.Log.Debug("probe back", "peer", node, "rtt", dpLink.FilteredPing())
	}
	dpLink.Renew()
	observeProbe(dpLink, pkt, rxTs)

	// Record the reply's current WireGuard endpoint on the endpoint that sent the probe.
	dpLink.WgEndpoint = ep

	// Probe pongs arrive frequently on multi-link meshes. Coalesce route
	// recomputation so delay samples can update without saturating dispatch.
	n.ScheduleRouteCompute(n.StarvationDelay)
}

// endpointFamilyUnreachable reports whether probing ep is pointless because
// the host has no route for the endpoint's address family (e.g. IPv6
// endpoints on an IPv4-only host). Endpoints with an explicit bind source are
// never skipped, since source-based policy routing may provide connectivity
// that a plain route lookup does not see.
func endpointFamilyUnreachable(ep *state.NylonEndpoint) bool {
	if ep.Bind.Source.IsValid() {
		return false
	}
	ap, err := ep.DynEP.Get()
	if err != nil {
		return false
	}
	return !familyReachable(ap.Addr())
}

func (n *Nylon) probeLinks(active bool) error {
	// probe links
	for _, neigh := range n.RouterState.Neighbours {
		for _, ep := range neigh.Eps {
			if ep.IsActive() == active {
				if endpointFamilyUnreachable(ep.AsNylonEndpoint()) {
					continue
				}
				err := n.Probe(neigh.Id, ep.AsNylonEndpoint())
				if err != nil {
					n.Log.Debug("probe failed", "err", err.Error())
				}
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
			if !familyReachable(ap.Addr()) {
				continue
			}
			idx := slices.IndexFunc(neigh.Eps, func(link state.Endpoint) bool {
				lap, err := link.AsNylonEndpoint().DynEP.Get()
				if err != nil {
					return false
				}
				return !link.IsRemote() && lap == ap
			})
			if idx == -1 {
				// add the link to the neighbour
				dpl := state.NewEndpoint(ep, false, nil, &n.RouterTunables)
				neigh.Eps = append(neigh.Eps, dpl)
				err := n.Probe(peer, dpl)
				if err != nil {
					//n.Log.Debug("discovery probe failed", "err", err.Error())
				}
			}
		}
	}
	return nil
}
