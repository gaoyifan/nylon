package core

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/encodeous/nylon/state"
)

type ApplyResult string

const (
	ApplyNoop            ApplyResult = "noop"
	ApplyApplied         ApplyResult = "applied"
	ApplyRejected        ApplyResult = "rejected"
	ApplyRestartRequired ApplyResult = "restart_required"
)

func (n *Nylon) ApplyCentralConfig(cfg *state.CentralCfg) (ApplyResult, error) {
	err, next := cfg.Clone()
	if err != nil {
		return ApplyRejected, err
	}
	state.ExpandCentralConfig(next)
	if err := state.CentralConfigValidator(next); err != nil {
		return ApplyRejected, err
	}
	if !next.IsRouter(n.LocalCfg.Id) {
		return ApplyRestartRequired, errors.New("local node is not a router in the new central config")
	}
	if reflect.DeepEqual(n.CentralCfg, next) {
		return ApplyNoop, nil
	}

	if err := n.reconcileRouterState(next); err != nil {
		return ApplyRejected, err
	}
	n.reconcileAdvertisedPrefixes(next)
	n.CentralCfg = *next

	if err := n.SyncWireGuard(); err != nil {
		return ApplyRejected, err
	}
	if err := n.SyncSystemState(); err != nil {
		return ApplyRejected, err
	}
	ComputeRoutes(n.RouterState, n)

	return ApplyApplied, nil
}

func (n *Nylon) reconcileRouterState(next *state.CentralCfg) error {
	desired := make(map[state.NodeId]state.RouterCfg)
	for _, peer := range next.GetPeers(n.LocalCfg.Id) {
		if !next.IsRouter(peer) {
			continue
		}
		desired[peer] = next.GetRouter(peer)
	}

	neighs := make([]*state.Neighbour, 0, len(desired))
	nextLinks := make(map[state.LinkID]*state.Link)
	for _, neigh := range n.RouterState.Neighbours {
		cfg, ok := desired[neigh.Id]
		if !ok {
			// remove old neighbours
			for _, link := range n.RouterState.GetPeerLinks(neigh.Id) {
				delete(n.router.IO, link.ID)
			}
			continue
		}
		// configure existing neighbours
		reconcileConfiguredEndpoints(neigh, cfg.Endpoints, n.LocalCfg.NormalizedBinds(), &n.RouterTunables)
		for idx, ep := range neigh.Eps {
			link := n.RouterState.GetLinkForEndpoint(neigh.Id, ep)
			if link == nil {
				nep := ep.AsNylonEndpoint()
				localBind := nep.LocalBind
				if localBind == "" {
					localBind = state.DefaultLocalBindID
					nep.LocalBind = localBind
				}
				for _, bind := range n.LocalCfg.NormalizedBinds() {
					if bind.ID == localBind {
						nep.Bind = bind
						break
					}
				}
				link = &state.Link{
					ID:       state.LinkID{Peer: neigh.Id, LocalBind: localBind, RemoteEndpoint: nep.RemoteEndpointID(), Generation: nep.Generation},
					Peer:     neigh.Id,
					Endpoint: ep,
					Routes:   make(map[netip.Prefix]state.NeighRoute),
				}
				if idx == 0 {
					neigh.Routes = link.Routes
				}
			}
			nextLinks[link.ID] = link
		}
		neighs = append(neighs, neigh)
		delete(desired, neigh.Id)
	}

	// create new neighbours
	ids := make([]state.NodeId, 0, len(desired))
	for id := range desired {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		cfg := desired[id]
		stNeigh := &state.Neighbour{
			Id:     id,
			Routes: make(map[netip.Prefix]state.NeighRoute),
			Eps:    make([]state.Endpoint, 0, len(cfg.Endpoints)),
		}
		for _, bind := range n.LocalCfg.NormalizedBinds() {
			for _, ep := range cfg.Endpoints {
				nep := state.NewEndpoint(ep, false, nil, &n.RouterTunables)
				nep.LocalBind = bind.ID
				nep.Bind = bind
				stNeigh.Eps = append(stNeigh.Eps, nep)
				link := &state.Link{
					ID: state.LinkID{
						Peer:           id,
						LocalBind:      bind.ID,
						RemoteEndpoint: nep.RemoteEndpointID(),
					},
					Peer:     id,
					Endpoint: nep,
					Routes:   make(map[netip.Prefix]state.NeighRoute),
				}
				if len(stNeigh.Eps) == 1 {
					stNeigh.Routes = link.Routes
				}
				nextLinks[link.ID] = link
			}
		}
		neighs = append(neighs, stNeigh)
	}
	n.RouterState.Neighbours = neighs
	n.RouterState.Links = nextLinks

	// rebuild pubkey to peer's id mapping
	pubkeyMap := make(map[state.NyPublicKey]state.NodeId)
	for _, x := range next.Routers {
		pubkeyMap[x.PubKey] = x.Id
	}
	for _, x := range next.Clients {
		pubkeyMap[x.PubKey] = x.Id
	}
	n.PeerMap.Store(new(pubkeyMap))
	return nil
}

func reconcileConfiguredEndpoints(neigh *state.Neighbour, desired []*state.DynamicEndpoint, binds []state.LocalBind, t *state.RouterTunables) {
	desiredByValue := make(map[string]*state.DynamicEndpoint, len(desired))
	for _, ep := range desired {
		desiredByValue[ep.Value] = ep
	}

	eps := make([]state.Endpoint, 0, len(neigh.Eps)+len(desired))
	seen := make(map[state.LinkID]struct{}, len(desired)*len(binds))
	for _, ep := range neigh.Eps {
		nep := ep.AsNylonEndpoint()
		if ep.IsRemote() {
			eps = append(eps, ep)
			continue
		}
		// only keep if desired
		if _, ok := desiredByValue[nep.DynEP.Value]; ok {
			localBind := nep.LocalBind
			if localBind == "" {
				localBind = state.DefaultLocalBindID
				nep.LocalBind = localBind
			}
			for _, bind := range binds {
				if bind.ID == localBind {
					nep.Bind = bind
					break
				}
			}
			id := state.LinkID{Peer: neigh.Id, LocalBind: localBind, RemoteEndpoint: nep.RemoteEndpointID(), Generation: nep.Generation}
			eps = append(eps, ep)
			seen[id] = struct{}{}
		}
	}
	for _, bind := range binds {
		for _, ep := range desired {
			id := state.LinkID{Peer: neigh.Id, LocalBind: bind.ID, RemoteEndpoint: ep.ID}
			if id.RemoteEndpoint == "" {
				id.RemoteEndpoint = state.RemoteEndpointID(ep.Value)
			}
			if _, ok := seen[id]; ok {
				continue
			}
			nep := state.NewEndpoint(ep, false, nil, t)
			nep.LocalBind = bind.ID
			nep.Bind = bind
			eps = append(eps, nep)
		}
	}
	neigh.Eps = eps
}

func (n *Nylon) reconcileAdvertisedPrefixes(next *state.CentralCfg) {
	cur := n.GetRouter(n.LocalCfg.Id)
	nextRouter := next.GetRouter(n.LocalCfg.Id)

	currentLocal := make(map[netip.Prefix]state.PrefixHealthWrapper)
	for _, prefix := range cur.Prefixes {
		currentLocal[prefix.GetPrefix()] = prefix
	}
	desiredLocal := make(map[netip.Prefix]state.PrefixHealthWrapper)
	for _, prefix := range nextRouter.Prefixes {
		desiredLocal[prefix.GetPrefix()] = prefix
	}

	for prefix, adv := range n.RouterState.Advertised {
		if adv.NodeId != n.LocalCfg.Id {
			continue
		}
		if _, ok := desiredLocal[prefix]; !ok {
			if old, ok := currentLocal[prefix]; ok {
				old.Stop()
			}
			delete(n.RouterState.Advertised, prefix)
		}
	}

	for prefix, desired := range desiredLocal {
		if _, ok := currentLocal[prefix]; !ok {
			n.Log.Debug("starting prefix healthcheck", "prefix", prefix)
			desired.Start(n.Log, &n.RouterTunables)
		}
		n.RouterState.Advertised[prefix] = state.Advertisement{
			NodeId:   n.LocalCfg.Id,
			Expiry:   maxConfigTime,
			MetricFn: desired.GetMetric,
			ExpiryFn: func() {
				desired.Stop()
			},
		}
	}
}

func (n *Nylon) startAdvertisedPrefixHealth() {
	for _, ph := range n.GetNode(n.LocalCfg.Id).Prefixes {
		n.Log.Debug("starting prefix healthcheck", "prefix", ph.GetPrefix())
		ph.Start(n.Log, &n.RouterTunables)
	}
}

var maxConfigTime = time.Unix(1<<63-62135596801, 999999999)
