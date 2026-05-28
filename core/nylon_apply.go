package core

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/encodeous/nylon/state"
)

type linkTransportKey struct {
	LocalBind state.LocalBindID
	Remote    netip.AddrPort
}

func bindMatchesEndpointFamily(bind state.LocalBind, ep *state.DynamicEndpoint) bool {
	if ep == nil || !bind.Source.IsValid() {
		return true
	}
	ap, err := ep.Get()
	if err != nil {
		return true
	}
	return state.SameIPFamily(bind.Source, ap.Addr())
}

func transportKeyFor(localBind state.LocalBindID, ep *state.DynamicEndpoint) (linkTransportKey, bool) {
	if ep == nil {
		return linkTransportKey{}, false
	}
	ap, err := ep.Get()
	if err != nil {
		return linkTransportKey{}, false
	}
	return linkTransportKey{LocalBind: localBind, Remote: ap}, true
}

func findBind(binds []state.LocalBind, id state.LocalBindID) (state.LocalBind, bool) {
	for _, bind := range binds {
		if bind.ID == id {
			return bind, true
		}
	}
	return state.LocalBind{}, false
}

// newConfiguredEndpoint creates a local (non-remote) endpoint for ep bound to
// the given local bind.
func newConfiguredEndpoint(ep *state.DynamicEndpoint, bind state.LocalBind, t *state.RouterTunables) *state.NylonEndpoint {
	nep := state.NewEndpoint(ep.Clone(), false, nil, t)
	nep.LocalBind = bind.ID
	nep.Bind = bind
	return nep
}

// newPeerLink builds the routing link that carries nep towards peer.
func newPeerLink(peer state.NodeId, nep *state.NylonEndpoint) *state.Link {
	return &state.Link{
		ID:       state.LinkID{Peer: peer, LocalBind: nep.LocalBind, RemoteEndpoint: nep.RemoteEndpointID(), Generation: nep.Generation},
		Peer:     peer,
		Endpoint: nep,
		Routes:   make(map[netip.Prefix]state.NeighRoute),
	}
}

// eachBindEndpoint invokes fn for every (bind, endpoint) pair whose IP families
// match and whose (bind, resolved remote) transport tuple is seen for the first
// time, i.e. the deduplicated local-bind × remote-endpoint product.
func eachBindEndpoint(binds []state.LocalBind, eps []*state.DynamicEndpoint, fn func(state.LocalBind, *state.DynamicEndpoint)) {
	seenTransport := make(map[linkTransportKey]struct{}, len(eps)*len(binds))
	for _, bind := range binds {
		for _, ep := range eps {
			if !bindMatchesEndpointFamily(bind, ep) {
				continue
			}
			if key, ok := transportKeyFor(bind.ID, ep); ok {
				if _, exists := seenTransport[key]; exists {
					continue
				}
				seenTransport[key] = struct{}{}
			}
			fn(bind, ep)
		}
	}
}

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
				if nep.LocalBind == "" {
					nep.LocalBind = state.DefaultLocalBindID
				}
				if bind, ok := findBind(n.LocalCfg.NormalizedBinds(), nep.LocalBind); ok {
					if nep.Bind != bind {
						nep.WgEndpoint = nil
					}
					nep.Bind = bind
				}
				link = newPeerLink(neigh.Id, nep)
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
		eachBindEndpoint(n.LocalCfg.NormalizedBinds(), cfg.Endpoints, func(bind state.LocalBind, ep *state.DynamicEndpoint) {
			nep := newConfiguredEndpoint(ep, bind, &n.RouterTunables)
			stNeigh.Eps = append(stNeigh.Eps, nep)
			link := newPeerLink(id, nep)
			if len(stNeigh.Eps) == 1 {
				stNeigh.Routes = link.Routes
			}
			nextLinks[link.ID] = link
		})
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
	seenTransport := make(map[linkTransportKey]struct{}, len(desired)*len(binds))
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
			if bind, ok := findBind(binds, localBind); ok {
				if nep.Bind != bind {
					nep.WgEndpoint = nil
				}
				nep.Bind = bind
			}
			if !bindMatchesEndpointFamily(nep.Bind, nep.DynEP) {
				continue
			}
			id := state.LinkID{Peer: neigh.Id, LocalBind: localBind, RemoteEndpoint: nep.RemoteEndpointID(), Generation: nep.Generation}
			if key, ok := transportKeyFor(localBind, nep.DynEP); ok {
				if _, exists := seenTransport[key]; exists {
					continue
				}
				seenTransport[key] = struct{}{}
			}
			eps = append(eps, ep)
			seen[id] = struct{}{}
		}
	}
	for _, bind := range binds {
		for _, ep := range desired {
			if !bindMatchesEndpointFamily(bind, ep) {
				continue
			}
			id := state.LinkID{Peer: neigh.Id, LocalBind: bind.ID, RemoteEndpoint: ep.ID}
			if id.RemoteEndpoint == "" {
				id.RemoteEndpoint = state.RemoteEndpointID(ep.Value)
			}
			if _, ok := seen[id]; ok {
				continue
			}
			if key, ok := transportKeyFor(bind.ID, ep); ok {
				if _, exists := seenTransport[key]; exists {
					continue
				}
				seenTransport[key] = struct{}{}
			}
			eps = append(eps, newConfiguredEndpoint(ep, bind, t))
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
