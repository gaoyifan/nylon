package core

import (
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/state"
)

type testConnEndpoint struct {
	dst      netip.AddrPort
	src      netip.Addr
	srcIfidx int32
}

func (e testConnEndpoint) ClearSrc() {}

func (e testConnEndpoint) SrcToString() string {
	return e.src.String()
}

func (e testConnEndpoint) DstToString() string {
	return e.dst.String()
}

func (e testConnEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

func (e testConnEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e testConnEndpoint) SrcIP() netip.Addr {
	return e.src
}

func (e testConnEndpoint) DstIPPort() netip.AddrPort {
	return e.dst
}

func (e testConnEndpoint) SrcIfidx() int32 {
	return e.srcIfidx
}

func TestResolveIncomingLinkUsesLocalBind(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	remote := netip.MustParseAddrPort("203.0.113.10:57175")
	sourceA := netip.MustParseAddr("10.0.0.1")
	sourceB := netip.MustParseAddr("10.0.0.2")

	n := &Nylon{
		RouterTunables: tunables,
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Links:          make(map[state.LinkID]*state.Link),
			Neighbours:     []*state.Neighbour{{Id: "peer", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		},
	}
	for _, bind := range []state.LocalBind{
		{ID: "bind-a", Source: sourceA},
		{ID: "bind-b", Source: sourceB},
	} {
		dyn := state.NewDynamicEndpoint(remote.String())
		dyn.ID = "shared-remote"
		ep := state.NewEndpoint(dyn, false, nil, &tunables)
		ep.LocalBind = bind.ID
		ep.Bind = bind
		n.RouterState.AddLink("peer", ep)
	}

	linkID, ok := n.ResolveIncomingLink("peer", testConnEndpoint{dst: remote, src: sourceB})
	if !ok {
		t.Fatal("expected incoming endpoint to resolve to a link")
	}
	if linkID.LocalBind != "bind-b" {
		t.Fatalf("expected bind-b link, got %s", linkID.String())
	}
}

func TestRotateLinkGenerationKeepsEndpointIdentity(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	oldAP := netip.MustParseAddrPort("203.0.113.10:57175")
	newAP := netip.MustParseAddrPort("203.0.113.20:57175")
	dyn := state.NewDynamicEndpoint("router.example.com:57175")
	dyn.ID = "router-primary"
	dyn.SetResolved(newAP)
	ep := state.NewEndpoint(dyn, false, nil, &tunables)
	ep.LocalBind = "bind-a"
	ep.Bind = state.LocalBind{ID: "bind-a", Source: netip.MustParseAddr("10.0.0.1")}

	n := &Nylon{
		RouterTunables: tunables,
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Links:          make(map[state.LinkID]*state.Link),
			Neighbours:     []*state.Neighbour{{Id: "peer", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		},
	}
	link := n.RouterState.AddLink("peer", ep)

	n.rotateLinkGeneration(link.ID, oldAP, dyn.Clone())

	oldLink := n.RouterState.GetLink(link.ID)
	if oldLink == nil {
		t.Fatal("expected old generation to remain")
	}
	oldResolved, err := oldLink.Endpoint.AsNylonEndpoint().DynEP.Get()
	if err != nil || oldResolved != oldAP {
		t.Fatalf("expected old link to keep %s, got %s err=%v", oldAP, oldResolved, err)
	}

	nextID := link.ID
	nextID.Generation++
	newLink := n.RouterState.GetLink(nextID)
	if newLink == nil {
		t.Fatal("expected new generation link")
	}
	newResolved, err := newLink.Endpoint.AsNylonEndpoint().DynEP.Get()
	if err != nil || newResolved != newAP {
		t.Fatalf("expected new link to use %s, got %s err=%v", newAP, newResolved, err)
	}
	if newLink.ID.RemoteEndpoint != link.ID.RemoteEndpoint || newLink.ID.LocalBind != link.ID.LocalBind {
		t.Fatalf("expected identity to be preserved, old=%s new=%s", link.ID.String(), newLink.ID.String())
	}
}

func TestProbePingFromNonNeighbourDoesNotCreateInvalidLink(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	n := &Nylon{
		RouterTunables: tunables,
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Links:          make(map[state.LinkID]*state.Link),
		},
	}

	handleProbePing(n, "unknown-peer", testConnEndpoint{
		dst: netip.MustParseAddrPort("203.0.113.10:57175"),
		src: netip.MustParseAddr("10.0.0.1"),
	})

	if links := n.RouterState.GetPeerLinks("unknown-peer"); len(links) != 0 {
		t.Fatalf("expected no learned links for non-neighbour peer, got %d", len(links))
	}
}

func TestReconcileConfiguredEndpointsSkipsDuplicateTransportTuple(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	remote := netip.MustParseAddrPort("203.0.113.10:57175")
	first := state.NewDynamicEndpoint("router-a.example.com:57175")
	first.ID = "first"
	first.SetResolved(remote)
	second := state.NewDynamicEndpoint("router-b.example.com:57175")
	second.ID = "second"
	second.SetResolved(remote)

	neigh := &state.Neighbour{
		Id:     "peer",
		Routes: make(map[netip.Prefix]state.NeighRoute),
	}
	reconcileConfiguredEndpoints(neigh, []*state.DynamicEndpoint{first, second}, []state.LocalBind{{ID: "wan"}}, &tunables)

	if len(neigh.Eps) != 1 {
		t.Fatalf("expected duplicate transport tuple to be skipped, got %d endpoints", len(neigh.Eps))
	}
}

func TestProbeNewDiscoversMissingBindSpecificLink(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	remote := netip.MustParseAddrPort("203.0.113.10:57175")
	dyn := state.NewDynamicEndpoint("router.example.com:57175")
	dyn.ID = "router"
	dyn.SetResolved(remote)

	existing := state.NewEndpoint(dyn.Clone(), false, nil, &tunables)
	existing.LocalBind = "wan-a"
	existing.Bind = state.LocalBind{ID: "wan-a", Source: netip.MustParseAddr("10.0.0.1")}

	n := &Nylon{
		RouterTunables: tunables,
		ConfigState: state.ConfigState{
			LocalCfg: state.LocalCfg{
				Id: "local",
				Binds: []state.LocalBind{
					{ID: "wan-a", Source: netip.MustParseAddr("10.0.0.1")},
					{ID: "wan-b", Source: netip.MustParseAddr("10.0.0.2")},
				},
			},
			CentralCfg: state.CentralCfg{
				Routers: []state.RouterCfg{
					{NodeCfg: state.NodeCfg{Id: "local"}},
					{NodeCfg: state.NodeCfg{Id: "peer"}, Endpoints: []*state.DynamicEndpoint{dyn}},
				},
				Graph: []string{"local, peer"},
			},
		},
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Links:          make(map[state.LinkID]*state.Link),
			Neighbours:     []*state.Neighbour{{Id: "peer", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		},
	}
	n.RouterState.AddLink("peer", existing)

	if err := n.probeNew(); err != nil {
		t.Fatal(err)
	}

	links := n.RouterState.GetPeerLinks("peer")
	if len(links) != 2 {
		t.Fatalf("expected one link per bind, got %d", len(links))
	}
	if link := n.RouterState.GetLink(state.LinkID{Peer: "peer", LocalBind: "wan-b", RemoteEndpoint: "router"}); link == nil {
		t.Fatalf("expected probeNew to add wan-b link, got %v", links)
	}
}

func TestBuildNeighRoutesIncludesAllPeerLinks(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	prefixA := netip.MustParsePrefix("10.0.0.1/32")
	prefixB := netip.MustParsePrefix("10.0.0.2/32")
	n := &Nylon{
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Links:          make(map[state.LinkID]*state.Link),
			Neighbours:     []*state.Neighbour{{Id: "peer", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		},
	}
	for _, item := range []struct {
		bind   state.LocalBindID
		prefix netip.Prefix
	}{
		{"wan-a", prefixA},
		{"wan-b", prefixB},
	} {
		ep := state.NewEndpoint(state.NewDynamicEndpoint("203.0.113.10:57175"), false, nil, &tunables)
		ep.LocalBind = item.bind
		link := n.RouterState.AddLink("peer", ep)
		link.Routes[item.prefix] = state.NeighRoute{
			PubRoute: state.PubRoute{
				Source: state.Source{NodeId: "peer", Prefix: item.prefix},
				FD:     state.FD{Seqno: 1, Metric: 10},
			},
			ExpireAt: time.Now().Add(time.Hour),
		}
	}

	routes := buildNeighRoutes(n, "peer")
	if len(routes) != 2 {
		t.Fatalf("expected routes from both links, got %d", len(routes))
	}
}
