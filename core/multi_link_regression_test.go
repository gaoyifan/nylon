package core

import (
	"net/netip"
	"testing"

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
