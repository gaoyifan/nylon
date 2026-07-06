//go:build integration

package integration

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn/bindtest"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"go.uber.org/goleak"
)

// owdTunables speeds up probing so the one-way delay filters converge within
// a few seconds instead of a minute.
func owdTunables() state.RouterTunables {
	tun := state.DefaultRouterTunables()
	tun.ProbeDelay /= 5
	tun.RouteUpdateDelay /= 3
	tun.MinimumConfidenceWindow /= 3
	tun.WindowSamples /= 3
	return tun
}

// neighbourStatus queries a node over IPC and returns the neighbour info and
// its endpoints keyed by configured address.
func neighbourStatus(t *testing.T, vh *VirtualHarness, node, peer state.NodeId) (*protocol.NeighbourInfo, map[string]*protocol.EndpointInfo) {
	t.Helper()
	ny := vh.Nylons[vh.IndexOf(node)].Load()
	resp := ipcCall(t, ny, &protocol.IpcRequest{
		Request: &protocol.IpcRequest_Status{Status: &protocol.StatusRequest{}},
	})
	if !resp.Ok {
		return nil, nil
	}
	for _, nb := range resp.GetStatus().GetNeighbours() {
		if nb.PeerId != string(peer) {
			continue
		}
		out := map[string]*protocol.EndpointInfo{}
		for _, ep := range nb.GetEndpoints() {
			out[ep.Address] = ep
		}
		return nb, out
	}
	return nil, nil
}

// TestOwdSymmetricLinkMeasurement checks the end-to-end measurement pipeline
// on a plain symmetric link: the offset-free RTT converges to the simulated
// round trip and the advertised neighbour cost matches it.
func TestOwdSymmetricLinkMeasurement(t *testing.T) {
	defer goleak.VerifyNone(t)
	tun := owdTunables()
	vh := &VirtualHarness{}
	vh.Tunables = &tun
	a1 := "192.168.60.1:1234"
	vh.NewNode("a", "10.0.0.1/32")
	b1 := "192.168.60.2:1234"
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{"a, b"}
	vh.Endpoints = map[string]state.NodeId{a1: "a", b1: "b"}

	const lat = 30 * time.Millisecond
	vh.AddLink(a1, b1).WithLatency(lat, 0)
	vh.AddLink(b1, a1).WithLatency(lat, 0)

	errs := vh.Start()
	defer vh.Stop()

	deadline := time.After(60 * time.Second)
	for {
		select {
		case err := <-errs:
			t.Fatal(err)
		case <-deadline:
			t.Fatal("timed out waiting for symmetric link measurement")
		case <-time.After(500 * time.Millisecond):
		}
		nb, eps := neighbourStatus(t, vh, "a", "b")
		if nb == nil {
			continue
		}
		ep := eps[b1]
		if ep == nil || ep.StabilizedRttNs == 0 {
			continue
		}
		rtt := time.Duration(ep.StabilizedRttNs)
		cost := time.Duration(nb.LinkCost) * time.Microsecond
		t.Logf("a->b rtt=%v link_cost=%v selected=%v outExcess=%v", rtt, cost, ep.Selected, ep.OutExcessNs)
		// symmetric single link: rtt ~ 2*lat, advertised cost ~ rtt, and the
		// only link is selected with zero excess delay in both directions
		if within(rtt, 2*lat, 15*time.Millisecond) &&
			within(cost, rtt, 5*time.Millisecond) &&
			ep.Selected && ep.OutExcessNs == 0 && ep.InExcessNs == 0 {
			return
		}
	}
}

// TestOwdParallelAsymmetricLinks is the key scenario from the PR #123
// discussion: two nodes connected by two parallel links with mirrored
// asymmetric delays,
//
//	link 1 (a1<->b1): a->b  5ms, b->a 60ms
//	link 2 (a2<->b2): a->b 60ms, b->a  5ms
//
// Both links have an identical RTT of 65ms, so an RTT-based comparison
// cannot tell them apart. With directional link selection a must send on
// link 1 and b on link 2 -- each direction independently picks its fastest
// path -- and the advertised neighbour cost must be the effective cycle
// (5ms + 5ms), not the RTT of either link.
func TestOwdParallelAsymmetricLinks(t *testing.T) {
	defer goleak.VerifyNone(t)
	tun := owdTunables()
	vh := &VirtualHarness{}
	vh.Tunables = &tun
	a1 := "192.168.61.1:1234"
	a2 := "192.168.61.2:1234"
	vh.NewNode("a", "10.0.0.1/32")
	b1 := "192.168.61.11:1234"
	b2 := "192.168.61.12:1234"
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{"a, b"}
	vh.Endpoints = map[string]state.NodeId{a1: "a", a2: "a", b1: "b", b2: "b"}

	// model two distinct physical paths: packets sent towards one end of a
	// link leave from the local endpoint of the same link
	pairs := map[string]string{b1: a1, b2: a2, a1: b1, a2: b2}
	vh.EpOut = func(cur state.NodeId, to bindtest.ChannelEndpoint2) bindtest.ChannelEndpoint2 {
		from, ok := pairs[to.DstToString()]
		if !ok {
			panic(fmt.Sprintf("no link peer for destination %v", to.DstToString()))
		}
		return bindtest.ChannelEndpoint2(netip.MustParseAddrPort(from))
	}

	const fast = 5 * time.Millisecond
	const slow = 60 * time.Millisecond
	vh.AddLink(a1, b1).WithLatency(fast, 0)
	vh.AddLink(b1, a1).WithLatency(slow, 0)
	vh.AddLink(a2, b2).WithLatency(slow, 0)
	vh.AddLink(b2, a2).WithLatency(fast, 0)

	errs := vh.Start()
	defer vh.Stop()

	check := func(nb *protocol.NeighbourInfo, eps map[string]*protocol.EndpointInfo, fastAddr, slowAddr string) bool {
		f, s := eps[fastAddr], eps[slowAddr]
		if f == nil || s == nil || f.OutExcessNs < 0 || s.OutExcessNs < 0 {
			return false
		}
		outDiff := time.Duration(s.OutExcessNs - f.OutExcessNs)
		inDiff := time.Duration(f.InExcessNs - s.InExcessNs)
		cost := time.Duration(nb.LinkCost) * time.Microsecond
		// the link that is fast in our sending direction must be selected,
		// with the measured outbound difference matching the asymmetry, and
		// the advertised cost must be the fast+fast cycle, well below the RTT
		return f.Selected && !s.Selected &&
			f.OutExcessNs == 0 && s.InExcessNs == 0 &&
			within(outDiff, slow-fast, 10*time.Millisecond) &&
			within(inDiff, slow-fast, 10*time.Millisecond) &&
			within(cost, 2*fast, 10*time.Millisecond)
	}

	dump := func(node, peer state.NodeId) {
		nb, eps := neighbourStatus(t, vh, node, peer)
		if nb == nil {
			t.Logf("%s: no neighbour info for %s", node, peer)
			return
		}
		t.Logf("%s: link_cost=%v", node, time.Duration(nb.LinkCost)*time.Microsecond)
		for addr, ep := range eps {
			t.Logf("%s: ep %v selected=%v metric=%v outExcess=%v inExcess=%v rtt=%v",
				node, addr, ep.Selected, ep.Metric,
				time.Duration(ep.OutExcessNs), time.Duration(ep.InExcessNs),
				time.Duration(ep.StabilizedRttNs))
		}
	}

	deadline := time.After(90 * time.Second)
	for {
		select {
		case err := <-errs:
			t.Fatal(err)
		case <-deadline:
			dump("a", "b")
			dump("b", "a")
			t.Fatal("timed out waiting for each side to prefer its fast outbound link")
		case <-time.After(500 * time.Millisecond):
		}

		nbA, epsA := neighbourStatus(t, vh, "a", "b")
		nbB, epsB := neighbourStatus(t, vh, "b", "a")
		if nbA == nil || nbB == nil {
			continue
		}
		// a sends fastest over link 1 (towards b1); b over link 2 (towards a2)
		if check(nbA, epsA, b1, b2) && check(nbB, epsB, a2, a1) {
			return
		}
	}
}

func within(v, target, tol time.Duration) bool {
	d := v - target
	if d < 0 {
		d = -d
	}
	return d <= tol
}
