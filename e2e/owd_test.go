//go:build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
)

// setEgressDelay attaches a netem qdisc to the interface that owns the given
// IP inside the node's container, adding a fixed one-way delay to all packets
// leaving through that interface.
func setEgressDelay(t *testing.T, h *Harness, node, ip string, delay time.Duration) {
	t.Helper()
	script := fmt.Sprintf(
		`IF=$(ip -o -4 addr show to %s | head -n1 | awk '{print $2}'); `+
			`[ -n "$IF" ] && tc qdisc replace dev "$IF" root netem delay %dms`,
		ip, delay.Milliseconds())
	stdout, stderr, err := h.Exec(node, []string{"sh", "-c", script})
	if err != nil {
		t.Fatalf("failed to set egress delay on %s (%s): %v\nstdout: %s\nstderr: %s",
			node, ip, err, stdout, stderr)
	}
}

func neighbourByID(status *protocol.StatusResponse, peer string) *protocol.NeighbourInfo {
	for _, nb := range status.GetNeighbours() {
		if nb.PeerId == peer {
			return nb
		}
	}
	return nil
}

func endpointByAddress(nb *protocol.NeighbourInfo, address string) *protocol.EndpointInfo {
	for _, ep := range nb.GetEndpoints() {
		if ep.GetAddress() == address {
			return ep
		}
	}
	return nil
}

// TestOwdAsymmetricParallelLinks runs the key scenario from the PR #123
// discussion on real network stacks: two nodes connected by two parallel
// links (two docker networks) with mirrored asymmetric delays applied via
// tc netem,
//
//	link 1 (net A): node1->node2  5ms, node2->node1 60ms
//	link 2 (net B): node1->node2 60ms, node2->node1  5ms
//
// Both links have an identical RTT of ~65ms, so an RTT-based comparison
// cannot tell them apart. With directional link selection node1 must send
// on link 1 and node2 on link 2, and the advertised neighbour cost must be
// the effective fast+fast cycle (~10ms) rather than the 65ms RTT. Unlike
// the in-process integration test, the two nylon processes here have
// genuinely different monotonic clock epochs, so this also verifies that
// the relative one-way delay comparisons are immune to real clock offsets.
func TestOwdAsymmetricParallelLinks(t *testing.T) {
	t.Parallel()
	h := NewHarness(t)

	netB, subnetB := h.NewExtraNetwork()

	node1Key := state.GenerateKey()
	node2Key := state.GenerateKey()

	// link 1 lives on the default harness network, link 2 on netB
	node1IPA := GetIP(h.Subnet, 10)
	node2IPA := GetIP(h.Subnet, 11)
	node1IPB := GetIP(subnetB, 10)
	node2IPB := GetIP(subnetB, 11)

	node1NylonIP := "10.10.0.1"
	node2NylonIP := "10.10.0.2"

	epA := func(ip string) string { return fmt.Sprintf("%s:57175", ip) }

	configDir := h.SetupTestDir()

	node1Cfg := SimpleRouter("node1", node1Key.Pubkey(), node1NylonIP, "")
	node1Cfg.Endpoints = []*state.DynamicEndpoint{
		state.NewDynamicEndpoint(epA(node1IPA)),
		state.NewDynamicEndpoint(epA(node1IPB)),
	}
	node2Cfg := SimpleRouter("node2", node2Key.Pubkey(), node2NylonIP, "")
	node2Cfg.Endpoints = []*state.DynamicEndpoint{
		state.NewDynamicEndpoint(epA(node2IPA)),
		state.NewDynamicEndpoint(epA(node2IPB)),
	}

	central := state.CentralCfg{
		Routers:   []state.RouterCfg{node1Cfg, node2Cfg},
		Graph:     []string{"node1, node2"},
		Timestamp: time.Now().UnixNano(),
	}
	centralPath := h.WriteConfig(configDir, "central.yaml", central)
	node1Path := h.WriteConfig(configDir, "node1.yaml", SimpleLocal("node1", node1Key))
	node2Path := h.WriteConfig(configDir, "node2.yaml", SimpleLocal("node2", node2Key))

	h.StartNodes(
		NodeSpec{
			Name: "node1", IP: node1IPA,
			CentralConfigPath: centralPath, NodeConfigPath: node1Path,
			ExtraNetworks: map[string]string{netB.Name: node1IPB},
		},
		NodeSpec{
			Name: "node2", IP: node2IPA,
			CentralConfigPath: centralPath, NodeConfigPath: node2Path,
			ExtraNetworks: map[string]string{netB.Name: node2IPB},
		},
	)

	// mirrored asymmetric delays: each node delays its own egress
	const fast = 5 * time.Millisecond
	const slow = 60 * time.Millisecond
	setEgressDelay(t, h, "node1", node1IPA, fast) // node1 -> node2 over link 1
	setEgressDelay(t, h, "node2", node2IPA, slow) // node2 -> node1 over link 1
	setEgressDelay(t, h, "node1", node1IPB, slow) // node1 -> node2 over link 2
	setEgressDelay(t, h, "node2", node2IPB, fast) // node2 -> node1 over link 2

	// each side must independently select the link that is fast in its own
	// outbound direction; the RTTs of the two links are indistinguishable
	prefersFast := func(status *protocol.StatusResponse, peer, fastAddr, slowAddr string) bool {
		nb := neighbourByID(status, peer)
		if nb == nil {
			return false
		}
		f := endpointByAddress(nb, fastAddr)
		s := endpointByAddress(nb, slowAddr)
		if f == nil || s == nil || f.GetOutExcessNs() < 0 || s.GetOutExcessNs() < 0 {
			return false
		}
		outDiff := time.Duration(s.GetOutExcessNs() - f.GetOutExcessNs())
		cost := time.Duration(nb.GetLinkCost()) * time.Microsecond
		t.Logf("%s: fast link selected=%v outExcess=%v, slow link outExcess=%v, link_cost=%v",
			peer, f.GetSelected(), time.Duration(f.GetOutExcessNs()), time.Duration(s.GetOutExcessNs()), cost)
		// the outbound-delay difference between the links (55ms) is measured
		// directly, and the advertised cost is the fast+fast cycle (~10ms),
		// well below the 65ms RTT of either link
		return f.GetSelected() && !s.GetSelected() &&
			outDiff > 40*time.Millisecond && outDiff < 70*time.Millisecond &&
			cost > 5*time.Millisecond && cost < 30*time.Millisecond
	}

	t.Log("Waiting for node1 to select link 1 (fast outbound)...")
	h.WaitForStatus(t, "node1", func(status *protocol.StatusResponse) bool {
		return prefersFast(status, "node2", epA(node2IPA), epA(node2IPB))
	})
	t.Log("Waiting for node2 to select link 2 (fast outbound)...")
	h.WaitForStatus(t, "node2", func(status *protocol.StatusResponse) bool {
		return prefersFast(status, "node1", epA(node1IPB), epA(node1IPA))
	})

	// sanity: the dataplane works across the tunnel
	stdout, stderr, err := h.Exec("node1", []string{"ping", "-c", "3", node2NylonIP})
	if err != nil {
		h.PrintLogs("node1")
		h.PrintLogs("node2")
		t.Fatalf("Ping failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}
	t.Logf("Ping output:\n%s", stdout)
}
