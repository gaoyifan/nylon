//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
)

func TestLANDiscovery(t *testing.T) {
	h := NewHarness(t)
	nodeAKey := state.GenerateKey()
	nodeBKey := state.GenerateKey()
	nodeCKey := state.GenerateKey()
	nodeDKey := state.GenerateKey()
	nodeAIP := GetIP(h.Subnet, 10)
	nodeBIP := GetIP(h.Subnet, 11)
	nodeCIP := GetIP(h.Subnet, 12)
	nodeDIP := GetIP(h.Subnet, 13)

	configDir := h.SetupTestDir()
	central := state.CentralCfg{
		Routers: []state.RouterCfg{
			SimpleRouter("node-a", nodeAKey.Pubkey(), "10.88.0.1", ""),
			SimpleRouter("node-b", nodeBKey.Pubkey(), "10.88.0.2", ""),
			SimpleRouter("node-c", nodeCKey.Pubkey(), "10.88.0.3", ""),
			SimpleRouter("node-d", nodeDKey.Pubkey(), "10.88.0.4", ""),
		},
		Graph: []string{
			"node-a, node-b",
			"node-b, node-c",
			"node-b, node-d",
		},
		Timestamp: time.Now().UnixNano(),
	}
	centralPath := h.WriteConfig(configDir, "central.yaml", central)

	nodeACfg := SimpleLocal("node-a", nodeAKey)
	nodeACfg.LANDiscovery = []string{"eth0"}
	nodeBCfg := SimpleLocal("node-b", nodeBKey)
	nodeBCfg.Port = 51820
	nodeBCfg.LANDiscovery = []string{"eth0"}
	nodeCCfg := SimpleLocal("node-c", nodeCKey)
	nodeCCfg.LANDiscovery = []string{"eth0"}
	nodeDCfg := SimpleLocal("node-d", nodeDKey)

	h.StartNodes(
		NodeSpec{Name: "node-a", IP: nodeAIP, CentralConfigPath: centralPath, NodeConfigPath: h.WriteConfig(configDir, "node-a.yaml", nodeACfg)},
		NodeSpec{Name: "node-b", IP: nodeBIP, CentralConfigPath: centralPath, NodeConfigPath: h.WriteConfig(configDir, "node-b.yaml", nodeBCfg)},
		NodeSpec{Name: "node-c", IP: nodeCIP, CentralConfigPath: centralPath, NodeConfigPath: h.WriteConfig(configDir, "node-c.yaml", nodeCCfg)},
		NodeSpec{Name: "node-d", IP: nodeDIP, CentralConfigPath: centralPath, NodeConfigPath: h.WriteConfig(configDir, "node-d.yaml", nodeDCfg)},
	)

	wantAEndpoint := fmt.Sprintf("%s:%d", nodeBIP, nodeBCfg.Port)
	wantBEndpoint := fmt.Sprintf("%s:%d", nodeAIP, nodeACfg.Port)
	wantBToCEndpoint := fmt.Sprintf("%s:%d", nodeCIP, nodeCCfg.Port)
	wantCEndpoint := fmt.Sprintf("%s:%d", nodeBIP, nodeBCfg.Port)
	h.WaitForStatus(t, "node-a", func(status *protocol.StatusResponse) bool {
		return hasActiveEndpoint(status, "node-b", wantAEndpoint, "eth0")
	})
	h.WaitForStatus(t, "node-b", func(status *protocol.StatusResponse) bool {
		return hasActiveEndpoint(status, "node-a", wantBEndpoint, "eth0")
	})
	h.WaitForStatus(t, "node-b", func(status *protocol.StatusResponse) bool {
		return hasActiveEndpoint(status, "node-c", wantBToCEndpoint, "eth0")
	})
	h.WaitForStatus(t, "node-c", func(status *protocol.StatusResponse) bool {
		return hasActiveEndpoint(status, "node-b", wantCEndpoint, "eth0")
	})
	h.WaitForStatus(t, "node-a", func(status *protocol.StatusResponse) bool {
		return HasSelectedRoute(status, "10.88.0.3/32", "node-b", "node-c")
	})
	h.WaitForStatus(t, "node-c", func(status *protocol.StatusResponse) bool {
		return HasSelectedRoute(status, "10.88.0.1/32", "node-b", "node-a")
	})

	stdout, stderr, err := h.Exec("node-a", []string{"ping", "-c", "3", "10.88.0.3"})
	if err != nil {
		h.PrintLogs("node-a")
		h.PrintLogs("node-b")
		h.PrintLogs("node-c")
		t.Fatalf("LAN-discovered transit path A -> B -> C failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	stdout, stderr, err = h.Exec("node-c", []string{"ping", "-c", "3", "10.88.0.1"})
	if err != nil {
		h.PrintLogs("node-a")
		h.PrintLogs("node-b")
		h.PrintLogs("node-c")
		t.Fatalf("LAN-discovered transit path C -> B -> A failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	for _, node := range []string{"node-a", "node-b", "node-c", "node-d"} {
		status, err := h.ReadStatus(node)
		if err != nil {
			t.Fatalf("read %s status: %v", node, err)
		}
		for _, neighbour := range status.GetNeighbours() {
			for _, endpoint := range neighbour.GetEndpoints() {
				if strings.HasSuffix(endpoint.GetAddress(), ":57176") || strings.HasSuffix(endpoint.GetResolved(), ":57176") {
					t.Fatalf("%s exposed the discovery destination as a routing endpoint: %+v", node, endpoint)
				}
			}
		}
	}

	statusA, err := h.ReadStatus("node-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, neighbour := range statusA.GetNeighbours() {
		if neighbour.GetPeerId() == "node-c" && len(neighbour.GetEndpoints()) != 0 {
			t.Fatalf("non-neighbour node-a learned a direct endpoint for node-c: %+v", neighbour.GetEndpoints())
		}
	}

	statusD, err := h.ReadStatus("node-d")
	if err != nil {
		t.Fatal(err)
	}
	for _, neighbour := range statusD.GetNeighbours() {
		if len(neighbour.GetEndpoints()) != 0 {
			t.Fatalf("non-participating node-d learned endpoints for %s: %+v", neighbour.GetPeerId(), neighbour.GetEndpoints())
		}
	}
}

func hasActiveEndpoint(status *protocol.StatusResponse, peerID, address, interfaceName string) bool {
	for _, neighbour := range status.GetNeighbours() {
		if neighbour.GetPeerId() != peerID {
			continue
		}
		for _, endpoint := range neighbour.GetEndpoints() {
			if endpoint.GetResolved() == address && endpoint.GetActive() && endpoint.GetLocalBindInterface() == interfaceName {
				return true
			}
		}
	}
	return false
}
