package state

import (
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func TestParseGraph_SimpleGraph(t *testing.T) {
	nodes := []string{"1", "2", "3", "4", "5"}
	input := `1, 2
3, 4
1,3,5`
	pairs, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.NoError(t, err)
	assert.ElementsMatch(t, pairs, []Pair[NodeId, NodeId]{
		{"1", "2"},
		{"3", "4"},
		{"1", "3"},
		{"3", "5"},
		{"1", "5"},
	})
}

func TestParseGraph_Groups(t *testing.T) {
	nodes := []string{"1", "2", "3", "4", "5", "6", "7"}
	input := `a = 1,2
b=3,,,4
c=5,6
d=a,b
d,d
7,d`
	pairs, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.NoError(t, err)
	assert.ElementsMatch(t, pairs, []Pair[NodeId, NodeId]{
		// d,d
		{"1", "2"},
		{"1", "3"},
		{"1", "4"},
		{"2", "3"},
		{"2", "4"},
		{"3", "4"},
		// 7,d
		{"1", "7"},
		{"2", "7"},
		{"3", "7"},
		{"4", "7"},
	})
}

func TestParseGraph_Cycle(t *testing.T) {
	nodes := []string{}
	input := `a = b
b = c
c = a`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "cycle detected in graph: [a b c]")
}

func TestParseGraph_DupGroupName(t *testing.T) {
	nodes := []string{}
	input := `a = b
a = b
b = b`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "duplicate group name: a")
}

func TestParseGraph_SymbolError(t *testing.T) {
	nodes := []string{"1"}
	input := `a = 1
b = 2`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "2 is not a valid node/group")
}

func TestParseGraph_EmptyGroup(t *testing.T) {
	nodes := []string{"1"}
	input := `a =`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "node/group list must not be empty")
}

func TestParseGraph_GroupNameIsNodeName(t *testing.T) {
	nodes := []string{"1"}
	input := `1 = 1`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "group name must not be a node name: 1")
}

func TestParseGraph_InvalidGroupDefinition(t *testing.T) {
	nodes := []string{"1"}
	input := `a = 1 = b`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, ". group definition must contain one '='")
}

func TestParseGraph_Single(t *testing.T) {
	nodes := []string{"1", "2", "3", "4", "5"}
	input := `1`
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "invalid pairing, [1]")
}

func TestParseGraph_None(t *testing.T) {
	nodes := []string{"1", "2", "3", "4", "5"}
	input := ``
	_, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.ErrorContains(t, err, "node/group list must not be empty")
}

func TestParseGraph_GroupsDeep(t *testing.T) {
	nodes := []string{"1", "2", "3", "4", "5", "6", "7"}
	input := `a = 1,2
b = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
c = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
d = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
e = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
f = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
g = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
h = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
i = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
j = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
k = a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a
k,k,3`
	pairs, err := ParseGraph(strings.Split(input, "\n"), nodes)
	assert.NoError(t, err)
	assert.ElementsMatch(t, pairs, []Pair[NodeId, NodeId]{
		{"1", "2"},
		{"1", "3"},
		{"2", "3"},
	})
}

func failGraph(t *testing.T, graph string) {
	_, err := ParseGraph(strings.Split(graph, "\n"), []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"})
	assert.Error(t, err)
}

func TestParseGraph_InvalidGraph(t *testing.T) {
	failGraph(t, `this graph is a baddie`)
	failGraph(t, `=========,,,,`)
	failGraph(t, `#`)
	failGraph(t, `\n\n\n\n\n\n`)
	failGraph(t, `1`)
	failGraph(t, `1,2,3,4,5,6,a`)
	failGraph(t, `1,2,3,4,5,6,7,8,9,10,11,12,13,14,15`)
	failGraph(t, `,,,,,,,,,,,,,,,,`)
	failGraph(t, `a=a`)
}

func TestLocalBindsParse(t *testing.T) {
	data := []byte(`
key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
id: alice
port: 57175
binds:
  - interface: eth0
    source: 203.0.113.10
`)
	var local LocalCfg
	err := yaml.Unmarshal(data, &local)
	assert.NoError(t, err)
	assert.Len(t, local.Binds, 1)
	assert.Equal(t, "eth0", local.Binds[0].Interface)
	assert.Equal(t, netip.MustParseAddr("203.0.113.10"), local.Binds[0].Source)
}

func TestLocalLANDiscoveryYAML(t *testing.T) {
	var local LocalCfg
	err := yaml.Unmarshal([]byte(`
key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
id: alice
port: 57175
lan_discovery:
  - eth0
  - wlan0
`), &local)
	assert.NoError(t, err)
	assert.Equal(t, LANDiscoveryInterfaces{"eth0", "wlan0"}, local.LANDiscovery)

	var deployed LocalCfg
	err = yaml.Unmarshal([]byte(`
key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
id: alice
port: 57175
lan_discovery:
  interfaces:
    - eth0
    - wlan0
`), &deployed)
	assert.NoError(t, err)
	assert.Equal(t, LANDiscoveryInterfaces{"eth0", "wlan0"}, deployed.LANDiscovery)

	encoded, err := yaml.Marshal(deployed)
	assert.NoError(t, err)
	assert.Contains(t, string(encoded), "lan_discovery:\n- eth0\n- wlan0")
	assert.NotContains(t, string(encoded), "interfaces:")
}

func TestRouterTCPObfuscationYAML(t *testing.T) {
	var central CentralCfg
	err := yaml.Unmarshal([]byte(`
routers:
  - id: alice
    tcp_obfuscation: true
`), &central)
	assert.NoError(t, err)
	if assert.Len(t, central.Routers, 1) {
		assert.True(t, central.Routers[0].TCPObfuscation)
	}
}

func TestLocalTransportCostsYAML(t *testing.T) {
	var local LocalCfg
	err := yaml.Unmarshal([]byte("tcp_cost: 3ms\nudp_cost: 5ms\n"), &local)
	assert.NoError(t, err)
	assert.Equal(t, 3*time.Millisecond, local.TCPCost)
	assert.Equal(t, 5*time.Millisecond, local.UDPCost)

	var defaults LocalCfg
	assert.Zero(t, defaults.TCPCost)
	assert.Zero(t, defaults.UDPCost)
}

func TestNodeConfigValidatorRejectsSelectorlessBind(t *testing.T) {
	local := LocalCfg{
		Id:    "alice",
		Key:   [32]byte{1},
		Port:  57175,
		Binds: []LocalBind{{}},
	}

	err := NodeConfigValidator(nil, &local)
	assert.ErrorContains(t, err, "must specify source or interface")
}

func TestNodeConfigValidatorAllowsBind(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local binds are linux-only")
	}
	local := LocalCfg{
		Id:    "alice",
		Key:   [32]byte{1},
		Port:  57175,
		Binds: []LocalBind{{Source: netip.MustParseAddr("203.0.113.10")}},
	}

	err := NodeConfigValidator(nil, &local)
	assert.NoError(t, err)
}

func TestNodeConfigValidatorTCPObfuscation(t *testing.T) {
	supported := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	central := CentralCfg{Routers: []RouterCfg{{
		NodeCfg:        NodeCfg{Id: "alice"},
		TCPObfuscation: true,
	}}}
	local := LocalCfg{
		Id:   "alice",
		Key:  [32]byte{1},
		Port: 57175,
	}

	err := NodeConfigValidator(&central, &local)
	if supported {
		assert.ErrorContains(t, err, "requires at least one bind with an interface")
	} else {
		assert.ErrorContains(t, err, "requires linux on amd64 or arm64")
	}

	local.Binds = []LocalBind{{Source: netip.MustParseAddr("203.0.113.10")}}
	err = NodeConfigValidator(&central, &local)
	if supported {
		assert.ErrorContains(t, err, "requires at least one bind with an interface")
	} else {
		assert.ErrorContains(t, err, "requires linux on amd64 or arm64")
	}

	local.Binds = []LocalBind{{Interface: "eth0"}}
	err = NodeConfigValidator(&central, &local)
	if supported {
		assert.NoError(t, err)
	} else {
		assert.ErrorContains(t, err, "requires linux on amd64 or arm64")
	}
}
