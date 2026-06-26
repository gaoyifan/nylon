package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildNodeIdMap_DeterministicAcrossOrdering(t *testing.T) {
	cfgA := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "syd-vm"}},
			{NodeCfg: NodeCfg{Id: "ios-phone"}},
			{NodeCfg: NodeCfg{Id: "openstick"}},
		},
		Clients: []ClientCfg{
			{NodeCfg: NodeCfg{Id: "tablet"}},
		},
	}
	cfgB := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "openstick"}},
			{NodeCfg: NodeCfg{Id: "syd-vm"}},
			{NodeCfg: NodeCfg{Id: "ios-phone"}},
		},
		Clients: []ClientCfg{
			{NodeCfg: NodeCfg{Id: "tablet"}},
		},
	}
	mA, err := BuildNodeIdMap(cfgA)
	assert.NoError(t, err)
	mB, err := BuildNodeIdMap(cfgB)
	assert.NoError(t, err)

	for _, id := range []NodeId{"syd-vm", "ios-phone", "openstick", "tablet"} {
		a, ok := mA.ToNumeric(id)
		assert.True(t, ok)
		b, ok := mB.ToNumeric(id)
		assert.True(t, ok)
		assert.Equal(t, a, b, "numeric id for %s should be stable across input order", id)
	}
}

func TestBuildNodeIdMap_ReservesZero(t *testing.T) {
	cfg := &CentralCfg{
		Routers: []RouterCfg{{NodeCfg: NodeCfg{Id: "a"}}},
	}
	m, err := BuildNodeIdMap(cfg)
	assert.NoError(t, err)

	_, ok := m.ToString(InvalidNodeIdNumeric)
	assert.False(t, ok, "InvalidNodeIdNumeric must not resolve to a node")

	numeric, ok := m.ToNumeric("a")
	assert.True(t, ok)
	assert.NotEqual(t, InvalidNodeIdNumeric, numeric)

	_, ok = m.ToNumeric("missing")
	assert.False(t, ok)
}

func TestBuildNodeIdMap_ImplicitStartsAtFirst(t *testing.T) {
	cfg := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "b"}},
			{NodeCfg: NodeCfg{Id: "a"}},
			{NodeCfg: NodeCfg{Id: "c"}},
		},
	}
	m, err := BuildNodeIdMap(cfg)
	assert.NoError(t, err)
	a, _ := m.ToNumeric("a")
	b, _ := m.ToNumeric("b")
	c, _ := m.ToNumeric("c")
	assert.Equal(t, FirstNodeIdNumeric, a)
	assert.Equal(t, FirstNodeIdNumeric+1, b)
	assert.Equal(t, FirstNodeIdNumeric+2, c)
}

func TestBuildNodeIdMap_ExplicitAndGapFill(t *testing.T) {
	cfg := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a", NumericId: 20}},
			{NodeCfg: NodeCfg{Id: "b"}},
			{NodeCfg: NodeCfg{Id: "c", NumericId: 16}},
			{NodeCfg: NodeCfg{Id: "d"}},
		},
	}
	m, err := BuildNodeIdMap(cfg)
	assert.NoError(t, err)
	// explicit honoured
	numeric, _ := m.ToNumeric("a")
	assert.EqualValues(t, 20, numeric)
	numeric, _ = m.ToNumeric("c")
	assert.EqualValues(t, 16, numeric)
	// implicit fill the lowest free slots (16 taken -> b=17, d=18)
	numeric, _ = m.ToNumeric("b")
	assert.EqualValues(t, 17, numeric)
	numeric, _ = m.ToNumeric("d")
	assert.EqualValues(t, 18, numeric)
	// reverse lookup
	id, ok := m.ToString(20)
	assert.True(t, ok)
	assert.EqualValues(t, "a", id)
}

func TestBuildNodeIdMap_RejectsExplicitBelowFirst(t *testing.T) {
	for _, bad := range []NodeIdNumeric{1, 3, 15} {
		cfg := &CentralCfg{Routers: []RouterCfg{{NodeCfg: NodeCfg{Id: "a", NumericId: bad}}}}
		_, err := BuildNodeIdMap(cfg)
		assert.Error(t, err, "numeric id %d must be rejected", bad)
	}
}

func TestBuildNodeIdMap_RejectsDuplicateExplicit(t *testing.T) {
	cfg := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a", NumericId: 16}},
			{NodeCfg: NodeCfg{Id: "b", NumericId: 16}},
		},
	}
	_, err := BuildNodeIdMap(cfg)
	assert.Error(t, err)
}
