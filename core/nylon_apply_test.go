package core

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestConfiguredEndpointsExpandsBindsAcrossMatchingEndpointFamilies(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	eps := configuredEndpoints([]state.LocalBind{
		{Source: netip.MustParseAddr("192.0.2.10")},
		{Source: netip.MustParseAddr("2001:db8::10")},
	}, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, &tunables)

	assert.Len(t, eps, 2)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), eps[0].AsNylonEndpoint().Bind.Source)
	assert.Equal(t, "198.51.100.10:57175", eps[0].AsNylonEndpoint().DynEP.Value)
	assert.Equal(t, netip.MustParseAddr("2001:db8::10"), eps[1].AsNylonEndpoint().Bind.Source)
	assert.Equal(t, "[2001:db8::20]:57175", eps[1].AsNylonEndpoint().DynEP.Value)
}

func TestConfiguredEndpointsUsesDefaultEndpointWhenNoBindsConfigured(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	eps := configuredEndpoints(nil, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, &tunables)

	assert.Len(t, eps, 2)
	assert.False(t, eps[0].AsNylonEndpoint().Bind.Source.IsValid())
	assert.False(t, eps[1].AsNylonEndpoint().Bind.Source.IsValid())
}
