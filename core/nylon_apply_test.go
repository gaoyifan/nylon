package core

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestReconcileAdvertisedPrefixesStartsChangedPrefixHealth(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::53/128")
	oldPrefix := state.PrefixHealthWrapper{
		PrefixHealth: &state.StaticPrefixHealth{Prefix: prefix},
	}
	n := testNylonWithPrefixes(oldPrefix)
	n.RouterState.Advertised[prefix] = state.Advertisement{
		NodeId:   n.LocalCfg.Id,
		Expiry:   maxConfigTime,
		MetricFn: oldPrefix.GetMetric,
	}

	delay := time.Millisecond
	next := testCentralConfig(n.LocalCfg.Id, state.PrefixHealthWrapper{
		PrefixHealth: &state.HTTPPrefixHealth{
			Prefix: prefix,
			URL:    "http://127.0.0.1:1/healthz",
			Delay:  &delay,
		},
	})

	n.reconcileAdvertisedPrefixes(&next)
	t.Cleanup(next.Routers[0].Prefixes[0].Stop)

	assert.Equal(t, state.INF, n.RouterState.Advertised[prefix].MetricFn())
}

func TestReconcileAdvertisedPrefixesStartsChangedPingPrefixHealth(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::54/128")
	oldPrefix := state.PrefixHealthWrapper{
		PrefixHealth: &state.StaticPrefixHealth{Prefix: prefix},
	}
	n := testNylonWithPrefixes(oldPrefix)
	n.RouterState.Advertised[prefix] = state.Advertisement{
		NodeId:   n.LocalCfg.Id,
		Expiry:   maxConfigTime,
		MetricFn: oldPrefix.GetMetric,
	}

	delay := 100 * time.Millisecond
	next := testCentralConfig(n.LocalCfg.Id, state.PrefixHealthWrapper{
		PrefixHealth: &state.PingPrefixHealth{
			Prefix: prefix,
			Addr:   netip.MustParseAddr("127.0.0.1"),
			Delay:  &delay,
		},
	})

	n.reconcileAdvertisedPrefixes(&next)
	t.Cleanup(next.Routers[0].Prefixes[0].Stop)

	assert.Equal(t, state.INF, n.RouterState.Advertised[prefix].MetricFn())
}

func TestReconcileAdvertisedPrefixesReusesUnchangedRunningPrefixHealth(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::53/128")
	delay := time.Millisecond
	current := state.PrefixHealthWrapper{
		PrefixHealth: &state.HTTPPrefixHealth{
			Prefix: prefix,
			URL:    "http://127.0.0.1:1/healthz",
			Delay:  &delay,
		},
	}
	n := testNylonWithPrefixes(current)
	current.Start(n.Log, &n.RouterTunables)
	t.Cleanup(current.Stop)
	n.RouterState.Advertised[prefix] = state.Advertisement{
		NodeId:   n.LocalCfg.Id,
		Expiry:   maxConfigTime,
		MetricFn: current.GetMetric,
		ExpiryFn: current.Stop,
	}

	next := testCentralConfig(n.LocalCfg.Id, state.PrefixHealthWrapper{
		PrefixHealth: &state.HTTPPrefixHealth{
			Prefix: prefix,
			URL:    "http://127.0.0.1:1/healthz",
			Delay:  &delay,
		},
	})

	n.reconcileAdvertisedPrefixes(&next)

	assert.Same(t, current.PrefixHealth, next.Routers[0].Prefixes[0].PrefixHealth)
	assert.Equal(t, state.INF, n.RouterState.Advertised[prefix].MetricFn())
}

func testNylonWithPrefixes(prefixes ...state.PrefixHealthWrapper) *Nylon {
	id := state.NodeId("node")
	tunables := state.DefaultRouterTunables()
	return &Nylon{
		RouterTunables: tunables,
		ConfigState: state.ConfigState{
			CentralCfg: testCentralConfig(id, prefixes...),
			LocalCfg: state.LocalCfg{
				Id: id,
			},
		},
		RouterState: &state.RouterState{
			RouterTunables: &tunables,
			Id:             id,
			SelfSeqno:      make(map[netip.Prefix]uint16),
			Routes:         make(map[netip.Prefix]state.SelRoute),
			Sources:        make(map[state.Source]state.FD),
			Advertised:     make(map[netip.Prefix]state.Advertisement),
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func testCentralConfig(id state.NodeId, prefixes ...state.PrefixHealthWrapper) state.CentralCfg {
	return state.CentralCfg{
		Routers: []state.RouterCfg{
			{
				NodeCfg: state.NodeCfg{
					Id:       id,
					Prefixes: prefixes,
				},
			},
		},
	}
}

// stubFamilyReachable overrides the host route lookup for the duration of a
// test, so results do not depend on the test machine's connectivity.
func stubFamilyReachable(t *testing.T, fn func(addr netip.Addr) bool) {
	orig := familyReachable
	familyReachable = fn
	t.Cleanup(func() { familyReachable = orig })
}

func allFamiliesReachable(netip.Addr) bool { return true }

func TestConfiguredEndpointsExpandsBindsAcrossMatchingEndpointFamilies(t *testing.T) {
	stubFamilyReachable(t, allFamiliesReachable)
	tunables := state.DefaultRouterTunables()
	eps := configuredEndpoints([]state.LocalBind{
		{Source: netip.MustParseAddr("192.0.2.10")},
		{Source: netip.MustParseAddr("2001:db8::10")},
	}, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, false, &tunables)

	assert.Len(t, eps, 2)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), eps[0].AsNylonEndpoint().Bind.Source)
	assert.Equal(t, "198.51.100.10:57175", eps[0].AsNylonEndpoint().DynEP.Value)
	assert.Equal(t, netip.MustParseAddr("2001:db8::10"), eps[1].AsNylonEndpoint().Bind.Source)
	assert.Equal(t, "[2001:db8::20]:57175", eps[1].AsNylonEndpoint().DynEP.Value)
}

func TestConfiguredEndpointsUsesDefaultEndpointWhenNoBindsConfigured(t *testing.T) {
	stubFamilyReachable(t, allFamiliesReachable)
	tunables := state.DefaultRouterTunables()
	eps := configuredEndpoints(nil, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, false, &tunables)

	assert.Len(t, eps, 2)
	assert.False(t, eps[0].AsNylonEndpoint().Bind.Source.IsValid())
	assert.False(t, eps[1].AsNylonEndpoint().Bind.Source.IsValid())
}

func TestConfiguredEndpointsAddsFakeTCPOnlyWhenEnabledAndInterfaceBound(t *testing.T) {
	stubFamilyReachable(t, allFamiliesReachable)
	tunables := state.DefaultRouterTunables()
	binds := []state.LocalBind{
		{Interface: "eth0"},
		{Source: netip.MustParseAddr("192.0.2.10")},
	}
	endpoints := []*state.DynamicEndpoint{state.NewDynamicEndpoint("198.51.100.10:57175")}

	for _, tc := range []struct {
		name    string
		enabled bool
		want    []conn.Transport
	}{
		{name: "enabled", enabled: true, want: []conn.Transport{conn.TransportUDP, conn.TransportFakeTCP, conn.TransportUDP}},
		{name: "disabled", want: []conn.Transport{conn.TransportUDP, conn.TransportUDP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eps := configuredEndpoints(binds, endpoints, tc.enabled, &tunables)
			transports := make([]conn.Transport, len(eps))
			for i, ep := range eps {
				transports[i] = ep.AsNylonEndpoint().Transport
			}
			assert.Equal(t, tc.want, transports)
		})
	}

	withoutBinds := configuredEndpoints(nil, endpoints, true, &tunables)
	assert.Len(t, withoutBinds, 1)
	assert.Equal(t, conn.TransportUDP, withoutBinds[0].AsNylonEndpoint().Transport)
}

func TestReconcileConfiguredEndpointsHotUpdatesRemoteFakeTCPCapability(t *testing.T) {
	stubFamilyReachable(t, allFamiliesReachable)
	tunables := state.DefaultRouterTunables()
	binds := []state.LocalBind{{Interface: "eth0"}}
	endpoints := []*state.DynamicEndpoint{state.NewDynamicEndpoint("198.51.100.10:57175")}
	neigh := &state.Neighbour{Eps: configuredEndpoints(binds, endpoints, false, &tunables)}
	udp := neigh.Eps[0]

	reconcileConfiguredEndpoints(neigh, configuredEndpoints(binds, endpoints, true, &tunables), true)
	assert.Len(t, neigh.Eps, 2)
	assert.Same(t, udp, neigh.Eps[0])
	assert.Equal(t, conn.TransportFakeTCP, neigh.Eps[1].AsNylonEndpoint().Transport)

	reconcileConfiguredEndpoints(neigh, configuredEndpoints(binds, endpoints, false, &tunables), false)
	assert.Equal(t, []state.Endpoint{udp}, neigh.Eps)
}

func TestReconcileConfiguredEndpointsDropsRemoteFakeTCPWhenCapabilityIsDisabled(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	udp := state.NewEndpoint(state.NewDynamicEndpoint("198.51.100.10:57175"), true, nil, &tunables)
	fakeTCP := state.NewEndpoint(state.NewDynamicEndpoint("198.51.100.10:57175"), true, nil, &tunables)
	fakeTCP.Transport = conn.TransportFakeTCP
	neigh := &state.Neighbour{Eps: []state.Endpoint{udp, fakeTCP}}

	reconcileConfiguredEndpoints(neigh, nil, false)

	assert.Equal(t, []state.Endpoint{udp}, neigh.Eps)
}

func TestApplyCentralConfigLocalFakeTCPCapabilityChangeRequiresRestart(t *testing.T) {
	current := state.CentralCfg{
		Routers: []state.RouterCfg{
			{NodeCfg: state.NodeCfg{Id: "a"}},
			{NodeCfg: state.NodeCfg{Id: "b"}},
		},
		Graph: []string{"a, b"},
	}
	n := &Nylon{ConfigState: state.ConfigState{CentralCfg: current, LocalCfg: state.LocalCfg{Id: "a"}}}
	next := current
	next.Routers = append([]state.RouterCfg(nil), current.Routers...)
	next.Routers[0].TCPObfuscation = true

	result, err := n.ApplyCentralConfig(&next)

	assert.Equal(t, ApplyRestartRequired, result)
	assert.ErrorContains(t, err, "tcp_obfuscation")
	assert.False(t, n.CentralCfg.GetRouter("a").TCPObfuscation)
}

func TestReconcileRouterStatePublishesMutualFakeTCPCapabilities(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	n := &Nylon{
		RouterTunables: tunables,
		ConfigState:    state.ConfigState{LocalCfg: state.LocalCfg{Id: "a"}},
		RouterState:    &state.RouterState{},
	}
	cfg := state.CentralCfg{
		Routers: []state.RouterCfg{
			{NodeCfg: state.NodeCfg{Id: "a"}, TCPObfuscation: true},
			{NodeCfg: state.NodeCfg{Id: "b"}, TCPObfuscation: true},
		},
		Graph: []string{"a, b"},
	}

	assert.NoError(t, n.reconcileRouterState(&cfg))
	peers := n.fakeTCPPeers.Load()
	if assert.NotNil(t, peers) {
		_, ok := (*peers)["b"]
		assert.True(t, ok)
	}

	cfg.Routers[1].TCPObfuscation = false
	assert.NoError(t, n.reconcileRouterState(&cfg))
	peers = n.fakeTCPPeers.Load()
	if assert.NotNil(t, peers) {
		_, ok := (*peers)["b"]
		assert.False(t, ok)
	}
}

func TestConfiguredEndpointsSkipsFamiliesWithoutRoute(t *testing.T) {
	stubFamilyReachable(t, func(addr netip.Addr) bool { return addr.Is4() })
	tunables := state.DefaultRouterTunables()

	// no binds: IPv6 endpoints are dropped on a v4-only host
	eps := configuredEndpoints(nil, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, false, &tunables)
	assert.Len(t, eps, 1)
	assert.Equal(t, "198.51.100.10:57175", eps[0].AsNylonEndpoint().DynEP.Value)

	// interface-only bind (no source): same filtering applies
	eps = configuredEndpoints([]state.LocalBind{
		{Interface: "eth0"},
	}, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("198.51.100.10:57175"),
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, false, &tunables)
	assert.Len(t, eps, 1)
	assert.Equal(t, "198.51.100.10:57175", eps[0].AsNylonEndpoint().DynEP.Value)

	// explicit bind source: kept even when the plain route lookup fails,
	// since source-based policy routing may provide connectivity
	eps = configuredEndpoints([]state.LocalBind{
		{Source: netip.MustParseAddr("2001:db8::10")},
	}, []*state.DynamicEndpoint{
		state.NewDynamicEndpoint("[2001:db8::20]:57175"),
	}, false, &tunables)
	assert.Len(t, eps, 1)
}

func TestEndpointFamilyUnreachable(t *testing.T) {
	stubFamilyReachable(t, func(addr netip.Addr) bool { return addr.Is4() })
	tunables := state.DefaultRouterTunables()

	v6 := state.NewEndpoint(state.NewDynamicEndpoint("[2001:db8::20]:57175"), false, nil, &tunables)
	assert.True(t, endpointFamilyUnreachable(v6))

	v4 := state.NewEndpoint(state.NewDynamicEndpoint("198.51.100.10:57175"), false, nil, &tunables)
	assert.False(t, endpointFamilyUnreachable(v4))

	// explicit bind source disables the check
	v6Bound := state.NewEndpoint(state.NewDynamicEndpoint("[2001:db8::20]:57175"), false, nil, &tunables)
	v6Bound.Bind = state.LocalBind{Source: netip.MustParseAddr("2001:db8::10")}
	assert.False(t, endpointFamilyUnreachable(v6Bound))
}
