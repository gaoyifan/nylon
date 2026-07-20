//go:build linux && !android

package core

import (
	"net"
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
)

func TestHandleProbeRejectsFakeTCPDiscovery(t *testing.T) {
	n := &Nylon{DispatchChannel: make(chan func() error, 1)}
	peers := map[state.NodeId]struct{}{"b": {}}
	n.fakeTCPPeers.Store(&peers)
	ep := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.2:51820")}
	ep.SetTransport(conn.TransportFakeTCP)

	handleProbe(n, &protocol.Ny_Probe{TxTs: 1, Reply: true, Discovery: true}, ep, nil, "b")

	select {
	case <-n.DispatchChannel:
		t.Fatal("LAN discovery accepted a fake TCP probe")
	default:
	}
}

func TestHandleProbeRejectsFakeTCPBeforeReplyWithoutMutualCapability(t *testing.T) {
	n := &Nylon{DispatchChannel: make(chan func() error, 1)}
	peers := make(map[state.NodeId]struct{})
	n.fakeTCPPeers.Store(&peers)
	received := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.2:51820")}
	received.SetTransport(conn.TransportFakeTCP)

	handleProbe(n, &protocol.Ny_Probe{TxTs: 1}, received, nil, "b")

	select {
	case <-n.DispatchChannel:
		t.Fatal("fake TCP probe without mutual capability reached dispatch")
	default:
	}
}

func TestHandleProbePingMatchesFakeTCPBind(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	tunables := state.DefaultRouterTunables()
	wrongInterface := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.2:51820"), false, nil, &tunables)
	wrongInterface.Transport = conn.TransportFakeTCP
	wrongInterface.Bind.Interface = "not-loopback"
	wrongInterface.Renew()
	wildcard := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.2:51820"), false, nil, &tunables)
	wildcard.Transport = conn.TransportFakeTCP
	wildcard.Bind.Interface = loopback.Name
	wildcard.Renew()
	wrongSource := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.2:51820"), false, nil, &tunables)
	wrongSource.Transport = conn.TransportFakeTCP
	wrongSource.Bind = state.LocalBind{Interface: loopback.Name, Source: netip.MustParseAddr("192.0.2.99")}
	wrongSource.Renew()
	exact := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.2:51820"), false, nil, &tunables)
	exact.Transport = conn.TransportFakeTCP
	exact.Bind = state.LocalBind{Interface: loopback.Name, Source: netip.MustParseAddr("192.0.2.1")}
	exact.Renew()
	n := &Nylon{
		RouterTunables: tunables,
		ConfigState: state.ConfigState{
			LocalCfg: state.LocalCfg{Id: "a"},
			CentralCfg: state.CentralCfg{Routers: []state.RouterCfg{
				{NodeCfg: state.NodeCfg{Id: "a"}, TCPObfuscation: true},
				{NodeCfg: state.NodeCfg{Id: "b"}, TCPObfuscation: true},
			}},
		},
		RouterState: &state.RouterState{Neighbours: []*state.Neighbour{{
			Id:  "b",
			Eps: []state.Endpoint{wrongInterface, wildcard, wrongSource, exact},
		}}},
	}
	received := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.2:51820")}
	received.SetSrc(netip.MustParseAddr("192.0.2.1"), int32(loopback.Index))
	received.SetTransport(conn.TransportFakeTCP)

	handleProbePing(n, "b", &protocol.Ny_Probe{TxTs: 1}, received, probeNowNs())

	if wrongInterface.WgEndpoint != nil {
		t.Fatal("fake TCP probe matched the wrong interface")
	}
	if wildcard.WgEndpoint != nil || wrongSource.WgEndpoint != nil {
		t.Fatal("fake TCP probe matched a wildcard or wrong source before an exact source")
	}
	if exact.WgEndpoint != received {
		t.Fatal("fake TCP probe did not match its exact local bind")
	}

	wildcardReceived := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.2:51820")}
	wildcardReceived.SetSrc(netip.MustParseAddr("192.0.2.9"), int32(loopback.Index))
	wildcardReceived.SetTransport(conn.TransportFakeTCP)
	handleProbePing(n, "b", &protocol.Ny_Probe{TxTs: 2}, wildcardReceived, probeNowNs())

	if wildcard.WgEndpoint != wildcardReceived {
		t.Fatal("fake TCP probe did not fall back to the interface-only bind")
	}
}
