package core

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLANDiscoveryInterfaceAcceptsDirectedBroadcast(t *testing.T) {
	iface := lanDiscoveryInterface{
		subnets: []lanDiscoverySubnet{
			{prefix: netip.MustParsePrefix("192.168.1.0/24"), broadcast: netip.MustParseAddr("192.168.1.255")},
			{prefix: netip.MustParsePrefix("10.0.0.0/24"), broadcast: netip.MustParseAddr("10.0.0.255")},
		},
	}

	tests := []struct {
		name        string
		source      string
		destination string
		want        bool
	}{
		{name: "same subnet broadcast", source: "192.168.1.10:57176", destination: "192.168.1.255", want: true},
		{name: "wrong source port", source: "192.168.1.10:6622", destination: "192.168.1.255"},
		{name: "unicast destination", source: "192.168.1.10:57176", destination: "192.168.1.20"},
		{name: "source outside subnet", source: "192.168.2.10:57176", destination: "192.168.1.255"},
		{name: "different configured subnet", source: "192.168.1.10:57176", destination: "10.0.0.255"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, iface.acceptsAnnouncement(
				netip.MustParseAddrPort(tt.source),
				netip.MustParseAddr(tt.destination),
			))
		})
	}
}

func TestLANDiscoveryInterfaceContainsProbeSource(t *testing.T) {
	iface := lanDiscoveryInterface{
		subnets: []lanDiscoverySubnet{{prefix: netip.MustParsePrefix("192.168.1.0/24")}},
	}
	require.True(t, iface.contains(netip.MustParseAddr("192.168.1.10")))
	require.False(t, iface.contains(netip.MustParseAddr("192.168.2.10")))
	require.False(t, iface.contains(netip.MustParseAddr("2001:db8::1")))
}
