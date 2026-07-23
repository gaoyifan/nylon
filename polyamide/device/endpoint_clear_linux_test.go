//go:build linux && !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
)

func TestSendBuffersPreservesFakeTCPEndpointSource(t *testing.T) {
	udpEndpoint := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:6622")}
	udpEndpoint.SetSrc(netip.MustParseAddr("198.51.100.1"), 1)
	fakeTCPEndpoint := &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.2:6622")}
	fakeTCPEndpoint.SetSrc(netip.MustParseAddr("198.51.100.2"), 2)
	fakeTCPEndpoint.SetTransport(conn.TransportFakeTCP)

	device := &Device{}
	device.net.bind = &fakeBindSized{size: 1}
	peer := &Peer{device: device}
	peer.endpoints.val = []conn.Endpoint{udpEndpoint, fakeTCPEndpoint}
	peer.endpoints.clearSrcOnTx = true

	if err := peer.SendBuffers([][]byte{{0}}, []conn.Endpoint{udpEndpoint}); err != nil {
		t.Fatalf("SendBuffers failed: %v", err)
	}
	if udpEndpoint.SrcIP().IsValid() || udpEndpoint.SrcIfidx() != 0 {
		t.Fatalf("UDP source was retained: %v ifindex %d", udpEndpoint.SrcIP(), udpEndpoint.SrcIfidx())
	}
	if got := fakeTCPEndpoint.SrcIP(); got != netip.MustParseAddr("198.51.100.2") {
		t.Fatalf("FakeTCP source = %v", got)
	}
	if got := fakeTCPEndpoint.SrcIfidx(); got != 2 {
		t.Fatalf("FakeTCP interface index = %d", got)
	}
}
