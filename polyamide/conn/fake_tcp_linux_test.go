//go:build linux && !android && (amd64 || arm64)

package conn

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/faketcp"
	"golang.org/x/sys/unix"
)

func TestFakeTCPSocketsAndPrepareRetry(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	if err := bind.EnableFakeTCP(time.Minute); err != nil {
		t.Fatal(err)
	}
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if port == 0 {
		t.Fatal("Open selected port 0")
	}
	if len(fns) < 2 {
		t.Fatalf("fake TCP Open returned %d receive functions", len(fns))
	}
	if err := bind.EnableFakeTCP(time.Minute); !errors.Is(err, ErrBindAlreadyOpen) {
		t.Fatalf("enable open bind error = %v", err)
	}

	if bind.ipv4 != nil {
		assertSocketOption(t, bind.ipv4, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		assertSocketOption(t, bind.fakeIPv4, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		assertSocketOption(t, bind.fakeIPv4, unix.SOL_SOCKET, unix.SO_NO_CHECK, 1)
		assertSocketOption(t, bind.fakeIPv4, unix.IPPROTO_UDP, unix.UDP_GRO, 0)
	}
	if bind.ipv6 != nil {
		assertSocketOption(t, bind.ipv6, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		assertSocketOption(t, bind.ipv6, unix.IPPROTO_UDP, unix.UDP_NO_CHECK6_RX, 1)
		assertSocketOption(t, bind.fakeIPv6, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		assertSocketOption(t, bind.fakeIPv6, unix.IPPROTO_UDP, unix.UDP_NO_CHECK6_RX, 1)
		assertSocketOption(t, bind.fakeIPv6, unix.IPPROTO_UDP, unix.UDP_NO_CHECK6_TX, 1)
		assertSocketOption(t, bind.fakeIPv6, unix.IPPROTO_UDP, unix.UDP_GRO, 0)
	}

	ep := fakeTCPEndpoint("127.0.0.1:1")
	if err := bind.Send([][]byte{[]byte("not established")}, ep); !errors.Is(err, ErrFakeTCPNotEstablished) {
		t.Fatalf("pre-handshake Send error = %v", err)
	}
	if err := bind.PrepareFakeTCP(ep); !errors.Is(err, ErrFakeTCPNotEstablished) {
		t.Fatalf("first Prepare error = %v", err)
	}
	key := fakeTCPKey(ep)
	firstISN := bind.fakeTCPStates[key].sendNext - 1
	if err := bind.PrepareFakeTCP(ep); !errors.Is(err, ErrFakeTCPNotEstablished) {
		t.Fatalf("retry Prepare error = %v", err)
	}
	if retryISN := bind.fakeTCPStates[key].sendNext - 1; retryISN != firstISN {
		t.Fatalf("SYN retry changed ISN from %d to %d", firstISN, retryISN)
	}
}

func TestFakeTCPFlowKeyIncludesSourceAndMatchesInterfaceWildcard(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.1:51820")
	one := &StdNetEndpoint{AddrPort: remote}
	one.SetSrc(netip.MustParseAddr("198.51.100.1"), 7)
	two := &StdNetEndpoint{AddrPort: remote}
	two.SetSrc(netip.MustParseAddr("198.51.100.2"), 7)
	if fakeTCPKey(one) == fakeTCPKey(two) {
		t.Fatal("different explicit source addresses share a flow key")
	}
	explicit := &StdNetBind{fakeTCPStates: map[fakeTCPFlowKey]*fakeTCPFlow{
		fakeTCPKey(one): {state: fakeTCPSYNSent},
	}}
	if _, flow := explicit.findFakeTCPFlowLocked(two); flow != nil {
		t.Fatal("different explicit source address matched an existing flow")
	}

	wildcard := &StdNetEndpoint{AddrPort: remote}
	wildcard.SetSrc(netip.Addr{}, 7)
	bind := &StdNetBind{fakeTCPStates: map[fakeTCPFlowKey]*fakeTCPFlow{
		fakeTCPKey(wildcard): {state: fakeTCPSYNSent},
	}}
	received := &StdNetEndpoint{AddrPort: remote}
	received.SetSrc(netip.MustParseAddr("198.51.100.9"), 7)
	key, flow := bind.findFakeTCPFlowLocked(received)
	if flow == nil || key != fakeTCPKey(wildcard) {
		t.Fatal("concrete PKTINFO source did not match interface-only flow")
	}
}

func TestPrepareFakeTCPReusesPassiveInterfaceFlow(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	bind := NewStdNetBind().(*StdNetBind)
	if err := bind.EnableFakeTCP(time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bind.Close(); err != nil {
			t.Error(err)
		}
	})

	remote := netip.MustParseAddrPort("127.0.0.1:1")
	received := &StdNetEndpoint{AddrPort: remote}
	received.SetSrc(netip.MustParseAddr("127.0.0.1"), int32(loopback.Index))
	if response, deliver := bind.handleFakeTCPPacket(received, fakeTCPPacket{
		flags: faketcp.TCPFlagSYN,
		seq:   100,
	}); response.flags != faketcp.TCPFlagSYN|faketcp.TCPFlagACK || deliver {
		t.Fatalf("passive SYN response=%#v deliver=%v", response, deliver)
	}
	passiveKey := fakeTCPKey(received)
	passiveFlow := bind.fakeTCPStates[passiveKey]

	interfaceOnly := &StdNetEndpoint{AddrPort: remote}
	interfaceOnly.SetSrc(netip.Addr{}, int32(loopback.Index))
	if err := bind.PrepareFakeTCP(interfaceOnly); !errors.Is(err, ErrFakeTCPNotEstablished) {
		t.Fatalf("PrepareFakeTCP error = %v", err)
	}
	if got := fakeTCPKey(interfaceOnly); got != passiveKey {
		t.Fatalf("prepared key = %#v, want passive key %#v", got, passiveKey)
	}
	if len(bind.fakeTCPStates) != 1 || bind.fakeTCPStates[passiveKey] != passiveFlow {
		t.Fatalf("flows after PrepareFakeTCP = %#v", bind.fakeTCPStates)
	}

	explicit := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:2")}
	explicit.SetSrc(netip.MustParseAddr("127.0.0.1"), int32(loopback.Index))
	explicitKey := fakeTCPKey(explicit)
	bind.fakeTCPStates[explicitKey] = &fakeTCPFlow{
		state:    fakeTCPSYNSent,
		sendNext: 201,
		lastSeen: time.Now(),
	}
	secondInterfaceOnly := &StdNetEndpoint{AddrPort: explicit.AddrPort}
	secondInterfaceOnly.SetSrc(netip.Addr{}, int32(loopback.Index))
	if err := bind.PrepareFakeTCP(secondInterfaceOnly); !errors.Is(err, ErrFakeTCPNotEstablished) {
		t.Fatalf("PrepareFakeTCP with explicit flow error = %v", err)
	}
	wildcardKey := fakeTCPKey(secondInterfaceOnly)
	if wildcardKey == explicitKey || bind.fakeTCPStates[wildcardKey] == bind.fakeTCPStates[explicitKey] {
		t.Fatal("interface-only endpoint reused an explicit-source flow")
	}
}

func assertSocketOption(t *testing.T, conn *net.UDPConn, level, option, want int) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptInt(int(fd), level, option)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if got != want {
		t.Fatalf("socket option (%d,%d) = %d, want %d", level, option, got, want)
	}
}
