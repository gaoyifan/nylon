package core

import (
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMplsLseRoundTrip(t *testing.T) {
	cases := []struct {
		label uint32
		tc    uint8
		bos   bool
		ttl   uint8
	}{
		{label: 1, tc: 0, bos: true, ttl: 64},
		{label: 0xFFFFF, tc: 7, bos: true, ttl: 1},
		{label: 0x12345, tc: 5, bos: false, ttl: 255},
		{label: 0, tc: 0, bos: false, ttl: 0},
	}
	for _, c := range cases {
		buf := make([]byte, device.MplsLseLen)
		encodeMplsLse(buf, c.label, c.tc, c.bos, c.ttl)
		label, tc, bos, ttl := decodeMplsLse(buf)
		assert.EqualValues(t, c.label, label, "label")
		assert.EqualValues(t, c.tc, tc, "tc")
		assert.Equal(t, c.bos, bos, "bos")
		assert.EqualValues(t, c.ttl, ttl, "ttl")
	}
}

func TestMplsLseLabelTruncatedToTwentyBits(t *testing.T) {
	buf := make([]byte, device.MplsLseLen)
	// labels above 0xFFFFF must not bleed into the tc/bos/ttl fields.
	encodeMplsLse(buf, 0x1FFFFF, 0, true, 0)
	label, _, bos, _ := decodeMplsLse(buf)
	assert.EqualValues(t, 0xFFFFF, label)
	assert.True(t, bos)
}

type lse struct {
	label uint32
	tc    uint8
	bos   bool
	ttl   uint8
}

// buildMplsElem frames a NyUnicast/MPLS packet with the given label stack and
// inner payload, laid out exactly as the dataplane would hand it to
// handleMplsPacket.
func buildMplsElem(t *testing.T, lses []lse, inner []byte) *device.TCElement {
	t.Helper()
	elem := &device.TCElement{Buffer: new([device.MaxMessageSize]byte)}
	off := device.MessageTransportHeaderSize
	payloadLen := 1 + len(lses)*device.MplsLseLen + len(inner)
	totalLen := device.PolyHeaderSize + payloadLen
	elem.Packet = elem.Buffer[off : off+totalLen]
	elem.SetIPVersion(NyUnicastProtoId)
	elem.SetLength(uint16(totalLen))
	pl := elem.Payload()
	pl[NyUnicastOffsetSubtype] = byte(NyUnicastSubtypeMpls)
	stack := pl[NyUnicastOffsetLse:]
	for i, l := range lses {
		encodeMplsLse(stack[i*device.MplsLseLen:], l.label, l.tc, l.bos, l.ttl)
	}
	copy(stack[len(lses)*device.MplsLseLen:], inner)
	return elem
}

func buildIPv4(t *testing.T, src, dst [4]byte) []byte {
	t.Helper()
	p := make([]byte, 20)
	p[0] = 0x45 // version 4, IHL 5
	p[device.IPv4offsetTotalLength] = byte(len(p) >> 8)
	p[device.IPv4offsetTotalLength+1] = byte(len(p))
	copy(p[device.IPv4offsetSrc:], src[:])
	copy(p[device.IPv4offsetDst:], dst[:])
	return p
}

const (
	testLocalNumeric = state.NodeIdNumeric(16)
	testPeerNumeric  = state.NodeIdNumeric(17)
	testInnerNumeric = state.NodeIdNumeric(100)
)

func testSnapshot(advertise bool, forward map[state.NodeIdNumeric]RouteTableEntry) *ExitFilterSnapshot {
	return &ExitFilterSnapshot{
		LocalIdNumeric:    testLocalNumeric,
		AdvertiseExitNode: advertise,
		NumericNames:      map[state.NodeIdNumeric]state.NodeId{},
		NodeForward:       forward,
	}
}

// Transit: outer label is for another node and a route exists -> forward to the
// next-hop peer with the MPLS TTL decremented and the stack otherwise intact.
func TestHandleMplsTransitForwards(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{1, 1, 1, 1})
	elem := buildMplsElem(t, []lse{{label: uint32(testPeerNumeric), bos: true, ttl: 64}}, inner)
	peer := &device.Peer{}
	snap := testSnapshot(true, map[state.NodeIdNumeric]RouteTableEntry{
		testPeerNumeric: {Nh: "peer", Peer: peer},
	})

	act, err := n.handleMplsPacket(elem, snap)
	require.NoError(t, err)
	assert.Equal(t, device.TcForward, act)
	assert.Same(t, peer, elem.ToPeer)
	_, _, _, ttl := decodeMplsLse(elem.Payload()[NyUnicastOffsetLse:])
	assert.EqualValues(t, 63, ttl, "transit must decrement MPLS TTL")
}

// Transit with no route -> drop.
func TestHandleMplsTransitNoRouteDrops(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{1, 1, 1, 1})
	elem := buildMplsElem(t, []lse{{label: uint32(testPeerNumeric), bos: true, ttl: 64}}, inner)
	snap := testSnapshot(true, map[state.NodeIdNumeric]RouteTableEntry{})

	act, err := n.handleMplsPacket(elem, snap)
	assert.Error(t, err)
	assert.Equal(t, device.TcDrop, act)
}

// Terminal, single (bottom-of-stack) label -> strip the whole stack and bounce
// the inner IP packet as a plain IP frame (L3Proto stays 0).
func TestHandleMplsTerminalDecapsIP(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8})
	elem := buildMplsElem(t, []lse{{label: uint32(testLocalNumeric), bos: true, ttl: 64}}, inner)
	snap := testSnapshot(true, nil)

	act, err := n.handleMplsPacket(elem, snap)
	require.NoError(t, err)
	assert.Equal(t, device.TcBounce, act)
	assert.EqualValues(t, 0, elem.L3Proto, "decapsulated IP must not carry an MPLS ethertype")
	assert.Equal(t, inner, elem.Packet, "Packet must be the inner IP packet, label stack stripped")
}

// Terminal, more labels below ours -> pop only our (outer) label and bounce the
// remaining MPLS packet, tagged with the MPLS ethertype for the TUN.
func TestHandleMplsTerminalPopsOuterLabel(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8})
	lses := []lse{
		{label: uint32(testLocalNumeric), tc: 0, bos: false, ttl: 64},
		{label: uint32(testInnerNumeric), tc: 3, bos: true, ttl: 33},
	}
	elem := buildMplsElem(t, lses, inner)
	snap := testSnapshot(true, nil)

	act, err := n.handleMplsPacket(elem, snap)
	require.NoError(t, err)
	assert.Equal(t, device.TcBounce, act)
	assert.EqualValues(t, tun.EthPMplsUnicast, elem.L3Proto, "popped MPLS frame must carry the MPLS ethertype")

	// The remaining packet is the inner label stack (LSE2 + IP) verbatim.
	require.GreaterOrEqual(t, len(elem.Packet), device.MplsLseLen)
	label, tc, bos, ttl := decodeMplsLse(elem.Packet[:device.MplsLseLen])
	assert.EqualValues(t, testInnerNumeric, label, "exposed label must be the inner label")
	assert.EqualValues(t, 3, tc)
	assert.True(t, bos, "inner label was bottom-of-stack")
	assert.EqualValues(t, 33, ttl, "inner label TTL preserved")
	assert.Equal(t, inner, elem.Packet[device.MplsLseLen:], "inner IP payload preserved byte-for-byte")
}

// TTL exhausted -> drop regardless of destination.
func TestHandleMplsTTLExceededDrops(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8})
	elem := buildMplsElem(t, []lse{{label: uint32(testLocalNumeric), bos: true, ttl: 0}}, inner)
	snap := testSnapshot(true, nil)

	act, err := n.handleMplsPacket(elem, snap)
	assert.Error(t, err)
	assert.Equal(t, device.TcDrop, act)
}

// Terminal but the node does not advertise exit service -> drop (both the IP and
// the MPLS-pop terminal paths are gated on this).
func TestHandleMplsTerminalNotAdvertisingDrops(t *testing.T) {
	n := &Nylon{}
	inner := buildIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8})

	single := buildMplsElem(t, []lse{{label: uint32(testLocalNumeric), bos: true, ttl: 64}}, inner)
	act, err := n.handleMplsPacket(single, testSnapshot(false, nil))
	assert.Error(t, err)
	assert.Equal(t, device.TcDrop, act)

	multi := buildMplsElem(t, []lse{
		{label: uint32(testLocalNumeric), bos: false, ttl: 64},
		{label: uint32(testInnerNumeric), bos: true, ttl: 64},
	}, inner)
	act, err = n.handleMplsPacket(multi, testSnapshot(false, nil))
	assert.Error(t, err)
	assert.Equal(t, device.TcDrop, act)
}
