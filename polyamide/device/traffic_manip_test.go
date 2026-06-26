package device

import (
	"encoding/binary"
	"testing"
)

func TestParsePacketRejectsLengthBeyondReadBuffer(t *testing.T) {
	var buf [MaxMessageSize]byte
	packet := buf[MessageTransportHeaderSize : MessageTransportHeaderSize+2016]
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[IPv6offsetPayloadLength:IPv6offsetPayloadLength+2], 2010)

	elem := &TCElement{
		Buffer: &buf,
		Packet: packet,
	}

	if elem.ParsePacket() {
		t.Fatal("expected oversized packet to be rejected")
	}
}

func TestParsePacketTrimsToAdvertisedLength(t *testing.T) {
	var buf [MaxMessageSize]byte
	packet := buf[MessageTransportHeaderSize : MessageTransportHeaderSize+128]
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[IPv6offsetPayloadLength:IPv6offsetPayloadLength+2], 8)

	elem := &TCElement{
		Buffer: &buf,
		Packet: packet,
	}

	if !elem.ParsePacket() {
		t.Fatal("expected valid packet to parse")
	}
	if len(elem.Packet) != 48 {
		t.Fatalf("expected packet length 48, got %d", len(elem.Packet))
	}
}

func TestFrameMplsUnicast(t *testing.T) {
	elem := &TCElement{Buffer: &[MaxMessageSize]byte{}}
	offset := MessageTransportHeaderSize

	// A single MPLS LSE (label 5, ttl 64, bottom-of-stack) followed by an
	// inner IPv4 header.
	mpls := []byte{0x00, 0x00, 0x51, 0x40, 0x45, 0x00, 0x00, 0x1c, 0xde, 0xad}
	copy(elem.Buffer[offset:], mpls)

	const protoId, subtype = 9, 1
	newSize := elem.FrameMplsUnicast(offset, len(mpls), protoId, subtype)
	if newSize != len(mpls)+PolyHeaderSize+1 {
		t.Fatalf("newSize = %d, want %d", newSize, len(mpls)+PolyHeaderSize+1)
	}

	if got := elem.Buffer[offset] >> 4; got != protoId {
		t.Fatalf("poly proto id nibble = %d, want %d", got, protoId)
	}
	wantPayloadLen := uint16(len(mpls) + 1) // subtype byte + mpls bytes
	if got := binary.BigEndian.Uint16(elem.Buffer[offset+PolyOffsetPayloadLength : offset+PolyOffsetPayloadLength+2]); got != wantPayloadLen {
		t.Fatalf("poly payload length = %d, want %d", got, wantPayloadLen)
	}
	if got := elem.Buffer[offset+PolyHeaderSize]; got != subtype {
		t.Fatalf("subtype = %d, want %d", got, subtype)
	}
	// the original MPLS bytes must be preserved verbatim after the prefix.
	got := elem.Buffer[offset+PolyHeaderSize+1 : offset+PolyHeaderSize+1+len(mpls)]
	for i := range mpls {
		if got[i] != mpls[i] {
			t.Fatalf("byte %d = 0x%x, want 0x%x (mpls payload corrupted)", i, got[i], mpls[i])
		}
	}

	// Validate length round-trips through GetLength (poly branch).
	elem.Packet = elem.Buffer[offset : offset+newSize]
	if l := int(elem.GetLength()); l != newSize {
		t.Fatalf("GetLength() = %d, want %d", l, newSize)
	}
}
