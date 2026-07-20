//go:build linux && !android && (amd64 || arm64)

package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	testManagedPort = 51820
	testRemotePort  = 443
	tcxNext         = ^uint32(0)
	tcxDrop         = 2
)

func TestTransformerPrograms(t *testing.T) {
	requirePrivilegedTests(t)

	spec, err := loadTransformer()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Variables["managed_port"].Set(uint16(testManagedPort)); err != nil {
		t.Fatal(err)
	}
	var objects transformerObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			t.Fatalf("%+v", verifierError)
		}
		t.Fatalf("%+v", err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Error(err)
		}
	})

	tests := []struct {
		name    string
		version int
		flags   uint8
		ack     uint32
		trailer []byte
	}{
		{
			name:    "IPv4 data",
			version: 4,
			flags:   TCPFlagACK,
			ack:     0x50607080,
			trailer: testFakeTCPFrame([]byte{0xde, 0xad, 0xbe, 0xef, 0x7a}),
		},
		{
			name:    "IPv6 data",
			version: 6,
			flags:   TCPFlagACK,
			ack:     0x50607080,
			trailer: testFakeTCPFrame([]byte{0xde, 0xad, 0xbe, 0xef, 0x7a}),
		},
		{
			name:    "four-byte framed data",
			version: 4,
			flags:   TCPFlagACK,
			ack:     0x50607080,
			trailer: testFakeTCPFrame([]byte{0, 0}),
		},
		{
			name:    "IPv4 SYN",
			version: 4,
			flags:   TCPFlagSYN,
			trailer: []byte{1, 3, 3, 14},
		},
		{
			name:    "IPv6 SYN",
			version: 6,
			flags:   TCPFlagSYN,
			trailer: []byte{1, 3, 3, 14},
		},
		{
			name:    "IPv4 SYN-ACK with zero ACK",
			version: 4,
			flags:   TCPFlagSYN | TCPFlagACK,
			trailer: []byte{1, 3, 3, 14},
		},
		{
			name:    "IPv4 ACK",
			version: 4,
			flags:   TCPFlagACK,
			ack:     0x50607080,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const sequence = 0x10203040
			carrier := testCarrierFrame(test.version, testManagedPort, sequence, test.ack, test.flags, test.trailer)

			action, tcpPacket, err := objects.FakeTcpEgress.Test(carrier)
			if err != nil {
				t.Fatal(err)
			}
			if action != tcxNext {
				t.Fatalf("egress action = %d, want TCX_NEXT", action)
			}
			assertTCPPacket(t, tcpPacket, test.version, sequence, test.ack, test.flags, test.trailer)
			tcpPacket = reverseTCPDirection(t, tcpPacket, test.version)

			action, udpPacket, err := objects.FakeTcpIngress.Test(tcpPacket)
			if err != nil {
				t.Fatal(err)
			}
			if action != tcxNext {
				t.Fatalf("ingress action = %d, want TCX_NEXT", action)
			}
			assertInboundUDPCarrier(t, udpPacket, test.version, sequence, test.ack, test.flags, test.trailer)
		})
	}

	t.Run("aggregated TCP carrier", func(t *testing.T) {
		const sequence = 0x10203040
		first := testFakeTCPFrame([]byte{0xde, 0xad, 0xbe, 0xef, 0x7a})
		second := testFakeTCPFrame([]byte{1, 2, 3})
		framed := append(append([]byte(nil), first...), second...)
		carrier := testCarrierFrame(4, testManagedPort, sequence, 0x50607080,
			TCPFlagACK, framed)
		_, tcpPacket, err := objects.FakeTcpEgress.Test(carrier)
		if err != nil {
			t.Fatal(err)
		}
		tcpPacket = reverseTCPDirection(t, tcpPacket, 4)

		const (
			skbContextSize = 192
			gsoSegsOffset  = 164
			gsoSizeOffset  = 176
		)
		context := make([]byte, skbContextSize)
		binary.NativeEndian.PutUint32(context[gsoSegsOffset:], 2)
		binary.NativeEndian.PutUint32(context[gsoSizeOffset:], uint32(len(first)))
		run := &ebpf.RunOptions{
			Data:    tcpPacket,
			DataOut: make([]byte, len(tcpPacket)+258),
			Context: context,
			Repeat:  1,
		}
		action, err := objects.FakeTcpIngress.Run(run)
		if err != nil {
			t.Fatal(err)
		}
		if action != tcxNext {
			t.Fatalf("ingress action = %d, want TCX_NEXT", action)
		}
		assertInboundUDPCarrier(t, run.DataOut, 4, sequence, 0x50607080,
			TCPFlagACK, framed)
	})

	t.Run("ordinary UDP with magic", func(t *testing.T) {
		packet := testCarrierFrame(4, testManagedPort, 0x10203040, 0x50607080,
			TCPFlagACK, testFakeTCPFrame([]byte{0xde, 0xad, 0xbe, 0xef}))
		l4Offset := 14 + 20
		checksum := transportChecksum(packet)
		if checksum == 0 {
			t.Fatal("ordinary UDP fixture has a zero checksum")
		}
		binary.BigEndian.PutUint16(packet[l4Offset+6:l4Offset+8], checksum)
		original := bytes.Clone(packet)

		action, output, err := objects.FakeTcpEgress.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		if action != tcxNext {
			t.Fatalf("egress action = %d, want TCX_NEXT", action)
		}
		if !bytes.Equal(output, original) {
			t.Fatal("ordinary UDP packet was modified")
		}
	})

	t.Run("carrier from wrong source port", func(t *testing.T) {
		packet := testCarrierFrame(4, testManagedPort+1, 0x10203040, 0x50607080,
			TCPFlagACK, testFakeTCPFrame([]byte{0xde, 0xad, 0xbe, 0xef}))
		original := bytes.Clone(packet)
		action, output, err := objects.FakeTcpEgress.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		if action != tcxNext {
			t.Fatalf("egress action = %d, want TCX_NEXT", action)
		}
		if !bytes.Equal(output, original) {
			t.Fatal("UDP packet from an unmanaged source port was modified")
		}
	})
}

func TestAttachLoopback(t *testing.T) {
	requirePrivilegedTests(t)

	manager, err := Attach(testManagedPort, []string{"lo"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
}

func requirePrivilegedTests(t *testing.T) {
	t.Helper()
	if os.Getenv("NYLON_PRIVILEGED_TESTS") != "1" {
		t.Skip("set NYLON_PRIVILEGED_TESTS=1 to run kernel BPF tests")
	}
}

func testFakeTCPFrame(payload []byte) []byte {
	frame := make([]byte, FrameHeaderSize+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[FrameHeaderSize:], payload)
	return frame
}

func testCarrierFrame(version int, sourcePort uint16, sequence, acknowledgement uint32, flags uint8, trailer []byte) []byte {
	l4Length := 20 + len(trailer)
	ipLength := 20
	etherType := uint16(0x0800)
	if version == 6 {
		ipLength = 40
		etherType = 0x86dd
	}
	packet := make([]byte, 14+ipLength+l4Length)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], etherType)
	if version == 4 {
		packet[14] = 0x45
		binary.BigEndian.PutUint16(packet[16:18], uint16(ipLength+l4Length))
		binary.BigEndian.PutUint16(packet[18:20], 0x1234)
		packet[22] = 64
		packet[23] = 17
		copy(packet[26:30], []byte{192, 0, 2, 1})
		copy(packet[30:34], []byte{198, 51, 100, 2})
		binary.BigEndian.PutUint16(packet[24:26], internetChecksum(packet[14:34]))
	} else {
		packet[14] = 0x60
		binary.BigEndian.PutUint16(packet[18:20], uint16(l4Length))
		packet[20] = 17
		packet[21] = 64
		copy(packet[22:38], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		copy(packet[38:54], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	}

	l4Offset := 14 + ipLength
	binary.BigEndian.PutUint16(packet[l4Offset:l4Offset+2], sourcePort)
	binary.BigEndian.PutUint16(packet[l4Offset+2:l4Offset+4], testRemotePort)
	binary.BigEndian.PutUint16(packet[l4Offset+4:l4Offset+6], uint16(l4Length))
	binary.BigEndian.PutUint16(packet[l4Offset+8:l4Offset+10], CarrierMagic)
	if flags&TCPFlagSYN == 0 && len(trailer) > 0 {
		binary.BigEndian.PutUint16(packet[l4Offset+10:l4Offset+12], FoldPayloadChecksum(trailer))
	} else {
		binary.BigEndian.PutUint16(packet[l4Offset+10:l4Offset+12], uint16(flags))
	}
	binary.BigEndian.PutUint32(packet[l4Offset+12:l4Offset+16], sequence)
	binary.BigEndian.PutUint32(packet[l4Offset+16:l4Offset+20], acknowledgement)
	copy(packet[l4Offset+20:], trailer)
	return packet
}

func assertTCPPacket(t *testing.T, packet []byte, version int, sequence, acknowledgement uint32, flags uint8, trailer []byte) {
	t.Helper()
	l4Offset, protocol := testL4OffsetAndProtocol(t, packet, version)
	if protocol != 6 {
		t.Fatalf("IP protocol = %d, want TCP", protocol)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset : l4Offset+2]); got != testManagedPort {
		t.Fatalf("TCP source port = %d, want %d", got, testManagedPort)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+2 : l4Offset+4]); got != testRemotePort {
		t.Fatalf("TCP destination port = %d, want %d", got, testRemotePort)
	}
	if got := binary.BigEndian.Uint32(packet[l4Offset+4 : l4Offset+8]); got != sequence {
		t.Fatalf("TCP sequence = %#x, want %#x", got, sequence)
	}
	if got := binary.BigEndian.Uint32(packet[l4Offset+8 : l4Offset+12]); got != acknowledgement {
		t.Fatalf("TCP acknowledgement = %#x, want %#x", got, acknowledgement)
	}
	wantDataOffset := byte(0x50)
	if flags&TCPFlagSYN != 0 {
		wantDataOffset = 0x60
	}
	if packet[l4Offset+12] != wantDataOffset {
		t.Fatalf("TCP data offset = %#x, want %#x", packet[l4Offset+12], wantDataOffset)
	}
	if packet[l4Offset+13] != flags {
		t.Fatalf("TCP flags = %#x, want %#x", packet[l4Offset+13], flags)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+14 : l4Offset+16]); got != 0xffff {
		t.Fatalf("TCP window = %#x, want 0xffff", got)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+18 : l4Offset+20]); got != 0 {
		t.Fatalf("TCP urgent pointer = %#x, want 0", got)
	}
	if !bytes.Equal(packet[l4Offset+20:], trailer) {
		t.Fatalf("TCP trailer = %x, want %x", packet[l4Offset+20:], trailer)
	}
	if got := transportChecksum(packet); got != 0 {
		t.Fatalf("TCP checksum verification = %#x, want 0", got)
	}
	assertIPv4Checksum(t, packet, version)
}

func assertInboundUDPCarrier(t *testing.T, packet []byte, version int, sequence, acknowledgement uint32, flags uint8, trailer []byte) {
	t.Helper()
	l4Offset, protocol := testL4OffsetAndProtocol(t, packet, version)
	if protocol != 17 {
		t.Fatalf("IP protocol = %d, want UDP", protocol)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset : l4Offset+2]); got != testRemotePort {
		t.Fatalf("UDP source port = %d, want %d", got, testRemotePort)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+2 : l4Offset+4]); got != testManagedPort {
		t.Fatalf("UDP destination port = %d, want %d", got, testManagedPort)
	}
	if got, want := binary.BigEndian.Uint16(packet[l4Offset+4:l4Offset+6]), len(packet)-l4Offset; int(got) != want {
		t.Fatalf("UDP length = %d, want %d", got, want)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+6 : l4Offset+8]); got != 0 {
		t.Fatalf("UDP checksum = %#x, want 0", got)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+8 : l4Offset+10]); got != CarrierMagic {
		t.Fatalf("carrier magic = %#x, want %#x", got, CarrierMagic)
	}
	if got := binary.BigEndian.Uint16(packet[l4Offset+10 : l4Offset+12]); got != uint16(flags) {
		t.Fatalf("carrier flags = %#x, want %#x", got, flags)
	}
	if got := binary.BigEndian.Uint32(packet[l4Offset+12 : l4Offset+16]); got != sequence {
		t.Fatalf("carrier sequence = %#x, want %#x", got, sequence)
	}
	if got := binary.BigEndian.Uint32(packet[l4Offset+16 : l4Offset+20]); got != acknowledgement {
		t.Fatalf("carrier acknowledgement = %#x, want %#x", got, acknowledgement)
	}
	if !bytes.Equal(packet[l4Offset+20:], trailer) {
		t.Fatalf("carrier trailer = %x, want %x", packet[l4Offset+20:], trailer)
	}
	assertIPv4Checksum(t, packet, version)
}

func reverseTCPDirection(t *testing.T, packet []byte, version int) []byte {
	t.Helper()
	packet = bytes.Clone(packet)
	var mac [6]byte
	copy(mac[:], packet[0:6])
	copy(packet[0:6], packet[6:12])
	copy(packet[6:12], mac[:])

	l4Offset, protocol := testL4OffsetAndProtocol(t, packet, version)
	if protocol != 6 {
		t.Fatalf("IP protocol = %d, want TCP", protocol)
	}
	if version == 4 {
		var address [4]byte
		copy(address[:], packet[26:30])
		copy(packet[26:30], packet[30:34])
		copy(packet[30:34], address[:])
		packet[24], packet[25] = 0, 0
		binary.BigEndian.PutUint16(packet[24:26], internetChecksum(packet[14:34]))
	} else {
		var address [16]byte
		copy(address[:], packet[22:38])
		copy(packet[22:38], packet[38:54])
		copy(packet[38:54], address[:])
	}
	packet[l4Offset], packet[l4Offset+1], packet[l4Offset+2], packet[l4Offset+3] =
		packet[l4Offset+2], packet[l4Offset+3], packet[l4Offset], packet[l4Offset+1]
	packet[l4Offset+16], packet[l4Offset+17] = 0, 0
	checksum := transportChecksum(packet)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[l4Offset+16:l4Offset+18], checksum)
	if got := transportChecksum(packet); got != 0 {
		t.Fatalf("reversed TCP checksum verification = %#x, want 0", got)
	}
	return packet
}

func testL4OffsetAndProtocol(t *testing.T, packet []byte, version int) (int, byte) {
	t.Helper()
	if version == 4 {
		return 14 + int(packet[14]&0x0f)*4, packet[23]
	}
	return 14 + 40, packet[20]
}

func assertIPv4Checksum(t *testing.T, packet []byte, version int) {
	t.Helper()
	if version == 4 && internetChecksum(packet[14:34]) != 0 {
		t.Fatal("invalid IPv4 header checksum")
	}
}

func transportChecksum(packet []byte) uint16 {
	if packet[14]>>4 == 4 {
		l4Offset := 14 + int(packet[14]&0x0f)*4
		l4Length := int(binary.BigEndian.Uint16(packet[16:18])) - (l4Offset - 14)
		pseudoHeader := make([]byte, 12)
		copy(pseudoHeader[0:8], packet[26:34])
		pseudoHeader[9] = packet[23]
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(l4Length))
		return internetChecksum(pseudoHeader, packet[l4Offset:l4Offset+l4Length])
	}
	l4Offset := 14 + 40
	l4Length := int(binary.BigEndian.Uint16(packet[18:20]))
	pseudoHeader := make([]byte, 40)
	copy(pseudoHeader[0:32], packet[22:54])
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(l4Length))
	pseudoHeader[39] = packet[20]
	return internetChecksum(pseudoHeader, packet[l4Offset:l4Offset+l4Length])
}

func internetChecksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for len(part) >= 2 {
			sum += uint32(part[0])<<8 | uint32(part[1])
			part = part[2:]
		}
		if len(part) == 1 {
			sum += uint32(part[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
