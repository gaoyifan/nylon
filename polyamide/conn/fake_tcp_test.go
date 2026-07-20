package conn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/faketcp"
)

func fakeTCPEndpoint(address string) *StdNetEndpoint {
	ep := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort(address)}
	ep.SetTransport(TransportFakeTCP)
	return ep
}

func TestStdNetEndpointTransportDefaultsToUDP(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	ep, err := bind.ParseEndpoint("192.0.2.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	std := ep.(*StdNetEndpoint)
	if got := std.Transport(); got != TransportUDP {
		t.Fatalf("parsed transport = %v, want UDP", got)
	}
	std.SetTransport(TransportFakeTCP)
	if got := std.Transport(); got != TransportFakeTCP {
		t.Fatalf("set transport = %v, want fake TCP", got)
	}
}

func TestFakeTCPCarrierEncoding(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	carrier := marshalFakeTCPPacket(fakeTCPPacket{
		flags:   faketcp.TCPFlagACK | faketcp.TCPFlagPSH,
		seq:     0x01020304,
		ack:     0x05060708,
		payload: payload,
	})
	if got := len(carrier); got != faketcp.CarrierHeaderSize+len(payload) {
		t.Fatalf("carrier length = %d", got)
	}
	if got := binary.BigEndian.Uint16(carrier[0:2]); got != faketcp.CarrierMagic {
		t.Fatalf("magic = %#x", got)
	}
	if got := binary.BigEndian.Uint16(carrier[2:4]); got != faketcp.FoldPayloadChecksum(payload) {
		t.Fatalf("payload checksum contribution = %#x", got)
	}
	if got := binary.BigEndian.Uint32(carrier[4:8]); got != 0x01020304 {
		t.Fatalf("seq = %#x", got)
	}
	if got := binary.BigEndian.Uint32(carrier[8:12]); got != 0x05060708 {
		t.Fatalf("ack = %#x", got)
	}
	if got := carrier[faketcp.CarrierHeaderSize:]; string(got) != string(payload) {
		t.Fatalf("payload = %x", got)
	}

	syn := marshalFakeTCPPacket(fakeTCPPacket{flags: faketcp.TCPFlagSYN, seq: 9})
	if got := len(syn); got != faketcp.CarrierHeaderSize+faketcp.SYNOptionSize {
		t.Fatalf("SYN carrier length = %d", got)
	}
	if got := binary.BigEndian.Uint16(syn[2:4]); got != uint16(faketcp.TCPFlagSYN) {
		t.Fatalf("SYN meta flags = %#x", got)
	}
	if got := syn[faketcp.CarrierHeaderSize:]; string(got) != string([]byte{1, 3, 3, 14}) {
		t.Fatalf("SYN options = %x", got)
	}

	ack := marshalFakeTCPPacket(fakeTCPPacket{flags: faketcp.TCPFlagACK, seq: 1, ack: 2})
	if got := ack[3]; got != faketcp.TCPFlagACK {
		t.Fatalf("ACK meta flags = %#x", got)
	}
}

func TestFakeTCPActivePassiveHandshakeAndData(t *testing.T) {
	now := time.Now()
	a := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	b := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	aEP := fakeTCPEndpoint("192.0.2.2:51820")
	bEP := fakeTCPEndpoint("192.0.2.1:51820")
	a.fakeTCPStates[fakeTCPKey(aEP)] = &fakeTCPFlow{
		state:    fakeTCPSYNSent,
		sendNext: 101,
		lastSeen: now,
	}

	synACK, deliver := b.handleFakeTCPPacket(bEP, fakeTCPPacket{
		flags: faketcp.TCPFlagSYN,
		seq:   100,
	})
	if deliver || synACK.flags != faketcp.TCPFlagSYN|faketcp.TCPFlagACK || synACK.ack != 101 {
		t.Fatalf("passive SYN result = %#v, deliver=%v", synACK, deliver)
	}
	ack, deliver := a.handleFakeTCPPacket(aEP, synACK)
	if deliver || ack.flags != faketcp.TCPFlagACK {
		t.Fatalf("active SYN-ACK result = %#v, deliver=%v", ack, deliver)
	}
	response, deliver := b.handleFakeTCPPacket(bEP, ack)
	if response.flags != 0 || deliver {
		t.Fatalf("final ACK response=%#v deliver=%v", response, deliver)
	}
	if a.fakeTCPStates[fakeTCPKey(aEP)].state != fakeTCPEstablished || b.fakeTCPStates[fakeTCPKey(bEP)].state != fakeTCPEstablished {
		t.Fatal("both sides did not reach established")
	}

	payload := []byte("wireguard datagram")
	repeated, deliver := a.handleFakeTCPPacket(aEP, synACK)
	if repeated.flags != faketcp.TCPFlagACK || deliver {
		t.Fatalf("established SYN-ACK response = %#v, deliver=%v", repeated, deliver)
	}

	response, deliver = b.handleFakeTCPPacket(bEP, fakeTCPPacket{
		flags:   faketcp.TCPFlagACK | faketcp.TCPFlagPSH,
		seq:     101,
		ack:     synACK.seq + 1,
		payload: payload,
	})
	if response.flags != 0 || !deliver {
		t.Fatalf("data response=%#v deliver=%v", response, deliver)
	}
	if got := b.fakeTCPStates[fakeTCPKey(bEP)].recvNext; got != 101+uint32(len(payload)) {
		t.Fatalf("receive high-water = %d", got)
	}

	newSYN, deliver := b.handleFakeTCPPacket(bEP, fakeTCPPacket{flags: faketcp.TCPFlagSYN, seq: 500})
	flow := b.fakeTCPStates[fakeTCPKey(bEP)]
	if newSYN.flags != 0 || deliver || flow.state != fakeTCPEstablished || flow.recvNext != 101+uint32(len(payload)) {
		t.Fatalf("established SYN result=%#v deliver=%v flow=%#v", newSYN, deliver, flow)
	}

	b.handleFakeTCPPacket(bEP, fakeTCPPacket{flags: faketcp.TCPFlagRST})
	if _, ok := b.fakeTCPStates[fakeTCPKey(bEP)]; ok {
		t.Fatal("RST did not delete flow")
	}
}

func TestFakeTCPFirstDataCompletesPassiveHandshake(t *testing.T) {
	bind := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	ep := fakeTCPEndpoint("192.0.2.1:51820")
	bind.fakeTCPStates[fakeTCPKey(ep)] = &fakeTCPFlow{
		state:    fakeTCPSYNReceived,
		sendNext: 201,
		recvNext: 101,
		lastSeen: time.Now(),
	}
	payload := []byte("first datagram after a lost final ACK")

	response, deliver := bind.handleFakeTCPPacket(ep, fakeTCPPacket{
		flags:   faketcp.TCPFlagACK | faketcp.TCPFlagPSH,
		seq:     101,
		ack:     201,
		payload: payload,
	})

	if response.flags != 0 || !deliver {
		t.Fatalf("first data response=%#v deliver=%v", response, deliver)
	}
	flow := bind.fakeTCPStates[fakeTCPKey(ep)]
	if flow.state != fakeTCPEstablished || flow.recvNext != 101+uint32(len(payload)) {
		t.Fatalf("flow after first data = %#v", flow)
	}
}

func TestFakeTCPSimultaneousOpen(t *testing.T) {
	a := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	b := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	aEP := fakeTCPEndpoint("192.0.2.2:51820")
	bEP := fakeTCPEndpoint("192.0.2.1:51820")
	a.fakeTCPStates[fakeTCPKey(aEP)] = &fakeTCPFlow{state: fakeTCPSYNSent, sendNext: 11, lastSeen: time.Now()}
	b.fakeTCPStates[fakeTCPKey(bEP)] = &fakeTCPFlow{state: fakeTCPSYNSent, sendNext: 21, lastSeen: time.Now()}

	aSYNACK, deliver := a.handleFakeTCPPacket(aEP, fakeTCPPacket{flags: faketcp.TCPFlagSYN, seq: 20})
	if aSYNACK.flags == 0 || deliver {
		t.Fatalf("A simultaneous SYN: response=%#v deliver=%v", aSYNACK, deliver)
	}
	bSYNACK, deliver := b.handleFakeTCPPacket(bEP, fakeTCPPacket{flags: faketcp.TCPFlagSYN, seq: 10})
	if bSYNACK.flags == 0 || deliver {
		t.Fatalf("B simultaneous SYN: response=%#v deliver=%v", bSYNACK, deliver)
	}
	if response, deliver := a.handleFakeTCPPacket(aEP, bSYNACK); response.flags == 0 || deliver {
		t.Fatalf("A simultaneous SYN-ACK: response=%#v deliver=%v", response, deliver)
	}
	if response, deliver := b.handleFakeTCPPacket(bEP, aSYNACK); response.flags == 0 || deliver {
		t.Fatalf("B simultaneous SYN-ACK: response=%#v deliver=%v", response, deliver)
	}
	if a.fakeTCPStates[fakeTCPKey(aEP)].state != fakeTCPEstablished || b.fakeTCPStates[fakeTCPKey(bEP)].state != fakeTCPEstablished {
		t.Fatal("simultaneous open did not establish both flows")
	}
}

func TestFakeTCPStateLimitDropsPassiveSYN(t *testing.T) {
	bind := &StdNetBind{
		fakeTCPStates:     make(map[fakeTCPFlowKey]*fakeTCPFlow, fakeTCPStateLimit),
		fakeTCPStaleAfter: time.Hour,
	}
	now := time.Now()
	for i := 0; i < fakeTCPStateLimit; i++ {
		bind.fakeTCPStates[fakeTCPFlowKey{
			remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 1),
		}] = &fakeTCPFlow{state: fakeTCPEstablished, lastSeen: now}
	}
	response, deliver := bind.handleFakeTCPPacket(fakeTCPEndpoint("203.0.113.1:51820"), fakeTCPPacket{
		flags: faketcp.TCPFlagSYN,
		seq:   1,
	})
	if deliver || response.flags != 0 || response.seq != 0 || response.ack != 0 || response.payload != nil {
		t.Fatalf("full table SYN = %#v, deliver=%v", response, deliver)
	}
	if len(bind.fakeTCPStates) != fakeTCPStateLimit {
		t.Fatalf("state count = %d", len(bind.fakeTCPStates))
	}
}

func TestFakeTCPStandaloneACKAfter32MiB(t *testing.T) {
	bind := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	ep := fakeTCPEndpoint("192.0.2.1:51820")
	bind.fakeTCPStates[fakeTCPKey(ep)] = &fakeTCPFlow{
		state:           fakeTCPEstablished,
		sendNext:        10,
		recvNext:        20,
		receivedUnacked: fakeTCPStandaloneACKAfter - 1,
		lastSeen:        time.Now(),
	}

	response, deliver := bind.handleFakeTCPPacket(ep, fakeTCPPacket{
		flags:   faketcp.TCPFlagACK | faketcp.TCPFlagPSH,
		seq:     20,
		payload: []byte{1},
	})
	if response.flags != faketcp.TCPFlagACK || !deliver || response.ack != 21 {
		t.Fatalf("standalone ACK response=%#v deliver=%v", response, deliver)
	}
}

func TestReceiveFakeTCPDeliversDataWhenACKSendFails(t *testing.T) {
	bind := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	ep := fakeTCPEndpoint("192.0.2.1:51820")
	bind.fakeTCPStates[fakeTCPKey(ep)] = &fakeTCPFlow{
		state:           fakeTCPEstablished,
		sendNext:        10,
		recvNext:        20,
		receivedUnacked: fakeTCPStandaloneACKAfter - 1,
		lastSeen:        time.Now(),
	}
	payload := []byte{1}
	carrier := marshalFakeTCPPacket(fakeTCPPacket{seq: 20, payload: payload})
	binary.BigEndian.PutUint16(carrier[2:4], uint16(faketcp.TCPFlagACK|faketcp.TCPFlagPSH))

	size, consumed := bind.receiveFakeTCP(carrier, ep)

	if !consumed || size != len(payload) || carrier[0] != payload[0] {
		t.Fatalf("received size=%d consumed=%v payload=%x", size, consumed, carrier[:size])
	}
}

func TestPrepareFakeTCPNotConfigured(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	ep := fakeTCPEndpoint("192.0.2.1:51820")
	if err := bind.PrepareFakeTCP(ep); !errors.Is(err, ErrFakeTCPNotConfigured) {
		t.Fatalf("unconfigured fake TCP error = %v", err)
	}
}

func TestFakeTCPCloseKeepsStateMapWritable(t *testing.T) {
	bind := &StdNetBind{fakeTCPStates: map[fakeTCPFlowKey]*fakeTCPFlow{{}: {}}}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	bind.fakeTCPStates[fakeTCPFlowKey{}] = &fakeTCPFlow{}
}
