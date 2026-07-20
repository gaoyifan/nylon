package conn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/faketcp"
	"golang.org/x/net/ipv6"
)

func frameFakeTCPPayload(payloads ...[]byte) []byte {
	var framed []byte
	for _, payload := range payloads {
		framed = binary.BigEndian.AppendUint16(framed, uint16(len(payload)))
		framed = append(framed, payload...)
	}
	return framed
}

func fakeTCPInboundCarrier(seq uint32, framed []byte) []byte {
	carrier := make([]byte, faketcp.CarrierHeaderSize+len(framed))
	binary.BigEndian.PutUint16(carrier[0:2], faketcp.CarrierMagic)
	carrier[3] = faketcp.TCPFlagACK
	binary.BigEndian.PutUint32(carrier[4:8], seq)
	copy(carrier[faketcp.CarrierHeaderSize:], framed)
	return carrier
}

type fakeTCPBatchInput struct {
	data []byte
	addr *net.UDPAddr
}

type fakeTCPBatchReader struct {
	inputs []fakeTCPBatchInput
	reads  int
}

func (r *fakeTCPBatchReader) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	r.reads++
	for i, input := range r.inputs {
		msgs[i].N = copy(msgs[i].Buffers[0], input.data)
		msgs[i].Addr = input.addr
	}
	return len(r.inputs), nil
}

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
		flags:   faketcp.TCPFlagACK,
		seq:     0x01020304,
		ack:     0x05060708,
		payload: payload,
	})
	if got := len(carrier); got != faketcp.CarrierHeaderSize+faketcp.FrameHeaderSize+len(payload) {
		t.Fatalf("carrier length = %d", got)
	}
	if got := binary.BigEndian.Uint16(carrier[0:2]); got != faketcp.CarrierMagic {
		t.Fatalf("magic = %#x", got)
	}
	framed := carrier[faketcp.CarrierHeaderSize:]
	if got := binary.BigEndian.Uint16(carrier[2:4]); got != faketcp.FoldPayloadChecksum(framed) {
		t.Fatalf("payload checksum contribution = %#x", got)
	}
	if got := binary.BigEndian.Uint32(carrier[4:8]); got != 0x01020304 {
		t.Fatalf("seq = %#x", got)
	}
	if got := binary.BigEndian.Uint32(carrier[8:12]); got != 0x05060708 {
		t.Fatalf("ack = %#x", got)
	}
	if got := binary.BigEndian.Uint16(framed[:faketcp.FrameHeaderSize]); got != uint16(len(payload)) {
		t.Fatalf("frame payload length = %d", got)
	}
	if got := framed[faketcp.FrameHeaderSize:]; !bytes.Equal(got, payload) {
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

	payload := frameFakeTCPPayload([]byte("wireguard datagram"))
	repeated, deliver := a.handleFakeTCPPacket(aEP, synACK)
	if repeated.flags != faketcp.TCPFlagACK || deliver {
		t.Fatalf("established SYN-ACK response = %#v, deliver=%v", repeated, deliver)
	}

	response, deliver = b.handleFakeTCPPacket(bEP, fakeTCPPacket{
		flags:   faketcp.TCPFlagACK,
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
		flags:   faketcp.TCPFlagACK,
		seq:     101,
		ack:     201,
		payload: frameFakeTCPPayload(payload),
	})

	if response.flags != 0 || !deliver {
		t.Fatalf("first data response=%#v deliver=%v", response, deliver)
	}
	flow := bind.fakeTCPStates[fakeTCPKey(ep)]
	if flow.state != fakeTCPEstablished || flow.recvNext != 101+uint32(faketcp.FrameHeaderSize+len(payload)) {
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
		receivedUnacked: fakeTCPStandaloneACKAfter - 3,
		lastSeen:        time.Now(),
	}

	response, deliver := bind.handleFakeTCPPacket(ep, fakeTCPPacket{
		flags:   faketcp.TCPFlagACK,
		seq:     20,
		payload: frameFakeTCPPayload([]byte{1}),
	})
	if response.flags != faketcp.TCPFlagACK || !deliver || response.ack != 23 {
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
		receivedUnacked: fakeTCPStandaloneACKAfter - 3,
		lastSeen:        time.Now(),
	}
	payload := []byte{1}
	carrier := marshalFakeTCPPacket(fakeTCPPacket{seq: 20, payload: payload})
	binary.BigEndian.PutUint16(carrier[2:4], uint16(faketcp.TCPFlagACK))

	framed, frames, consumed := bind.receiveFakeTCP(carrier, ep)

	if !consumed || frames != 1 || !bytes.Equal(framed, frameFakeTCPPayload(payload)) {
		t.Fatalf("received frames=%d consumed=%v payload=%x", frames, consumed, framed)
	}
}

func TestReceiveFakeTCPAggregateAndMalformedFraming(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.1:51820")
	first := []byte{0x01, 0x02, 0x03}
	second := []byte("a longer WireGuard datagram")
	framed := frameFakeTCPPayload(first, second)
	bind := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
	ep := &StdNetEndpoint{AddrPort: remote}
	flow := &fakeTCPFlow{
		state:    fakeTCPEstablished,
		sendNext: 10,
		recvNext: 20,
		lastSeen: time.Now(),
	}
	bind.fakeTCPStates[fakeTCPKey(ep)] = flow

	payload, frames, consumed := bind.receiveFakeTCP(fakeTCPInboundCarrier(20, framed), ep)
	if !consumed || frames != 2 || !bytes.Equal(payload, framed) {
		t.Fatalf("aggregate payload=%x frames=%d consumed=%v", payload, frames, consumed)
	}
	if flow.recvNext != 20+uint32(len(framed)) {
		t.Fatalf("receive high-water = %d, want %d", flow.recvNext, 20+len(framed))
	}
	if ep.Transport() != TransportFakeTCP {
		t.Fatalf("aggregate endpoint transport = %v", ep.Transport())
	}

	malformed := []struct {
		name   string
		framed []byte
	}{
		{name: "truncated length", framed: []byte{0x00}},
		{name: "zero length", framed: []byte{0x00, 0x00}},
		{name: "truncated payload", framed: []byte{0x00, 0x02, 0xaa}},
		{name: "trailing byte", framed: append(frameFakeTCPPayload([]byte{0xaa}), 0x00)},
	}
	for _, tt := range malformed {
		t.Run(tt.name, func(t *testing.T) {
			bind := &StdNetBind{fakeTCPStates: make(map[fakeTCPFlowKey]*fakeTCPFlow)}
			ep := &StdNetEndpoint{AddrPort: remote}
			flow := &fakeTCPFlow{
				state:           fakeTCPEstablished,
				sendNext:        10,
				recvNext:        20,
				receivedUnacked: 7,
				lastSeen:        time.Unix(123, 0),
			}
			bind.fakeTCPStates[fakeTCPKey(ep)] = flow
			before := *flow

			payload, frames, consumed := bind.receiveFakeTCP(fakeTCPInboundCarrier(20, tt.framed), ep)
			if !consumed || payload != nil || frames != 0 {
				t.Fatalf("malformed payload=%x frames=%d consumed=%v", payload, frames, consumed)
			}
			if *flow != before {
				t.Fatalf("malformed frame mutated flow: got %#v, want %#v", *flow, before)
			}
			if ep.Transport() != TransportUDP {
				t.Fatalf("malformed endpoint transport = %v", ep.Transport())
			}
		})
	}
}

func TestReceiveIPSplitsFakeTCPAggregate(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.1:51820")
	payloads := [][]byte{
		{0x01},
		[]byte("unequal second datagram"),
		{0x03, 0x04, 0x05, 0x06},
	}
	framed := frameFakeTCPPayload(payloads...)
	bind := NewStdNetBind().(*StdNetBind)
	ep := &StdNetEndpoint{AddrPort: remote}
	flow := &fakeTCPFlow{state: fakeTCPEstablished, sendNext: 10, recvNext: 20, lastSeen: time.Now()}
	bind.fakeTCPStates = map[fakeTCPFlowKey]*fakeTCPFlow{fakeTCPKey(ep): flow}
	reader := fakeTCPBatchReader{inputs: []fakeTCPBatchInput{{
		data: fakeTCPInboundCarrier(20, framed),
		addr: net.UDPAddrFromAddrPort(remote),
	}}}
	var pending fakeTCPPending
	bufs := make([][]byte, len(payloads)+1)
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, len(bufs))
	eps := make([]Endpoint, len(bufs))

	n, err := bind.receiveIP(&reader, nil, false, true, &pending, bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payloads) {
		t.Fatalf("received datagrams = %d, want %d", n, len(payloads))
	}
	for i, want := range payloads {
		if !bytes.Equal(bufs[i][:sizes[i]], want) {
			t.Fatalf("datagram %d = %x, want %x", i, bufs[i][:sizes[i]], want)
		}
		if eps[i] != eps[0] {
			t.Fatalf("datagram %d has a different endpoint", i)
		}
		gotEP, ok := eps[i].(*StdNetEndpoint)
		if !ok || gotEP.Transport() != TransportFakeTCP || gotEP.AddrPort != remote {
			t.Fatalf("datagram %d endpoint = %#v", i, eps[i])
		}
	}
	if flow.recvNext != 20+uint32(len(framed)) {
		t.Fatalf("receive high-water = %d, want %d", flow.recvNext, 20+len(framed))
	}
}

func TestReceiveIPDefersFakeTCPAggregateBeyondCapacity(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.1:51820")
	payloads := [][]byte{{1}, {2, 3}, {4, 5, 6}}
	framed := frameFakeTCPPayload(payloads...)
	bind := NewStdNetBind().(*StdNetBind)
	ep := &StdNetEndpoint{AddrPort: remote}
	flow := &fakeTCPFlow{state: fakeTCPEstablished, sendNext: 10, recvNext: 20, lastSeen: time.Now()}
	bind.fakeTCPStates = map[fakeTCPFlowKey]*fakeTCPFlow{fakeTCPKey(ep): flow}
	reader := fakeTCPBatchReader{inputs: []fakeTCPBatchInput{{
		data: fakeTCPInboundCarrier(20, framed),
		addr: net.UDPAddrFromAddrPort(remote),
	}}}
	var pending fakeTCPPending
	bufs := [][]byte{make([]byte, 128), make([]byte, 128)}
	sizes := make([]int, len(bufs))
	eps := make([]Endpoint, len(bufs))

	n, err := bind.receiveIP(&reader, nil, false, true, &pending, bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(bufs) {
		t.Fatalf("first read returned n=%d, want %d", n, len(bufs))
	}
	for i := range bufs {
		if !bytes.Equal(bufs[i][:sizes[i]], payloads[i]) {
			t.Fatalf("first read datagram %d = %x, want %x", i, bufs[i][:sizes[i]], payloads[i])
		}
	}

	n, err = bind.receiveIP(&reader, nil, false, true, &pending, bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], payloads[2]) {
		t.Fatalf("pending read returned n=%d payload=%x, want %x", n, bufs[0][:sizes[0]], payloads[2])
	}
	if reader.reads != 1 {
		t.Fatalf("socket reads = %d, want 1", reader.reads)
	}
	if flow.recvNext != 20+uint32(len(framed)) {
		t.Fatalf("receive high-water = %d, want %d", flow.recvNext, 20+len(framed))
	}
}

func TestFakeTCPPendingOwnsEndpoint(t *testing.T) {
	payloads := [][]byte{{1}, {2}}
	ep := fakeTCPEndpoint("192.0.2.1:51820")
	ep.src = []byte{3, 4}
	var pending fakeTCPPending
	pending.append(frameFakeTCPPayload(payloads...), ep, true)

	ep.SetTransport(TransportUDP)
	ep.src[0] = 5
	bufs := [][]byte{make([]byte, 8)}
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	if n := pending.receive(bufs, sizes, eps); n != 1 {
		t.Fatalf("first pending receive = %d, want 1", n)
	}
	firstEP := eps[0].(*StdNetEndpoint)
	if firstEP.Transport() != TransportFakeTCP || !bytes.Equal(firstEP.src, []byte{3, 4}) {
		t.Fatalf("first pending endpoint = %#v", firstEP)
	}
	firstEP.SetTransport(TransportUDP)
	firstEP.src[0] = 6

	if n := pending.receive(bufs, sizes, eps); n != 1 {
		t.Fatalf("second pending receive = %d, want 1", n)
	}
	secondEP := eps[0].(*StdNetEndpoint)
	if secondEP.Transport() != TransportFakeTCP || !bytes.Equal(secondEP.src, []byte{3, 4}) {
		t.Fatalf("second pending endpoint = %#v", secondEP)
	}
}

func TestReceiveIPDoesNotDrainPendingAfterClose(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	bind := NewStdNetBind().(*StdNetBind)
	bind.ipv4 = conn
	var pending fakeTCPPending
	pending.append([]byte{1}, fakeTCPEndpoint("192.0.2.1:51820"), false)
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}

	bufs := [][]byte{make([]byte, 8)}
	sizes := make([]int, 1)
	eps := make([]Endpoint, 1)
	n, err := bind.receiveIP(nil, conn, false, true, &pending, bufs, sizes, eps)
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive after close = (%d, %v), want (0, net.ErrClosed)", n, err)
	}
	if len(pending.packets) != 0 {
		t.Fatal("pending packets retained after close")
	}
}

func TestReceiveIPCompactsMixedFakeTCPBatch(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.1:51820")
	first := []byte{1, 2, 3}
	second := []byte("second framed datagram")
	framed := frameFakeTCPPayload(first, second)
	bind := NewStdNetBind().(*StdNetBind)
	ep := &StdNetEndpoint{AddrPort: remote}
	flow := &fakeTCPFlow{state: fakeTCPEstablished, sendNext: 10, recvNext: 20, lastSeen: time.Now()}
	bind.fakeTCPStates = map[fakeTCPFlowKey]*fakeTCPFlow{fakeTCPKey(ep): flow}
	addr := net.UDPAddrFromAddrPort(remote)
	reader := fakeTCPBatchReader{inputs: []fakeTCPBatchInput{
		{data: []byte("ordinary before"), addr: addr},
		{data: fakeTCPInboundCarrier(20, nil), addr: addr},
		{data: fakeTCPInboundCarrier(20, framed), addr: addr},
		{data: []byte("ordinary after"), addr: addr},
	}}
	var pending fakeTCPPending
	bufs := make([][]byte, 8)
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, len(bufs))
	eps := make([]Endpoint, len(bufs))

	n, err := bind.receiveIP(&reader, nil, false, true, &pending, bufs, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{[]byte("ordinary before"), first, second, []byte("ordinary after")}
	if n != len(want) {
		t.Fatalf("received datagrams = %d, want %d", n, len(want))
	}
	for i := range want {
		if !bytes.Equal(bufs[i][:sizes[i]], want[i]) {
			t.Fatalf("datagram %d = %x, want %x", i, bufs[i][:sizes[i]], want[i])
		}
	}
	if eps[0].(*StdNetEndpoint).Transport() != TransportUDP ||
		eps[3].(*StdNetEndpoint).Transport() != TransportUDP ||
		eps[1] != eps[2] || eps[1].(*StdNetEndpoint).Transport() != TransportFakeTCP {
		t.Fatalf("mixed endpoints = %#v", eps[:n])
	}
	if flow.recvNext != 20+uint32(len(framed)) {
		t.Fatalf("receive high-water = %d, want %d", flow.recvNext, 20+len(framed))
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
