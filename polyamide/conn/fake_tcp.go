package conn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/encodeous/nylon/polyamide/faketcp"
)

const (
	fakeTCPStateLimit         = 65536
	fakeTCPStandaloneACKAfter = 32 * 1024 * 1024
)

var (
	ErrFakeTCPNotEstablished = errors.New("fake TCP connection is not established")
	ErrFakeTCPNotConfigured  = errors.New("fake TCP is not configured")
	ErrFakeTCPUnsupported    = errors.New("fake TCP requires Linux on amd64 or arm64")
	ErrFakeTCPStateLimit     = errors.New("fake TCP state limit reached")
)

type fakeTCPState uint8

const (
	fakeTCPSYNSent fakeTCPState = iota
	fakeTCPSYNReceived
	fakeTCPEstablished
)

type fakeTCPFlowKey struct {
	remote netip.AddrPort
	local  netip.Addr
	ifidx  int32
}

type fakeTCPFlow struct {
	state           fakeTCPState
	sendNext        uint32
	recvNext        uint32
	receivedUnacked uint64
	lastSeen        time.Time
	passive         bool
}

type fakeTCPPacket struct {
	flags   uint8
	seq     uint32
	ack     uint32
	payload []byte
}

// EnableFakeTCP enables fake-TCP before Open.
func (s *StdNetBind) EnableFakeTCP(staleAfter time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipv4 != nil || s.ipv6 != nil || s.fakeIPv4 != nil || s.fakeIPv6 != nil {
		return ErrBindAlreadyOpen
	}
	if !fakeTCPPlatformSupported() {
		return ErrFakeTCPUnsupported
	}
	s.fakeTCPEnabled = true
	s.fakeTCPStaleAfter = staleAfter
	return nil
}

// PrepareFakeTCP starts or retries the proactive handshake for endpoint. The
// endpoint remains unavailable until this method observes an established flow.
func (s *StdNetBind) PrepareFakeTCP(ep *StdNetEndpoint) error {
	s.mu.Lock()
	enabled := s.fakeTCPEnabled
	open := s.ipv4 != nil || s.ipv6 != nil
	s.mu.Unlock()
	if !enabled {
		return ErrFakeTCPNotConfigured
	}
	if !open {
		return net.ErrClosed
	}

	now := time.Now()
	key := fakeTCPKey(ep)
	s.fakeTCPMu.Lock()
	s.cleanupFakeTCPStatesLocked(now, false)
	flow := s.fakeTCPStates[key]
	if flow == nil && key.local.IsUnspecified() {
		// A passive SYN may arrive before an interface-only endpoint is
		// prepared, so its flow is keyed by the concrete PKTINFO address.
		// Reuse that flow instead of creating a second sequence space.
		for candidateKey, candidate := range s.fakeTCPStates {
			if candidateKey.remote != key.remote || candidateKey.ifidx != key.ifidx ||
				!candidateKey.local.IsValid() || candidateKey.local.IsUnspecified() || !candidate.passive {
				continue
			}
			if flow == nil || candidate.lastSeen.After(flow.lastSeen) {
				key, flow = candidateKey, candidate
			}
		}
		if flow != nil {
			ep.SetSrc(key.local, key.ifidx)
		}
	}
	if flow != nil && flow.state == fakeTCPEstablished {
		s.fakeTCPMu.Unlock()
		return nil
	}
	if flow == nil {
		if len(s.fakeTCPStates) >= fakeTCPStateLimit {
			s.cleanupFakeTCPStatesLocked(now, true)
			if len(s.fakeTCPStates) >= fakeTCPStateLimit {
				s.fakeTCPMu.Unlock()
				return ErrFakeTCPStateLimit
			}
		}
		flow = &fakeTCPFlow{
			state:    fakeTCPSYNSent,
			sendNext: fakeTCPRandomISN() + 1,
			lastSeen: now,
		}
		s.fakeTCPStates[key] = flow
	}
	packet := fakeTCPPacket{
		flags: faketcp.TCPFlagSYN,
		seq:   flow.sendNext - 1,
	}
	if flow.state == fakeTCPSYNReceived {
		packet.flags |= faketcp.TCPFlagACK
		packet.ack = flow.recvNext
	}
	s.fakeTCPMu.Unlock()

	err := s.sendFakeTCPPackets(ep, []fakeTCPPacket{packet})
	if err != nil {
		return errors.Join(ErrFakeTCPNotEstablished, err)
	}
	return ErrFakeTCPNotEstablished
}

func fakeTCPKey(ep *StdNetEndpoint) fakeTCPFlowKey {
	return fakeTCPFlowKey{remote: ep.AddrPort, local: ep.SrcIP(), ifidx: ep.SrcIfidx()}
}

// A concrete source received through PKTINFO first matches its exact flow, then
// falls back to an interface-only flow that was opened with an unspecified
// source. Explicit source binds continue to use their exact keys.
func (s *StdNetBind) findFakeTCPFlowLocked(ep *StdNetEndpoint) (fakeTCPFlowKey, *fakeTCPFlow) {
	key := fakeTCPKey(ep)
	if flow := s.fakeTCPStates[key]; flow != nil {
		return key, flow
	}
	if !key.local.IsValid() || key.local.IsUnspecified() {
		return key, nil
	}
	wildcard := netip.IPv6Unspecified()
	if key.local.Is4() {
		wildcard = netip.IPv4Unspecified()
	}
	wildcardKey := fakeTCPFlowKey{remote: key.remote, local: wildcard, ifidx: key.ifidx}
	if flow := s.fakeTCPStates[wildcardKey]; flow != nil {
		return wildcardKey, flow
	}
	return key, nil
}

func fakeTCPRandomISN() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (s *StdNetBind) cleanupFakeTCPStatesLocked(now time.Time, force bool) {
	if s.fakeTCPStaleAfter <= 0 {
		return
	}
	if !force && !s.fakeTCPLastClean.IsZero() && now.Sub(s.fakeTCPLastClean) < s.fakeTCPStaleAfter {
		return
	}
	for key, flow := range s.fakeTCPStates {
		if now.Sub(flow.lastSeen) >= s.fakeTCPStaleAfter {
			delete(s.fakeTCPStates, key)
		}
	}
	s.fakeTCPLastClean = now
}

// handleFakeTCPPacket consumes a carrier received after ingress TCX has put the
// observed TCP flags in meta. It returns WireGuard payload only for established
// data packets and returns a control response separately so no socket write is
// performed while fakeTCPMu is held.
func (s *StdNetBind) handleFakeTCPPacket(ep *StdNetEndpoint, packet fakeTCPPacket) (fakeTCPPacket, bool) {
	now := time.Now()
	s.fakeTCPMu.Lock()
	defer s.fakeTCPMu.Unlock()
	s.cleanupFakeTCPStatesLocked(now, false)
	key, flow := s.findFakeTCPFlowLocked(ep)

	if packet.flags&faketcp.TCPFlagRST != 0 || packet.flags&faketcp.TCPFlagFIN != 0 {
		delete(s.fakeTCPStates, key)
		return fakeTCPPacket{}, false
	}

	if packet.flags&faketcp.TCPFlagSYN != 0 {
		if packet.flags&faketcp.TCPFlagACK == 0 {
			if flow != nil && flow.state == fakeTCPEstablished {
				return fakeTCPPacket{}, false
			}
			if flow == nil {
				if len(s.fakeTCPStates) >= fakeTCPStateLimit {
					s.cleanupFakeTCPStatesLocked(now, true)
					if len(s.fakeTCPStates) >= fakeTCPStateLimit {
						return fakeTCPPacket{}, false
					}
				}
				flow = &fakeTCPFlow{sendNext: fakeTCPRandomISN() + 1, passive: true}
				s.fakeTCPStates[key] = flow
			} else if flow.state == fakeTCPSYNReceived && flow.recvNext != packet.seq+1 {
				flow.sendNext = fakeTCPRandomISN() + 1
			}
			flow.state = fakeTCPSYNReceived
			flow.recvNext = packet.seq + 1
			flow.receivedUnacked = 0
			flow.lastSeen = now
			return fakeTCPPacket{
				flags: faketcp.TCPFlagSYN | faketcp.TCPFlagACK,
				seq:   flow.sendNext - 1,
				ack:   flow.recvNext,
			}, false
		}

		if flow != nil && flow.state == fakeTCPEstablished {
			if packet.ack == flow.sendNext && packet.seq+1 == flow.recvNext {
				flow.lastSeen = now
				return fakeTCPPacket{
					flags: faketcp.TCPFlagACK,
					seq:   flow.sendNext,
					ack:   flow.recvNext,
				}, false
			}
			return fakeTCPPacket{}, false
		}
		if flow == nil ||
			(flow.state != fakeTCPSYNSent && flow.state != fakeTCPSYNReceived) ||
			packet.ack != flow.sendNext {
			return fakeTCPPacket{}, false
		}
		flow.state = fakeTCPEstablished
		flow.recvNext = packet.seq + 1
		flow.lastSeen = now
		return fakeTCPPacket{
			flags: faketcp.TCPFlagACK,
			seq:   flow.sendNext,
			ack:   flow.recvNext,
		}, false
	}

	if flow == nil {
		return fakeTCPPacket{}, false
	}
	if flow.state == fakeTCPSYNReceived && packet.flags&faketcp.TCPFlagACK != 0 && packet.ack == flow.sendNext {
		if len(packet.payload) != 0 && packet.seq != flow.recvNext {
			return fakeTCPPacket{}, false
		}
		flow.state = fakeTCPEstablished
		flow.lastSeen = now
		if len(packet.payload) == 0 {
			return fakeTCPPacket{}, false
		}
	}
	if flow.state != fakeTCPEstablished {
		return fakeTCPPacket{}, false
	}
	flow.lastSeen = now
	if len(packet.payload) == 0 {
		return fakeTCPPacket{}, false
	}

	end := packet.seq + uint32(len(packet.payload))
	if int32(end-flow.recvNext) > 0 {
		flow.receivedUnacked += uint64(uint32(end - flow.recvNext))
		flow.recvNext = end
	}
	if flow.receivedUnacked >= fakeTCPStandaloneACKAfter {
		flow.receivedUnacked = 0
		return fakeTCPPacket{
			flags: faketcp.TCPFlagACK,
			seq:   flow.sendNext,
			ack:   flow.recvNext,
		}, true
	}
	return fakeTCPPacket{}, true
}

func marshalFakeTCPPacket(packet fakeTCPPacket) []byte {
	length := faketcp.CarrierHeaderSize + len(packet.payload)
	if packet.flags&faketcp.TCPFlagSYN != 0 {
		length += faketcp.SYNOptionSize
	} else if len(packet.payload) > 0 {
		length += faketcp.FrameHeaderSize
	}
	var carrier []byte
	// WireGuard relinquishes its oversized message buffer after Send.
	if len(packet.payload) > 0 && cap(packet.payload) >= length {
		carrier = packet.payload[:length]
	} else {
		carrier = make([]byte, length)
	}
	if len(packet.payload) > 0 {
		copy(carrier[faketcp.CarrierHeaderSize+faketcp.FrameHeaderSize:], packet.payload)
	}
	binary.BigEndian.PutUint16(carrier[0:2], faketcp.CarrierMagic)
	if len(packet.payload) > 0 {
		binary.BigEndian.PutUint16(carrier[faketcp.CarrierHeaderSize:], uint16(len(packet.payload)))
		binary.BigEndian.PutUint16(carrier[2:4], faketcp.FoldPayloadChecksum(carrier[faketcp.CarrierHeaderSize:]))
	} else {
		carrier[3] = packet.flags
	}
	binary.BigEndian.PutUint32(carrier[4:8], packet.seq)
	binary.BigEndian.PutUint32(carrier[8:12], packet.ack)
	if packet.flags&faketcp.TCPFlagSYN != 0 {
		copy(carrier[12:16], []byte{1, 3, 3, 14})
	}
	return carrier
}

func nextFakeTCPFrame(data []byte) (frame, remaining []byte, ok bool) {
	if len(data) < faketcp.FrameHeaderSize {
		return nil, nil, false
	}
	length := int(binary.BigEndian.Uint16(data[:faketcp.FrameHeaderSize]))
	if length < faketcp.MinFramePayloadSize || length > len(data)-faketcp.FrameHeaderSize {
		return nil, nil, false
	}
	end := faketcp.FrameHeaderSize + length
	return data[faketcp.FrameHeaderSize:end], data[end:], true
}

func (s *StdNetBind) sendFakeTCPPackets(ep *StdNetEndpoint, packets []fakeTCPPacket) error {
	s.mu.Lock()
	conn := s.fakeIPv4
	writer := batchWriter(s.fakeIPv4PC)
	if ep.DstIP().Is6() {
		conn = s.fakeIPv6
		writer = s.fakeIPv6PC
	}
	s.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if ep.DstIP().Is6() {
		as16 := ep.DstIP().As16()
		ua.IP = ua.IP[:16]
		copy(ua.IP, as16[:])
	} else {
		as4 := ep.DstIP().As4()
		ua.IP = ua.IP[:4]
		copy(ua.IP, as4[:])
	}
	ua.Port = int(ep.Port())
	for i, packet := range packets {
		(*msgs)[i].Addr = ua
		(*msgs)[i].Buffers[0] = marshalFakeTCPPacket(packet)
		setSrcControl(&(*msgs)[i].OOB, ep)
	}
	return s.send(conn, writer, (*msgs)[:len(packets)])
}

func (s *StdNetBind) sendFakeTCPData(bufs [][]byte, ep *StdNetEndpoint) error {
	s.fakeTCPMu.Lock()
	_, flow := s.findFakeTCPFlowLocked(ep)
	if flow == nil || flow.state != fakeTCPEstablished {
		s.fakeTCPMu.Unlock()
		return ErrFakeTCPNotEstablished
	}
	var packets [IdealBatchSize]fakeTCPPacket
	for i, buf := range bufs {
		packets[i] = fakeTCPPacket{
			flags:   faketcp.TCPFlagACK,
			seq:     flow.sendNext,
			ack:     flow.recvNext,
			payload: buf,
		}
		flow.sendNext += uint32(faketcp.FrameHeaderSize + len(buf))
	}
	flow.receivedUnacked = 0
	s.fakeTCPMu.Unlock()
	return s.sendFakeTCPPackets(ep, packets[:len(bufs)])
}

func (s *StdNetBind) receiveFakeTCP(carrier []byte, ep *StdNetEndpoint) ([]byte, int, bool) {
	if len(carrier) < 2 || binary.BigEndian.Uint16(carrier[:2]) != faketcp.CarrierMagic {
		return nil, 0, false
	}
	if len(carrier) < faketcp.CarrierHeaderSize {
		return nil, 0, true
	}
	flags := uint8(binary.BigEndian.Uint16(carrier[2:4]))
	payloadAt := faketcp.CarrierHeaderSize
	if flags&faketcp.TCPFlagSYN != 0 {
		if len(carrier) < faketcp.CarrierHeaderSize+faketcp.SYNOptionSize {
			return nil, 0, true
		}
		payloadAt += faketcp.SYNOptionSize
	}
	payload := carrier[payloadAt:]
	frameCount := 0
	if flags&faketcp.TCPFlagSYN == 0 && len(payload) > 0 {
		for remaining := payload; len(remaining) > 0; frameCount++ {
			_, next, ok := nextFakeTCPFrame(remaining)
			if !ok {
				return nil, 0, true
			}
			remaining = next
		}
	}
	packet := fakeTCPPacket{
		flags:   flags,
		seq:     binary.BigEndian.Uint32(carrier[4:8]),
		ack:     binary.BigEndian.Uint32(carrier[8:12]),
		payload: payload,
	}
	ep.SetTransport(TransportFakeTCP)
	response, deliver := s.handleFakeTCPPacket(ep, packet)
	if response.flags != 0 {
		_ = s.sendFakeTCPPackets(ep, []fakeTCPPacket{response})
	}
	if !deliver {
		return nil, 0, true
	}
	return payload, frameCount, true
}
