/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/encodeous/nylon/perf"
	"github.com/encodeous/nylon/polyamide/faketcp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ Bind = (*StdNetBind)(nil)
)

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind struct {
	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv6          *net.UDPConn
	fakeIPv4      *net.UDPConn
	fakeIPv6      *net.UDPConn
	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv6PC        *ipv6.PacketConn // will be nil on non-Linux
	fakeIPv4PC    *ipv4.PacketConn
	fakeIPv6PC    *ipv6.PacketConn
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	blackhole4 bool
	blackhole6 bool

	fakeTCPEnabled    bool
	fakeTCPStaleAfter time.Duration
	fakeTCPMu         sync.Mutex
	fakeTCPStates     map[fakeTCPFlowKey]*fakeTCPFlow
	fakeTCPLastClean  time.Time
}

func NewStdNetBind() Bind {
	return &StdNetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if
	// supported. Typically this is a PKTINFO structure from/for control
	// messages, see unix.PKTINFO for an example.
	src []byte
	// transport selects the wire carrier used for this endpoint. The zero value
	// is UDP so endpoints produced by ParseEndpoint and receive paths retain the
	// existing behavior unless explicitly changed.
	transport Transport
}

// Transport identifies the wire carrier used for an endpoint.
type Transport uint8

const (
	TransportUDP Transport = iota
	TransportFakeTCP
)

func (e *StdNetEndpoint) Transport() Transport { return e.transport }

func (e *StdNetEndpoint) SetTransport(transport Transport) { e.transport = transport }

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (e *StdNetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See control_default,linux, etc for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e *StdNetEndpoint) DstIPPort() netip.AddrPort {
	return e.AddrPort
}

func listenNet(network string, port int, control controlFn) (*net.UDPConn, int, error) {
	config := listenConfig()
	if control != nil {
		config = listenConfig(control)
	}
	conn, err := config.ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil || s.fakeIPv4 != nil || s.fakeIPv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn, fakeV4conn, fakeV6conn *net.UDPConn
	closeOpened := func() {
		for _, conn := range []*net.UDPConn{v4conn, v6conn, fakeV4conn, fakeV6conn} {
			if conn != nil {
				_ = conn.Close()
			}
		}
	}
	var control controlFn
	if s.fakeTCPEnabled {
		control = fakeTCPListenControl(false)
	}
	var selectedPort int
	v4conn, selectedPort, err = listenNet("udp4", port, control)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	if err == nil {
		port = selectedPort
	}
	if v4conn != nil && s.fakeTCPEnabled {
		fakeV4conn, _, err = listenNet("udp4", port, fakeTCPListenControl(true))
		if err != nil {
			closeOpened()
			return nil, 0, err
		}
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, selectedPort, err = listenNet("udp6", port, control)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		closeOpened()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		closeOpened()
		return nil, 0, err
	}
	if err == nil {
		port = selectedPort
	}
	if v6conn != nil && s.fakeTCPEnabled {
		fakeV6conn, _, err = listenNet("udp6", port, fakeTCPListenControl(true))
		if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			closeOpened()
			tries++
			goto again
		}
		if err != nil {
			closeOpened()
			return nil, 0, err
		}
	}
	var fns []ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		var v4pc *ipv4.PacketConn
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload, s.fakeTCPEnabled))
		s.ipv4 = v4conn
	}
	if fakeV4conn != nil {
		s.fakeIPv4PC = ipv4.NewPacketConn(fakeV4conn)
		fns = append(fns, s.makeReceiveIPv4(s.fakeIPv4PC, fakeV4conn, false, true))
		s.fakeIPv4 = fakeV4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		var v6pc *ipv6.PacketConn
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.ipv6PC = v6pc
		}
		fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload, s.fakeTCPEnabled))
		s.ipv6 = v6conn
	}
	if fakeV6conn != nil {
		s.fakeIPv6PC = ipv6.NewPacketConn(fakeV6conn)
		fns = append(fns, s.makeReceiveIPv6(s.fakeIPv6PC, fakeV6conn, false, true))
		s.fakeIPv6 = fakeV6conn
	}
	if len(fns) == 0 {
		closeOpened()
		return nil, 0, syscall.EAFNOSUPPORT
	}
	if s.fakeTCPEnabled {
		s.fakeTCPMu.Lock()
		s.fakeTCPStates = make(map[fakeTCPFlowKey]*fakeTCPFlow)
		s.fakeTCPLastClean = time.Time{}
		s.fakeTCPMu.Unlock()
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

var (
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

type fakeTCPPendingPacket struct {
	data   []byte
	ep     *StdNetEndpoint
	framed bool
}

type fakeTCPPending struct {
	packets []fakeTCPPendingPacket
}

func (p *fakeTCPPending) append(data []byte, ep *StdNetEndpoint, framed bool) {
	pendingEP := *ep
	pendingEP.src = append([]byte(nil), ep.src...)
	p.packets = append(p.packets, fakeTCPPendingPacket{
		data:   append([]byte(nil), data...),
		ep:     &pendingEP,
		framed: framed,
	})
}

func (p *fakeTCPPending) receive(bufs [][]byte, sizes []int, eps []Endpoint) int {
	n := 0
	for n < len(bufs) && len(p.packets) > 0 {
		packet := &p.packets[0]
		if packet.framed {
			length := int(binary.BigEndian.Uint16(packet.data[:faketcp.FrameHeaderSize]))
			sizes[n] = copy(bufs[n], packet.data[faketcp.FrameHeaderSize:faketcp.FrameHeaderSize+length])
			packet.data = packet.data[faketcp.FrameHeaderSize+length:]
		} else {
			sizes[n] = copy(bufs[n], packet.data)
			packet.data = nil
		}
		eps[n] = packet.ep
		n++
		if len(packet.data) == 0 {
			*packet = fakeTCPPendingPacket{}
			p.packets = p.packets[1:]
		} else {
			pendingEP := *packet.ep
			pendingEP.src = append([]byte(nil), packet.ep.src...)
			packet.ep = &pendingEP
		}
	}
	if len(p.packets) == 0 {
		p.packets = nil
	}
	return n
}

func (s *StdNetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	fakeTCPEnabled bool,
	pending *fakeTCPPending,
	bufs [][]byte,
	sizes []int,
	eps []Endpoint,
) (n int, err error) {
	if fakeTCPEnabled {
		if len(pending.packets) > 0 {
			if conn != nil {
				s.mu.Lock()
				closed := conn != s.ipv4 && conn != s.ipv6 && conn != s.fakeIPv4 && conn != s.fakeIPv6
				if closed {
					pending.packets = nil
					s.mu.Unlock()
					return 0, net.ErrClosed
				}
			}
			n := pending.receive(bufs, sizes, eps)
			if conn != nil {
				s.mu.Unlock()
			}
			perf.RecvBatchSize.Add(float64(n))
			return n, nil
		}
	}

	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	var numMsgs int
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if rxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	perf.RecvsPerSecond.Add(1)
	if !fakeTCPEnabled {
		for i := 0; i < numMsgs; i++ {
			msg := &(*msgs)[i]
			sizes[i] = msg.N
			if msg.N == 0 {
				continue
			}
			addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
			ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
			getSrcFromControl(msg.OOB[:msg.NN], ep)
			eps[i] = ep
		}
		perf.RecvBatchSize.Add(float64(numMsgs))
		return numMsgs, nil
	}

	var frameCounts [IdealBatchSize]int
	retained := 0
	total := 0
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		if msg.N == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		outputCount := 1
		payload, frames, carrier := s.receiveFakeTCP(msg.Buffers[0][:msg.N], ep)
		if carrier {
			if frames == 0 {
				continue
			}
			available := len(bufs) - total
			if available == 0 {
				pending.append(payload, ep, true)
				continue
			}
			payloadAt := len(payload)
			if frames > available {
				payloadAt = 0
				for range available {
					length := int(binary.BigEndian.Uint16(payload[payloadAt : payloadAt+faketcp.FrameHeaderSize]))
					payloadAt += faketcp.FrameHeaderSize + length
				}
				pending.append(payload[payloadAt:], ep, true)
				frames = available
			}
			msg.N = copy(bufs[retained], payload[:payloadAt])
			frameCounts[retained] = frames
			outputCount = frames
		} else if total == len(bufs) {
			pending.append(msg.Buffers[0][:msg.N], ep, false)
			continue
		} else if retained != i {
			msg.N = copy(bufs[retained], msg.Buffers[0][:msg.N])
		}
		sizes[retained] = msg.N
		eps[retained] = ep
		retained++
		total += outputCount
	}
	if total == 0 {
		sizes[0] = 0
		perf.RecvBatchSize.Add(1)
		return 1, nil
	}

	outputAt := total
	for i := retained - 1; i >= 0; i-- {
		frames := frameCounts[i]
		if frames == 0 {
			outputAt--
			if outputAt != i {
				sizes[outputAt] = copy(bufs[outputAt], bufs[i][:sizes[i]])
				eps[outputAt] = eps[i]
			}
			continue
		}

		outputAt -= frames
		framed := bufs[i][:sizes[i]]
		ep := eps[i]
		at := 0
		for j := 0; j < frames; j++ {
			length := int(binary.BigEndian.Uint16(framed[at : at+faketcp.FrameHeaderSize]))
			at += faketcp.FrameHeaderSize
			sizes[outputAt+j] = copy(bufs[outputAt+j], framed[at:at+length])
			eps[outputAt+j] = ep
			at += length
		}
	}
	perf.RecvBatchSize.Add(float64(total))
	return total, nil
}

func (s *StdNetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload, fakeTCPEnabled bool) ReceiveFunc {
	var pending fakeTCPPending
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, fakeTCPEnabled, &pending, bufs, sizes, eps)
	}
}

func (s *StdNetBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload, fakeTCPEnabled bool) ReceiveFunc {
	var pending fakeTCPPending
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, fakeTCPEnabled, &pending, bufs, sizes, eps)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var closeErrors []error
	if s.ipv4 != nil {
		closeErrors = append(closeErrors, s.ipv4.Close())
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	if s.ipv6 != nil {
		closeErrors = append(closeErrors, s.ipv6.Close())
		s.ipv6 = nil
		s.ipv6PC = nil
	}
	if s.fakeIPv4 != nil {
		closeErrors = append(closeErrors, s.fakeIPv4.Close())
		s.fakeIPv4 = nil
		s.fakeIPv4PC = nil
	}
	if s.fakeIPv6 != nil {
		closeErrors = append(closeErrors, s.fakeIPv6.Close())
		s.fakeIPv6 = nil
		s.fakeIPv6PC = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	s.fakeTCPMu.Lock()
	clear(s.fakeTCPStates)
	s.fakeTCPLastClean = time.Time{}
	s.fakeTCPMu.Unlock()
	return errors.Join(closeErrors...)
}

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint) error {
	ep, ok := endpoint.(*StdNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	if ep.Transport() == TransportFakeTCP {
		return s.sendFakeTCPData(bufs, ep)
	}
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		br = s.ipv6PC
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := endpoint.DstIP().As16()
		ua.IP = ua.IP[:16]
		copy(ua.IP, as16[:])
	} else {
		as4 := endpoint.DstIP().As4()
		ua.IP = ua.IP[:4]
		copy(ua.IP, as4[:])
	}
	ua.Port = int(ep.Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, ep, bufs, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			setSrcControl(&(*msgs)[i].OOB, ep)
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			perf.SendBatchSize.Add(float64(n))
			perf.SendsPerSecond.Add(1)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
		perf.SendsPerSecond.Add(float64(len(msgs)))
		perf.SendBatchSize.Add(1)
	}
	return err
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// This is a hard limit imposed by the kernel.
	udpSegmentMaxDatagrams = 64
)

type setGSOFunc func(control *[]byte, gsoSize uint16)

func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint, bufs [][]byte, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of bufs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		if i > 0 {
			msgLen := len(buf)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type getGSOFunc func(control []byte) (int, error)

func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = getGSO(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		control := append([]byte(nil), msg.OOB[:msg.NN]...)
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].OOB = append(msgs[n].OOB[:0], control...)
			msgs[n].NN = len(control)
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}
