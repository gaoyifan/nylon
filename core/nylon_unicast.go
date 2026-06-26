package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
)

// NyUnicast is a generic node-to-node tunnel packet type carried inside the
// polyamide TC layer. It carves out a subtype byte so the same encapsulation
// can be reused for future node-targeted features without re-inventing the
// wire format each time.
//
// Wire format (all integers big-endian):
//
//	+---------------------+----------+-----------------+------------------+
//	| poly outer header   | subtype  | MPLS LSE        | subtype payload  |
//	| (PolyHeaderSize=3)  | (1 byte) | (MplsLseLen=4)  |                  |
//	+---------------------+----------+-----------------+------------------+
//
// Poly outer header (managed by polyamide):
//
//	byte 0   : NyUnicastProtoId << 4 (so the IP-version nibble reads as 9)
//	bytes 1-2: payload length (total packet length minus PolyHeaderSize)
//
// NyUnicast payload header (this package):
//
//	byte 0   : subtype (see NyUnicastSubtype*)
//	bytes 1-4: a single MPLS label-stack entry
//	             label (20 bits) : destination NodeIdNumeric
//	             tc    (3 bits)  : traffic class, passed through unchanged
//	             s     (1 bit)   : bottom-of-stack
//	             ttl   (8 bits)  : hop limit, decremented at every transit node
//	bytes 5+ : subtype-specific payload
//
// For NyUnicastSubtypeMpls the destination is the MPLS label (isomorphic to the
// node's numeric id) and, when the bottom-of-stack bit is set, the payload is the
// original IPv4/IPv6 packet emitted by the origin's TUN. The exit node strips
// the label and "unwraps" the inner packet into the local stack. No source node
// id is carried, so there is no source-ownership validation at the exit.
const (
	NyUnicastProtoId    = 9
	NyUnicastHeaderSize = 1 + device.MplsLseLen // subtype + MPLS LSE
	NyUnicastDefaultTTL = 64

	NyUnicastOffsetSubtype = 0
	NyUnicastOffsetLse     = 1
)

type NyUnicastSubtype byte

const (
	// NyUnicastSubtypeMpls wraps a single-entry MPLS label stack whose label
	// is the destination node id. When the bottom-of-stack bit is set the
	// stacked payload is an IPv4/IPv6 packet to be emitted at the exit node.
	NyUnicastSubtypeMpls NyUnicastSubtype = 1
)

// encodeMplsLse writes a single MPLS label-stack entry into b[:device.MplsLseLen].
func encodeMplsLse(b []byte, label uint32, tc uint8, bos bool, ttl uint8) {
	var s uint32
	if bos {
		s = 1
	}
	v := (label&0xFFFFF)<<12 | uint32(tc&0x7)<<9 | s<<8 | uint32(ttl)
	binary.BigEndian.PutUint32(b[:device.MplsLseLen], v)
}

// decodeMplsLse parses a single MPLS label-stack entry from b[:device.MplsLseLen].
func decodeMplsLse(b []byte) (label uint32, tc uint8, bos bool, ttl uint8) {
	v := binary.BigEndian.Uint32(b[:device.MplsLseLen])
	label = v >> 12
	tc = uint8((v >> 9) & 0x7)
	bos = (v>>8)&0x1 == 1
	ttl = uint8(v)
	return
}

// ExitFilterSnapshot is an immutable view of all the state the exit filter
// needs to make a decision: local identity, exit configuration, the numeric
// node-id mapping, and the numeric-keyed next-hop forwarding table.
//
// It is rebuilt by the dispatch goroutine on three occasions: at startup,
// after every central config apply, and after every route mutation. The
// filter only ever loads (and never mutates) the pointer. This keeps the
// dataplane path lock-free and entirely free of references into the live
// LocalCfg / CentralCfg / RouterState structures.
type ExitFilterSnapshot struct {
	// Local identity.
	LocalId        state.NodeId
	LocalIdNumeric state.NodeIdNumeric

	// Local capabilities.
	AdvertiseExitNode bool
	ExitNode          state.NodeId        // empty => not configured to use an exit
	ExitNodeNumeric   state.NodeIdNumeric // InvalidNodeIdNumeric if ExitNode is empty or unmapped

	// Numeric -> string lookup, copied out of NodeIdMap for trace/log paths
	// that need readable names.
	NumericNames map[state.NodeIdNumeric]state.NodeId

	// NodeForward maps a destination node's numeric id to the next-hop
	// peer (and its NodeId for trace output). Built off the currently
	// selected routes — every entry has a finite metric and is reachable
	// via a peer that is not the local node.
	NodeForward map[state.NodeIdNumeric]RouteTableEntry
}

// rebuildExitFilterSnapshot constructs a fresh snapshot from the current
// LocalCfg + CentralCfg + NodeIdMap and the currently selected routes.
// Must be called on the dispatch goroutine.
func (n *Nylon) rebuildExitFilterSnapshot(idMap *state.NodeIdMap) *ExitFilterSnapshot {
	snap := &ExitFilterSnapshot{
		LocalId:           n.LocalCfg.Id,
		AdvertiseExitNode: n.LocalCfg.AdvertiseExitNode,
		ExitNode:          n.LocalCfg.ExitNode,
		NumericNames:      make(map[state.NodeIdNumeric]state.NodeId),
		NodeForward:       make(map[state.NodeIdNumeric]RouteTableEntry),
	}
	if numeric, ok := idMap.ToNumeric(n.LocalCfg.Id); ok {
		snap.LocalIdNumeric = numeric
	}
	if snap.ExitNode != "" {
		if numeric, ok := idMap.ToNumeric(snap.ExitNode); ok {
			snap.ExitNodeNumeric = numeric
		}
	}
	addName := func(id state.NodeId) {
		if numeric, ok := idMap.ToNumeric(id); ok {
			snap.NumericNames[numeric] = id
		}
	}
	for _, r := range n.CentralCfg.Routers {
		addName(r.Id)
	}
	for _, c := range n.CentralCfg.Clients {
		addName(c.Id)
	}

	// Build the per-node forwarding table. We look each node's assigned
	// addresses up in the prefix-keyed ForwardTable (already atomic,
	// already aggregation-aware) — iterating RouterState.Routes by
	// NodeId would miss nodes whose /32 has been folded into a Babel
	// supernet. ForwardTable is rebuilt before this snapshot, so the
	// lookup sees the latest entries.
	if ft := n.router.ForwardTable.Load(); ft != nil {
		add := func(id state.NodeId, addrs []netip.Addr) {
			if id == n.LocalCfg.Id {
				return
			}
			numeric, ok := idMap.ToNumeric(id)
			if !ok {
				return
			}
			if _, exists := snap.NodeForward[numeric]; exists {
				return
			}
			for _, addr := range addrs {
				entry, ok := ft.Lookup(addr)
				if !ok || entry.Blackhole || entry.Peer == nil {
					continue
				}
				snap.NodeForward[numeric] = entry
				break
			}
		}
		for _, r := range n.CentralCfg.Routers {
			add(r.Id, r.Addresses)
		}
		for _, c := range n.CentralCfg.Clients {
			add(c.Id, c.Addresses)
		}
	}
	return snap
}

// refreshNodeBindings recomputes both the NodeIdMap and ExitFilter snapshots
// from the current config and routing state, and stores them atomically.
// Must be called on the dispatch goroutine after any change that could
// affect either the numeric-id assignment (CentralCfg) or the per-node
// next-hop (selected routes / local exit settings).
func (n *Nylon) refreshNodeBindings() error {
	idMap, err := state.BuildNodeIdMap(&n.CentralCfg)
	if err != nil {
		return err
	}
	n.NodeIdMap.Store(idMap)
	n.ExitFilter.Store(n.rebuildExitFilterSnapshot(idMap))
	return nil
}

// refreshExitFilter rebuilds just the ExitFilter snapshot using the current
// NodeIdMap. Cheaper than refreshNodeBindings; appropriate when only the
// routing state has changed.
func (n *Nylon) refreshExitFilter() {
	idMap := n.NodeIdMap.Load()
	if idMap == nil {
		return
	}
	n.ExitFilter.Store(n.rebuildExitFilterSnapshot(idMap))
}

// wrapExitPacket re-frames the current IP packet in `packet` as a NyUnicast
// MPLS packet bound for `exit`: a single bottom-of-stack label-stack entry
// whose label is the exit node id. Mutates packet in place.
func wrapExitPacket(packet *device.TCElement, exit state.NodeIdNumeric) error {
	if exit == state.InvalidNodeIdNumeric {
		return errors.New("nylon: invalid node id in exit header")
	}

	inner := packet.Packet
	origLen := len(inner)
	headerLen := device.PolyHeaderSize + NyUnicastHeaderSize
	totalLen := headerLen + origLen
	if totalLen > len(packet.Buffer)-device.MessageTransportHeaderSize {
		return errors.New("nylon: packet too large for exit encapsulation")
	}

	// Slide inner IP packet right by headerLen and rebase Packet to point
	// at the new outer header. We use the message-transport offset so the
	// downstream encryptor sees the same Buffer layout as for any other
	// packet.
	buf := packet.Buffer[device.MessageTransportHeaderSize : device.MessageTransportHeaderSize+totalLen]
	copy(buf[headerLen:], inner)
	packet.Packet = buf

	packet.SetIPVersion(NyUnicastProtoId)
	packet.SetLength(uint16(totalLen))
	pl := packet.Payload()
	pl[NyUnicastOffsetSubtype] = byte(NyUnicastSubtypeMpls)
	encodeMplsLse(pl[NyUnicastOffsetLse:], uint32(exit), 0, true, NyUnicastDefaultTTL)
	return nil
}

func packetSrc(packet []byte) (netip.Addr, error) {
	return packetAddr(packet, true)
}

func packetDst(packet []byte) (netip.Addr, error) {
	return packetAddr(packet, false)
}

func packetAddr(packet []byte, src bool) (netip.Addr, error) {
	if len(packet) == 0 {
		return netip.Addr{}, errors.New("empty inner packet")
	}
	switch packet[0] >> 4 {
	case 4:
		offset := device.IPv4offsetDst
		if src {
			offset = device.IPv4offsetSrc
		}
		if len(packet) < offset+net.IPv4len {
			return netip.Addr{}, errors.New("short IPv4 packet")
		}
		return netip.AddrFrom4([4]byte(packet[offset : offset+net.IPv4len])), nil
	case 6:
		offset := device.IPv6offsetDst
		if src {
			offset = device.IPv6offsetSrc
		}
		if len(packet) < offset+net.IPv6len {
			return netip.Addr{}, errors.New("short IPv6 packet")
		}
		return netip.AddrFrom16([16]byte(packet[offset : offset+net.IPv6len])), nil
	default:
		return netip.Addr{}, errors.New("inner packet is not IP")
	}
}

// handleMplsPacket dispatches a NyUnicast / NyUnicastSubtypeMpls packet. The
// destination node is the (outer) MPLS label:
//
//   - label is not us: transit, decrementing the MPLS TTL and forwarding the
//     whole stack to the next hop.
//   - label is us, bottom-of-stack set: strip the entire label stack and bounce
//     the inner IP packet to the local stack.
//   - label is us, more labels below: pop our (outer) label and bounce the
//     remaining MPLS packet to the TUN, leaving the inner stack to the kernel
//     (e.g. an `ip -M route` pop rule). Requires PI mode to emit a non-IP frame.
//
// Reads only the supplied snapshot, never the live config.
//
// The same path serves both inbound transit packets (received from a peer) and
// freshly wrapped locally-originated packets (an MPLS packet the kernel routed
// into our TUN, re-framed at read time): in both cases the label selects the
// next hop with no per-node configuration.
func (n *Nylon) handleMplsPacket(packet *device.TCElement, snap *ExitFilterSnapshot) (device.TCAction, error) {
	t := n.Trace
	payload := packet.Payload()
	if len(payload) < NyUnicastHeaderSize {
		return device.TcDrop, errors.New("mpls packet shorter than header")
	}
	lse := payload[NyUnicastOffsetLse : NyUnicastOffsetLse+device.MplsLseLen]
	label, _, bos, ttl := decodeMplsLse(lse)
	if ttl == 0 {
		return device.TcDrop, errors.New("mpls ttl exceeded")
	}
	dst := state.NodeIdNumeric(label)

	if dst != snap.LocalIdNumeric {
		entry, ok := snap.NodeForward[dst]
		if !ok || entry.Peer == nil {
			return device.TcDrop, fmt.Errorf("no route to node numeric=%d", label)
		}
		lse[device.MplsLseLen-1]-- // decrement TTL (low byte of the LSE)
		packet.ToPeer = entry.Peer
		packet.Priority = device.TcMediumPriority
		if n.DBG_trace_tc {
			t.Submit(fmt.Sprintf("ExitTransit: dst %s via %s\n", snap.NumericNames[dst], entry.Nh))
		}
		return device.TcForward, nil
	}

	// Terminal: this node is the destination of the (outer) label.
	if !snap.AdvertiseExitNode {
		return device.TcDrop, errors.New("local node is not advertising exit service")
	}

	// rest is everything past our (outer) label-stack entry: the original IP
	// packet when our label is the bottom of the stack, otherwise the inner
	// MPLS packet (the labels stacked below ours).
	rest := payload[NyUnicastHeaderSize:]
	if len(rest) == 0 {
		return device.TcDrop, errors.New("mpls packet has no payload")
	}

	if !bos {
		// More labels remain below ours. Pop our (outer) label and emit the
		// remaining MPLS packet out the TUN; the kernel's MPLS stack (e.g. an
		// `ip -M route` pop rule) takes it from there. This requires the TUN
		// to run in PI mode so it can frame a non-IP (MPLS) ethertype.
		if len(rest) < device.MplsLseLen {
			return device.TcDrop, errors.New("mpls stack truncated after outer label")
		}
		copy(packet.Packet[:len(rest)], rest)
		packet.Packet = packet.Packet[:len(rest)]
		packet.L3Proto = tun.EthPMplsUnicast
		if n.DBG_trace_tc {
			t.Submit(fmt.Sprintf("ExitPop: popped label %d, %d bytes of mpls to TUN\n", label, len(rest)))
		}
		return device.TcBounce, nil
	}

	// Bottom of stack: the payload is the original IP packet. Strip the label
	// stack entirely and bounce the inner IP packet to the local stack.
	inner := rest
	src, err := packetSrc(inner)
	if err != nil {
		return device.TcDrop, err
	}
	dstAddr, err := packetDst(inner)
	if err != nil {
		return device.TcDrop, err
	}
	if n.DBG_trace_tc {
		t.Submit(fmt.Sprintf("ExitDecap: %s -> %s\n", src, dstAddr))
	}
	// Repoint Packet at the inner IP packet so subsequent filters /
	// system routing see it as a regular IP packet from this node.
	copy(packet.Packet[:len(inner)], inner)
	packet.Packet = packet.Packet[:len(inner)]
	packet.ParsePacket()
	return device.TcBounce, nil
}
