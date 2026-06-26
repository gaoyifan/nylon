package device

import (
	"slices"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/tun"
)

// polyamide traffic control provides a facility to re-order, manipulate, and redirect packets between nylon/polyamide nodes
// this facility operates at the IP/polysock level

type TCAction int
type TCPriority int

const (
	// TcPass will pass the packet on to the next layer
	TcPass TCAction = iota
	// TcBounce will bounce the packet back to the system for handling
	TcBounce
	// TcForward will send the packet through nylon/polyamide. toPeer must be set in TCElement
	TcForward
	// TcDrop will completely drop the packet
	TcDrop
)

const (
	TcNormalPriority TCPriority = iota
	TcMediumPriority
	TcHighPriority
	TcMaxPriority
)

type TCFilter func(dev *Device, packet *TCElement) (TCAction, error)

func TCFAllowedip(dev *Device, packet *TCElement) (TCAction, error) {
	if packet.ToPeer != nil {
		return TcForward, nil
	}
	peer := dev.Allowedips.Lookup(packet.GetDstBytes())
	if peer != nil {
		packet.ToPeer = peer
		//fmt.Printf("fw: %s -> %s\n", packet.GetDst().String(), peer)
		return TcForward, nil
	}

	//fmt.Printf("nfw addr: %s\n", packet.GetDst().String())
	return TcPass, nil
}

func TCFDrop(dev *Device, packet *TCElement) (TCAction, error) {
	//dev.Log.Verbosef("TCFDrop packet: %v -> %v", packet.GetSrc(), packet.GetDst())
	return TcDrop, nil
}

func TCFBounce(dev *Device, packet *TCElement) (TCAction, error) {
	if packet.Incoming() {
		//dev.Log.Verbosef("TCFBounce packet: %v -> %v", packet.GetSrc(), packet.GetDst())
		return TcBounce, nil
	}
	return TcPass, nil
}

type TCElement struct {
	Buffer   *[MaxMessageSize]byte // slice holding the packet data
	Packet   []byte                // slice of "buffer" (always!)
	FromEp   conn.Endpoint         // what the source wireguard UDP endpoint (if any) is
	ToEp     conn.Endpoint         // which wireguard UDP endpoint to send this Packet to
	FromPeer *Peer                 // which peer (if any) sent us this Packet
	ToPeer   *Peer                 // which peer to send this Packet to
	Priority TCPriority            // Priority, higher is better
	// L3Proto is the ethertype to use when this packet is bounced back to the
	// TUN. Zero means "infer from the IP version nibble" (the normal IPv4/IPv6
	// case). A filter that produces a non-IP frame (e.g. an MPLS packet after
	// popping a label) sets this so the TUN prepends the right tun_pi proto.
	L3Proto uint16
}

func (elem *TCElement) clearPointers() {
	elem.Buffer = nil
	elem.Packet = nil
	elem.FromEp = nil
	elem.ToEp = nil
	elem.FromPeer = nil
	elem.ToPeer = nil
	elem.L3Proto = 0
}

func (device *Device) NewTCElement() *TCElement {
	elem := device.GetTCElement()
	elem.Buffer = device.GetMessageBuffer()
	return elem
}

func (device *Device) InstallFilter(filter TCFilter) {
	device.TCFilters = append(device.TCFilters, filter)
}

type TCState struct {
	priority     [][]*TCElement
	bouncePkts   []*TCElement
	bounceBufs   [][]byte
	bounceProtos []uint16
	elemsForPeer map[*Peer][]*TCElement
}

func NewTCState() *TCState {
	return &TCState{
		priority:     make([][]*TCElement, TcMaxPriority+1),
		bouncePkts:   make([]*TCElement, 0, conn.IdealBatchSize),
		bounceBufs:   make([][]byte, 0, conn.IdealBatchSize),
		bounceProtos: make([]uint16, 0, conn.IdealBatchSize),
		elemsForPeer: make(map[*Peer][]*TCElement),
	}
}

func (device *Device) TCBatch(batch []*TCElement, tcs *TCState) {
	for i, elem := range batch {
		// process TC Filters
		act := TcPass
		if !elem.ParsePacket() || !elem.Validate() {
			device.Log.Errorf("Found malformed packet, dropping packet")
			act = TcDrop
		} else {
			for _, filter := range slices.Backward(device.TCFilters) {
				nAct, err := filter(device, elem)
				act = nAct
				if err != nil {
					device.Log.Errorf("Error on filter action: %v", err)
					act = TcDrop
				}
				if act != TcPass {
					break
				}
			}
		}
		if act == TcPass {
			device.Log.Errorf("Unexpectedly passed all filters!")
			act = TcDrop
		}

		batch[i] = nil

		switch act {
		case TcDrop:
			// cleanup
			device.PutMessageBuffer(elem.Buffer)
			device.PutTCElement(elem)
		case TcBounce:
			// bounce back to system
			tcs.bouncePkts = append(tcs.bouncePkts, elem)
		case TcForward:
			// reroute/forward packet
			if elem.ToPeer == nil {
				device.Log.Errorf("Failed to forward packet to destination, toPeer not set")
				device.PutMessageBuffer(elem.Buffer)
				device.PutTCElement(elem)
				continue
			}
			tcs.priority[elem.Priority] = append(tcs.priority[elem.Priority], elem)
		default:
			panic("unreachable default case")
		}
	}

	// bounce packets back to the system
	if len(tcs.bouncePkts) > 0 {
		hasNonIP := false
		for _, elem := range tcs.bouncePkts {
			tcs.bounceBufs = append(tcs.bounceBufs, elem.Buffer[:MessageTransportHeaderSize+len(elem.Packet)])
			tcs.bounceProtos = append(tcs.bounceProtos, elem.L3Proto)
			if elem.L3Proto != 0 {
				hasNonIP = true
			}
		}
		// here, we need to use elem.Buffer instead of elem.Packet since we will get io.ErrShortBuffer if offset < 4
		var err error
		if pw, ok := device.tun.device.(tun.ProtoWriter); ok && hasNonIP {
			// At least one packet is non-IP (e.g. an MPLS frame after a label
			// pop); hand the per-packet ethertypes to the TUN so it can set the
			// tun_pi proto instead of guessing from the IP-version nibble.
			_, err = pw.WriteWithProtos(tcs.bounceBufs, MessageTransportHeaderSize, tcs.bounceProtos)
		} else {
			_, err = device.tun.device.Write(tcs.bounceBufs, MessageTransportHeaderSize)
		}
		if err != nil && !device.isClosed() {
			device.Log.Errorf("Failed to loop back packets to TUN device: %v", err)
		}
		for i, elem := range tcs.bouncePkts {
			device.PutMessageBuffer(elem.Buffer)
			device.PutTCElement(elem)
			tcs.bouncePkts[i] = nil
			tcs.bounceBufs[i] = nil
			tcs.bounceProtos[i] = 0
		}
		tcs.bounceBufs = tcs.bounceBufs[:0]
		tcs.bouncePkts = tcs.bouncePkts[:0]
		tcs.bounceProtos = tcs.bounceProtos[:0]
	}

	// forward packets to peers based on priority
	for p, elems := range slices.Backward(tcs.priority) {
		for i, elem := range elems {
			if elem == nil {
				continue
			}
			tcs.elemsForPeer[elem.ToPeer] = append(tcs.elemsForPeer[elem.ToPeer], elem)
			elems[i] = nil
		}
		tcs.priority[p] = tcs.priority[p][:0]
	}

	// stage packets to peers
	for peer, elems := range tcs.elemsForPeer {
		if len(elems) == 0 {
			continue
		}
		if peer.isRunning.Load() {
			obec := device.GetOutboundElementsContainer()
			for i, elem := range elems {
				obe := device.GetOutboundElement()
				obe.nonce = 0
				obe.endpoint = elem.ToEp
				obe.packet = elem.Packet
				obe.buffer = elem.Buffer
				obec.elems = append(obec.elems, obe)
				device.PutTCElement(elem)
				elems[i] = nil
			}
			peer.StagePackets(obec)
			peer.SendStagedPackets()
		} else {
			for i, elem := range elems {
				device.PutMessageBuffer(elem.Buffer)
				device.PutTCElement(elem)
				elems[i] = nil
			}
		}
		tcs.elemsForPeer[peer] = elems[:0]
	}
}
