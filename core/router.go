package core

import (
	"net/netip"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/gaissmai/bart"
	"go4.org/netipx"
	"google.golang.org/protobuf/proto"

	"github.com/encodeous/nylon/log"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

type RouteTableEntry struct {
	Nh        state.NodeId
	LinkID    state.LinkID
	Peer      *device.Peer
	Endpoint  conn.Endpoint
	Blackhole bool
}

func (n *Nylon) GetLinkIO(linkID state.LinkID) *IOPending {
	nio, ok := n.router.IO[linkID]
	if !ok {
		nio = &IOPending{
			SeqnoReq: make(map[state.Source]state.Pair[uint16, uint8]),
			Acks:     make(map[netip.Prefix]struct{}),
			Updates:  make(map[netip.Prefix]*protocol.Ny_Update),
		}
		n.router.IO[linkID] = nio
	}
	n.router.IO[linkID] = nio
	return nio
}

func (n *Nylon) SendRouteUpdate(linkID state.LinkID, advRoute state.PubRoute) {
	nio := n.GetLinkIO(linkID)
	prefix, _ := advRoute.Prefix.MarshalBinary()
	nio.Updates[advRoute.Prefix] = &protocol.Ny_Update{
		RouterId: string(advRoute.NodeId),
		Prefix:   prefix,
		Seqno:    uint32(advRoute.Seqno),
		Metric:   advRoute.Metric,
	}
}

func (n *Nylon) SendAckRetract(linkID state.LinkID, prefix netip.Prefix) {
	nio := n.GetLinkIO(linkID)
	nio.Acks[prefix] = struct{}{}
}

func (n *Nylon) BroadcastSendRouteUpdate(advRoute state.PubRoute) {
	for _, link := range n.RouterState.LinkList() {
		if link.Endpoint != nil && link.Endpoint.IsActive() {
			n.SendRouteUpdate(link.ID, advRoute)
		}
	}
}

func (n *Nylon) RequestSeqno(linkID state.LinkID, src state.Source, seqno uint16, hopCnt uint8) {
	nio := n.GetLinkIO(linkID)
	if n.router.SeqnoDedup == nil {
		n.router.SeqnoDedup = ttlcache.New[state.Source, uint16](ttlcache.WithTTL[state.Source, uint16](n.SeqnoDedupTTL), ttlcache.WithDisableTouchOnHit[state.Source, uint16]())
	}
	old := n.router.SeqnoDedup.Get(src)
	maxSeq := seqno
	if old != nil {
		maxSeq = max(seqno, old.Value())
		if SeqnoGe(old.Value(), seqno) {
			return // we have already sent such a request before
		}
	}
	n.router.SeqnoDedup.Set(src, maxSeq, ttlcache.DefaultTTL)
	req, ok := nio.SeqnoReq[src]
	if !ok || seqno < req.V1 {
		req = state.Pair[uint16, uint8]{V1: seqno, V2: hopCnt}
	} else {
		if hopCnt > req.V2 {
			req.V2 = hopCnt
		}
	}
	nio.SeqnoReq[src] = req
}

func (n *Nylon) BroadcastRequestSeqno(src state.Source, seqno uint16, hopCnt uint8) {
	if n.router.SeqnoDedup == nil {
		n.router.SeqnoDedup = ttlcache.New[state.Source, uint16](ttlcache.WithTTL[state.Source, uint16](n.SeqnoDedupTTL), ttlcache.WithDisableTouchOnHit[state.Source, uint16]())
	}
	old := n.router.SeqnoDedup.Get(src)
	maxSeq := seqno
	if old != nil {
		maxSeq = max(seqno, old.Value())
		if SeqnoGe(old.Value(), seqno) {
			return
		}
	}
	n.router.SeqnoDedup.Set(src, maxSeq, ttlcache.DefaultTTL)
	for _, link := range n.RouterState.LinkList() {
		if link.Endpoint != nil && link.Endpoint.IsActive() {
			nio := n.GetLinkIO(link.ID)
			req, ok := nio.SeqnoReq[src]
			if !ok || seqno < req.V1 {
				req = state.Pair[uint16, uint8]{V1: seqno, V2: hopCnt}
			} else if hopCnt > req.V2 {
				req.V2 = hopCnt
			}
			nio.SeqnoReq[src] = req
		}
	}
}

func (n *Nylon) RouterEvent(event string, desc string, args ...any) {
	if event == log.EventNoEndpointToNeigh {
		return // ignored
	}
	n.router.log.Debug(desc, append([]any{"event", event}, args...)...)
}

func (n *Nylon) UpdateNeighbour(neigh state.NodeId) {
	PushFullTableToPeer(n.RouterState, n, neigh)
}

func (n *Nylon) TableInsertRoute(prefix netip.Prefix, route state.SelRoute) {
	nh := route.Nh
	nf := n.router.ForwardTable.Load().Clone()
	ne := n.router.ExitTable.Load().Clone()
	if route.Metric == state.INF {
		nf.Insert(prefix, RouteTableEntry{
			Nh:        nh,
			Blackhole: true,
		})
		ne.Delete(prefix)
		n.router.ForwardTable.Store(nf)
		n.router.ExitTable.Store(ne)
		return
	}
	peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(nh).PubKey))
	var endpoint conn.Endpoint
	link := n.RouterState.GetLink(route.NhLink)
	if link != nil && link.Endpoint != nil {
		if nep := link.Endpoint.AsNylonEndpoint(); nep != nil {
			endpoint = nep.WgEndpoint
			if endpoint == nil && n.Device != nil {
				endpoint, _ = nep.GetWgEndpoint(n.Device)
			}
		}
	}
	nf.Insert(prefix, RouteTableEntry{
		Nh:       nh,
		LinkID:   route.NhLink,
		Peer:     peer,
		Endpoint: endpoint,
	})
	if route.Nh == n.LocalCfg.Id {
		ne.Insert(prefix, RouteTableEntry{
			Nh:       nh,
			LinkID:   route.NhLink,
			Peer:     peer,
			Endpoint: endpoint,
		})
	} else {
		ne.Delete(prefix)
	}
	n.router.ForwardTable.Store(nf)
	n.router.ExitTable.Store(ne)
}

func (n *Nylon) TableDeleteRoute(prefix netip.Prefix) {
	nf := n.router.ForwardTable.Load().Clone()
	ne := n.router.ExitTable.Load().Clone()
	nf.Delete(prefix)
	ne.Delete(prefix)
	n.router.ForwardTable.Store(nf)
	n.router.ExitTable.Store(ne)
}

type IOPending struct {
	// SeqnoReq values represent a pair of (seqno, hop count)
	SeqnoReq map[state.Source]state.Pair[uint16, uint8]
	Acks     map[netip.Prefix]struct{}
	Updates  map[netip.Prefix]*protocol.Ny_Update
}

func (n *Nylon) CleanupRouter() error {
	n.router.log = nil
	n.router.IO = nil
	n.router.SeqnoDedup = nil
	return nil
}

func (n *Nylon) GcRouter() error {
	RunGC(n.RouterState, n)
	for id := range n.router.IO {
		if n.RouterState.GetLink(id) == nil {
			delete(n.router.IO, id)
			continue
		}
	}
	if n.router.SeqnoDedup != nil {
		n.router.SeqnoDedup.DeleteExpired()
	}
	return nil
}

func (n *Nylon) InitRouter() error {
	n.router.log = n.Log.With("module", log.ScopeRouter)
	n.router.log.Debug("init router")
	n.router.IO = make(map[state.LinkID]*IOPending)
	n.router.SeqnoDedup = ttlcache.New[state.Source, uint16](ttlcache.WithTTL[state.Source, uint16](n.SeqnoDedupTTL), ttlcache.WithDisableTouchOnHit[state.Source, uint16]())
	n.router.ForwardTable.Store(new(bart.Table[RouteTableEntry]{}))
	n.router.ExitTable.Store(new(bart.Table[RouteTableEntry]{}))
	n.RouterState = &state.RouterState{
		RouterTunables: &n.RouterTunables,
		Id:             n.LocalCfg.Id,
		SelfSeqno:      make(map[netip.Prefix]uint16),
		Routes:         make(map[netip.Prefix]state.SelRoute),
		Sources:        make(map[state.Source]state.FD),
		Links:          make(map[state.LinkID]*state.Link),
		Neighbours:     make([]*state.Neighbour, 0),
		Advertised:     make(map[netip.Prefix]state.Advertisement),
	}
	maxTime := time.Unix(1<<63-62135596801, 999999999)
	for _, prefix := range n.GetRouter(n.LocalCfg.Id).Prefixes {
		n.RouterState.Advertised[prefix.GetPrefix()] = state.Advertisement{
			NodeId:        n.LocalCfg.Id,
			Expiry:        maxTime,
			IsPassiveHold: false,
			MetricFn:      prefix.GetMetric,
		}
	}

	n.router.log.Debug("schedule router tasks")

	n.RepeatTask(func() error {
		FullTableUpdate(n.RouterState, n)
		return nil
	}, n.RouteUpdateDelay)
	n.RepeatTask(func() error {
		SolveStarvation(n.RouterState, n)
		return nil
	}, n.StarvationDelay)

	n.RepeatTask(func() error {
		return n.flushIO()
	}, n.NeighbourIOFlushDelay)
	return nil
}

// ComputeSysRouteTable computes: computed = prefixes - (((n.CentralCfg.ExcludeIPs U selected self prefixes) - n.LocalCfg.UnexcludeIPs) U n.LocalCfg.ExcludeIPs)
func (n *Nylon) ComputeSysRouteTable() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0)
	selectedSelf := make([]netip.Prefix, 0)
	for entry, v := range n.RouterState.Routes {
		prefixes = append(prefixes, entry)
		if v.Nh == n.LocalCfg.Id {
			selectedSelf = append(selectedSelf, entry)
		}
	}

	excludes := netipx.IPSetBuilder{}
	excludes.AddSet(state.MakeSet(n.CentralCfg.ExcludeIPs))
	excludes.AddSet(state.MakeSet(selectedSelf))
	excludes.RemoveSet(state.MakeSet(n.LocalCfg.UnexcludeIPs))
	excludes.AddSet(state.MakeSet(n.LocalCfg.ExcludeIPs))

	final := netipx.IPSetBuilder{}
	final.AddSet(state.MakeSet(prefixes))
	res, _ := excludes.IPSet()
	final.RemoveSet(res)

	res, _ = final.IPSet()
	return res.Prefixes()
}

func (n *Nylon) updatePassiveClient(prefix state.PrefixHealthWrapper, node state.NodeId, passiveHold bool) {
	// inserts an artificial route into the table

	hasPassiveHold := false
	old, ok := n.RouterState.Advertised[prefix.GetPrefix()]
	if ok && old.NodeId == node {
		hasPassiveHold = old.IsPassiveHold
	}

	if passiveHold && !hasPassiveHold {
		// the first time we enter passive hold, we should increment the seqno to prevent other nodes from switching away from the route
		// this reduces a lot of route flapping when the client wakes up, sends some traffic and then goes back to sleep
		n.RouterState.SetSeqno(prefix.GetPrefix(), n.RouterState.GetSeqno(prefix.GetPrefix())+1)
	}

	// passive nodes may only have static prefixes, so we don't call prefix.Start()
	n.RouterState.Advertised[prefix.GetPrefix()] = state.Advertisement{
		NodeId:        node,
		Expiry:        time.Now().Add(n.ClientKeepaliveInterval),
		IsPassiveHold: passiveHold,
		MetricFn:      prefix.GetMetric,
		ExpiryFn: func() {
			// we didn't start the prefix monitoring
		},
	}
}

func (n *Nylon) hasRecentlyAdvertised(prefix netip.Prefix) bool {
	adv, ok := n.RouterState.Advertised[prefix]
	if !ok {
		return false
	}
	return time.Now().Before(adv.Expiry)
}

func (n *Nylon) checkNeigh(id state.NodeId) bool {
	for _, node := range n.RouterState.Neighbours {
		if node.Id == id {
			return true
		}
	}
	n.router.log.Warn("received packet from unknown neighbour", "from", id)
	return false
}

func (n *Nylon) checkPrefix(prefix netip.Prefix) bool {
	for _, p := range n.GetPrefixes() {
		if p == prefix {
			return true
		}
	}
	n.router.log.Warn("received packet for unknown prefix", "prefix", prefix)
	return false
}

func (n *Nylon) checkNode(id state.NodeId) bool {
	ncfg := n.TryGetNode(id)
	if ncfg == nil {
		n.router.log.Warn("received packet from unknown node", "from", id)
	}
	return ncfg != nil
}

// packet handlers
func (n *Nylon) routerHandleRouteUpdate(linkID state.LinkID, update *protocol.Ny_Update) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(update.Prefix)
	if err != nil {
		n.router.log.Warn("received update with invalid prefix", "prefix", update.Prefix, "err", err)
		return nil
	}
	link := n.RouterState.GetLink(linkID)
	if link == nil ||
		!n.checkPrefix(prefix) ||
		!n.checkNode(state.NodeId(update.RouterId)) {
		return nil
	}
	HandleLinkUpdate(n.RouterState, n, linkID, state.PubRoute{
		Source: state.Source{
			NodeId: state.NodeId(update.RouterId),
			Prefix: prefix,
		},
		FD: state.FD{
			Seqno:  uint16(update.Seqno),
			Metric: update.Metric,
		},
	})
	ComputeRoutes(n.RouterState, n)
	return nil
}

func (n *Nylon) routerHandleAckRetract(linkID state.LinkID, update *protocol.Ny_AckRetract) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(update.Prefix)
	if err != nil {
		n.router.log.Warn("received ack retract with invalid prefix", "prefix", update.Prefix, "err", err)
		return nil
	}
	if !n.checkPrefix(prefix) || n.RouterState.GetLink(linkID) == nil {
		return nil
	}
	HandleLinkAckRetract(n.RouterState, n, linkID, prefix)
	return nil
}

func (n *Nylon) routerHandleSeqnoRequest(linkID state.LinkID, pkt *protocol.Ny_SeqnoRequest) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(pkt.Prefix)
	if err != nil {
		n.router.log.Warn("received seqno request with invalid prefix", "prefix", pkt.Prefix, "err", err)
		return nil
	}
	if n.RouterState.GetLink(linkID) == nil ||
		!n.checkPrefix(prefix) ||
		!n.checkNode(state.NodeId(pkt.RouterId)) {
		return nil
	}
	HandleLinkSeqnoRequest(n.RouterState, n, linkID, state.Source{
		NodeId: state.NodeId(pkt.RouterId),
		Prefix: prefix,
	}, uint16(pkt.Seqno), uint8(pkt.HopCount))
	return nil
}

func (n *Nylon) flushIO() error {
	for _, link := range n.RouterState.LinkList() {
		// TODO, investigate effect of packet loss on control messages
		nio := n.GetLinkIO(link.ID)
		if nio == nil {
			continue
		}
		if link.Endpoint != nil && link.Endpoint.IsActive() {
			peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(link.Peer).PubKey))
			ep := link.Endpoint.AsNylonEndpoint()
			if ep == nil {
				continue
			}
			nep, err := ep.GetWgEndpoint(n.Device)
			if err != nil {
				continue
			}
			for {
				bundle := &protocol.TransportBundle{}
				tLength := 0

				// we can coalesce messages, but we need to make sure we don't fragment our UDP packet
				// if a single proto message is somehow larger than SafeMTU, we still send it, but it will get fragmented

				for seqR, _ := range nio.SeqnoReq {
					prefixBytes, _ := seqR.Prefix.MarshalBinary()
					req := &protocol.Ny{Type: &protocol.Ny_SeqnoRequestOp{
						SeqnoRequestOp: &protocol.Ny_SeqnoRequest{
							RouterId: string(seqR.NodeId),
							Prefix:   prefixBytes,
							Seqno:    uint32(nio.SeqnoReq[seqR].V1),
							HopCount: uint32(nio.SeqnoReq[seqR].V2),
						},
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.SeqnoReq, seqR)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				for id, update := range nio.Updates {
					req := &protocol.Ny{Type: &protocol.Ny_RouteOp{
						RouteOp: update,
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.Updates, id)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				for prefix := range nio.Acks {
					prefixBytes, _ := prefix.MarshalBinary()
					req := &protocol.Ny{Type: &protocol.Ny_AckRetractOp{
						AckRetractOp: &protocol.Ny_AckRetract{
							Prefix: prefixBytes,
						},
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.Acks, prefix)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				if tLength == 0 {
					break
				}
			send:
				err := n.SendNylonBundle(bundle, nep, peer)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
