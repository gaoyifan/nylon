package state

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type NodeId string
type LocalBindID string
type RemoteEndpointID string

const DefaultLocalBindID LocalBindID = "default"

type LinkID struct {
	Peer           NodeId
	LocalBind      LocalBindID
	RemoteEndpoint RemoteEndpointID
	Generation     uint64
}

func (id LinkID) String() string {
	return fmt.Sprintf("%s/%s/%s/%d", id.Peer, id.LocalBind, id.RemoteEndpoint, id.Generation)
}

// Compare orders links deterministically by their identity fields. It avoids
// formatting the ID to a string because it runs in the route-computation hot
// path (LinkList sorts on every call).
func (id LinkID) Compare(other LinkID) int {
	if c := cmp.Compare(id.Peer, other.Peer); c != 0 {
		return c
	}
	if c := cmp.Compare(id.LocalBind, other.LocalBind); c != 0 {
		return c
	}
	if c := cmp.Compare(id.RemoteEndpoint, other.RemoteEndpoint); c != 0 {
		return c
	}
	return cmp.Compare(id.Generation, other.Generation)
}

func (id LinkID) Less(other LinkID) bool {
	return id.Compare(other) < 0
}

// Source is a pair of a router-id and a prefix (Babel Section 2.7).
type Source struct {
	NodeId
	netip.Prefix
}

func (s Source) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("router", string(s.NodeId)),
		slog.String("prefix", s.Prefix.String()),
	)
}

func (s Source) String() string {
	return fmt.Sprintf("(router: %s, prefix: %s)", s.NodeId, s.Prefix)
}

type Advertisement struct {
	NodeId
	Expiry        time.Time
	IsPassiveHold bool
	MetricFn      func() uint32
	ExpiryFn      func()
}
type RouterState struct {
	*RouterTunables
	Id        NodeId
	SelfSeqno map[netip.Prefix]uint16
	Routes    map[netip.Prefix]SelRoute
	Sources   map[Source]FD
	// Links are routed adjacencies. Neighbours is retained as a peer-level
	// compatibility view for older tests and status grouping.
	Links      map[LinkID]*Link
	Neighbours []*Neighbour
	// Advertised is a map tracking the prefix and the time it will be advertised until
	Advertised map[netip.Prefix]Advertisement
}

func (s *RouterState) GetSeqno(prefix netip.Prefix) uint16 {
	seq, ok := s.SelfSeqno[prefix]
	if !ok {
		return 0
	}
	return seq
}

func (s *RouterState) SetSeqno(prefix netip.Prefix, seqno uint16) {
	s.SelfSeqno[prefix] = seqno
}

func (s *RouterState) StringRoutes() string {
	buf := make([]string, 0)
	for prefix, route := range s.Routes {
		buf = append(buf, fmt.Sprintf("%s via %s", prefix, route))
	}
	slices.Sort(buf)
	return strings.Join(buf, "\n")
}

type Neighbour struct {
	Id     NodeId
	Routes map[netip.Prefix]NeighRoute
	Eps    []Endpoint
}

type Link struct {
	ID       LinkID
	Peer     NodeId
	Endpoint Endpoint
	Routes   map[netip.Prefix]NeighRoute
}

// IsActive reports whether the link has an endpoint that is currently active.
// It is safe to call on a nil link.
func (l *Link) IsActive() bool {
	return l != nil && l.Endpoint != nil && l.Endpoint.IsActive()
}

type FD struct {
	Seqno  uint16
	Metric uint32
}

func (fd FD) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("seqno", uint64(fd.Seqno)),
		slog.Uint64("metric", uint64(fd.Metric)),
	)
}

type PubRoute struct {
	Source
	// FD will depend on which table the route is in. In the neighbour table,
	// it represents the metric advertised by the neighbour.
	// In the selected route table, it represents the metric that
	// the route will be advertised with.
	FD
	RetractionToken uint64
}

func (r PubRoute) String() string {
	return fmt.Sprintf("(router: %s, prefix: %s, seqno: %d, metric: %d)", r.NodeId, r.Prefix, r.Seqno, r.Metric)
}

func (r PubRoute) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("router", string(r.NodeId)),
		slog.String("prefix", r.Prefix.String()),
		slog.Uint64("seqno", uint64(r.Seqno)),
		slog.Uint64("metric", uint64(r.Metric)),
	)
}

type NeighRoute struct {
	PubRoute
	ExpireAt time.Time // when the route expires
}

type SelRoute struct {
	PubRoute
	NhLink      LinkID
	Nh          NodeId    // next hop node
	ExpireAt    time.Time // when the route expires
	RetractedBy []LinkID
}

func (r SelRoute) String() string {
	return fmt.Sprintf("(nh: %s, router: %s, prefix: %s, seqno: %d, metric: %d)", r.Nh, r.NodeId, r.Prefix, r.Seqno, r.Metric)
}

func (r SelRoute) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("nh", r.Nh), // Use Any if Nh is an object/interface
		slog.String("router", string(r.NodeId)),
		slog.String("prefix", r.Prefix.String()),
		slog.Uint64("seqno", uint64(r.Seqno)),
		slog.Uint64("metric", uint64(r.Metric)),
	)
}

func (s *RouterState) GetNeighbour(node NodeId) *Neighbour {
	nIdx := slices.IndexFunc(s.Neighbours, func(neighbour *Neighbour) bool {
		return neighbour.Id == node
	})
	if nIdx == -1 {
		return nil
	}
	return s.Neighbours[nIdx]
}

func (s *RouterState) EnsureLinkState() {
	if s.Links == nil {
		s.Links = make(map[LinkID]*Link)
	}
	for _, neigh := range s.Neighbours {
		if neigh.Routes == nil {
			neigh.Routes = make(map[netip.Prefix]NeighRoute)
		}
		for idx, ep := range neigh.Eps {
			id := endpointLinkID(neigh.Id, ep, idx)
			if _, ok := s.Links[id]; ok {
				continue
			}
			s.Links[id] = &Link{
				ID:       id,
				Peer:     neigh.Id,
				Endpoint: ep,
				Routes:   neigh.Routes,
			}
		}
	}
}

func endpointLinkID(peer NodeId, ep Endpoint, idx int) LinkID {
	localBind := DefaultLocalBindID
	generation := uint64(0)
	var remoteID RemoteEndpointID
	if nep := ep.AsNylonEndpoint(); nep != nil {
		remoteID = nep.RemoteEndpointID()
		if nep.LocalBind != "" {
			localBind = nep.LocalBind
		}
		generation = nep.Generation
	} else {
		remoteID = RemoteEndpointID("ep-" + strconv.Itoa(idx))
	}
	return LinkID{
		Peer:           peer,
		LocalBind:      localBind,
		RemoteEndpoint: remoteID,
		Generation:     generation,
	}
}

func (s *RouterState) AddLink(peer NodeId, ep Endpoint) *Link {
	s.EnsureLinkState()
	linksForPeer := s.GetPeerLinks(peer)
	id := endpointLinkID(peer, ep, len(linksForPeer))
	for _, link := range linksForPeer {
		if link.ID == id {
			link.Endpoint = ep
			return link
		}
	}
	link := &Link{
		ID:       id,
		Peer:     peer,
		Endpoint: ep,
		Routes:   make(map[netip.Prefix]NeighRoute),
	}
	s.Links[id] = link
	neigh := s.GetNeighbour(peer)
	if neigh == nil {
		neigh = &Neighbour{Id: peer, Routes: make(map[netip.Prefix]NeighRoute)}
		s.Neighbours = append(s.Neighbours, neigh)
	}
	neigh.Eps = append(neigh.Eps, ep)
	if len(neigh.Eps) == 1 {
		neigh.Routes = link.Routes
	}
	return link
}

func (s *RouterState) RemoveLink(id LinkID) {
	s.EnsureLinkState()
	delete(s.Links, id)
	if neigh := s.GetNeighbour(id.Peer); neigh != nil {
		for i, ep := range neigh.Eps {
			if endpointLinkID(id.Peer, ep, i) == id {
				neigh.Eps = append(neigh.Eps[:i], neigh.Eps[i+1:]...)
				break
			}
		}
	}
}

func (s *RouterState) GetLink(id LinkID) *Link {
	s.EnsureLinkState()
	return s.Links[id]
}

func (s *RouterState) GetLinkForEndpoint(peer NodeId, ep Endpoint) *Link {
	s.EnsureLinkState()
	for _, link := range s.GetPeerLinks(peer) {
		if link.Endpoint == ep {
			return link
		}
	}
	return nil
}

func (s *RouterState) GetPeerLinks(peer NodeId) []*Link {
	s.EnsureLinkState()
	links := make([]*Link, 0)
	for _, link := range s.Links {
		if link.Peer == peer {
			links = append(links, link)
		}
	}
	slices.SortFunc(links, func(a, b *Link) int {
		return a.ID.Compare(b.ID)
	})
	return links
}

func (s *RouterState) GetDefaultLink(peer NodeId) *Link {
	links := s.GetPeerLinks(peer)
	if len(links) == 0 {
		return nil
	}
	return links[0]
}

func (s *RouterState) LinkList() []*Link {
	s.EnsureLinkState()
	links := make([]*Link, 0, len(s.Links))
	for _, link := range s.Links {
		links = append(links, link)
	}
	slices.SortFunc(links, func(a, b *Link) int {
		return a.ID.Compare(b.ID)
	})
	return links
}
