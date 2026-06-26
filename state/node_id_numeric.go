package state

import (
	"fmt"
	"slices"
)

// NodeIdNumeric is a compact numeric identifier for a node, derived from the
// central config. It is used in dataplane packet headers in place of the
// variable-length NodeId string so the parser can run with a fixed-size
// header on the hot path.
//
// The value is intentionally isomorphic to an MPLS label: the NyUnicast exit
// path carries the destination node id as the 20-bit label of a single MPLS
// label-stack entry, so an operator can steer traffic to an exit purely with
// `ip route ... encap mpls <node-id>` and no per-node configuration.
//
// Value 0 is reserved as "invalid / unassigned". Valid numeric ids begin at
// FirstNodeIdNumeric and are assigned deterministically (alphabetical order
// over the union of routers and clients in the central config). Both ends of a
// tunnel must hold the same central config to agree on the mapping; this is
// already a prerequisite for routing in nylon.
type NodeIdNumeric uint32

const InvalidNodeIdNumeric NodeIdNumeric = 0

// FirstNodeIdNumeric is the first assignable numeric id. MPLS labels 0-15 are
// reserved by the kernel — e.g. label 3 (implicit null) is rejected for
// encapsulation — and a node's numeric id doubles as its MPLS label, so
// assignment starts at the first unreserved label.
const FirstNodeIdNumeric NodeIdNumeric = 16

// MaxNodeIdNumeric is the largest representable numeric node id. It matches the
// 20-bit MPLS label space (an MPLS label-stack entry carries a 20-bit label),
// so a node id always fits in a single label.
const MaxNodeIdNumeric NodeIdNumeric = 0xFFFFF

// NodeIdMap is an immutable bidirectional NodeId <-> NodeIdNumeric lookup
// table. Construct via BuildNodeIdMap and treat the returned value as
// read-only.
type NodeIdMap struct {
	byNumeric map[NodeIdNumeric]NodeId
	byString  map[NodeId]NodeIdNumeric
}

// BuildNodeIdMap returns a deterministic NodeId <-> NodeIdNumeric mapping
// derived from the given central config. The same input config produces the
// same mapping on every node, so peers always agree on the encoding.
//
// A node may pin its numeric id explicitly via NodeCfg.NumericId (which doubles
// as its MPLS label). Explicit ids must be >= FirstNodeIdNumeric; anything
// lower is rejected with an error (and the process exits at startup / config
// apply). Nodes without an explicit id are packed into the lowest free slots
// starting at FirstNodeIdNumeric, in alphabetical order, so the assignment is
// deterministic and stable regardless of input ordering.
func BuildNodeIdMap(c *CentralCfg) (*NodeIdMap, error) {
	ids := make([]NodeId, 0, len(c.Routers)+len(c.Clients))
	explicit := make(map[NodeId]NodeIdNumeric, len(c.Routers)+len(c.Clients))
	seen := make(map[NodeId]struct{}, len(c.Routers)+len(c.Clients))
	collect := func(n NodeCfg) {
		if _, ok := seen[n.Id]; ok {
			return
		}
		seen[n.Id] = struct{}{}
		ids = append(ids, n.Id)
		if n.NumericId != InvalidNodeIdNumeric {
			explicit[n.Id] = n.NumericId
		}
	}
	for _, r := range c.Routers {
		collect(r.NodeCfg)
	}
	for _, cl := range c.Clients {
		collect(cl.NodeCfg)
	}
	slices.Sort(ids)

	if uint64(len(ids)) > uint64(MaxNodeIdNumeric-FirstNodeIdNumeric+1) {
		return nil, fmt.Errorf("network has %d nodes, exceeds NodeIdNumeric capacity of %d", len(ids), MaxNodeIdNumeric-FirstNodeIdNumeric+1)
	}

	m := &NodeIdMap{
		byNumeric: make(map[NodeIdNumeric]NodeId, len(ids)),
		byString:  make(map[NodeId]NodeIdNumeric, len(ids)),
	}
	assign := func(id NodeId, numeric NodeIdNumeric) {
		m.byNumeric[numeric] = id
		m.byString[id] = numeric
	}

	// First pass: honour explicitly pinned ids (alphabetical order).
	for _, id := range ids {
		numeric, ok := explicit[id]
		if !ok {
			continue
		}
		if numeric < FirstNodeIdNumeric {
			return nil, fmt.Errorf("node %s pins node id %d, which is below the minimum of %d (numeric ids / MPLS labels 0-%d are reserved)", id, numeric, FirstNodeIdNumeric, FirstNodeIdNumeric-1)
		}
		if numeric > MaxNodeIdNumeric {
			return nil, fmt.Errorf("node %s pins node id %d, which is above the maximum of %d", id, numeric, MaxNodeIdNumeric)
		}
		if other, dup := m.byNumeric[numeric]; dup {
			return nil, fmt.Errorf("nodes %s and %s both pin node id %d", other, id, numeric)
		}
		assign(id, numeric)
	}

	// Second pass: pack the remaining nodes into the lowest free slots,
	// starting at FirstNodeIdNumeric (insert into the gaps left by explicit ids).
	next := FirstNodeIdNumeric
	for _, id := range ids {
		if _, ok := explicit[id]; ok {
			continue
		}
		for {
			if next > MaxNodeIdNumeric {
				return nil, fmt.Errorf("ran out of node id space while assigning %s", id)
			}
			if _, taken := m.byNumeric[next]; !taken {
				break
			}
			next++
		}
		assign(id, next)
		next++
	}
	return m, nil
}

// ToNumeric returns the numeric id for a NodeId, or InvalidNodeIdNumeric if the
// node is not present in the mapping.
func (m *NodeIdMap) ToNumeric(id NodeId) (NodeIdNumeric, bool) {
	if m == nil {
		return InvalidNodeIdNumeric, false
	}
	b, ok := m.byString[id]
	return b, ok
}

// ToString returns the NodeId for a numeric id, or ("", false) if the numeric
// id is unassigned.
func (m *NodeIdMap) ToString(b NodeIdNumeric) (NodeId, bool) {
	if m == nil || b == InvalidNodeIdNumeric {
		return "", false
	}
	id, ok := m.byNumeric[b]
	return id, ok
}

// Len returns the number of nodes in the mapping.
func (m *NodeIdMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.byString)
}
