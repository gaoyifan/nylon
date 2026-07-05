package state

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// familyRouteTTL bounds how often we re-run the per-family route lookup, so
// per-probe checks stay cheap while still noticing connectivity changes.
const familyRouteTTL = 15 * time.Second

type familyRouteState struct {
	checkedAt time.Time
	reachable bool
}

var (
	familyRouteMu    sync.Mutex
	familyRouteCache = map[bool]familyRouteState{} // keyed by "is IPv6"
)

// FamilyReachable reports whether the host currently has a route and a usable
// (non-link-local) source address towards addr's family. It performs a
// connected-UDP route lookup (no packets are sent) and caches the result per
// address family for a short period. Invalid addresses are treated as
// reachable so callers fail open.
func FamilyReachable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	isV6 := addr.Is6() && !addr.Is4In6()
	familyRouteMu.Lock()
	defer familyRouteMu.Unlock()
	if st, ok := familyRouteCache[isV6]; ok && time.Since(st.checkedAt) < familyRouteTTL {
		return st.reachable
	}
	reachable := probeFamilyRoute(addr)
	familyRouteCache[isV6] = familyRouteState{checkedAt: time.Now(), reachable: reachable}
	return reachable
}

func probeFamilyRoute(addr netip.Addr) bool {
	// Connecting a UDP socket only performs a kernel route lookup; nothing is
	// sent on the wire.
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		return false
	}
	defer c.Close()
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return true
	}
	src, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return true
	}
	return !src.IsLinkLocalUnicast()
}
