package state

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
)

type Endpoint interface {
	Metric() uint32
	IsRemote() bool
	IsActive() bool
	AsNylonEndpoint() *NylonEndpoint
}

func SameIPFamily(a, b netip.Addr) bool {
	if !a.IsValid() || !b.IsValid() {
		return true
	}
	return a.BitLen() == b.BitLen()
}

/*
		DynamicEndpoint represents either an ip:port or a dns name. This may be resolved to a different address at any time

		Examples:
	    - nylon.example.com -> resolves to <ip>:57175 (DefaultPort)
		- nylon2.example.com:12345 -> resolves to <ip>:12345
		- SRV record: _nylon._udp.example.com. port: 8000 target: nylon3.example.com -> resolves to <ip>:8000
*/
type DynamicEndpoint struct {
	Value      string
	lastValue  netip.AddrPort
	lastUpdate time.Time
	rw         *sync.RWMutex
}

func NewDynamicEndpoint(value string) *DynamicEndpoint {
	return &DynamicEndpoint{
		Value: value,
		rw:    &sync.RWMutex{},
	}
}

func (ep *DynamicEndpoint) Parse() (host string, port uint16, err error) {
	// Try to parse as AddrPort directly first to handle cases like [::1]:port correctly
	if ap, err := netip.ParseAddrPort(ep.Value); err == nil {
		return ap.Addr().String(), ap.Port(), nil
	}

	h, portStr, err := net.SplitHostPort(ep.Value)
	if err != nil {
		// No port specified?
		// TODO: more robust validation
		return ep.Value, uint16(DefaultPort), nil
	} else {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %w", err)
		}
		return h, uint16(p), nil
	}
}

func (ep *DynamicEndpoint) Refresh(resolveExpiry time.Duration) (netip.AddrPort, error) {
	// 1. Try to parse as AddrPort directly
	if ap, err := netip.ParseAddrPort(ep.Value); err == nil {
		return ap, nil
	}

	ep.rw.RLock()
	// if this endpoint is down, we will refresh every EndpointResolveDelay
	if time.Since(ep.lastUpdate) < resolveExpiry && ep.lastValue != (netip.AddrPort{}) {
		ep.rw.RUnlock()
		return ep.lastValue, nil
	}
	ep.rw.RUnlock()

	host, port, err := ep.Parse()
	if err != nil {
		return netip.AddrPort{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// 2. Try SRV lookup
	target, srvPort, err := ResolveSRV(ctx, "nylon", "udp", host)
	if err == nil {
		addrs, err := ResolveName(ctx, target)
		if err == nil && len(addrs) > 0 {
			ep.rw.Lock()
			defer ep.rw.Unlock()
			ep.lastUpdate = time.Now()
			ep.lastValue = netip.AddrPortFrom(addrs[0], srvPort)
			return ep.lastValue, nil
		}
	}

	// 3. Normal A/AAAA lookup
	addrs, err := ResolveName(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no addresses found for %s", host)
	}

	ep.rw.Lock()
	defer ep.rw.Unlock()
	ep.lastUpdate = time.Now()
	ep.lastValue = netip.AddrPortFrom(addrs[0], port)
	return ep.lastValue, nil
}

func (ep *DynamicEndpoint) Get() (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(ep.Value); err == nil {
		return ap, nil
	}
	ep.rw.RLock()
	defer ep.rw.RUnlock()
	if ep.lastValue != (netip.AddrPort{}) {
		return ep.lastValue, nil
	}
	return netip.AddrPort{}, fmt.Errorf("endpoint not resolved")
}

func (ep *DynamicEndpoint) Clear() {
	ep.rw.Lock()
	defer ep.rw.Unlock()
	ep.lastUpdate = time.Time{}
}

func (ep *DynamicEndpoint) String() string {
	return ep.Value
}

func (ep *DynamicEndpoint) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	ep.Value = s
	ep.rw = &sync.RWMutex{}
	return nil
}

func (ep *DynamicEndpoint) MarshalYAML() (interface{}, error) {
	return ep.Value, nil
}

const (
	// ProbeTimeout is how long a sent probe may stay unacknowledged before
	// it is counted as lost.
	ProbeTimeout = 5 * time.Second
	// EchoValidity bounds how old a received probe may be before we stop
	// echoing it back. Long hold times are still handled correctly by the
	// RTT formula, but clock drift makes very old echoes less accurate.
	EchoValidity = 10 * time.Second
	// ClockJumpReset is the relative-delay discontinuity beyond which a
	// filter assumes the peer's clock epoch changed (e.g. process restart)
	// and resets instead of slowly converging.
	ClockJumpReset = time.Minute
	// MinLinkDelay is the floor for the delay used as a metric base; it
	// plays the same role as the old 100us RTT clamp.
	MinLinkDelay = 50 * time.Microsecond
	// WarmupDelay is the metric base used before a link has collected
	// enough samples to be confident.
	WarmupDelay = time.Second
	// pendingProbeCap bounds the per-link window of unacknowledged probes.
	pendingProbeCap = 128
)

// delayFilter smooths a series of relative one-way delay samples with an
// EWMA followed by a windowed median with hysteresis (the same pipeline
// previously applied to RTT samples). Samples are *relative* delays: they
// embed the unknown clock offset between the two nodes, may be negative,
// and only differences between samples of the same series (or sums with the
// opposite direction) are meaningful.
type delayFilter struct {
	history    []time.Duration
	histSort   []time.Duration
	dirty      bool
	prevMedian time.Duration
	exp        float64
	init       bool
}

func (f *delayFilter) reset() {
	f.history = f.history[:0]
	f.dirty = true
	f.init = false
	f.exp = 0
	f.prevMedian = 0
}

func (f *delayFilter) update(sample time.Duration, t *RouterTunables) {
	s := float64(sample)
	// A large discontinuity means the relative clock offset itself jumped
	// (peer restarted and its monotonic epoch moved). Converging through the
	// EWMA would poison the window for minutes, so start over.
	if f.init && math.Abs(s-f.exp) > float64(ClockJumpReset) {
		f.reset()
	}
	const alpha = 0.0836
	if !f.init {
		f.exp = s
		f.init = true
	}
	f.exp = alpha*s + (1-alpha)*f.exp
	f.history = append(f.history, time.Duration(int64(f.exp)))
	if len(f.history) > t.WindowSamples {
		f.history = f.history[1:]
	}
	f.dirty = true
}

func (f *delayFilter) ready(t *RouterTunables) bool {
	return len(f.history) >= t.MinimumConfidenceWindow
}

func (f *delayFilter) filtered() time.Duration {
	if !f.init {
		return 0
	}
	return time.Duration(int64(f.exp))
}

// stabilized returns the outlier-trimmed windowed median, only moving when
// the previous value falls outside the trimmed range. Requires ready().
func (f *delayFilter) stabilized(t *RouterTunables) time.Duration {
	if f.dirty {
		f.histSort = slices.Clone(f.history)
		slices.Sort(f.histSort)
		f.dirty = false
	}
	le := len(f.histSort)
	low := f.histSort[int(float64(le)*t.OutlierPercentage)]
	high := f.histSort[int(float64(le)*(1-t.OutlierPercentage))]
	med := f.histSort[le/2]
	if low > f.prevMedian || high < f.prevMedian {
		f.prevMedian = med
	}
	return f.prevMedian
}

// linkIdCounter hands out process-unique link ids, used to attribute probe
// replies to the exact link they were sent on.
var linkIdCounter atomic.Uint64

type NylonEndpoint struct {
	sync.RWMutex  // this mutex is for delay smoothing and metric calculation
	t             *RouterTunables
	lastHeardBack time.Time
	remoteInit    bool
	WgEndpoint    conn.Endpoint
	DynEP         *DynamicEndpoint
	Bind          LocalBind
	Transport     conn.Transport

	// LinkId is a process-unique identifier carried in outgoing probes and
	// echoed back in replies (see protocol.Ny_Probe).
	LinkId uint64

	// Relative one-way delay filters (RFC 9616-style measurement).
	// owdOut smooths (peer rx ts - local tx ts): the delay towards the peer
	// plus the peer-local clock offset. owdIn smooths (local rx ts - peer tx
	// ts): the delay from the peer minus the same offset. Their sum is the
	// offset-free RTT. The relative delays themselves are never used as
	// absolute quantities; they are only compared between links of the same
	// neighbour (which share the same clock offset, so comparisons are
	// exact) or summed with the opposite direction (where the offset
	// cancels).
	owdOut delayFilter
	owdIn  delayFilter

	// Echo state: the most recent probe received from the peer on this link,
	// echoed back in our next outgoing probe.
	peerTx     int64 // peer's TxTs (peer clock, ns)
	peerTxRxAt int64 // local monotonic ns when peerTx was received
	havePeerTx bool

	// pending holds the TxTs of sent probes that have not been echoed yet.
	// Used both for loss accounting and to validate incoming echoes (an echo
	// that does not match a pending probe is stale or duplicated).
	pending []int64

	// packet-loss estimation derived from probe echo/expiry
	lossEWMA    float64
	lossInit    bool
	lossSamples int
}

func (ep *NylonEndpoint) AsNylonEndpoint() *NylonEndpoint {
	return ep
}

func (ep *NylonEndpoint) GetWgEndpoint(device *device.Device) (conn.Endpoint, error) {
	ap, err := ep.DynEP.Get()
	if err != nil {
		return nil, err
	}
	if !SameIPFamily(ep.Bind.Source, ap.Addr()) {
		return nil, fmt.Errorf("bind source %s does not match endpoint %s", ep.Bind.Source, ap)
	}

	if ep.WgEndpoint == nil || ep.WgEndpoint.DstIPPort() != ap {
		wgEp, err := device.Bind().ParseEndpoint(ap.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse endpoint: %s, %v", ap.String(), err)
		}
		ep.WgEndpoint = wgEp
	}
	if setter, ok := ep.WgEndpoint.(interface {
		SetSrc(netip.Addr, int32)
	}); ok && (ep.Bind.Source.IsValid() || ep.Bind.Interface != "") {
		ifidx := int32(0)
		if ep.Bind.Interface != "" {
			iface, err := net.InterfaceByName(ep.Bind.Interface)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve bind interface %s: %w", ep.Bind.Interface, err)
			}
			ifidx = int32(iface.Index)
		}
		setter.SetSrc(ep.Bind.Source, ifidx)
	}
	if ep.Transport == conn.TransportFakeTCP {
		wgEndpoint, ok := ep.WgEndpoint.(*conn.StdNetEndpoint)
		if !ok {
			return nil, fmt.Errorf("fake TCP requires StdNetEndpoint")
		}
		wgEndpoint.SetTransport(conn.TransportFakeTCP)
		bind, ok := device.Bind().(*conn.StdNetBind)
		if !ok {
			return nil, fmt.Errorf("fake TCP requires StdNetBind")
		}
		if err := bind.PrepareFakeTCP(wgEndpoint); err != nil {
			return nil, err
		}
	}
	return ep.WgEndpoint, nil
}

// CompareEndpoints orders a neighbour's links by sending preference:
// active before inactive, then links with a ready directional measurement by
// their outbound score (stabilized relative outbound delay plus loss
// penalty and the matching local transport cost; exact between links of the
// same neighbour since they share the same clock offset), and finally by the
// effective endpoint metric as a fallback for links that are still warming
// up (or are not NylonEndpoints).
func CompareEndpoints(a, b Endpoint) int {
	if c := cmpBool(a.IsActive(), b.IsActive()); c != 0 {
		return c
	}
	aOut, aOk := outboundScore(a)
	bOut, bOk := outboundScore(b)
	if c := cmpBool(aOk, bOk); c != 0 {
		return c
	}
	if aOk && aOut != bOut {
		return cmp.Compare(aOut, bOut)
	}
	return cmp.Compare(effectiveEndpointMetric(a), effectiveEndpointMetric(b))
}

func cmpBool(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return -1
	}
	return 1
}

func outboundScore(ep Endpoint) (int64, bool) {
	nep := ep.AsNylonEndpoint()
	if nep == nil {
		return 0, false
	}
	out, _, ok := nep.dirScores()
	out += int64(endpointCost(nep))
	return out, ok
}

func effectiveEndpointMetric(ep Endpoint) uint32 {
	metric := ep.Metric()
	nep := ep.AsNylonEndpoint()
	if nep == nil {
		return metric
	}
	return addMetricCost(metric, endpointCost(nep))
}

func endpointCost(ep *NylonEndpoint) time.Duration {
	if ep.Transport == conn.TransportFakeTCP {
		return ep.t.TCPCost
	}
	return ep.t.UDPCost
}

func addMetricCost(metric uint32, cost time.Duration) uint32 {
	if metric == INF {
		return INF
	}
	return uint32(min(uint64(metric)+uint64(cost.Microseconds()), uint64(INFM)))
}

// BestEndpoint returns the link this node should send on: the active link
// with the lowest outbound score (see CompareEndpoints). nil when no link is
// active.
func (n *Neighbour) BestEndpoint() Endpoint {
	var best Endpoint
	for _, link := range n.Eps {
		if !link.IsActive() {
			continue
		}
		if best == nil || CompareEndpoints(link, best) < 0 {
			best = link
		}
	}
	return best
}

// LinkCost is the single-hop cost towards this neighbour advertised to the
// routing layer. Each side selects its sending link independently (per
// direction, by relative one-way delay), so the round trip experienced by
// traffic is our best outbound link combined with the peer's best outbound
// link -- which is exactly the link we measure as best inbound. The cost is
// this effective cycle latency,
//
//	base = min_i relOut(i) + min_j relIn(j)
//
// where the unknown clock offset cancels between the two terms, penalized by
// the coupled loss of the two selected links (the cycle loses a packet when
// either direction does):
//
//	p = 1 - (1-p_out)(1-p_in)
//	cost = base/(1-p) + LossRetxFloor * p/(1-p)
//
// For a single symmetric link this reduces to the link's RTT with its own
// loss, matching the previous RTT-based metric. Absolute one-way delays are
// never needed: single-hop link selection only requires exact relative
// comparisons, and the advertised cost only requires the offset-free cycle
// latency. Network-wide asymmetric route optimization is out of scope for
// the current Babel-derived protocol.
func (n *Neighbour) LinkCost() uint32 {
	var outEp, inEp *NylonEndpoint
	var bestOut, bestIn int64
	haveActive := false
	for _, ep := range n.Eps {
		if !ep.IsActive() {
			continue
		}
		haveActive = true
		nep := ep.AsNylonEndpoint()
		if nep == nil {
			continue
		}
		out, in, ok := nep.dirScores()
		if !ok {
			continue
		}
		outScore := out + int64(endpointCost(nep))
		if outEp == nil || outScore < bestOut {
			outEp, bestOut = nep, outScore
		}
		if inEp == nil || in < bestIn {
			inEp, bestIn = nep, in
		}
	}
	if !haveActive {
		return INF
	}
	if outEp == nil || inEp == nil {
		// warming up, or the neighbour has no NylonEndpoints (tests):
		// fall back to the per-link metric of the preferred link
		best := n.BestEndpoint()
		if best == nil {
			return INF
		}
		return effectiveEndpointMetric(best)
	}
	outRel, _, _ := outEp.RelDelays()
	_, inRel, _ := inEp.RelDelays()
	base := max(outRel+inRel, MinLinkDelay)
	t := outEp.t
	pOut := min(outEp.LossRate(), t.LossCap)
	pIn := min(inEp.LossRate(), t.LossCap)
	p := min(1-(1-pOut)*(1-pIn), t.LossCap)
	return addMetricCost(etxMetric(base, p, t), endpointCost(outEp))
}

func (u *NylonEndpoint) isActiveUnlocked() bool {
	return time.Since(u.lastHeardBack) <= u.t.LinkDeadThreshold
}

func (u *NylonEndpoint) IsActive() bool {
	u.RLock()
	defer u.RUnlock()
	return u.isActiveUnlocked()
}

func (u *NylonEndpoint) Renew() {
	u.Lock()
	defer u.Unlock()
	if !u.isActiveUnlocked() {
		// a recovered link starts with clean delay and loss estimates
		u.owdOut.reset()
		u.owdIn.reset()
		u.havePeerTx = false
		u.pending = u.pending[:0]
		u.lossEWMA = 0
		u.lossInit = false
		u.lossSamples = 0
	}
	u.lastHeardBack = time.Now()
}

func (u *NylonEndpoint) IsAlive() bool {
	return u.IsActive() || !u.remoteInit // we never gc endpoints that we have in our config
}

func NewEndpoint(endpoint *DynamicEndpoint, remoteInit bool, wgEndpoint conn.Endpoint, t *RouterTunables) *NylonEndpoint {
	return &NylonEndpoint{
		t:          t,
		remoteInit: remoteInit,
		WgEndpoint: wgEndpoint,
		DynEP:      endpoint,
		LinkId:     linkIdCounter.Add(1),
	}
}

// RegisterProbe records that a probe with the given transmit timestamp was
// sent on this link, so its echo can later be validated and unanswered
// probes can be counted as lost. Must be called before the probe can
// possibly be answered (i.e. before it is handed to the send path).
func (u *NylonEndpoint) RegisterProbe(txTs int64) {
	u.Lock()
	defer u.Unlock()
	u.pending = append(u.pending, txTs)
	if len(u.pending) > pendingProbeCap {
		u.pending = u.pending[len(u.pending)-pendingProbeCap:]
	}
}

// CancelProbe removes a registered probe without counting it as lost, used
// when the local send itself failed.
func (u *NylonEndpoint) CancelProbe(txTs int64) {
	u.Lock()
	defer u.Unlock()
	if idx := slices.Index(u.pending, txTs); idx != -1 {
		u.pending = slices.Delete(u.pending, idx, idx+1)
	}
}

// SweepProbes expires pending probes older than ProbeTimeout, folding each
// of them into the loss estimate as a lost probe. nowNs is the current local
// monotonic timestamp (same clock as the probe TxTs values).
func (u *NylonEndpoint) SweepProbes(nowNs int64) {
	u.Lock()
	defer u.Unlock()
	kept := u.pending[:0]
	for _, txTs := range u.pending {
		if nowNs-txTs > int64(ProbeTimeout) {
			u.recordLossLocked(false)
		} else {
			kept = append(kept, txTs)
		}
	}
	u.pending = kept
}

// EchoInfo returns the timestamps to echo in the next outgoing probe: the
// TxTs of the most recent probe received from the peer on this link and the
// local time it was received. ok is false when nothing recent enough is
// available.
func (u *NylonEndpoint) EchoInfo(nowNs int64) (originTx, originRx int64, ok bool) {
	u.RLock()
	defer u.RUnlock()
	if !u.havePeerTx || nowNs-u.peerTxRxAt > int64(EchoValidity) {
		return 0, 0, false
	}
	return u.peerTx, u.peerTxRxAt, true
}

// ObserveInbound folds a received probe (ping or pong) into the inbound
// relative one-way delay filter and stores it as the latest echo candidate.
// peerTx is the probe's TxTs on the peer's clock, rxNs the local receive
// timestamp.
func (u *NylonEndpoint) ObserveInbound(peerTx, rxNs int64) {
	u.Lock()
	defer u.Unlock()
	if u.havePeerTx && peerTx <= u.peerTx {
		// duplicate or reordered probe... unless the peer's clock epoch
		// moved backwards far enough to indicate a restart.
		if u.peerTx-peerTx < int64(ClockJumpReset) {
			return
		}
	}
	u.peerTx = peerTx
	u.peerTxRxAt = rxNs
	u.havePeerTx = true
	u.owdIn.update(time.Duration(rxNs-peerTx), u.t)
}

// ObserveEcho folds an echoed probe of ours into the outbound relative
// one-way delay filter. originTx is our probe's TxTs as echoed by the peer,
// peerRx the peer's receive timestamp for it (peer clock). The echo is only
// accepted when it matches a pending probe, which both deduplicates repeated
// echoes and rejects stale echoes from before a local restart. Returns
// whether the echo was accepted.
func (u *NylonEndpoint) ObserveEcho(originTx, peerRx int64) bool {
	u.Lock()
	defer u.Unlock()
	idx := slices.Index(u.pending, originTx)
	if idx == -1 {
		return false
	}
	u.pending = slices.Delete(u.pending, idx, idx+1)
	u.owdOut.update(time.Duration(peerRx-originTx), u.t)
	u.recordLossLocked(true)
	return true
}

// RelDelays returns the stabilized relative one-way delays of the link. The
// values embed the unknown clock offset to the peer and are only meaningful
// when compared with the other links of the same neighbour (same offset) or
// summed with the opposite direction (offset cancels). ok is false until
// both directions have enough samples.
func (u *NylonEndpoint) RelDelays() (out, in time.Duration, ok bool) {
	u.Lock()
	defer u.Unlock()
	if !u.owdOut.ready(u.t) || !u.owdIn.ready(u.t) {
		return 0, 0, false
	}
	return u.owdOut.stabilized(u.t), u.owdIn.stabilized(u.t), true
}

// dirScores returns the per-direction link-selection scores: the stabilized
// relative one-way delay plus a clock-offset-free loss penalty (the expected
// extra time spent retransmitting over this link). Scores are only
// comparable between links of the same neighbour.
func (u *NylonEndpoint) dirScores() (out, in int64, ok bool) {
	rOut, rIn, ok := u.RelDelays()
	if !ok {
		return 0, 0, false
	}
	pen := time.Duration(0)
	if p := min(u.LossRate(), u.t.LossCap); p > 0 {
		pen = time.Duration(float64(rOut+rIn+u.t.LossRetxFloor) * p / (1 - p))
	}
	return int64(rOut + pen), int64(rIn + pen), true
}

// FilteredPing returns the EWMA-filtered RTT (sum of the two relative
// one-way delay EWMAs; clock offsets cancel). Zero when unavailable.
func (u *NylonEndpoint) FilteredPing() time.Duration {
	u.RLock()
	defer u.RUnlock()
	if !u.owdOut.init || !u.owdIn.init {
		return 0
	}
	return u.owdOut.filtered() + u.owdIn.filtered()
}

// StabilizedPing returns the stabilized RTT (sum of the two stabilized
// relative one-way delays; clock offsets cancel). Zero when unavailable.
func (u *NylonEndpoint) StabilizedPing() time.Duration {
	out, in, ok := u.RelDelays()
	if !ok {
		return 0
	}
	return out + in
}

// recordLossLocked folds the outcome of a single probe into the endpoint's
// loss estimate (an EWMA of the per-probe loss indicator). received is true
// when an echo came back, false when the probe timed out (was lost).
func (u *NylonEndpoint) recordLossLocked(received bool) {
	sample := 1.0
	if received {
		sample = 0.0
	}
	if !u.lossInit {
		u.lossEWMA = sample
		u.lossInit = true
	} else {
		a := u.t.LossSmoothingAlpha
		u.lossEWMA = a*sample + (1-a)*u.lossEWMA
	}
	if u.lossSamples < u.t.MinimumConfidenceWindow {
		u.lossSamples++
	}
}

// LossRate returns the smoothed packet-loss probability in [0, LossCap]. It
// returns 0 until enough probes have been observed, so a cold link is never
// penalized for loss.
func (u *NylonEndpoint) LossRate() float64 {
	u.RLock()
	defer u.RUnlock()
	if u.lossSamples < u.t.MinimumConfidenceWindow {
		return 0
	}
	l := u.lossEWMA
	if l < 0 {
		l = 0
	}
	if l > u.t.LossCap {
		l = u.t.LossCap
	}
	return l
}

// Metric is the per-link cost: the offset-free stabilized RTT of the link
// penalized by its loss rate, or a conservative WarmupDelay while the link
// is warming up. It is used for display and as an ordering fallback; route
// costs towards a neighbour use Neighbour.LinkCost, and the choice of which
// link to send on uses the directional scores (CompareEndpoints).
func (u *NylonEndpoint) Metric() uint32 {
	// if link is dead, return INF
	if !u.IsActive() {
		return INF
	}
	base := u.StabilizedPing()
	if base == 0 {
		base = WarmupDelay
	}
	base = max(base, MinLinkDelay)
	return etxMetric(base, u.LossRate(), u.t)
}

// etxMetric penalizes a delay base with an ETX-style retransmission model:
// the expected delivery time under geometric retransmission is base/(1-p),
// plus a fixed per-retransmission floor so that low-delay-but-lossy links
// are still penalized:
//
//	metric = base/(1-p) + RetxFloor * p/(1-p)
//	       = base + (base + RetxFloor) * p/(1-p)
func etxMetric(base time.Duration, p float64, t *RouterTunables) uint32 {
	if p <= 0 {
		return DurationToMetric(base)
	}
	factor := p / (1 - p)
	extra := time.Duration(float64(base+t.LossRetxFloor) * factor)
	return DurationToMetric(base + extra)
}

func (u *NylonEndpoint) IsRemote() bool {
	return u.remoteInit
}

func DurationToMetric(d time.Duration) uint32 {
	if d == time.Duration(math.MaxInt64) {
		return INF
	}
	return uint32(min(d.Microseconds(), int64(INF)-1))
}

func MetricToDuration(m uint32) time.Duration {
	if m >= INF {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(m) * time.Microsecond
}
