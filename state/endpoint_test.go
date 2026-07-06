package state

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSameIPFamily(t *testing.T) {
	assert.True(t, SameIPFamily(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")))
	assert.True(t, SameIPFamily(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")))
	assert.False(t, SameIPFamily(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")))
	assert.True(t, SameIPFamily(netip.Addr{}, netip.MustParseAddr("2001:db8::1")))
}

// linkSim drives a NylonEndpoint through simulated timestamped probe
// exchanges with a peer whose clock differs from ours by a fixed offset.
// It reproduces exactly what the core probe path does: register the probe,
// observe the peer's reply timestamps, and echo-validate our own probe.
type linkSim struct {
	ep     *NylonEndpoint
	now    int64 // local monotonic clock, ns
	offset int64 // peer clock - local clock, ns
}

func newLinkSim(tun *RouterTunables, offset time.Duration) *linkSim {
	ep := NewEndpoint(NewDynamicEndpoint("127.0.0.1:0"), false, nil, tun)
	return &linkSim{ep: ep, now: int64(time.Hour), offset: int64(offset)}
}

// round simulates one full probe exchange: our probe takes `out` to reach
// the peer and the peer's reply takes `in` to come back.
func (s *linkSim) round(out, in time.Duration) {
	txTs := s.now
	s.ep.RegisterProbe(txTs)
	peerRx := txTs + int64(out) + s.offset
	peerTx := peerRx + int64(20*time.Microsecond) // peer hold time
	rxTs := peerTx - s.offset + int64(in)
	s.ep.Renew()
	s.ep.ObserveInbound(peerTx, rxTs)
	s.ep.ObserveEcho(txTs, peerRx)
	s.now = max(rxTs, txTs+int64(time.Second))
}

// lostRound simulates a probe whose echo never arrives.
func (s *linkSim) lostRound() {
	txTs := s.now
	s.ep.RegisterProbe(txTs)
	s.now = txTs + int64(time.Second)
	s.ep.SweepProbes(s.now + int64(ProbeTimeout))
}

// neighbourOf wraps endpoints in a Neighbour, as links of the same peer.
func neighbourOf(eps ...*NylonEndpoint) *Neighbour {
	n := &Neighbour{Id: "peer"}
	for _, ep := range eps {
		n.Eps = append(n.Eps, ep)
	}
	return n
}

// setLoss pins an endpoint's smoothed loss estimate to an exact value so
// loss-dependent formulas can be asserted deterministically.
func setLoss(ep *NylonEndpoint, p float64) {
	ep.Lock()
	defer ep.Unlock()
	ep.lossEWMA = p
	ep.lossInit = true
	ep.lossSamples = ep.t.MinimumConfidenceWindow
}

// recordProbe folds a single probe outcome into the loss estimate, standing
// in for the echo/sweep paths that record loss in production.
func recordProbe(ep *NylonEndpoint, received bool) {
	ep.Lock()
	defer ep.Unlock()
	ep.recordLossLocked(received)
}

// runTests feeds a synthetic RTT series through a simulated link and returns
// the true RTT of each sample alongside the stabilized estimate.
func runTests(t *testing.T, ping func(i int) float64, dura time.Duration) (truth, stabilized []time.Duration) {
	t.Helper()
	tunables := DefaultRouterTunables()
	sim := newLinkSim(&tunables, 5*time.Second)

	samples := int(dura / tunables.ProbeDelay)
	for i := 0; i < samples; i++ {
		nping := time.Duration(ping(i) * float64(time.Millisecond))
		sim.round(nping/2, nping/2)
		if i > tunables.MinimumConfidenceWindow {
			truth = append(truth, nping)
			stabilized = append(stabilized, sim.ep.StabilizedPing())
		}
	}
	return truth, stabilized
}

func TestEndpointSin(t *testing.T) {
	rng := rand.New(rand.NewPCG(0, 0))
	truth, finalFiltered := runTests(t, func(i int) float64 {
		val := math.Cos(float64(i)/1000.0-math.Pi/2) * 10
		if rng.Int()%30 == 0 {
			val += float64(rng.Int() % 20)
		}
		val2 := math.Sin(float64(i+400)/50.0)*2 + rng.Float64()
		val3 := math.Abs(rng.NormFloat64()) * 5
		return val + val2 + val3 + 75
	}, time.Hour*2)

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth[i])
		variance += diff * diff
	}
	// deviation from pingY should be 10 + 5 + 2 = 17ms
	stdev := math.Sqrt(variance / float64(len(finalFiltered)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*20)
	assert.Less(t, len(distinctValues), int((time.Hour*2)/time.Minute))
}

func TestEndpointPosX(t *testing.T) {
	// absolute worst case scenario for number of metric changes
	rng := rand.New(rand.NewPCG(0, 0))
	truth, finalFiltered := runTests(t, func(i int) float64 {
		val := float64(i) / 50.0
		if rng.Int()%30 == 0 {
			val += float64(rng.Int() % 20)
		}
		val2 := math.Sin(float64(i+400)/50.0)*2 + rng.Float64()
		val3 := math.Abs(rng.NormFloat64()) * 5
		return val + val2 + val3 + 75
	}, time.Hour*2)

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*20)
	// once per minute is acceptable
	assert.Less(t, len(distinctValues), int(time.Hour*2/time.Minute))
}

func TestEndpointNegX(t *testing.T) {
	// absolute worst case scenario for number of metric changes
	rng := rand.New(rand.NewPCG(0, 0))
	truth, finalFiltered := runTests(t, func(i int) float64 {
		val := -float64(i) / 50.0
		if rng.Int()%30 == 0 {
			val += float64(rng.Int() % 20)
		}
		val2 := math.Sin(float64(i+400)/50.0)*2 + rng.Float64()
		val3 := math.Abs(rng.NormFloat64()) * 5
		return val + val2 + val3 + 500
	}, time.Hour*2)

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*40)
	// once per minute is acceptable
	assert.Less(t, len(distinctValues), int(time.Hour*2/time.Minute))
}

func TestEndpointNormal(t *testing.T) {
	// absolute worst case scenario for number of metric changes
	rng := rand.New(rand.NewPCG(0, 0))
	truth, finalFiltered := runTests(t, func(i int) float64 {
		return 50 + rng.NormFloat64()*10
	}, time.Hour*2)

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*40)
	// once per minute is acceptable
	assert.Less(t, len(distinctValues), int(time.Hour*2/time.Minute))
}

// stableLink returns an active endpoint that has converged on the given
// per-direction delays with the given peer clock offset.
func stableLink(out, in, offset time.Duration, tun *RouterTunables) *linkSim {
	sim := newLinkSim(tun, offset)
	for i := 0; i < tun.WindowSamples; i++ {
		sim.round(out, in)
	}
	return sim
}

func TestOwdSymmetricLink(t *testing.T) {
	tun := DefaultRouterTunables()
	// a clock offset far larger than the delay must not affect anything
	sim := stableLink(25*time.Millisecond, 25*time.Millisecond, 7*time.Second, &tun)

	// the relative delays embed the offset, but their sum is the true RTT
	out, in, ok := sim.ep.RelDelays()
	assert.True(t, ok)
	assert.InDelta(t, float64(50*time.Millisecond), float64(out+in), float64(time.Millisecond))
	assert.InDelta(t, float64(50*time.Millisecond), float64(sim.ep.StabilizedPing()), float64(time.Millisecond))
	// the per-link metric is the offset-free RTT
	assert.InDelta(t, float64(DurationToMetric(50*time.Millisecond)), float64(sim.ep.Metric()), float64(DurationToMetric(time.Millisecond)))
	// a single-link neighbour advertises the link's own RTT as its cost
	n := neighbourOf(sim.ep)
	assert.InDelta(t, float64(sim.ep.Metric()), float64(n.LinkCost()), float64(DurationToMetric(time.Millisecond)))
}

func TestOwdNegativeOffsetSymmetric(t *testing.T) {
	tun := DefaultRouterTunables()
	sim := stableLink(10*time.Millisecond, 10*time.Millisecond, -3*time.Second, &tun)
	// a negative offset makes the raw outbound relative delay negative; the
	// offset still cancels in the RTT
	out, in, ok := sim.ep.RelDelays()
	assert.True(t, ok)
	assert.Less(t, out, time.Duration(0))
	assert.InDelta(t, float64(20*time.Millisecond), float64(out+in), float64(time.Millisecond))
}

// TestOwdAsymmetricLinks reproduces the extreme example from the design
// discussion: two links between the same pair of nodes,
//
//	L1: out 1ms,   back 100ms
//	L2: out 100ms, back 1ms
//
// Both links have an identical RTT of 101ms, so an RTT-based comparison
// cannot tell them apart. Directional selection must prefer L1 for our
// outbound traffic (the peer, symmetrically, will prefer its L2), and the
// advertised neighbour cost must be the effective cycle: our best outbound
// (1ms on L1) plus the peer's best outbound towards us (1ms on L2).
func TestOwdAsymmetricLinks(t *testing.T) {
	tun := DefaultRouterTunables()
	offset := 3 * time.Second // same peer => same clock offset on both links
	l1 := newLinkSim(&tun, offset)
	l2 := newLinkSim(&tun, offset)
	for i := 0; i < tun.WindowSamples; i++ {
		l1.round(1*time.Millisecond, 100*time.Millisecond)
		l2.round(100*time.Millisecond, 1*time.Millisecond)
	}
	n := neighbourOf(l1.ep, l2.ep)

	// we send on L1; the RTT-based per-link metrics are indistinguishable
	assert.Same(t, l1.ep, n.BestEndpoint().AsNylonEndpoint())
	assert.Less(t, CompareEndpoints(l1.ep, l2.ep), 0)
	assert.InDelta(t, float64(l1.ep.Metric()), float64(l2.ep.Metric()), float64(DurationToMetric(time.Millisecond)))

	// the outbound difference between the links is measured exactly: 99ms
	out1, in1, _ := l1.ep.RelDelays()
	out2, in2, _ := l2.ep.RelDelays()
	assert.InDelta(t, float64(99*time.Millisecond), float64(out2-out1), float64(time.Millisecond))
	assert.InDelta(t, float64(99*time.Millisecond), float64(in1-in2), float64(time.Millisecond))

	// advertised cost: best out (L1, 1ms) + best in (L2, 1ms) = 2ms cycle
	assert.InDelta(t, float64(DurationToMetric(2*time.Millisecond)), float64(n.LinkCost()), float64(DurationToMetric(time.Millisecond)))
}

// Two symmetric links with different RTTs: both directions prefer the
// faster link and the neighbour cost is its RTT.
func TestLinkCostSymmetricPair(t *testing.T) {
	tun := DefaultRouterTunables()
	offset := -2 * time.Second
	fast := stableLink(10*time.Millisecond, 10*time.Millisecond, offset, &tun)
	slow := stableLink(50*time.Millisecond, 50*time.Millisecond, offset, &tun)
	n := neighbourOf(fast.ep, slow.ep)

	assert.Same(t, fast.ep, n.BestEndpoint().AsNylonEndpoint())
	assert.Less(t, fast.ep.Metric(), slow.ep.Metric())
	assert.InDelta(t, float64(DurationToMetric(20*time.Millisecond)), float64(n.LinkCost()), float64(DurationToMetric(time.Millisecond)))
}

func TestOwdWarmup(t *testing.T) {
	tun := DefaultRouterTunables()
	sim := newLinkSim(&tun, time.Second)
	sim.round(time.Millisecond, time.Millisecond)
	// not enough samples: no delay estimate, and both the per-link metric
	// and the advertised neighbour cost fall back to the warmup value
	_, _, ok := sim.ep.RelDelays()
	assert.False(t, ok)
	assert.Equal(t, DurationToMetric(WarmupDelay), sim.ep.Metric())
	assert.Equal(t, DurationToMetric(WarmupDelay), neighbourOf(sim.ep).LinkCost())
}

// TestLinkCostCoupledLoss checks that the advertised cost couples the loss
// of the two selected directions: the cycle loses a packet when either
// direction does, p = 1-(1-p_out)(1-p_in).
func TestLinkCostCoupledLoss(t *testing.T) {
	tun := DefaultRouterTunables()
	offset := time.Second
	l1 := stableLink(5*time.Millisecond, 50*time.Millisecond, offset, &tun)
	l2 := stableLink(50*time.Millisecond, 5*time.Millisecond, offset, &tun)
	setLoss(l1.ep, 0.1)
	setLoss(l2.ep, 0.2)
	n := neighbourOf(l1.ep, l2.ep)

	// selection still picks l1 out / l2 in (loss penalties do not flip it)
	assert.Same(t, l1.ep, n.BestEndpoint().AsNylonEndpoint())

	base := 10 * time.Millisecond // 5ms out on l1 + 5ms in on l2
	p := 1 - (1-0.1)*(1-0.2)
	factor := p / (1 - p)
	expected := DurationToMetric(base + time.Duration(float64(base+tun.LossRetxFloor)*factor))
	assert.InDelta(t, float64(expected), float64(n.LinkCost()), float64(DurationToMetric(time.Millisecond)))
}

// A fast-but-lossy link must lose the directional selection to a slightly
// slower clean sibling once its expected retransmission cost exceeds the
// delay difference.
func TestDirectionalSelectionWithLoss(t *testing.T) {
	tun := DefaultRouterTunables()
	offset := -4 * time.Second
	lossyFast := stableLink(5*time.Millisecond, 5*time.Millisecond, offset, &tun)
	cleanSlow := stableLink(20*time.Millisecond, 20*time.Millisecond, offset, &tun)
	setLoss(lossyFast.ep, 0.5)
	n := neighbourOf(lossyFast.ep, cleanSlow.ep)

	assert.Same(t, cleanSlow.ep, n.BestEndpoint().AsNylonEndpoint())
	assert.Less(t, CompareEndpoints(cleanSlow.ep, lossyFast.ep), 0)
}

// CompareEndpoints must order active links strictly before inactive ones:
// the WireGuard endpoint list is sorted with it and traffic is sent to the
// first entry, so an inverted comparison sends data to a dead address even
// while probes flow on the healthy links (regression: cluster nodes with
// unreachable configured endpoints blackholed all data traffic).
func TestCompareEndpointsActiveFirst(t *testing.T) {
	tun := DefaultRouterTunables()
	active := stableLink(5*time.Millisecond, 5*time.Millisecond, time.Second, &tun)
	dead := NewEndpoint(NewDynamicEndpoint("192.0.2.1:1"), false, nil, &tun)

	assert.True(t, active.ep.IsActive())
	assert.False(t, dead.IsActive())
	assert.Less(t, CompareEndpoints(active.ep, dead), 0)
	assert.Greater(t, CompareEndpoints(dead, active.ep), 0)

	links := []Endpoint{dead, active.ep}
	slices.SortStableFunc(links, CompareEndpoints)
	assert.Same(t, active.ep, links[0].AsNylonEndpoint())
}

func TestEchoValidation(t *testing.T) {
	tun := DefaultRouterTunables()
	sim := stableLink(5*time.Millisecond, 5*time.Millisecond, time.Second, &tun)
	before := sim.ep.FilteredPing()

	// an echo that does not match any pending probe (stale, duplicated, or
	// from before a restart) must be rejected and must not move the filters
	assert.False(t, sim.ep.ObserveEcho(12345, 99999))
	assert.Equal(t, before, sim.ep.FilteredPing())

	// a matching echo is accepted exactly once
	txTs := sim.now
	sim.ep.RegisterProbe(txTs)
	assert.True(t, sim.ep.ObserveEcho(txTs, txTs+int64(5*time.Millisecond)))
	assert.False(t, sim.ep.ObserveEcho(txTs, txTs+int64(5*time.Millisecond)))
}

func TestClockJumpResets(t *testing.T) {
	tun := DefaultRouterTunables()
	sim := stableLink(5*time.Millisecond, 5*time.Millisecond, 0, &tun)
	// peer restarts: its clock epoch jumps by two minutes
	sim.offset += int64(2 * time.Minute)
	for i := 0; i < tun.MinimumConfidenceWindow+1; i++ {
		sim.round(5*time.Millisecond, 5*time.Millisecond)
	}
	// with the discontinuity reset the filters converge within a window
	// instead of slowly blending in the 2-minute jump
	assert.InDelta(t, float64(10*time.Millisecond), float64(sim.ep.FilteredPing()), float64(2*time.Millisecond))
}

func TestPendingProbeLossSweep(t *testing.T) {
	tun := DefaultRouterTunables()
	sim := stableLink(5*time.Millisecond, 5*time.Millisecond, 0, &tun)
	assert.Equal(t, 0.0, sim.ep.LossRate())

	// probes that are never echoed are counted as lost once they expire
	for i := 0; i < 10; i++ {
		sim.lostRound()
	}
	assert.Greater(t, sim.ep.LossRate(), 0.0)
}

// stableEndpoint returns an active endpoint whose delay estimate has settled
// to the given RTT (symmetric link, offset-free) and whose loss estimate is
// untouched, matching the old helper's semantics.
func stableEndpoint(base time.Duration, tun *RouterTunables) *NylonEndpoint {
	sim := stableLink(base/2, base/2, 0, tun)
	resetLoss(sim.ep)
	return sim.ep
}

// resetLoss clears the loss estimate that stableLink's simulated echoes
// accumulated, so loss-focused tests start from a pristine state.
func resetLoss(ep *NylonEndpoint) {
	ep.Lock()
	defer ep.Unlock()
	ep.lossEWMA = 0
	ep.lossInit = false
	ep.lossSamples = 0
}

func TestEndpointLossConfidenceGate(t *testing.T) {
	tun := DefaultRouterTunables()
	ep := stableEndpoint(50*time.Millisecond, &tun)
	// fewer than the confidence window of loss samples: no penalty yet
	for i := 0; i < tun.MinimumConfidenceWindow-1; i++ {
		recordProbe(ep, false)
	}
	assert.Equal(t, 0.0, ep.LossRate())
	assert.Equal(t, DurationToMetric(ep.StabilizedPing()), ep.Metric())
}

func TestEndpointLossMetric(t *testing.T) {
	tun := DefaultRouterTunables()
	base := 50 * time.Millisecond
	clean := stableEndpoint(base, &tun)
	lossy := stableEndpoint(base, &tun)
	for i := 0; i < tun.MinimumConfidenceWindow; i++ {
		recordProbe(clean, true)
		recordProbe(lossy, false)
	}

	// a link with no loss is unchanged; a fully-lossy link saturates at LossCap
	assert.Equal(t, 0.0, clean.LossRate())
	assert.InDelta(t, tun.LossCap, lossy.LossRate(), 1e-9)
	assert.Equal(t, DurationToMetric(clean.StabilizedPing()), clean.Metric())
	assert.Greater(t, lossy.Metric(), clean.Metric())

	// the lossy metric matches the ETX-style formula exactly
	p := lossy.LossRate()
	bs := lossy.StabilizedPing()
	factor := p / (1 - p)
	expected := DurationToMetric(bs + time.Duration(float64(bs+tun.LossRetxFloor)*factor))
	assert.Equal(t, expected, lossy.Metric())
}

func TestEndpointLossConverges(t *testing.T) {
	tun := DefaultRouterTunables()
	ep := stableEndpoint(50*time.Millisecond, &tun)
	// a deterministic 1-in-4 loss pattern; the EWMA should converge near 0.25
	for i := 0; i < 400; i++ {
		recordProbe(ep, i%4 != 0)
	}
	assert.InDelta(t, 0.25, ep.LossRate(), 0.05)
}

func TestEndpointLossMonotonic(t *testing.T) {
	tun := DefaultRouterTunables()
	base := 50 * time.Millisecond
	low := stableEndpoint(base, &tun)
	high := stableEndpoint(base, &tun)
	for i := 0; i < 400; i++ {
		recordProbe(low, i%4 != 0)  // ~25% loss
		recordProbe(high, i%2 != 0) // ~50% loss
	}
	assert.Greater(t, low.LossRate(), 0.0)
	assert.Greater(t, high.LossRate(), low.LossRate())
	assert.Greater(t, high.Metric(), low.Metric())
}

// A low-delay but lossy link must lose to a clean higher-delay link, which is
// the "long lossy link" problem ETX is designed to prevent.
func TestEndpointLossyLowRttLosesToCleanHighRtt(t *testing.T) {
	tun := DefaultRouterTunables()
	lossyFast := stableEndpoint(5*time.Millisecond, &tun)
	cleanSlow := stableEndpoint(80*time.Millisecond, &tun)
	for i := 0; i < tun.MinimumConfidenceWindow; i++ {
		recordProbe(lossyFast, i%2 != 0) // ~50% loss
		recordProbe(cleanSlow, true)
	}
	assert.Greater(t, lossyFast.Metric(), cleanSlow.Metric())
}

func TestDynamicEndpoint_Parse(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedHost string
		expectedPort uint16
		wantErr      bool
	}{
		{
			name:         "IPv4 with port",
			input:        "127.0.0.1:12345",
			expectedHost: "127.0.0.1",
			expectedPort: 12345,
		},
		{
			name:         "IPv6 with port",
			input:        "[::1]:12345",
			expectedHost: "::1",
			expectedPort: 12345,
		},
		{
			name:         "Hostname with port",
			input:        "example.com:54321",
			expectedHost: "example.com",
			expectedPort: 54321,
		},
		{
			name:         "Hostname default port",
			input:        "nylon.example.com",
			expectedHost: "nylon.example.com",
			expectedPort: uint16(DefaultPort),
		},
		{
			name:         "IPv4 default port",
			input:        "192.168.1.1",
			expectedHost: "192.168.1.1",
			expectedPort: uint16(DefaultPort),
		},
		{
			name:    "Invalid port",
			input:   "example.com:abc",
			wantErr: true,
		},
		{
			name:    "Not a URL",
			input:   "http://example.com/nylon",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := NewDynamicEndpoint(tt.input)
			host, port, err := ep.Parse()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHost, host)
				assert.Equal(t, tt.expectedPort, port)
			}
		})
	}
}
