package state

import (
	"math"
	"math/rand/v2"
	"net/netip"
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

type DataSource struct {
	Name string
	Data []time.Duration
}

//func generateMultiLinePlot(dataSources []DataSource, title string) (*plot.Plot, error) {
//	p := plot.New()
//
//	p.Title.Text = title
//	p.X.Label.Text = "Sample #"
//	p.Y.Label.Text = "Duration (ms)"
//
//	// Define a color palette for the lines
//	colors := []color.Color{
//		color.RGBA{R: 255, G: 0, B: 0, A: 255},   // Red
//		color.RGBA{R: 0, G: 0, B: 255, A: 255},   // Blue
//		color.RGBA{R: 0, G: 255, B: 0, A: 255},   // Green
//		color.RGBA{R: 255, G: 0, B: 255, A: 255}, // Magenta
//		color.RGBA{R: 0, G: 255, B: 255, A: 255}, // Cyan
//	}
//
//	for i, ds := range dataSources {
//		points := make(plotter.XYs, len(ds.Data))
//		for j, d := range ds.Data {
//			points[j].X = float64(j)
//			points[j].Y = float64(d.Milliseconds())
//		}
//
//		line, err := plotter.NewLine(points)
//		if err != nil {
//			return nil, fmt.Errorf("failed to create line for %s: %v", ds.Name, err)
//		}
//
//		line.Color = colors[i%len(colors)] // Cycle through colors
//		p.Add(line)
//		p.Legend.Add(ds.Name, line)
//	}
//
//	return p, nil
//}

func runTests(t *testing.T, ping func(i int) float64, dura time.Duration, fn string) (DataSource, DataSource) {
	t.Helper()
	tunables := DefaultRouterTunables()
	dep := NewEndpoint(NewDynamicEndpoint("127.0.0.1:0"), false, nil, &tunables)

	truth := DataSource{
		Name: "Truth",
		Data: []time.Duration{},
	}

	low := DataSource{
		Name: "Low",
		Data: []time.Duration{},
	}

	high := DataSource{
		Name: "High",
		Data: []time.Duration{},
	}

	filtered := DataSource{
		Name: "Filtered",
		Data: []time.Duration{},
	}

	stabilized := DataSource{
		Name: "Stabilized",
		Data: []time.Duration{},
	}

	samples := int(dura / tunables.ProbeDelay)
	for i := 0; i < samples; i++ {
		nping := time.Duration(ping(i) * float64(time.Millisecond))
		dep.UpdatePing(nping)
		if i > tunables.MinimumConfidenceWindow {
			truth.Data = append(truth.Data, nping)
			high.Data = append(high.Data, dep.HighRange())
			low.Data = append(low.Data, dep.LowRange())
			filtered.Data = append(filtered.Data, dep.FilteredPing())
			stabilized.Data = append(stabilized.Data, dep.StabilizedPing())
		}
	}

	//dataSources := []DataSource{truth, high, low, filtered, stabilized}

	//p, err := generateMultiLinePlot(dataSources, "Comparison of ping and stabilized ping")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//if err := p.Save(8*vg.Inch, 6*vg.Inch, spew.Sprintf("method_comparison_%s.png", fn)); err != nil {
	//	t.Fatalf("Failed to save plot: %v", err)
	//}

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
	}, time.Hour*2, "sin")

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered.Data {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth.Data[i])
		variance += diff * diff
	}
	// deviation from pingY should be 10 + 5 + 2 = 17ms
	stdev := math.Sqrt(variance / float64(len(finalFiltered.Data)))
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
	}, time.Hour*2, "PosX")

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered.Data {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth.Data[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered.Data)))
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
	}, time.Hour*2, "NegX")

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered.Data {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth.Data[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered.Data)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*40)
	// once per minute is acceptable
	assert.Less(t, len(distinctValues), int(time.Hour*2/time.Minute))
}

func TestEndpointNormal(t *testing.T) {
	// absolute worst case scenario for number of metric changes
	rng := rand.New(rand.NewPCG(0, 0))
	truth, finalFiltered := runTests(t, func(i int) float64 {
		return 50 + rng.NormFloat64()*10
	}, time.Hour*2, "normal")

	distinctValues := make(map[uint64]struct{})

	variance := 0.0
	for i, d := range finalFiltered.Data {
		distinctValues[uint64(d)] = struct{}{}
		diff := float64(d - truth.Data[i])
		variance += diff * diff
	}
	stdev := math.Sqrt(variance / float64(len(finalFiltered.Data)))
	assert.Less(t, time.Duration(stdev), time.Millisecond*40)
	// once per minute is acceptable
	assert.Less(t, len(distinctValues), int(time.Hour*2/time.Minute))
}

// stableEndpoint returns an active endpoint whose StabilizedPing has settled to
// base (history filled with a constant RTT).
func stableEndpoint(base time.Duration, tun *RouterTunables) *NylonEndpoint {
	ep := NewEndpoint(NewDynamicEndpoint("127.0.0.1:0"), false, nil, tun)
	ep.Renew()
	for i := 0; i < tun.WindowSamples; i++ {
		ep.UpdatePing(base)
	}
	return ep
}

func TestEndpointLossConfidenceGate(t *testing.T) {
	tun := DefaultRouterTunables()
	ep := stableEndpoint(50*time.Millisecond, &tun)
	// fewer than the confidence window of loss samples: no penalty yet
	for i := 0; i < tun.MinimumConfidenceWindow-1; i++ {
		ep.RecordProbe(false)
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
		clean.RecordProbe(true)
		lossy.RecordProbe(false)
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
		ep.RecordProbe(i%4 != 0)
	}
	assert.InDelta(t, 0.25, ep.LossRate(), 0.05)
}

func TestEndpointLossMonotonic(t *testing.T) {
	tun := DefaultRouterTunables()
	base := 50 * time.Millisecond
	low := stableEndpoint(base, &tun)
	high := stableEndpoint(base, &tun)
	for i := 0; i < 400; i++ {
		low.RecordProbe(i%4 != 0)  // ~25% loss
		high.RecordProbe(i%2 != 0) // ~50% loss
	}
	assert.Greater(t, low.LossRate(), 0.0)
	assert.Greater(t, high.LossRate(), low.LossRate())
	assert.Greater(t, high.Metric(), low.Metric())
}

// A low-RTT but lossy link must lose to a clean higher-RTT link, which is the
// "long lossy link" problem ETX is designed to prevent.
func TestEndpointLossyLowRttLosesToCleanHighRtt(t *testing.T) {
	tun := DefaultRouterTunables()
	lossyFast := stableEndpoint(5*time.Millisecond, &tun)
	cleanSlow := stableEndpoint(80*time.Millisecond, &tun)
	for i := 0; i < tun.MinimumConfidenceWindow; i++ {
		lossyFast.RecordProbe(i%2 != 0) // ~50% loss
		cleanSlow.RecordProbe(true)
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
