package state

import "time"

// RouterTunables contains all timing and algorithm parameters for the router.
// These are set once at startup and should not be mutated after the Nylon instance starts.
type RouterTunables struct {
	HopCost               uint32        // add a 5 microsecond hop cost to prevent loops on ultra-fast networks.
	TransitCost           uint32        // extra cost (microseconds) added to routes learned from neighbours, penalizing transit through this node; own prefixes are unaffected (transit_cost in node.yaml)
	TCPCost               time.Duration // non-negative fake-TCP penalty applied to outbound selection and link cost (tcp_cost in node.yaml)
	UDPCost               time.Duration // non-negative UDP penalty applied to outbound selection and link cost (udp_cost in node.yaml)
	LargeChangeThreshold  uint32        // 100 milliseconds change
	SeqnoRequestHopCount  uint8
	RouteUpdateDelay      time.Duration
	ProbeDelay            time.Duration
	ProbeRecoveryDelay    time.Duration
	ProbeDiscoveryDelay   time.Duration
	StarvationDelay       time.Duration
	SeqnoDedupTTL         time.Duration
	NeighbourIOFlushDelay time.Duration
	IPCDispatchTimeout    time.Duration
	SafeMTU               int

	// WindowSamples is the sliding window size
	WindowSamples     int
	OutlierPercentage float64
	// MinimumConfidenceWindow is the minimum number of samples before we lower the ping
	MinimumConfidenceWindow int

	GcDelay           time.Duration
	LinkDeadThreshold time.Duration
	RouteExpiryTime   time.Duration

	// Packet-loss metric factor (ETX-style). The per-link metric is penalized
	// as: metric = base/(1-p) + LossRetxFloor * p/(1-p), where p is the
	// smoothed loss rate clamped to LossCap.
	LossSmoothingAlpha float64       // EWMA factor for per-probe loss samples
	LossRetxFloor      time.Duration // fixed per-retransmission cost floor
	LossCap            float64       // upper clamp on the loss rate (< 1)

	// MetricSmoothingAlpha is the EWMA factor for the smoothed route metric
	// ms(R) used by the RFC 8966 A.3 dual-metric route-selection hysteresis.
	MetricSmoothingAlpha float64

	// client configuration
	ClientKeepaliveInterval time.Duration
	ClientDeadThreshold     time.Duration

	// central updates
	CentralUpdateDelay time.Duration

	// healthcheck defaults
	HealthCheckDelay       time.Duration
	HealthCheckMaxFailures int

	EndpointResolveExpiry time.Duration
	EndpointResolveDelay  time.Duration

	MaxConfigSize int64
}

// NylonOptions contains runtime flags set at startup (typically from CLI flags).
type NylonOptions struct {
	DBG_log_probe        bool
	DBG_log_wireguard    bool
	DBG_log_repo_updates bool
	DBG_log_json         bool
	DBG_debug            bool
	DBG_trace            bool
	DBG_trace_tc         bool

	// Exit-node overrides. Each value is paired with a *Set boolean so an
	// empty value can still represent "explicitly cleared by CLI" without
	// being ambiguous with "not specified".
	AdvertiseExitNode    bool
	AdvertiseExitNodeSet bool
	ExitNode             NodeId
	ExitNodeSet          bool

	ExitNodeDefaultRoute    bool
	ExitNodeDefaultRouteSet bool
}

func DefaultRouterTunables() RouterTunables {
	probeDelay := time.Millisecond * 1000
	routeUpdateDelay := time.Second * 5
	return RouterTunables{
		HopCost:               5,
		LargeChangeThreshold:  100 * 1000,
		SeqnoRequestHopCount:  64,
		RouteUpdateDelay:      routeUpdateDelay,
		ProbeDelay:            probeDelay,
		ProbeRecoveryDelay:    time.Millisecond * 1500,
		ProbeDiscoveryDelay:   time.Second * 10,
		StarvationDelay:       time.Millisecond * 100,
		SeqnoDedupTTL:         time.Second * 3,
		NeighbourIOFlushDelay: time.Millisecond * 500,
		IPCDispatchTimeout:    time.Second,
		SafeMTU:               1200,

		WindowSamples:           int((time.Second * 60) / probeDelay),
		OutlierPercentage:       0.05,
		MinimumConfidenceWindow: int(time.Second * 15 / probeDelay),

		GcDelay:           time.Millisecond * 1000,
		LinkDeadThreshold: 5 * probeDelay,
		RouteExpiryTime:   5 * routeUpdateDelay,

		LossSmoothingAlpha: 0.1,
		LossRetxFloor:      time.Millisecond * 100,
		LossCap:            0.95,

		// time constant ~3x RouteUpdateDelay; with updates roughly every
		// RouteUpdateDelay this yields a smoothing factor near 1/3.
		MetricSmoothingAlpha: 0.33,

		ClientKeepaliveInterval: 3 * probeDelay,
		ClientDeadThreshold:     6 * probeDelay, // 2 * ClientKeepaliveInterval

		CentralUpdateDelay: time.Second * 10,

		HealthCheckDelay:       time.Second * 15,
		HealthCheckMaxFailures: 3,

		EndpointResolveExpiry: time.Minute * 1,
		EndpointResolveDelay:  time.Second * 15,

		MaxConfigSize: 1 << 20, // 1 MB
	}
}

func DefaultNylonOptions() NylonOptions {
	return NylonOptions{}
}
