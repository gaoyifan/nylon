package core

import (
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
)

func TestBuildEndpointsReportsFakeTCPTransport(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	endpoint := state.NewEndpoint(
		state.NewDynamicEndpoint("192.0.2.1:57175"),
		false,
		nil,
		&tunables,
	)
	endpoint.Transport = conn.TransportFakeTCP

	got := buildEndpoints(&state.Neighbour{Eps: []state.Endpoint{endpoint}})
	if len(got) != 1 {
		t.Fatalf("buildEndpoints returned %d endpoints, want 1", len(got))
	}
	if got[0].Transport != protocol.EndpointTransport_FAKE_TCP {
		t.Fatalf("transport = %v, want %v", got[0].Transport, protocol.EndpointTransport_FAKE_TCP)
	}
}

func TestBuildEndpointsKeepsRawMetricWithTCPCost(t *testing.T) {
	tunables := state.DefaultRouterTunables()
	tunables.TCPCost = -5 * time.Millisecond
	udp := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.1:57175"), false, nil, &tunables)
	tcp := state.NewEndpoint(state.NewDynamicEndpoint("192.0.2.1:57176"), false, nil, &tunables)
	tcp.Transport = conn.TransportFakeTCP
	udp.Renew()
	tcp.Renew()

	got := buildEndpoints(&state.Neighbour{Eps: []state.Endpoint{udp, tcp}})
	if len(got) != 2 {
		t.Fatalf("buildEndpoints returned %d endpoints, want 2", len(got))
	}
	if !got[0].Selected || got[0].Transport != protocol.EndpointTransport_FAKE_TCP {
		t.Fatalf("first endpoint = %+v, want selected fake TCP", got[0])
	}
	if got[0].Metric != state.DurationToMetric(state.WarmupDelay) {
		t.Fatalf("reported metric = %d, want raw warmup metric", got[0].Metric)
	}
}

func TestIPCProbeTimeout(t *testing.T) {
	tests := []struct {
		name      string
		timeoutMs uint32
		want      time.Duration
	}{
		{
			name: "default",
			want: defaultIPCProbeTimeout,
		},
		{
			name:      "user value",
			timeoutMs: 1500,
			want:      1500 * time.Millisecond,
		},
		{
			name:      "capped",
			timeoutMs: uint32((maxIPCProbeTimeout + time.Second) / time.Millisecond),
			want:      maxIPCProbeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipcProbeTimeout(&protocol.ProbeRequest{TimeoutMs: tt.timeoutMs})
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}
