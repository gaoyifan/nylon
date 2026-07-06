//go:build !linux

package core

// probeNowNs returns the probe timestamp clock. On platforms without
// CLOCK_MONOTONIC_RAW support wired up, use the Go runtime monotonic clock;
// it is immune to wall-clock steps, though it may follow OS frequency
// slewing.
func probeNowNs() int64 {
	return probeNowNsFallback()
}
