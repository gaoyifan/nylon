package core

import (
	"golang.org/x/sys/unix"
)

// probeNowNs returns the probe timestamp clock: CLOCK_MONOTONIC_RAW, the
// raw hardware-based tick counter. Unlike CLOCK_MONOTONIC (which backs Go's
// time.Since), it is not frequency-disciplined by NTP (adjtimex slewing, up
// to ±500ppm), so probe delay measurements are independent of wall-clock
// calibration. The epoch (boot time) is arbitrary, which is fine: probes
// only ever compare timestamps from the same process, or combine timestamps
// from two processes in ways where the unknown offset cancels (see
// protocol.Ny_Probe).
func probeNowNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		// CLOCK_MONOTONIC_RAW exists on every kernel nylon can run on
		// (>= 2.6.28); if the vDSO call somehow fails, fall back to the Go
		// monotonic clock rather than breaking probing.
		return probeNowNsFallback()
	}
	return ts.Nano()
}
