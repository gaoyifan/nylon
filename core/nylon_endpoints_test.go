package core

import (
	"slices"
	"sync"
	"testing"
)

func TestProbeTimestampAllocatorStrictlyIncreases(t *testing.T) {
	var timestamps probeTimestampAllocator

	if got := timestamps.next(100); got != 100 {
		t.Fatalf("first timestamp = %d, want 100", got)
	}
	if got := timestamps.next(100); got != 101 {
		t.Fatalf("repeated timestamp = %d, want 101", got)
	}
	if got := timestamps.next(99); got != 102 {
		t.Fatalf("backward timestamp = %d, want 102", got)
	}
}

func TestProbeTimestampAllocatorIsConcurrentAndUnique(t *testing.T) {
	const goroutines = 16
	const timestampsPerGoroutine = 64
	const total = goroutines * timestampsPerGoroutine
	const now = int64(100)

	var timestamps probeTimestampAllocator
	values := make(chan int64, total)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			<-start
			for range timestampsPerGoroutine {
				values <- timestamps.next(now)
			}
		})
	}
	close(start)
	wg.Wait()
	close(values)

	got := make([]int64, 0, total)
	for timestamp := range values {
		got = append(got, timestamp)
	}
	slices.Sort(got)
	for i, timestamp := range got {
		want := now + int64(i)
		if timestamp != want {
			t.Fatalf("timestamp %d = %d, want %d", i, timestamp, want)
		}
	}
}
