//go:build !integration

package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/encodeous/nylon/polyamide/tun"
)

type closeUnblocksListener struct {
	closeOnce     sync.Once
	closed        chan struct{}
	releaseSecond chan struct{}
	accepts       atomic.Int32
}

func newCloseUnblocksListener() *closeUnblocksListener {
	return &closeUnblocksListener{
		closed:        make(chan struct{}),
		releaseSecond: make(chan struct{}),
	}
}

func (l *closeUnblocksListener) Accept() (net.Conn, error) {
	if l.accepts.Add(1) == 1 {
		<-l.closed
	} else {
		<-l.releaseSecond
	}
	return nil, net.ErrClosed
}

func (l *closeUnblocksListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*closeUnblocksListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestNewWireGuardDeviceClosesTUNWhenUAPIFails(t *testing.T) {
	tunDevice := newLifecycleTUN(func(string) {})
	initErr := errors.New("initialize UAPI")
	originalCreateTUN := createWireGuardTUN
	originalInitUAPI := initWireGuardUAPI
	createWireGuardTUN = func(string, int) (tun.Device, error) { return tunDevice, nil }
	initWireGuardUAPI = func(*slog.Logger, string) (net.Listener, error) { return nil, initErr }
	t.Cleanup(func() {
		createWireGuardTUN = originalCreateTUN
		initWireGuardUAPI = originalInitUAPI
	})

	n := &Nylon{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dev, gotTUN, name, err := NewWireGuardDevice(n)

	if !errors.Is(err, initErr) {
		t.Fatalf("NewWireGuardDevice error = %v, want %v", err, initErr)
	}
	if dev != nil || gotTUN != nil || name != "" {
		t.Fatalf("failed initialization returned resources: dev=%v tun=%v name=%q", dev, gotTUN, name)
	}
	select {
	case <-tunDevice.closed:
	default:
		t.Fatal("TUN was not closed after UAPI initialization failed")
	}
	if n.wgUapi != nil {
		t.Fatal("failed UAPI listener was retained")
	}
}

func TestWireGuardUAPIAcceptLoopStopsAfterListenerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tunDevice := newLifecycleTUN(func(string) {})
		listener := newCloseUnblocksListener()
		originalCreateTUN := createWireGuardTUN
		originalInitUAPI := initWireGuardUAPI
		createWireGuardTUN = func(string, int) (tun.Device, error) { return tunDevice, nil }
		initWireGuardUAPI = func(*slog.Logger, string) (net.Listener, error) { return listener, nil }
		defer func() {
			createWireGuardTUN = originalCreateTUN
			initWireGuardUAPI = originalInitUAPI
		}()

		ctx, cancel := context.WithCancel(context.Background())
		n := &Nylon{
			Context: ctx,
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		dev, gotTUN, _, err := NewWireGuardDevice(n)
		if err != nil {
			t.Fatalf("NewWireGuardDevice: %v", err)
		}
		n.Device = dev
		n.Tun = gotTUN

		synctest.Wait()
		if err := n.closeWireGuardTransport(); err != nil {
			t.Fatalf("closeWireGuardTransport: %v", err)
		}
		synctest.Wait()
		accepts := listener.accepts.Load()

		cancel()
		close(listener.releaseSecond)
		synctest.Wait()
		if accepts != 1 {
			t.Fatalf("Accept called %d times after listener close, want 1", accepts)
		}
	})
}
