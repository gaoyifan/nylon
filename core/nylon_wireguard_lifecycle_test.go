package core

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/faketcp"
	"github.com/encodeous/nylon/polyamide/tun"
)

type lifecycleBind struct {
	once     sync.Once
	record   func(string)
	closeErr error
}

func (*lifecycleBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}
func (b *lifecycleBind) Close() error {
	b.once.Do(func() { b.record("bind") })
	return b.closeErr
}
func (*lifecycleBind) SetMark(uint32) error                        { return nil }
func (*lifecycleBind) Send([][]byte, conn.Endpoint) error          { return nil }
func (*lifecycleBind) ParseEndpoint(string) (conn.Endpoint, error) { return nil, nil }
func (*lifecycleBind) BatchSize() int                              { return 1 }

type lifecycleTUN struct {
	once   sync.Once
	record func(string)
	closed chan struct{}
	events chan tun.Event
}

func newLifecycleTUN(record func(string)) *lifecycleTUN {
	return &lifecycleTUN{record: record, closed: make(chan struct{}), events: make(chan tun.Event)}
}

func (*lifecycleTUN) File() *os.File { return nil }
func (t *lifecycleTUN) Read([][]byte, []int, int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}
func (*lifecycleTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (*lifecycleTUN) MTU() (int, error)                       { return device.DefaultMTU, nil }
func (*lifecycleTUN) Name() (string, error)                   { return "lifecycle", nil }
func (t *lifecycleTUN) Events() <-chan tun.Event              { return t.events }
func (t *lifecycleTUN) Close() error {
	t.once.Do(func() {
		t.record("tun")
		close(t.closed)
		close(t.events)
	})
	return nil
}
func (*lifecycleTUN) BatchSize() int { return 1 }

type lifecycleListener struct {
	record   func(string)
	closeErr error
}

func (*lifecycleListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *lifecycleListener) Close() error {
	l.record("uapi")
	return l.closeErr
}
func (*lifecycleListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestCloseWireGuardTransportClosesSocketsBeforeTCXAndJoinsErrors(t *testing.T) {
	var order []string
	record := func(step string) { order = append(order, step) }
	bindErr := errors.New("bind close")
	uapiErr := errors.New("uapi close")
	tcxErr := errors.New("tcx close")

	bind := &lifecycleBind{record: record, closeErr: bindErr}
	tunDevice := newLifecycleTUN(record)
	dev := device.NewDevice(tunDevice, bind, &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	})
	n := &Nylon{
		Device:  dev,
		Tun:     tunDevice,
		wgUapi:  &lifecycleListener{record: record, closeErr: uapiErr},
		fakeTCP: &faketcp.Manager{},
	}

	originalClose := closeFakeTCPManager
	closeFakeTCPManager = func(*faketcp.Manager) error {
		record("tcx")
		return tcxErr
	}
	t.Cleanup(func() { closeFakeTCPManager = originalClose })

	err := n.closeWireGuardTransport()

	if !errors.Is(err, bindErr) || !errors.Is(err, uapiErr) || !errors.Is(err, tcxErr) {
		t.Fatalf("cleanup error %v does not preserve every resource error", err)
	}
	want := []string{"bind", "tun", "uapi", "tcx"}
	if len(order) != len(want) {
		t.Fatalf("cleanup order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("cleanup order = %v, want %v", order, want)
		}
	}
	if n.Device != nil || n.Tun != nil || n.wgUapi != nil || n.fakeTCP != nil {
		t.Fatal("closed resources were not cleared")
	}
}
