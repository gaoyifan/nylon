//go:build linux && !android && (amd64 || arm64)

package conn_test

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/faketcp"
)

func TestFakeTCPLoopbackHandshakeAndData(t *testing.T) {
	if os.Getenv("NYLON_PRIVILEGED_TESTS") != "1" {
		t.Skip("set NYLON_PRIVILEGED_TESTS=1 to run kernel BPF tests")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	bind := conn.NewStdNetBind().(*conn.StdNetBind)
	if err := bind.EnableFakeTCP(time.Second); err != nil {
		t.Fatal(err)
	}
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := faketcp.Attach(port, []string{loopback.Name})
	if err != nil {
		_ = bind.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
		if err := bind.Close(); err != nil {
			t.Error(err)
		}
	})

	received := make(chan []byte, 1)
	receiveErrors := make(chan error, len(receivers))
	for _, receive := range receivers {
		go func(receive conn.ReceiveFunc) {
			for {
				buffers := make([][]byte, conn.IdealBatchSize)
				for i := range buffers {
					buffers[i] = make([]byte, 2048)
				}
				sizes := make([]int, conn.IdealBatchSize)
				endpoints := make([]conn.Endpoint, conn.IdealBatchSize)
				n, err := receive(buffers, sizes, endpoints)
				if err != nil {
					receiveErrors <- err
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] != 0 {
						received <- append([]byte(nil), buffers[i][:sizes[i]]...)
					}
				}
			}
		}(receive)
	}

	endpoint := &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	endpoint.SetSrc(netip.MustParseAddr("127.0.0.1"), int32(loopback.Index))
	endpoint.SetTransport(conn.TransportFakeTCP)
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := bind.PrepareFakeTCP(endpoint)
		if err == nil {
			break
		}
		if !errors.Is(err, conn.ErrFakeTCPNotEstablished) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("fake TCP handshake did not establish")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := []byte("wireguard datagram over fake TCP")
	if err := bind.Send([][]byte{payload}, endpoint); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if string(got) != string(payload) {
			t.Fatalf("received %q, want %q", got, payload)
		}
	case err := <-receiveErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("fake TCP data was not received")
	}
}
