//go:build integration

package core

import (
	"log/slog"
	"sync"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
)

type lifecycleVirtualNet struct {
	bind conn.Bind
	tun  tun.Device
}

func (v lifecycleVirtualNet) Bind(state.NodeId) conn.Bind { return v.bind }
func (v lifecycleVirtualNet) Tun(state.NodeId) tun.Device { return v.tun }

func TestNewNylonRollsBackAfterLateInitializationFailure(t *testing.T) {
	var mu sync.Mutex
	var closed []string
	record := func(resource string) {
		mu.Lock()
		closed = append(closed, resource)
		mu.Unlock()
	}
	bind := &lifecycleBind{record: record}
	tunDevice := newLifecycleTUN(record)
	key := state.NyPrivateKey{1}
	central := state.CentralCfg{Routers: []state.RouterCfg{{
		NodeCfg: state.NodeCfg{Id: "a", PubKey: key.Pubkey()},
	}}}
	local := state.LocalCfg{
		Id:             "a",
		Key:            key,
		Port:           57175,
		NoNetConfigure: true,
		LANDiscovery:   []string{"nylon-interface-that-does-not-exist"},
	}

	n, err := NewNylon(central, local, slog.LevelError, "", map[string]any{
		"vnet": lifecycleVirtualNet{bind: bind, tun: tunDevice},
	}, state.NylonOptions{}, nil)

	if err == nil {
		t.Fatal("NewNylon succeeded despite an invalid LAN discovery interface")
	}
	if n != nil {
		t.Fatal("failed initialization returned a Nylon instance")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 2 || closed[0] != "bind" || closed[1] != "tun" {
		t.Fatalf("closed resources = %v, want [bind tun]", closed)
	}
}
