//go:build !integration

package core

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/encodeous/nylon/log"
	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
)

var createWireGuardTUN = tun.CreateTUN
var initWireGuardUAPI = InitUAPI

func NewWireGuardDevice(n *Nylon) (dev *device.Device, tunDevice tun.Device, realItf string, err error) {
	itfName := n.InterfaceName // attempt to name the interface

	if runtime.GOOS == "darwin" {
		itfName = "utun"
	}

	mtu := n.Mtu
	if mtu == 0 {
		mtu = device.DefaultMTU
	}

	tdev, err := createWireGuardTUN(itfName, mtu)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create TUN: %v. Check if an interface with the name nylon exists already", err)
	}
	realInterfaceName, err := tdev.Name()
	if err == nil {
		itfName = realInterfaceName
	}

	wgLog := n.Log.With("module", log.ScopePolyamide)

	// setup WireGuard
	bind := conn.NewDefaultBind()
	defer func() {
		if err == nil {
			return
		}
		if n.wgUapi != nil {
			err = errors.Join(err, n.wgUapi.Close())
			n.wgUapi = nil
		}
		err = errors.Join(err, bind.Close(), tdev.Close())
	}()

	if n.CentralCfg.IsRouter(n.LocalCfg.Id) && n.GetRouter(n.LocalCfg.Id).TCPObfuscation {
		stdBind, ok := bind.(*conn.StdNetBind)
		if !ok {
			return nil, nil, "", fmt.Errorf("tcp_obfuscation requires the standard network bind")
		}
		fakeTCPStaleAfter := max(
			n.LinkDeadThreshold,
			device.RekeyTimeout+
				time.Duration(device.RekeyTimeoutJitterMaxMs)*time.Millisecond+
				n.ProbeRecoveryDelay,
		)
		if err := stdBind.EnableFakeTCP(fakeTCPStaleAfter); err != nil {
			return nil, nil, "", err
		}
	}
	// Start UAPI before the device, so every fallible acquisition is complete
	// before NewDevice starts its worker goroutines.
	n.wgUapi, err = initWireGuardUAPI(n.Log, itfName)
	if err != nil {
		return nil, nil, "", err
	}

	dev = device.NewDevice(tdev, bind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			if n.DBG_log_wireguard {
				wgLog.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			if strings.Contains(format, "Failed to send PolySock packets") {
				return
			}
			wgLog.Error(fmt.Sprintf(format, args...))
		},
	})

	if n.wgUapi != nil {
		uapi := n.wgUapi
		go func() {
			for {
				accept, err := uapi.Accept()
				if err != nil {
					n.Log.Debug(err.Error())
					return
				}
				go dev.IpcHandle(accept)
			}
		}()
	}

	n.Log.Info("Created WireGuard interface", "name", itfName)
	return dev, tdev, itfName, nil
}
