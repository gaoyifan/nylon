//go:build linux || openbsd || freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func (s *StdNetBind) SetMark(mark uint32) error {
	if fwmarkIoctl == 0 {
		return nil
	}
	for _, conn := range []*net.UDPConn{s.ipv4, s.ipv6, s.fakeIPv4, s.fakeIPv6} {
		if conn == nil {
			continue
		}
		fd, err := conn.SyscallConn()
		if err != nil {
			return err
		}
		var operr error
		err = fd.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
		})
		if err == nil {
			err = operr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
