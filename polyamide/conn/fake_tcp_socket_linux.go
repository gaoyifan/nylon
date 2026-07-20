//go:build linux && !android && (amd64 || arm64)

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func fakeTCPPlatformSupported() bool { return true }

func fakeTCPListenControl(fake bool) controlFn {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			if sockErr != nil {
				return
			}
			if network == "udp6" {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_NO_CHECK6_RX, 1)
				if sockErr == nil && fake {
					sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_NO_CHECK6_TX, 1)
				}
			} else if fake {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_NO_CHECK, 1)
			}
			if sockErr == nil && fake {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 0)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
