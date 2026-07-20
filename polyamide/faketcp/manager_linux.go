//go:build linux && !android && (amd64 || arm64)

package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/encodeous/nylon/polyamide/rwcancel"
	"golang.org/x/sys/unix"
)

const (
	ethSSFeatures  = 4
	ethGStringLen  = 32
	ethtoolBlockSz = 16
)

type Manager struct {
	objects transformerObjects
	links   []link.Link

	interfaceNames map[int]string
	netlinkFD      int
	netlinkCancel  *rwcancel.RWCancel
	errors         chan error
	watcher        sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

func Attach(port uint16, interfaceNames []string) (*Manager, error) {
	if err := requireKernel66(); err != nil {
		return nil, err
	}

	netlinkFD, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open fake TCP interface watcher: %w", err)
	}
	if err := unix.Bind(netlinkFD, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK,
	}); err != nil {
		unix.Close(netlinkFD)
		return nil, fmt.Errorf("bind fake TCP interface watcher: %w", err)
	}
	netlinkCancel, err := rwcancel.NewRWCancel(netlinkFD)
	if err != nil {
		unix.Close(netlinkFD)
		return nil, fmt.Errorf("make fake TCP interface watcher cancellable: %w", err)
	}

	manager := &Manager{
		interfaceNames: make(map[int]string),
		netlinkFD:      netlinkFD,
		netlinkCancel:  netlinkCancel,
		errors:         make(chan error, 1),
	}
	cleanup := func() {
		for i := len(manager.links) - 1; i >= 0; i-- {
			_ = manager.links[i].Close()
		}
		_ = manager.objects.Close()
		netlinkCancel.Close()
		_ = unix.Close(netlinkFD)
	}

	for _, name := range interfaceNames {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("look up fake TCP interface %q: %w", name, err)
		}
		if _, exists := manager.interfaceNames[iface.Index]; exists {
			continue
		}
		if err := requireHardwareAggregationOff(iface.Name); err != nil {
			cleanup()
			return nil, err
		}
		manager.interfaceNames[iface.Index] = iface.Name
	}

	spec, err := loadTransformer()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("load fake TCP BPF specification: %w", err)
	}
	if err := spec.Variables["managed_port"].Set(port); err != nil {
		cleanup()
		return nil, fmt.Errorf("set fake TCP managed port: %w", err)
	}
	if err := spec.LoadAndAssign(&manager.objects, nil); err != nil {
		cleanup()
		return nil, fmt.Errorf("load fake TCP BPF programs: %w", err)
	}

	for index, name := range manager.interfaceNames {
		egress, err := link.AttachTCX(link.TCXOptions{
			Interface: index,
			Program:   manager.objects.FakeTcpEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("attach fake TCP egress to %q: %w", name, err)
		}
		manager.links = append(manager.links, egress)

		ingress, err := link.AttachTCX(link.TCXOptions{
			Interface: index,
			Program:   manager.objects.FakeTcpIngress,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("attach fake TCP ingress to %q: %w", name, err)
		}
		manager.links = append(manager.links, ingress)
	}

	manager.watcher.Add(1)
	go manager.watchInterfaces()
	return manager, nil
}

func (m *Manager) Errors() <-chan error {
	return m.errors
}

func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		_ = m.netlinkCancel.Cancel()
		m.watcher.Wait()
		for i := len(m.links) - 1; i >= 0; i-- {
			m.closeErr = errors.Join(m.closeErr, m.links[i].Close())
		}
		m.closeErr = errors.Join(m.closeErr, m.objects.Close())
		close(m.errors)
	})
	return m.closeErr
}

func (m *Manager) watchInterfaces() {
	defer m.watcher.Done()
	defer m.netlinkCancel.Close()
	defer unix.Close(m.netlinkFD)

	buffer := make([]byte, 1<<16)
	for {
		n, _, _, _, err := unix.Recvmsg(m.netlinkFD, buffer, nil, 0)
		if err != nil && rwcancel.RetryAfterError(err) {
			if m.netlinkCancel.ReadyRead() {
				continue
			}
			return
		}
		if err != nil {
			m.reportError(fmt.Errorf("receive fake TCP interface event: %w", err))
			return
		}

		for remaining := buffer[:n]; len(remaining) >= unix.SizeofNlMsghdr; {
			header := *(*unix.NlMsghdr)(unsafe.Pointer(&remaining[0]))
			if header.Len < unix.SizeofNlMsghdr || int(header.Len) > len(remaining) {
				m.reportError(errors.New("invalid fake TCP interface netlink message"))
				return
			}
			message := remaining[:header.Len]
			aligned := (int(header.Len) + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
			if aligned > len(remaining) {
				aligned = len(remaining)
			}
			remaining = remaining[aligned:]

			if header.Type != unix.RTM_NEWLINK && header.Type != unix.RTM_DELLINK {
				continue
			}
			if len(message) < unix.SizeofNlMsghdr+unix.SizeofIfInfomsg {
				m.reportError(errors.New("short fake TCP interface netlink message"))
				return
			}
			info := *(*unix.IfInfomsg)(unsafe.Pointer(&message[unix.SizeofNlMsghdr]))
			name, tracked := m.interfaceNames[int(info.Index)]
			if !tracked {
				continue
			}
			if header.Type == unix.RTM_DELLINK {
				m.reportError(fmt.Errorf("fake TCP interface %q was removed", name))
				return
			}
			iface, err := net.InterfaceByIndex(int(info.Index))
			if err != nil || iface.Name != name {
				m.reportError(fmt.Errorf("fake TCP interface %q changed", name))
				return
			}
		}
	}
}

func (m *Manager) reportError(err error) {
	m.errors <- err
}

func requireKernel66() error {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return fmt.Errorf("read Linux kernel version: %w", err)
	}
	values := [2]int{}
	value, part := 0, 0
	for _, character := range name.Release {
		if character >= '0' && character <= '9' {
			value = value*10 + int(character-'0')
			continue
		}
		values[part] = value
		part++
		if part == len(values) {
			break
		}
		value = 0
	}
	if values[0] < 6 || values[0] == 6 && values[1] < 6 {
		return ErrUnsupported
	}
	return nil
}

type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [8 + unix.SizeofPtr]byte
}

func ethtoolIoctl(fd int, interfaceName string, data unsafe.Pointer) error {
	request := ifreqData{data: data}
	copy(request.name[:], interfaceName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL,
		uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}

func requireHardwareAggregationOff(interfaceName string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open ethtool socket for fake TCP interface %q: %w", interfaceName, err)
	}
	defer unix.Close(fd)

	setInfo := struct {
		command uint32
		_       uint32
		mask    uint64
		count   uint32
	}{command: unix.ETHTOOL_GSSET_INFO, mask: 1 << ethSSFeatures}
	if err := ethtoolIoctl(fd, interfaceName, unsafe.Pointer(&setInfo)); err != nil {
		return fmt.Errorf("query features of fake TCP interface %q: %w", interfaceName, err)
	}
	if setInfo.mask&(1<<ethSSFeatures) == 0 {
		return fmt.Errorf("fake TCP interface %q does not expose ethtool features", interfaceName)
	}

	stringsBuffer := make([]byte, 12+int(setInfo.count)*ethGStringLen)
	binary.NativeEndian.PutUint32(stringsBuffer[0:4], unix.ETHTOOL_GSTRINGS)
	binary.NativeEndian.PutUint32(stringsBuffer[4:8], ethSSFeatures)
	binary.NativeEndian.PutUint32(stringsBuffer[8:12], setInfo.count)
	if err := ethtoolIoctl(fd, interfaceName, unsafe.Pointer(&stringsBuffer[0])); err != nil {
		return fmt.Errorf("read features of fake TCP interface %q: %w", interfaceName, err)
	}

	blockCount := (int(setInfo.count) + 31) / 32
	featuresBuffer := make([]byte, 8+blockCount*ethtoolBlockSz)
	binary.NativeEndian.PutUint32(featuresBuffer[0:4], unix.ETHTOOL_GFEATURES)
	binary.NativeEndian.PutUint32(featuresBuffer[4:8], uint32(blockCount))
	if err := ethtoolIoctl(fd, interfaceName, unsafe.Pointer(&featuresBuffer[0])); err != nil {
		return fmt.Errorf("read feature state of fake TCP interface %q: %w", interfaceName, err)
	}

	for index := 0; index < int(setInfo.count); index++ {
		nameBytes := stringsBuffer[12+index*ethGStringLen : 12+(index+1)*ethGStringLen]
		name := unix.ByteSliceToString(nameBytes)
		if name != "rx-lro" && name != "rx-gro-hw" {
			continue
		}
		block := index / 32
		bit := uint(index % 32)
		active := binary.NativeEndian.Uint32(featuresBuffer[8+block*ethtoolBlockSz+8:])
		if active&(1<<bit) != 0 {
			return fmt.Errorf("fake TCP requires %s off on interface %q", name, interfaceName)
		}
	}
	return nil
}
