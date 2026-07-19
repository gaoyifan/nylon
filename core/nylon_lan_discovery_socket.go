package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/encodeous/nylon/state"
	"golang.org/x/net/ipv4"
)

const lanDiscoveryPort = state.LANDiscoveryPort

type lanDiscoverySocket struct {
	udp        *net.UDPConn
	packet     *ipv4.PacketConn
	interfaces map[int]*lanDiscoveryInterface
}

type lanDiscoveryInterface struct {
	index   int
	name    string
	subnets []lanDiscoverySubnet
}

type lanDiscoverySubnet struct {
	prefix    netip.Prefix
	broadcast netip.Addr
}

func (i *lanDiscoveryInterface) contains(source netip.Addr) bool {
	source = source.Unmap()
	for _, subnet := range i.subnets {
		if subnet.prefix.Contains(source) {
			return true
		}
	}
	return false
}

func (i *lanDiscoveryInterface) acceptsAnnouncement(source netip.AddrPort, destination netip.Addr) bool {
	if source.Port() != lanDiscoveryPort {
		return false
	}
	sourceAddr := source.Addr().Unmap()
	destination = destination.Unmap()
	for _, subnet := range i.subnets {
		if subnet.prefix.Contains(sourceAddr) && subnet.broadcast == destination {
			return true
		}
	}
	return false
}

func openLANDiscoverySocket(names []string) (*lanDiscoverySocket, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("LAN discovery requires at least one interface")
	}

	interfaces := make(map[int]*lanDiscoveryInterface, len(names))
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("resolve LAN discovery interface %s: %w", name, err)
		}
		subnets, err := interfaceIPv4Subnets(iface)
		if err != nil {
			return nil, err
		}
		if len(subnets) == 0 {
			return nil, fmt.Errorf("LAN discovery interface %s has no IPv4 broadcast address", name)
		}
		interfaces[iface.Index] = &lanDiscoveryInterface{
			index:   iface.Index,
			name:    iface.Name,
			subnets: subnets,
		}
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: lanDiscoveryPort,
	})
	if err != nil {
		return nil, fmt.Errorf("listen for LAN discovery: %w", err)
	}

	packet := ipv4.NewPacketConn(udp)
	if err := packet.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true); err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("enable LAN discovery packet metadata: %w", err)
	}
	return &lanDiscoverySocket{
		udp:        udp,
		packet:     packet,
		interfaces: interfaces,
	}, nil
}

func interfaceIPv4Subnets(iface *net.Interface) ([]lanDiscoverySubnet, error) {
	if iface.Flags&net.FlagBroadcast == 0 {
		return nil, nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list LAN discovery addresses on %s: %w", iface.Name, err)
	}
	seen := make(map[netip.Prefix]struct{})
	subnets := make([]lanDiscoverySubnet, 0, len(addrs))
	for _, address := range addrs {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 31 {
			continue
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		ip := prefix.Addr().As4()
		mask := net.CIDRMask(prefix.Bits(), 32)
		for i := range ip {
			ip[i] |= ^mask[i]
		}
		subnets = append(subnets, lanDiscoverySubnet{
			prefix:    prefix,
			broadcast: netip.AddrFrom4(ip),
		})
	}
	return subnets, nil
}

func (s *lanDiscoverySocket) Send(payload []byte) error {
	var sendErr error
	for _, iface := range s.interfaces {
		for _, subnet := range iface.subnets {
			destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(subnet.broadcast, lanDiscoveryPort))
			_, err := s.packet.WriteTo(payload, &ipv4.ControlMessage{IfIndex: iface.index}, destination)
			if err != nil {
				sendErr = errors.Join(sendErr, fmt.Errorf("broadcast LAN discovery announcement on %s: %w", iface.name, err))
			}
		}
	}
	return sendErr
}

func (s *lanDiscoverySocket) Read() ([]byte, netip.AddrPort, *lanDiscoveryInterface, error) {
	buf := make([]byte, lanDiscoveryAnnouncementSize+1)
	for {
		n, control, source, err := s.packet.ReadFrom(buf)
		if err != nil {
			return nil, netip.AddrPort{}, nil, err
		}
		if control == nil {
			continue
		}
		iface, ok := s.interfaces[control.IfIndex]
		if !ok {
			continue
		}

		udpSource, ok := source.(*net.UDPAddr)
		if !ok {
			return nil, netip.AddrPort{}, nil, fmt.Errorf("unexpected LAN discovery source type %T", source)
		}
		sourceAddrPort := udpSource.AddrPort()
		sourceAddrPort = netip.AddrPortFrom(sourceAddrPort.Addr().Unmap(), sourceAddrPort.Port())
		destination, ok := netip.AddrFromSlice(control.Dst)
		if !ok || !iface.acceptsAnnouncement(sourceAddrPort, destination) {
			continue
		}
		return buf[:n], sourceAddrPort, iface, nil
	}
}

func (s *lanDiscoverySocket) Close() error {
	return s.udp.Close()
}
