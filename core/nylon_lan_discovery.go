package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"go.step.sm/crypto/x25519"
)

var lanDiscoveryDomain = []byte("nylon/lan-discovery/v1\x00")

const lanDiscoveryAnnouncementSize = x25519.SignatureSize + len("nylon/lan-discovery/v1\x00") + 2 + len(state.NyPublicKey{})

type lanDiscoveryAttemptKey struct {
	peer          state.NodeId
	interfaceName string
}

type lanDiscoveryService struct {
	socket       *lanDiscoverySocket
	announcement []byte
	lastAttempt  map[lanDiscoveryAttemptKey]time.Time
	readerDone   chan struct{}
	closeOnce    sync.Once
}

func makeLANDiscoveryAnnouncement(key state.NyPrivateKey, port uint16) ([]byte, error) {
	payload := make([]byte, len(lanDiscoveryDomain)+2+len(state.NyPublicKey{}))
	copy(payload, lanDiscoveryDomain)
	binary.BigEndian.PutUint16(payload[len(lanDiscoveryDomain):], port)
	publicKey := key.Pubkey()
	copy(payload[len(lanDiscoveryDomain)+2:], publicKey[:])
	return state.SignBundle(payload, key)
}

func readLANDiscoveryAnnouncement(data []byte) (state.NyPublicKey, uint16, error) {
	var publicKey state.NyPublicKey
	if len(data) != lanDiscoveryAnnouncementSize {
		return publicKey, 0, fmt.Errorf("invalid LAN discovery announcement size %d", len(data))
	}

	payload := data[x25519.SignatureSize:]
	if !bytes.HasPrefix(payload, lanDiscoveryDomain) {
		return publicKey, 0, errors.New("invalid LAN discovery protocol version")
	}
	portOffset := len(lanDiscoveryDomain)
	port := binary.BigEndian.Uint16(payload[portOffset : portOffset+2])
	if port == 0 {
		return publicKey, 0, errors.New("invalid LAN discovery WireGuard port")
	}
	copy(publicKey[:], payload[portOffset+2:])
	return publicKey, port, nil
}

func (n *Nylon) initLANDiscovery() error {
	if len(n.LocalCfg.LANDiscovery) == 0 {
		return nil
	}

	socket, err := openLANDiscoverySocket(n.LocalCfg.LANDiscovery)
	if err != nil {
		return err
	}
	announcement, err := makeLANDiscoveryAnnouncement(n.LocalCfg.Key, n.Device.ListenPort())
	if err != nil {
		_ = socket.Close()
		return fmt.Errorf("sign LAN discovery announcement: %w", err)
	}

	service := &lanDiscoveryService{
		socket:       socket,
		announcement: announcement,
		lastAttempt:  make(map[lanDiscoveryAttemptKey]time.Time),
		readerDone:   make(chan struct{}),
	}
	n.lanDiscovery = service
	go service.readLoop(n)

	n.RepeatTask(func() error {
		if err := service.socket.Send(service.announcement); err != nil {
			n.Log.Debug("failed to send LAN discovery announcement", "error", err)
		}
		return nil
	}, n.ProbeDiscoveryDelay)
	n.Log.Info("enabled LAN discovery", "interfaces", n.LocalCfg.LANDiscovery, "port", lanDiscoveryPort)
	return nil
}

func (d *lanDiscoveryService) readLoop(n *Nylon) {
	defer close(d.readerDone)
	for {
		packet, source, iface, err := d.socket.Read()
		if err != nil {
			if n.Context.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			n.Cancel(fmt.Errorf("read LAN discovery announcement: %w", err))
			return
		}

		publicKey, port, err := readLANDiscoveryAnnouncement(packet)
		if err != nil {
			continue
		}
		peerMap := n.PeerMap.Load()
		if peerMap == nil {
			continue
		}
		peer, ok := (*peerMap)[publicKey]
		if !ok || peer == n.LocalCfg.Id {
			continue
		}
		candidate := netip.AddrPortFrom(source.Addr(), port)
		if _, err := state.VerifyBundle(packet, publicKey); err != nil {
			continue
		}
		attemptKey := lanDiscoveryAttemptKey{peer: peer, interfaceName: iface.name}
		if time.Since(d.lastAttempt[attemptKey]) < state.ProbeTimeout {
			continue
		}
		if n.Dispatch(func() error {
			n.handleLANDiscoveryAnnouncement(peer, publicKey, iface.name, candidate)
			return nil
		}) {
			d.lastAttempt[attemptKey] = time.Now()
		}
	}
}

func (n *Nylon) handleLANDiscoveryAnnouncement(peerID state.NodeId, publicKey state.NyPublicKey, interfaceName string, candidate netip.AddrPort) {
	neighbour := n.RouterState.GetNeighbour(peerID)
	if neighbour == nil {
		return
	}
	peer := n.Device.LookupPeer(device.NoisePublicKey(publicKey))
	if peer == nil {
		return
	}

	for _, endpoint := range neighbour.Eps {
		lanEndpoint := endpoint.AsNylonEndpoint()
		resolved, err := lanEndpoint.DynEP.Get()
		if err == nil && resolved == candidate && lanEndpoint.IsRemote() && lanEndpoint.IsActive() &&
			lanEndpoint.Bind.Interface == interfaceName {
			return
		}
	}

	candidateEndpoint := state.NewEndpoint(
		state.NewDynamicEndpoint(candidate.String()),
		true,
		nil,
		&n.RouterTunables,
	)
	candidateEndpoint.Bind.Interface = interfaceName
	wgEndpoint, err := candidateEndpoint.GetWgEndpoint(n.Device)
	if err != nil {
		n.Log.Debug("failed to prepare LAN discovery candidate", "peer", peerID, "endpoint", candidate, "error", err)
		return
	}

	if err := peer.SendHandshakeInitiationTo(wgEndpoint); err != nil {
		n.Log.Debug("failed to initiate LAN discovery handshake", "peer", peerID, "endpoint", candidate, "error", err)
		return
	}
	_, err = n.sendDiscoveryEndpointProbe(peerID, candidateEndpoint, state.ProbeTimeout)
	if err != nil {
		n.Log.Debug("failed to probe LAN discovery candidate", "peer", peerID, "endpoint", candidate, "error", err)
	}
}

func (d *lanDiscoveryService) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.socket.Close()
		<-d.readerDone
	})
	return closeErr
}

func promoteLANDiscoveryEndpoint(n *Nylon, node state.NodeId, pkt *protocol.Ny_Probe, wgEndpoint conn.Endpoint, candidate *state.NylonEndpoint, rxTs int64) {
	endpoint := wgEndpoint.DstIPPort()
	indexed, ok := wgEndpoint.(interface{ SrcIfidx() int32 })
	if !ok {
		return
	}
	iface, ok := n.lanDiscovery.socket.interfaces[int(indexed.SrcIfidx())]
	if !ok || iface.name != candidate.Bind.Interface || !iface.contains(endpoint.Addr()) {
		return
	}

	neighbour := n.RouterState.GetNeighbour(node)
	if neighbour == nil {
		return
	}

	for _, link := range neighbour.Eps {
		lanEndpoint := link.AsNylonEndpoint()
		resolved, err := lanEndpoint.DynEP.Get()
		if err != nil || resolved != endpoint || !lanEndpoint.IsRemote() ||
			lanEndpoint.Bind.Interface != candidate.Bind.Interface {
			continue
		}
		wasInactive := !lanEndpoint.IsActive()
		lanEndpoint.WgEndpoint = wgEndpoint
		lanEndpoint.Renew()
		if pkt.OriginTxTs != nil {
			lanEndpoint.RegisterProbe(*pkt.OriginTxTs)
		}
		observeProbe(lanEndpoint, pkt, rxTs)
		if wasInactive {
			ComputeRoutes(n.RouterState, n)
			n.UpdateNeighbour(node)
		} else {
			n.ScheduleRouteCompute(n.StarvationDelay)
		}
		return
	}

	candidate.DynEP = state.NewDynamicEndpoint(endpoint.String())
	candidate.WgEndpoint = wgEndpoint
	candidate.Renew()
	if pkt.OriginTxTs != nil {
		candidate.RegisterProbe(*pkt.OriginTxTs)
	}
	observeProbe(candidate, pkt, rxTs)
	neighbour.Eps = append(neighbour.Eps, candidate)
	ComputeRoutes(n.RouterState, n)
	n.UpdateNeighbour(node)
}
