/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"
)

func TestSendHandshakeInitiationTo(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, false)
	peers := pair[0].dev.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	peer := peers[0]
	endpoints := peer.GetEndpoints()
	if len(endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(endpoints))
	}
	explicitEndpoint := endpoints[0]

	// Discovery must work before the peer has any configured endpoint.
	peer.SetEndpoints(nil)
	if err := peer.SendHandshakeInitiationTo(explicitEndpoint); err != nil {
		t.Fatalf("explicit handshake failed: %v", err)
	}
	if peer.timers.retransmitHandshake.IsPending() {
		t.Fatal("explicit handshake scheduled retransmission")
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for peer.keypairs.Current() == nil {
		select {
		case <-deadline.C:
			t.Fatal("explicit handshake did not establish a keypair")
		case <-ticker.C:
		}
	}

	// A usable current keypair suppresses a discovery handshake before it
	// mutates the normal handshake rate-limit state.
	oldLastSent := time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = oldLastSent
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiationTo(explicitEndpoint); err != nil {
		t.Fatalf("handshake with usable keypair failed: %v", err)
	}
	peer.handshake.mutex.RLock()
	lastSent := peer.handshake.lastSentHandshake
	peer.handshake.mutex.RUnlock()
	if !lastSent.Equal(oldLastSent) {
		t.Fatal("explicit handshake was sent despite a usable current keypair")
	}
}
