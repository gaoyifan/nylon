package core

import (
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/require"
)

func TestLANDiscoveryAnnouncementRoundTrip(t *testing.T) {
	key := state.GenerateKey()
	announcement, err := makeLANDiscoveryAnnouncement(key, 6622)
	require.NoError(t, err)
	require.Len(t, announcement, lanDiscoveryAnnouncementSize)

	publicKey, port, err := readLANDiscoveryAnnouncement(announcement)
	require.NoError(t, err)
	require.Equal(t, key.Pubkey(), publicKey)
	require.Equal(t, uint16(6622), port)
	_, err = state.VerifyBundle(announcement, publicKey)
	require.NoError(t, err)
}

func TestLANDiscoveryAnnouncementRejectsInvalidPackets(t *testing.T) {
	key := state.GenerateKey()
	announcement, err := makeLANDiscoveryAnnouncement(key, 6622)
	require.NoError(t, err)

	for _, packet := range [][]byte{
		announcement[:len(announcement)-1],
		append(append([]byte(nil), announcement...), 0),
	} {
		_, _, err = readLANDiscoveryAnnouncement(packet)
		require.Error(t, err)
	}

	announcement[0] ^= 1
	publicKey, _, err := readLANDiscoveryAnnouncement(announcement)
	require.NoError(t, err)
	_, err = state.VerifyBundle(announcement, publicKey)
	require.Error(t, err)

	zeroPort, err := makeLANDiscoveryAnnouncement(key, 0)
	require.NoError(t, err)
	_, _, err = readLANDiscoveryAnnouncement(zeroPort)
	require.Error(t, err)
}
