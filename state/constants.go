package state

const (
	INF = ^(uint32)(0)
	// INFM is the maximum value for a metric that is not a retraction.
	INFM = INF - 1

	// default port
	DefaultPort = 57175
	// LANDiscoveryPort is reserved for LAN discovery announcements.
	LANDiscoveryPort = 57176
)
