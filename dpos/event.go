package dpos

import "github.com/elastos/Elastos.ELA/events"

// Constants for the type of a notification message.
const (
	ETNewPeer      events.EventType = 1000
	ETDonePeer     events.EventType = 1001
	ETStopRoutes   events.EventType = 1002
	ETElaMsg       events.EventType = 1003
	ETAnnounceAddr events.EventType = 1004
)
