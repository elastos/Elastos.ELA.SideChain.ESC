package dpos_msg

import "github.com/elastos/Elastos.ELA/events"

// Constants for the type of a notification message.
const (
	ETOnArbiter          events.EventType = 2001
	ETRequireArbiter     events.EventType = 2002
	ETReqArbiterSig      events.EventType = 2003
	ETFeedBackArbiterSig events.EventType = 2004
	ETESCStateChanged    events.EventType = 2005
)
