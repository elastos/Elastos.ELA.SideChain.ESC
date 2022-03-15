package dpos_msg

import "github.com/elastos/Elastos.ELA/events"

// Constants for the type of a notification message.
const (
	ETSelfOnDuty         events.EventType = 2001
	ETOnArbiter          events.EventType = 2002
	ETRequireArbiter     events.EventType = 2003
	ETReqArbiterSig      events.EventType = 2004
	ETFeedBackArbiterSig events.EventType = 2005
)
