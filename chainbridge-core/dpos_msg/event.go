package dpos_msg

import "github.com/elastos/Elastos.ELA/events"

// Constants for the type of a notification message.
const (
	ETOnProposal         events.EventType = 2001
	ETSelfOnDuty         events.EventType = 2002
	ETOnArbiter          events.EventType = 2003
	ETRequireArbiter     events.EventType = 2004
	ETReqArbiterSig      events.EventType = 2005
	ETFeedBackArbiterSig events.EventType = 2006
)
