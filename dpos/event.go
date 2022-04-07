// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import "github.com/elastos/Elastos.ELA/events"

// Constants for the type of a notification message.
const (
	ETNewPeer          events.EventType = 1000
	ETDonePeer         events.EventType = 1001
	ETStopRoutes       events.EventType = 1002
	ETElaMsg           events.EventType = 1003
	ETAnnounceAddr     events.EventType = 1004
	ETNextProducers    events.EventType = 1005
	ETOnSPVHeight      events.EventType = 1006
	ETSmallCroTx       events.EventType = 1007
	ETFailedWithdrawTx events.EventType = 1008
	ETUpdateProducers  events.EventType = 1009
	ETOnDutyEvent      events.EventType = 1010
)
