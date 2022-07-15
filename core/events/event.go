package events

import (
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
)

// MinedBlockEvent is posted when a block has been imported.
type MinedBlockEvent struct{}

// OnDutyEvent is posted when self is on duty.
type OnDutyEvent struct{}

//InitCurrentProducers is posted when spv module is initialization completed
type InitCurrentProducers struct{}

//CmallCrossTx is posted when a small cross transaction is received 2/3 signatures
type CmallCrossTx struct {
	Tx it.Transaction
}
