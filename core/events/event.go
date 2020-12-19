package events

// MinedBlockEvent is posted when a block has been imported.
type MinedBlockEvent struct{}

// OnDutyEvent is posted when self is on duty.
type OnDutyEvent struct{}

//InitCurrentProducers is posted when spv module is initialization completed
type InitCurrentProducers struct {}
