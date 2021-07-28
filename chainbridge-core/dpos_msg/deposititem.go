package dpos_msg

type DepositItem struct {
	SourceChainID uint8  // Source where message was initiated
	DestChainID   uint8  // Destination chain of message
	DepositNonce  uint64 // Nonce for the deposit
	ResourceId    [32]byte
	Data          []byte
}