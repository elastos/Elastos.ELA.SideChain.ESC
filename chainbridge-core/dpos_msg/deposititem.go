package dpos_msg

type DepositItem struct {
	SourceChainID uint64 // Source where message was initiated
	DestChainID   uint64 // Destination chain of message
	DepositNonce  uint64 // Nonce for the deposit
	ResourceId    [32]byte
	Data          []byte
}
