package _interface

import (
	"github.com/elastos/Elastos.ELA.SPV/bloom"
	"github.com/elastos/Elastos.ELA.SPV/interface/store"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
)

// SPV service config
type Config struct {
	// DataDir is the data path to store db files peer addresses etc.
	DataDir string

	// The chain parameters within network settings.
	ChainParams *config.Params

	// PermanentPeers are the peers need to be connected permanently.
	PermanentPeers []string

	// Rollback callbacks that, the transactions
	// on the given height has been rollback
	OnRollback func(height uint32)

	//FilterType is the filter type .(FTBloom, FTDPOS  and so on )
	FilterType uint8

	//node version
	NodeVersion string

	//this spv GenesisBlockAddress
	GenesisBlockAddress string
}

/*
SPV service is the interface to interactive with the SPV (Simplified Payment Verification)
service implementation running background, you can register specific accounts that you are
interested in and receive transaction notifications of these accounts.
*/
type SPVService interface {
	// RegisterTransactionListener register the listener to receive transaction notifications
	// listeners must be registered before call Start() method, or some notifications will go missing.
	RegisterTransactionListener(TransactionListener) error

	// RegisterBlockListener register the listener to receive block notifications
	// listeners must be registered before call Start() method, or some notifications will go missing.
	RegisterBlockListener(BlockListener) error

	// RegisterRevertListener register the listener to receive revert related transactions notifications.
	// listeners must be registered before call Start() method, or some notifications will go missing.
	RegisterRevertListener(listener RevertListener) error

	// After receive the transaction callback, call this method
	// to confirm that the transaction with the given ID was handled,
	// so the transaction will be removed from the notify queue.
	// the notifyId is the key to specify which listener received this notify.
	SubmitTransactionReceipt(notifyId common.Uint256, txId common.Uint256) error

	// To verify if a transaction is valid
	// This method is useful when receive a transaction from other peer
	VerifyTransaction(bloom.MerkleProof, types.Transaction) error

	// Send a transaction to the P2P network
	SendTransaction(types.Transaction) error

	// GetTransaction query a transaction by it's hash.
	GetTransaction(txId *common.Uint256) (*types.Transaction, error)

	// GetTransactionIds query all transaction hashes on the given block height.
	GetTransactionIds(height uint32) ([]*common.Uint256, error)

	// GetArbiters Get arbiters according to height.
	GetArbiters(height uint32) (crcArbiters [][]byte, normalArbiters [][]byte, err error)

	// Get next turn arbiters.
	GetNextArbiters() (workingHeight uint32, crcArbiters [][]byte, normalArbiters [][]byte, err error)

	// Get consensus algorithm by height.
	GetConsensusAlgorithm(height uint32) (ConsensusAlgorithm, error)

	// GetReservedCustomIDs query all controversial reserved custom ID.
	GetReservedCustomIDs() (map[string]struct{}, error)

	// GetReceivedCustomIDs query all controversial received custom ID.
	GetReceivedCustomIDs() (map[string]common.Uint168, error)

	//HaveRetSideChainDepositCoinTx query tx data by tx hash
	HaveRetSideChainDepositCoinTx(txHash common.Uint256) bool

	// GetRateOfCustomIDFee query current rate of custom ID fee.
	GetRateOfCustomIDFee(height uint32) (common.Fixed64, error)

	// GetBlockListener Get block listener
	GetBlockListener() BlockListener

	// Get headers database
	HeaderStore() store.HeaderStore

	// Start the SPV service
	Start()

	// Stop the SPV service
	Stop()

	// ClearData delete all data stores data including HeaderStore and DataStore.
	ClearData() error
}

const (
	// FlagNotifyConfirmed indicates if this transaction should be callback after reach the confirmed height,
	// by default 6 confirmations are needed according to the protocol
	FlagNotifyConfirmed = 1 << 0

	// FlagNotifyInSyncing indicates if notify this listener when SPV is in syncing.
	FlagNotifyInSyncing = 1 << 1
)

/*
Register this listener into the IService RegisterTransactionListener() method
to receive transaction notifications.
*/
type TransactionListener interface {
	// The address this listener interested
	Address() string

	// Type() indicates which transaction type this listener are interested
	Type() types.TxType

	// Flags control the notification actions by the given flag
	Flags() uint64

	// Notify() is the method to callback the received transaction
	// with the merkle tree proof to verify it, the notifyId is key of this
	// notify message and it must be submitted with the receipt together.
	Notify(notifyId common.Uint256, proof bloom.MerkleProof, tx types.Transaction)
}

/*
Register this listener to IService RegisterRevertListener() method
to receive revert related transactions notifications.
*/
type RevertListener interface {
	// NotifyRevertToPow is the method to callback when received RevertToPow transaction.
	NotifyRevertToPow(tx types.Transaction)

	// NotifyRevertToPow is the method to callback when received RevertToDPOS transaction.
	NotifyRevertToDPOS(tx types.Transaction)

	NotifyRollbackRevertToPow(tx types.Transaction)

	// NotifyRollbackRevertToDPOS is the method to callback when rolled back RevertToDPOS transaction.
	NotifyRollbackRevertToDPOS(tx types.Transaction)
}

/*
Register this listener to IService RegisterBlockListener() method
to receive block notifications.
*/
type BlockListener interface {

	// NotifyBlock is the method to callback the received block
	NotifyBlock(block *util.Block)

	// BlockHeight is the method to get the Current Block height
	BlockHeight() uint32

	// StoreAuxBlockParam store submitted aux block
	StoreAuxBlock(block interface{})

	// RegisterPowService register service
	RegisterFunc(handleFunc func(block interface{}) error)
}
