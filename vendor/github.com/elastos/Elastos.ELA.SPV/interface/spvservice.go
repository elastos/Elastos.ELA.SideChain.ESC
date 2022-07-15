package _interface

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/elastos/Elastos.ELA.SPV/bloom"
	"github.com/elastos/Elastos.ELA.SPV/database"
	"github.com/elastos/Elastos.ELA.SPV/interface/iutil"
	"github.com/elastos/Elastos.ELA.SPV/interface/store"
	"github.com/elastos/Elastos.ELA.SPV/sdk"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SPV/wallet/sutil"

	"github.com/elastos/Elastos.ELA/common"
	elatx "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	elacommon "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/p2p/msg"
)

const (
	defaultDataDir = "./data_spv"

	// notifyTimeout is the duration to timeout a notify to the listener, and
	// resend the notify to the listener.
	notifyTimeout = 10 * time.Second // 10 second
)

type ConsensusAlgorithm byte

const (
	DPOS ConsensusAlgorithm = 0x00
	POW  ConsensusAlgorithm = 0x01
)

type spvservice struct {
	sdk.IService
	headers        store.HeaderStore
	db             store.DataStore
	rollback       func(height uint32)
	listeners      map[common.Uint256]TransactionListener
	revertListener RevertListener
	blockListener  BlockListener
	//FilterType is the filter type .(FTBloom, FTDPOS  and so on )
	filterType uint8
	// p2p  Protocol version height  use to change version msg content
	NewP2PProtocolVersionHeight uint64
}

// NewSPVService creates a new SPV service instance.
func NewSPVService(cfg *Config) (*spvservice, error) {
	dataDir := defaultDataDir
	if len(cfg.DataDir) > 0 {
		dataDir = cfg.DataDir
	}
	_, err := os.Stat(dataDir)
	if os.IsNotExist(err) {
		err := os.MkdirAll(dataDir, os.ModePerm)
		if err != nil {
			return nil, fmt.Errorf("make data dir failed")
		}
	}

	headerStore, err := store.NewHeaderStore(dataDir, newBlockHeader)
	if err != nil {
		return nil, err
	}

	var originArbiters [][]byte
	for _, a := range cfg.ChainParams.CRCArbiters {
		v, err := hex.DecodeString(a)
		if err != nil {
			return nil, err
		}
		originArbiters = append(originArbiters, v)
	}
	dataStore, err := store.NewDataStore(dataDir, originArbiters,
		len(cfg.ChainParams.CRCArbiters)*3, cfg.GenesisBlockAddress)
	if err != nil {
		return nil, err
	}

	service := &spvservice{
		headers:                     headerStore,
		db:                          dataStore,
		rollback:                    cfg.OnRollback,
		listeners:                   make(map[common.Uint256]TransactionListener),
		filterType:                  cfg.FilterType,
		NewP2PProtocolVersionHeight: cfg.ChainParams.NewP2PProtocolVersionHeight,
	}

	chainStore := database.NewChainDB(headerStore, service)

	serviceCfg := &sdk.Config{
		DataDir:        dataDir,
		ChainParams:    cfg.ChainParams,
		PermanentPeers: cfg.PermanentPeers,
		CandidateFlags: []uint64{
			uint64(pact.SFNodeNetwork),
			uint64(pact.SFNodeBloom),
		},
		GenesisHeader:  GenesisHeader(cfg.ChainParams.GenesisBlock),
		ChainStore:     chainStore,
		NewTransaction: newTransaction,
		NewBlockHeader: newBlockHeader,
		GetTxFilter:    service.GetFilter,
		StateNotifier:  service,
		NodeVersion:    cfg.NodeVersion,
	}

	service.IService, err = sdk.NewService(serviceCfg)
	if err != nil {
		return nil, err
	}

	return service, nil
}

func (s *spvservice) RegisterTransactionListener(listener TransactionListener) error {
	address, err := common.Uint168FromAddress(listener.Address())
	if err != nil {
		return fmt.Errorf("address %s is not a valied address", listener.Address())
	}
	key := getListenerKey(listener)
	if _, ok := s.listeners[key]; ok {
		return fmt.Errorf("listener with address: %s type: %s flags: %d already registered",
			listener.Address(), listener.Type().Name(), listener.Flags())
	}
	s.listeners[key] = listener
	return s.db.Addrs().Put(address)
}

func (s *spvservice) RegisterRevertListener(listener RevertListener) error {
	s.revertListener = listener
	return nil
}

func (s *spvservice) RegisterBlockListener(listener BlockListener) error {
	s.blockListener = listener
	return nil
}

func (s *spvservice) SubmitTransactionReceipt(notifyId, txHash common.Uint256) error {
	return s.db.Que().Del(&notifyId, &txHash)
}

func (s *spvservice) VerifyTransaction(proof bloom.MerkleProof, tx it.Transaction) error {
	// Get Header from main chain
	header, err := s.headers.Get(&proof.BlockHash)
	if err != nil {
		return errors.New("can not get block from main chain")
	}

	// Check if merkleroot is match
	merkleBlock := msg.MerkleBlock{
		Header:       header.BlockHeader,
		Transactions: proof.Transactions,
		Hashes:       proof.Hashes,
		Flags:        proof.Flags,
	}
	txIds, err := bloom.CheckMerkleBlock(merkleBlock)
	if err != nil {
		return fmt.Errorf("check merkle branch failed, %s", err.Error())
	}
	if len(txIds) == 0 {
		return fmt.Errorf("invalid transaction proof, no transactions found")
	}

	// Check if transaction hash is match
	match := false
	for _, txId := range txIds {
		if *txId == tx.Hash() {
			match = true
			break
		}
	}
	if !match {
		return fmt.Errorf("transaction hash not match proof")
	}

	return nil
}

func (s *spvservice) SendTransaction(tx it.Transaction) error {
	return s.IService.SendTransaction(iutil.NewTx(tx))
}

func (s *spvservice) GetTransaction(txId *common.Uint256) (it.Transaction, error) {
	utx, err := s.db.Txs().Get(txId)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(utx.RawData)
	tx, err := functions.GetTransactionByBytes(r)
	if err != nil {
		return nil, errors.New("invalid transaction")
	}
	err = tx.Deserialize(r)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

// Get arbiters according to height
func (s *spvservice) GetArbiters(height uint32) (crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	return s.db.Arbiters().GetByHeight(height)
}

// Get next turn arbiters according to height
func (s *spvservice) GetNextArbiters() (workingHeight uint32, crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	return s.db.Arbiters().GetNext()
}

// Get consensus algorithm by height.
func (s *spvservice) GetConsensusAlgorithm(height uint32) (ConsensusAlgorithm, error) {
	mode, err := s.db.Arbiters().GetConsensusAlgorithmByHeight(height)
	return ConsensusAlgorithm(mode), err
}

// Get reserved custom ID.
func (s *spvservice) GetReservedCustomIDs(height uint32) (map[string]struct{}, error) {
	return s.db.CID().GetReservedCustomIDs(height, s.db.Arbiters().GetRevertInfo())
}

// Get received custom ID.
func (s *spvservice) GetReceivedCustomIDs(height uint32) (map[string]common.Uint168, error) {
	return s.db.CID().GetReceivedCustomIDs(height, s.db.Arbiters().GetRevertInfo())
}

// Get rate of custom ID fee.
func (s *spvservice) GetRateOfCustomIDFee(height uint32) (common.Fixed64, error) {
	return s.db.CID().GetCustomIDFeeRate(height)
}

//GetReturnSideChainDepositCoin query tx data by tx hash
func (s *spvservice) HaveRetSideChainDepositCoinTx(txHash common.Uint256) bool {
	return s.db.CID().HaveRetSideChainDepositCoinTx(txHash)
}

func (s *spvservice) GetTransactionIds(height uint32) ([]*common.Uint256, error) {
	return s.db.Txs().GetIds(height)
}

func (s *spvservice) GetBlockListener() BlockListener {
	return s.blockListener
}

func (s *spvservice) HeaderStore() store.HeaderStore {
	return s.headers
}

func (s *spvservice) GetFilter() *msg.TxFilterLoad {
	addrs := s.db.Addrs().GetAll()
	f := bloom.NewFilter(uint32(len(addrs)), math.MaxUint32, 0)
	for _, address := range addrs {
		f.Add(address.Bytes())
	}
	return f.ToTxFilterMsg(s.filterType)
}

func (s *spvservice) putTx(batch store.DataBatch, utx util.Transaction,
	height uint32) (bool, error) {

	tx := utx.(*iutil.Tx)
	hits := make(map[common.Uint168]struct{})
	ops := make(map[*util.OutPoint]common.Uint168)
	for index, output := range tx.Outputs() {
		if s.db.Addrs().GetFilter().ContainAddr(output.ProgramHash) {
			outpoint := util.NewOutPoint(tx.Hash(), uint16(index))
			ops[outpoint] = output.ProgramHash
			hits[output.ProgramHash] = struct{}{}
		}
	}

	for _, input := range tx.Inputs() {
		op := input.Previous
		addr := s.db.Ops().HaveOp(util.NewOutPoint(op.TxID, op.Index))
		if addr != nil {
			hits[*addr] = struct{}{}
		}
	}

	switch tx.TxType() {
	case elacommon.RevertToPOW:
		revertToPOW := tx.Payload().(*payload.RevertToPOW)
		nakedBatch := batch.GetNakedBatch()
		err := s.db.Arbiters().BatchPutRevertTransaction(
			nakedBatch, revertToPOW.WorkingHeight, byte(POW))
		if err != nil {
			return false, err
		}
	case elacommon.RevertToDPOS:
		revertToDPOS := tx.Payload().(*payload.RevertToDPOS)
		nakedBatch := batch.GetNakedBatch()
		err := s.db.Arbiters().BatchPutRevertTransaction(
			nakedBatch, height+revertToDPOS.WorkHeightInterval, byte(DPOS))
		if err != nil {
			return false, err
		}
	case elacommon.NextTurnDPOSInfo:
		nextTurnDposInfo := tx.Payload().(*payload.NextTurnDPOSInfo)
		nakedBatch := batch.GetNakedBatch()
		err := s.db.Arbiters().BatchPut(nextTurnDposInfo.WorkingHeight,
			nextTurnDposInfo.CRPublicKeys, nextTurnDposInfo.DPOSPublicKeys, nakedBatch)
		if err != nil {
			return false, err
		}
	case elacommon.ReturnSideChainDepositCoin:
		_, ok := tx.Payload().(*payload.ReturnSideChainDepositCoin)
		if !ok {
			return false, errors.New("invalid ReturnSideChainDepositCoin tx")
		}
		nakedBatch := batch.GetNakedBatch()
		err := s.db.CID().BatchPutRetSideChainDepositCoinTx(tx.Transaction, nakedBatch)
		if err != nil {
			return false, err
		}
	case elacommon.CRCProposal:
		p, ok := tx.Payload().(*payload.CRCProposal)
		if !ok {
			return false, errors.New("invalid crc proposal tx")
		}
		nakedBatch := batch.GetNakedBatch()
		switch p.ProposalType {
		case payload.ReserveCustomID:
			err := s.db.CID().BatchPutControversialReservedCustomIDs(
				p.ReservedCustomIDList, p.Hash(tx.PayloadVersion()), nakedBatch)
			if err != nil {
				return false, err
			}
		case payload.ReceiveCustomID:
			err := s.db.CID().BatchPutControversialReceivedCustomIDs(
				p.ReceivedCustomIDList, p.ReceiverDID, p.Hash(tx.PayloadVersion()), nakedBatch)
			if err != nil {
				return false, err
			}
		case payload.ChangeCustomIDFee:
			if err := s.db.CID().BatchPutControversialChangeCustomIDFee(
				p.RateOfCustomIDFee, p.Hash(tx.PayloadVersion()), p.EIDEffectiveHeight, nakedBatch); err != nil {
				return false, err
			}
		}
	case elacommon.ProposalResult:
		p, ok := tx.Payload().(*payload.RecordProposalResult)
		if !ok {
			return false, errors.New("invalid custom ID result tx")
		}
		nakedBatch := batch.GetNakedBatch()
		err := s.db.CID().BatchPutCustomIDProposalResults(p.ProposalResults, height, nakedBatch)
		if err != nil {
			return false, err
		}
	}

	if len(hits) == 0 {
		return true, nil
	}

	for op, addr := range ops {
		if err := batch.Ops().Put(op, addr); err != nil {
			return false, err
		}
	}

	for _, listener := range s.listeners {
		hash, _ := common.Uint168FromAddress(listener.Address())
		if _, ok := hits[*hash]; ok {
			// skip transactions that not match the require type
			if listener.Type() != tx.TxType() {
				continue
			}

			// queue message
			batch.Que().Put(&store.QueItem{
				NotifyId: getListenerKey(listener),
				TxId:     tx.Hash(),
				Height:   height,
			})
		}
	}

	return false, batch.Txs().Put(util.NewTx(utx, height))
}

// PutTxs persists the main chain transactions into database and can be
// queried by GetTxs(height).  Returns the false positive transaction count
// and error.
func (s *spvservice) PutTxs(txs []util.Transaction, height uint32) (uint32, error) {
	fps := uint32(0)
	batch := s.db.Batch()
	defer batch.Rollback()
	for _, tx := range txs {
		fp, err := s.putTx(batch, tx, height)
		if err != nil {
			return 0, err
		}
		if fp {
			fps++
		}
	}
	if err := batch.Commit(); err != nil {
		return 0, err
	}
	return fps, nil
}

// PutForkTxs persists the fork chain transactions into database with the
// fork block hash and can be queried by GetForkTxs(hash).
func (s *spvservice) PutForkTxs(txs []util.Transaction, hash *common.Uint256) error {
	ftxs := make([]*util.Tx, 0, len(txs))
	for _, utx := range txs {
		ftxs = append(ftxs, util.NewTx(utx, 0))
	}
	return s.db.Txs().PutForkTxs(ftxs, hash)
}

// HaveTx returns if the transaction already saved in database
// by it's id.
func (s *spvservice) HaveTx(txId *common.Uint256) (bool, error) {
	tx, err := s.db.Txs().Get(txId)
	return tx != nil, err
}

// GetTxs returns all transactions in main chain within the given height.
func (s *spvservice) GetTxs(height uint32) ([]util.Transaction, error) {
	txIDs, err := s.db.Txs().GetIds(height)
	if err != nil {
		return nil, err
	}

	txs := make([]util.Transaction, 0, len(txIDs))
	for _, txID := range txIDs {
		utx, err := s.db.Txs().Get(txID)
		if err != nil {
			return nil, err
		}
		r := bytes.NewReader(utx.RawData)
		var tx = newTransaction(r)
		err = tx.Deserialize(r)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

// GetForkTxs returns all transactions within the fork block hash.
func (s *spvservice) GetForkTxs(hash *common.Uint256) ([]util.Transaction, error) {
	ftxs, err := s.db.Txs().GetForkTxs(hash)
	if err != nil {
		return nil, err
	}

	txs := make([]util.Transaction, 0, len(ftxs))
	for _, ftx := range ftxs {
		r := bytes.NewReader(ftx.RawData)
		var tx = newTransaction(r)
		err = tx.Deserialize(r)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

// DelTxs remove all transactions in main chain within the given height.
func (s *spvservice) DelTxs(height uint32) error {
	// Delete transactions, outpoints and queued items.
	batch := s.db.Batch()
	defer batch.Rollback()
	if err := batch.DelAll(height); err != nil {
		return err
	}
	if err := batch.Commit(); err != nil {
		return err
	}

	// Invoke main chain rollback.
	if s.rollback != nil {
		s.rollback(height)
	}
	return nil
}

// TransactionAnnounce will be invoked when received a new announced transaction.
func (s *spvservice) TransactionAnnounce(tx util.Transaction) {}

// TransactionAccepted will be invoked after a transaction sent by
// SendTransaction() method has been accepted.  Notice: this method needs at
// lest two connected peers to work.
func (s *spvservice) TransactionAccepted(tx util.Transaction) {}

// TransactionRejected will be invoked if a transaction sent by SendTransaction()
// method has been rejected.
func (s *spvservice) TransactionRejected(tx util.Transaction) {}

// TransactionConfirmed will be invoked after a transaction sent by
// SendTransaction() method has been packed into a block.
func (s *spvservice) TransactionConfirmed(tx *util.Tx) {}

// BlockCommitted will be invoked when a block and transactions within it are
// successfully committed into database.
func (s *spvservice) BlockCommitted(block *util.Block) {
	// Look up for queued transactions
	items, err := s.db.Que().GetAll()
	if err != nil {
		return
	}
	for _, item := range items {
		// Check if the notify should be resend due to timeout.
		if time.Now().Before(item.LastNotify.Add(notifyTimeout)) {
			continue
		}

		//	Get header
		header, err := s.headers.GetByHeight(item.Height)
		if err != nil {
			log.Errorf("query merkle proof at height %d failed, %s", item.Height, err.Error())
			continue
		}

		//	Get transaction from db
		utx, err := s.db.Txs().Get(&item.TxId)
		if err != nil {
			log.Errorf("query transaction failed, txId %s", item.TxId.String())
			continue
		}

		r := bytes.NewReader(utx.RawData)
		tx, err := functions.GetTransactionByBytes(r)
		if err != nil {
			log.Errorf("query transaction failed, txId %s", item.TxId.String())
			continue
		}
		err = tx.Deserialize(r)
		if err != nil {
			continue
		}

		var proof = bloom.MerkleProof{
			BlockHash:    header.Hash(),
			Height:       header.Height,
			Transactions: header.NumTxs,
			Hashes:       header.Hashes,
			Flags:        header.Flags,
		}

		// Notify listeners
		listener, ok := s.notifyTransaction(item.NotifyId, proof, tx, block.Height-item.Height)
		if ok {
			item.LastNotify = time.Now()
			s.db.Que().Put(item)
			listener.Notify(item.NotifyId, proof, tx)
		}

		if s.revertListener != nil && tx.IsRevertToPOW() {
			s.revertListener.NotifyRevertToDPOS(tx)
		}
		if s.revertListener != nil && tx.IsRevertToDPOS() {
			s.revertListener.NotifyRevertToDPOS(tx)
		}
	}

	if s.blockListener != nil && s.IsCurrent() {
		s.blockListener.NotifyBlock(block)
	}

}

func (s *spvservice) ClearData() error {
	if err := s.headers.Clear(); err != nil {
		log.Warnf("Clear header store error %s", err.Error())
	}
	if err := s.db.Clear(); err != nil {
		log.Warnf("Clear data store error %s", err.Error())
	}
	return nil
}

func (s *spvservice) Clear() error {
	return s.db.Clear()
}

func (s *spvservice) Close() error {
	return s.db.Close()
}

func (s *spvservice) queueMessageByListener(
	listener TransactionListener, tx it.Transaction, height uint32) {
	// skip unpacked transaction
	if height == 0 {
		return
	}

	// skip transactions that not match the require type
	if listener.Type() != tx.TxType() {
		return
	}

	// queue message
	s.db.Que().Put(&store.QueItem{
		NotifyId: getListenerKey(listener),
		TxId:     tx.Hash(),
		Height:   height,
	})
}

func (s *spvservice) notifyTransaction(notifyId common.Uint256,
	proof bloom.MerkleProof, tx it.Transaction,
	confirmations uint32) (TransactionListener, bool) {

	listener, ok := s.listeners[notifyId]
	if !ok {
		return nil, false
	}

	// Get transaction id
	txId := tx.Hash()

	// Remove notifications if FlagNotifyInSyncing not set
	if s.IService.IsCurrent() == false &&
		listener.Flags()&FlagNotifyInSyncing != FlagNotifyInSyncing {

		if listener.Flags()&FlagNotifyConfirmed == FlagNotifyConfirmed {
			if confirmations >= getConfirmations(tx) {
				s.db.Que().Del(&notifyId, &txId)
			}
		} else {
			s.db.Que().Del(&notifyId, &txId)
		}
		return nil, false
	}

	// Notify listener
	if listener.Flags()&FlagNotifyConfirmed == FlagNotifyConfirmed {
		if confirmations >= getConfirmations(tx) {
			return listener, true
		}
	} else {
		listener.Notify(notifyId, proof, tx)
		return listener, true
	}

	return nil, false
}

func getListenerKey(listener TransactionListener) common.Uint256 {
	buf := new(bytes.Buffer)
	addr, _ := common.Uint168FromAddress(listener.Address())
	common.WriteElements(buf, addr[:], listener.Type(), listener.Flags())
	return sha256.Sum256(buf.Bytes())
}

func getConfirmations(tx it.Transaction) uint32 {
	// TODO user can set confirmations attribute in transaction,
	// if the confirmation attribute is set, use it instead of default value
	if tx.TxType() == elacommon.CoinBase {
		return 100
	}
	return DefaultConfirmations
}

func newBlockHeader() util.BlockHeader {
	return iutil.NewHeader(&elacommon.Header{})
}

func newTransaction(r io.Reader) util.Transaction {
	tx, _ := elatx.GetTransactionByBytes(r)
	return sutil.NewTx(tx)
}

// GenesisHeader creates a specific genesis header by the given
// foundation address.
func GenesisHeader(genesisBlock *types.Block) util.BlockHeader {
	return iutil.NewHeader(&genesisBlock.Header)
}
