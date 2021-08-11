package spv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	core "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/elanet/filter"
	"github.com/elastos/Elastos.ELA/events"

	"github.com/elastos/Elastos.ELA.SPV/bloom"
	spv "github.com/elastos/Elastos.ELA.SPV/interface"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/blocksigner"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	ethCommon "github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb/leveldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/event"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"

	"github.com/elastos/Elastos.ELA.SideChain/types"
	"golang.org/x/net/context"
)

var (
	dataDir          = "./"
	ipcClient        *ethclient.Client
	SpvService       *Service
	spvTxhash        string //Spv notification main chain hash
	spvTransactiondb *leveldb.Database
	muiterator       sync.RWMutex
	muupti           sync.RWMutex
	candSend         int32     //1 can send recharge transactions, 0 can not send recharge transactions
	candIterator     int32 = 0 //0 Iteratively send recharge transactions, 1 can't iteratively send recharge transactions
	MinedBlockSub    *event.TypeMuxSubscription

	GetDefaultSingerAddr func() ethCommon.Address

	failedMutex      sync.RWMutex
	failedTxList = make(map[uint64][]string)
	consensusMode spv.ConsensusAlgorithm
)

const (
	databaseCache int = 768

	handles = 16

	//Unprocessed refill transaction index prefix
	UnTransaction string = "UnT-"

	// missingNumber is returned by GetBlockNumber if no header with the
	// given block hash has been stored in the database
	missingNumber = uint64(0xffffffffffffffff)

	//Cross-chain exchange rate
	rate int64 = 10000000000

	//Cross-chain recharge unprocessed transaction index
	UnTransactionIndex = "UnTI"

	//Cross-chain recharge unprocessed transaction seek
	UnTransactionSeek = "UnTS"

	// Fixed number of extra-data prefix bytes reserved for signer vanity
	ExtraVanity = 32

	// Fixed number of extra-data suffix bytes reserved for signer seal
	ExtraSeal = 65

	// Fixed height of ela chain height with LitterEnd encode
	ExtraElaHeight = 8

	blockDiff = 6
)

//type MinedBlockEvent struct{}

type Config struct {
	// DataDir is the data path to store db files peer addresses etc.
	DataDir string

	// ActiveNet indicates the ELA network to connect with.
	ActiveNet string

	// GenesisAddress is the address generated by the side chain genesis block.
	GenesisAddress string
}

type Service struct {
	spv.SPVService

	mux      *event.TypeMux
}

//Spv database initialization
func SpvDbInit(spvdataDir string) {
	db, err := leveldb.New(filepath.Join(spvdataDir, "spv_transaction_info.db"), databaseCache, handles, "eth/db/ela/")
	if err != nil {
		log.Error("spv Open db", "err", err)
		return
	}
	spvTransactiondb = db
}

//Spv service initialization
func NewService(cfg *Config, client *rpc.Client, tmux *event.TypeMux) (*Service, error) {
	var chainParams *config.Params
	switch strings.ToLower(cfg.ActiveNet) {
	case "testnet", "test", "t":
		chainParams = config.DefaultParams.TestNet()
		chainParams.Magic = 2018111
	case "regnet", "reg", "r":
		chainParams = config.DefaultParams.RegNet()
	case "goreli", "g":
		chainParams = config.DefaultParams.RegNet()
		chainParams.Magic = 2018211
	default:
		chainParams = &config.DefaultParams

	}
	spvCfg := &spv.Config{
		DataDir:    cfg.DataDir,
		FilterType: filter.FTNexTTurnDPOSInfo,
		OnRollback: nil, // Not implemented yet
	}
	//chainParams, spvCfg = ResetConfig(chainParams, spvCfg)
	ResetConfigWithReflect(chainParams, spvCfg)
	spvCfg.ChainParams = chainParams
	spvCfg.PermanentPeers = chainParams.PermanentPeers
	dataDir = cfg.DataDir
	spvCfg.NodeVersion = "ESC_1.9.7"
	initLog(cfg.DataDir)

	service, err := spv.NewSPVService(spvCfg)
	if err != nil {
		log.Error("Spv New DPOS SPVService: ", "err", err)
		return nil, err
	}

	SpvService = &Service{service, tmux}
	err = service.RegisterTransactionListener(&listener{
		address: cfg.GenesisAddress,
		service: service,
	})
	if err != nil {
		log.Error("Spv Register Transaction Listener: ", "err", err)
		return nil, err
	}
	err = service.RegisterBlockListener(&BlockListener{})
	if err != nil {
		return nil, err
	}

	ipcClient = ethclient.NewClient(client)
	genesis, err := ipcClient.HeaderByNumber(context.Background(), new(big.Int).SetInt64(0))
	if err != nil {
		log.Error("IpcClient: ", "err", err)
	}

	signersSize := len(genesis.Extra) - ExtraVanity - ExtraSeal
	if signersSize % ethCommon.AddressLength == ExtraElaHeight {
		signersSize -= ExtraElaHeight
	}
	singersNum := signersSize / ethCommon.AddressLength
	if singersNum > 0 {
		signers := make([]ethCommon.Address, singersNum)
		for i := 0; i < singersNum; i++ {
			copy(signers[i][:], genesis.Extra[ExtraVanity + i * ethCommon.AddressLength:])
		}
		blocksigner.Signers = make(map[ethCommon.Address]struct{})
		for _, signer := range signers {
			blocksigner.Signers[signer] = struct{}{}
		}
	}
	addr :=  GetDefaultSingerAddr()
	_, blocksigner.SelfIsProducer = blocksigner.Signers[addr]
	return SpvService, nil
}

//minedBroadcastLoop Mining awareness, eth can initiate a recharge transaction after the block
func MinedBroadcastLoop(minedBlockSub *event.TypeMuxSubscription, ondutySub *event.TypeMuxSubscription) {
	var i = 0

	for {
		select {
		case <-minedBlockSub.Chan():
			i++
			if i >= 2 {
				atomic.StoreInt32(&candSend, 1)
				IteratorUnTransaction(GetDefaultSingerAddr())
			}
			events.Notify(dpos_msg.ETSelfOnDuty, nil)
		case <-ondutySub.Chan():
			if i >= 2 {
				i = 0
				log.Info("receive onduty event")
				atomic.StoreInt32(&candSend, 0)
			}
		}
	}
}

func (s *Service) GetDatabase() *leveldb.Database {
	return spvTransactiondb
}

func (s *Service) VerifyTransaction(tx *types.Transaction) error {
	payload, ok := tx.Payload.(*types.PayloadRechargeToSideChain)
	if !ok {
		return errors.New("[VerifyTransaction] Invalid payload core.PayloadRechargeToSideChain")
	}

	switch tx.PayloadVersion {
	case types.RechargeToSideChainPayloadVersion0:

		proof := new(bloom.MerkleProof)
		mainChainTransaction := new(core.Transaction)

		reader := bytes.NewReader(payload.MerkleProof)
		if err := proof.Deserialize(reader); err != nil {
			return errors.New("[VerifyTransaction] RechargeToSideChain payload deserialize failed")
		}

		reader = bytes.NewReader(payload.MainChainTransaction)
		if err := mainChainTransaction.Deserialize(reader); err != nil {
			return errors.New("[VerifyTransaction] RechargeToSideChain mainChainTransaction deserialize failed")
		}

		if err := s.SPVService.VerifyTransaction(*proof, *mainChainTransaction); err != nil {
			return errors.New("[VerifyTransaction] SPV module verify transaction failed.")
		}

	case types.RechargeToSideChainPayloadVersion1:

		_, err := s.GetTransaction(&payload.MainChainTransactionHash)
		if err != nil {
			return errors.New("[VerifyTransaction] Main chain transaction not found")
		}

	default:
		return errors.New("[VerifyTransaction] invalid payload version.")
	}

	return nil
}

func (s *Service) VerifyElaHeader(hash *common.Uint256) error {
	blockChain := s.HeaderStore()
	_, err := blockChain.Get(hash)
	if err != nil {
		return errors.New("[VerifyElaHeader] Verify ela header failed.")
	}
	return nil
}

type listener struct {
	address string
	service spv.SPVService
}

func (l *listener) Address() string {
	return l.address
}

func (l *listener) Type() core.TxType {
	return core.TransferCrossChainAsset
}

func (l *listener) Flags() uint64 {
	return spv.FlagNotifyInSyncing | spv.FlagNotifyConfirmed
}

func (l *listener) Notify(id common.Uint256, proof bloom.MerkleProof, tx core.Transaction) {
	// Submit transaction receipt
	log.Info("========================================================================================")
	log.Info("mainchain transaction info")
	log.Info("----------------------------------------------------------------------------------------")
	log.Info(string(tx.String()))
	log.Info("----------------------------------------------------------------------------------------")
	if !blocksigner.SelfIsProducer {
		atomic.StoreInt32(&candSend, 0)
	}
	savePayloadInfo(tx, l)
	l.service.SubmitTransactionReceipt(id, tx.Hash())// give spv service a receipt, Indicates receipt of notice
}

func NotifySmallCrossTx(tx core.Transaction) {
	log.Info("========================================================================================")
	log.Info("smallMainchain transaction info")
	log.Info("----------------------------------------------------------------------------------------")
	log.Info(string(tx.String()))
	log.Info("----------------------------------------------------------------------------------------")
	savePayloadInfo(tx, nil)
}

func OnReceivedRechargeTx(tx core.Transaction) error {
	output := make([]*core.Output, 0)
	for _, v := range tx.Outputs {
		if v.Type != core.OTCrossChain {
			continue
		}
		op, ok := v.Payload.(*outputpayload.CrossChainOutput)
		if !ok {
			return errors.New("invalid cross chain output payload")
		}
		err := op.Validate()
		if err != nil {
			return err
		}
		output = append(output, v)
	}
	if len(output) > 0 {
		err := saveOutputPayload(output, tx.Hash().String())
		if err != nil {
			return err
		}
	}
	return nil
}

func saveOutputPayload(outputs []*core.Output, txHash string) error {
	var fees []string
	var address []string
	var amounts []string
	var memos [][]byte
	for _, output := range outputs {
		op, ok := output.Payload.(*outputpayload.CrossChainOutput)
		if !ok {
			return errors.New("invalid cross chain output payload")
		}
		fees = append(fees, (output.Value -op.TargetAmount).String())
		amounts = append(amounts, output.Value.String())
		address = append(address, op.TargetAddress)
		memos = append(memos, op.TargetData)
	}
	addr := strings.Join(address, ",")
	fee := strings.Join(fees, ",")
	output := strings.Join(amounts, ",")
	if spvTxhash == txHash {
		return nil
	}
	spvTxhash = txHash
	err := spvTransactiondb.Put([]byte(txHash + "Fee"), []byte(fee))
	if err != nil {
		log.Error("saveOutputPayload Put Fee: ", "err", err, "elaHash", txHash)
	}

	err = spvTransactiondb.Put([]byte(txHash + "Address"), []byte(addr))
	if err != nil {
		log.Error("saveOutputPayload Put Address: ", "err", err, "elaHash", txHash)
	}
	err = spvTransactiondb.Put([]byte(txHash + "Output"), []byte(output))
	if err != nil {
		log.Error("saveOutputPayload Put Output: ", "err", err, "elaHash", txHash)
	}

	input  := memos[0]
	err = spvTransactiondb.Put([]byte(txHash + "Input"), input)
	if err != nil {
		log.Error("saveOutputPayload Put Input: ", "err", err, "elaHash", txHash)
	}
	if atomic.LoadInt32(&candSend) == 1 {
		from := GetDefaultSingerAddr()
		IteratorUnTransaction(from)
		f, err := common.StringToFixed64(fees[0])
		if err != nil {
			log.Error("saveOutputPayload Fee StringToFixed64: ", "err", err, "elaHash", txHash)
			return err

		}
		fe := new(big.Int).SetInt64(f.IntValue())
		y := new(big.Int).SetInt64(rate)
		feeValue := new(big.Int).Mul(fe, y)
		err, _ = SendTransaction(from, txHash, feeValue)
		if err != nil {
			log.Info("SendTransaction failed", "error", err.Error())
		}

	} else {
		UpTransactionIndex(txHash)
	}

	return nil
}

//
//savePayloadInfo save and send spv perception
func savePayloadInfo(elaTx core.Transaction, l *listener) {
	if elaTx.PayloadVersion >= payload.TransferCrossChainVersionV1 {
		err := OnReceivedRechargeTx(elaTx)
		if err != nil {
			log.Error("new recharge tx resolve error", "error", err)
		}
		return
	}
	nr := bytes.NewReader(elaTx.Payload.Data(elaTx.PayloadVersion))
	p := new(payload.TransferCrossChainAsset)
	p.Deserialize(nr, elaTx.PayloadVersion)
	var fees []string
	var address []string
	var outputs []string
	for i, amount := range p.CrossChainAmounts {
		v, err := SafeFixed64Minus(elaTx.Outputs[i].Value, amount)
		if err != nil {
			log.Error("SafeFixed64Minus error", "error", err)
			continue
		}
		fees = append(fees, v.String())
		outputs = append(outputs, elaTx.Outputs[i].Value.String())
		address = append(address, p.CrossChainAddresses[i])
	}
	addr := strings.Join(address, ",")
	fee := strings.Join(fees, ",")
	output := strings.Join(outputs, ",")
	if spvTxhash == elaTx.Hash().String() {
		return
	}
	spvTxhash = elaTx.Hash().String()
	err := spvTransactiondb.Put([]byte(elaTx.Hash().String()+"Fee"), []byte(fee))

	if err != nil {
		log.Error("SpvServicedb Put Fee: ", "err", err, "elaHash", elaTx.Hash().String())
	}

	err = spvTransactiondb.Put([]byte(elaTx.Hash().String()+"Address"), []byte(addr))

	if err != nil {
		log.Error("SpvServicedb Put Address: ", "err", err, "elaHash", elaTx.Hash().String())
	}
	err = spvTransactiondb.Put([]byte(elaTx.Hash().String()+"Output"), []byte(output))

	if err != nil {
		log.Error("SpvServicedb Put Output: ", "err", err, "elaHash", elaTx.Hash().String())
	}

	input  := []byte("")
	err = spvTransactiondb.Put([]byte(elaTx.Hash().String()+"Input"), input)
	if err != nil {
		log.Error("SpvServicedb Put Input: ", "err", err, "elaHash", elaTx.Hash().String())
	}
	if atomic.LoadInt32(&candSend) == 1 {
		from := GetDefaultSingerAddr()
		IteratorUnTransaction(from)
		f, err := common.StringToFixed64(fees[0])
		if err != nil {
			log.Error("SpvSendTransaction Fee StringToFixed64: ", "err", err, "elaHash", elaTx)
			return

		}
		fe := new(big.Int).SetInt64(f.IntValue())
		y := new(big.Int).SetInt64(rate)
		feeValue := new(big.Int).Mul(fe, y)
		err, _ = SendTransaction(from, elaTx.Hash().String(), feeValue)
		if err != nil {
			log.Error("SendTransaction error", "error", err)
		}

	} else {
		UpTransactionIndex(elaTx.Hash().String())
	}
	return
}

//UpTransactionIndex records spv-aware refill transaction index
func UpTransactionIndex(elaTx string) {
	muupti.Lock()
	defer muupti.Unlock()
	if strings.HasPrefix(elaTx, "0x") {
		elaTx = elaTx[2:]
	}
	index := GetUnTransactionNum(spvTransactiondb, UnTransactionIndex)
	if index == missingNumber {
		index = 1
	}
	err := spvTransactiondb.Put(append([]byte(UnTransaction), encodeUnTransactionNumber(index)...), []byte(elaTx))
	if err != nil {
		log.Error(fmt.Sprintf("SpvServicedb Put UnTransaction: %v", err), "elaHash", elaTx)
	}
	log.Trace(UnTransaction+"put", "index", index, "elaTx", elaTx)
	err = spvTransactiondb.Put([]byte(UnTransactionIndex), encodeUnTransactionNumber(index+1))
	if err != nil {
		log.Error("UnTransactionIndexPut", err, index+1)
		return
	}
	log.Trace(UnTransactionIndex+"put", "index", index+1)

}

//IteratorUnTransaction iterates before mining and processes existing spv refill transactions
func IteratorUnTransaction(from ethCommon.Address) {
	muiterator.Lock()
	defer muiterator.Unlock()
	if !blocksigner.SelfIsProducer {
		log.Error("error signers", "signer", from.String())
		return
	}

	if atomic.LoadInt32(&candIterator) == 1 {
		return
	}
	atomic.StoreInt32(&candIterator, 1)
	go func(addr ethCommon.Address) {
		defer atomic.StoreInt32(&candIterator, 0)
		for {
			// stop send tx if candSend == 0
			if atomic.LoadInt32(&candSend) == 0 {
				log.Info("stop send tx, canSend is 0")
				break
			}
			index := GetUnTransactionNum(spvTransactiondb, UnTransactionIndex)
			if index == missingNumber {
				break
			}
			seek := GetUnTransactionNum(spvTransactiondb, UnTransactionSeek)
			if seek == missingNumber {
				seek = 1
			}
			log.Info("get recharge tx", "seek", seek)
			if seek == index {
				log.Info("send over recharge", "seek", seek, "index", index)
				break
			}
			txHash, err := spvTransactiondb.Get(append([]byte(UnTransaction), encodeUnTransactionNumber(seek)...))
			if err != nil {
				log.Error("get UnTransaction ", "err", err, "seek", seek)
				setNextSeek(seek)
				break
			}
			fee, _, _ := FindOutputFeeAndaddressByTxHash(string(txHash))
			if fee.Uint64() <= 0 {
				log.Error("FindOutputFeeAndaddressByTxHash fee is 0")
				if IsFailedElaTx(string(txHash)) {
					setNextSeek(seek)
					break
				}
				OnTx2Failed(string(txHash))
				setNextSeek(seek)
				break
			}
			err, finished := SendTransaction(from, string(txHash), fee)
			if err != nil {
				log.Info("SendTransaction failed", "error", err.Error())
			}
			if finished {
				setNextSeek(seek)
			}
		}

	}(from)
}

func setNextSeek(seek uint64) {
	err := spvTransactiondb.Delete(append([]byte(UnTransaction), encodeUnTransactionNumber(seek)...))
	log.Trace(UnTransaction+"delete", "seek", seek)
	if err != nil {
		log.Error("UnTransactionIndexDeleteSeek ", "err", err, "seek", seek)
	}

	err = spvTransactiondb.Put([]byte(UnTransactionSeek), encodeUnTransactionNumber(seek+1))
	log.Trace(UnTransactionSeek+"put", "seek", seek+1)
	if err != nil {
		log.Error("UnTransactionIndexPutSeek ", err, seek+1)
		return
	}
}

//SendTransaction sends a reload transaction to txpool
func SendTransaction(from ethCommon.Address, elaTx string, fee *big.Int)(err error, finished bool){
	ethTx, err := ipcClient.StorageAt(context.Background(), ethCommon.Address{}, ethCommon.HexToHash("0x"+elaTx), nil)
	if err != nil {
		log.Error(fmt.Sprintf("IpcClient StorageAt: %v", err))
		return err, true
	}
	h := ethCommon.Hash{}
	if ethCommon.BytesToHash(ethTx) != h {
		onElaTxPacked(elaTx)
		err = errors.New("Cross-chain transactions have been processed")
		return err, true
	}
	data, err := common.HexStringToBytes(elaTx)
	if err != nil {
		log.Error("elaTx HexStringToBytes: "+elaTx, "err", err)
		return err, true
	}

	if IsFailedElaTx(elaTx) {
		err = errors.New("is failed tx, can't to send")
		return err, true
	}

	msg := ethereum.CallMsg{From: from, To: &ethCommon.Address{}, Data: data}
	gasLimit, err := ipcClient.EstimateGas(context.Background(), msg)
	if err != nil {
		log.Error("IpcClient EstimateGas:", "err", err, "main txhash", elaTx)
		if IsFailedElaTx(elaTx) {
			return err, true
		}
		OnTx2Failed(elaTx)
		return err, false
	}

	if gasLimit == 0 {
		if IsFailedElaTx(elaTx) {
			return err, true
		}
		OnTx2Failed(elaTx)
		log.Error("gasLimit is zero:","main txhash", elaTx)
		return err, false
	}

	if atomic.LoadInt32(&candSend) == 0 {
		err = errors.New("canSend is 0")
		return err, false
	}
	price := new(big.Int).Quo(fee, new(big.Int).SetUint64(gasLimit))
	callmsg := ethereum.TXMsg{From: from, To: &ethCommon.Address{}, Gas: gasLimit, Data: data, GasPrice: price}
	hash, err := ipcClient.SendPublicTransaction(context.Background(), callmsg)
	if err != nil {
		return err, true
	}
	log.Info("Cross chain Transaction", "elaTx", elaTx, "ethTh", hash.String(), "gasLimit", gasLimit)
	return nil, true
}

func encodeUnTransactionNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

func encodeTxList(txlist []string) []byte {
	buffer := new(bytes.Buffer)
	common.WriteVarUint(buffer, uint64(len(txlist)))
	for _, txid := range txlist {
		common.WriteVarString(buffer, txid)
	}
	return buffer.Bytes()
}

func decodeTxList(data []byte) ([]string, error) {
	buffer := new(bytes.Buffer)
	buffer.Write(data)
	txList := make([]string, 0)
	len, err := common.ReadVarUint(buffer, 0)
	if err != nil {
		return txList, err
	}
	var i uint64 = 0
	for i = 0; i < len; i++ {
		txid, err := common.ReadVarString(buffer)
		if err != nil {
			return txList, err
		}
		txList = append(txList, txid)
	}
	return txList, nil
}

func GetUnTransactionNum(db DatabaseReader, Prefix string) uint64 {
	data, _ := db.Get([]byte(Prefix))
	if len(data) != 8 {
		return missingNumber
	}
	return binary.BigEndian.Uint64(data)
}

// DatabaseReader wraps the Get method of a backing data store.
type DatabaseReader interface {
	Get(key []byte) (value []byte, err error)
}

//FindOutputFeeAndaddressByTxHash Finds the eth recharge address, recharge amount, and transaction fee based on the main chain hash.
func FindOutputFeeAndaddressByTxHash(transactionHash string) (*big.Int, ethCommon.Address, *big.Int) {
	var emptyaddr ethCommon.Address
	if transactionHash[0:2] == "0x" {
		transactionHash = transactionHash[2:]
	}
	if IsFailedElaTx(transactionHash) {
		log.Error("IsFailedElaTx", "transactionHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)
	}
	if spvTransactiondb == nil {
		return new(big.Int), emptyaddr, new(big.Int)
	}
	v, err := spvTransactiondb.Get([]byte(transactionHash + "Fee"))
	if err != nil {
		log.Error("SpvServicedb Get Fee: ", "err", err, "elaHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)
	}
	fmt.Println("FindOutputFeeAndaddressByTxHash fee", string(v))
	fees := strings.Split(string(v), ",")
	f, err := common.StringToFixed64(fees[0])
	if err != nil {
		log.Error("SpvServicedb Get Fee StringToFixed64: ", "err", err, "elaHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)

	}
	fe := new(big.Int).SetInt64(f.IntValue())
	y := new(big.Int).SetInt64(rate)

	addrss, err := spvTransactiondb.Get([]byte(transactionHash + "Address"))
	if err != nil {
		log.Error("SpvServicedb Get Address: ", "err", err, "elaHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)

	}
	addrs := strings.Split(string(addrss), ",")
	if !ethCommon.IsHexAddress(addrs[0]) {
		return new(big.Int), emptyaddr, new(big.Int)
	}
	outputs, err := spvTransactiondb.Get([]byte(transactionHash + "Output"))
	if err != nil {
		log.Error("SpvServicedb Get elaHash: ", "err", err, "elaHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)

	}
	output := strings.Split(string(outputs), ",")
	o, err := common.StringToFixed64(output[0])
	if err != nil {
		log.Error("SpvServicedb Get elaHash StringToFixed64: ", "err", err, "elaHash", transactionHash)
		return new(big.Int), emptyaddr, new(big.Int)

	}
	op := new(big.Int).SetInt64(o.IntValue())
	return new(big.Int).Mul(fe, y), ethCommon.HexToAddress(addrs[0]), new(big.Int).Mul(op, y)
}

func FindOutRechargeInput(transactionHash string) []byte {
	if spvTransactiondb == nil {
		return []byte{}
	}
	if transactionHash[0:2] == "0x" {
		transactionHash = transactionHash[2:]
	}

	input, err := spvTransactiondb.Get([]byte(transactionHash + "Input"))
	if err != nil {
		input = []byte{}
	}
	return input
}

func OnTx2Failed(elaTx string) {
	if IsPackagedElaTx(elaTx) {
		return
	}
	if IsFailedElaTx (elaTx) {
		return
	}
	failedMutex.Lock()
	defer failedMutex.Unlock()
	ethTx, err := ipcClient.StorageAt(context.Background(), ethCommon.Address{}, ethCommon.HexToHash("0x"+elaTx), nil)
	if err != nil {
		log.Error(fmt.Sprintf("%s StorageAt: %v",elaTx, err))
		return
	}

	h := ethCommon.Hash{}
	if ethHash := ethCommon.BytesToHash(ethTx); ethHash.String() != h.String() {
		log.Error(fmt.Sprintf("%s submit by: %s",elaTx, ethHash.String()))
		return
	}
	height, err := ipcClient.CurrentBlockNumber(context.Background())
	if err != nil {
		log.Error("get CurrentBlockNumber failed", "error",  err.Error())
		return
	}
	txList := failedTxList[height]
	if txList == nil {
		txList = make([]string, 0)
	}
	txList = append(txList, elaTx)
	failedTxList[height] = txList
	data := encodeTxList(txList)
	err = spvTransactiondb.Put(encodeUnTransactionNumber(height), data)
	log.Info("recharge tx failed", "height", height, "tx", elaTx)
}

func IsPackagedElaTx(elaTx string) bool {
	ethTx, err := ipcClient.StorageAt(context.Background(), ethCommon.Address{}, ethCommon.HexToHash("0x"+elaTx), nil)
	if err == nil {
		h := ethCommon.Hash{}
		if ethCommon.BytesToHash(ethTx) != h {
			onElaTxPacked(elaTx)
			return true
		}
	}
	return false
}

func IsFailedElaTx(elaTx string) bool {
	failedMutex.Lock()
	defer failedMutex.Unlock()

	if elaTx[0:2] == "0x" {
		elaTx = elaTx[2:]
	}
	for _, txs := range failedTxList {
		for _, txid := range txs {
			if txid[0:2] == "0x" {
				txid = txid[2:]
			}
			if txid == elaTx {
				return true
			}
		}
	}

	it := spvTransactiondb.NewIterator()
	defer it.Release()
	for it.Next() {
		value := it.Value()
		txs, err := decodeTxList(value)
		if err != nil {
			continue
		}
		key := it.Key()
		if len(key) != 8 || len(txs) == 0 {
			continue
		}
		for _, txid := range txs {
			if txid[0:2] == "0x" {
				txid = txid[2:]
			}
			if txid == elaTx {
				return true
			}
		}
	}
	return false
}

func onElaTxPacked(elaTx string) {
	failedMutex.Lock()
	defer failedMutex.Unlock()
	for height, txs := range failedTxList {
		for i, txid := range txs {
			if txid == elaTx {
				if len(txs) == 1 {
					delete(failedTxList, height)
					spvTransactiondb.Delete(encodeUnTransactionNumber(height))
				} else {
					txs = append(txs[:i], txs[i+1:]...)
					data := encodeTxList(txs)
					spvTransactiondb.Put(encodeUnTransactionNumber(height), data)
				}
				break
			}
		}
	}

	it := spvTransactiondb.NewIterator()
	defer it.Release()
	for it.Next() {
		value := it.Value()
		txs, err := decodeTxList(value)
		if err != nil {
			continue
		}
		if len(it.Key()) != 8 || len(txs) == 0 {
			continue
		}
		height := binary.BigEndian.Uint64(it.Key())
		for i, txid := range txs {
			if txid == elaTx {
				if len(txs) == 1 {
					delete(failedTxList, height)
					spvTransactiondb.Delete(encodeUnTransactionNumber(height))
				} else {
					txs = append(txs[:i], txs[i+1:]...)
					data := encodeTxList(txs)
					spvTransactiondb.Put(encodeUnTransactionNumber(height), data)
				}
				break
			}
		}
	}
}

func GetFailedRechargeTxs(height uint64) []string {
	failedMutex.Lock()
	defer failedMutex.Unlock()
	list := make([]string, 0)
	height, err := SafeUInt64Minus(height, blockDiff)
	if err != nil {
		return list
	}
	txs := failedTxList[height]
	if txs == nil || len(txs) == 0 {
		txs = getTxsOnDb(height)
	}
	for _, txid := range txs {
		list = append(list, txid)
	}
	return list
}

func GetFailedRechargeTxByHash(hash string) string {
	failedMutex.Lock()
	defer failedMutex.Unlock()
	currentHeight, err := ipcClient.CurrentBlockNumber(context.Background())
	if err != nil {
		log.Error("GetFailedRechargeTxByHash CurrentBlockNumber failed", "error",  err.Error())
		return ""
	}
	for height, txs := range failedTxList {
		v, err := SafeUInt64Minus(currentHeight, height)
		if err != nil || v < blockDiff {
			continue
		}
		for _, tx := range txs {
			if tx == hash {
				return tx
			}
		}
	}

	it := spvTransactiondb.NewIterator()
	defer it.Release()
	for it.Next() {
		value := it.Value()
		txs, err := decodeTxList(value)
		if err != nil {
			continue
		}
		key := it.Key()
		if len(key) != 8 || len(txs) == 0 {
			continue
		}
		height := binary.BigEndian.Uint64(key)
		diff, err := SafeUInt64Minus(currentHeight, height)
		if err != nil ||  diff < blockDiff {
			continue
		}
		for _, tx := range txs {
			if tx == hash {
				return tx
			}
		}
	}
	return ""
}

func getTxsOnDb(height uint64) []string {
	list := make([]string, 0)
	data, err := spvTransactiondb.Get(encodeUnTransactionNumber(height))
	if err != nil {
		return list
	}
	list, err = decodeTxList(data)
	if err != nil {
		return list
	}
	return list
}

func SendEvilProof(addr ethCommon.Address, info interface{}) {
	log.Info("Send evil Proof", "signer", addr.String())
	//ToDO connect ela chain

}

func GetArbiters() ([]string, error) {
	producers, err := ipcClient.GetCurrentProducers(context.Background())
	if err != nil {
		return nil, err
	}
	return producers, nil
}

func GetClient() *ethclient.Client {
	return ipcClient
}