package chainbridge_core

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/aribiters"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/listener"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/lvldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"

	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/p2p"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
)

const (
	MAX_RETRYCOUNT = 60
)

var (
	MsgReleayer          *relayer.Relayer
	errChn               chan error
	stopChn              chan struct{}
	isRequireArbiter     bool
	canStart             int32
	nextTurnArbiters     [][]byte
	requireArbitersCount int
	arbiterManager       *aribiters.ArbiterManager

	IsFirstUpdateArbiter bool
	api                  *API
	pbftEngine           *pbft.Pbft
	isStarted            bool
	wasArbiter           bool
	retryCount           int

	currentArbitersOnContract []common.Address
	selfArbiterAddr           string

	escChainID uint64
)

func init() {
	errChn = make(chan error)
	stopChn = make(chan struct{})
	arbiterManager = aribiters.CreateArbiterManager()
	nextTurnArbiters = make([][]byte, 0)
	atomic.StoreInt32(&canStart, 1)
	isStarted = false
	isRequireArbiter = false
}

func APIs(engine *pbft.Pbft) []rpc.API {
	if api == nil {
		api = &API{engine}
	}
	return []rpc.API{{
		Namespace: "bridge",
		Version:   "1.0",
		Service:   api,
		Public:    true,
	}}
}

func Init(engine *pbft.Pbft, accountPath, accountPassword string) {
	pbftEngine = engine
	if MsgReleayer != nil {
		log.Warn("chain bridge is started")
		return
	}
	err := initRelayer(engine, accountPath, accountPassword)
	if err != nil {
		bridgelog.Error("chain bridge started error", "error", err)
		return
	}
}

func Start() bool {
	if MsgReleayer == nil || pbftEngine == nil {
		bridgelog.Warn("chain bridge is not init")
		return false
	}
	if isStarted {
		return false
	}
	bridgelog.Info("chain bridge start")
	isStarted = true
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case events.ETDirectPeersChanged:
			bridgelog.Info("ETDirectPeersChanged, to collect old arbiter signed new arbiter's signature")
			if atomic.LoadInt32(&canStart) == 0 {
				bridgelog.Info("is starting, can't restart")
				return
			}
			isProducer := pbftEngine.IsProducer()
			self := pbftEngine.GetProducer()
			keypair := pbftEngine.GetBridgeArbiters()
			selfArbiterAddr = keypair.Address()
			currentArbitersOnContract = MsgReleayer.GetArbiters(escChainID)
			isValidator := currentArbitersHasself()
			bridgelog.Info("selfArbiterAddr ", selfArbiterAddr, "isValidator", isValidator)
			IsFirstUpdateArbiter = len(currentArbitersOnContract) == 0
			producers := spv.GetNextTurnPeers()
			sort.Slice(producers, func(i, j int) bool {
				return bytes.Compare(producers[i][:], producers[j][:]) < 0
			})
			if !IsFirstUpdateArbiter && isSameNexturnArbiter(producers) && wasArbiter == isProducer &&
				arbiterManager.GetTotalCount() == pbftEngine.GetTotalArbitersCount() && isValidator == isProducer {
				bridgelog.Info("ETDirectPeersChanged is same current producers")
				return
			}
			nextTurnArbiters = make([][]byte, 0)
			if len(producers) > 0 {
				nextTurnArbiters = make([][]byte, len(producers))
				if !IsFirstUpdateArbiter {
					for i, p := range producers {
						nextTurnArbiters[i] = make([]byte, len(p))
						copy(nextTurnArbiters[i], p[:])
					}
				}
			}
			bridgelog.Info("GetNextTurnPeers", "count ", len(producers), "nextTurnArbiters", len(nextTurnArbiters))

			if !isProducer {
				if wasArbiter {
					api.UpdateArbiters(escChainID)
				}
				if !isValidator {
					bridgelog.Info("self is not a producer, chain bridge is stop")
					return
				}
			}
			arbiterManager.Clear()
			arbiterManager.SetTotalCount(pbftEngine.GetTotalArbitersCount())
			wasArbiter = true
			bridgelog.Info("became a producer, collect arbiter")

			if IsFirstUpdateArbiter || nexturnHasSelf(self) || len(nextTurnArbiters) == 0 {
				var pid peer.PID
				copy(pid[:], self)
				arbiterManager.AddArbiter(pid, pbftEngine.GetBridgeArbiters().PublicKeyBytes()) //add self
			} else {
				bridgelog.Info("nexturn self is not a producer")
			}
			retryCount = 0

			if isRequireArbiter {
				Stop("Re apply for arbiter list ")
			}

			atomic.StoreInt32(&canStart, 0)
			go onSelfIsArbiter()
		case dpos.ETUpdateProducers:
			api.UpdateArbiters(escChainID)
		case dpos_msg.ETOnArbiter:
			res, _ := hanleDArbiter(pbftEngine, e)
			if res {
				list := arbiterManager.GetArbiterList()
				bridgelog.Info("now arbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount)
				if len(list) == requireArbitersCount {
					if IsFirstUpdateArbiter {
						api.UpdateArbiters(escChainID)
					} else {
						requireArbitersSignature(pbftEngine)
					}
				}
			}
		case dpos_msg.ETRequireArbiter:
			receivedRequireArbiter(pbftEngine, e)
		case dpos_msg.ETReqArbiterSig:
			receivedReqArbiterSignature(pbftEngine, e)
		case dpos_msg.ETFeedBackArbiterSig:
			handleFeedBackArbitersSig(pbftEngine, e)
		}
	})
	return true
}

func currentArbitersHasself() bool {
	if currentArbitersOnContract != nil && len(currentArbitersOnContract) > 0 {
		for _, arbiter := range currentArbitersOnContract {
			if arbiter.String() == selfArbiterAddr {
				return true
			}
		}
	}
	return false
}

func isSameNexturnArbiter(producers []peer.PID) bool {
	if len(producers) <= 0 || len(nextTurnArbiters) <= 0 {
		return false
	}
	if len(producers) != len(nextTurnArbiters) {
		return false
	}
	for i, p := range producers {
		if !bytes.Equal(p[:], nextTurnArbiters[i]) {
			return false
		}
	}
	return true
}

func nexturnHasSelf(acc []byte) bool {
	for _, arbiter := range nextTurnArbiters {
		if bytes.Equal(acc, arbiter) {
			return true
		}
	}
	return false
}

func handleFeedBackArbitersSig(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*dpos_msg.FeedBackArbitersSignature)
	if !ok {
		return
	}
	producer := m.Producer
	if !engine.IsProducerByAccount(producer) {
		bridgelog.Warn("handleFeedBackArbitersSig failed , is not producer", common.Bytes2Hex(producer))
		return
	}
	hash, err := arbiterManager.HashArbiterList()
	if err != nil {
		bridgelog.Warn("HashArbiterList failed", "error", err)
		return
	}
	_, err = crypto.SigToPub(accounts.TextHash(hash.Bytes()), m.Signature)
	if err != nil {
		bridgelog.Warn("[handleFeedBackArbitersSig] Ecrecover error", "error", err)
		return
	}
	var pid peer.PID
	copy(pid[:], producer)
	err = arbiterManager.AddSignature(pid, m.Signature)
	if err != nil {
		bridgelog.Info("AddSignature failed", "error", err, "from", common.Bytes2Hex(producer))
		return
	}
	signatures := arbiterManager.GetSignatures()
	count := len(signatures)
	bridgelog.Info("handleFeedBackArbitersSig", "count", count, "producer", common.Bytes2Hex(producer), "engine.GetTotalArbitersCount()", engine.GetTotalArbitersCount())
}

func receivedReqArbiterSignature(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*dpos_msg.RequireArbitersSignature)
	if !ok {
		return
	}
	if engine.IsProducerByAccount(m.PID[:]) == false {
		bridgelog.Warn("[receivedReqArbiterSignature] target is not a producer", "pid", common.Bytes2Hex(m.PID[:]))
		return
	}
	if int(m.ArbiterCount) != len(arbiterManager.GetArbiterList()) {
		bridgelog.Warn("[receivedReqArbiterSignature] ArbiterCount is not same", "m.arbiterCount", m.ArbiterCount, "arbiterList", len(arbiterManager.GetArbiterList()), "from node", common.Bytes2Hex(m.PID[:]))
		return
	}
	selfProducer := engine.GetProducer()
	msg := &dpos_msg.FeedBackArbitersSignature{}
	msg.Producer = selfProducer

	kp := engine.GetBridgeArbiters().(*secp256k1.Keypair)
	privateKey := kp.PrivateKey()
	hash, err := arbiterManager.HashArbiterList()
	if err != nil {
		bridgelog.Error("receivedReqArbiterSignature HashArbiterList failed", "error", err)
	}
	sign, err := crypto.Sign(accounts.TextHash(hash.Bytes()), privateKey)
	if err != nil {
		bridgelog.Warn("sign arbiters error", "error", err)
		return
	}
	msg.Signature = sign
	if currentArbitersHasself() {
		engine.SendMsgToPeer(msg, m.PID)
		if !arbiterManager.HasSignature(selfProducer) {
			bridgelog.Info("add self signature")
			go events.Notify(dpos_msg.ETFeedBackArbiterSig, msg) //add self signature
		}
	} else {
		bridgelog.Error("receivedReqArbiterSignature current aribter list not contain self")
	}
}

func requireArbitersSignature(engine *pbft.Pbft) {
	signCount := len(arbiterManager.GetSignatures())
	if api.HasProducerMajorityCount(signCount, arbiterManager.GetTotalCount()) {
		log.Info("collect over signatures, no nned to require")
		return
	}
	go func() {
		for {
			select {
			case <-time.NewTimer(2 * time.Second).C:
				signCount = len(arbiterManager.GetSignatures())
				log.Info("requireArbitersSignature", "signCount", signCount, "total", arbiterManager.GetTotalCount(), "total2", engine.GetTotalArbitersCount())
				if api.HasProducerMajorityCount(signCount, arbiterManager.GetTotalCount()) {
					log.Info("collect over signatures", "spv.SpvIsWorkingHeight()", spv.SpvIsWorkingHeight())
					if spv.SpvIsWorkingHeight() {
						api.UpdateArbiters(escChainID)
					}
					return
				}
				arbiterCount := len(arbiterManager.GetArbiterList())
				selfProducer := engine.GetProducer()
				msg := &dpos_msg.RequireArbitersSignature{
					ArbiterCount: uint8(arbiterCount),
				}
				copy(msg.PID[:], selfProducer)
				peers := arbiterManager.FilterSignatures(engine.GetCurrentProducers())
				log.Info("to collecting signatures", "len", len(peers))
				engine.BroadMessageToPeers(msg, peers)
			}
		}
	}()
}

func receivedRequireArbiter(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*dpos_msg.RequireArbiter)
	if !ok {
		return
	}
	SendAriberToPeer(engine, m.PID)
}

func hanleDArbiter(engine *pbft.Pbft, e *events.Event) (bool, error) {
	// Verify signature of the message.
	m, ok := e.Data.(*dpos_msg.DArbiter)
	if !ok {
		err := errors.New("hanleDArbiter error data")
		log.Error(err.Error())
		return false, err
	}
	selfSigner := engine.GetProducer()

	if bytes.Equal(selfSigner, m.Encode[:]) == false {
		log.Info("hanleDArbiter is not self DArbiter", "selfSigner", common.Bytes2Hex(selfSigner), "encode", common.Bytes2Hex(m.Encode[:]))
		return false, nil
	}
	pubKey, err := elaCrypto.DecodePoint(m.PID[:])
	if err != nil {
		log.Error("hanleDArbiter invalid public key")
		return false, errors.New("hanleDArbiter invalid public key")
	}
	if !engine.IsProducerByAccount(m.PID[:]) && !nexturnHasSelf(m.PID[:]) {
		log.Error("hanleDArbiter is not a producer")
		return false, nil
	}
	err = elaCrypto.Verify(*pubKey, m.Data(), m.Signature)
	if err != nil {
		log.Error("hanleDArbiter invalid signature", "pid", common.Bytes2Hex(m.PID[:]))
		return false, err
	}
	signerPublicKey, err := engine.DecryptArbiter(m.Cipher)
	if err != nil {
		log.Error("hanleDArbiter decrypt address cipher error", "error:", err, "self", common.Bytes2Hex(selfSigner), "cipher", common.Bytes2Hex(m.Cipher))
		return false, err
	}
	data := GetProducersData()
	err = elaCrypto.Verify(*pubKey, data, m.ArbitersSignature)
	if err != nil {
		log.Error("hanleDArbiter producers verify error", "pid", common.Bytes2Hex(m.PID[:]), "data", common.Bytes2Hex(data))
		return false, err
	}
	err = arbiterManager.AddArbiter(m.PID, signerPublicKey)
	if err != nil {
		log.Error("add arbiter error", "error", err)
		return false, nil
	}

	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey), " m.PID[:]", common.Bytes2Hex(m.PID[:]))
	return true, nil
}

func onSelfIsArbiter() {
	isRequireArbiter = true
	defer func() {
		bridgelog.Info("onSelfIsArbiter is quit")
		isRequireArbiter = false
		atomic.StoreInt32(&canStart, 1)
	}()
	for {
		select {
		case <-time.After(time.Second * 2):
			list := arbiterManager.GetArbiterList()
			bridgelog.Info("arbiterManager GetArbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount)
			if len(list) >= requireArbitersCount && requireArbitersCount > 0 {
				return
			}
			requireArbiters(pbftEngine)
			atomic.StoreInt32(&canStart, 1)
		case err := <-errChn:
			bridgelog.Error("failed to listen and serve 2 ", "error", err)
			return
		}
	}
}

func requireArbiters(engine *pbft.Pbft) bool {
	var peers [][]byte
	if IsFirstUpdateArbiter || len(nextTurnArbiters) == 0 {
		peers = engine.GetCurrentProducers()
	} else {
		peers = nextTurnArbiters
	}
	count := getActivePeerCount(engine, peers)
	nowArbiterCount := len(arbiterManager.GetArbiterList())
	log.Info("getActivePeerCount", "count", count, "total", len(peers), "IsFirstUpdateArbiter", IsFirstUpdateArbiter, "retryCount", retryCount)
	if api.HasProducerMajorityCount(count, len(peers)) {
		if count < len(peers) && retryCount < MAX_RETRYCOUNT && nowArbiterCount > 1 {
			retryCount++
			return false
		}

		list := arbiterManager.FilterArbiters(peers)
		requireArbitersCount = len(peers)
		selfProducer := engine.GetProducer()
		msg := &dpos_msg.RequireArbiter{}
		copy(msg.PID[:], selfProducer)

		bridgelog.Info("request arbiters", "len", len(list))
		engine.BroadMessageToPeers(msg, list)
		return true
	}
	return false
}

func SendSelfToArbiters(engine *pbft.Pbft, peers [][]byte) {
	for _, p := range peers {
		pid := peer.PID{}
		copy(pid[:], p)
		SendAriberToPeer(engine, pid)
	}
}

func SendAriberToPeer(engine *pbft.Pbft, pid peer.PID) {
	if engine.IsProducerByAccount(pid[:]) == false && !nexturnHasSelf(pid[:]) {
		log.Warn("target is not a producer", "pid", pid.String())
		return
	}
	signer := engine.GetBridgeArbiters().PublicKeyBytes()
	selfProducer := engine.GetProducer()
	publicKey, err := elaCrypto.DecodePoint(pid[:])
	if err != nil {
		log.Error("DecodePoint pbk error", "error", err, "selfProducer", common.Bytes2Hex(selfProducer))
		return
	}
	producersData := GetProducersData()
	cipher, err := elaCrypto.Encrypt(publicKey, signer)
	msg := &dpos_msg.DArbiter{
		Timestamp:         time.Now(),
		Cipher:            cipher,
		ArbitersSignature: engine.SignData(producersData),
	}
	copy(msg.PID[:], selfProducer[:])
	copy(msg.Encode[:], pid[:])
	msg.Signature = engine.SignData(msg.Data())

	engine.SendMsgToPeer(msg, pid)
}

func GetProducersData() []byte {
	if len(nextTurnArbiters) <= 0 {
		return []byte{}
	}
	data := make([]byte, 0)
	for _, producer := range nextTurnArbiters {
		data = append(data, producer...)
	}
	return data
}

func getActivePeerCount(engine *pbft.Pbft, arbiters [][]byte) int {
	count := 0
	peers := engine.GetAllArbiterPeersInfo()
	hasSelf := false
	self := engine.GetProducer()
	for _, arb := range arbiters {
		if bytes.Equal(arb, self) {
			hasSelf = true
		}
		for _, peer := range peers {
			if bytes.Equal(arb, peer.PID[:]) {
				if peer.State == p2p.CS2WayConnection {
					count++
				}
				if peer.State == p2p.CSNoneConnection {
					log.Info("none connect", "pid:", peer.PID.String(), "IP", peer.Addr)
				}
				break
			}
		}
	}
	if hasSelf {
		count += 1 //add self node
	}
	return count
}

func initRelayer(engine *pbft.Pbft, accountPath, accountPassword string) error {
	if MsgReleayer != nil {
		return nil
	}
	cfg, err := config.GetConfig(config.DefaultConfigDir)
	if err != nil {
		return err
	}
	db, err := lvldb.NewLvlDB(config.BlockstoreFlagName)
	if err != nil {
		return err
	}
	escChainID = engine.GetBlockChain().Config().ChainID.Uint64()
	count := len(cfg.Chains)
	chains := make([]relayer.RelayedChain, count)
	for i := 0; i < count; i++ {
		layer, errMsg := createChain(&cfg.Chains[i], db, engine, accountPath, accountPassword)
		if errMsg != nil {
			return errors.New(fmt.Sprintf("evm chain is create error:%s, chainid:%d", errMsg.Error(), cfg.Chains[i].Id))
		}
		chains[i] = layer
		if escChainID == layer.ChainID() {
			engine.GetBlockChain().Config().BridgeContractAddr = layer.GetBridgeContract()
		}
	}
	MsgReleayer = relayer.NewRelayer(chains, escChainID)
	return nil
}

func Stop(msg string) {
	if isRequireArbiter {
		errChn <- fmt.Errorf(msg)
	}
	atomic.StoreInt32(&canStart, 1)
	isRequireArbiter = false
}
func createChain(generalConfig *config.GeneralChainConfig, db blockstore.KeyValueReaderWriter, engine *pbft.Pbft, accountPath, accountPassword string) (*evm.EVMChain, error) {
	ethClient := evmclient.NewEVMClient(engine)
	if ethClient == nil {
		return nil, errors.New("create evm client error")
	}
	err := ethClient.Configurate(generalConfig, accountPath, accountPassword)
	if err != nil {
		return nil, err
	}

	var evmVoter *voter.EVMVoter
	if engine.GetBridgeArbiters() != nil {
		kp := engine.GetBridgeArbiters().(*secp256k1.Keypair)
		if kp != nil {
			evmVoter = voter.NewVoter(ethClient, kp)
		}
	}
	evmListener := listener.NewEVMListener(ethClient, &generalConfig.Opts)
	chain := evm.NewEVMChain(evmListener, evmVoter, generalConfig.Id, db,
		generalConfig, arbiterManager)
	return chain, nil
}

func StartUpdateNode() {
	go MsgReleayer.Start()
}
