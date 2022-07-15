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
	"github.com/elastos/Elastos.ELA.SideChain.ESC/node"
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
	isNeedRecoveryArbiters    bool

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

func Init(engine *pbft.Pbft, stack *node.Node, accountPath, accountPassword string) {
	pbftEngine = engine
	if MsgReleayer != nil {
		log.Warn("chain bridge is started")
		return
	}
	err := initRelayer(engine, stack, accountPath, accountPassword)
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
		case events.ETDirectPeersChangedV2:
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
			nextTotalCount := spv.GetTotalProducersCount()
			if !IsFirstUpdateArbiter && isSameNexturnArbiter(producers) && wasArbiter == isProducer &&
				arbiterManager.GetNextTotalCount() == nextTotalCount && isValidator == isProducer {
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
			wasArbiter = isProducer
			if !isProducer {
				bridgelog.Info("self is not a producer, chain bridge is stop")
				return
			}
			arbiterManager.Clear()
			if IsFirstUpdateArbiter {
				arbiterManager.SetTotalCount(pbftEngine.GetTotalArbitersCount(), pbftEngine.GetTotalArbitersCount())
			} else {
				arbiterManager.SetTotalCount(pbftEngine.GetTotalArbitersCount(), nextTotalCount)
			}

			wasArbiter = true
			bridgelog.Info("became a producer, collect arbiter")

			if IsFirstUpdateArbiter || nexturnHasSelf(self) || len(nextTurnArbiters) == 0 {
				var pid peer.PID
				copy(pid[:], self)
				err := arbiterManager.AddArbiter(pid, pbftEngine.GetBridgeArbiters().PublicKeyBytes()) //add self
				if err != nil {
					bridgelog.Error("add self public key failed", "error", err)
				}
			} else {
				bridgelog.Info("nexturn self is not a producer")
			}
			retryCount = 0

			if isRequireArbiter {
				Stop("Re apply for arbiter list ")
			}
			atomic.StoreInt32(&canStart, 0)
			err := arbiterManager.AddCurrentArbiter(keypair.PublicKeyBytes())
			if err != nil {
				bridgelog.Info("AddCurrentArbiter failed", "error", err)
			}
			go collectToUpdateArbiters()
		case dpos.ETUpdateProducers:
			if selfDutyIndex, ok := e.Data.(int); ok {
				go func() {
					if selfDutyIndex > 0 {
						selfDutyIndex = selfDutyIndex + 1
					}
					time.Sleep(time.Duration(selfDutyIndex*8) * time.Second)
					err := api.UpdateArbiters(escChainID)
					if err != nil {
						log.Error("ETUpdateProducers failed", "error", err)
					}
				}()
			}
			//onProducersChanged(e)
		case dpos_msg.ETOnArbiter:
			res, err := hanleDArbiter(pbftEngine, e)
			if res {
				list := arbiterManager.GetArbiterList()
				consensusArbiterCount := len(arbiterManager.GetConsensusArbiters().List)
				bridgelog.Info("now arbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount, "consensusArbiterCount", consensusArbiterCount)
				if len(list) == requireArbitersCount && consensusArbiterCount <= 1 {
					arbiterManager.SaveToCollection()
					if IsFirstUpdateArbiter {
						err := api.UpdateArbiters(escChainID)
						if err != nil {
							bridgelog.Warn("UpdateArbiters failed", "error", err)
						}
					} else {
						requireArbitersSignature(pbftEngine)
					}
					requireArbiters(pbftEngine, true)
				}
			} else if err != nil {
				bridgelog.Error("hanleDArbiter error", "msg", err)
			}
		case dpos_msg.ETRequireArbiter:
			receivedRequireArbiter(pbftEngine, e)
		case dpos_msg.ETReqArbiterSig:
			receivedReqArbiterSignature(pbftEngine, e)
		case dpos_msg.ETFeedBackArbiterSig:
			handleFeedBackArbitersSig(pbftEngine, e)
		case dpos_msg.ETESCStateChanged:
			escStateChanged(e)
		case dpos.ETOnDutyEvent:
			recoveryArbiter()
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
	if len(producers) == 0 && len(nextTurnArbiters) == 0 {
		return true
	}
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
	salt, err := MsgReleayer.GetHashSalt(escChainID)
	if err != nil {
		bridgelog.Warn("GetHashSalt failed", "error")
		return
	}
	hash, err := arbiterManager.HashArbiterList(salt)
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

	salt, err := MsgReleayer.GetHashSalt(escChainID)
	if err != nil {
		bridgelog.Warn("GetHashSalt failed", "error")
		return
	}

	hash, err := arbiterManager.HashArbiterList(salt)
	if err != nil {
		bridgelog.Error("receivedReqArbiterSignature HashArbiterList failed", "error", err)
	}
	sign, err := crypto.Sign(accounts.TextHash(hash.Bytes()), privateKey)
	if err != nil {
		bridgelog.Warn("sign arbiters error", "error", err)
		return
	}
	msg.Signature = sign
	engine.SendMsgToPeer(msg, m.PID)
	if currentArbitersHasself() {
		if !arbiterManager.HasSignature(selfProducer) {
			bridgelog.Info("add self signature")
			go events.Notify(dpos_msg.ETFeedBackArbiterSig, msg) //add self signature
		}
	} else {
		bridgelog.Warn("receivedReqArbiterSignature current aribter list not contain self")
	}
}

func requireArbitersSignature(engine *pbft.Pbft) {
	signCount := len(arbiterManager.GetSignatures())
	producersCount := pbftEngine.GetTotalProducerCount()
	if api.HasProducerMajorityCount(signCount, producersCount) {
		arbiterManager.SaveToCollection()
		log.Info("collect over signatures, no nned to require")
		return
	}
	go func() {
		for {
			select {
			case <-time.NewTimer(2 * time.Second).C:
				signCount = len(arbiterManager.GetSignatures())
				log.Info("requireArbitersSignature", "signCount", signCount, "total", arbiterManager.GetCurrentTotalCount())
				if api.HasProducerMajorityCount(signCount, producersCount) {
					log.Info("collect over signatures SaveTo collection and judge is recovery state")
					arbiterManager.SaveToCollection()
					setRecoveryArbiterList()
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

func setRecoveryArbiterList() {
	collection := arbiterManager.GetCollection()
	address := make([]common.Address, 0)
	for _, arbiter := range collection.List {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err == nil {
			addr := crypto.PubkeyToAddress(*escssaPUb)
			address = append(address, addr)
		}
	}

	verifyCount := 0
	for _, arbiter := range currentArbitersOnContract {
		for _, addr := range address {
			if arbiter.String() == addr.String() {
				verifyCount++
				break
			}
		}
	}
	bridgelog.Info("recoveryArbiterList", "current list", len(currentArbitersOnContract), "selfIsOnduty", pbftEngine.IsOnduty(), "collection len", len(address))
	if verifyCount == len(currentArbitersOnContract) && len(address) != verifyCount {
		isNeedRecoveryArbiters = true
	} else {
		isNeedRecoveryArbiters = false
	}
}

func recoveryArbiter() {
	if isNeedRecoveryArbiters == false {
		return
	}
	err := api.UpdateArbiters(escChainID)
	if err != nil {
		bridgelog.Error("recoveryArbiter failed", "error", err)
	}
	isNeedRecoveryArbiters = false
}

func receivedRequireArbiter(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*dpos_msg.RequireArbiter)
	if !ok {
		return
	}
	SendAriberToPeer(engine, m.PID, m.IsCurrent)
}

func hanleDArbiter(engine *pbft.Pbft, e *events.Event) (bool, error) {
	// Verify signature of the message.
	m, ok := e.Data.(*dpos_msg.DArbiter)
	if !ok {
		err := errors.New("hanleDArbiter error data")
		return false, err
	}
	selfSigner := engine.GetProducer()

	if bytes.Equal(selfSigner, m.Encode[:]) == false {
		log.Info("hanleDArbiter is not self DArbiter", "selfSigner", common.Bytes2Hex(selfSigner), "encode", common.Bytes2Hex(m.Encode[:]))
		return false, nil
	}
	pubKey, err := elaCrypto.DecodePoint(m.PID[:])
	if err != nil {
		return false, errors.New("hanleDArbiter invalid public key")
	}
	if !engine.IsProducerByAccount(m.PID[:]) && !nexturnHasSelf(m.PID[:]) {
		log.Error("hanleDArbiter is not a producer")
		return false, nil
	}
	err = elaCrypto.Verify(*pubKey, m.Data(), m.Signature)
	if err != nil {
		return false, err
	}
	signerPublicKey, err := engine.DecryptArbiter(m.Cipher)
	if err != nil {
		return false, err
	}
	if m.IsCurrent {
		err = arbiterManager.AddCurrentArbiter(signerPublicKey)
	} else {
		err = arbiterManager.AddArbiter(m.PID, signerPublicKey)
	}
	if err != nil {
		log.Error("add arbiter error", "error", err)
		return false, nil
	}
	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey), " m.PID[:]", common.Bytes2Hex(m.PID[:]), "isCurrent", m.IsCurrent)
	return true, nil
}

func collectToUpdateArbiters() {
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
				bridgelog.Info("update arbiter collect completed, to collected current arbiters")
				arbiterManager.SaveToCollection()
				if IsFirstUpdateArbiter {
					err := api.UpdateArbiters(escChainID)
					if err != nil {
						bridgelog.Error("init arbiter failed", "error", err)
					}
				} else {
					requireArbitersSignature(pbftEngine)
				}
				requireArbiters(pbftEngine, true)
				return
			}
			requireArbiters(pbftEngine, false)
			atomic.StoreInt32(&canStart, 1)
		case err := <-errChn:
			bridgelog.Error("failed to listen and serve 2 ", "error", err)
			return
		}
	}
}

func requireArbiters(engine *pbft.Pbft, isCurrent bool) {
	var peers [][]byte
	if IsFirstUpdateArbiter || len(nextTurnArbiters) == 0 || isCurrent {
		peers = engine.GetCurrentProducers()
	} else {
		peers = nextTurnArbiters
	}
	count := getActivePeerCount(engine, peers)
	nowArbiterCount := len(arbiterManager.GetArbiterList())
	log.Info("getActivePeerCount", "count", count, "total", len(peers), "IsFirstUpdateArbiter", IsFirstUpdateArbiter, "retryCount", retryCount, "isCurrent", isCurrent)
	if api.HasProducerMajorityCount(count, len(peers)) {
		if count < len(peers) && retryCount < MAX_RETRYCOUNT && nowArbiterCount > 1 && !isCurrent {
			retryCount++
			return
		}
		var list [][]byte
		if isCurrent {
			list = peers
			requireArbitersCount = count
		} else {
			list = arbiterManager.FilterArbiters(peers)
			if retryCount == MAX_RETRYCOUNT {
				requireArbitersCount = count
			} else {
				requireArbitersCount = len(peers)
			}
		}

		selfProducer := engine.GetProducer()
		msg := &dpos_msg.RequireArbiter{IsCurrent: isCurrent}
		copy(msg.PID[:], selfProducer)

		bridgelog.Info("request arbiters", "len", len(list))
		engine.BroadMessageToPeers(msg, list)
	}
}

func SendAriberToPeer(engine *pbft.Pbft, pid peer.PID, isCurrent bool) {
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
	cipher, err := elaCrypto.Encrypt(publicKey, signer)
	msg := &dpos_msg.DArbiter{
		Timestamp: time.Now(),
		Cipher:    cipher,
		IsCurrent: isCurrent,
	}
	copy(msg.PID[:], selfProducer[:])
	copy(msg.Encode[:], pid[:])
	msg.Signature = engine.SignData(msg.Data())

	engine.SendMsgToPeer(msg, pid)
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

func escStateChanged(e *events.Event) {
	v, ok := e.Data.(int)
	state := uint8(v)
	bridgelog.Info("received esc chain state changed", "state", e.Data)
	if !ok {
		return
	}
	if state < spv.ChainState_DPOS || state > spv.ChainState_Error {
		bridgelog.Error("error state value", "state", state)
		return
	}
	if !currentArbitersHasself() {
		bridgelog.Error("self is not in current arbiter list , can't update esc state")
		return
	}
	err := MsgReleayer.SetESCState(state)
	if err != nil {
		bridgelog.Error("SetESCState failed", "error", err)
	}
}

func onProducersChanged(e *events.Event) {
	if !currentArbitersHasself() {
		bridgelog.Info("self is not in contract arbiter list")
		return
	}
	collection := arbiterManager.GetCollection()
	arbiters := collection.List
	total := collection.NextTotalCount
	addresses := make([]common.Address, 0)
	for _, arbiter := range arbiters {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			bridgelog.Error("arbiter publick key is error", "arbiter", common.Bytes2Hex(arbiter))
			continue
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		addresses = append(addresses, addr)
	}

	err := MsgReleayer.SetManualArbiters(addresses, total)
	bridgelog.Info("SetManualArbiters", "total", total, "error", err, "arbiterCount", len(addresses))
}

func initRelayer(engine *pbft.Pbft, stack *node.Node, accountPath, accountPassword string) error {
	if MsgReleayer != nil {
		return nil
	}
	cfg, err := config.GetConfig(config.DefaultConfigDir)
	if err != nil {
		log.Info("engine.GetBlockChain().Config().BridgeContractAddr", "address", engine.GetBlockChain().Config().BridgeContractAddr)
		err = createSelfChain(engine, stack)
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

func createSelfChain(engine *pbft.Pbft, stack *node.Node) error {
	if engine.GetBlockChain().Config().ChainID == nil {
		return errors.New("escChainID is nil")
	}
	escChainID = engine.GetBlockChain().Config().ChainID.Uint64()
	rpc := fmt.Sprintf("http://localhost:%d", stack.Config().HTTPPort)
	generalConfig := config.GeneralChainConfig{
		Name:     "ESC",
		Id:       escChainID,
		Endpoint: rpc,
	}
	layer, errMsg := createChain(&generalConfig, nil, engine, "", "")
	if errMsg != nil {
		return errors.New(fmt.Sprintf("evm createSelfChain is error:%s, chainid:%d", errMsg.Error(), escChainID))
	}
	chains := make([]relayer.RelayedChain, 1)
	chains[0] = layer
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
		evmVoter = voter.NewVoter(ethClient, kp)
	} else {
		evmVoter = voter.NewVoter(ethClient, nil)
	}
	evmListener := listener.NewEVMListener(ethClient, &generalConfig.Opts)
	chain := evm.NewEVMChain(evmListener, evmVoter, generalConfig.Id, db,
		generalConfig, arbiterManager)
	return chain, nil
}

func StartUpdateNode() {
	go MsgReleayer.Start()
}
