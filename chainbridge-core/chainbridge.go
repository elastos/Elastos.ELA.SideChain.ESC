package chainbridge_core

import (
	"bytes"
	"errors"
	"fmt"
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
	relayStarted         bool
	canStart             int32
	nextTurnArbiters     [][]byte
	requireArbitersCount int
	arbiterManager       *aribiters.ArbiterManager

	IsFirstUpdateArbiter bool
	api                  *API
	pbftEngine           *pbft.Pbft
	isStarted            bool
	wasArbiter           bool
	selfIsSuperVoter     bool
	retryCount           int

	currentArbitersOnContract []common.Address
	currentSuperSigner        common.Address
	selfArbiterAddr           string
	isNewStart                bool
)

func init() {
	errChn = make(chan error)
	relayStarted = false
	arbiterManager = aribiters.CreateArbiterManager()
	nextTurnArbiters = make([][]byte, 0)
	atomic.StoreInt32(&canStart, 1)
	isStarted = false
	isNewStart = true
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
	chainID := uint8(pbftEngine.GetBlockChain().Config().ChainID.Uint64())
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
			singer := MsgReleayer.GetCurrentSuperSigner(chainID)
			signerIsUpdate := singer != currentSuperSigner
			currentSuperSigner = singer
			keypair := pbftEngine.GetBridgeArbiters()
			selfArbiterAddr = keypair.Address()
			var emptyAddr common.Address
			if currentSuperSigner != emptyAddr {
				nodepublickey := MsgReleayer.GetSuperSignerNodePublickey(chainID)
				pbftEngine.GetBlockChain().Config().Layer2SuperNodePubKey = nodepublickey
				selfIsSuperVoter = selfArbiterAddr == currentSuperSigner.String()
				err := spv.UpdateSuperNodePublickey(nodepublickey, signerIsUpdate)
				if err != nil {
					log.Warn("UpdateSuperNodePublickey", "error", err)
				}
				if selfIsSuperVoter {
					updateL2SuperSigner(keypair.PublicKeyBytes())
					log.Info(">>>> Layer2EFVoter", "public_key:", pbftEngine.GetBlockChain().Config().Layer2EFVoter, "address:", keypair.Address())
				}
			} else {
				selfIsSuperVoter = bytes.Equal(self, common.Hex2Bytes(pbftEngine.GetBlockChain().Config().Layer2SuperNodePubKey))
			}
			bridgelog.Info("GetCurrentSuperSigner", currentSuperSigner.String(), "selfArbiterAddr ", selfArbiterAddr, "selfIsSuperVoter", selfIsSuperVoter, "nodePublickey", pbftEngine.GetBlockChain().Config().Layer2SuperNodePubKey)
			currentArbitersOnContract = MsgReleayer.GetArbiters(chainID)
			IsFirstUpdateArbiter = len(currentArbitersOnContract) == 0
			producers := spv.GetNextTurnPeers()
			if !IsFirstUpdateArbiter && isSameNexturnArbiter(producers) && wasArbiter == isProducer &&
				arbiterManager.GetTotalCount() == pbftEngine.GetTotalArbitersCount() {
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
			atomic.StoreInt32(&canStart, 0)
			if !isProducer && !selfIsSuperVoter {
				if wasArbiter {
					api.UpdateArbiters(0)
				}
				bridgelog.Info("self is not a producer, chain bridge is stop")
				Stop()
				return
			}
			arbiterManager.Clear()
			arbiterManager.SetTotalCount(pbftEngine.GetTotalArbitersCount())
			wasArbiter = true
			bridgelog.Info("became a producer, collet arbiter")

			if IsFirstUpdateArbiter || nexturnHasSelf(self) || selfIsSuperVoter || len(nextTurnArbiters) == 0 {
				var pid peer.PID
				copy(pid[:], self)
				arbiterManager.AddArbiter(pid, pbftEngine.GetBridgeArbiters().PublicKeyBytes()) //add self
			} else {
				bridgelog.Info("nexturn self is not a producer")
			}
			retryCount = 0
			go onSelfIsArbiter()
		case dpos.ETUpdateProducers:
			api.UpdateArbiters(0)
			isProducer := pbftEngine.IsProducer()
			if !isProducer {
				bridgelog.Info("ETUpdateProducers self is not a producer, chain bridge is stop")
				Stop()
				return
			}
		case dpos_msg.ETOnArbiter:
			res, _ := hanleDArbiter(pbftEngine, e)
			if res {
				list := arbiterManager.GetArbiterList()
				bridgelog.Info("now arbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount, "selfIsSuperVoter", selfIsSuperVoter)
				if len(list) == requireArbitersCount {
					if IsFirstUpdateArbiter {
						api.UpdateArbiters(0)
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
		case dpos.ETChangeSuperSigner:
			onReceivedChangSuperMsg(pbftEngine, e)
		}
	})
	return true
}

func onReceivedChangSuperMsg(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*relayer.ChangeSuperSigner)
	if !ok {
		bridgelog.Error("onReceivedChangSuperMsg event data is not ChangeSuperSigner", "data", e.Data)
		return
	}
	if uint64(m.SourceChain) != engine.GetBlockChain().Config().ChainID.Uint64() {
		bridgelog.Info("onReceivedChangSuperMsg is not current chain")
		return
	}
	superVoter := MsgReleayer.GetCurrentSuperSigner(m.SourceChain)
	if superVoter != m.NewSuperSigner {
		bridgelog.Info("onReceivedChangSuperMsg is not current superSigner")
		return
	}

	bridgelog.Info("onReceivedChangSuperMsg", "m", m.NewSuperSigner.String())

	engine.GetBlockChain().Config().Layer2SuperNodePubKey = m.NodePublicKey
	err := spv.UpdateSuperNodePublickey(m.NodePublicKey, currentSuperSigner != superVoter)
	if err != nil {
		log.Error("UpdateSuperNodePublickey failed", "error", err)
	}
	currentSuperSigner = superVoter
}

func currentArbitersHasself() bool {
	if currentArbitersOnContract == nil || len(currentArbitersOnContract) == 0 {
		return true
	}
	for _, arbiter := range currentArbitersOnContract {
		if arbiter.String() == selfArbiterAddr {
			return true
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
		log.Error("handleFeedBackArbitersSig failed , is not producer", common.Bytes2Hex(producer))
		return
	}
	hash, err := arbiterManager.HashArbiterList()
	if err != nil {
		log.Error("HashArbiterList failed", "error", err)
		return
	}
	_, err = crypto.SigToPub(accounts.TextHash(hash.Bytes()), m.Signature)
	if err != nil {
		log.Error("[handleFeedBackArbitersSig] Ecrecover error", "error", err)
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
		bridgelog.Warn("[receivedReqArbiterSignature] ArbiterCount is not same", "m.arbiterCount", m.ArbiterCount, "arbiterList", len(arbiterManager.GetArbiterList()))
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
	if !selfIsSuperVoter || selfIsSuperVoter && currentArbitersHasself() {
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
			case <-time.NewTimer(time.Second).C:
				signCount = len(arbiterManager.GetSignatures())
				log.Info("requireArbitersSignature", "signCount", signCount, "total", arbiterManager.GetTotalCount(), "total2", engine.GetTotalArbitersCount())
				if api.HasProducerMajorityCount(signCount, arbiterManager.GetTotalCount()) {
					log.Info("collect over signatures")
					api.UpdateArbiters(0)
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

func updateL2SuperSigner(efVoter []byte) {
	pbftEngine.GetBlockChain().Config().Layer2EFVoter = common.Bytes2Hex(efVoter)
	go events.Notify(dpos_msg.ETUpdateLayer2SuperVoter, efVoter)
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
	efVoter := common.Bytes2Hex(signerPublicKey)
	superNodePubkey := common.Hex2Bytes(engine.GetBlockChain().Config().Layer2SuperNodePubKey)
	if bytes.Equal(superNodePubkey, m.PID[:]) {
		if efVoter != engine.GetBlockChain().Config().Layer2EFVoter {
			updateL2SuperSigner(signerPublicKey)
		}
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

	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey), " m.PID[:]", common.Bytes2Hex(m.PID[:]), "superNodePubkey", engine.GetBlockChain().Config().Layer2SuperNodePubKey)
	return true, nil
}

func onSelfIsArbiter() {
	for {
		select {
		case <-time.After(time.Second * 2):
			list := arbiterManager.GetArbiterList()
			log.Info("arbiterManager GetArbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount)
			if len(list) == requireArbitersCount && requireArbitersCount > 0 {
				return
			}
			if requireArbiters(pbftEngine) {
				atomic.StoreInt32(&canStart, 1)
				if !relayStarted {
					relayStarted = true
					go func() {
						err := relayerStart()
						log.Error("bridge relay error", "error", err)
					}()
				} else {
					log.Info("bridge is starting relay")
				}
			}
		case err := <-errChn:
			log.Error("failed to listen and serve", "error", err)
			if stopChn != nil {
				close(stopChn)
			}
			return
		}
	}
}

func requireArbiters(engine *pbft.Pbft) bool {
	var peers [][]byte
	if IsFirstUpdateArbiter || len(nextTurnArbiters) == 0 ||
		uint64(spv.GetWorkingHeight())-spv.GetSpvHeight() > pbftEngine.GetBlockChain().Config().PreConnectOffset {
		peers = engine.GetCurrentProducers()
	} else {
		peers = nextTurnArbiters
	}
	count := getActivePeerCount(engine, peers)
	log.Info("getActivePeerCount", "count", count, "total", len(peers), "IsFirstUpdateArbiter", IsFirstUpdateArbiter, "retryCount", retryCount)
	if api.HasProducerMajorityCount(count, len(peers)) {
		if count < len(peers) && retryCount < MAX_RETRYCOUNT {
			retryCount++
			return false
		}

		list := arbiterManager.FilterArbiters(peers)
		if isNewStart {
			SendSelfToArbiters(engine, list)
		}
		isNewStart = false

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
	db, err := lvldb.NewLvlDB(config.BlockstoreFlagName)
	if err != nil {
		return err
	}

	path := config.DefaultConfigDir + "layer1_config.json"
	layer1, err := createChain(path, db, engine, accountPath, accountPassword)
	if err != nil {
		return errors.New(fmt.Sprintf("layer1 is create error:%s", err.Error()))
	}
	evm.Layer1ChainID = layer1.ChainID()
	path = config.DefaultConfigDir + "layer2_config.json"
	layer2, err := createChain(path, db, engine, accountPath, accountPassword)
	if layer1 == nil {
		return errors.New(fmt.Sprintf("layer2 is create error:%s", err.Error()))
	}
	evm.Layer2ChainID = layer2.ChainID()
	engine.GetBlockChain().Config().BridgeContractAddr = layer2.GetBridgeContract()

	MsgReleayer = relayer.NewRelayer([]relayer.RelayedChain{layer1, layer2})
	return nil
}

func relayerStart() error {
	stopChn = make(chan struct{})
	go MsgReleayer.Start(stopChn, errChn)

	select {
	case err := <-errChn:
		log.Error("failed to listen and serve", "error", err)
		close(stopChn)
		return err
	}
	return nil
}

func Stop() {
	if relayStarted {
		relayStarted = false
		errChn <- fmt.Errorf("chain bridge is shut down")
	}
	atomic.StoreInt32(&canStart, 1)
	wasArbiter = false
}

func createChain(path string, db blockstore.KeyValueReaderWriter, engine *pbft.Pbft, accountPath, accountPassword string) (*evm.EVMChain, error) {
	ethClient := evmclient.NewEVMClient(engine)
	if ethClient == nil {
		return nil, errors.New("create evm client error")
	}
	err := ethClient.Configurate(path, accountPath, accountPassword)
	if err != nil {
		return nil, err
	}
	ethCfg := ethClient.GetConfig()
	eventHandler := listener.NewETHEventHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Bridge), ethClient)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.Bridge, listener.OnEventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.Erc20Handler, listener.OnEventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.WEthHandler, listener.OnEventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.Erc721Handler, listener.OnEventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.GenericHandler, listener.OnEventHandler)
	evmListener := listener.NewEVMListener(ethClient, eventHandler, common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Bridge))
	messageHandler := voter.NewEVMMessageHandler(ethClient, common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Bridge))
	messageHandler.RegisterMessageHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Erc20Handler), voter.ERC20MessageHandler)
	messageHandler.RegisterMessageHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.WEthHandler), voter.ERC20MessageHandler)
	messageHandler.RegisterMessageHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Erc721Handler), voter.ERC721MessageHandler)
	var evmVoter *voter.EVMVoter
	if engine.GetBridgeArbiters() != nil {
		kp := engine.GetBridgeArbiters().(*secp256k1.Keypair)
		if kp != nil {
			evmVoter = voter.NewVoter(messageHandler, ethClient, kp)
		}
	}
	chain := evm.NewEVMChain(evmListener, evmVoter, db, ethCfg.SharedEVMConfig.Id,
		&ethCfg.SharedEVMConfig, arbiterManager, engine.GetBlockChain().Config().Layer2EFVoter)
	return chain, nil
}
