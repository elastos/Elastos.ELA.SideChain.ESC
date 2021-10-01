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

var (
	MsgReleayer *relayer.Relayer
	errChn chan error
	stopChn chan struct{}
	relayStarted bool
	canStart int32
	nextTurnArbiters [][]byte
	requireArbitersCount int
	arbiterManager *aribiters.ArbiterManager

	IsFirstUpdateArbiter bool
	api *API
)

func init() {
	errChn = make(chan error)
	relayStarted = false
	arbiterManager = aribiters.CreateArbiterManager()
	nextTurnArbiters = make([][]byte, 0)
	atomic.StoreInt32(&canStart, 1)
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

func Start(engine *pbft.Pbft, accountPath, accountPassword string) {
	log.Info("chain bridge start")
	if MsgReleayer != nil {
		log.Warn("chain bridge is started")
		return
	}
	err := initRelayer(engine, accountPath, accountPassword)
	if err != nil {
		log.Error("chain bridge started error", "error", err)
		return
	}
	chainID := uint8(engine.GetBlockChain().Config().ChainID.Uint64())
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case events.ETDirectPeersChanged:
			bridgelog.Info("ETDirectPeersChanged")
			if atomic.LoadInt32(&canStart) == 0 {
				bridgelog.Info("is starting, can't restart")
				return
			}
			self := engine.GetProducer()
			judgeSame := true
			arbiters := MsgReleayer.GetArbiters(chainID)
			if IsFirstUpdateArbiter &&  len(arbiters) > 0 {
				IsFirstUpdateArbiter = false
				judgeSame = false
			} else {
				IsFirstUpdateArbiter =  len(arbiters) == 0
			}

			producers := spv.GetNextTurnPeers()
			if judgeSame && isSameNexturnArbiter(producers) {
				bridgelog.Info("ETDirectPeersChanged is same current producers")
				return
			}
			atomic.StoreInt32(&canStart, 0)
			bridgelog.Info("IsFirstUpdateArbiter", "IsFirstUpdateArbiter", IsFirstUpdateArbiter, "producers count", len(producers))
			nextTurnArbiters = make([][]byte, len(producers))
			for i, p := range producers {
				nextTurnArbiters[i] = make([]byte, len(p))
				copy(nextTurnArbiters[i], p[:])
			}
			arbiterManager.Clear()
			arbiterManager.SetTotalCount(engine.GetTotalArbitersCount())
			isProducer := engine.IsProducer()
			if !isProducer {
				bridgelog.Info("self is not a producer, chain bridge is stop")
				Stop()
				return
			}
			bridgelog.Info("became a producer, collet arbiter")
			if IsFirstUpdateArbiter || nexturnHasSelf(self) {
				var pid peer.PID
				copy(pid[:], self)
				arbiterManager.AddArbiter(pid, engine.GetBridgeArbiters().PublicKeyBytes())//add self
			} else {
				bridgelog.Info("nexturn self is not a producer")
			}
			go onSelfIsArbiter(engine)
		case dpos.ETUpdateProducers:
			api.UpdateArbiters(0)
			isProducer := engine.IsProducer()
			if !isProducer {
				log.Info("self is not a producer, chain bridge is stop")
				Stop()
				return
			}
		case dpos_msg.ETOnArbiter:
			res, _ := hanleDArbiter(engine, e)
			if res {
				list := arbiterManager.GetArbiterList()
				log.Info("now arbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount)
				if len(list) == requireArbitersCount {
					if IsFirstUpdateArbiter {
						api.UpdateArbiters(0)
					} else {
						requireArbitersSignature(engine)
					}
				}
			}
		case dpos_msg.ETRequireArbiter:
			receivedRequireArbiter(engine, e)
		case dpos_msg.ETReqArbiterSig:
			receivedReqArbiterSignature(engine, e)
		case dpos_msg.ETFeedBackArbiterSig:
			handleFeedBackArbitersSig(engine, e)
		}
	})
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
	signCount := len(arbiterManager.GetSignatures())
	if api.HasProducerMajorityCount(signCount, arbiterManager.GetTotalCount()) {
		log.Info("handleFeedBackArbitersSig, collect over signatures", "signCount", signCount, "total", arbiterManager.GetTotalCount())
		return
	}
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
		log.Info("AddSignature failed", "error", err, "from", common.Bytes2Hex(producer))
		return
	}
	signatures := arbiterManager.GetSignatures()
	count := len(signatures)
	log.Info("handleFeedBackArbitersSig", "count", count, "producer", common.Bytes2Hex(producer), "engine.GetTotalArbitersCount()", engine.GetTotalArbitersCount())

	//if hasProducerMajorityCount(count, engine.GetTotalArbitersCount()) {
	//	//TODO will update by consensus update
	//	list := arbiterManager.GetArbiterList()
	//	total := arbiterManager.GetTotalCount()
	//	sigs := make([][]byte, 0)
	//	for _, sig := range signatures {
	//		sigs = append(sigs, sig)
	//	}
	//	err := MsgReleayer.UpdateArbiters(list, total, sigs, 0)
	//	if err != nil {
	//		log.Error("Update Arbiter error", "error", err)
	//	}
	//}
}

func receivedReqArbiterSignature(engine *pbft.Pbft, e *events.Event) {
	m, ok := e.Data.(*dpos_msg.RequireArbitersSignature)
	if !ok {
		return
	}

	if engine.IsProducerByAccount(m.PID[:]) == false {
		log.Warn("[receivedReqArbiterSignature] target is not a producer", "pid", common.Bytes2Hex(m.PID[:]))
		return
	}
	if int(m.ArbiterCount) != len(arbiterManager.GetArbiterList()) {
		log.Warn("[receivedReqArbiterSignature] ArbiterCount is not same", "m.arbiterCount", m.ArbiterCount, "arbiterList", len(arbiterManager.GetArbiterList()))
		return
	}
	selfProducer := engine.GetProducer()
	msg := &dpos_msg.FeedBackArbitersSignature{}
	msg.Producer = selfProducer

	kp := engine.GetBridgeArbiters().(*secp256k1.Keypair)
	privateKey := kp.PrivateKey()
	hash, err := arbiterManager.HashArbiterList()
	if err != nil {
		log.Error("receivedReqArbiterSignature HashArbiterList failed", "error", err)
	}
	sign, err := crypto.Sign(accounts.TextHash(hash.Bytes()), privateKey)
	if err != nil {
		log.Warn("sign arbiters error", "error", err)
		return
	}
	msg.Signature = sign
	engine.SendMsgToPeer(msg, m.PID)
	if !arbiterManager.HasSignature(selfProducer) {
		log.Info("add self signature")
		go events.Notify(dpos_msg.ETFeedBackArbiterSig, msg)//add self signature
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
					return
				}
				arbiterCount := len(arbiterManager.GetArbiterList())
				selfProducer := engine.GetProducer()
				msg := &dpos_msg.RequireArbitersSignature{
					ArbiterCount: uint8(arbiterCount),
				}
				copy(msg.PID[:], selfProducer)
				peers := arbiterManager.FilterSignatures(engine.GetCurrentProducers())
				log.Info("to collected signatures", "len", len(peers))
				engine.BroadMessageToPeers(msg, peers)
			}
		}
	}()
}

func receivedRequireArbiter(engine *pbft.Pbft, e *events.Event)  {
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
	data := GetNextProducersData()
	err = elaCrypto.Verify(*pubKey, data, m.ArbitersSignature)
	if err != nil {
		log.Error("hanleDArbiter producers verify error", "pid", common.Bytes2Hex(m.PID[:]), "data", common.Bytes2Hex(data))
		return false, err
	}

	signerPublicKey, err := engine.DecryptArbiter(m.Cipher)
	if err != nil {
		log.Error("hanleDArbiter decrypt address cipher error", "error:", err, "self", common.Bytes2Hex(selfSigner), "cipher", common.Bytes2Hex(m.Cipher))
		return false, err
	}
	err = arbiterManager.AddArbiter(m.PID, signerPublicKey)
	if err != nil {
		log.Error("add arbiter error", "error", err)
		return false, nil
	}
	//escssaPUb, err := crypto.DecompressPubkey(signerPublicKey)
	//if err != nil {
	//	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey), "err", err)
	//	return true, nil
	//}
	//log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey),  "addr", crypto.PubkeyToAddress(*escssaPUb), "err", err)
	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey))
	return true, nil
}

func onSelfIsArbiter(engine *pbft.Pbft) {
	for{
		select {
		case <-time.After(time.Second * 2):
			list := arbiterManager.GetArbiterList()
			log.Info("GetArbiterList", "count", len(list), "requireArbitersCount", requireArbitersCount)
			if len(list) == requireArbitersCount && requireArbitersCount > 0 {
				return
			}
			if requireArbiters(engine) {
				atomic.StoreInt32(&canStart, 1)
				if !relayStarted {
					relayStarted = true
					err := relayerStart()
					log.Error("bridge relay error", "error", err)
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
	if IsFirstUpdateArbiter {
		peers = engine.GetCurrentProducers()
	} else {
		peers = nextTurnArbiters
	}
	requireArbitersCount = len(peers)
	count := getActivePeerCount(engine, peers)
	log.Info("getActivePeerCount", "count", count, "total", len(peers))
	if count >= len(peers) {
		selfProducer := engine.GetProducer()
		msg := &dpos_msg.RequireArbiter{}
		copy(msg.PID[:], selfProducer)

		list := arbiterManager.FilterArbiters(peers)
		log.Info("request arbiters", "len", len(list))
		engine.BroadMessageToPeers(msg, list)
		return true
	}
	return false
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
	producersData := GetNextProducersData()
	cipher, err := elaCrypto.Encrypt(publicKey, signer)
	msg := &dpos_msg.DArbiter{
		Timestamp: time.Now(),
		Cipher: cipher,
		ArbitersSignature: engine.SignData(producersData),
	}
	copy(msg.PID[:], selfProducer[:])
	copy(msg.Encode[:], pid[:])
	msg.Signature = engine.SignData(msg.Data())

	engine.SendMsgToPeer(msg, pid)
}

func GetNextProducersData() []byte {
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
					count ++
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

func Stop()  {
	if relayStarted {
		relayStarted = false
		errChn <- fmt.Errorf("chain bridge is shut down")
	}
	atomic.StoreInt32(&canStart, 1)
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
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.Bridge, listener.Erc20EventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.Erc20Handler, listener.Erc20EventHandler)
	eventHandler.RegisterEventHandler(ethCfg.SharedEVMConfig.Opts.WEthHandler, listener.Erc20EventHandler)
	evmListener := listener.NewEVMListener(ethClient, eventHandler, common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Bridge))
	messageHandler := voter.NewEVMMessageHandler(ethClient, common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Bridge))
	messageHandler.RegisterMessageHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.Erc20Handler), voter.ERC20MessageHandler)
	messageHandler.RegisterMessageHandler(common.HexToAddress(ethCfg.SharedEVMConfig.Opts.WEthHandler), voter.ERC20MessageHandler)

	kp := engine.GetBridgeArbiters().(*secp256k1.Keypair)
	if kp == nil {
		return nil, errors.New("GetBridgeArbiters is nil")
	}
	voter := voter.NewVoter(messageHandler, ethClient, kp)

	chain := evm.NewEVMChain(evmListener, voter, db, ethCfg.SharedEVMConfig.Id, &ethCfg.SharedEVMConfig, arbiterManager)
	return chain, nil
}