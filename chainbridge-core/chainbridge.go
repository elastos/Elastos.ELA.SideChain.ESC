package chainbridge_core

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
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
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"

	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
)

var (
	MsgReleayer *relayer.Relayer
	errChn chan error
	stopChn chan struct{}
	relayStarted bool
	canStart int32
	broadProducers [][]byte
	arbiterManager *aribiters.ArbiterManager
)

func init() {
	errChn = make(chan error)
	relayStarted = false
	arbiterManager = aribiters.CreateArbiterManager()
	atomic.StoreInt32(&canStart, 1)
}

func APIs(engine *pbft.Pbft) []rpc.API {
	return []rpc.API{{
		Namespace: "bridge",
		Version:   "1.0",
		Service:   &API{engine},
		Public:    true,
	}}
}

func Start(engine *pbft.Pbft, accountPassword string) {
	log.Info("chain bridge start")
	if MsgReleayer != nil {
		log.Warn("chain bridge is started")
		return
	}
	initRelayer(engine, accountPassword)
	arbiterManager.SetTotalCount(engine.GetTotalArbitersCount())
	arbiterManager.AddArbiter(engine.GetBridgeArbiters().PublicKeyBytes())//add self
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case events.ETDirectPeersChanged:
			if atomic.LoadInt32(&canStart) == 0 {
				return
			}
			atomic.StoreInt32(&canStart, 0)
			isProducer := engine.IsProducer()
			if isProducer {
				go onSelfIsArbiter(engine)
			}
			if !isProducer {
				relayStarted = false
				errChn <- fmt.Errorf("chain bridge is not a super node")
				return
			}
		case dpos_msg.ETOnArbiter:
			if hanleDArbiter(engine, e) {
				list := arbiterManager.GetArbiterList()
				if engine.HasProducerMajorityCount(len(list)) {
					go func() {
						time.Sleep(2 * time.Second)
						total := arbiterManager.GetTotalCount()
						err := MsgReleayer.UpdateArbiters(list, total, 0)
						if err != nil {
							log.Error("Update Arbiter error", "error", err)
						}
					}()
				}
			}
		case dpos_msg.ETRequireArbiter:
			receivedRequireArbiter(engine, e)
		}
	})
}

func receivedRequireArbiter(engine *pbft.Pbft, e *events.Event)  {
	m, ok := e.Data.(*dpos_msg.RequireArbiter)
	if !ok {
		return
	}
	SendAriberToPeer(engine, m.PID)
}

func hanleDArbiter(engine *pbft.Pbft, e *events.Event) bool {
	// Verify signature of the message.
	m, ok := e.Data.(*dpos_msg.DArbiter)
	if !ok {
		return false
	}
	selfSigner := engine.GetProducer()

	if bytes.Equal(selfSigner, m.Encode[:]) == false {
		log.Info("hanleDArbiter is not self DArbiter", "selfSigner", common.Bytes2Hex(selfSigner), "encode", common.Bytes2Hex(m.Encode[:]))
		return false
	}
	pubKey, err := elaCrypto.DecodePoint(m.PID[:])
	if err != nil {
		log.Error("hanleDArbiter invalid public key")
		return false
	}
	if !engine.IsProducerByAccount(m.PID[:]) {
		log.Error("hanleDArbiter is not a producer")
		return false
	}
	err = elaCrypto.Verify(*pubKey, m.Data(), m.Signature)
	if err != nil {
		log.Error("hanleDArbiter invalid signature", m.Signature)
		return false
	}
	signerPublicKey, err := engine.DecryptArbiter(m.Cipher)
	if err != nil {
		log.Error("hanleDArbiter decrypt address cipher error", "error:", err, "self", common.Bytes2Hex(selfSigner), "cipher", common.Bytes2Hex(m.Cipher))
		return false
	}
	err = arbiterManager.AddArbiter(signerPublicKey)
	if err != nil {
		log.Error("add arbiter error", "error", err)
		return false
	}
	escssaPUb, err := crypto.DecompressPubkey(signerPublicKey)
	if err != nil {
		log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey), "err", err)
		return true
	}
	log.Info("hanleDArbiter", "signerPublicKey:", common.Bytes2Hex(signerPublicKey),  "addr", crypto.PubkeyToAddress(*escssaPUb), "err", err)
	return true
}

func onSelfIsArbiter(engine *pbft.Pbft) {
	out:
	for{
		select {
		case <-time.After(time.Second * 2):
			if requireArbiters(engine) {
				atomic.StoreInt32(&canStart, 1)
				if !relayStarted {
					relayStarted = true
					err := relayerStart()
					log.Error("bridge relay error", "error", err)
				} else {
					log.Info("bridge is starting relay")
				}
				break out
			}
		case err := <-errChn:
			log.Error("failed to listen and serve", "error", err)
			close(stopChn)
		}
	}
}

func requireArbiters(engine *pbft.Pbft) bool {
	count := getActivePeerCount(engine)
	log.Info("getActivePeerCount", "count", count)
	if engine.HasProducerMajorityCount(count) {
		selfProducer := engine.GetProducer()
		msg := &dpos_msg.RequireArbiter{}
		copy(msg.PID[:], selfProducer)
		engine.BroadMessage(msg)
		return true
	}
	return false
}

func SendAriberToPeer(engine *pbft.Pbft, pid peer.PID) {
	if engine.IsProducerByAccount(pid[:]) == false {
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
		Cipher: cipher,
	}
	copy(msg.PID[:], selfProducer[:])
	copy(msg.Encode[:], pid[:])
	msg.Signature = engine.SignData(msg.Data())

	engine.SendMsgToPeer(msg, pid)
}

func getActivePeerCount(engine *pbft.Pbft) int {
	peers := engine.GetAtbiterPeersInfo()
	count := 0
	for _, peer := range peers {
		if peer.ConnState == "2WayConnection" {
			count ++
		}
	}
	count += 1 //add self node
	return count
}

func initRelayer(engine *pbft.Pbft, accountPassword string) {
	if MsgReleayer != nil {
		return
	}
	db, err := lvldb.NewLvlDB(config.BlockstoreFlagName)
	if err != nil {
		panic(err)
	}

	path := config.DefaultConfigDir + "layer1_config.json"
	layer1 := createChain(path, db, engine, accountPassword)
	evm.Layer1ChainID = layer1.ChainID()
	path = config.DefaultConfigDir + "layer2_config.json"
	layer2 := createChain(path, db, engine, accountPassword)
	evm.Layer2ChainID = layer2.ChainID()
	engine.GetBlockChain().Config().BridgeContractAddr = layer2.GetBridgeContract()

	MsgReleayer = relayer.NewRelayer([]relayer.RelayedChain{layer1, layer2})
}

func relayerStart() error {
	stopChn = make(chan struct{})
	go MsgReleayer.Start(stopChn, errChn)

	sysErr := make(chan os.Signal, 1)
	signal.Notify(sysErr,
		syscall.SIGTERM,
		syscall.SIGINT)

	select {
	case err := <-errChn:
		log.Error("failed to listen and serve", "error", err)
		close(stopChn)
		return err
	case sig := <-sysErr:
		log.Error(fmt.Sprintf("terminating got [%v] signal", sig))
		return nil
	}
	return nil
}

func createChain(path string, db blockstore.KeyValueReaderWriter, engine *pbft.Pbft, accountPassword string) *evm.EVMChain {
	ethClient := evmclient.NewEVMClient(engine)
	err := ethClient.Configurate(path, accountPassword)
	if err != nil {
		panic(err)
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
		panic("GetBridgeArbiters is nil")
	}
	voter := voter.NewVoter(messageHandler, ethClient, kp)

	chain := evm.NewEVMChain(evmListener, voter, db, ethCfg.SharedEVMConfig.Id, &ethCfg.SharedEVMConfig)
	return chain
}