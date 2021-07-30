package chainbridge_core

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/listener"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/lvldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"

	"github.com/elastos/Elastos.ELA/account"
)

var MsgReleayer *relayer.Relayer
var errChn chan error
var stopChn chan struct{}
var relayStarted bool

func init() {
	errChn = make(chan error)
	relayStarted = false
}

func Start(engine *pbft.Pbft, accountPassword, arbiterKeystore, arbiterPassword string) {
	if MsgReleayer != nil {
		log.Warn("chain bridge is started")
		return
	}
	events.Subscribe(func(e *events.Event) {
		pbk := engine.GetProducer()
		switch e.Type {
		case events.ETDirectPeersChanged:
			peers := e.Data.([]peer.PID)
			isProducer := false
			for _, p := range peers {
				if bytes.Equal(pbk, p[:]) {
					isProducer = true
					if MsgReleayer == nil {
						initRelayer(engine, accountPassword, arbiterKeystore, arbiterPassword)
					}
					go func() {
						if !relayStarted {
							relayStarted = true
							err := relayerStart()
							log.Error("bridge relay error", "error", err)
						}
					}()
					break
				}
			}
			if !isProducer {
				relayStarted = false
				errChn <- fmt.Errorf("chain bridge is not a super node")
			}
		}
	})
}

func initRelayer(engine *pbft.Pbft, accountPassword, arbiterKeystore, arbiterPassword string) {
	if MsgReleayer != nil {
		return
	}
	db, err := lvldb.NewLvlDB(config.BlockstoreFlagName)
	if err != nil {
		panic(err)
	}

	path := config.DefaultConfigDir + "layer1_config.json"
	layer1 := createChain(path, db, engine, accountPassword, arbiterKeystore, arbiterPassword)
	evm.Layer1ChainID = layer1.ChainID()
	path = config.DefaultConfigDir + "layer2_config.json"
	layer2 := createChain(path, db, engine, accountPassword, arbiterKeystore, arbiterPassword)
	evm.Layer2ChainID = layer2.ChainID()

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
		log.Info(fmt.Sprintf("terminating got [%v] signal", sig))
		return nil
	}
	return nil
}

func createChain(path string, db blockstore.KeyValueReaderWriter, engine *pbft.Pbft, accountPassword, arbiterKeystore, arbiterPassword string) *evm.EVMChain {
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
	kp, err := GetArbiterAccount(arbiterKeystore, []byte(arbiterPassword))
	if err != nil {
		panic("GetArbiterAccount error" + err.Error())
	}
	voter := voter.NewVoter(messageHandler, ethClient, kp)

	chain := evm.NewEVMChain(evmListener, voter, db, ethCfg.SharedEVMConfig.Id, &ethCfg.SharedEVMConfig)
	return chain
}

func GetArbiterAccount(keystorePath string, password []byte) (*secp256k1.Keypair, error) {
	client, err := account.Open(keystorePath, password)
	if err != nil {
		return nil, err
	}
	return secp256k1.NewKeypairFromPrivateKey(client.GetMainAccount().PrivateKey)
}