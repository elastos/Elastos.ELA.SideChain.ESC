package chainbridge_core

import (
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/listener"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/lvldb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"os"
	"os/signal"
	"syscall"
)

var MsgReleayer *relayer.Relayer

func Run(engine *pbft.Pbft, accountPassword string) error {
	errChn := make(chan error)
	stopChn := make(chan struct{})
	db, err := lvldb.NewLvlDB(config.BlockstoreFlagName)
	if err != nil {
		panic(err)
	}

	path := config.DefaultConfigDir + "layer1_config.json"
	layer1 := createChain(path, db, nil, accountPassword)
	evm.Layer1ChainID = layer1.ChainID()
	path = config.DefaultConfigDir + "layer2_config.json"
	layer2 := createChain(path, db, engine, accountPassword)
	evm.Layer2ChainID = layer2.ChainID()

	MsgReleayer = relayer.NewRelayer([]relayer.RelayedChain{layer1, layer2})
	go MsgReleayer.Start(stopChn, errChn)

	sysErr := make(chan os.Signal, 1)
	signal.Notify(sysErr,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGHUP,
		syscall.SIGQUIT)

	select {
	case err := <-errChn:
		log.Error("failed to listen and serve", "error", err)
		close(stopChn)
		return err
	case sig := <-sysErr:
		log.Info(fmt.Sprintf("terminating got [%v] signal", sig))
		return nil
	}
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
	voter := voter.NewVoter(messageHandler, ethClient)

	chain := evm.NewEVMChain(evmListener, voter, db, ethCfg.SharedEVMConfig.Id, &ethCfg.SharedEVMConfig)
	return chain
}