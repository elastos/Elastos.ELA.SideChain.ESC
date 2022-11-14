// Copyright 2014 The Elastos.ELA.SideChain.ESC Authors
// This file is part of the Elastos.ELA.SideChain.ESC library.
//
// The Elastos.ELA.SideChain.ESC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Elastos.ELA.SideChain.ESC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Elastos.ELA.SideChain.ESC library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi/bind"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/blocksigner"
	chainbridge_core "github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/clique"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/ethash"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/bloombits"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/events"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/eth/downloader"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/eth/filters"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/eth/gasprice"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/event"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/internal/ethapi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/miner"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/node"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/p2p"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/p2p/enr"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"

	_interface "github.com/elastos/Elastos.ELA.SPV/interface"

	"github.com/elastos/Elastos.ELA/core/types/payload"
	msg2 "github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	elapeer "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	eevents "github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/p2p/msg"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	APIs() []rpc.API
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
	SetContractBackend(bind.ContractBackend)
}

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	config *Config

	// Channel for shutting down the service
	shutdownChan chan bool
	stopChan     chan bool

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner     *miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
}

func (s *Ethereum) SetEngine(engine consensus.Engine) {
	if s.engine == engine {
		return
	}
	isMining := false
	log.Info("-----------------[SWITCH ENGINE TO DPOS!]-----------------")
	pbftEngine := engine.(*pbft.Pbft)
	if s.miner != nil {
		isMining = s.miner.Mining()
		s.StopMining()
	}
	s.engine.Close()
	s.engine = engine
	s.blockchain.SetEngine(engine)
	if s.miner != nil {
		s.miner.SetEngine(engine)
		if pbftEngine != nil && isMining {
			s.miner.Start(s.etherbase)
		}
	}
}

func (s *Ethereum) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// SetClient sets a rpc client which connecting to our local node.
func (s *Ethereum) SetContractBackend(backend bind.ContractBackend) {
	// Pass the rpc client to les server if it is enabled.
	if s.lesServer != nil {
		s.lesServer.SetContractBackend(backend)
	}
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(ctx *node.ServiceContext, config *Config, node *node.Node) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(common.Big0) <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", DefaultConfig.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(DefaultConfig.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		config.TrieCleanCache += config.TrieDirtyCache
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Assemble the Ethereum object
	chainDb, err := ctx.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlockWithOverride(chainDb, config.Genesis, config.OverrideIstanbul)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	chainConfig.PassBalance = config.PassBalance
	chainConfig.BlackContractAddr = config.BlackContractAddr
	chainConfig.EvilSignersJournalDir = config.EvilSignersJournalDir

	if chainConfig.Pbft != nil {
		if chainConfig.Pbft.DPoSV2StartHeight <= 0 { //if config is set, use config value
			chainConfig.Pbft.DPoSV2StartHeight = config.DPoSV2StartHeight
		}
		msg2.SetPayloadVersion(msg2.DPoSV2Version)
		chainConfig.Pbft.NodeVersion = node.Config().Version
	}

	if len(chainConfig.PbftKeyStore) > 0 {
		config.PbftKeyStore = chainConfig.PbftKeyStore
	} else {
		chainConfig.PbftKeyStore = config.PbftKeyStore
	}

	if chainConfig.PreConnectOffset > 0 {
		config.PreConnectOffset = chainConfig.PreConnectOffset
	} else {
		chainConfig.PreConnectOffset = config.PreConnectOffset
	}

	if len(chainConfig.PbftKeyStorePassWord) > 0 {
		config.PbftKeyStorePassWord = chainConfig.PbftKeyStorePassWord
	} else {
		chainConfig.PbftKeyStorePassWord = config.PbftKeyStorePassWord
	}

	if chainConfig.Pbft != nil {
		if len(chainConfig.Pbft.IPAddress) > 0 {
			config.PbftIPAddress = chainConfig.Pbft.IPAddress
		} else {
			chainConfig.Pbft.IPAddress = config.PbftIPAddress
		}
		if chainConfig.Pbft.DPoSPort > 0 {
			config.PbftDPosPort = chainConfig.Pbft.DPoSPort
		} else {
			chainConfig.Pbft.DPoSPort = config.PbftDPosPort
		}
	}

	if config.DynamicArbiterHeight > 0 {
		chainConfig.DynamicArbiterHeight = config.DynamicArbiterHeight
	}
	chainConfig.FrozeAccountList = config.FrozenAccountList
	chainConfig.BridgeContractAddr = config.ArbiterListContract
	chainConfig.PledgeBillContract = config.PledgedBillContract
	log.Info("Initialised chain configuration", "config", chainConfig, "config.Miner.Etherbase", config.Miner.Etherbase)

	eth := &Ethereum{
		config:         config,
		chainDb:        chainDb,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, chainConfig, &config.Ethash, config.Miner.Notify, config.Miner.Noverify, chainDb),
		shutdownChan:   make(chan bool),
		stopChan:       make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.Miner.GasPrice,
		etherbase:      config.Miner.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks, params.BloomConfirms),
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "versions", ProtocolVersions, "network", config.NetworkId, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
		}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
		}
	)
	engine := pbft.New(chainConfig, ctx.ResolvePath(""))
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, chainConfig, eth.engine, engine, vmConfig, eth.shouldPreserve)
	if err != nil {
		return nil, err
	}
	eth.SetEngine(eth.blockchain.Engine())
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, chainConfig, eth.blockchain)

	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit
	checkpoint := config.Checkpoint
	if checkpoint == nil {
		checkpoint = params.TrustedCheckpoints[genesisHash]
	}
	if eth.protocolManager, err = NewProtocolManager(chainConfig, checkpoint, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.blockchain.Engine(), eth.blockchain, chainDb, cacheLimit, config.Whitelist, node.Stop); err != nil {
		return nil, err
	}
	eth.miner = miner.New(eth, &config.Miner, chainConfig, eth.EventMux(), eth.blockchain.Engine(), eth.isLocalBlock)
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))

	eth.APIBackend = &EthAPIBackend{ctx.ExtRPCEnabled(), eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	SubscriptEvent(eth, engine)

	engine.IsCurrent = func() bool {
		progress := eth.Downloader().Progress()
		curHeight := eth.blockchain.CurrentHeader().Number.Uint64()
		if engine.IsBadBlock(progress.HighestBlock) && curHeight+1 == progress.HighestBlock {
			log.Warn(
				"Highest block is bad block, no sync", "currentBlock", progress.CurrentBlock, "highestBlock", progress.HighestBlock)
			return true
		}
		return progress.CurrentBlock >= progress.HighestBlock
	}
	engine.StartMine = func() {
		if eth.IsMining() {
			eth.StopMining()
		}
		eth.StartMining(0)
	}

	engine.OnDuty = func() {
		log.Info("change view broad on duty event")
		eth.eventMux.Post(events.OnDutyEvent{})
	}
	var issync int32
	engine.OnInsertChainError = func(id elapeer.PID, block *types.Block, err error) {
		newHeight := block.NumberU64()
		if atomic.LoadInt32(&issync) == 1 {
			return
		}
		if err != consensus.ErrFutureBlock {
			atomic.StoreInt32(&issync, 1)
			eth.protocolManager.BroadcastBlock(block, true)
			initTime := time.Now()
			go func() {
				defer atomic.StoreInt32(&issync, 0)
				for {
					nowBlock := eth.blockchain.CurrentBlock()
					if newHeight <= nowBlock.NumberU64() || time.Now().Sub(initTime) > 50*time.Second {
						break
					}
					peer := eth.protocolManager.peers.BestPeer()
					if peer == nil {
						return
					}
					localTd := eth.blockchain.GetTd(nowBlock.Hash(), nowBlock.NumberU64())
					if localTd.Cmp(peer.td) >= 0 {
						log.Info("remove not best peer")
						eth.protocolManager.removePeer(peer.id)
						peer = eth.protocolManager.peers.BestPeer()
					}

					if peer != nil && localTd.Cmp(peer.td) < 0 {
						go eth.protocolManager.synchronise(peer)
						log.Info("synchronise from ", "peer", peer.id, "td", peer.td.Uint64(), "localTd", localTd.Uint64())
					}
					time.Sleep(5 * time.Second)
				}
			}()

		}
	}

	engine.SetBlockChain(eth.blockchain)
	spv.PbftEngine = engine
	dposAccount, err := dpos.GetDposAccount(chainConfig.PbftKeyStore, []byte(chainConfig.PbftKeyStorePassWord))
	if err != nil {
		return eth, nil
	}
	if chainConfig.Pbft != nil {
		routeCfg := dpos.Config{
			PID:        dposAccount.PublicKeyBytes(),
			Addr:       fmt.Sprintf("%s:%d", chainConfig.Pbft.IPAddress, chainConfig.Pbft.DPoSPort),
			TimeSource: engine.GetTimeSource(),
			Sign:       dposAccount.Sign,
			IsCurrent: func() bool {
				return engine.IsCurrent()
			},
			RelayAddr: func(iv *msg.InvVect, data interface{}) {
				inv := msg.NewInv()
				inv.AddInvVect(iv)

				invBuf := new(bytes.Buffer)
				inv.Serialize(invBuf)
				eth.protocolManager.BroadcastDAddr(&dpos.ElaMsg{
					Type: dpos.Inv,
					Msg:  invBuf.Bytes(),
				})
			},
			OnCipherAddr: func(pid elapeer.PID, cipher []byte) {
				addr, err := dposAccount.DecryptAddr(cipher)
				if err != nil {
					log.Error("decrypt address cipher error", "error:", err)
					return
				}
				log.Info("AddDirectLinkPeer", "address:", addr)
				engine.AddDirectLinkPeer(pid, addr)
			},
		}
		routes := dpos.New(&routeCfg)
		go routes.Start()
		go engine.StartServer()

		height := big.NewInt(0).Add(eth.blockchain.CurrentHeader().Number, big.NewInt(1))
		if eth.blockchain.Engine() != engine && eth.blockchain.Config().IsPBFTFork(height) {
			log.Info("before change engine")
			eth.SetEngine(engine)
		}
	}

	return eth, nil
}

func InitCurrentProducers(engine *pbft.Pbft, config *params.ChainConfig, currentBlock *types.Block) {
	number := currentBlock.NumberU64()
	log.Info("InitCurrentProducers", "nonce", currentBlock.Nonce(), "height", number)
	if currentBlock == nil {
		return
	}
	if !config.IsPBFTFork(currentBlock.Number()) {
		fmt.Println(" >>> is not pbft engine")
		return
	}
	mode := spv.GetCurrentConsensusMode()
	spvHeight := currentBlock.Nonce()
	selfDutyIndex := engine.GetSelfDutyIndex()
	if spvHeight <= 0 && mode == _interface.DPOS && len(engine.GetCurrentProducers()) > 0 {
		res := engine.OnInsertBlock(currentBlock)
		blocksigner.SelfIsProducer = engine.IsProducer()
		log.Info("blocksigner.SelfIsProducer", "", blocksigner.SelfIsProducer)
		if res {
			eevents.Notify(dpos.ETUpdateProducers, selfDutyIndex)
		}
		return
	}
	bestSpvHeight := spv.GetSpvHeight()
	log.Info("", " >>> bestSpvHeight ", bestSpvHeight)
	if bestSpvHeight > spvHeight {
		spvHeight = bestSpvHeight
	}
	producers, totalProducers, err := spv.GetProducers(spvHeight)
	if err != nil {
		log.Info("GetProducers error", "error", err, "spvHeight", spvHeight)
		return
	}
	if engine.IsCurrentProducers(producers) {
		log.Info("is current producers, do not need update", "totalProducers", totalProducers)
		return
	}
	blocksigner.SelfIsProducer = false
	log.Info("UpdateCurrentProducers ", "producer length", len(producers), "spvHeight", spvHeight)
	engine.UpdateCurrentProducers(producers, totalProducers, spvHeight)
	spv.InitNextTurnDposInfo()
	go func() {
		if engine.AnnounceDAddr() {
			if engine.IsProducer() {
				blocksigner.SelfIsProducer = true
				eevents.Notify(dpos.ETUpdateProducers, selfDutyIndex)
				engine.Recover()
			}
		}
	}()
}

func SubscriptEvent(eth *Ethereum, engine consensus.Engine) {
	//dynamic switch dpos engine
	if !eth.blockchain.Config().IsPBFTFork(eth.blockchain.CurrentHeader().Number) {
		var engineChan = make(chan core.EngineChangeEvent)
		engineSub := eth.blockchain.SubscribeChangeEnginesEvent(engineChan)
		go func() {
			defer engineSub.Unsubscribe()
			for {
				select {
				case <-engineChan:
					eth.SetEngine(engine)
					return
				case <-engineSub.Err():
					return
				}
			}
		}()
	}
	var blockEvent = make(chan core.ChainEvent)
	chainSub := eth.blockchain.SubscribeChainEvent(blockEvent)
	initProducersSub := eth.EventMux().Subscribe(events.InitCurrentProducers{})
	go func() {
		defer func() {
			chainSub.Unsubscribe()
			initProducersSub.Unsubscribe()
		}()
		for {
			select {
			case b := <-blockEvent:
				if eth.blockchain.Config().IsPBFTFork(b.Block.Number()) {
					pbftEngine := engine.(*pbft.Pbft)
					pbftEngine.AccessFutureBlock(b.Block)
					selfDutyIndex := pbftEngine.GetSelfDutyIndex()
					res := pbftEngine.OnInsertBlock(b.Block)
					blocksigner.SelfIsProducer = pbftEngine.IsProducer()
					if res {
						eevents.Notify(dpos.ETUpdateProducers, selfDutyIndex)
					}
				}
			case <-initProducersSub.Chan():
				pbftEngine := engine.(*pbft.Pbft)
				currentHeader := eth.blockchain.CurrentBlock()
				InitCurrentProducers(pbftEngine, eth.blockchain.Config(), currentHeader)
			case <-eth.stopChan:
				return
			}
		}
	}()

}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<32 | params.VersionMinor<<16 | params.VersionPatch<<8 | params.VersionCross),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service
func CreateConsensusEngine(ctx *node.ServiceContext, chainConfig *params.ChainConfig, config *ethash.Config, notify []string, noverify bool, db ethdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}
	// Otherwise assume proof-of-work
	switch config.PowMode {
	case ethash.ModeFake:
		log.Warn("Ethash used in fake mode")
		return ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		return ethash.NewTester(nil, noverify)
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		return ethash.NewShared()
	default:
		engine := ethash.New(ethash.Config{
			CacheDir:       ctx.ResolvePath(config.CacheDir),
			CachesInMem:    config.CachesInMem,
			CachesOnDisk:   config.CachesOnDisk,
			DatasetDir:     config.DatasetDir,
			DatasetsInMem:  config.DatasetsInMem,
			DatasetsOnDisk: config.DatasetsOnDisk,
		}, notify, noverify)
		engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the les server
	if s.lesServer != nil {
		apis = append(apis, s.lesServer.APIs()...)
	}
	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append any APIs exposed explicitly by the les server
	if s.lesServer != nil {
		apis = append(apis, s.lesServer.APIs()...)
	}

	apis = append(apis, chainbridge_core.APIs(s.BlockChain().GetDposEngine().(*pbft.Pbft))...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if len(s.config.PbftMinerAddress) > 0 && s.engine == s.blockchain.GetDposEngine() {
		etherbase = common.HexToAddress(s.config.PbftMinerAddress)
		s.lock.Lock()
		s.etherbase = etherbase
		s.lock.Unlock()

		log.Info("Etherbase configured by user", "address", etherbase.String())
		return etherbase, nil
	}

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}

	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase.String())
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// isLocalBlock checks whether the specified block is mined
// by local miner accounts.
//
// We regard two types of accounts as local miner account: etherbase
// and accounts specified via `txpool.locals` flag.
func (s *Ethereum) isLocalBlock(block *types.Block) bool {
	author, err := s.engine.Author(block.Header())
	if err != nil {
		log.Warn("Failed to retrieve block author", "number", block.NumberU64(), "hash", block.Hash(), "err", err)
		return false
	}
	// Check whether the given address is etherbase.
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()
	if author == etherbase {
		return true
	}
	// Check whether the given address is specified by `txpool.local`
	// CLI flag.
	for _, account := range s.config.TxPool.Locals {
		if account == author {
			return true
		}
	}
	return false
}

// shouldPreserve checks whether we should preserve the given block
// during the chain reorg depending on whether the author of block
// is a local account.
func (s *Ethereum) shouldPreserve(block *types.Block) bool {
	// The reason we need to disable the self-reorg preserving for clique
	// is it can be probable to introduce a deadlock.
	//
	// e.g. If there are 7 available signers
	//
	// r1   A
	// r2     B
	// r3       C
	// r4         D
	// r5   A      [X] F G
	// r6    [X]
	//
	// In the round5, the inturn signer E is offline, so the worst case
	// is A, F and G sign the block of round5 and reject the block of opponents
	// and in the round6, the last available signer B is offline, the whole
	// network is stuck.
	if _, ok := s.engine.(*clique.Clique); ok {
		return false
	}
	if _, ok := s.engine.(*pbft.Pbft); ok {
		if oldBlock := s.blockchain.GetBlockByNumber(block.NumberU64()); oldBlock != nil {
			if oldBlock.Hash() == block.Hash() {
				return false
			}
			log.Info("detected chain fork", "old block", oldBlock.Hash().String(), "new block", block.Hash().String(),
				"oldBlock time", oldBlock.Time(), "newBlock time", block.Time())
			var oldConfirm payload.Confirm
			oldErr := oldConfirm.Deserialize(bytes.NewReader(oldBlock.Extra()))
			if oldErr != nil {
				log.Error("old Block is error confirm")
			}
			var newConfirm payload.Confirm
			newErr := newConfirm.Deserialize(bytes.NewReader(block.Extra()))
			if newErr != nil {
				log.Error("new Block is error confirm")
				return false
			}

			oldNonce := oldBlock.Nonce()
			newNonce := block.Nonce()
			log.Info("detected chain fork", "oldNonce", oldNonce, "newNonce", newNonce, "SignersCount", s.engine.SignersCount())
			if oldNonce > 0 && newNonce > 0 && oldNonce != newNonce {
				return newNonce > oldNonce
			}

			oldViewOffset := oldConfirm.Proposal.ViewOffset
			newViewOffset := newConfirm.Proposal.ViewOffset
			log.Info("detected chain fork", "oldViewOffset", oldViewOffset, "newViewOffset", newViewOffset, "SignersCount", s.engine.SignersCount())
			//return newViewOffset > oldViewOffset
		}
	}
	return s.isLocalBlock(block)
}

// SetEtherbase sets the mining reward address.
func (s *Ethereum) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.miner.SetEtherbase(etherbase)
}

// StartMining starts the miner with the given number of CPU threads. If mining
// is already running, this method adjust the number of threads allowed to use
// and updates the minimum price required by the transaction pool.
func (s *Ethereum) StartMining(threads int) error {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		log.Info("Updated mining threads", "threads", threads)
		if threads == 0 {
			threads = -1 // Disable the miner from within
		}
		th.SetThreads(threads)
	}
	// If the miner was not running, initialize it
	if !s.IsMining() {
		// Propagate the initial price point to the transaction pool
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)

		// Configure the local mining address
		eb, err := s.Etherbase()
		if err != nil {
			log.Error("Cannot start mining without etherbase", "err", err)
			return fmt.Errorf("etherbase missing: %v", err)
		}
		if clique, ok := s.engine.(*clique.Clique); ok {
			wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
			if wallet == nil || err != nil {
				log.Error("Etherbase account unavailable locally", "err", err)
				return fmt.Errorf("signer missing: %v", err)
			}
			clique.Authorize(eb, wallet.SignData)
		}
		// If mining is started, we can disable the transaction rejection mechanism
		// introduced to speed sync times.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)

		go s.miner.Start(eb)
	}
	return nil
}

// StopMining terminates the miner, both at the consensus engine level as well as
// at the block creation level.
func (s *Ethereum) StopMining() {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	// Stop the block creating itself
	s.miner.Stop()
}

func (s *Ethereum) IsMining() bool      { return s.miner.Mining() }
func (s *Ethereum) Miner() *miner.Miner { return s.miner }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) TxPool() *core.TxPool               { return s.txPool }
func (s *Ethereum) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) EthVersion() int                    { return int(ProtocolVersions[0]) }
func (s *Ethereum) NetVersion() uint64                 { return s.networkID }
func (s *Ethereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *Ethereum) Synced() bool                       { return atomic.LoadUint32(&s.protocolManager.acceptTxs) == 1 }
func (s *Ethereum) ArchiveMode() bool                  { return s.config.NoPruning }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := make([]p2p.Protocol, len(ProtocolVersions))
	for i, vsn := range ProtocolVersions {
		protos[i] = s.protocolManager.makeProtocol(vsn)
		protos[i].Attributes = []enr.Entry{s.currentEthEntry()}
	}
	if s.lesServer != nil {
		protos = append(protos, s.lesServer.Protocols()...)
	}
	return protos
}

// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start(srvr *p2p.Server) error {
	s.startEthEntryUpdate(srvr.LocalNode())

	// Start the bloom bits servicing goroutines
	s.startBloomHandlers(params.BloomBitsBlocks)

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	fmt.Println("ethereum stop 111111111")
	spv.Close()
	fmt.Println("ethereum stop 222222222")
	close(s.stopChan)
	fmt.Println("ethereum stop 3333333333")
	s.bloomIndexer.Close()
	fmt.Println("ethereum stop 44444444")
	s.blockchain.Stop()
	fmt.Println("ethereum stop 55555555")
	s.engine.Close()
	fmt.Println("ethereum stop 666666666")
	s.protocolManager.Stop()
	fmt.Println("ethereum stop 77777777")
	if s.lesServer != nil {
		s.lesServer.Stop()
		fmt.Println("ethereum stop 88888888")
	}
	fmt.Println("ethereum stop 99999999")
	s.txPool.Stop()
	fmt.Println("ethereum stop aaaaaaaaaa")
	s.miner.Stop()
	fmt.Println("ethereum stop bbbbbbbbbbb")
	s.eventMux.Stop()
	fmt.Println("ethereum stop cccccccccc")
	s.chainDb.Close()
	fmt.Println("ethereum stop ddddddddddd")
	close(s.shutdownChan)
	fmt.Println("ethereum stop eeeeeeeeeee")
	return nil
}
