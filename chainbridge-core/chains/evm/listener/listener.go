package listener

import (
	"context"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"math/big"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
)

var BlockDelay = big.NewInt(6)
var BlockRetryInterval = time.Second * 5

type SetArbitersEvent struct {
	AddressList  []common.Address
	AddressCount [32]byte
	Sig          []byte
}

type ChainClient interface {
	LatestBlock() (*big.Int, error)
	FetchUpdateArbitersLogs(ctx context.Context, contractAddress common.Address, startBlock *big.Int, endBlock *big.Int) ([]*relayer.SetArbiterListMsg, error)
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
}

type EVMListener struct {
	chainReader   ChainClient
	bridgeAddress common.Address
	opsConfig     *config.OpsConfig
}

func NewEVMListener(chainReader ChainClient, opsConfig *config.OpsConfig) *EVMListener {
	listener := &EVMListener{chainReader: chainReader, opsConfig: opsConfig}
	listener.bridgeAddress = common.HexToAddress(opsConfig.Bridge)
	if opsConfig.BlockConfirmations > 0 {
		BlockDelay = big.NewInt(opsConfig.BlockConfirmations)
	}

	return listener
}

func (l *EVMListener) ListenToEvents(startBlock *big.Int, chainID uint64,
	kvrw blockstore.KeyValueWriter,
	errChn chan<- error) <-chan *relayer.SetArbiterListMsg {
	ch := make(chan *relayer.SetArbiterListMsg)
	go func() {
		for {
			select {
			default:
				head, err := l.chainReader.LatestBlock()
				if err != nil {
					time.Sleep(BlockRetryInterval)
					continue
				}
				// Sleep if the difference is less than BlockDelay; (latest - current) < BlockDelay
				if big.NewInt(0).Sub(head, startBlock).Cmp(BlockDelay) == -1 {
					time.Sleep(BlockRetryInterval)
					continue
				}
				err = l.fetchUpdateArbitersMsg(startBlock, chainID, ch)
				if err != nil {
					errChn <- err
					return
				}

				if startBlock.Int64()%20 == 0 {
					// Logging process every 20 bocks to exclude spam
					bridgelog.Info("Queried block for deposit events", "block", startBlock.String(), "chainId", chainID)
				}
				//Write to block store. Not a critical operation, no need to retry
				err = blockstore.StoreBlock(kvrw, startBlock, chainID)
				if err != nil {
					bridgelog.Error("Failed to write latest block to blockstore", "block", startBlock.String())
				}
				// Goto next block
				startBlock.Add(startBlock, big.NewInt(1))
			}
		}
	}()
	return ch
}

func (l *EVMListener) fetchUpdateArbitersMsg(startBlock *big.Int, chainID uint64, msg chan *relayer.SetArbiterListMsg) error {
	bridgelog.Info("FetchUpdateArbitersLogs", "startBlock", startBlock.Uint64(), "chainID", chainID)
	logs, err := l.chainReader.FetchUpdateArbitersLogs(context.Background(), l.bridgeAddress, startBlock, startBlock)
	if err != nil {
		return err
	}
	for _, eventLog := range logs {
		msg <- eventLog
		bridgelog.Info(fmt.Sprintf("Resolved message %+v in block %s", eventLog, startBlock.String()))
	}
	return nil
}
