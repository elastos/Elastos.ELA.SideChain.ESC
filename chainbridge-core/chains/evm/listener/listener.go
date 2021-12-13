// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package listener

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

var BlockRetryInterval = time.Second * 5
var BlockDelay = big.NewInt(6) //TODO: move to config
var BatchMsgInterval = time.Second * 30

type DepositRecord struct {
	TokenAddress                   common.Address
	DestinationChainID             uint8
	ResourceID                     [32]byte
	DepositNonce                   uint64
	Depositer                      common.Address
	Amount                         *big.Int
	Fee 						   *big.Int
}

type ChangeSuperSigner struct {
	OldSuperSigner common.Address
	NewSuperSigner common.Address
}

type ChainClient interface {
	LatestBlock() (*big.Int, error)
	FetchDepositLogs(ctx context.Context, address common.Address, startBlock *big.Int, endBlock *big.Int) ([]*DepositRecord, error)
	FetchChangeSuperSigner(ctx context.Context, address common.Address, startBlock *big.Int, endBlock *big.Int) ([]*ChangeSuperSigner, error)
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
}

type EventHandler interface {
	HandleEvent(sourceID, destID uint8, nonce uint64, rID [32]byte) error
}

type EVMListener struct {
	chainReader   ChainClient
	eventHandler  EventHandler
	bridgeAddress common.Address
}

func NewEVMListener(chainReader ChainClient, handler EventHandler, bridgeAddress common.Address) *EVMListener {
	return &EVMListener{chainReader: chainReader, eventHandler: handler, bridgeAddress: bridgeAddress}
}

func (l *EVMListener) ListenToEvents(startBlock *big.Int, chainID uint8,
	                                 kvrw blockstore.KeyValueWriter,
	                                 stopChn <-chan struct{},
	                                 errChn chan<- error) (<-chan *relayer.Message, <-chan *relayer.ChangeSuperSigner) {
	ch := make(chan *relayer.Message)
	changeSuperCh := make(chan *relayer.ChangeSuperSigner)
	go func() {
		for {
			select {
			case <-stopChn:
				return
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
				err = l.fetchDepositMsg(startBlock, chainID, ch)
				if err != nil {
					errChn <- err
					return
				}

				err = l.fetchChangeSuperSigner(startBlock,chainID, changeSuperCh)
				if err != nil {
					errChn <- err
					return
				}
				if startBlock.Int64()%20 == 0 {
					// Logging process every 20 bocks to exclude spam
					log.Debug("Queried block for deposit events", "block", startBlock.String(), "chainId", chainID)
				}
				//Write to block store. Not a critical operation, no need to retry
				err = blockstore.StoreBlock(kvrw, startBlock, chainID)
				if err != nil {
					log.Error("Failed to write latest block to blockstore", "block", startBlock.String())
				}
				// Goto next block
				startBlock.Add(startBlock, big.NewInt(1))
			}
		}
	}()
	return ch, changeSuperCh
}

func (l *EVMListener) fetchDepositMsg(startBlock *big.Int, chainID uint8, msg chan *relayer.Message) error {
	log.Info("FetchDepositLogs", "startBlock", startBlock.Uint64(), "chainID", chainID)
	logs, err := l.chainReader.FetchDepositLogs(context.Background(), l.bridgeAddress, startBlock, startBlock)
	if err != nil {
		// Filtering logs error really can appear only on wrong configuration or temporary network problem
		// so i do no see any reason to break execution
		log.Error("FetchDepositLogs errors", "ChainID", chainID)
		return nil
	}
	for _, eventLog := range logs {
		err = l.eventHandler.HandleEvent(chainID, eventLog.DestinationChainID, eventLog.DepositNonce, eventLog.ResourceID)
		if err != nil {
			log.Error("HandleEvent error", "error", err)
			return err
		}

		m := &relayer.Message{
			Source: chainID,
			Destination: eventLog.DestinationChainID,
			DepositNonce: eventLog.DepositNonce,
			ResourceId: eventLog.ResourceID,
			Payload: []interface{}{
				eventLog.Amount.Bytes(),
				eventLog.Depositer,
				eventLog.Fee.Bytes(),
			},
		}
		msg <- m
		log.Info(fmt.Sprintf("Resolved message %+v in block %s", m, startBlock.String()))
	}
	return nil
}


func (l *EVMListener) fetchChangeSuperSigner(startBlock *big.Int, chainID uint8, msg chan *relayer.ChangeSuperSigner) error {
	logs, err := l.chainReader.FetchChangeSuperSigner(context.Background(), l.bridgeAddress, startBlock, startBlock)
	if err != nil {
		// Filtering logs error really can appear only on wrong configuration or temporary network problem
		// so i do no see any reason to break execution
		log.Error("FetchChangeSuperSigner errors", "ChainID", chainID)
		return nil
	}
	for _, eventLog := range logs {
		m := &relayer.ChangeSuperSigner{
			SourceChain: chainID,
			OldSuperSigner: eventLog.OldSuperSigner,
			NewSuperSigner: eventLog.NewSuperSigner,
		}
		msg <- m
		log.Info(fmt.Sprintf("Resolved change super msg %+v in block %s", m.NewSuperSigner.String(), startBlock.String()))
	}
	return nil
}
