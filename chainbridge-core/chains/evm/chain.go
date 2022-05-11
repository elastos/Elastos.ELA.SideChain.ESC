// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/aribiters"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type EventListener interface {
	ListenToEvents(startBlock *big.Int, chainID uint64, kvrw blockstore.KeyValueWriter, errChn chan<- error) <-chan *relayer.SetArbiterListMsg
}

type ProposalVoter interface {
	GetClient() voter.ChainClient
	GetPublicKey() ([]byte, error)
	GetSignerAddress() (common.Address, error)
	SetArbiterList(arbiters []common.Address, totalCount int, signature [][]byte, bridgeAddress string) error
	GetArbiterList(bridgeAddress string) ([]common.Address, error)
	GetSignatures(bridgeAddress string) ([][crypto.SignatureLength]byte, error)
	GetTotalCount(bridgeAddress string) (uint64, error)
	GetESCState(bridgeAddress string) (uint8, error)
	GetHashSalt(bridgeAddress string) (*big.Int, error)
	IsDeployedBridgeContract(bridgeAddress string) bool
	SetESCState(bridgeAddress string, state uint8) error
	SetManualArbiter(bridgeAddress string, arbiter []common.Address, totalSigner int) error
}

// EVMChain is struct that aggregates all data required for
type EVMChain struct {
	listener              EventListener // Rename
	writer                ProposalVoter
	chainID               uint64
	kvdb                  blockstore.KeyValueReaderWriter
	bridgeContractAddress string
	config                *config.GeneralChainConfig
	arbiterManager        *aribiters.ArbiterManager
}

func NewEVMChain(dr EventListener, writer ProposalVoter, chainID uint64, kvdb blockstore.KeyValueReaderWriter,
	config *config.GeneralChainConfig, arbiterManager *aribiters.ArbiterManager) *EVMChain {
	chain := &EVMChain{listener: dr, writer: writer, chainID: chainID, config: config}
	chain.bridgeContractAddress = config.Opts.Bridge
	chain.arbiterManager = arbiterManager
	chain.kvdb = kvdb

	return chain
}

func (c *EVMChain) getMaxArbitersSign() int {
	total := c.writer.GetClient().Engine().GetTotalArbitersCount()
	return total*2/3 + 1
}

func (c *EVMChain) WriteArbiters(arbiters []common.Address, signatures [][]byte, totalCount int) error {
	if c.writer.IsDeployedBridgeContract(c.bridgeContractAddress) == false {
		return errors.New(fmt.Sprintf("%d is not deploy chainbridge contract", c.chainID))
	}

	isSame := false
	nowArbiters := c.GetArbiters()
	if len(arbiters) == len(nowArbiters) {
		isSame = true
		for i, arbiter := range nowArbiters {
			if !bytes.Equal(arbiter.Bytes(), arbiters[i].Bytes()) {
				isSame = false
				break
			}
		}
	}
	if !isSame {
		return c.writer.SetArbiterList(arbiters, totalCount, signatures, c.bridgeContractAddress)
	}
	return errors.New("is same arbiters on contract")
}

func (c *EVMChain) GetArbiters() []common.Address {
	list, err := c.writer.GetArbiterList(c.bridgeContractAddress)
	if err != nil {
		log.Error("GetArbiterList error", "error", err)
		return []common.Address{}
	}
	return list
}

func (c *EVMChain) GetSignatures() ([][crypto.SignatureLength]byte, error) {
	sigs, err := c.writer.GetSignatures(c.bridgeContractAddress)
	if err != nil {
		log.Error("GetSignatures error", "error", err)
		return [][crypto.SignatureLength]byte{}, err
	}
	return sigs, nil
}
func (c *EVMChain) GetTotalCount() (uint64, error) {
	count, err := c.writer.GetTotalCount(c.bridgeContractAddress)
	if err != nil {
		log.Error("GetTotalCount error", "error", err)
		return 0, err
	}
	return count, nil
}

func (c *EVMChain) GetESCState() (uint8, error) {
	state, err := c.writer.GetESCState(c.bridgeContractAddress)
	if err != nil {
		log.Error("GetTotalCount error", "error", err)
		return 0, err
	}
	return state, nil
}

func (c *EVMChain) GetHashSalt() (*big.Int, error) {
	return c.writer.GetHashSalt(c.bridgeContractAddress)
}

func (c *EVMChain) SetESCState(state uint8) error {
	err := c.writer.SetESCState(c.bridgeContractAddress, state)
	if err != nil {
		return err
	}
	return nil
}

func (c *EVMChain) SetManualArbiters(arbiters []common.Address, totalSigner int) error {
	err := c.writer.SetManualArbiter(c.bridgeContractAddress, arbiters, totalSigner)
	if err != nil {
		log.Error("SetManualArbiters error", "error", err)
		return err
	}
	return nil
}

func (c *EVMChain) GetBridgeContract() string {
	return c.config.Opts.Bridge
}

func (c *EVMChain) ChainID() uint64 {
	return c.chainID
}

// PollEvents is the goroutine that polling blocks and searching Deposit Events in them. Event then sent to eventsChan
func (c *EVMChain) PollEvents(sysErr chan<- error, stop <-chan struct{}, eventsChan chan *relayer.SetArbiterListMsg) {
	log.Info("Polling Blocks...", "startBlock", c.config.Opts.StartBlock)
	// Handler chain specific configs and flags
	block, err := blockstore.SetupBlockstore(c.config, c.kvdb, big.NewInt(0).SetUint64(c.config.Opts.StartBlock))
	if err != nil {
		sysErr <- fmt.Errorf("error %w on getting last stored block", err)
		return
	}
	ech := c.listener.ListenToEvents(block, c.chainID, c.kvdb, sysErr)
	for {
		select {
		case newEvent := <-ech:
			// Here we can place middlewares for custom logic?
			eventsChan <- newEvent
			continue
		case <-stop:
			bridgelog.Info("PollEvents stopped")
			return
		}
	}
}
