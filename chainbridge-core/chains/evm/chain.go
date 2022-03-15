// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"errors"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/aribiters"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type ProposalVoter interface {
	GetClient() voter.ChainClient
	GetPublicKey() ([]byte, error)
	GetSignerAddress() (common.Address, error)
	SetArbiterList(arbiters []common.Address, totalCount int, signature [][]byte, bridgeAddress string) error
	GetArbiterList(bridgeAddress string) ([]common.Address, error)
	IsDeployedBridgeContract(bridgeAddress string) bool
}

// EVMChain is struct that aggregates all data required for
type EVMChain struct {
	writer                ProposalVoter
	chainID               uint64
	bridgeContractAddress string
	config                *config.GeneralChainConfig
	arbiterManager        *aribiters.ArbiterManager
}

func NewEVMChain(writer ProposalVoter, chainID uint64,
	config *config.GeneralChainConfig, arbiterManager *aribiters.ArbiterManager) *EVMChain {
	chain := &EVMChain{writer: writer, chainID: chainID, config: config}
	chain.bridgeContractAddress = config.Opts.Bridge
	chain.arbiterManager = arbiterManager

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

	return c.writer.SetArbiterList(arbiters, totalCount, signatures, c.bridgeContractAddress)
}

func (c *EVMChain) GetArbiters() []common.Address {
	list, err := c.writer.GetArbiterList(c.bridgeContractAddress)
	if err != nil {
		log.Error("GetArbiterList error", "error", err)
		return []common.Address{}
	}
	return list
}

func (c *EVMChain) GetBridgeContract() string {
	return c.config.Opts.Bridge
}

func (c *EVMChain) ChainID() uint64 {
	return c.chainID
}
