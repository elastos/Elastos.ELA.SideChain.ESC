// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/msg_pool"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/events"

)

var Layer1ChainID uint8
var Layer2ChainID uint8

type EventListener interface {
	ListenToEvents(startBlock *big.Int, chainID uint8, kvrw blockstore.KeyValueWriter, stopChn <-chan struct{}, errChn chan<- error) <-chan *relayer.Message
}

type ProposalVoter interface {
	HandleProposal(message *relayer.Message) (*voter.Proposal, error)
    GetClient() voter.ChainClient
	SignAndBroadProposal(proposal *voter.Proposal) common.Hash
}

// EVMChain is struct that aggregates all data required for
type EVMChain struct {
	listener              EventListener // Rename
	writer                ProposalVoter
	chainID               uint8
	kvdb                  blockstore.KeyValueReaderWriter
	bridgeContractAddress string
	config                *config.GeneralChainConfig
	msgPool               *msg_pool.MsgPool



}

func NewEVMChain(dr EventListener, writer ProposalVoter, kvdb blockstore.KeyValueReaderWriter, chainID uint8, config *config.GeneralChainConfig) *EVMChain {
	chain := &EVMChain{listener: dr, writer: writer, kvdb: kvdb, chainID: chainID, config: config}
	chain.msgPool = msg_pool.NewMsgPool()
	chain.subscribeEvent()
	return chain
}

func (c *EVMChain) subscribeEvent() {
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case dpos_msg.ETOnProposal:
			if msg, ok := e.Data.(*dpos_msg.DepositProposalMsg); ok {
				proposal := c.msgPool.Get(msg.DepositNonce)
				if proposal == nil {
					return
				}
				if c.msgPool.IsInExecutePool(proposal) {
					log.Info("all ready in execute pool", "proposal", proposal.Hash().String())
					return
				}
				if compareMsg(msg, proposal) {
					err := c.OnProposal(msg, proposal.Hash().Bytes())
					if err != nil {
						log.Error("OnProposal error", "error", err)
					} else {
						log.Info("proposal verify suc")
						c.msgPool.OnProposalVerified(proposal.Hash(), msg.Proposer, msg.Signature)
						fmt.Println("verifiedCount", c.msgPool.GetVerifiedCount(proposal.Hash()))
						if c.msgPool.GetVerifiedCount(proposal.Hash()) > c.getMaxArbitersSign() {
							c.msgPool.PutAbleExecuteProposal(proposal)
						}
					}
				} else {
					log.Error("received error deposit proposal")
				}
			}
		}
	})
}

func compareMsg(msg1 *dpos_msg.DepositProposalMsg, msg2 *voter.Proposal) bool {
	if msg2 == nil || msg1 == nil {
		return false
	}
	if msg1.SourceChainID != msg2.Source {
		return false
	}
	if msg1.DestChainID != msg2.Destination {
		return false
	}
	if bytes.Compare(msg1.ResourceId[:], msg2.ResourceId[:]) != 0 {
		return false
	}
	if bytes.Compare(msg1.Data, msg2.Data) != 0 {
		return false
	}
	return true
}

func (c *EVMChain) getMaxArbitersSign() int {
	total := c.writer.GetClient().Engine().GetTotalProducerCount()
	return total * 2 / 3
}

func (c *EVMChain) OnProposal(msg *dpos_msg.DepositProposalMsg, proposalHash []byte) error {
	pk, err := crypto.DecodePoint(msg.Proposer)
	if err != nil {
		return err
	}
	if err := crypto.Verify(*pk, proposalHash, msg.Signature); err != nil {
		return err
	}

	return nil
}

// PollEvents is the goroutine that polling blocks and searching Deposit Events in them. Event then sent to eventsChan
func (c *EVMChain) PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *relayer.Message) {
	log.Info("Polling Blocks...")
	// Handler chain specific configs and flags
	block, err := blockstore.SetupBlockstore(c.config, c.kvdb, big.NewInt(c.config.Opts.StartBlock))
	if err != nil {
		sysErr <- fmt.Errorf("error %w on getting last stored block", err)
		return
	}
	ech := c.listener.ListenToEvents(block, c.chainID, c.kvdb, stop, sysErr)
	for {
		select {
		case <-stop:
			return
		case newEvent := <-ech:
			// Here we can place middlewares for custom logic?
			eventsChan <- newEvent
			continue
		}
	}
}

func (c *EVMChain) Write(msg *relayer.Message) error {
	proposal, err := c.writer.HandleProposal(msg)
	if err != nil {
		return err
	}
	err = c.msgPool.Put(proposal)
	if err != nil {
		return err
	}
	if msg.Destination == Layer2ChainID {
		hash := c.writer.SignAndBroadProposal(proposal)
		log.Info("SignAndBroadProposal", "hash", hash.String())
	}
	return nil
}

func (c *EVMChain) ChainID() uint8 {
	return c.chainID
}

func (c *EVMChain) Start() bool {
	return true
}