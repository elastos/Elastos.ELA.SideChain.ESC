// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/blockstore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/listener"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/msg_pool"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

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
	SignAndBroadProposalBatch(list []*voter.Proposal) common.Hash
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
	go chain.subscribeEvent()
	return chain
}

func (c *EVMChain) subscribeEvent() {
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case dpos_msg.ETOnProposal:
			 c.onProposalEvent(e)
		case dpos_msg.ETSelfOnDuty:
			c.selfOnDuty(e)
		}
	})
}

func (c *EVMChain) selfOnDuty(e *events.Event) {
	list := c.msgPool.GetToLayer2ExecuteProposal()
	log.Info("selfOnDuty selfOnDuty", "list count", len(list))
	for _, p := range list {
		if p.ProposalIsComplete(c.writer.GetClient()) {
			log.Info("Proposal is completed", "proposal", p.Hash().String())
			continue
		}
		err := p.Execute(c.writer.GetClient())
		if err != nil {
			log.Error("proposal is execute error", "error", err)
		}

	}
}

func (c *EVMChain) onProposalEvent(e *events.Event) {
	if msg, ok := e.Data.(*dpos_msg.DepositProposalMsg); ok {
		if c.chainID != Layer2ChainID {
			return
		}
		err := c.onDepositMsg(msg)
		if err != nil {
			log.Error("onDepositMsg error", "error", err)
		}
		return
	}

	if msg, ok := e.Data.(*dpos_msg.BatchMsg); ok {
		if c.chainID != Layer1ChainID {
			return
		}
		err := c.onBatchMsg(msg)
		if err != nil {
			log.Error("onBatchMsg error", "error", err)
		}
		return
	}

}

func (c *EVMChain) onBatchMsg(msg *dpos_msg.BatchMsg) error {
	if len(msg.Items) <= 0 {
		return errors.New("batch msg count is 0")
	}
	for _, item := range msg.Items {
		proposal := c.msgPool.GetToLayer1Proposal(item.DepositNonce)
		if proposal == nil {
			return errors.New(fmt.Sprintf("not have this proposal:%d", item.DepositNonce))
		}
		if proposal.Destination != c.chainID {
			return errors.New(fmt.Sprintf("proposal destination is not correct, chainID:%d, propsal destination:%d", c.chainID, proposal.Destination))
		}
		if proposal.Destination == Layer1ChainID {
			if c.msgPool.IsInLayer1ExecutePool(proposal) {
				return errors.New("all ready in execute pool")
			}
		}
		if !compareMsg(&item, proposal) {
			return errors.New("received error deposit proposal")
		}
	}

	err := c.onBatchProposal(msg, msg.GetHash().Bytes())
	if err != nil {
		return errors.New(fmt.Sprintf("onBatchProposal error: %s", err.Error()))
	} else {
		log.Info("onBatchProposal verified success")
		//TODO complete this add to verifyed list
	}

	return nil
}

func (c *EVMChain) onDepositMsg(msg *dpos_msg.DepositProposalMsg) error {
	proposal := c.msgPool.GetToLayer2Proposal(msg.Item.DepositNonce)
	if proposal == nil {
		return errors.New(fmt.Sprintf("not have this proposal, nonce:%d", msg.Item.DepositNonce))
	}
	if proposal.Destination != c.chainID {
		return errors.New(fmt.Sprintf("proposal destination is not correct, chainID:%d, propsal destination:%d", c.chainID, proposal.Destination))
	}
	if proposal.Destination == Layer2ChainID {
		if c.msgPool.IsInLayer2ExecutePool(proposal) {
			return errors.New("all ready in execute pool")
		}
	}

	if compareMsg(&msg.Item, proposal) {
		err := c.onProposal(msg, proposal.Hash().Bytes())
		if err != nil {
			return errors.New(fmt.Sprintf("OnProposal error: %s", err.Error()))
		} else {
			c.msgPool.OnProposalVerified(proposal.Hash(), msg.Proposer, msg.Signature)
			log.Info("proposal verify suc", "verified count", c.msgPool.GetVerifiedCount(proposal.Hash()))
			if c.msgPool.GetVerifiedCount(proposal.Hash()) > c.getMaxArbitersSign() {
				c.msgPool.PutAbleExecuteProposal(proposal)
			}
		}
	} else {
		return errors.New("received error deposit proposal")
	}
	return nil
}

func compareMsg(msg1 *dpos_msg.DepositItem, msg2 *voter.Proposal) bool {
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

func (c *EVMChain) onProposal(msg *dpos_msg.DepositProposalMsg, proposalHash []byte) error {
	pk, err := crypto.SigToPub(proposalHash, msg.Signature)
	if err != nil {
		return err
	}
	pub := crypto.CompressPubkey(pk)
	if bytes.Compare(msg.Proposer, pub) != 0 {
		return errors.New(fmt.Sprintf("verified signature error, proposer:%s, publicKey:%s", common.Bytes2Hex(msg.Proposer), common.Bytes2Hex(pub)))
	}
	return nil
}

func (c *EVMChain) onBatchProposal(msg *dpos_msg.BatchMsg, proposalHash []byte) error {
	pk, err := crypto.SigToPub(proposalHash, msg.Signature)
	if err != nil {
		return err
	}
	pub := crypto.CompressPubkey(pk)
	if bytes.Compare(msg.Proposer, pub) != 0 {
		return errors.New(fmt.Sprintf("verified signature error, proposer:%s, publicKey:%s", common.Bytes2Hex(msg.Proposer), common.Bytes2Hex(pub)))
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
	log.Info("handle new relayer message", "source", proposal.Source, "target", proposal.Destination, "nonce", proposal.DepositNonce)

	if msg.Destination == Layer2ChainID {
		err = c.msgPool.PutToLayer2Proposal(proposal)
		if err != nil {
			return err
		}
		hash := c.writer.SignAndBroadProposal(proposal)
		log.Info("SignAndBroadProposal", "hash", hash.String())
	} else if msg.Destination == Layer1ChainID {
		log.Info("Put to layer1 msg pool", "chainID", c.chainID)
		err := c.msgPool.PutToLayer1Proposal(proposal)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *EVMChain) GenerateBatchProposal(stop <-chan struct{}) {
	if c.chainID != Layer1ChainID {
		return
	}
	go func() {
		for {
			for {
				select {
				case <-stop:
					return
				case  <-time.After(listener.BatchMsgInterval):
					list := c.msgPool.GetToLayer1Batch()
					log.Info("GenerateBatchProposal...", "list count", len(list))
					if len(list) > 0 {
						c.writer.SignAndBroadProposalBatch(list)
					}
					continue
				}
			}
		}
	}()
}

func (c *EVMChain) ChainID() uint8 {
	return c.chainID
}

func (c *EVMChain) Start() bool {
	return true
}