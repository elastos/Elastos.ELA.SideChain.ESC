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

const MaxBatchCount = 100

type EventListener interface {
	ListenToEvents(startBlock *big.Int, chainID uint8, kvrw blockstore.KeyValueWriter, stopChn <-chan struct{}, errChn chan<- error) <-chan *relayer.Message
}

type ProposalVoter interface {
	HandleProposal(message *relayer.Message) (*voter.Proposal, error)
	GetClient() voter.ChainClient
	SignAndBroadProposal(proposal *voter.Proposal) common.Hash
	SignAndBroadProposalBatch(list []*voter.Proposal) *dpos_msg.BatchMsg
	FeedbackBatchMsg(msg *dpos_msg.BatchMsg) common.Hash
	GetPublicKey() ([]byte, error)
	GetSignerAddress() (common.Address, error)
	SetArbiterList(bridgeAddress string) error
	GetArbiterList(bridgeAddress string) ([]common.Address, error)
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
	currentProposal       *dpos_msg.BatchMsg
}

func NewEVMChain(dr EventListener, writer ProposalVoter, kvdb blockstore.KeyValueReaderWriter, chainID uint8, config *config.GeneralChainConfig) *EVMChain {
	chain := &EVMChain{listener: dr, writer: writer, kvdb: kvdb, chainID: chainID, config: config}
	chain.bridgeContractAddress = config.Opts.Bridge
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
			go func() {
				time.Sleep(1 * time.Second) //wait block data write to db
				c.selfOnDuty(e)
			}()
		}
	})
}

func (c *EVMChain) selfOnDuty(e *events.Event) {
	queueList := c.msgPool.GetQueueList()
	pendingList := c.msgPool.GetPendingList()

	log.Info("selfOnDuty selfOnDuty", "chainID", c.chainID, "queueList", len(queueList), "pendingList", len(pendingList))
	if c.chainID == Layer2ChainID {
		if len(queueList) > 0 && len(pendingList) == 0 {
			for _, p := range queueList {
				c.broadProposal(p)
			}
		} else if len(pendingList) > 0 {
			log.Info("ExecuteToLayer2Proposal", "list count", len(pendingList))
			err := c.ExecuteProposals(pendingList)
			if err != nil {
				log.Error("ExecuteProposals error", "error", err)
			}
		}
	} else if c.chainID == Layer1ChainID {
		c.generateBatchProposal()
	}
}

func (c *EVMChain) broadProposal(p *voter.Proposal) {
	if p.ProposalIsComplete(c.writer.GetClient()) {
		log.Info("Proposal is executed", "proposal", p.Hash().String())
		c.msgPool.OnProposalExecuted(p.DepositNonce)
		return
	}
	hash := c.writer.SignAndBroadProposal(p)
	log.Info("SignAndBroadProposal", "hash", hash.String())
}

func (c *EVMChain) ExecuteProposals(list []*voter.Proposal) error {
	for _, p := range list {
		if p.ProposalIsComplete(c.writer.GetClient()) {
			log.Info("Proposal is completed", "proposal", p.Hash().String(), "dest", p.Destination, "chainid", c.chainID)
			c.msgPool.OnProposalExecuted(p.DepositNonce)
			continue
		}
		signature := c.msgPool.GetSignatures(p.Hash())
		err := p.Execute(c.writer.GetClient(), signature)
		if err != nil {
			log.Error("proposal is execute error", "error", err)
			return err
		}
	}
	return nil
}

func (c *EVMChain) ExecuteProposalBatch(msg *dpos_msg.BatchMsg) error {
	items := make([]*voter.Proposal, 0)
	for _, it := range msg.Items {
		p := c.msgPool.GetQueueProposal(it.DepositNonce)
		if p.ProposalIsComplete(c.writer.GetClient()) {
			log.Info("Proposal is completed", "proposal", p.Hash().String(), "dest", p.Destination, "chainid", c.chainID)
			c.msgPool.OnProposalExecuted(p.DepositNonce)
			continue
		}
		items = append(items, p)
	}
	if len(items) > 0 {
		err := voter.ExecuteBatch(c.writer.GetClient(), items)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *EVMChain) onProposalEvent(e *events.Event) {
	log.Info("on deposit proposal event")
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

	if msg, ok := e.Data.(*dpos_msg.FeedbackBatchMsg); ok {
		if c.chainID != Layer1ChainID {
			return
		}
		err := c.onFeedbackBatchMsg(msg)
		if err != nil {
			log.Error("onFeedbackBatchMsg error", "error", err)
		}
		return
	}
}

func (c *EVMChain) onFeedbackBatchMsg(msg *dpos_msg.FeedbackBatchMsg) error {
	if msg.BatchMsgHash.String() != c.currentProposal.GetHash().String() {
		return errors.New("The feedback  is not current proposal")
	}
	if c.msgPool.ArbiterIsVerified(msg.BatchMsgHash, msg.Signer) {
		return errors.New(fmt.Sprintf("is verified arbiter:%s", common.Bytes2Hex(msg.Proposer)))
	}
	if c.msgPool.GetVerifiedCount(msg.BatchMsgHash) > c.getMaxArbitersSign() {
		return errors.New("is collect enough feedback")
	}

	if err := c.verifySignature(msg); err != nil {
		return err
	}

	c.msgPool.OnProposalVerified(msg.BatchMsgHash, msg.Signer, msg.Signature)
	log.Info("onFeedbackBatchMsg", "verified count", c.msgPool.GetVerifiedCount(msg.BatchMsgHash))
	if c.msgPool.GetVerifiedCount(msg.BatchMsgHash) > c.getMaxArbitersSign() {
		err := c.ExecuteProposalBatch(c.currentProposal)
		if err != nil {
			log.Error("ExecuteProposalBatch error", "error", err)
		}
	}
	return nil
}

func (c *EVMChain) verifySignature(msg *dpos_msg.FeedbackBatchMsg) error {
	pk, err := crypto.SigToPub(c.currentProposal.GetHash().Bytes(), msg.Signature)
	if err != nil {
		return err
	}
	pub := crypto.CompressPubkey(pk)
	if bytes.Compare(msg.Signer, pub) != 0 {
		return errors.New(fmt.Sprintf("verified signature error, signer:%s, publicKey:%s", common.Bytes2Hex(msg.Signer), common.Bytes2Hex(pub)))
	}

	//TODO need judge pub is a arbiter
	return nil
}

func (c *EVMChain) onBatchMsg(msg *dpos_msg.BatchMsg) error {
	if len(msg.Items) <= 0 {
		return errors.New("batch msg count is 0")
	}
	for _, item := range msg.Items {
		proposal := c.msgPool.GetQueueProposal(item.DepositNonce)
		if proposal == nil {
			return errors.New(fmt.Sprintf("not have this proposal:%d", item.DepositNonce))
		}
		if proposal.Destination != c.chainID {
			return errors.New(fmt.Sprintf("proposal destination is not correct, chainID:%d, propsal destination:%d", c.chainID, proposal.Destination))
		}

		if proposal.ProposalIsComplete(c.writer.GetClient()) {
			c.msgPool.OnProposalExecuted(proposal.DepositNonce)
			return errors.New(fmt.Sprintf("proposal is completed, hash:%s, dest:%d, source:%d", proposal.Hash().String(), proposal.Destination, c.chainID))
		}
		if !compareMsg(&item, proposal) {
			return errors.New("received error deposit proposal")
		}
	}

	err := c.onBatchProposal(msg, msg.GetHash().Bytes())
	if err != nil {
		return errors.New(fmt.Sprintf("onBatchProposal error: %s", err.Error()))
	} else {
		c.writer.FeedbackBatchMsg(msg)
	}

	return nil
}

func (c *EVMChain) onDepositMsg(msg *dpos_msg.DepositProposalMsg) error {
	proposal := c.msgPool.GetQueueProposal(msg.Item.DepositNonce)
	if proposal == nil {
		return errors.New(fmt.Sprintf("not have this proposal, nonce:%d", msg.Item.DepositNonce))
	}
	if proposal.Destination != c.chainID {
		return errors.New(fmt.Sprintf("proposal destination is not correct, chainID:%d, propsal destination:%d", c.chainID, proposal.Destination))
	}
	if proposal.Destination == Layer2ChainID {
		if c.msgPool.IsPeningProposal(proposal) {
			return errors.New("all ready in execute pool")
		}
	}
	if proposal.ProposalIsComplete(c.writer.GetClient()) {
		c.msgPool.OnProposalExecuted(proposal.DepositNonce)
		return errors.New("all ready executed proposal")
	}

	if compareMsg(&msg.Item, proposal) {
		err := c.onProposal(msg, proposal.Hash().Bytes())
		if err != nil {
			return errors.New(fmt.Sprintf("OnProposal error: %s", err.Error()))
		} else {
			c.msgPool.OnProposalVerified(proposal.Hash(), msg.Proposer, msg.Signature)
			log.Info("proposal verify suc", "verified count", c.msgPool.GetVerifiedCount(proposal.Hash()))
			if c.msgPool.GetVerifiedCount(proposal.Hash()) > c.getMaxArbitersSign() {
				c.msgPool.PutExecuteProposal(proposal)
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
	pbk, err := c.writer.GetPublicKey()
	if err != nil {
		return err
	}
	if bytes.Equal(msg.Proposer, pbk) {
		return errors.New("is self submit proposal")
	}

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

func (c *EVMChain) WriteArbiters() error {
	return c.writer.SetArbiterList(c.bridgeContractAddress)
}

func (c *EVMChain) Write(msg *relayer.Message) error {
	proposal, err := c.writer.HandleProposal(msg)
	if err != nil {
		return err
	}
	log.Info("handle new relayer message", "source", proposal.Source, "target", proposal.Destination, "nonce", proposal.DepositNonce)

	if proposal.ProposalIsComplete(c.writer.GetClient()) {
		return err
	}

	err = c.msgPool.PutProposal(proposal)
	if err != nil {
		return err
	}
	if msg.Destination == Layer2ChainID {
		c.broadProposal(proposal)
	}
	return nil
}

func (c *EVMChain) generateBatchProposal() {
	list := c.msgPool.GetQueueList()
	items := make([]*voter.Proposal, 0)
	count := len(list)
	for i := 0; i < count; i++ {
		if list[i].ProposalIsComplete(c.writer.GetClient()) {
			c.msgPool.OnProposalExecuted(list[i].DepositNonce)
			continue
		}
		items = append(items, list[i])
	}
	count = len(items)
	if count > 0 {
		if count > MaxBatchCount {
			items = items[0:MaxBatchCount]
		}
		c.currentProposal = c.writer.SignAndBroadProposalBatch(items)
		log.Info("GenerateBatchProposal...", "list count", count, "proposal", c.currentProposal.GetHash().String())
		c.writer.FeedbackBatchMsg(c.currentProposal)
	}
}

func (c *EVMChain) ChainID() uint8 {
	return c.chainID
}
