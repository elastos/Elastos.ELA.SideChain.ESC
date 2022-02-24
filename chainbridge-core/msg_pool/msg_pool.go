// Copyright 2015 The Elastos.ELA.SideChain.ETH Authors
// This file is part of the Elastos.ELA.SideChain.ETH library.
//
// The Elastos.ELA.SideChain.ETH library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Elastos.ELA.SideChain.ETH library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Elastos.ELA.SideChain.ETH library. If not, see <http://www.gnu.org/licenses/>.

package msg_pool

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
)

const MAX_BATCH_SIZE = 100

// Transactions is a Transaction slice type for basic sorting.
type NonceProposal []*voter.Proposal

// Len returns the length of s.
func (s NonceProposal) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s.
func (s NonceProposal) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp.
func (s NonceProposal) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

func (s NonceProposal) Less(i, j int) bool { return s[i].DepositNonce < s[j].DepositNonce }

func (s *NonceProposal) Push(x interface{}) {
	*s = append(*s, x.(*voter.Proposal))
}

func (s *NonceProposal) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

func (s *NonceProposal) Delete(index int) {
	if index < 0 || index >= s.Len() {
		return
	}
	if index == s.Len() - 1 {
		s.Pop()
		return
	}

	list := *s
	*s = append(list[:index], list[index+1:]...)
}

type MsgPool struct {
	queueList map[uint64]*voter.Proposal // Hash map storing the transaction data
	queueLock sync.RWMutex

	verifiedProposalSignatures map[common.Hash][][]byte
	verifiedProposalArbiter map[common.Hash][][]byte
	supernodeProposalSignature map[common.Hash][]byte
	supernodeProposalVerifed map[common.Hash][]byte
	arbiterLock sync.RWMutex

	pendingList NonceProposal

	superVoter []byte

	pendingLock sync.RWMutex

	beforeLock sync.RWMutex
	beforeList map[uint64][]*dpos_msg.DepositProposalMsg
}

func NewMsgPool(supervoter []byte) *MsgPool {
	return &MsgPool{
		queueList: make(map[uint64]*voter.Proposal),
		verifiedProposalSignatures: make(map[common.Hash][][]byte),
		verifiedProposalArbiter: make(map[common.Hash][][]byte),
		supernodeProposalSignature: make(map[common.Hash][]byte),
		supernodeProposalVerifed: make(map[common.Hash][]byte),
		pendingList: make(NonceProposal, 0),
		beforeList: make(map[uint64][]*dpos_msg.DepositProposalMsg, 0),
		superVoter: supervoter,
	}
}

func (m *MsgPool) UpdateSuperVoter(voter []byte) {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	m.superVoter = voter
}

func (m *MsgPool) GetSuperVoter() []byte {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	voter := make([]byte, len(m.superVoter))
	copy(voter, m.superVoter)
	return voter
}

func (m *MsgPool) GetQueueProposal(nonce uint64) *voter.Proposal {
	m.queueLock.RLock()
	defer m.queueLock.RUnlock()
	return m.queueList[nonce]
}

func (m *MsgPool) GetQueueList() []*voter.Proposal  {
	m.queueLock.RLock()
	defer m.queueLock.RUnlock()
	count := len(m.queueList)
	if count > MAX_BATCH_SIZE {
		count = MAX_BATCH_SIZE
	}
	list := make([]*voter.Proposal, 0, count)
	for _, msg := range m.queueList {
		list = append(list, msg)
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) PutProposal(msg *voter.Proposal) error {
	m.queueLock.Lock()
	defer m.queueLock.Unlock()
	nonce := msg.DepositNonce
	if m.queueList[nonce] != nil {
		return errors.New(fmt.Sprintf("error nonce %d", nonce))
	}
	m.queueList[nonce] = msg
	return nil
}

func (m *MsgPool) OnProposalVerified(proposalHash common.Hash, arbiter, signature []byte, containSuperSigner bool) bool {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	log.Info("OnProposalVerified", "supervoter", common.Bytes2Hex(m.superVoter), "arbiter", common.Bytes2Hex(arbiter))
	isSuperVoter := false
	if bytes.Equal(arbiter, m.superVoter) {
		log.Info("received super voter signature", "arbiter", common.Bytes2Hex(arbiter))
		m.supernodeProposalSignature[proposalHash] = signature
		m.supernodeProposalVerifed[proposalHash] = arbiter
		isSuperVoter = true
		if !containSuperSigner {
			return isSuperVoter
		}
	}

	arbiterList := m.verifiedProposalArbiter[proposalHash]
	arbiterList = append(arbiterList, arbiter)
	m.verifiedProposalArbiter[proposalHash] = arbiterList

	sigList := m.verifiedProposalSignatures[proposalHash]
	sigList = append(sigList, signature)
	m.verifiedProposalSignatures[proposalHash] = sigList
	return isSuperVoter
}

func (m *MsgPool) GetSuperVoterSigner(proposalHash common.Hash) []byte {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	sig := m.supernodeProposalSignature[proposalHash]
	return sig
}

func (m *MsgPool) GetVerifiedCount(proposalHash common.Hash) int {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	arbiterList := m.verifiedProposalArbiter[proposalHash]
	return len(arbiterList)
}

func (m *MsgPool) GetSignatures(proposalHash common.Hash) [][]byte {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	signatures := m.verifiedProposalSignatures[proposalHash]
	return signatures
}

func (m *MsgPool) GetArbiters(proposalHash common.Hash) [][]byte {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	signers := m.verifiedProposalArbiter[proposalHash]
	return signers
}

func (m *MsgPool) ArbiterIsVerified(proposalHash common.Hash, arbiter []byte) bool {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	arbiterList := m.verifiedProposalArbiter[proposalHash]
	for _, arb := range arbiterList {
		if bytes.Compare(arb, arbiter) == 0 {
			return true
		}
	}
	if bytes.Compare(m.supernodeProposalVerifed[proposalHash], arbiter) == 0 {
		return true
	}
	return false
}

func (m *MsgPool) PutExecuteProposal(proposal *voter.Proposal) {
	if m.IsPeningProposal(proposal) {
		log.Info("all ready in execute pool")
		return
	}
	m.pendingLock.Lock()
	defer m.pendingLock.Unlock()
	m.pendingList.Push(proposal)
}

func (m *MsgPool) GetPendingList() []*voter.Proposal {
	m.pendingLock.RLock()
	defer m.pendingLock.RUnlock()

	list := make([]*voter.Proposal, 0, len(m.pendingList))
	for i := 0; i < len(m.pendingList); i++ {
		list = append(list, m.pendingList[i])
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) IsPeningProposal(proposal *voter.Proposal) bool {
	m.pendingLock.RLock()
	defer m.pendingLock.RUnlock()
	for _, msg := range m.pendingList {
		if msg.Hash().String() == proposal.Hash().String() {
			return true
		}
	}
	return false
}

func (m *MsgPool) PutBeforeProposal(proposal *dpos_msg.DepositProposalMsg) {
	m.beforeLock.Lock()
	defer m.beforeLock.Unlock()
	list := m.beforeList[proposal.Item.DepositNonce]
	for _, msg := range list {
		if bytes.Equal(msg.Proposer, proposal.Proposer) {
			return
		}
	}
	list = append(list, proposal)
	m.beforeList[proposal.Item.DepositNonce] = list
}

func (m *MsgPool) GetBeforeProposal(proposal *voter.Proposal) []*dpos_msg.DepositProposalMsg {
	m.beforeLock.Lock()
	defer m.beforeLock.Unlock()
	return m.beforeList[proposal.DepositNonce]
}

func (m *MsgPool) OnProposalExecuted(nonce uint64) {
    proposal := m.GetQueueProposal(nonce)
    if proposal == nil {
		return
	}
	m.arbiterLock.Lock()
    hash := proposal.Hash()
    delete(m.verifiedProposalArbiter, hash)
	delete(m.verifiedProposalSignatures, hash)
    delete(m.supernodeProposalSignature, hash)
    delete(m.verifiedProposalArbiter, hash)
	m.arbiterLock.Unlock()

	m.pendingLock.Lock()
	for i := 0; i < len(m.pendingList); i++ {
		if m.pendingList[i].DepositNonce == nonce {
			m.pendingList.Delete(i)
			break
		}
	}

	m.pendingLock.Unlock()

	m.queueLock.Lock()
	delete(m.queueList, nonce)
	m.queueLock.Unlock()
}