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

func (s NonceProposal) Less(i, j int) bool { return s[i].DepositNonce > s[j].DepositNonce }

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
	toLayer2Items map[uint64]*voter.Proposal // Hash map storing the transaction data
	lock2 sync.RWMutex

	toLayer1Items map[uint64]*voter.Proposal // Hash map storing the transaction data
	lock1 sync.RWMutex

	verifiedProposalSignatures map[common.Hash][][]byte
	verifiedProposalArbiter map[common.Hash][][]byte
	arbiterLock sync.RWMutex

	executeLayer1Proposal NonceProposal
	proposal1Lock sync.RWMutex

	executeLayer2Proposal NonceProposal
	proposalLock sync.RWMutex
}

func NewMsgPool() *MsgPool {
	return &MsgPool{
		toLayer2Items: make(map[uint64]*voter.Proposal),
		toLayer1Items: make(map[uint64]*voter.Proposal),
		verifiedProposalSignatures: make(map[common.Hash][][]byte),
		verifiedProposalArbiter: make(map[common.Hash][][]byte),
		executeLayer2Proposal: make(NonceProposal, 0),
		executeLayer1Proposal: make(NonceProposal, 0),
	}
}

func (m *MsgPool) GetToLayer2Proposal(nonce uint64) *voter.Proposal {
	m.lock2.RLock()
	defer m.lock2.RUnlock()
	return m.toLayer2Items[nonce]
}

func (m *MsgPool) GetToLayer2Proposals() []*voter.Proposal  {
	count := len(m.toLayer2Items)
	if count > MAX_BATCH_SIZE {
		count = MAX_BATCH_SIZE
	}
	list := make([]*voter.Proposal, 0, count)
	for _, msg := range m.toLayer2Items {
		list = append(list, msg)
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) PutToLayer2Proposal(msg *voter.Proposal) error {
	m.lock2.Lock()
	defer m.lock2.Unlock()
	nonce := msg.DepositNonce
	if m.toLayer2Items[nonce] != nil {
		return errors.New(fmt.Sprintf("error nonce %d", nonce))
	}
	m.toLayer2Items[nonce] = msg
	return nil
}

func (m *MsgPool) GetToLayer1Proposal(nonce uint64) *voter.Proposal {
	m.lock1.RLock()
	defer m.lock1.RUnlock()
	return m.toLayer1Items[nonce]
}

func (m *MsgPool) PutToLayer1Proposal(msg *voter.Proposal) error {
	m.lock1.Lock()
	defer m.lock1.Unlock()
	nonce := msg.DepositNonce
	if m.toLayer1Items[nonce] != nil {
		return errors.New(fmt.Sprintf("PutToLayer1Proposal error nonce %d", nonce))
	}
	m.toLayer1Items[nonce] = msg
	return nil
}

func (m *MsgPool) OnProposalVerified(proposalHash common.Hash, arbiter, signature []byte)  {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	if m.arbiterIsVerified(proposalHash, arbiter) {
		log.Info("is verified arbiter", "arbiter", common.Bytes2Hex(arbiter))
		return
	}
	arbiterList := m.verifiedProposalArbiter[proposalHash]
	arbiterList = append(arbiterList, arbiter)
	m.verifiedProposalArbiter[proposalHash] = arbiterList

	sigList := m.verifiedProposalSignatures[proposalHash]
	sigList = append(sigList, signature)
	m.verifiedProposalSignatures[proposalHash] = sigList
}

func (m *MsgPool) GetVerifiedCount(proposalHash common.Hash) int {
	m.arbiterLock.Lock()
	defer m.arbiterLock.Unlock()
	arbiterList := m.verifiedProposalArbiter[proposalHash]
	return len(arbiterList)
}

func (m *MsgPool) arbiterIsVerified(proposalHash common.Hash, arbiter []byte) bool {
	arbiterList := m.verifiedProposalArbiter[proposalHash]
	for _, arb := range arbiterList {
		if bytes.Compare(arb, arbiter) == 0 {
			return true
		}
	}
	return false
}

func (m *MsgPool) PutAbleExecuteProposal(proposal *voter.Proposal) {
	m.proposalLock.Lock()
	defer m.proposalLock.Unlock()

	if m.IsInLayer2ExecutePool(proposal) {
		log.Info("all ready in execute pool")
		return
	}
	m.executeLayer2Proposal.Push(proposal)
}

func (m *MsgPool) GetToLayer2ExecuteProposal() []*voter.Proposal {
	m.proposalLock.RLock()
	defer m.proposalLock.RUnlock()

	list := make([]*voter.Proposal, 0, len(m.executeLayer2Proposal))
	for i := 0; i < len(m.executeLayer2Proposal); i++ {
		list = append(list, m.executeLayer2Proposal[i])
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) IsInLayer2ExecutePool(proposal *voter.Proposal) bool {
	for _, msg := range m.executeLayer2Proposal {
		if msg.Hash().String() == proposal.Hash().String() {
			return true
		}
	}
	return false
}

func (m *MsgPool) GetToLayer1Batch() []*voter.Proposal {
	count := len(m.toLayer1Items)
	if count > MAX_BATCH_SIZE {
		count = MAX_BATCH_SIZE
	}
	list := make([]*voter.Proposal, 0, count)
	for _, msg := range m.toLayer1Items {
		list = append(list, msg)
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) IsInLayer1ExecutePool(proposal *voter.Proposal) bool {
	for _, msg := range m.executeLayer1Proposal {
		if msg.Hash().String() == proposal.Hash().String() {
			return true
		}
	}
	return false
}

func (m *MsgPool) OnTolayer2ProposalCompleted(nonce uint64) {
	m.proposalLock.RLock()
	defer m.proposalLock.RUnlock()
	for i := 0; i < len(m.executeLayer2Proposal); i++ {
		if m.executeLayer2Proposal[i].DepositNonce == nonce {
			m.executeLayer2Proposal.Delete(i)
			break
		}
	}
	delete(m.toLayer2Items, nonce)
}