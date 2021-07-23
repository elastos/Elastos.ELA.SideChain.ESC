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

	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/voter"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
)

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

type MsgPool struct {
	items map[uint64]*voter.Proposal // Hash map storing the transaction data
	lock sync.RWMutex

	verifiedProposalSignatures map[common.Hash][][]byte
	verifiedProposalArbiter map[common.Hash][][]byte
	arbiterLock sync.RWMutex

	executeProposal NonceProposal
	proposalLock sync.RWMutex
}

func NewMsgPool() *MsgPool {
	return &MsgPool{
		items: make(map[uint64]*voter.Proposal),
		verifiedProposalSignatures: make(map[common.Hash][][]byte),
		verifiedProposalArbiter: make(map[common.Hash][][]byte),
		executeProposal: make(NonceProposal, 0),
	}
}

// Get retrieves the current transactions associated with the given nonce.
func (m *MsgPool) Get(nonce uint64) *voter.Proposal {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.items[nonce]
}

func (m *MsgPool) Put(msg *voter.Proposal) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	nonce := msg.DepositNonce
	if m.items[nonce] != nil {
		return errors.New(fmt.Sprintf("error nonce %d", nonce))
	}
	m.items[nonce] = msg
	return nil
}

func (m *MsgPool) Remove(nonce uint64) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	_, ok := m.items[nonce]
	if !ok {
		return false
	}
	delete(m.items, nonce)
	return true
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

	if m.IsInExecutePool(proposal) {
		log.Info("all ready in execute pool")
		return
	}
	m.executeProposal.Push(proposal)
}

func (m *MsgPool) GetAbleExecuteProposal() []*voter.Proposal {
	m.proposalLock.RLock()
	defer m.proposalLock.RUnlock()

	list := make([]*voter.Proposal, 0, len(m.executeProposal))
	for i := 0; i < len(m.executeProposal); i++ {
		list = append(list, m.executeProposal.Pop().(*voter.Proposal))
	}
	sort.Sort(NonceProposal(list))
	return list
}

func (m *MsgPool) IsInExecutePool(proposal *voter.Proposal) bool {
	for _, msg := range m.executeProposal {
		if msg.Hash().String() == proposal.Hash().String() {
			return true
		}
	}
	return false
}