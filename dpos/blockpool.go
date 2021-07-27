// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"errors"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

const cachedCount = 6

type DBlock interface {
	GetHash() common.Uint256
	GetHeight() uint64
	Nonce() uint64
}

type ConfirmInfo struct {
	Confirm *payload.Confirm
	Height  uint64
}

type BlockPool struct {
	sync.RWMutex
	blocks         map[common.Uint256]DBlock
	confirms       map[common.Uint256]*payload.Confirm
	heightConfirms map[uint64]*payload.Confirm
	badBlocks      map[common.Uint256]DBlock

	VerifyConfirm func(confirm *payload.Confirm, elaHeight uint64) error
	VerifyBlock   func(block DBlock) error
	SealHash      func(block DBlock) (common.Uint256, error)

	futureBlocks map[common.Uint256]DBlock
}

func NewBlockPool(verifyConfirm func(confirm *payload.Confirm, elaHeight uint64) error,
	verifyBlock func(block DBlock) error,
	sealHash func(block DBlock) (common.Uint256, error)) *BlockPool {
	return &BlockPool{
		blocks:         make(map[common.Uint256]DBlock),
		confirms:       make(map[common.Uint256]*payload.Confirm),
		heightConfirms: make(map[uint64]*payload.Confirm),
		badBlocks:      make(map[common.Uint256]DBlock),
		futureBlocks:   make(map[common.Uint256]DBlock),
		VerifyConfirm:  verifyConfirm,
		VerifyBlock:    verifyBlock,
		SealHash:       sealHash,
	}
}

func (bm *BlockPool) HandleParentBlock(parent DBlock) bool {
	bm.Lock()
	var handledBlock DBlock
	for _, block := range bm.futureBlocks {
		if block.GetHeight()-1 == parent.GetHeight() {
			handledBlock = block
			break
		}
	}
	bm.Unlock()
	if handledBlock != nil {
		bm.AppendDposBlock(handledBlock)
		return true
	}
	return false
}

func (bm *BlockPool) IsFutureBlock(hash common.Uint256) bool {
	bm.Lock()
	defer bm.Unlock()

	for _, block := range bm.futureBlocks {
		sealHash, err := bm.SealHash(block)
		if err != nil {
			return false
		}
		if sealHash.IsEqual(hash) {
			return true
		}
	}
	return false
}

func (bm *BlockPool) AddBadBlock(block DBlock) error {
	bm.Lock()
	defer bm.Unlock()

	hash, err := bm.SealHash(block)
	if err != nil {
		return err
	}
	if _, ok := bm.badBlocks[hash]; ok {
		return errors.New("duplicate badBlock in pool")
	}
	bm.badBlocks[hash] = block
	return nil
}

func (bm *BlockPool) IsBadBlockProposal(proposal *payload.DPOSProposal) bool {
	bm.Lock()
	defer bm.Unlock()
	hash := proposal.BlockHash
	if b, ok := bm.badBlocks[hash]; ok {
		log.Info("bad block propsoal", "height", b.GetHeight())
		return true
	}
	return false
}

func (bm *BlockPool) AppendFutureBlock(dposBlock DBlock) error {
	bm.Lock()
	defer bm.Unlock()

	return bm.appendFutureBlock(dposBlock)
}

func (bm *BlockPool) appendFutureBlock(block DBlock) error {
	hash, err := bm.SealHash(block)
	if err != nil {
		return err
	}
	if _, ok := bm.futureBlocks[hash]; ok {
		return errors.New("duplicate futureBlocks in pool")
	}
	bm.futureBlocks[hash] = block
	return nil
}

func (bm *BlockPool) AppendConfirm(confirm *payload.Confirm) error {
	bm.Lock()
	_, ok := bm.confirms[confirm.Proposal.BlockHash]
	bm.Unlock()
	if ok {
		return errors.New("conformation is all ready in block pool")
	}
	return bm.appendConfirm(confirm)
}

func (bm *BlockPool) AppendDposBlock(dposBlock DBlock) error {
	Info("[--AppendDposBlock--], height", dposBlock.GetHeight())
	return bm.appendBlock(dposBlock)
}

func (bm *BlockPool) appendBlock(block DBlock) error {
	// add block
	hash, err := bm.SealHash(block)
	if err != nil {
		return err
	}
	if bm.HasBlock(hash) {
		return errors.New("duplicate block in pool")
	}
	// verify block
	if err := bm.VerifyBlock(block); err != nil {
		Info("[AppendBlock] check block sanity failed, ", err)
		return err
	}
	bm.Lock()
	bm.blocks[hash] = block
	if _, ok := bm.futureBlocks[hash]; ok {
		delete(bm.futureBlocks, hash)
	}
	bm.Unlock()
	return nil
}

func (bm *BlockPool) appendConfirm(confirm *payload.Confirm) error {
	log.Info("[appendConfirm] start")
	defer Info("[appendConfirm] end")
	// verify confirmation
	dblock, ok := bm.GetBlock(confirm.Proposal.BlockHash)
	if !ok {
		return errors.New("appennd confirm error, not have DBlock")
	}
	if err := bm.VerifyConfirm(confirm, dblock.Nonce()); err != nil {
		return err
	}
	bm.Lock()
	bm.confirms[confirm.Proposal.BlockHash] = confirm
	bm.Unlock()
	err := bm.confirmBlock(confirm.Proposal.BlockHash)
	if err != nil {
		return err
	}

	return nil
}

func (bm *BlockPool) ConfirmBlock(hash common.Uint256) error {
	bm.Lock()
	err := bm.confirmBlock(hash)
	bm.Unlock()
	return err
}

func (bm *BlockPool) confirmBlock(hash common.Uint256) error {
	Info("[ConfirmBlock] block hash:", hash)
	bm.Lock()

	block, ok := bm.blocks[hash]
	if !ok {
		bm.Unlock()
		return errors.New("there is no block in pool when confirming block")
	}

	confirm, ok := bm.confirms[hash]
	if !ok {
		bm.Unlock()
		return errors.New("there is no block confirmation in pool when confirming block")
	}

	bm.heightConfirms[block.GetHeight()] = confirm
	bm.Unlock()

	return nil
}

func (bm *BlockPool) AddToBlockMap(block DBlock) {
	bm.Lock()
	defer bm.Unlock()

	hash, _ := bm.SealHash(block)

	bm.blocks[hash] = block
}

func (bm *BlockPool) HasBlock(hash common.Uint256) bool {
	_, ok := bm.GetBlock(hash)
	return ok
}

func (bm *BlockPool) HashConfirmed(number uint64) bool {
	bm.Lock()
	var temp DBlock = nil
	for _, block := range bm.blocks {
		if block.GetHeight() == number {
			temp = block
			break
		}
	}
	bm.Unlock()
	if temp != nil {
		hash, _ := bm.SealHash(temp)
		_, has := bm.GetConfirm(hash)
		return has
	}

	return false
}

func (bm *BlockPool) GetBlock(hash common.Uint256) (DBlock, bool) {
	bm.Lock()
	block, ok := bm.blocks[hash]
	bm.Unlock()
	return block, ok
}

func (bm *BlockPool) AddToConfirmMap(confirm *payload.Confirm) {
	bm.Lock()
	defer bm.Unlock()

	bm.confirms[confirm.Proposal.BlockHash] = confirm
}

func (bm *BlockPool) CleanFinalConfirmedBlock(height uint64) {
	bm.Lock()
	defer bm.Unlock()

	for _, block := range bm.blocks {
		hash, _ := bm.SealHash(block)
		if height > cachedCount && block.GetHeight() < height-cachedCount {
			delete(bm.blocks, hash)
			delete(bm.confirms, hash)
		}
	}

	for _, block := range bm.badBlocks {
		hash, _ := bm.SealHash(block)
		if height > cachedCount && block.GetHeight() < height-cachedCount {
			delete(bm.badBlocks, hash)
		}
	}

	for cheight, _ := range bm.heightConfirms {
		if height > cachedCount && cheight < height-cachedCount {
			delete(bm.heightConfirms, cheight)
		}
	}
}

func (bm *BlockPool) GetConfirmByHeight(height uint64) (*payload.Confirm, bool) {
	bm.Lock()
	defer bm.Unlock()

	confirm, ok := bm.heightConfirms[height]
	return confirm, ok
}

func (bm *BlockPool) GetConfirm(hash common.Uint256) (*payload.Confirm, bool) {
	bm.Lock()
	defer bm.Unlock()

	confirm, ok := bm.confirms[hash]
	return confirm, ok
}

func (bm *BlockPool) RemoveConfirm(hash common.Uint256) {
	bm.Lock()
	defer bm.Unlock()

	if _, ok := bm.confirms[hash]; ok {
		delete(bm.confirms, hash)
	}
}
