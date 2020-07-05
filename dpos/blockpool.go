// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"errors"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/events"
)

const cachedCount = 6

type DBlock interface {
	GetHash() common.Uint256
	GetHeight() uint64
}

type ConfirmInfo struct {
	Confirm *payload.Confirm
	Height  uint64
}

type BlockPool struct {
	sync.RWMutex
	blocks   map[common.Uint256]DBlock
	confirms map[common.Uint256]*payload.Confirm

	OnConfirmBlock func(block DBlock, confirm *payload.Confirm) error
	VerifyConfirm  func(confirm *payload.Confirm) error
	VerifyBlock    func(block DBlock) error
	SealHash	func(block DBlock) (common.Uint256, error)

	futureBlocks map[common.Uint256]DBlock
}

func NewBlockPool(confirmBlock func(block DBlock, confirm *payload.Confirm) error,
	verifyConfirm func(confirm *payload.Confirm) error,
	verifyBlock func(block DBlock) error,
	sealHash func(block DBlock) (common.Uint256, error)) *BlockPool {
	return &BlockPool{
		blocks:         make(map[common.Uint256]DBlock),
		confirms:       make(map[common.Uint256]*payload.Confirm),
		futureBlocks:   make(map[common.Uint256]DBlock),
		OnConfirmBlock: confirmBlock,
		VerifyConfirm:  verifyConfirm,
		VerifyBlock:    verifyBlock,
		SealHash: sealHash,
	}
}

func (bm *BlockPool) HandleParentBlock(parent DBlock) bool {
	for _, block := range bm.futureBlocks {
		if block.GetHeight() - 1 == parent.GetHeight() {
			bm.AppendDposBlock(block)
			return true
		}
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
	defer bm.Unlock()

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

	// verify confirmation
	if err := bm.VerifyConfirm(confirm); err != nil {
		return err
	}
	bm.confirms[confirm.Proposal.BlockHash] = confirm

	err := bm.confirmBlock(confirm.Proposal.BlockHash)
	if err != nil {
		return err
	}
	block := bm.blocks[confirm.Proposal.BlockHash]

	// notify new confirm accepted.
	events.Notify(events.ETConfirmAccepted, &ConfirmInfo{
		Confirm: confirm,
		Height:  block.GetHeight(),
	})

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

	block, ok := bm.blocks[hash]
	if !ok {
		return errors.New("there is no block in pool when confirming block")
	}

	confirm, ok := bm.confirms[hash]
	if !ok {
		return errors.New("there is no block confirmation in pool when confirming block")
	}

	if bm.OnConfirmBlock != nil {
		err := bm.OnConfirmBlock(block, confirm)
		if err != nil {
			return err
		}
	} else {
		panic("Not set OnConfirmBlock callBack")
	}

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
		if height > cachedCount && block.GetHeight() < height - cachedCount {
			delete(bm.blocks, hash)
			delete(bm.confirms, hash)
		}
	}
}

func (bm *BlockPool) GetConfirm(hash common.Uint256) (*payload.Confirm, bool) {
	bm.Lock()
	defer bm.Unlock()

	confirm, ok := bm.confirms[hash]
	return confirm, ok
}
