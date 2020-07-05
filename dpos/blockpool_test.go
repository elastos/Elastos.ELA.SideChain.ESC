// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

type mockHeader struct {
	ParentHash common.Uint256
	Root       common.Uint256
	Timestamp  uint32
	Height     uint64
}

func (h *mockHeader) Serialize(w io.Writer) error {
	err := h.ParentHash.Serialize(w)
	if err != nil {
		return err
	}
	err = h.Root.Serialize(w)
	if err != nil {
		return err
	}
	err = common.WriteUint32(w, h.Timestamp)
	if err != nil {
		return err
	}
	err = common.WriteUint64(w, h.Height)
	if err != nil {
		return err
	}

	return nil
}

type mockTransaction struct {
	From  common.Uint168
	To    common.Uint168
	Value uint64
	Sign  []byte
}

type mockBlock struct {
	header *mockHeader
	txs    []*mockTransaction
}

func (b *mockBlock) GetHash() common.Uint256 {
	buf := new(bytes.Buffer)
	b.header.Serialize(buf)
	return common.Sha256D(buf.Bytes())
}

func (b *mockBlock) GetHeight() uint64 {
	return b.header.Height
}

func onConfirmBlock(block DBlock, confirm *payload.Confirm) error {
	return nil
}

func verifyConfirm(confirm *payload.Confirm) error {
	return nil
}

func verifyBlock(block DBlock) error {
	return nil
}

func sealHash(block DBlock) (common.Uint256, error) {
	return common.EmptyHash, nil
}

func randomUint256() *common.Uint256 {
	randBytes := make([]byte, 32)
	rand.Read(randBytes)
	result, _ := common.Uint256FromBytes(randBytes)

	return result
}

func newTestBlock() *mockBlock {
	header := &mockHeader{
		ParentHash: *randomUint256(),
		Root:       *randomUint256(),
		Timestamp:  rand.Uint32(),
		Height:     rand.Uint64(),
	}

	block := &mockBlock{
		header: header,
	}
	return block
}

func TestBlockPool_AppendDposBlock(t *testing.T) {
	blockPool := NewBlockPool(onConfirmBlock, verifyConfirm, verifyBlock, sealHash)
	size := rand.Intn(10) + 10

	blocks := make([]common.Uint256, 0)
	for i := 0; i < size; i++ {
		block := newTestBlock()
		confirm := &payload.Confirm{
			Proposal: payload.DPOSProposal{BlockHash: block.GetHash()},
		}
		blockPool.AppendConfirm(confirm)
		blockPool.AppendDposBlock(block)
		blocks = append(blocks, block.GetHash())
	}

	for i := 0; i < size; i++ {
		b, ok := blockPool.GetBlock(blocks[i])
		assert.NotNil(t, b)
		assert.True(t, ok)
	}
}
