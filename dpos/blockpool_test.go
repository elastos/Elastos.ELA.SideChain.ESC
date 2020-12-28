// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

type BlockNonce [8]byte
// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}


type mockHeader struct {
	ParentHash common.Uint256
	Root       common.Uint256
	Timestamp  uint32
	Height     uint64
	Nonce      BlockNonce
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

func (b *mockBlock) Nonce() uint64 {
	return binary.BigEndian.Uint64(b.header.Nonce[:])
}

func (b *mockBlock) GetHash() common.Uint256 {
	buf := new(bytes.Buffer)
	b.header.Serialize(buf)
	return common.Sha256D(buf.Bytes())
}

func (b *mockBlock) GetHeight() uint64 {
	return b.header.Height
}

func verifyConfirm(confirm *payload.Confirm, elaHeight uint64) error {
	return nil
}

func verifyBlock(block DBlock) error {
	return nil
}

func sealHash(block DBlock) (common.Uint256, error) {
	return block.GetHash(), nil
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
	blockPool := NewBlockPool(verifyConfirm, verifyBlock, sealHash)
	size := rand.Intn(10) + 10

	blocks := make([]common.Uint256, 0)
	for i := 0; i < size; i++ {
		block := newTestBlock()
		hash, _ := sealHash(block)
		confirm := &payload.Confirm{
			Proposal: payload.DPOSProposal{BlockHash: hash},
		}

		blockPool.AppendDposBlock(block)
		blockPool.AppendConfirm(confirm)

		blocks = append(blocks, block.GetHash())
	}

	for i := 0; i < size; i++ {
		b, ok := blockPool.GetBlock(blocks[i])
		assert.NotNil(t, b)
		assert.True(t, ok)
	}
}
