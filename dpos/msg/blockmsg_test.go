// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

type mockHeader struct {
	ParentHash  common.Uint256
	Root        common.Uint256
	Timestamp   uint32
	Height      uint64
}

type mockBlock struct {
	header *mockHeader
	txs []*mockTransaction
}

func (b *mockBlock) Serialize(w io.Writer) error {
	err := b.header.ParentHash.Serialize(w)
	if err != nil {
		return err
	}
	err = b.header.Root.Serialize(w)
	if err != nil {
		return err
	}
	err = common.WriteUint32(w, b.header.Timestamp)
	if err != nil {
		return err
	}
	err = common.WriteUint64(w, b.header.Height)
	if err != nil {
		return err
	}
	common.WriteVarUint(w, uint64(len(b.txs)))
	for _, tx := range b.txs {
		err = tx.From.Serialize(w)
		if err != nil {
			return err
		}
		err = tx.To.Serialize(w)
		if err != nil {
			return err
		}
		err = common.WriteUint64(w, tx.Value)
		if err != nil {
			return err
		}
		err = common.WriteVarBytes(w, tx.Sign)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *mockBlock) Deserialize(r io.Reader) error {
	err := b.header.ParentHash.Deserialize(r)
	if err != nil {
		return err
	}
	err = b.header.Root.Deserialize(r)
	if err != nil {
		return err
	}
	b.header.Timestamp, err = common.ReadUint32(r)
	if err != nil {
		return err
	}
	b.header.Height, err = common.ReadUint64(r)
	if err != nil {
		return err
	}
	len, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	for i := 0; uint64(i) < len; i++ {
		tx := &mockTransaction{}
		err = tx.From.Deserialize(r)
		if err != nil {
			return err
		}
		err = tx.To.Deserialize(r)
		if err != nil {
			return err
		}
		tx.Value, err = common.ReadUint64(r)
		if err != nil {
			return err
		}
		tx.Sign, err = common.ReadVarBytes(r, 64, "")
		b.txs = append(b.txs, tx)
	}
	return nil
}

type mockTransaction struct {
	From  common.Uint168
	To    common.Uint168
	Value uint64
	Sign  []byte
}

func (tx *mockTransaction) Serialize(w io.Writer) error {
	err := tx.From.Serialize(w)
	if err != nil {
		return err
	}
	err = tx.To.Serialize(w)
	if err != nil {
		return err
	}
	err = common.WriteUint64(w, tx.Value)
	if err != nil {
		return err
	}
	err = common.WriteVarBytes(w, tx.Sign)
	return err
}

func (tx *mockTransaction) Deserialize(r io.Reader) error {
	err := tx.From.Deserialize(r)
	if err != nil {
		return err
	}
	err = tx.To.Deserialize(r)
	if err != nil {
		return err
	}
	tx.Value, err = common.ReadUint64(r)
	if err != nil {
		return err
	}
	tx.Sign, err = common.ReadVarBytes(r, 64, "")
	return err
}

func randomUint168() *common.Uint168 {
	randBytes := make([]byte, 21)
	rand.Read(randBytes)
	result, _ := common.Uint168FromBytes(randBytes)

	return result
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
		Root: *randomUint256(),
		Timestamp: rand.Uint32(),
		Height: rand.Uint64(),
	}

	txs := make([]*mockTransaction, 0)
	len := rand.Intn(10)
	for i := 0; i < len; i++ {
		sign := make([]byte, 64)
		rand.Read(sign)
		tx := &mockTransaction{
			From: *randomUint168(),
			To: *randomUint168(),
			Value: rand.Uint64(),
			Sign: sign,
		}
		txs = append(txs, tx)
	}

	block := &mockBlock{
		header: header,
		txs: txs,
	}
	return block
}

func TestBlockMsg(t *testing.T) {
	b1 := newTestBlock()
	buffer := new(bytes.Buffer)
	err := b1.Serialize(buffer)
	assert.NoError(t, err)

	msg1 := NewBlockMsg(buffer.Bytes())
	msgBuffer := new(bytes.Buffer)
	err = msg1.Serialize(msgBuffer)
	assert.NoError(t, err)

	msg2 := NewBlockMsg([]byte{})
	err = msg2.Deserialize(msgBuffer)
	assert.NoError(t, err)

	assert.Equal(t, msg1.GetData(), msg2.GetData())

	b2 := &mockBlock{
		header: &mockHeader{},
		txs: make([]*mockTransaction, 0),
	}

	r := bytes.NewBuffer(msg2.GetData())
	err = b2.Deserialize(r)
	assert.NoError(t, err)
	assert.Equal(t, b1, b2)
}