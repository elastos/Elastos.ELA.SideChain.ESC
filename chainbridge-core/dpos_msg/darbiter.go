package dpos_msg

import (
	"bytes"
	"io"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/p2p"
)

const (
	// maxCipherLength indicates the max length of the address cipher.
	maxCipherLength = 256
)

// Ensure BatchMsg implement p2p.Message interface.
var _ p2p.Message = (*DArbiter)(nil)

type DArbiter struct {
	// The peer ID indicates who's address it is.
	PID [33]byte

	// Timestamp represents the time when this message created.
	Timestamp time.Time

	// Which peer ID is used to encode the address cipher.
	Encode [33]byte

	// The encrypted network address using the encode peer ID.
	Cipher []byte

	// Signature of the encode peer ID and cipher to proof the sender itself.
	Signature []byte

	// is current consensus producers
	IsCurrent bool
}

func (m *DArbiter) CMD() string {
	return CmdDArbiter
}

func (m *DArbiter) MaxLength() uint32 {
	return 388 // 33+33+256+65 + 1
}

func (m *DArbiter) Serialize(w io.Writer) error {
	var timestamp = m.Timestamp.Unix()
	err := common.WriteElements(w, m.PID, timestamp, m.Encode)
	if err != nil {
		return err
	}

	if err := common.WriteVarBytes(w, m.Cipher); err != nil {
		return err
	}

	err = common.WriteVarBytes(w, m.Signature)
	if err != nil {
		return err
	}
	if m.IsCurrent == true {
		err = common.WriteUint8(w, 1)
	} else {
		err = common.WriteUint8(w, 0)
	}
	return err
}

func (m *DArbiter) Deserialize(r io.Reader) error {
	var timestamp int64
	err := common.ReadElements(r, &m.PID, &timestamp, &m.Encode)
	if err != nil {
		return err
	}
	m.Timestamp = time.Unix(timestamp, 0)

	m.Cipher, err = common.ReadVarBytes(r, maxCipherLength, "DArbiter.Cipher")
	if err != nil {
		return err
	}

	m.Signature, err = common.ReadVarBytes(r, crypto.SignatureLength,
		"DArbiter.Signature")

	res, err := common.ReadUint8(r)
	if err != nil {
		return err
	}
	if res == 1 {
		m.IsCurrent = true
	} else {
		m.IsCurrent = false
	}
	return err
}

func (m *DArbiter) Data() []byte {
	b := new(bytes.Buffer)
	var timestamp = m.Timestamp.Unix()
	common.WriteElements(b, timestamp, m.Encode)
	common.WriteVarBytes(b, m.Cipher)
	if m.IsCurrent == true {
		common.WriteUint8(b, 1)
	} else {
		common.WriteUint8(b, 0)
	}
	return b.Bytes()
}
