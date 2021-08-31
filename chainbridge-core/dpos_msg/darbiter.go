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

	ArbitersSignature []byte

	// Signature of the encode peer ID and cipher to proof the sender itself.
	Signature []byte
}

func (m *DArbiter) CMD() string {
	return CmdDArbiter
}

func (m *DArbiter) MaxLength() uint32 {
	return 387 // 33+33+256+65
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

	if err := common.WriteVarBytes(w, m.ArbitersSignature); err != nil {
		return err
	}

	return common.WriteVarBytes(w, m.Signature)
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

	m.ArbitersSignature, err = common.ReadVarBytes(r, crypto.SignatureLength,
		"DArbiter.ArbitersSignature")
	m.Signature, err = common.ReadVarBytes(r, crypto.SignatureLength,
		"DArbiter.Signature")
	return err
}

func (m *DArbiter) Data() []byte {
	b := new(bytes.Buffer)
	var timestamp = m.Timestamp.Unix()
	common.WriteElements(b, timestamp, m.Encode)
	common.WriteVarBytes(b, m.Cipher)
	common.WriteVarBytes(b, m.ArbitersSignature)
	return b.Bytes()
}

func (m *DArbiter) Hash() common.Uint256 {
	return common.Sha256D(m.Data())
}