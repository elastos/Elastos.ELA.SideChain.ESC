package dpos_msg

import (
	"bytes"
	"errors"
	"io"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/p2p"
)


// Ensure BatchMsg implement p2p.Message interface.
var _ p2p.Message = (*BatchMsg)(nil)

type BatchMsg struct {
	Items []DepositItem

	Proposer  []byte
	Signature []byte

	PID peer.PID
}

func (m *BatchMsg) CMD() string {
	return CmdBatchProposal
}

func (m *BatchMsg) MaxLength() uint32 {
	return 8000 * 100
}

func (m *BatchMsg) SerializeUnsigned(w io.Writer) error {
	count := len(m.Items)
	elaCom.WriteUint8(w, uint8(count))
	for i := 0; i < count; i++ {
		item := m.Items[i]
		if err := elaCom.WriteUint8(w, item.SourceChainID); err != nil {
			return err
		}
		if err := elaCom.WriteUint8(w, item.DestChainID); err != nil {
			return err
		}
		if err := elaCom.WriteUint64(w, item.DepositNonce); err != nil {
			return err
		}
		if err := elaCom.WriteVarBytes(w, item.ResourceId[:]); err != nil {
			return err
		}
		if err := elaCom.WriteVarBytes(w, item.Data); err != nil {
			return err
		}
	}

	return nil
}

func (m *BatchMsg) Serialize(w io.Writer) error {
	if err := m.SerializeUnsigned(w); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Proposer); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Signature); err != nil {
		return err
	}

	return nil
}

func (m *BatchMsg) Deserialize(r io.Reader) error {
	count, err := elaCom.ReadUint8(r)
	if err != nil {
		return err
	}
	m.Items = make([]DepositItem, count, count)
	for i := 0; i < int(count); i++ {
		source, err := elaCom.ReadUint8(r)
		if err != nil {
			return err
		}
		m.Items[i].SourceChainID = source

		dest, err := elaCom.ReadUint8(r)
		if err != nil {
			log.Error("DepositProposalMsg Deserialize DestChainID error", "error", err)
			return err
		}
		m.Items[i].DestChainID = dest

		nonce, err := elaCom.ReadUint64(r)
		if err != nil {
			log.Error("DepositProposalMsg Deserialize nonce error", "error", err)
			return err
		}
		m.Items[i].DepositNonce = nonce

		resource, err := elaCom.ReadVarBytes(r, 32, "resourceID")
		if err != nil {
			log.Error("DepositProposalMsg Deserialize resourceID error", "error", err)
			return err
		}
		copy(m.Items[i].ResourceId[:], resource[:])
		data, err := elaCom.ReadVarBytes(r, 1000, "data")
		if err != nil {
			log.Error("DepositProposalMsg Deserialize data error", "error", err)
			return err
		}
		m.Items[i].Data = data
	}

	proposer, err := elaCom.ReadVarBytes(r, 33, "proposers")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize proposer error", "error", err)
		return err
	}
	m.Proposer = proposer
	signature, err := elaCom.ReadVarBytes(r, 65, "signature")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize signature error", "error", err)
		return err
	}
	m.Signature = signature
	return nil
}

func (m *BatchMsg) GetData(w io.Writer) error {
	count := len(m.Items)
	if count < 1 {
		return errors.New("batch msg items is empty")
	}

	chainID := big.NewInt(0).SetUint64(uint64(m.Items[0].SourceChainID)).Bytes()
	if _, err := w.Write(common.LeftPadBytes(chainID, 32)); err != nil {
		return err
	}

	for i := 0; i < count; i++ {
		nonce := big.NewInt(0).SetUint64(m.Items[i].DepositNonce).Bytes()
		if _, err := w.Write(common.LeftPadBytes(nonce, 32)); err != nil {
			return err
		}

		if _, err := w.Write(m.Items[i].ResourceId[:]); err != nil {
			return err
		}

		if _, err := w.Write(m.Items[i].Data); err != nil {
			return err
		}
	}

	return nil
}

func (m *BatchMsg) GetHash() (hash common.Hash) {
	w := bytes.NewBuffer([]byte{})
	err := m.GetData(w)
	if err != nil {
		log.Error("Proposal Serialize error", "error", err)
		return hash
	}
	hash = crypto.Keccak256Hash(w.Bytes())
	log.Info("BatchMsg hash", hash.String())
	return hash
}

