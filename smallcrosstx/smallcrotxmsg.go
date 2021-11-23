package smallcrosstx

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

type SmallCrossTx struct {
	RawTxID string
	RawTx string
	Signatures []string
	BlockHeight uint64
}

func NewSmallCrossTx() *SmallCrossTx {
	tx := &SmallCrossTx{
		RawTxID: "",
		RawTx: "",
		Signatures: nil,
		BlockHeight: 0,
	}
	return tx
}

func (ct *SmallCrossTx) Serialize(w io.Writer) error {
	err := common.WriteVarString(w, ct.RawTxID)
	if err != nil {
		return err
	}
	err = common.WriteVarString(w, ct.RawTx)
	if err != nil {
		return err
	}
	count := len(ct.Signatures)
	err = common.WriteUint8(w, uint8(count))
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		err = common.WriteVarString(w, ct.Signatures[i])
		if err != nil {
			return err
		}
	}
	err = common.WriteUint64(w, ct.BlockHeight)
	if err != nil {
		return err
	}
	return err
}

func (ct *SmallCrossTx) Deserialize(r io.Reader) error {
	rawID, err := common.ReadVarString(r)
	if err != nil {
		return err
	}
	rawTx, err := common.ReadVarString(r)
	if err != nil {
		return err
	}
	count, err := common.ReadUint8(r)
	if err != nil {
		return err
	}
	ct.Signatures = make([]string, 0)
	for i := 0; i < int(count); i++ {
		sig, err := common.ReadVarString(r)
		if err != nil {
			return err
		}
		ct.Signatures = append(ct.Signatures, sig)
	}
	height, err := common.ReadUint64(r)
	if err != nil {
		return err
	}
	ct.RawTxID = rawID
	ct.RawTx = rawTx
	ct.BlockHeight = height
	return nil
}

func (ct *SmallCrossTx) VerifiedSignature(sig string) bool {
	for _, signature := range ct.Signatures {
		if signature == sig {
			return true
		}
	}
	return false
}

type ETSmallCrossTx struct {
	RawTx string
	Signature string
}