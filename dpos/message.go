package dpos

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

type ElaMsgType byte

const (
	DAddr ElaMsgType = iota
	Inv
	GetData
)

type MsgEvent struct {
	ElaMsg *ElaMsg
	Peer IPeer
}

type ElaMsg struct {
	Type ElaMsgType
	Msg  []byte
}

func (em *ElaMsg) Serialize(w io.Writer) error {
	if err := common.WriteUint8(w, uint8(em.Type)); err != nil {
		return err
	}

	return common.WriteVarBytes(w, em.Msg)
}

func (em *ElaMsg) Deserialize(r io.Reader) error {
	msgType, err := common.ReadUint8(r)
	if err != nil {
		return err
	}
	em.Type = ElaMsgType(msgType)

	newMsg, err := common.ReadVarBytes(r, common.MaxVarStringLength, "ElaMsg")
	if err != nil {
		return err
	}
	em.Msg = newMsg

	return nil
}