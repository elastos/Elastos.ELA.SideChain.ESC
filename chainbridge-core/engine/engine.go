package engine

import (
	"github.com/elastos/Elastos.ELA/p2p"
)

type ESCEngine interface {
	IsOnduty() bool
	SendMsgProposal(proposalMsg p2p.Message)
	SignData(data []byte) []byte
	GetProducer() []byte
	GetTotalProducerCount() int
}