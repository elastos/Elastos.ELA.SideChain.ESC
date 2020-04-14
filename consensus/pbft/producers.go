package pbft

import (
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
)

type Producers struct {
	producers []common.Address
	dutyIndex int
}

func NewProducers(producers []common.Address) *Producers {
	producer := &Producers{
		dutyIndex: 		  0,
	}
	producer.UpdateProducers(producers)
	return producer
}

func (p *Producers) UpdateProducers(producers []common.Address) error {
	p.producers = make([]common.Address, len(producers))
	copy(p.producers, producers)
	p.dutyIndex = 0
	return nil
}

func (p *Producers) GetProducers() []common.Address {
	list := make([]common.Address, len(p.producers))
	copy(list, p.producers)
	return list
}

func (p *Producers) IsProducers(signer *common.Address) bool {
	for _, producer := range p.producers {
		if signer.String() == producer.String() {
			return true
		}
	}
	return false
}

func (p *Producers) IsOnduty(signer *common.Address) bool {
	index := p.dutyIndex % len(p.producers)
	dutySigner := p.producers[index]
	return dutySigner.String() == signer.String()
}

func (p *Producers) ChangeHeight() {
	p.dutyIndex ++
}

func (p *Producers) GetDutyIndex() int {
	return p.dutyIndex
}