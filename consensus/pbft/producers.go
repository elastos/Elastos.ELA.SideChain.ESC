package pbft

import (
	"bytes"
)

type Producers struct {
	producers [][]byte
	dutyIndex int
}

func NewProducers(producers [][]byte) *Producers {
	producer := &Producers{
		dutyIndex: 		  0,
	}
	producer.UpdateProducers(producers)
	return producer
}

func (p *Producers) UpdateProducers(producers [][]byte) error {
	p.producers = make([][]byte, len(producers))
	copy(p.producers, producers)
	p.dutyIndex = 0
	return nil
}

func (p *Producers) GetProducers() [][]byte {
	list := make([][]byte, len(p.producers))
	copy(list, p.producers)
	return list
}

func (p *Producers) IsProducers(signer []byte) bool {
	for _, producer := range p.producers {
		if bytes.Equal(producer, signer) {
			return true
		}
	}
	return false
}

func (p *Producers) IsOnduty(signer []byte) bool {
	index := p.dutyIndex % len(p.producers)
	dutySigner := p.producers[index]
	return bytes.Equal(dutySigner, signer)
}

func (p *Producers) ChangeHeight() {
	p.dutyIndex ++
}

func (p *Producers) GetDutyIndex() int {
	return p.dutyIndex
}