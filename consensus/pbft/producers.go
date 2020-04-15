package pbft

import (
	"bytes"
	"sync"
)

type Producers struct {
	producers [][]byte
	dutyIndex int
	mtx       sync.Mutex
}

func NewProducers(producers [][]byte) *Producers {
	producer := &Producers{
		dutyIndex: 		  0,
	}
	producer.UpdateProducers(producers)
	return producer
}

func (p *Producers) UpdateProducers(producers [][]byte) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.producers = make([][]byte, len(producers))
	copy(p.producers, producers)
	p.dutyIndex = 0
	return nil
}

func (p *Producers) GetProducers() [][]byte {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	list := make([][]byte, len(p.producers))
	copy(list, p.producers)
	return list
}

func (p *Producers) IsProducers(signer []byte) bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	for _, producer := range p.producers {
		if bytes.Equal(producer, signer) {
			return true
		}
	}
	return false
}

func (p *Producers) IsOnduty(signer []byte) bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	index := p.dutyIndex % len(p.producers)
	dutySigner := p.producers[index]
	return bytes.Equal(dutySigner, signer)
}

func (p *Producers) ChangeView() {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.dutyIndex ++
}

func (p *Producers) GetDutyIndex() int {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	index := p.dutyIndex
	return index
}

func (p *Producers) GetMajorityCount() int {
	p.mtx.Lock()
	minSignCount := int(float64(len(p.producers)) * 2 / 3)
	p.mtx.Unlock()
	return minSignCount

}

func (p *Producers) IsMajorityAgree(count int) bool {
	num := len(p.producers)
	return num > p.GetMajorityCount()
}

func (p *Producers) IsMajorityRejected(count int) bool {
	num := len(p.producers)
	return count >= num - p.GetMajorityCount()
}