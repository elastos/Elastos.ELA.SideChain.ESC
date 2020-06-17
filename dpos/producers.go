// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"sync"
)

type Producers struct {
	producers [][]byte
	mtx       sync.Mutex
}

func NewProducers(producers [][]byte) *Producers {
	producer := &Producers{
	}
	producer.UpdateProducers(producers)
	return producer
}

func (p *Producers) UpdateProducers(producers [][]byte) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.producers = make([][]byte, len(producers))
	copy(p.producers, producers)
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

func (p *Producers) GetMajorityCount() int {
	p.mtx.Lock()
	minSignCount := int(float64(len(p.producers)) * 2 / 3)
	p.mtx.Unlock()
	return minSignCount

}

func (p *Producers) GetProducersCount() int {
	p.mtx.Lock()
	result := len(p.producers)
	p.mtx.Unlock()
	return result
}

func (p *Producers) GetNextOnDutyProducer(offset uint32) []byte {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	producers := p.producers
	if len(producers) == 0 {
		return nil
	}
	index := int(offset) % len(producers)
	producer := producers[index]

	return producer
}

func (p *Producers) IsMajorityAgree(count int) bool {
	return count >= p.GetMajorityCount()
	//TODO should use below condition
	//return count > p.GetMajorityCount()
}

func (p *Producers) IsMajorityRejected(count int) bool {
	num := len(p.producers)
	return count >= num-p.GetMajorityCount()
}

func (p *Producers) HasProducerMajorityCount(num int) bool {
	return num > p.GetMajorityCount()
}

func (p *Producers) HasArbitersMinorityCount(num int) bool {
	p.mtx.Lock()
	count := len(p.producers)
	p.mtx.Unlock()
	return num >= count-p.GetMajorityCount()
}
