// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
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
	p.dutyIndex ++
	p.mtx.Unlock()
	str := "ChangeView-------------------\n"
	for _, signer := range p.producers {
		if p.IsOnduty(signer) {
			str = str + common.BytesToHexString(signer) + " onDuty \n"
		} else {
			str = str + common.BytesToHexString(signer) + " not onDuty \n"
		}

	}
	Info(str)
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

func (p *Producers) GetProducersCount() int {
	p.mtx.Lock()
	result := len(p.producers)
	p.mtx.Unlock()
	return result
}

func (p *Producers) IsMajorityAgree(count int) bool {
	return count >= p.GetMajorityCount()
	//TODO should use below condition
	//return count > p.GetMajorityCount()
}

func (p *Producers) IsMajorityRejected(count int) bool {
	num := len(p.producers)
	return count >= num - p.GetMajorityCount()
}