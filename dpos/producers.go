// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
)

var defaultCRCSignerNumber = 12
var zero = common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000000000")

type Producers struct {
	totalProducers int
	producers      [][]byte
	dutyIndex      uint32
	workingHeight  uint64
	spvHeight      uint64

	nextTotalProducers int
	nextProducers      []peer.PID
	mtx                sync.Mutex
}

func NewProducers(producers [][]byte, startHeight uint64) *Producers {
	producer := &Producers{
		dutyIndex:     0,
		workingHeight: startHeight,
	}
	defaultCRCSignerNumber = len(producers)
	producer.UpdateProducers(producers, len(producers), 0)
	return producer
}

func (p *Producers) UpdateProducers(producers [][]byte, totalCount int, spvHeight uint64) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.producers = make([][]byte, len(producers))
	copy(p.producers, producers)
	p.totalProducers = totalCount
	p.spvHeight = spvHeight
	return nil
}

func (p *Producers) ChangeCurrentProducers(changeHeight uint64, spvHeight uint64) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.producers = make([][]byte, len(p.nextProducers))

	for i, signer := range p.nextProducers {
		if bytes.Equal(signer[:], zero) {
			continue
		}
		p.producers[i] = make([]byte, len(signer))
		copy(p.producers[i][:], signer[:])
	}
	p.SetWorkingHeight(changeHeight)
	p.totalProducers = p.nextTotalProducers
	p.spvHeight = spvHeight

}

func (p *Producers) SetWorkingHeight(changeHeight uint64) {
	p.workingHeight = changeHeight
}

func (p *Producers) UpdateNextProducers(producers []peer.PID, totalCount int) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	sort.Slice(producers, func(i, j int) bool {
		return bytes.Compare(producers[i][:], producers[j][:]) < 0
	})
	p.nextProducers = []peer.PID{}
	p.nextProducers = make([]peer.PID, len(producers))
	copy(p.nextProducers[:], producers[:])
	p.nextTotalProducers = totalCount
	return nil
}

func (p *Producers) GetNeedConnectArbiters() []peer.PID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	pids := make([]peer.PID, 0)
	for _, producer := range p.producers {
		var pid peer.PID
		copy(pid[:], producer)
		pids = append(pids, pid)
	}

	for _, producer := range p.nextProducers {
		var pid peer.PID
		copy(pid[:], producer[:])
		pids = append(pids, pid)
	}
	return pids
}

func (p *Producers) getCurrentNeedConnectArbiters() []peer.PID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	pids := make([]peer.PID, 0)
	for _, producer := range p.producers {
		var pid peer.PID
		copy(pid[:], producer)
		pids = append(pids, pid)
	}
	return pids
}

func (p *Producers) GetNextNeedConnectArbiters() []peer.PID {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	pids := make([]peer.PID, 0)
	for _, producer := range p.nextProducers {
		var pid peer.PID
		copy(pid[:], producer[:])
		pids = append(pids, pid)
	}
	return pids
}

func (p *Producers) UpdateDutyIndex(height uint64) uint32 {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if len(p.producers) <= 0 {
		return 0
	}
	index := (height + 1 - p.workingHeight) % uint64(len(p.producers))
	p.dutyIndex = uint32(index)
	return uint32(index)
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

func (p *Producers) ProducerIndex(signer []byte) int {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	for index, producer := range p.producers {
		if bytes.Equal(producer, signer) {
			return index
		}
	}
	return -1
}

func (p *Producers) GetMajorityCount() int {
	p.mtx.Lock()
	minSignCount := int(float64(p.totalProducers) * 2 / 3)
	p.mtx.Unlock()
	return minSignCount

}

func (p *Producers) GetCRMajorityCount() int {
	return p.GetMajorityCountByTotalSigners(defaultCRCSignerNumber)
}

func (p *Producers) GetMajorityCountByTotalSigners(totalSigner int) int {
	p.mtx.Lock()
	minSignCount := int(float64(totalSigner) * 2 / 3)
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
	index := (p.dutyIndex + offset) % uint32(len(producers))
	producer := producers[index]

	return producer
}

func (p *Producers) IsMajorityAgree(count int) bool {
	return count > p.GetMajorityCount()
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
