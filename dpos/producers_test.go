// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

func getRandProducers() [][]byte {
	size := rand.Intn(20) + 5
	signers := make([][]byte, size)
	for i := 0; i < size; i++ {
		data := make([]byte, 33)
		rand.Read(data)
		signers[i] = data
	}
	return signers
}

func TestNewProducers(t *testing.T) {
	signers := getRandProducers()
	p := NewProducers(signers, 0)
	producers := p.GetProducers()
	for i, v := range signers {
		assert.Equal(t, producers[i], v)
	}

	index := rand.Intn(len(signers))
	assert.True(t,  p.IsProducers(signers[index]))

	data := make([]byte, 33)
	rand.Read(data)
	assert.False(t,  p.IsProducers(data))

	signers = getRandProducers()

	peers := make([]peer.PID, 0)
	for _, arbiter := range signers {
		var pid peer.PID
		copy(pid[:], arbiter)
		peers = append(peers, pid)
	}
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i], signers[j]) < 0
	})

	p.UpdateNextProducers(peers, len(peers))

	var wg sync.WaitGroup
	wg.Add(4)
	height := rand.Uint64()
	svpHeight := rand.Uint64()
	p.ChangeCurrentProducers(height, svpHeight)
	go func() {
		p.ChangeCurrentProducers(height, svpHeight)
		wg.Done()
	}()
	go func() {
		p.ChangeCurrentProducers(height, svpHeight)
		wg.Done()
	}()

	go func() {
		producers = p.GetProducers()
		assert.Equal(t, len(producers), len(signers))
		for i, v := range signers {
			assert.True(t, bytes.Equal(producers[i], v))
		}

		assert.Equal(t, p.workingHeight, height)
		assert.Equal(t, p.spvHeight, svpHeight)
		wg.Done()
	}()

	go func() {
		producers = p.GetProducers()
		assert.Equal(t, len(producers), len(signers))
		for i, v := range signers {
			assert.True(t, bytes.Equal(producers[i], v))
		}
		assert.Equal(t, p.workingHeight, height)
		assert.Equal(t, p.spvHeight, svpHeight)
		wg.Done()
	}()

	wg.Wait()
}
