// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getRandProducers() [][]byte {
	size := rand.Intn(20) + 5
	signers := make([][]byte, size)
	for i := 0; i < size; i++ {
		data := make([]byte, 32)
		rand.Read(data)
		signers[i] = data
	}
	return signers
}

func TestNewProducers(t *testing.T) {
	signers := getRandProducers()
	p := NewProducers(signers)
	producers := p.GetProducers()
	for i, v := range signers {
		assert.Equal(t, producers[i], v)
	}

	index := rand.Intn(len(signers))
	assert.True(t,  p.IsProducers(signers[index]))

	data := make([]byte, 32)
	rand.Read(data)
	assert.False(t,  p.IsProducers(data))
}

func TestProducers_IsOnduty(t *testing.T) {
	signers := getRandProducers()
	p := NewProducers(signers)

	changeCount := rand.Intn(200)
	for i := 0; i < changeCount; i++ {
		p.ChangeView()
		signer := signers[(i + 1) %len(signers)]
		assert.True(t, p.IsOnduty(signer))
	}

	assert.Equal(t, p.GetDutyIndex(), changeCount)
}