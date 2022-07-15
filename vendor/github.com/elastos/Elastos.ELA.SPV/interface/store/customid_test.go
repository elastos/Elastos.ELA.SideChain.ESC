package store

import (
	"testing"

	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

func TestCustomID_GetConfirmCount(t *testing.T) {
	var currenHeight uint32
	var proposalHeight uint32
	var revertInfo []RevertInfo

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, false, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 100,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 200,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 200,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 300,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 200,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 300,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 900,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 200,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 300,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 900,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 200,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 300,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 1000,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 98,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 102,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 996,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, false, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 98,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 102,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 996,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 2000,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, false, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 200,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 300,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 400,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 500,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 2000,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 2000,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 3000,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 20,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 30,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 40,
			Mode:          byte(state.DPOS),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 20,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 30,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 110,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 120,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, true, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))

	currenHeight = 1000
	proposalHeight = 100
	revertInfo = []RevertInfo{
		{
			WorkingHeight: 10,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 20,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 30,
			Mode:          byte(state.POW),
		},
		{
			WorkingHeight: 110,
			Mode:          byte(state.DPOS),
		},
		{
			WorkingHeight: 115,
			Mode:          byte(state.POW),
		},
	}
	assert.Equal(t, false, isProposalConfirmed(currenHeight, proposalHeight, revertInfo))
}
