package voter

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge_abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/stretchr/testify/assert"
)

func TestProposal_Serialize(t *testing.T) {
	p := Proposal{
		Source: 1,
		DepositNonce: rand.Uint64(),
		ResourceId: common.Hash([]byte{1,2,3}),
		Data: []byte{1,2,3,4,5},
	}

	w := bytes.NewBuffer([]byte{})
	err := p.Serialize(w)
	assert.NoError(t, err)

	proposal := &Proposal{}
	proposal.Deserialize(w)

	assert.Equal(t, proposal.Source, p.Source)
	assert.Equal(t, proposal.DepositNonce, p.DepositNonce)
	assert.Equal(t, proposal.ResourceId, p.ResourceId)
	assert.Equal(t, proposal.Data, p.Data)

	assert.Equal(t, proposal.Hash(), p.Hash())
}

func Test_abiEncode(t *testing.T) {
	a, _ := chainbridge_abi.GetTestExecuteProposalAbi()

	nonceList := make([]uint64, 0)
	dataList := make([][]byte, 0)
	resourceID := make([][32]byte, 0)

	nonceList = append(nonceList, uint64(1))
	data, _ := common.HexStringToBytes("0000000000000000000000000000000000000000000000000429d069189e00000000000000000000000000000000000000000000000000000000000000000014534369554d1f1b36e5527793d67a7774a45bd8d1")
	dataList = append(dataList, data)
	resid, _ := common.HexStringToBytes("e86ee9f56944ada89e333f06eb40065a86b50a19c5c19dc94fe2d9e15cf947c8")
	var id [32]byte
	copy(id[:], resid[:])
	resourceID = append(resourceID, id)

	input, _ := a.Methods["test"].Inputs.Pack(uint8(80), nonceList, dataList, resourceID)
	hash := crypto.Keccak256Hash(input)

	uint8Type, _ := abi.NewType("uint8", "", nil)
	uint64ArrType, _ := abi.NewType("uint64[]", "", nil)
	bytesArray, _ := abi.NewType("bytes[]", "", nil)
	bytes32Array, _ := abi.NewType("bytes32[]", "", nil)
	argument := abi.Arguments{
		{
			Type: uint8Type,
		},
		{
			Type: uint64ArrType,
		},
		{
			Type: bytesArray,
		},
		{
			Type: bytes32Array,
		},
	}

	input, _ = argument.Pack(uint8(80), nonceList, dataList, resourceID)
	hash2 := crypto.Keccak256Hash(input)

	assert.Equal(t, hash, hash2)
}