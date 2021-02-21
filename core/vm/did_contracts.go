package vm

import (
	"encoding/json"
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContractDID interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(evm *EVM, input []byte) ([]byte, error) // Run runs the precompiled contract
}

var PrecompileContractsDID = map[common.Address] PrecompiledContractDID {
	common.BytesToAddress([]byte{22}): &operationDID{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContractDID(evm *EVM, p PrecompiledContractDID, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(input)
	if contract.UseGas(gas) {
		return p.Run(evm, input)
	}
	return nil, ErrOutOfGas
}

type operationDID struct{}

func (j *operationDID) RequiredGas(input []byte) uint64 {
	return 1000
}

func (j *operationDID) Run(evm *EVM, input []byte) ([]byte, error) {
	data := getData(input, 32, uint64(len(input)) - 32)
	doc := new(did.Operation)
	if err := json.Unmarshal(data, doc); err != nil {
		return false32Byte, errors.New("createDIDVerify input is error")
	}
	payloadBase64, _ := base64url.DecodeString(doc.Payload)
	payloadInfo := new(did.DIDPayloadInfo)
	if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
		return false32Byte, errors.New("createDIDVerify Payload is error")
	}
	doc.PayloadInfo = payloadInfo

	switch doc.Header.Operation {
	case did.Create_DID_Operation:
		err := checkRegisterDID(evm, doc)
		if err != nil {
			log.Error("checkRegisterDID error", "error", err)
			return false32Byte, err
		}
	case did.Update_DID_Operation:
	case did.Deactivate_DID_Operation:
	case did.Transfer_DID_Operation:
	default:
		return false32Byte, errors.New("error operation:" + doc.Header.Operation)
	}

	//buf := new(bytes.Buffer)
	//doc.Serialize(buf, did.DIDInfoVersion)

	//evm.StateDB.CreateDID(id, buf.Bytes())

	return true32Byte, nil
}

