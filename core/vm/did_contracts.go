package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContractDID interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(evm *EVM, input []byte, gas uint64) ([]byte, error) // Run runs the precompiled contract
}

var PrecompileContractsDID = map[common.Address] PrecompiledContractDID {
	common.BytesToAddress([]byte{22}): &operationDID{},
}



// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContractDID(evm *EVM, p PrecompiledContractDID, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(input)
	if contract.UseGas(gas) {
		return p.Run(evm, input, contract.Gas)
	}
	return nil, ErrOutOfGas
}

type operationDID struct{}

func (j *operationDID) RequiredGas(input []byte) uint64 {
	return 1000
}

func (j *operationDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	data := getData(input, 64, uint64(len(input)) - 64)
	ttype := getData(input, 32, 32)
	dtype := new(big.Int).SetBytes(ttype)
	var didType = did.DIDType(dtype.Uint64())

	switch didType {
	case did.RegisterDID:
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
		err := checkRegisterDID(evm, doc)
		if err != nil {
			log.Error("checkRegisterDID error", "error", err)
			return false32Byte, err
		}

		id := rawdb.GetDIDFromUri(doc.PayloadInfo.ID)
		buf := new(bytes.Buffer)
		doc.Serialize(buf, did.DIDInfoVersion)
		evm.StateDB.AddDIDLog(id, byte(didType), buf.Bytes())
	case did.DeactivateDID:
		doc := new(did.DeactivateDIDOptPayload)
		if err := json.Unmarshal(data, doc); err != nil {
			return false32Byte, errors.New("createDIDVerify input is error")
		}
		err := checkDeactivateDID(evm, doc)
		if err != nil {
			log.Error("checkDeactivateDID error", "error", err)
			return false32Byte, err
		}

		id := rawdb.GetDIDFromUri(doc.Payload)
		buf := new(bytes.Buffer)
		doc.Serialize(buf, did.DIDInfoVersion)
		evm.StateDB.AddDIDLog(id, byte(didType), buf.Bytes())
	case did.CustomizedDID:
		doc := new(did.CustomizedDIDOperation)
		if err := json.Unmarshal(data, doc); err != nil {
			return false32Byte, errors.New("createDIDVerify input is error")
		}
		err := checkCustomizedDID(evm, doc, gas)
		if err != nil {
			log.Error("checkCustomizedDID error", "error", err)
			return false32Byte, err
		}
	case did.VerifiableCredentialTxType:

	case did.DeactivateCustomizedDIDTxType:
	default:
		return false32Byte, errors.New("error didType:" + didType.String())
	}

	return true32Byte, nil
}

