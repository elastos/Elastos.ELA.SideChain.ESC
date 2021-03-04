package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common/math"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContractDID interface {
	RequiredGas(evm *EVM, input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(evm *EVM, input []byte, gas uint64) ([]byte, error) // Run runs the precompiled contract
}

var PrecompileContractsDID = map[common.Address] PrecompiledContractDID {
	common.BytesToAddress([]byte{22}): &operationDID{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContractDID(evm *EVM, p PrecompiledContractDID, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(evm, input)
	if contract.UseGas(gas) 	 {
		return p.Run(evm, input, contract.Gas)
	}
	log.Error("run did contract out of gas")
	return nil, ErrOutOfGas
}

type operationDID struct{}

func (j *operationDID) RequiredGas(evm *EVM, input []byte) uint64 {
	data := getData(input, 32, uint64(len(input)) - 32)
	p := new(did.DIDPayload)
	if err := json.Unmarshal(data, p); err != nil {
		log.Error("did document input is error", "input", string(data))
		return math.MaxUint64
	}
	if evm.GasPrice.Uint64() < params.DIDBaseGasprice {
		log.Error("gas price is too small", "need",  params.DIDBaseGasprice)
		return math.MaxUint64
	}
	payloadBase64, _ := base64url.DecodeString(p.Payload)
	payload := new(did.DIDDoc)
	if err := json.Unmarshal(payloadBase64, payload); err != nil {
		log.Error("payloadBase64 is error", "payloadBase64", payloadBase64)
		return math.MaxUint64
	}
	p.DIDDoc = payload
	buf := new(bytes.Buffer)
	p.Serialize(buf, did.DIDVersion)

	var needFee int64 = 0
	switch p.Header.Operation {
	case did.Create_DID_Operation, did.Update_DID_Operation, did.Transfer_DID_Operation:
		isRegisterDID := false
		if p.Header.Operation != did.Transfer_DID_Operation {
			isRegisterDID = isDID(p.DIDDoc)
		}
		if isRegisterDID {
			needFee = getIDTxFee(payload.ID, payload.Expires, p.Header.Operation, nil, buf.Len()).IntValue()
		} else {
			needFee = getIDTxFee(payload.ID, payload.Expires, p.Header.Operation, payload.Controller, buf.Len()).IntValue()
		}
	default:
		needFee = getIDTxFee(payload.ID, payload.Expires, p.Header.Operation, nil, buf.Len()).IntValue()
	}

	fe := new(big.Int).SetInt64(needFee)
	y := new(big.Int).SetInt64(did.FeeRate)
	ethFee := new(big.Int).Mul(fe, y)
	gas := new(big.Int).Quo(ethFee, new(big.Int).SetUint64(evm.GasPrice.Uint64()))
	return gas.Uint64()
}

func (j *operationDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	data := getData(input, 32, uint64(len(input)) - 32)
	p := new(did.DIDPayload)
	if err := json.Unmarshal(data, p); err != nil {
		log.Error("DIDPayload input is error", "input", string(data))
		return false32Byte, err
	}
	switch p.Header.Operation {
	case did.Create_DID_Operation, did.Update_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			return false32Byte, errors.New("createDIDVerify Payload is error")
		}
		p.DIDDoc = payloadInfo

		var err error
		isRegisterDID := isDID(p.DIDDoc)
		if isRegisterDID {
			err = checkRegisterDID(evm, p, gas)
			log.Error("checkRegisterDID error", "error", err)
		} else {
			err = checkCustomizedDID(evm, p, gas)
			log.Error("checkCustomizedDID error", "error", err)
		}
		if err != nil {
			return false32Byte, err
		}
		id := rawdb.GetDIDFromUri(p.DIDDoc.ID)
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(id, p.Header.Operation, buf.Bytes())
	case did.Transfer_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			return false32Byte, errors.New("createDIDVerify Payload is error")
		}
		p.DIDDoc = payloadInfo
		if err := checkCustomizedDID(evm, p, gas); err != nil {
			log.Error("checkCustomizedDID error", "error", err)
			return false32Byte, err
		}
	case did.Deactivate_DID_Operation:
		payloadBase64, _ := base64url.DecodeString(p.Payload)
		payloadInfo := new(did.DIDDoc)
		if err := json.Unmarshal(payloadBase64, payloadInfo); err != nil {
			log.Error("checkDeactivateDID Payload error", "error", err)
			return false32Byte, errors.New("checkDeactivateDID Payload is error")
		}
		p.DIDDoc = payloadInfo
		if err :=  checkDeactivateDID(evm, p); err != nil {
			log.Error("checkDeactivateDID error", "error", err)
			return false32Byte, err
		}
	case did.Declare_Verifiable_Credential_Operation, did.Revoke_Verifiable_Credential_Operation:
		if err := checkVerifiableCredential(evm, p); err != nil {
			log.Error("checkVerifiableCredential error", "error", err)
			return false32Byte, err
		}
	default:
		log.Error("error operation", "operation", p.Header.Operation)
		return false32Byte, errors.New("error operation:" + p.Header.Operation)
	}

	return true32Byte, nil
}

