package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/internal/didapi"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"

	elacom "github.com/elastos/Elastos.ELA/common"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContractDID interface {
	RequiredGas(evm *EVM, input []byte) uint64              // RequiredPrice calculates the contract gas use
	Run(evm *EVM, input []byte, gas uint64) ([]byte, error) // Run runs the precompiled contract
}

var PrecompileContractsDID = map[common.Address]PrecompiledContractDID{
	common.BytesToAddress([]byte{22}): &operationDID{},
	common.BytesToAddress([]byte{23}): &resolveDID{},
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContractDID(evm *EVM, p PrecompiledContractDID, input []byte, contract *Contract) (ret []byte, err error) {
	gas := p.RequiredGas(evm, input)
	if contract.UseGas(gas) {
		return p.Run(evm, input, contract.Gas)
	}
	log.Error("run did contract out of gas")
	return nil, ErrOutOfGas
}

type operationDID struct{}

func (j *operationDID) RequiredGas(evm *EVM, input []byte) uint64 {
	return params.DIDBaseGasCost
}

func checkPublicKey(publicKey            *did.DIDPublicKeyInfo )error{
	if  publicKey.ID == ""{
		return errors.New("check Doc PublicKey ID is empty")
	}
	if  publicKey.PublicKeyBase58 == ""{
		return  errors.New("check Doc PublicKey PublicKeyBase58 is empty")
	}
	return nil
}

func checkAuthen(didWithPrefix string, authen       []interface{}, publicKey []did.DIDPublicKeyInfo)(error){
	//auth should not be empty
	if len(authen) == 0 {
		return errors.New("did doc Authentication is nil")
	}
	masterPubKeyVerifyOk := false
	//auth embed public must accord with checkPublicKey
	didAddress := did.GetDIDFromUri(didWithPrefix)
	for _, auth := range authen {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			for i := 0; i < len(publicKey); i++ {
				//if this is not my public key ignore.
				if publicKey[i].Controller != "" && publicKey[i].Controller !=  didWithPrefix {
					continue
				}
				if verificationMethodEqual(publicKey[i].ID, keyString) {
					if did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, didAddress){
						masterPubKeyVerifyOk = true
					}
				}
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return errors.New("checkAuthen Marshal auth error")
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return  errors.New("checkAuthen Unmarshal DIDPublicKeyInfo error")
			}
			if err := checkPublicKey(didPublicKeyInfo); err != nil{
				return  err
			}
			for i := 0; i < len(publicKey); i++ {
				//if this is not my public key ignore.
				if publicKey[i].Controller != "" && publicKey[i].Controller !=  didWithPrefix {
					continue
				}
				if verificationMethodEqual(publicKey[i].ID, didPublicKeyInfo.ID) {
					if did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, didAddress){
						masterPubKeyVerifyOk = true
					}
				}
			}
		}
	}
	if !masterPubKeyVerifyOk{
		return  errors.New("authen at least have one master public key")

	}
	return   nil
}

func isPublicKeyIDUnique(p *did.DIDPayload)bool{
	// New empty IDSet
	IDSet := make(map[string]bool)
	for i := 0; i < len(p.DIDDoc.PublicKey); i++ {
		//get uri fregment
		_,uriFregment := did.GetController(p.DIDDoc.PublicKey[i].ID)
		//
		if _,ok := IDSet[uriFregment]; ok{
			return false
		}
		IDSet[uriFregment] = true
	}

	for _, auth := range p.DIDDoc.Authentication {
		switch auth.(type) {
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return false
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return false
			}
			//get uri fregment
			_,uriFregment := did.GetController(didPublicKeyInfo.ID)
			//
			if _,ok := IDSet[uriFregment]; ok{
				return false
			}
			IDSet[uriFregment] = true
		default:
			continue
		}
	}
	return true
}

func  checkPayloadSyntax(p *did.DIDPayload) error {
	// check proof
	if p.Proof.VerificationMethod == "" {
		return errors.New("proof Creator is nil")
	}
	if p.Proof.Signature == "" {
		return errors.New("proof Created is nil")
	}
	if p.DIDDoc != nil {
		if !isPublicKeyIDUnique(p) {
			return errors.New("doc public key id is not unique")
		}
		if err := checkAuthen(p.DIDDoc.ID, p.DIDDoc.Authentication, p.DIDDoc.PublicKey); err != nil {
			return err
		}
		if p.DIDDoc.Expires == "" {
			return errors.New("did doc Expires is nil")
		}

		for _, pkInfo := range p.DIDDoc.PublicKey {
			if err := checkPublicKey(&pkInfo); err != nil{
				return err
			}
		}
		DIDProofArray, err := getDocProof(p.DIDDoc.Proof)
		if err != nil {
			return err
		}
		for _, proof := range DIDProofArray {
			if proof.Creator == "" {
				return errors.New("proof Creator is null")
			}
			if proof.Created == "" {
				return errors.New("proof Created is null")
			}
			if proof.SignatureValue == "" {
				return errors.New("proof SignatureValue is null")
			}
		}
	}
	return nil
}


func (j *operationDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	//block height from context BlockNumber. config height address from config

	configHeight := evm.chainConfig.OldDIDMigrateHeight
	configAddr := evm.chainConfig.OldDIDMigrateAddr
	senderAddr := evm.Context.Origin.String()
	log.Info("####", "configAddr", configAddr, "senderAddr", senderAddr)

	//BlockNumber <= configHeight senderAddr must be configAddr
	if evm.Context.BlockNumber.Cmp(configHeight) <= 0 {
		if senderAddr != configAddr {
			log.Info("#### BlockNumber.Cmp(configHeight) <= 0 or callerAddress.String() != configAddr")
			return false32Byte, errors.New("Befor configHeight only configAddr can send DID tx")
		}
	} else {
		if senderAddr == configAddr {
			log.Info("#### BlockNumber.Cmp(configHeight) > 0 callerAddress.String() should not configAddr")
			return false32Byte, errors.New("after configHeight  configAddr can not send migrate DID tx")
		}
	}

	data := getData(input, 32, uint64(len(input))-32)
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
			if err = checkRegisterDID(evm, p, gas); err != nil {
				log.Error("checkRegisterDID error", "error", err, "ID", p.DIDDoc.ID)
			}
		} else {
			if err = checkCustomizedDID(evm, p, gas); err != nil {
				log.Error("checkCustomizedDID error", "error", err, "ID", p.DIDDoc.ID)
			}
		}
		if err != nil {
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.DIDDoc.ID, p.Header.Operation, buf.Bytes())
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
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.DIDDoc.ID, p.Header.Operation, buf.Bytes())
	case did.Deactivate_DID_Operation:
		if err := checkDeactivateDID(evm, p); err != nil {
			log.Error("checkDeactivateDID error", "error", err)
			return false32Byte, err
		}
		id := p.Payload
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(id, p.Header.Operation, buf.Bytes())
	case did.Declare_Verifiable_Credential_Operation, did.Revoke_Verifiable_Credential_Operation:
		if err := checkVerifiableCredential(evm, p); err != nil {
			log.Error("checkVerifiableCredential error", "error", err)
			return false32Byte, err
		}
		buf := new(bytes.Buffer)
		p.Serialize(buf, did.DIDVersion)
		evm.StateDB.AddDIDLog(p.CredentialDoc.ID, p.Header.Operation, buf.Bytes())
	default:
		log.Error("error operation", "operation", p.Header.Operation)
		return false32Byte, errors.New("error operation:" + p.Header.Operation)
	}
	return true32Byte, nil
}

func isDID(didDoc *did.DIDDoc) bool {

	if !strings.HasPrefix(didDoc.ID, did.DID_ELASTOS_PREFIX) {
		return false
	}
	idString := did.GetDIDFromUri(didDoc.ID)

	for _, pkInfo := range didDoc.PublicKey {
		publicKey := base58.Decode(pkInfo.PublicKeyBase58)
		if did.IsMatched(publicKey, idString) {
			return true
		}
	}
	return false
}

type resolveDID struct {}

func (j *resolveDID) RequiredGas(evm *EVM, input []byte) uint64 {
	return params.ResolveDIDCost
}

func (j *resolveDID) Run(evm *EVM, input []byte, gas uint64) ([]byte, error) {
	var didDocState didapi.DidDocState = didapi.NonExist
	data := getData(input, 32, uint64(len(input) - 32))
	params := make(map[string]interface{})

	err := json.Unmarshal(data, &params)
	if err != nil {
		return false32Byte, errors.New( "resolveDID input is error" + string(data))
	}

	//remove DID_ELASTOS_PREFIX
	idParam, ok := params["did"].(string)
	if !ok {
		return false32Byte, errors.New( "did is null")
	}
	id := idParam
	if rawdb.IsURIHasPrefix(idParam) {
		id = did.GetDIDFromUri(id)
	}

	//check is valid address
	_, err = elacom.Uint168FromAddress(id)
	if err != nil {
		return false32Byte, errors.New("invalid did")
	}

	isGetAll, ok := params["all"].(bool)
	if !ok {
		isGetAll = false
	}

	branchPath, ok := params["branch"].([]interface{})
	if !ok {
		return false32Byte, errors.New("branch is null")
	}

	var rpcPayloadDid didapi.ResolvePayloadDIDInfo
	buf := new(bytes.Buffer)
	buf.WriteString(idParam)
	txData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return false32Byte, errors.New("did is not exist")
	}

	var txsData []did.DIDTransactionData
	if isGetAll {
		txsData, err = evm.StateDB.GetAllDIDTxData(buf.Bytes(), evm.chainConfig)
		if err != nil {
			return false32Byte, errors.New("get did transaction failed")
		}
	} else {
		if txData != nil {
			txsData = append(txsData, *txData)
		}
	}

	for index, txData := range txsData {
		rpcPayloadDid.DID = txData.Operation.DIDDoc.ID
		err, timestamp := getTxTime(evm, txData.TXID)
		if err != nil {
			continue
		}
		tempTXData := new(didapi.RpcTranasactionData)
		succe := tempTXData.FromTranasactionData(txData)
		if succe == false {
			continue
		}
		tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
		if index == 0 {
			if evm.StateDB.IsDIDDeactivated(idParam) {
				didDocState = didapi.Deactivated
				deactiveTXData, err := getDeactiveTx(evm, buf.Bytes())
				if err != nil {
					return nil, err
				}
				rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, deactiveTXData.ToResolveTxData())
			} else {
				didDocState = didapi.Valid
			}
			rpcPayloadDid.Status = int(didDocState)
		}
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, tempTXData.ToResolveTxData())
	}

	res, err := json.Marshal(rpcPayloadDid)
	if err != nil {
		return false32Byte, err
	}
	jin, err := simplejson.NewJson(res)
	if err != nil {
		log.Error("set simple json error", "error", err)
		return false32Byte, err
	}

	for _, p := range branchPath {
		if path, ok := p.(string); ok {
			jin = jin.Get(path)
		} else if path, ok := p.(float64); ok {
			jin = jin.GetIndex(int(path))
		}
	}
	inter := jin.Interface()
	if jin == nil {
		return false32Byte, errors.New("get value error")
	}
	vv, err := json.Marshal(inter)
	log.Info("resolve did", "return", string(vv), "err", err)
	return vv, err
}

func getTxTime(evm *EVM, txid string) (error, uint64) {
	hash := common.HexToHash(txid)
	tx, blockHash, blockNumber, _ := evm.StateDB.ReadTransaction(hash)
	if tx == nil {
		return errors.New("unkown tx"), 0
	}
	block := evm.StateDB.ReadBlock(blockHash, blockNumber)
	if block == nil {
		return errors.New("unkown block header"), 0

	}
	return nil, block.Time()
}

func getDeactiveTx(evm *EVM, idKey []byte) (*didapi.RpcTranasactionData, error) {
	deactiveTxData, err := evm.StateDB.GetDeactivatedTxData(idKey, evm.chainConfig)
	if err != nil {
		return nil, errors.New("get did deactivate transaction failed")
	}
	//change from DIDTransactionData to RpcTranasactionData
	rpcTXData := new(didapi.RpcTranasactionData)
	succe := rpcTXData.FromTranasactionData(*deactiveTxData)
	if succe == false {
		return nil, errors.New("change deactive tx data failed")
	}
	//fill tx Timestamp
	err, timestamp := getTxTime(evm, rpcTXData.TXID)
	if err != nil {
		return nil, errors.New("get did deactivate transaction failed" + err.Error())
	}
	rpcTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
	return rpcTXData, nil
}