package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/vm"
	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/crypto"
)

// Common errors.
var (
	ErrLeveldbNotFound = errors.New("leveldb: not found")
	ErrNotFound = errors.New("not found")
)

var didParam did.DIDParams
const PrefixCRDID contract.PrefixType = 0x67

func InitDIDParams(params did.DIDParams) {
	didParam = params
}

func CreateCRDIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

func checkRegisterDID(evm *EVM, doc *did.Operation) error {
	if doc.Header.Operation != did.Create_DID_Operation {
		return errors.New("invalid Operation")
	}

	_, err := time.Parse(time.RFC3339, doc.PayloadInfo.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	if err := checkDIDOperation(evm, &doc.Header, doc.PayloadInfo.ID); err != nil {
		return err
	}

	if err := checkVerificationMethodV1(doc.Proof.VerificationMethod,
		doc.PayloadInfo); err != nil {
		return err
	}
	// todo checkVerificationMethodV2 use pubkeyCount++

	//get  public key
	publicKeyBase58 := getPublicKey(doc.Proof.VerificationMethod,
		doc.PayloadInfo.Authentication, doc.PayloadInfo.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	publicKeyByte := base58.Decode(publicKeyBase58)
	signature, _ := base64url.DecodeString(doc.Proof.Signature)

	pk, err := crypto.DecodePoint(publicKeyByte)
	if err != nil {
		return err
	}
	err = crypto.Verify(*pk, doc.GetData(), signature)
	if err != nil {
		return err
	}
	payloadInfo := doc.PayloadInfo
	if err = checkVeriﬁableCredential(evm, payloadInfo.ID, payloadInfo.VerifiableCredential,
		payloadInfo.Authentication, payloadInfo.PublicKey, nil); err != nil {
		return err
	}
	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func checkDIDOperation(evm *EVM, header *did.DIDHeaderInfo, idUri string) error {
	id := GetDIDFromUri(idUri)
	if id == "" {
		return errors.New("WRONG DID FORMAT")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(id)

	if evm.StateDB.IsDIDDeactivated(id) {
		return errors.New("DID is deactivated")
	}

	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes())

	dbExist := true
	if err != nil {
		if err.Error() == ErrNotFound.Error() || err.Error() == ErrLeveldbNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == did.Create_DID_Operation {
			return errors.New("DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == did.Update_DID_Operation {
			//check PreviousTxid
			preTXID, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			if lastTXData.TXID != preTXID.String() {
				return errors.New("PreviousTxid IS NOT CORRECT")
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

/*
	Brief introduction:
		1, get public from Issuer2, verify credential sign
	Details:
		1，Traverse each credential, if Issuer is an empty string, use the ID in CredentialSubject,
			if it is still an empty string, use the outermost DID, indicating that it is a self-declared Credential
		2, if Issuer is not empty string, get Issuer public key from db，
	       if Issuer is not exist  check if realIssuer is ID,
           if so get public key from Authentication or PublicKey
        3, verify credential sign. if ID is compact format must Completion ID
*/
func checkVeriﬁableCredential(evm *EVM, DID string, VerifiableCredential []did.VerifiableCredential,
	Authentication []interface{}, PublicKey []did.DIDPublicKeyInfo, controller interface{}) error {

	var issuerPublicKey, issuerCode, signature []byte
	var err error
	isDID := isResiteredDID(evm, DID)
	//1，Traverse each credential, if Issuer is an empty string, use the DID in CredentialSubject,
	//if it is still an empty string, use the outermost DID, indicating that it is a self-declared Credential
	for _, cridential := range VerifiableCredential {
		realIssuer := cridential.Issuer
		proof := cridential.GetDIDProofInfo()
		if cridential.Issuer == "" {
			creSub := cridential.CredentialSubject.(map[string]interface{})
			for k, v := range creSub {
				if k == did.ID_STRING {
					realIssuer = v.(string)
					break
				}
			}
			if realIssuer == "" {
				realIssuer = DID
			}
			pubKeyStr := getPublicKey(proof.VerificationMethod, Authentication, PublicKey)
			if pubKeyStr == "" {
				return errors.New("checkVeriﬁableCredential NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		} else {
			//2,if Issuer is not empty string, get Issuer public key from db，
			//if Issuer is not exist  check if realIssuer is DID,
			//if so get public key from Authentication or PublicKey
			if issuerPublicKey, err = getIssuerPublicKey(evm, realIssuer, proof.VerificationMethod); err != nil {
				if realIssuer == DID {
					if isDID {
						pubKeyStr := getPublicKey(proof.VerificationMethod, Authentication, PublicKey)
						if pubKeyStr == "" {
							return errors.New("DID NOT FIND PUBLIC KEY OF VerificationMethod")
						}
						issuerPublicKey = base58.Decode(pubKeyStr)
					} else {
						pubKeyStr, _ := getPublicKeyByVerificationMethod(evm, proof.VerificationMethod, realIssuer, PublicKey,
							Authentication, controller)
						if pubKeyStr == "" {
							return errors.New("realIssuer NOT FIND PUBLIC KEY OF VerificationMethod")
						}
						issuerPublicKey = base58.Decode(pubKeyStr)
					}

				} else {
					return err
				}
			}
		}
		if issuerCode, err = getCodeByPubKey(issuerPublicKey); err != nil {
			return err
		}
		//get signature
		if signature, err = base64url.DecodeString(proof.Signature); err != nil {
			return err
		}
		//if DID is compact format must Completion DID
		cridential.VerifiableCredentialData.CompleteCompact(DID)
		// verify proof
		var success bool

		success, err = VerifyByVM(cridential.VerifiableCredentialData, issuerCode, signature)
		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		return nil
	}
	return nil
}

func GetLastDIDTxData(evm *EVM, issuerDID string) (*did.TranasactionData, error) {
	did := GetDIDFromUri(issuerDID)
	if did == "" {
		return nil, errors.New("WRONG DID FORMAT")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(did)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes())

	if err != nil {
		if err.Error() == ErrNotFound.Error() || err.Error() == ErrLeveldbNotFound.Error() {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return lastTXData, nil
}

func GetDIDFromUri(idURI string) string {
	index := strings.LastIndex(idURI, ":")
	if index == -1 {
		return ""
	}
	return idURI[index+1:]
}

func getUriSegment(uri string) string {
	index := strings.LastIndex(uri, "#")
	if index == -1 {
		return ""
	}
	return uri[index:]
}

func getPublicKey(VerificationMethod string, Authentication []interface{},
	PublicKey []did.DIDPublicKeyInfo) string {

	proofUriSegment := getUriSegment(VerificationMethod)

	for _, pkInfo := range PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range Authentication {
		switch auth.(type) {
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return ""
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return ""
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58
			}
		default:
			return ""
		}
	}
	return ""
}

func checkVerificationMethodV1(VerificationMethod string,
	payloadInfo *did.DIDPayloadInfo) error {

	proofUriSegment := getUriSegment(VerificationMethod)

	masterPubKeyVerifyOk := false
	for i := 0; i < len(payloadInfo.PublicKey); i++ {
		if proofUriSegment == getUriSegment(payloadInfo.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(payloadInfo.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress != GetDIDFromUri(payloadInfo.ID) {
				return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
			}
			masterPubKeyVerifyOk = true
			break
		}
	}

	for _, auth := range payloadInfo.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				return nil
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return err
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return err
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return nil
			}
		default:
			return errors.New("[ID checkVerificationMethodV1] invalid  auth.(type)")
		}
	}
	if masterPubKeyVerifyOk {
		return nil
	}
	return errors.New("[ID checkVerificationMethodV1] wrong public key by VerificationMethod ")
}

func getDIDAddress(publicKey []byte) (string, error) {
	code, err := getCodeByPubKey(publicKey)
	if err != nil {
		return "", err
	}
	newCode := make([]byte, len(code))
	copy(newCode, code)
	didCode := append(newCode[:len(newCode)-1], 0xAD)
	ct1, err2 := CreateCRIDContractByCode(didCode)
	if err2 != nil {
		return "", err
	}
	return ct1.ToProgramHash().ToAddress()
}

func getCIDAdress(publicKey []byte) (string, error) {
	hash, err := getDIDByPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return hash.ToAddress()
}

func getDIDByPublicKey(publicKey []byte) (*common.Uint168, error) {
	pk, _ := crypto.DecodePoint(publicKey)
	redeemScript, err := contract.CreateStandardRedeemScript(pk)
	if err != nil {
		return nil, err
	}
	return getDIDHashByCode(redeemScript)
}

func getDIDHashByCode(code []byte) (*common.Uint168, error) {
	ct1, error := CreateCRDIDContractByCode(code)
	if error != nil {
		return nil, error
	}
	return ct1.ToProgramHash(), error
}

func getCodeByPubKey(publicKey []byte) ([]byte, error) {
	pk, err := crypto.DecodePoint(publicKey)
	if err != nil {
		return nil, err
	}
	code, err2 := contract.CreateStandardRedeemScript(pk)
	if err2 != nil {
		return nil, err2
	}
	return code, nil
}

func CreateCRIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}

func isResiteredDID(evm *EVM, id string) bool {
	TranasactionData, err := GetLastDIDTxData(evm, id)
	// err  not registerd
	if err != nil {
		return false
	}
	//not find 	  not registerd
	if TranasactionData == nil {
		return false
	}
	// registered
	return true
}

//payloadInfo *id.CustomizedDIDPayload
func getPublicKeyByVerificationMethod(evm *EVM, VerificationMethod, ID string,
	PublicKey []did.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) (string, error) {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == ID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if compactSymbol == getUriSegment(keyString) {
					return keyString, nil
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return "", err
				}
				didPublicKeyInfo := new(did.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return "", err
				}
				if compactSymbol == getUriSegment(didPublicKeyInfo.ID) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			default:
				return "", errors.New(" invalid  auth.(type)")
			}
		}
	} else {
		//2, check is proofUriSegment public key come from controller
		if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
			//2.1 is controller exist
			for _, controller := range controllerArray {
				if controller == prefixDid {
					//get controllerDID last store data
					TranasactionData, err := GetLastDIDTxData(evm, prefixDid)
					if err != nil {
						return "", err
					}
					if TranasactionData == nil {
						return "", errors.New("prefixDid DID not exist in level db")
					}
					payload := TranasactionData.Operation.PayloadInfo
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return "", errors.New("multi controller NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
					if IsMatched(PublicKey, did) {
						return pubKeyBase58Str, nil
					}
				}
			}
		} else if controller, bController := Controller.(string); bController == true {
			if controller == prefixDid {
				//get controllerDID last store data
				TranasactionData, err := GetLastDIDTxData(evm, prefixDid)
				if err != nil {
					return "", err
				}
				if TranasactionData == nil {
					return "", errors.New("prefixDid DID not exist in level db")
				}
				payload := TranasactionData.Operation.PayloadInfo
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return "", errors.New("single controller NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
				if IsMatched(PublicKey, did) {
					return pubKeyBase58Str, nil
				}
			}
		}
	}
	return "", errors.New(" wrong public key by VerificationMethod ")
}

// issuerDID can be did or customizeDID
func getIssuerPublicKey(evm *EVM, issuerDID, idURI string) ([]byte, error) {
	var publicKey []byte
	if txData, err := GetLastDIDTxData(evm, issuerDID); err != nil {
		return nil, err
	} else {
		if txData == nil {
			issuerTxData, err := GetLastCustomizedDIDTxData(evm, issuerDID)
			if err != nil {
				return []byte{}, err
			}
			if issuerTxData == nil {
				return []byte{}, errors.New("LEVELDB NOT FIND issuerDID TX DATA")
			}
			payloadInfo := issuerTxData.Operation.GetPayloadInfo()
			pubKeyStr := getPublicKey(idURI, payloadInfo.Authentication, payloadInfo.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)

		} else {
			payloadInfo := txData.Operation.PayloadInfo
			pubKeyStr := getPublicKey(idURI, payloadInfo.Authentication, payloadInfo.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)
		}

	}
	return publicKey, nil
}

func GetLastCustomizedDIDTxData(evm *EVM, customizedDID string) (*did.CustomizedDIDTranasactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	return evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())
}

func GetDIDAndCompactSymbolFromUri(idURI string) (string, string) {
	index := strings.LastIndex(idURI, "#")
	if index == -1 {
		return "", ""
	}
	return idURI[:index], idURI[index:]
}

func IsMatched(publicKey []byte, did string) bool {

	if didTemp, err := getDIDAddress(publicKey); err != nil {
		return false
	} else {
		if didTemp != did {
			return false
		}
		return true
	}
}

func VerifyByVM(iDateContainer interfaces.IDataContainer, code []byte,
	signature []byte) (bool, error) {

	se := vm.NewExecutionEngine(iDateContainer,
		new(vm.CryptoECDsa), vm.MAXSTEPS, nil, nil)

	se.LoadScript(code, false)
	se.LoadScript(getParameterBySignature(signature), true)
	//execute program on VM
	se.Execute()

	if se.GetState() != vm.HALT {
		return false, errors.New("[VM] Finish State not equal to HALT")
	}

	if se.GetEvaluationStack().Count() != 1 {
		return false, errors.New("[VM] Execute Engine Stack Count Error")
	}

	success := se.GetExecuteResult()
	if !success {
		return false, errors.New("[VM] Check Sig FALSE")
	}
	return true, nil
}

func getParameterBySignature(signature []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)
	return buf.Bytes()
}

func checkDeactivateDID(evm *EVM, deactivateDIDOpt *did.DeactivateDIDOptPayload) error {
	targetDIDUri := deactivateDIDOpt.Payload
	targetDID := GetDIDFromUri(targetDIDUri)
	if targetDID == "" {
		return errors.New("WRONG DID FORMAT")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(targetDID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes())
	if err != nil {
		return err
	}

	//do not deactivage a did who was already deactivate
	if evm.StateDB.IsDIDDeactivated(targetDID) {
		return errors.New("DID WAS AREADY DEACTIVE")
	}

	//get  public key
	publicKeyBase58 := getAuthorizatedPublicKey(&deactivateDIDOpt.Proof,
		lastTXData.Operation.PayloadInfo)
	if publicKeyBase58 == "" {
		return errors.New("Not find the publickey verificationMethod   ")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(deactivateDIDOpt.Proof.Signature)

	var success bool
	success, err = VerifyByVM(deactivateDIDOpt, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}
	return nil
}


func getAuthorizatedPublicKey(proof *did.DIDProofInfo, payloadInfo *did.DIDPayloadInfo) string {
	proofUriSegment := getUriSegment(proof.VerificationMethod)

	for _, pkInfo := range payloadInfo.PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range payloadInfo.Authorization {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				for i := 0; i < len(payloadInfo.PublicKey); i++ {
					if proofUriSegment == getUriSegment(payloadInfo.PublicKey[i].ID) {
						return payloadInfo.PublicKey[i].PublicKeyBase58
					}
				}
				return ""
			}
		case map[string]interface{}:
			data, err := json.Marshal(auth)
			if err != nil {
				return ""
			}
			didPublicKeyInfo := new(did.DIDPublicKeyInfo)
			err = json.Unmarshal(data, didPublicKeyInfo)
			if err != nil {
				return ""
			}
			if proofUriSegment == getUriSegment(didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58
			}
		default:
			return ""
		}
	}

	return ""
}

func checkCustomizedDID(evm *EVM, customizedDIDPayload *did.CustomizedDIDOperation, gas uint64) error {
	// check Custom ID available?
	if err := checkCustomizedDIDAvailable(customizedDIDPayload); err != nil {
		return err
	}

	////check txn fee
	if err := checkCustomizedDIDTxFee(customizedDIDPayload, gas); err != nil {
		return err
	}

	//check Expires must be  format RFC3339
	_, err := time.Parse(time.RFC3339, customizedDIDPayload.Doc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}
	//if this customized did is already exist operation should not be create
	//if this customized did is not exist operation should not be update
	if err := checkCustomizedDIDOperation(evm, &customizedDIDPayload.Header,
		customizedDIDPayload.Doc.CustomID); err != nil {
		return err
	}

	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.CustomizedDIDPayload
	var verifyDoc *did.CustomizedDIDPayload
	if customizedDIDPayload.Header.Operation == did.Create_Customized_DID_Operation ||
		customizedDIDPayload.Header.Operation == did.Transfer_Customized_DID_Operation {
		verifyDoc = customizedDIDPayload.Doc
	} else {
		verifyDoc, err = getVerifyDocMultisign(evm, customizedDIDPayload.Doc.CustomID)
		if err != nil {
			return err
		}
	}

	// check payload.proof
	if err := checkCustomizedDIDVerificationMethod(evm,
		customizedDIDPayload.Proof.VerificationMethod, verifyDoc.CustomID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
		return err
	}

	if err := checkCustomIDOuterProof(evm, customizedDIDPayload, verifyDoc); err != nil {
		return err
	}

	//todo This custoized did and register did are mutually exclusive
	//todo check expires

	N := 0
	multisignStr := verifyDoc.Multisig
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}

	// check ticket when operation is 'Transfer'
	if customizedDIDPayload.Header.Operation == did.Transfer_Customized_DID_Operation {
		buf := new(bytes.Buffer)
		buf.WriteString(verifyDoc.CustomID)
		lastTxHash, err := evm.StateDB.GetLastCustomizedDIDTxHash(buf.Bytes())
		if err != nil {
			return err
		}
		if err := checkTicketAvailable(evm, customizedDIDPayload,
			verifyDoc.CustomID, lastTxHash, N, verifyDoc); err != nil {
			return err
		}
	}

	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller

	DIDProofArray, err := checkCustomizedDIDAllVerificationMethod(evm, verifyDoc, customizedDIDPayload.Doc.Proof)
	if err != nil {
		return err
	}

	//3, Verifiable credential
	if err = checkVeriﬁableCredential(evm,
		customizedDIDPayload.Doc.CustomID, customizedDIDPayload.Doc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller); err != nil {
		return err
	}
	//4, proof multisign verify
	err = checkCustomIDInnerProof(evm, DIDProofArray, customizedDIDPayload.Doc.CustomizedDIDPayloadData, N, verifyDoc)
	if err != nil {
		return err
	}
	return nil

}

//3, proof multisign verify
func checkCustomIDInnerProof(evm *EVM, DIDProofArray []*did.CustomizedDIDProofInfo, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.CustomizedDIDPayload) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.CustomID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := getCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool
		success, err = VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < N {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < N")
	}
	return nil
}


func checkCustomizedDIDAvailable(cPayload *did.CustomizedDIDOperation) error {
	if spv.SpvService == nil {
		return errors.New("spv service is not started")
	}
	reservedCustomIDs, err := spv.SpvService.GetReservedCustomIDs()
	if err != nil {
		return err
	}
	receivedCustomIDs, err := spv.SpvService.GetReceivedCustomIDs()
	if err != nil {
		return err
	}
	if cPayload.Doc == nil {
		return errors.New("error customized did document")
	}
	if _, ok := reservedCustomIDs[cPayload.Doc.CustomID]; ok {
		if customDID, ok := receivedCustomIDs[cPayload.Doc.CustomID]; ok {
			rcDID, err := customDID.ToAddress()
			if err != nil {
				return errors.New("invalid customDID in db")
			}
			if id, ok := cPayload.Doc.Controller.(string); ok {
				if !strings.Contains(id, rcDID) {
					return errors.New("invalid controller did")
				}
			} else {
				// customID need be one of the controller.
				var controllerCount int
				if dids, ok := cPayload.Doc.Controller.([]string); ok {
					for _, did := range dids {
						if strings.Contains(did, rcDID) {
							controllerCount++
						}
					}
				} else {
					return errors.New("invalid controller")
				}
				if controllerCount != 1 {
					return errors.New("not in controller")
				}
				// customID need be one oof the signature
				if proofs, ok := cPayload.Doc.Proof.([]*did.CustomizedDIDProofInfo); ok {
					var invalidProofCount int
					for _, proof := range proofs {
						if strings.Contains(proof.Creator, rcDID) {
							invalidProofCount++
						}
					}
					if invalidProofCount == 0 {
						return errors.New("there is no signature of custom ID")
					} else if invalidProofCount > 1 {
						return errors.New("there is duplicated signature of custom ID")
					}
				} else if proof, ok := cPayload.Doc.Proof.(*did.CustomizedDIDProofInfo); ok {
					if !strings.Contains(proof.Creator, rcDID) {
						return errors.New("there is no signature of custom ID")
					}
				} else {
					//error
					return errors.New("invalid Proof type")
				}
			}
		}
	}

	return nil
}


func getCustomizedDIDTxFee(customizedDIDPayload *did.CustomizedDIDOperation) common.Fixed64 {
	//A id lenght
	A := getCustomizedDIDLenFactor(customizedDIDPayload.Doc.CustomID)
	//B Valid period
	B := getValidPeriodFactor(customizedDIDPayload.Doc.Expires)
	//C operation create or update
	C := getOperationFactor(customizedDIDPayload.Header.Operation)
	//M controller sign number
	M := getControllerFactor(customizedDIDPayload.Doc.Controller)
	//E doc size
	buf := new(bytes.Buffer)
	customizedDIDPayload.Serialize(buf, did.CustomizedDIDVersion)
	E := common.Fixed64(buf.Len())
	//F factor got from cr proposal
	F := didParam.CustomIDFeeRate
	feeRate, err := spv.SpvService.GetRateOfCustomIDFee()
	if err == nil {
		F = feeRate
	}

	fee := (A*B*C*M + E) * F
	return fee
}

func getCustomizedDIDLenFactor(customizeDID string) common.Fixed64 {
	len := len(customizeDID)

	if len == 1 {
		return 6400
	} else if len == 2 {
		return 3200
	} else if len >= 3 && len <= 32 {
		//100 - [(n-1) / 8 ]
		return 100 - ((common.Fixed64(len) - 1) / 8)
	} else if len >= 33 && len <= 64 {
		//93 + [(n-1) / 8 ]
		return 93 + ((common.Fixed64(len) - 1) / 8)
	} else {
		//100 * (n-59) / 3
		return 100 + ((common.Fixed64(len) - 59) / 3)
	}
}


func checkCustomizedDIDTxFee(customizedDIDPayload *did.CustomizedDIDOperation, txFee uint64) error {
	//feeHelper := v.GetFeeHelper()
	//if feeHelper == nil {
	//	return errors.New("feeHelper == nil")
	//}
	//
	//txFee, err := feeHelper.GetTxFee(txn, v.GetParams().ElaAssetId)
	//if err != nil {
	//	return err
	//}
	//2. calculate the  fee that one cutomized did tx should paid
	needFee := getCustomizedDIDTxFee(customizedDIDPayload)
	if txFee <= uint64(needFee) {
		return errors.New("invalid txFee")
	}

	//check fee and should paid fee
	return nil
}

func getValidPeriodFactor(Expires string) common.Fixed64 {

	expiresTime, _ := time.Parse(time.RFC3339, Expires)

	//n := common.Fixed64(expiresTime.Year() - v.Chain.MedianTimePast.Year())
	n := common.Fixed64(expiresTime.Year() - time.Now().Year())
	//todo calculate vailid year, get median time
	//curMediantime := v.Chain.MedianTimePast
	//n := curMediantime - Expires
	//n := common.Fixed64(0)
	if n <= 0 {
		return 1
	}
	return n * (101 - n) / 100
}

func getOperationFactor(operation string) common.Fixed64 {
	if operation == did.Update_Customized_DID_Operation {
		return 12
	}
	return 10
}

func getControllerFactor(controller interface{}) common.Fixed64 {
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		controllerLen := len(controllerArray)
		if controllerLen <= 3 {
			return 1
		}
		//M=2**(m-3)
		return 2 * (common.Fixed64(controllerLen) - 3)
	}
	return 1

}


//check operateion create---->db must not have
//                 update----->db must have
func checkCustomizedDIDOperation(evm *EVM, header *did.CustomizedDIDHeaderInfo,
	customizedDID string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	lastTXData, err := evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())

	dbExist := true
	if err != nil {
		if err.Error() == ErrNotFound.Error() || err.Error() == ErrLeveldbNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == did.Create_Customized_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == did.Update_Customized_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := service.ToReversedString(*hash)

			if lastTXData.TXID != preTXID {
				return errors.New("Customized DID PreviousTxid IS NOT CORRECT")
			}
		}
	} else {
		if header.Operation == did.Update_Customized_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func getVerifyDocMultisign(evm *EVM, customizedID string) (*did.CustomizedDIDPayload, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedID)
	transactionData, err := evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return transactionData.Operation.Doc, nil
}

//DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
//is  controller primary key
//txPrefixDID is customized ID
func checkCustomizedDIDVerificationMethod(evm *EVM, VerificationMethod, txPrefixDID string,
	publicKey []did.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) error {
	prefixDid, compactSymbol := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in Authentication. if it is in then check done
	if prefixDid == "" || prefixDid == txPrefixDID {
		var pubkeyCount int
		for i := 0; i < len(publicKey); i++ {
			if compactSymbol == getUriSegment(publicKey[i].ID) {
				pubKeyByte := base58.Decode(publicKey[i].PublicKeyBase58)
				//get did address
				didAddress, err := getDIDAddress(pubKeyByte)
				if err != nil {
					return err
				}
				//didAddress must equal address in DID
				if didAddress != GetDIDFromUri(txPrefixDID) {
					return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
				}
				pubkeyCount++
				break
			}
		}
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if compactSymbol == getUriSegment(keyString) {
					pubkeyCount++
					//publicKey is primary and is reference in authentication
					if pubkeyCount == 2 {
						pubkeyCount--
					}
				}
			case map[string]interface{}:
				data, err := json.Marshal(auth)
				if err != nil {
					return err
				}
				didPublicKeyInfo := new(did.DIDPublicKeyInfo)
				err = json.Unmarshal(data, didPublicKeyInfo)
				if err != nil {
					return err
				}
				if compactSymbol == getUriSegment(didPublicKeyInfo.ID) {
					pubkeyCount++
				}
			default:
				return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] invalid  auth.(type)")
			}
		}
		if pubkeyCount == 1 {
			return nil
		}
	} else {
		//2, check is proofUriSegment public key come from controller
		if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
			//2.1 is controller exist
			for _, controller := range controllerArray {
				if controller == prefixDid {
					//get controllerDID last store data
					TranasactionData, err := GetLastDIDTxData(evm, prefixDid)
					if err != nil {
						return err
					}
					if TranasactionData == nil {
						return errors.New("prefixDid GetLastDIDTxData not exist in level db")
					}
					payload := TranasactionData.Operation.PayloadInfo
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
					if IsMatched(PublicKey, did) {
						return nil
					}
				}
			}
		} else if controller, bController := Controller.(string); bController == true {
			if controller == prefixDid {
				//get controllerDID last store data
				TranasactionData, err := GetLastDIDTxData(evm, prefixDid)
				if err != nil {
					return err
				}
				if TranasactionData == nil {
					return errors.New("prefixDid LastDIDTxData not exist in level db")
				}
				payload := TranasactionData.Operation.PayloadInfo
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := GetDIDFromUri(TranasactionData.Operation.PayloadInfo.ID)
				if IsMatched(PublicKey, did) {
					return nil
				}
			}
		}
	}
	return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] wrong public key by VerificationMethod ")
}


func GetMultisignMN(mulstiSign string) (int, int, error) {
	index := strings.LastIndex(mulstiSign, ":")
	if index == -1 {
		return 0, 0, errors.New("mulstiSign did not have :")
	}
	M, err := strconv.Atoi(mulstiSign[0:index])
	if err != nil {
		return 0, 0, err
	}
	N, err := strconv.Atoi(mulstiSign[index+1:])
	if err != nil {
		return 0, 0, err
	}
	return M, N, nil
}

func checkCustomIDOuterProof(evm *EVM, txPayload *did.CustomizedDIDOperation, verifyDoc *did.CustomizedDIDPayload) error {
	//get  public key
	publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, txPayload.Proof.VerificationMethod, verifyDoc.CustomID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
	if publicKeyBase58 == "" {
		return errors.New("checkCustomIDOuterProof not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(txPayload.Proof.Signature)

	var success bool
	success, err = VerifyByVM(txPayload, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkCustomIDProof[VM] Check Sig FALSE")
	}
	return nil
}


func checkTicketAvailable(evm *EVM, cPayload *did.CustomizedDIDOperation,
	customID string, lastTxHash common.Uint256, N int, verifyDoc *did.CustomizedDIDPayload) error {
	// check customID
	if cPayload.Ticket.CustomID != customID {
		return errors.New("invalid CustomID in ticket")
	}

	// 'to' need exist in controller
	to := cPayload.Ticket.To
	var existInController bool
	if controllerArray, ok := cPayload.Doc.Controller.([]interface{}); ok {
		for _, controller := range controllerArray {
			if controller == to {
				existInController = true
			}
		}
	} else if controller, ok := cPayload.Doc.Controller.(string); ok {
		if controller == to {
			existInController = true
		}
	}
	if !existInController {
		return errors.New("'to' is not in controller")
	}

	// 'to' need exist in proof
	dIDProofArray := make([]*did.CustomizedDIDProofInfo, 0)
	customizedDIDProof := &did.CustomizedDIDProofInfo{}
	existInProof := false
	if err := Unmarshal(cPayload.Doc.Proof, &dIDProofArray); err == nil {
		for _, proof := range dIDProofArray {
			if proof.Creator == to {
				existInProof = true
			}
		}

	} else if err := Unmarshal(cPayload.Doc.Proof, customizedDIDProof); err == nil {
		if customizedDIDProof.Creator == to {
			existInProof = true
		}
	}
	if !existInProof {
		return errors.New("'to' is not in proof")
	}

	// check transactionID
	if cPayload.Ticket.TransactionID != lastTxHash.String() {
		return errors.New("invalid TransactionID of ticket")
	}

	// check proof
	if err := checkTicketProof(evm, cPayload.Ticket, N, verifyDoc, cPayload.Ticket.Proof); err != nil {
		return errors.New("invalid proof of ticket")
	}

	return nil
}

func Unmarshal(src, target interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func checkTicketProof(evm *EVM, ticket *did.CustomIDTicket, N int,
	verifyDoc *did.CustomizedDIDPayload, Proof interface{}) error {
	ticketProofArray, err := checkCustomizedDIDTicketProof(evm, verifyDoc, Proof)
	if err != nil {
		return err
	}

	err = checkCustomIDTicketProof(evm, ticketProofArray, ticket, N, verifyDoc)
	if err != nil {
		return err
	}

	return nil
}

func checkCustomIDTicketProof(evm *EVM, ticketProofArray []*did.TransferCustomizedDIDProofInfo, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.CustomizedDIDPayload) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, ticketProof := range ticketProofArray {
		//get  public key
		publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, ticketProof.VerificationMethod, verifyDoc.CustomID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDTicketProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := getCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(ticketProof.SignatureValue)

		var success bool
		success, err = VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < N {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < N")
	}
	return nil
}

func checkCustomizedDIDTicketProof(evm *EVM, verifyDoc *did.CustomizedDIDPayload, Proof interface{}) ([]*did.TransferCustomizedDIDProofInfo,
	error) {
	DIDProofArray := make([]*did.TransferCustomizedDIDProofInfo, 0)
	CustomizedDIDProof := &did.TransferCustomizedDIDProofInfo{}
	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.CustomID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.CustomID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("checkCustomizedDIDAllVerificationMethod Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

func checkCustomizedDIDAllVerificationMethod(evm *EVM, verifyDoc *did.CustomizedDIDPayload, Proof interface{}) ([]*did.CustomizedDIDProofInfo,
	error) {
	//2,DIDProofInfo VerificationMethod must be in CustomizedDIDPayload Authentication or
	//is come from controller
	//var DIDProofArray []*id.CustomizedDIDProofInfo
	DIDProofArray := make([]*did.CustomizedDIDProofInfo, 0)

	//var CustomizedDIDProof id.CustomizedDIDProofInfo
	CustomizedDIDProof := &did.CustomizedDIDProofInfo{}
	//var bExist bool

	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.CustomID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.CustomID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
			return nil, err
		}
	} else {
		//error
		return nil, errors.New("checkCustomizedDIDAllVerificationMethod Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}