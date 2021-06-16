package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"

	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
)

// Common errors.
var (
	ErrLeveldbNotFound = errors.New("leveldb: not found")
	ErrNotFound        = errors.New("not found")
)

// blockStatus is a bit field representing the validation state of the block.
type publicKeyType byte

const (
	//defualt public key
	DefaultPublicKey publicKeyType = iota

	//Authtication public key
	AuthPublicKey

	//Authorization key
	AuthorPublicKey
)

var didParam did.DIDParams

const PrefixCRDID contract.PrefixType = 0x67

func InitDIDParams(params did.DIDParams) {
	didParam = params
}

func checkRegisterDID(evm *EVM, p *did.DIDPayload, gas uint64) error {
	_, err := time.Parse(time.RFC3339, p.DIDDoc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	//check txn fee use RequiredGas
	fee := evm.GasPrice.Uint64() * gas
	configHeight := evm.chainConfig.OldDIDMigrateHeight
	configAddr := evm.chainConfig.OldDIDMigrateAddr
	senderAddr := evm.Context.Origin.String()

	if configHeight  == nil || evm.Context.BlockNumber.Cmp(configHeight) > 0 || senderAddr != configAddr{
		// abnormal payload check
		if err :=checkPayloadSyntax(p); err != nil {
			log.Error("checkPayloadSyntax error", "error", err, "ID", p.DIDDoc.ID)
			return  err
		}
		if err := checkRegisterDIDTxFee(p, fee); err != nil {
			return err
		}
	}

	if err := checkDIDOperation(evm, &p.Header, p.DIDDoc.ID); err != nil {
		return err
	}

	if err := checkVerificationMethodV1(p.Proof.VerificationMethod,
		p.DIDDoc); err != nil {
		return err
	}
	// todo checkVerificationMethodVuse2  pubkeyCount++

	//get  public key
	publicKeyBase58, _ := getAuthenPublicKey(evm, p.Proof.VerificationMethod, true,
		p.DIDDoc.PublicKey, p.DIDDoc.Authentication, nil)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(p.Proof.Signature)

	var success bool
	success, err = did.VerifyByVM(p, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkDIDTransaction [VM]  Check Sig FALSE")
	}
	doc := p.DIDDoc
	if err = checkVerifiableCredentials(evm, doc.ID, doc.VerifiableCredential,
		doc.Authentication, doc.PublicKey, nil, true); err != nil {
		if err.Error() == "[VM] Check Sig FALSE" && evm.Context.BlockNumber.Cmp(configHeight) < 0{
			log.Warn("checkRegisterDID end "," Check Sig FALSE ID", p.DIDDoc.ID)
			return nil
		}
		return err
	}

	if configHeight  == nil || evm.Context.BlockNumber.Cmp(configHeight) > 0 || senderAddr != configAddr {
		DIDProofArray, err := getDocProof(p.DIDDoc.Proof)
		if len(DIDProofArray) <=0 {
			return  errors.New("checkDIDTransaction doc proof is empty str")
		}
		if err != nil {
			return err
		}
		var verifyDoc *did.DIDDoc
		verifyDoc = p.DIDDoc
		if err = checkDIDInnerProof(evm,p.DIDDoc.ID, DIDProofArray, doc.DIDPayloadData, len(DIDProofArray), verifyDoc); err != nil {
			return err
		}
	}
	return nil
}

func checkRegisterDIDTxFee(operation *did.DIDPayload, txFee uint64) error {
	//2. calculate the  fee that one cutomized did txls should paid
	payload := operation.DIDDoc
	buf := new(bytes.Buffer)
	operation.Serialize(buf, did.DIDVersion)

	needFee := getIDTxFee(payload.ID, payload.Expires, operation.Header.Operation, nil, buf.Len())
	log.Error("#### checkRegisterDIDTxFee ", "needFee sela", needFee)

	toETHfee := needFee * float64(did.FeeRate)
	if float64(txFee) < toETHfee {
		msg := fmt.Sprintf("invalid txFee, need %f, set %f", toETHfee, float64(txFee))
		return errors.New(msg)
	}

	//check fee and should paid fee
	return nil
}

func checkCustomizedDIDTxFee(payload *did.DIDPayload, txFee uint64) error {
	//2. calculate the  fee that one cutomized did tx should paid
	doc := payload.DIDDoc
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	needFee := getIDTxFee(doc.ID, doc.Expires, payload.Header.Operation, doc.Controller, buf.Len())

	toETHfee := needFee * float64(did.FeeRate)

	if float64(txFee) < toETHfee {
		msg := fmt.Sprintf("invalid txFee, need %f, set %f", toETHfee, float64(txFee))
		return errors.New(msg)
	}

	//check fee and should paid fee
	return nil
}

//check operateion create---->db must not have
//                 update----->db must have
func checkDIDOperation(evm *EVM, header *did.Header,
	idUri string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(idUri)

	if evm.StateDB.IsDIDDeactivated(idUri) {
		return errors.New("DID is deactivated")
	}

	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
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
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := hash.String()
			if preTXID[:2] == "0x" {
				preTXID = preTXID[:2]
			}
			if lastTXData.TXID[:2] == "0x" {
				lastTXData.TXID = lastTXData.TXID[2:]
			}
			configHeight := evm.chainConfig.OldDIDMigrateHeight
			if evm.Context.BlockNumber.Cmp(configHeight) > 0 {
				if lastTXData.TXID != preTXID {
					return errors.New("PreviousTxid IS NOT CORRECT")
				}
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func checkVerificationMethodV1(VerificationMethod string,
	DIDDoc *did.DIDDoc) error {
	masterPubKeyVerifyOk := false
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		if verificationMethodEqual(VerificationMethod, DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := did.GetDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress == did.GetDIDFromUri(DIDDoc.ID) {
				masterPubKeyVerifyOk = true
				break
			}
		}
	}

	for _, auth := range DIDDoc.Authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(VerificationMethod, keyString) {
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
			if verificationMethodEqual(VerificationMethod, didPublicKeyInfo.ID) {
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

func getDIDAutheneKey(verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo) (string, error) {
	for _, auth := range authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(verificationMethod, keyString){
				for _, pkInfo := range publicKey {
					if verificationMethodEqual(verificationMethod, pkInfo.ID) {
						return pkInfo.PublicKeyBase58, nil
					}
				}
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
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				return didPublicKeyInfo.PublicKeyBase58, nil
			}
		default:
			return "", errors.New("[Operation checkVerificationMethodV0] invalid  auth.(type)")
		}
	}
	return "", nil
}

func verificationMethodEqual(verificationMethod string, vcid string) bool {
	contr1, uriFregment1 := did.GetController(verificationMethod)
	contr2, uriFregment2 := did.GetController(vcid)
	if contr1 == "" || contr2 == "" {
		return uriFregment1 == uriFregment2
	}
	return contr1 == contr2 && uriFregment1 == uriFregment2
}

//get did/cutsomizedid Authentication public key
//for did  includes default key + authentication key
//for customizedID includes self authen + controller authen+ controller default key
func getAuthenPublicKey(evm *EVM, verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, controller interface{}) (string, error) {
	if isDID {
		return getDIDAutheneKey(verificationMethod, authentication, publicKey)
	} else {
		return getCustomizedIDPublicKey(evm, verificationMethod, publicKey, authentication, controller, AuthPublicKey)
	}
}

//authorization []interface{},
func getCustomizedIDPublicKey(evm *EVM, verificationMethod string, publicKey []did.DIDPublicKeyInfo,
	authentication []interface{}, controller interface{}, keyType publicKeyType) (string, error) {
	contr, _ := did.GetController(verificationMethod)

	if keyType == AuthPublicKey {
		for _, auth := range authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if verificationMethodEqual(verificationMethod, keyString){
					for _, pkInfo := range publicKey {
						if verificationMethodEqual(verificationMethod, pkInfo.ID) {
							return pkInfo.PublicKeyBase58, nil
						}
					}
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
				if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			}
		}
	}
	//contr, _ := id.GetController(verificationMethod)
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == contr {
				doc, err := GetIDLastDoc(evm, contr)
				if err != nil {
					return "", err
				}
				return getDIDPublicKeyByType(contr,verificationMethod, doc.Authentication, doc.PublicKey,
					doc.Authorization, keyType)
			}
		}
	} else if controller, bController := controller.(string); bController == true {
		if controller == contr {
			doc, err := GetIDLastDoc(evm, contr)
			if err != nil {
				return "", err
			}
			return getDIDPublicKeyByType(contr, verificationMethod, doc.Authentication, doc.PublicKey,
				doc.Authorization, keyType)
		}
	}
	return "", nil
}

func getDIDPublicKeyByType(didWithPrefix,verificationMethod string, authentication []interface{},
	publicKey []did.DIDPublicKeyInfo, authorization []interface{}, keyType publicKeyType) (string, error) {
	var pubKeyBase58Str string
	var err error
	switch keyType {
	case DefaultPublicKey:
		pubKeyBase58Str, err = getDIDDefaultKey(didWithPrefix,verificationMethod, authentication, publicKey)
	case AuthorPublicKey:
		pubKeyBase58Str, err = getDIDDeactivateKey(didWithPrefix,verificationMethod, authentication, publicKey, authorization)
	case AuthPublicKey:
		pubKeyBase58Str, err = getDIDAutheneKey(verificationMethod, authentication, publicKey)
	}
	if pubKeyBase58Str == "" {
		return "", err
	}
	return pubKeyBase58Str, nil
}

func getDIDDeactivateKey(ID,verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo,
	authorization []interface{}) (string, error) {
	publickeyBase58, _ := getDIDDefaultKey(ID, verificationMethod, authentication, publicKey)
	if publickeyBase58 == "" {
		for _, auth := range authorization {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if verificationMethodEqual(verificationMethod, keyString){
					for i := 0; i < len(publicKey); i++ {
						if verificationMethodEqual(verificationMethod, publicKey[i].ID) {
							return publicKey[i].PublicKeyBase58, nil
						}
					}
					return "", nil
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
				if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID ) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			default:
				return "", nil
			}
		}
	}else{
		return publickeyBase58, nil
	}

	return "", nil
}

func getDIDDefaultKey(dID, verificationMethod string, authentication []interface{}, publicKey []did.DIDPublicKeyInfo) (string, error) {
	didAddress:= did.GetDIDFromUri(dID)
	for _, auth := range authentication {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if verificationMethodEqual(verificationMethod, keyString){
				for _, pkInfo := range publicKey {
					if verificationMethodEqual(verificationMethod, pkInfo.ID) {
						if did.IsPublickDIDMatched(pkInfo.PublicKeyBase58,  didAddress) {
							return pkInfo.PublicKeyBase58, nil
						}
					}
				}
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
			if verificationMethodEqual(verificationMethod, didPublicKeyInfo.ID) {
				if did.IsPublickDIDMatched(didPublicKeyInfo.PublicKeyBase58 , didAddress) {
					return didPublicKeyInfo.PublicKeyBase58, nil
				}
			}
		default:
			return "", errors.New("[Operation checkVerificationMethodV0] invalid  auth.(type)")
		}
	}
	return "", nil
}

func GetIDLastDoc(evm *EVM, id string) (*did.DIDDoc, error) {
	TranasactionData, err := GetLastDIDTxData(evm, id)
	if err != nil {
		return nil, err
	}
	if TranasactionData == nil {
		return nil, errors.New("prefixDid DID not exist in level db")
	}
	return TranasactionData.Operation.DIDDoc, nil
}

func GetLastDIDTxData(evm *EVM, issuerDID string) (*did.DIDTransactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(issuerDID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return lastTXData, nil
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
func checkVerifiableCredentials(evm *EVM, ID string, VerifiableCredential []did.VerifiableCredential,
	Authentication []interface{}, PublicKey []did.DIDPublicKeyInfo, controller interface{}, isDID bool) error {
	var issuerPublicKey, issuerCode, signature []byte
	var err error
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
				realIssuer = ID
			}
			pubKeyStr, _ := getAuthenPublicKey(evm, proof.VerificationMethod, isDID, PublicKey, Authentication, controller)
			if pubKeyStr == "" {
				return errors.New("checkVerifiableCredentials NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			issuerPublicKey = base58.Decode(pubKeyStr)
		} else {
			//2,if Issuer is not empty string, get Issuer public key from db，
			//if Issuer is not exist  check if realIssuer is DID,
			//if so get public key from Authentication or PublicKey
			if issuerPublicKey, err = getIssuerPublicKey(evm, realIssuer, proof.VerificationMethod, isDID); err != nil {
				if realIssuer == ID {
					pubKeyStr, _ := getAuthenPublicKey(evm, proof.VerificationMethod, isDID, PublicKey, Authentication, controller)
					if pubKeyStr == "" {
						return errors.New("DID NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					issuerPublicKey = base58.Decode(pubKeyStr)
				} else {
					return err
				}
			}
		}
		if issuerCode, err = did.GetCodeByPubKey(issuerPublicKey); err != nil {
			return err
		}
		//get signature
		if signature, err = base64url.DecodeString(proof.Signature); err != nil {
			return err
		}
		//if DID is compact format must Completion DID
		cridential.CompleteCompact(ID)
		// verify proof
		var success bool

		success, err = did.VerifyByVM(cridential.VerifiableCredentialData, issuerCode, signature)
		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
	}
	return nil
}

func isResiteredDID(evm *EVM, ID string) bool {
	TranasactionData, err := GetLastDIDTxData(evm, ID)
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

// issuerDID can be did or customizeDID
func getIssuerPublicKey(evm *EVM, issuerID, verificationMethod string, isDID bool) ([]byte, error) {
	var publicKey []byte
	var txData *did.DIDTransactionData
	var err error
	if txData, err = GetLastDIDTxData(evm, issuerID); err != nil {
		return nil, err
	}

	if txData == nil {
		return []byte{}, errors.New("issuerID is not registered")
	} else {
		DIDDoc := txData.Operation.DIDDoc
		pubKeyStr, _ := getAuthenPublicKey(evm, verificationMethod, isDID, DIDDoc.PublicKey, DIDDoc.Authentication, DIDDoc.Controller)
		if pubKeyStr == "" {
			return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
		}
		publicKey = base58.Decode(pubKeyStr)
	}
	return publicKey, nil
}

func checkCustomizedDID(evm *EVM, customizedDIDPayload *did.DIDPayload, gas uint64) error {

	// check Custom ID available?
	if err := checkCustomizedDIDAvailable(customizedDIDPayload); err != nil {
		return err
	}

	fee := gas * evm.GasPrice.Uint64()
	if err := checkCustomizedDIDTxFee(customizedDIDPayload, fee); err != nil {
		return err
	}

	//check Expires must be  format RFC3339
	_, err := time.Parse(time.RFC3339, customizedDIDPayload.DIDDoc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}
	//if this customized did is already exist operation should not be create
	//if this customized did is not exist operation should not be update
	if err := checkCustomizedDIDOperation(evm, &customizedDIDPayload.Header,
		customizedDIDPayload.DIDDoc.ID); err != nil {
		return err
	}

	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	var verifyDoc *did.DIDDoc
	if customizedDIDPayload.Header.Operation == did.Create_DID_Operation ||
		customizedDIDPayload.Header.Operation == did.Transfer_DID_Operation {
		verifyDoc = customizedDIDPayload.DIDDoc
	} else {
		verifyDoc, err = getVerifyDocMultisign(evm, customizedDIDPayload.DIDDoc.ID)
		if err != nil {
			return err
		}
	}

	// check payload.proof
	if IsVerifMethCustIDDefKey(evm,
		customizedDIDPayload.Proof.VerificationMethod, verifyDoc.ID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
		return errors.New("payload.proof VerificationMethod key not default key")
	}

	if err := checkCustomIDOuterProof(evm, customizedDIDPayload, verifyDoc); err != nil {
		return err
	}

	//todo This custoized did and register did are mutually exclusive
	//todo check expires

	M := 0
	multisignStr := verifyDoc.MultiSig
	if multisignStr != "" {
		M, _, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}

	// check ticket when operation is 'Transfer'
	if customizedDIDPayload.Header.Operation == did.Transfer_DID_Operation {
		buf := new(bytes.Buffer)
		buf.WriteString(verifyDoc.ID)
		lastTx, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
		if err != nil {
			return err
		}
		M, _, err := GetMultisignMN(lastTx.Operation.DIDDoc.MultiSig)
		if err != nil {
			return err
		}
		if err := checkTicketAvailable(evm, customizedDIDPayload,
			verifyDoc.ID, lastTx.TXID, M, lastTx.Operation.DIDDoc); err != nil {
			return err
		}
	}

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//getDocProof

	if !isVerificationsMethodsValid(evm, verifyDoc, customizedDIDPayload.DIDDoc.Proof) {
		return errors.New("DIDDoc.Proof verificationMethod is invalid")
	}

	DIDProofArray, err := getDocProof(customizedDIDPayload.DIDDoc.Proof)
	if err != nil {
		return err
	}

	//3, Verifiable credential
	if err = checkVerifiableCredentials(evm,
		customizedDIDPayload.DIDDoc.ID, customizedDIDPayload.DIDDoc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller,false); err != nil {
		return err
	}
	//4, proof multisign verify
	err = checkCustomIDInnerProof(evm, customizedDIDPayload.DIDDoc.ID,DIDProofArray,
		customizedDIDPayload.DIDDoc.DIDPayloadData, M, verifyDoc)
	if err != nil {
		return err
	}
	return nil

}

//3, proof multisign verify
func  checkDIDInnerProof(evm *EVM,ID string, DIDProofArray []*did.DocProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := getDefaultPublicKey(evm,ID, CustomizedDIDProof.Creator, true, verifyDoc.PublicKey,
			verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkDIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool

		success, err = did.VerifyByVM(iDateContainer, code, signature)

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

//3, proof multisign verify
func checkCustomIDInnerProof(evm *EVM, ID string,DIDProofArray []*did.DocProof, iDateContainer interfaces.IDataContainer,
	M int, verifyDoc *did.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := getDefaultPublicKey(evm,ID, CustomizedDIDProof.Creator, false, verifyDoc.PublicKey,
			verifyDoc.Authentication, verifyDoc.Controller)
		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDInnerProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(CustomizedDIDProof.SignatureValue)

		var success bool
		success, err = did.VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < M {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < M")
	}
	return nil
}

func checkTicketAvailable(evm *EVM, cPayload *did.DIDPayload,
	customID string, lastTxHash string, N int, verifyDoc *did.DIDDoc) error {
	if cPayload.Ticket.CustomID != customID {
		return errors.New("invalid ID in ticket")
	}

	// 'to' need exist in controller
	to := cPayload.Ticket.To
	var existInController bool
	if controllerArray, ok := cPayload.DIDDoc.Controller.([]interface{}); ok {
		for _, controller := range controllerArray {
			if controller == to {
				existInController = true
			}
		}
	} else if controller, ok := cPayload.DIDDoc.Controller.(string); ok {
		if controller == to {
			existInController = true
		}
	}
	if !existInController {
		return errors.New("'to' is not in controller")
	}

	// 'to' need exist in proof
	dIDProofArray := make([]*did.DocProof, 0)
	customizedDIDProof := &did.DocProof{}
	existInProof := false
	if err := Unmarshal(cPayload.DIDDoc.Proof, &dIDProofArray); err == nil {
		for _, proof := range dIDProofArray {
			if proof.Creator == to {
				existInProof = true
			}
		}

	} else if err := Unmarshal(cPayload.DIDDoc.Proof, customizedDIDProof); err == nil {
		contrID, _ := did.GetController(customizedDIDProof.Creator) // check customID
		if contrID == to {
			existInProof = true
		}
	}
	if !existInProof {
		return errors.New("'to' is not in proof")
	}

	// check transactionID
	if cPayload.Ticket.TransactionID != lastTxHash {
		return errors.New("invalid TransactionID of ticket")
	}

	// check proof
	if err := checkTicketProof(evm, cPayload.Ticket, N, verifyDoc, cPayload.Ticket.Proof); err != nil {
		return errors.New("invalid proof of ticket")
	}

	return nil
}

func checkTicketProof(evm *EVM, ticket *did.CustomIDTicket, N int,
	verifyDoc *did.DIDDoc, Proof interface{}) error {
	ticketProofArray, err := checkCustomizedDIDTicketProof(evm, verifyDoc, Proof)
	if err != nil {
		return err
	}

	err = checkCustomIDTicketProof(evm, ticketProofArray, ticket.CustomIDTicketData, N, verifyDoc)
	if err != nil {
		return err
	}

	return nil
}

func checkCustomIDTicketProof(evm *EVM, ticketProofArray []*did.TicketProof, iDateContainer interfaces.IDataContainer,
	M int, verifyDoc *did.DIDDoc) error {
	isDID := did.IsDID(verifyDoc.ID, verifyDoc.PublicKey)
	verifyOkCount := 0
	//3, proof multisign verify
	for _, ticketProof := range ticketProofArray {
		//get  public key
		publicKeyBase58, _ := getAuthenPublicKey(evm, ticketProof.VerificationMethod, isDID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)

		if publicKeyBase58 == "" {
			return errors.New("checkCustomIDTicketProof Not find proper publicKeyBase58")
		}
		//get code
		//var publicKeyByte []byte
		publicKeyByte := base58.Decode(publicKeyBase58)

		//var code []byte
		code, err := did.GetCodeByPubKey(publicKeyByte)
		if err != nil {
			return err
		}
		signature, _ := base64url.DecodeString(ticketProof.Signature)

		var success bool
		success, err = did.VerifyByVM(iDateContainer, code, signature)

		if err != nil {
			return err
		}
		if !success {
			return errors.New("[VM] Check Sig FALSE")
		}
		verifyOkCount++
	}
	if verifyOkCount < M {
		return errors.New("[VM] Check Sig FALSE verifyOkCount < M")
	}
	return nil
}

func checkCustomizedDIDTicketProof(evm *EVM, verifyDoc *did.DIDDoc, Proof interface{}) ([]*did.TicketProof,
	error) {
	DIDProofArray := make([]*did.TicketProof, 0)
	CustomizedDIDProof := &did.TicketProof{}
	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if IsVerifMethCustIDDefKey(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
				return nil, errors.New("DIDProofArray TicketProof  verification method key is not def key")
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if IsVerifMethCustIDDefKey(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
			return nil, errors.New("TicketProof verification method key is not def key")
		}
	} else {
		//error
		return nil, errors.New("isVerificationsMethodsValid Invalid Proof type")
	}
	//proof object
	if bDIDProofArray == false {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	}
	return DIDProofArray, nil
}

func checkCustomIDOuterProof(evm *EVM, txPayload *did.DIDPayload, verifyDoc *did.DIDDoc) error {
	//get  public key
	publicKeyBase58, _ := getAuthenPublicKey(evm, txPayload.Proof.VerificationMethod, false,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller)
	if publicKeyBase58 == "" {
		return errors.New("checkCustomIDOuterProof not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(txPayload.Proof.Signature)

	var success bool
	success, err = did.VerifyByVM(txPayload, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkCustomIDProof[VM] Check Sig FALSE")
	}
	return nil
}

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func getVerifyDocMultisign(evm *EVM, customizedID string) (*did.DIDDoc, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedID)
	transactionData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return nil, err
	}
	return transactionData.Operation.DIDDoc, nil
}

//get did/cutsomizedid default key
func getDefaultPublicKey(evm *EVM,ID, verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, controller interface{}) (string, error) {
	if isDID {
		return getDIDDefaultKey(ID,verificationMethod, authentication, publicKey)
	} else {
		return getCustomizedIDPublicKey(evm, verificationMethod, nil, nil, controller, DefaultPublicKey)
	}
}

func checkCustomizedDIDAvailable(cPayload *did.DIDPayload) error {
	if spv.SpvService == nil && didParam.IsTest == true {
		return nil
	} else {
		return errors.New("spv is not inited")
	}
	reservedCustomIDs, err := spv.SpvService.GetReservedCustomIDs()
	if err != nil {
		return err
	}
	receivedCustomIDs, err := spv.SpvService.GetReceivedCustomIDs()
	if err != nil {
		return err
	}
	if reservedCustomIDs == nil || len(reservedCustomIDs) == 0 {
		return nil
	}
	if _, ok := reservedCustomIDs[cPayload.DIDDoc.ID]; ok {
		if customDID, ok := receivedCustomIDs[cPayload.DIDDoc.ID]; ok {
			rcDID, err := customDID.ToAddress()
			if err != nil {
				return errors.New("invalid customDID in db")
			}
			if id, ok := cPayload.DIDDoc.Controller.(string); ok {
				if !strings.Contains(id, rcDID) {
					return errors.New("invalid controller did")
				}
			} else {
				// customID need be one of the controller.
				var controllerCount int
				if dids, ok := cPayload.DIDDoc.Controller.([]string); ok {
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
				if proofs, ok := cPayload.DIDDoc.Proof.([]*did.DocProof); ok {
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
				} else if proof, ok := cPayload.DIDDoc.Proof.(*did.DocProof); ok {
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

//check operateion create---->db must not have
//                 update----->db must have
func checkCustomizedDIDOperation(evm *EVM, header *did.Header,
	customizedDID string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)

	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if header.Operation == did.Create_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION ALREADY EXIST")
		} else if header.Operation == did.Update_DID_Operation {
			//check PreviousTxid
			hash, err := common.Uint256FromHexString(header.PreviousTxid)
			if err != nil {
				return err
			}
			preTXID := hash.String()

			configHeight := evm.chainConfig.OldDIDMigrateHeight
			if evm.Context.BlockNumber.Cmp(configHeight) > 0 {
				if lastTXData.TXID != preTXID {
					return errors.New("Customized DID PreviousTxid IS NOT CORRECT")
				}
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

//is VerificationMethod CustomizedID DefaultKey
func IsVerifMethCustIDDefKey(evm *EVM, VerificationMethod, ID string,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, Controller interface{}) bool {
	controllerVM, _ := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	//1, check is proofUriSegment public key in authentication. if it is in then check done
	if controllerVM == "" || controllerVM == ID {
		var pubkeyCount int
		for i := 0; i < len(publicKey); i++ {
			if verificationMethodEqual(VerificationMethod, publicKey[i].ID) {
				id := did.GetDIDFromUri(publicKey[i].ID)
				if !did.IsPublickDIDMatched(publicKey[i].PublicKeyBase58, id) {
					return false
				}
				pubkeyCount++
				break
			}
		}
		if pubkeyCount == 1 {
			return true
		}
	} else {
		IsVerifMethCustIDControllerKey(evm, VerificationMethod, ID, Controller, true)
	}
	return false
}

// keyType default key / authenKey
func IsVerifMethCustIDControllerKey(evm *EVM, VerificationMethod, ID string, Controller interface{},
	isDefaultKey bool) bool {
	controllerVM, _ := GetDIDAndCompactSymbolFromUri(VerificationMethod)
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == controllerVM {
				doc, err := GetIDLastDoc(evm, controllerVM)
				if err != nil {
					return false
				}
				//payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := ""
				if isDefaultKey {
					pubKeyBase58Str, _ = getDefaultPublicKey(evm,ID, VerificationMethod, true, doc.PublicKey,
						doc.Authentication, doc.Controller)
				} else {
					pubKeyBase58Str, _ = getAuthenPublicKey(evm, VerificationMethod, true, doc.PublicKey,
						doc.Authentication, doc.Controller)
				}

				if pubKeyBase58Str == "" {
					return false
				}
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == controllerVM {
			//get controllerDID last store data
			doc, err := GetIDLastDoc(evm, controllerVM)
			if err != nil {
				return false
			}
			pubKeyBase58Str, _ := getDefaultPublicKey(evm,controller, VerificationMethod, true, doc.PublicKey,
				doc.Authentication, doc.Controller)
			if pubKeyBase58Str == "" {
				return false
			}
			return true
		}
	}
	return false
}

func GetDIDAndCompactSymbolFromUri(idURI string) (string, string) {
	index := strings.LastIndex(idURI, "#")
	if index == -1 {
		return "", ""
	}
	return idURI[:index], idURI[index:]
}

func getDocProof(Proof interface{}) ([]*did.DocProof, error) {
	DIDProofArray := make([]*did.DocProof, 0)

	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		DIDProofArray = append(DIDProofArray, CustomizedDIDProof)
	} else {
		//error
		return nil, errors.New("isVerificationsMethodsValid Invalid Proof type")
	}
	return DIDProofArray, nil
}

func isVerificationsMethodsValid(evm *EVM, verifyDoc *did.DIDDoc, Proof interface{}) bool {
	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//var DIDProofArray []*id.DocProof
	DIDProofArray := make([]*did.DocProof, 0)
	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool

	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		for _, CustomizedDIDProof = range DIDProofArray {
			if !IsVerifMethCustIDAuthKey(evm, CustomizedDIDProof.Creator, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
				return false
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if !IsVerifMethCustIDAuthKey(evm, CustomizedDIDProof.Creator, verifyDoc.ID,
			verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller) {
			return false
		}
	} else {
		return false
	}

	return true
}

func IsVerifMethCustIDAuthKey(evm *EVM, VerificationMethod, ID string,
	publicKey []did.DIDPublicKeyInfo, Authentication []interface{}, Controller interface{}) bool {
	if IsVerifMethCustIDDefKey(evm, VerificationMethod, ID, publicKey, Authentication, Controller) {
		return true
	}
	controllerVM, _ := GetDIDAndCompactSymbolFromUri(VerificationMethod)

	if controllerVM == "" || controllerVM == ID {
		//proofUriSegment---PublicKeyBase58 is in Authentication
		for _, auth := range Authentication {
			switch auth.(type) {
			case string:
				keyString := auth.(string)
				if verificationMethodEqual(VerificationMethod, keyString) {
					return true
				}
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
				if verificationMethodEqual(VerificationMethod, didPublicKeyInfo.ID) {
					return true
				}
			}
		}
	} else {
		return IsVerifMethCustIDControllerKey(evm, VerificationMethod, ID, Controller, false)
	}
	return false
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

//Payload
//ID  Expires  Controller Operation Payload interface
func getIDTxFee(customID, expires, operation string, controller interface{}, payloadLen int) float64 {
	//A id lenght lengthRate
	A := getCustomizedDIDLenFactor(customID)
	//B Valid period lifeRate
	B := getValidPeriodFactor(expires, time.Now())
	//C operation create or update OperationRate
	C := getOperationFactor(operation)
	//M controller sign number multisigRate
	M := getControllerFactor(controller)
	//E doc size sizeRate
	E := getSizeFactor(payloadLen)
	//F factor got from cr proposal
	F := didParam.CustomIDFeeRate
	if spv.SpvService != nil {
		feeRate, _ := spv.SpvService.GetRateOfCustomIDFee()
		if feeRate != 0 {
			F = feeRate
		}
	}
	fee := (A*B*C*E + M) * float64(F)
	return fee
}

func getCustomizedDIDLenFactor(ID string) float64 {
	len := len(ID)
	if len == 0 {
		return 0.3
	} else if len == 1 {
		return 6400
	} else if len == 2 {
		return 3200
	} else if len == 3 {
		return 1200
	} else if len <= 32 {
		//100 - [(n-1) / 8 ]
		return 100 - float64((len-1)/8)
	} else if len <= 64 {
		//93 + [(n-1) / 8 ]
		return 93 + float64((len-1)/8)
	} else {
		//100 * (n-59) / 3
		return 100 * ((float64(len) - 59) / 2)
	}
}

func getDays(t1, t2 time.Time) int64 {
	t1Unix := t1.Unix()
	t2Unix := t2.Unix()
	return (t1Unix - t2Unix) / (24 * 3600)
}

func getValidPeriodFactor(Expires string, nowTime time.Time) float64 {
	expiresTime, _ := time.Parse(time.RFC3339, Expires)
	days := getDays(expiresTime, nowTime)
	if days < 180 {
		days += 180
	}
	years := float64(days) / 365

	lifeRate := float64(0)
	if years < 1 {
		lifeRate = years * ((100 - (3 * math.Log2(1))) / 100)
	} else {
		lifeRate = years * ((100 - (3 * math.Log2(years))) / 100)
	}
	return lifeRate

}

func getOperationFactor(operation string) float64 {
	factor := float64(0)
	switch operation {
	case "create":
		factor = 1
	case "update":
		factor = 0.8
	case "transfer":
		factor = 1.2
	case "deactivate":
		factor = 0.3
	case "declare":
		factor = 1
	case "revoke":
		factor = 0.3
	default:
		factor = 1
	}
	return factor
}

func getSizeFactor(payLoadSize int) float64 {
	factor := float64(0)
	if payLoadSize <= 1024 {
		factor = 1
	} else if payLoadSize <= 32*1024 {
		factor = math.Log10(float64(payLoadSize/1024))/2 + 1
	} else {
		factor = math.Pow(float64(payLoadSize/1024), 0.9)*math.Log10(float64(payLoadSize/1024)) - 33.4
	}
	return factor
}

func getControllerFactor(controller interface{}) float64 {
	if controller == nil {
		return 0
	}
	if controllerArray, bControllerArray := controller.([]interface{}); bControllerArray == true {
		controllerLen := len(controllerArray)
		if controllerLen <= 1 {
			return float64(controllerLen)
		}
		//M=2**(m+3)
		return math.Pow(2, float64(controllerLen+3))
	}
	return 1

}

func checkDeactivateDID(evm *EVM, deactivateDIDOpt *did.DIDPayload) error {
	ID := deactivateDIDOpt.Payload
	isDID, err := evm.StateDB.IsDID(ID)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	buf.WriteString(ID)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes(), evm.chainConfig)
	if err != nil {
		return err
	}
	//do not deactivage a did who was already deactivate
	if evm.StateDB.IsDIDDeactivated(ID) {
		return errors.New("DID WAS AREADY DEACTIVE")
	}

	//get  public key getAuthorizatedPublicKey
	//getDeactivatePublicKey
	didDoc := lastTXData.Operation.DIDDoc
	publicKeyBase58, err := getDeactivatePublicKey(evm,didDoc.ID, deactivateDIDOpt.Proof.VerificationMethod, isDID,
		didDoc.PublicKey, didDoc.Authentication, didDoc.Authorization, didDoc.Controller)
	if publicKeyBase58 == "" {
		return errors.New("Not find the publickey of verificationMethod")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(deactivateDIDOpt.Proof.Signature)

	var success bool
	success, err = did.VerifyByVM(deactivateDIDOpt, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}
	return nil
}

//get did/cutsomizedid deactivate public key
//for did include default key + authorization key
//for customizedID controller default key
/*
verificationMethod: did/customizedID uni public string
isDID: true is did and  false is customizedID
publicKey: public keys
authentication: authentication
authorization: authorization
controller controller
*/
func getDeactivatePublicKey(evm *EVM, ID,verificationMethod string, isDID bool,
	publicKey []did.DIDPublicKeyInfo, authentication []interface{}, authorization []interface{},
	controller interface{}) (string, error) {

	if isDID {
		return getDIDDeactivateKey(ID,verificationMethod, authentication, publicKey, authorization)
	} else {
		// customizedid use default key not authorization key
		return getCustomizedIDPublicKey(evm, verificationMethod, nil, nil, controller, DefaultPublicKey)
	}
}

func checkVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	_, err := time.Parse(time.RFC3339, payload.CredentialDoc.ExpirationDate)
	if err != nil {
		return errors.New("invalid ExpirationDate")
	}

	switch payload.Header.Operation {
	case did.Declare_Verifiable_Credential_Operation:
		return checkDeclareVerifiableCredential(evm, payload)
	case did.Revoke_Verifiable_Credential_Operation:
		return checkRevokeVerifiableCredential(evm, payload)
	}

	return errors.New("invalid operation")
}

func checkDeclareVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	//1, if one credential is declear can not be declear again
	//if one credential is revoke  can not be decalre or revoke again
	// this is the receiver id  todo
	receiverID := GetVerifiableCredentialID(payload.CredentialDoc)
	credentialID := payload.CredentialDoc.ID
	issuer := getCredentialIssuer(receiverID, payload.CredentialDoc)
	if err := checkVerifiableCredentialOperation(evm, &payload.Header, credentialID); err != nil {
		return err
	}

	////todo check expires
	ok, err := evm.StateDB.IsDID(receiverID)
	if err != nil {
		return err
	}
	if ok {
		return checkDeclareCustomizedDIDVerifiableCredential(evm, receiverID, issuer, payload)
	} else {
		return checkCustomizedDIDVerifiableCredential(evm, receiverID, payload)
	}
}

//1, if one credential is declear can not be declear again
//if one credential is revoke  can not be decalre or revoke again
func checkVerifiableCredentialOperation(evm *EVM, header *did.Header,
	CredentialID string) error {
	if header.Operation != did.Declare_Verifiable_Credential_Operation {
		return errors.New("checkVerifiableCredentialOperation WRONG OPERATION")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(CredentialID)
	tx, err := evm.StateDB.GetLastVerifiableCredentialTxData(buf.Bytes(), evm.chainConfig)
	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist && tx.Operation.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		return errors.New("VerifiableCredential WRONG OPERATION ALREADY Declare")
	}
	if dbExist && tx.Operation.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
		receiverID := GetVerifiableCredentialID(tx.Operation.CredentialDoc)
		issuer := getCredentialIssuer(receiverID, tx.Operation.CredentialDoc)
		if err := checkRevokeCustomizedDIDVerifiableCredential(evm, receiverID, issuer, &tx.Operation); err == nil {
			return errors.New("VerifiableCredential WRONG OPERATION ALREADY Revoked")
		}
	}

	return nil
}

func checkRevokeCustomizedDIDVerifiableCredential(evm *EVM, owner string, issuer string, payload *did.DIDPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	if err := checkCustomizedDIDVerifiableCredential(evm, owner, payload); err == nil {
		return nil
	}

	if err := checkCustomizedDIDVerifiableCredential(evm, issuer, payload); err == nil {
		return nil
	}

	return errors.New("invalid signer of revoke payload")
}

func checkCustomizedDIDVerifiableCredential(evm *EVM, signer string, payload *did.DIDPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	verifyDoc, err := getVerifyDocMultisign(evm, signer)
	if err != nil {
		return err
	}
	ok, err := evm.StateDB.IsDID(signer)
	if err != nil {
		return err
	}
	publicKeyBase58, _ := getAuthenPublicKey(evm, payload.Proof.VerificationMethod, ok, verifyDoc.PublicKey,
		verifyDoc.Authentication, verifyDoc.Controller)
	if publicKeyBase58 == "" {
		return errors.New("checkCustomizedDIDVerifiableCredential Not find proper publicKeyBase58")
	}

	//check outter signature
	err = did.CheckSignature(payload, publicKeyBase58, payload.Proof.Signature)
	if err != nil {
		return err
	}
	//4, Verifiable credential
	if err = checkVerifiableCredentials(evm, verifyDoc.ID, []did.VerifiableCredential{*payload.CredentialDoc.VerifiableCredential},
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller, false); err != nil {
		return err
	}
	return nil
}

func checkRevokeVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	credentialID := payload.CredentialDoc.ID

	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)
	lastTXData, err := evm.StateDB.GetLastVerifiableCredentialTxData(buf.Bytes(), evm.chainConfig)

	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		if lastTXData == nil {
			return errors.New("checkRevokeVerifiableCredential invalid last transaction")
		}
		if lastTXData.Operation.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
			return errors.New("VerifiableCredential revoked again")
		}

		// check if owner or issuer send this transaction
		owner := GetVerifiableCredentialID(lastTXData.Operation.CredentialDoc)
		issuer := getCredentialIssuer(owner, lastTXData.Operation.CredentialDoc)
		return checkRevokeCustomizedDIDVerifiableCredential(evm, owner, issuer, payload)
	}

	return nil
}

func getCredentialIssuer(DID string, cridential *did.VerifiableCredentialDoc) string {
	realIssuer := cridential.Issuer
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
	}
	return realIssuer
}

func GetVerifiableCredentialID(cridential *did.VerifiableCredentialDoc) string {
	creSub := cridential.CredentialSubject.(map[string]interface{})
	ID := ""
	for k, v := range creSub {
		if k == did.ID_STRING {
			ID = v.(string)
			break
		}
	}
	return ID
}

func checkDeclareCustomizedDIDVerifiableCredential(evm *EVM, owner string, issuer string, payload *did.DIDPayload) error {

	if err := checkDIDVerifiableCredential(evm, owner, payload); err == nil {
		return nil
	}

	if err := checkDIDVerifiableCredential(evm, issuer, payload); err == nil {
		return nil
	}

	return errors.New("invalid credential signature")
}

//receiveDID is did
//issuer can be did or customizeddid(one/more controller)
//if it is revoke  issuer can deactive
//VerificationMethod should be did
func checkDIDVerifiableCredential(evm *EVM, signer string,
	credPayload *did.DIDPayload) error {
	verifyDIDDoc, err := GetIDLastDoc(evm, signer)
	if err != nil {
		return err
	}
	var proof *did.Proof
	if proof, err = checkDIDAllMethod(evm, signer, credPayload); err != nil {
		return err
	}
	//get  public key
	ok, err := evm.StateDB.IsDID(signer)
	if err != nil {
		return err
	}
	publicKeyBase58, _ := getAuthenPublicKey(evm, proof.VerificationMethod, ok,
		verifyDIDDoc.PublicKey, verifyDIDDoc.Authentication, nil)
	if publicKeyBase58 == "" {
		return errors.New("checkDIDVerifiableCredential Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := did.GetCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(proof.Signature)

	var success bool
	success, err = did.VerifyByVM(credPayload, code, signature)

	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}

	if err = checkVerifiableCredentials(evm, signer, []did.VerifiableCredential{*credPayload.CredentialDoc.VerifiableCredential},
		verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey, nil,true); err != nil {
		return err
	}
	return nil
}

func checkDIDAllMethod(evm *EVM, ownerDID string, credPayload *did.DIDPayload) (*did.Proof, error) {
	//var DIDProofArray []*id.Proof
	proof := credPayload.Proof
	if credPayload.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
		verifMethod := proof.VerificationMethod
		if isIDVerifMethodMatch(evm, verifMethod, ownerDID) {
			return &proof, nil
		}
		return nil, errors.New("revoke  Proof and id is not matched")
	} else if credPayload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		if !isIDVerifMethodMatch(evm, proof.VerificationMethod, ownerDID) {
			return nil, errors.New("proof  ownerDID not match")
		}
		return &proof, nil
	} else {
		return nil, errors.New("invalid Operation")
	}
}

func isIDVerifMethodMatch(evm *EVM, verificationMethod, ID string) bool {
	return isDIDVerifMethodMatch(verificationMethod, ID) || isCustomizedVerifMethodMatch(evm, verificationMethod, ID)
}

func isDIDVerifMethodMatch(verificationMethod, ID string) bool {
	return strings.Contains(verificationMethod, ID)
}

//here issuer must be customizdDID
func isCustomizedVerifMethodMatch(evm *EVM, verificationMethod, issuer string) bool {
	prefixDid, _ := GetDIDAndCompactSymbolFromUri(verificationMethod)

	doc, err := GetIDLastDoc(evm, issuer)
	if err != nil {
		return false
	}
	Controller := doc.Controller
	//2, check is proofUriSegment public key come from controller
	if controllerArray, bControllerArray := Controller.([]interface{}); bControllerArray == true {
		//2.1 is controller exist
		for _, controller := range controllerArray {
			if controller == prefixDid {
				return true

			}
		}
	} else if controller, bController := Controller.(string); bController == true {
		if controller == prefixDid {
			return true
		}
	}
	return false
}
