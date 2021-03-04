package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA.SideChain/vm"
	"github.com/elastos/Elastos.ELA.SideChain/vm/interfaces"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
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


func  isDID(didDoc *did.DIDDoc) bool {
	if didDoc == nil {
		return false
	}
	if !strings.HasPrefix(didDoc.ID, did.DID_ELASTOS_PREFIX) {
		return false
	}
	idString := rawdb.GetDIDFromUri(didDoc.ID)
	for _, pkInfo := range didDoc.PublicKey {
		publicKey := base58.Decode(pkInfo.PublicKeyBase58)
		if IsMatched(publicKey, idString) {
			return true
		}
	}
	return false
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

func CreateCRIDContractByCode(code []byte) (*contract.Contract, error) {
	if len(code) == 0 {
		return nil, errors.New("code is nil")
	}
	return &contract.Contract{
		Code:   code,
		Prefix: PrefixCRDID,
	}, nil
}


func getParameterBySignature(signature []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)
	return buf.Bytes()
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


func checkRegisterDID(evm *EVM, p *did.DIDPayload, gas uint64) error {
	_, err := time.Parse(time.RFC3339, p.DIDDoc.Expires)
	if err != nil {
		return errors.New("invalid Expires")
	}

	//check txn fee use RequiredGas
	fee := evm.GasPrice.Uint64() * gas
	if err := checkRegisterDIDTxFee(p, fee); err != nil {
		return err
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
	publicKeyBase58 := getPublicKey(p.Proof.VerificationMethod,
		p.DIDDoc.Authentication, p.DIDDoc.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(p.Proof.Signature)

	var success bool
	success, err = VerifyByVM(p, code, signature)
	if err != nil {
		return err
	}
	if !success {
		return errors.New("checkDIDTransaction [VM]  Check Sig FALSE")
	}
	doc := p.DIDDoc
	if err = checkVerifiableCredentials(evm, doc.ID, doc.VerifiableCredential,
		doc.Authentication, doc.PublicKey, nil); err != nil {
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
func checkVerifiableCredentials(evm *EVM, DID string, VerifiableCredential []did.VerifiableCredential,
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
				return errors.New("checkVerifiableCredentials NOT FIND PUBLIC KEY OF VerificationMethod")
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
		cridential.CompleteCompact(DID)
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

//DIDDoc *id.DIDDoc
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
					doc := TranasactionData.Operation.DIDDoc
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, doc.Authentication, doc.PublicKey)
					if pubKeyBase58Str == "" {
						return "", errors.New("multi controller NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := rawdb.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
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
				payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return "", errors.New("single controller NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := rawdb.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
				if IsMatched(PublicKey, did) {
					return pubKeyBase58Str, nil
				}
			}
		}
	}
	return "", errors.New(" wrong public key by VerificationMethod ")
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

func GetDIDAndCompactSymbolFromUri(idURI string) (string, string) {
	index := strings.LastIndex(idURI, "#")
	if index == -1 {
		return "", ""
	}
	return idURI[:index], idURI[index:]
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
			DIDDoc := issuerTxData.Operation.GetDIDDoc()
			pubKeyStr := getPublicKey(idURI, DIDDoc.Authentication, DIDDoc.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)

		} else {
			DIDDoc := txData.Operation.DIDDoc
			pubKeyStr := getPublicKey(idURI, DIDDoc.Authentication, DIDDoc.PublicKey)
			if pubKeyStr == "" {
				return []byte{}, errors.New("getIssuerPublicKey NOT FIND PUBLIC KEY OF VerificationMethod")
			}
			publicKey = base58.Decode(pubKeyStr)
		}

	}
	return publicKey, nil
}

func GetLastDIDTxData (evm *EVM, issuerDID string) (*did.DIDTransactionData, error) {
	did := rawdb.GetDIDFromUri(issuerDID)
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

func GetLastCustomizedDIDTxData(evm *EVM, customizedDID string) (*did.DIDTransactionData, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)
	return evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())
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

//Proof VerificationMethod must be in DIDDIDDoc Authentication or
//is did publickKey
func checkVerificationMethodV1(VerificationMethod string, DIDDoc *did.DIDDoc)error {
	proofUriSegment := getUriSegment(VerificationMethod)

	masterPubKeyVerifyOk := false
	for i := 0; i < len(DIDDoc.PublicKey); i++ {
		if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
			pubKeyByte := base58.Decode(DIDDoc.PublicKey[i].PublicKeyBase58)
			//get did address
			didAddress, err := getDIDAddress(pubKeyByte)
			if err != nil {
				return err
			}
			//didAddress must equal address in DID
			if didAddress != rawdb.GetDIDFromUri(DIDDoc.ID) {
				return errors.New("[ID checkVerificationMethodV1] ID and PublicKeyBase58 not match ")
			}
			masterPubKeyVerifyOk = true
			break
		}
	}

	for _, auth := range DIDDoc.Authentication {
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


//todo use VerificationMethod correspond public key
func getPublicKey(VerificationMethod string, Authentication []interface{}, PublicKey []did.DIDPublicKeyInfo) string {
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


//check operateion create---->db must not have
//                 update----->db must have
func checkDIDOperation(evm *EVM, header *did.Header, idUri string) error {
	id := rawdb.GetDIDFromUri(idUri)
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
			preTXID := service.ToReversedString(*hash)

			if lastTXData.TXID != preTXID {
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

func checkRegisterDIDTxFee(p *did.DIDPayload, txFee uint64) error {
	payload := p.DIDDoc
	buf := new(bytes.Buffer)
	p.Serialize(buf, did.DIDVersion)
	needFee := getIDTxFee(payload.ID, payload.Expires, p.Header.Operation, nil, buf.Len())


	fe := new(big.Int).SetInt64(needFee.IntValue())
	toETHfee := new(big.Int).Mul(fe, big.NewInt(did.FeeRate))

	if txFee < toETHfee.Uint64() {
		return errors.New("invalid txFee")
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
	fe := new(big.Int).SetInt64(needFee.IntValue())
	toETHfee := new(big.Int).Mul(fe, big.NewInt(did.FeeRate))
	if txFee < toETHfee.Uint64() {
		return errors.New("invalid txFee")
	}

	//check fee and should paid fee
	return nil
}

//Payload
//ID  Expires Controller Operation Payload interface
func getIDTxFee(customID, expires, operation string, controller interface{}, payloadLen int) common.Fixed64 {
	//A id lenght
	A := getCustomizedDIDLenFactor(customID)
	//B Valid period
	B := getValidPeriodFactor(expires)
	//C operation create or update
	C := getOperationFactor(operation)
	//M controller sign number
	M := getControllerFactor(controller)
	//E doc size
	E := getSizeFactor(payloadLen)
	//F factor got from cr proposal
	F := didParam.CustomIDFeeRate
	if spv.SpvService != nil {
		feeRate, _ := spv.SpvService.GetRateOfCustomIDFee()
		if feeRate != 0 {
			F = feeRate
		}
	}
	fee := (A*B*C*M + E) * float64(F)
	return common.Fixed64(fee)
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
		return 100 - ((float64(len) - 1) / 8)
	} else if len <= 64 {
		//93 + [(n-1) / 8 ]
		return 93 + ((float64(len) - 1) / 8)
	} else {
		//100 * (n-59) / 3
		return 100 * ((float64(len) - 59) / 2)
	}
}


func getValidPeriodFactor(Expires string) float64 {
	expiresTime, _ := time.Parse(time.RFC3339, Expires)
	days := expiresTime.Day() - time.Now().Day()
	if days < 180 {
		expiresTime.Add(180 * 24 * time.Hour)
	}

	years := float64(expiresTime.Year() - time.Now().Year())

	if years <= 0 {
		return 1
	}
	lifeRate := float64(0)
	if years < 1 {
		lifeRate = float64(years * ((100 - 3*math.Log2(1)) / 100))
	} else {
		lifeRate = float64(years * ((100 - 3*math.Log2(years)) / 100))
	}
	return lifeRate

}

func getOperationFactor(operation string) float64 {
	factor := float64(0)
	switch operation {
	case "CREATE":
		factor = 1
	case "UPDATE":
		factor = 0.8
	case "TRANSFER":
		factor = 1.2
	case "DEACTIVATE":
		factor = 0.3
	case "DECLARE":
		factor = 1
	case "REVOKE":
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
		factor = float64(payLoadSize/1024)*0.9*math.Log10(float64(payLoadSize/1024)) - 33.4
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
		return 2 * (float64(controllerLen) + 3)
	}
	return 1
}

func getUriSegment(uri string) string {
	index := strings.LastIndex(uri, "#")
	if index == -1 {
		return ""
	}
	return uri[index:]
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
	if err := checkCustomizedDIDVerificationMethod(evm,
		customizedDIDPayload.Proof.VerificationMethod, verifyDoc.ID,
		verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
		return err
	}

	if err := checkCustomIDOuterProof(evm, customizedDIDPayload, verifyDoc); err != nil {
		return err
	}

	//todo This custoized did and register did are mutually exclusive
	//todo check expires

	N := 0
	multisignStr := verifyDoc.MultiSig
	if multisignStr != "" {
		_, N, err = GetMultisignMN(multisignStr)
		if err != nil {
			return err
		}
	}

	// check ticket when operation is 'Transfer'
	if customizedDIDPayload.Header.Operation == did.Transfer_DID_Operation {
		buf := new(bytes.Buffer)
		buf.WriteString(verifyDoc.ID)
		lastTxHash, err := evm.StateDB.GetLastCustomizedDIDTxHash(buf.Bytes())
		if err != nil {
			return err
		}
		if err := checkTicketAvailable(evm, customizedDIDPayload,
			verifyDoc.ID, lastTxHash, N, verifyDoc); err != nil {
			return err
		}
	}

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller

	DIDProofArray, err := checkCustomizedDIDAllVerificationMethod(evm, verifyDoc, customizedDIDPayload.DIDDoc.Proof)
	if err != nil {
		return err
	}

	//3, Verifiable credential
	if err = checkVerifiableCredentials(evm,
		customizedDIDPayload.DIDDoc.ID, customizedDIDPayload.DIDDoc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller); err != nil {
		return err
	}
	//4, proof multisign verify
	err = checkCustomIDInnerProof(evm, DIDProofArray, customizedDIDPayload.DIDDoc.DIDPayloadData, N, verifyDoc)
	if err != nil {
		return err
	}
	return nil

}

func checkCustomizedDIDAllVerificationMethod(evm *EVM, verifyDoc *did.DIDDoc, Proof interface{}) ([]*did.DocProof,
	error) {
	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller
	//var DIDProofArray []*id.DocProof
	DIDProofArray := make([]*did.DocProof, 0)

	//var CustomizedDIDProof id.DocProof
	CustomizedDIDProof := &did.DocProof{}
	//var bExist bool

	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.ID,
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

func checkTicketAvailable(evm *EVM, cPayload *did.DIDPayload,
	customID string, lastTxHash common.Uint256, N int, verifyDoc *did.DIDDoc) error {
	// check customID
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

func checkCustomIDOuterProof(evm *EVM, txPayload *did.DIDPayload, verifyDoc *did.DIDDoc) error {
	//get  public key
	publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, txPayload.Proof.VerificationMethod, verifyDoc.ID,
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


//check operateion create---->db must not have
//                 update----->db must have
func checkCustomizedDIDOperation(evm *EVM, header *did.Header, customizedDID string) error {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedDID)

	lastTXData, err := evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())

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
			preTXID := service.ToReversedString(*hash)

			if lastTXData.TXID != preTXID {
				return errors.New("Customized DID PreviousTxid IS NOT CORRECT")
			}
		}
	} else {
		if header.Operation == did.Update_DID_Operation {
			return errors.New("Customized DID WRONG OPERATION NOT EXIST")
		}
	}
	return nil
}

func checkCustomizedDIDAvailable(cPayload *did.DIDPayload) error {
	if spv.SpvService == nil &&  didParam.IsTest == true {
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

//Proof VerificationMethod must be in DIDDoc Authentication or
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
				if didAddress != rawdb.GetDIDFromUri(txPrefixDID) {
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
					payload := TranasactionData.Operation.DIDDoc
					// check if VerificationMethod related public key is default key
					pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
					if pubKeyBase58Str == "" {
						return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
					}
					PublicKey := base58.Decode(pubKeyBase58Str)
					did := rawdb.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
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
				payload := TranasactionData.Operation.DIDDoc
				// check if VerificationMethod related public key is default key
				pubKeyBase58Str := getPublicKey(VerificationMethod, payload.Authentication, payload.PublicKey)
				if pubKeyBase58Str == "" {
					return errors.New("checkCustomizedDIDVerificationMethod NOT FIND PUBLIC KEY OF VerificationMethod")
				}
				PublicKey := base58.Decode(pubKeyBase58Str)
				did := rawdb.GetDIDFromUri(TranasactionData.Operation.DIDDoc.ID)
				if IsMatched(PublicKey, did) {
					return nil
				}
			}
		}
	}
	return errors.New("[txPrefixDID checkCustomizedDIDVerificationMethod] wrong public key by VerificationMethod ")
}

//	if operation is "create" use now m/n and public key otherwise use last time m/n and public key
func getVerifyDocMultisign(evm *EVM, customizedID string) (*did.DIDDoc, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(customizedID)
	transactionData, err := evm.StateDB.GetLastCustomizedDIDTxData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return transactionData.Operation.DIDDoc, nil
}

func checkCustomIDTicketProof(evm *EVM, ticketProofArray []*did.TicketProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, ticketProof := range ticketProofArray {
		//get  public key
		publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, ticketProof.VerificationMethod, verifyDoc.ID,
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
		signature, _ := base64url.DecodeString(ticketProof.Signature)

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

//3, proof multisign verify
func checkCustomIDInnerProof(evm *EVM, DIDProofArray []*did.DocProof, iDateContainer interfaces.IDataContainer,
	N int, verifyDoc *did.DIDDoc) error {
	verifyOkCount := 0
	//3, proof multisign verify
	for _, CustomizedDIDProof := range DIDProofArray {
		//get  public key
		publicKeyBase58, _ := getPublicKeyByVerificationMethod(evm, CustomizedDIDProof.Creator, verifyDoc.ID,
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
		fmt.Println("publicKeyBase58 ", publicKeyBase58)
		fmt.Println("signature ", CustomizedDIDProof.SignatureValue)

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

func checkTicketProof(evm *EVM, ticket *did.CustomIDTicket, N int,
	verifyDoc *did.DIDDoc, Proof interface{}) error {
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

func checkCustomizedDIDTicketProof(evm *EVM, verifyDoc *did.DIDDoc, Proof interface{}) ([]*did.TicketProof,
	error) {
	DIDProofArray := make([]*did.TicketProof, 0)
	CustomizedDIDProof := &did.TicketProof{}
	bDIDProofArray := false
	if err := Unmarshal(Proof, &DIDProofArray); err == nil {
		bDIDProofArray = true
		for _, CustomizedDIDProof = range DIDProofArray {
			if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
				verifyDoc.PublicKey, verifyDoc.Authentication, verifyDoc.Controller); err != nil {
				return nil, err
			}
		}
	} else if err := Unmarshal(Proof, CustomizedDIDProof); err == nil {
		if err := checkCustomizedDIDVerificationMethod(evm, CustomizedDIDProof.VerificationMethod, verifyDoc.ID,
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

func checkDeactivateDID(evm *EVM, deactivateDIDOpt *did.DIDPayload) error {
	targetDIDUri := deactivateDIDOpt.Payload
	targetDID := rawdb.GetDIDFromUri(targetDIDUri)
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
		lastTXData.Operation.DIDDoc)
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

func getAuthorizatedPublicKey(proof *did.Proof, DIDDoc *did.DIDDoc) string {
	proofUriSegment := getUriSegment(proof.VerificationMethod)

	for _, pkInfo := range DIDDoc.PublicKey {
		if proofUriSegment == getUriSegment(pkInfo.ID) {
			return pkInfo.PublicKeyBase58
		}
	}
	for _, auth := range DIDDoc.Authorization {
		switch auth.(type) {
		case string:
			keyString := auth.(string)
			if proofUriSegment == getUriSegment(keyString) {
				for i := 0; i < len(DIDDoc.PublicKey); i++ {
					if proofUriSegment == getUriSegment(DIDDoc.PublicKey[i].ID) {
						return DIDDoc.PublicKey[i].PublicKeyBase58
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

//1, if one credential is declear can not be declear again
//if one credential is revoke  can not be decalre or revoke again
func checkDeclareVerifiableCredentialOperation(evm *EVM, header *did.Header,
	CredentialID string) error {
	if header.Operation != did.Declare_Verifiable_Credential_Operation {
		return errors.New("checkDeclareVerifiableCredentialOperation WRONG OPERATION")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(CredentialID)
	_, err := evm.StateDB.GetLastVerifiableCredentialTxData(buf.Bytes())
	dbExist := true
	if err != nil {
		if err.Error() == ErrLeveldbNotFound.Error() || err.Error() == ErrNotFound.Error() {
			dbExist = false
		} else {
			return err
		}
	}
	if dbExist {
		return errors.New("VerifiableCredential WRONG OPERATION ALREADY Declare")
	}

	return nil
}

func checkDeclareVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	//1, if one credential is declear can not be declear again
	//if one credential is revoke  can not be decalre or revoke again
	// this is the receiver id  todo
	receiverID := GetVerifiableCredentialID(payload.CredentialDoc)
	credentialID := payload.CredentialDoc.ID
	issuer := getCredentialIssuer(receiverID, payload.CredentialDoc)
	if err := checkDeclareVerifiableCredentialOperation(evm, &payload.Header, credentialID); err != nil {
		return err
	}

	////todo This customized did and register did are mutually exclusive
	////todo check expires

	// if it is "create" use now m/n and public key otherwise use last time m/n and public key
	// get credential target ID , Authentication , PublicKey, m,n of multisign   (isDID/customized did)
	//
	isDID := isResiteredDID(evm, receiverID)
	if isDID {
		////issuer can revoke credential
		//if payload.Header.Operation == id.Revoke_Verifiable_Credential_Operation {
		//	if CustomizedDIDProof, bExist := payload.Proof.(*id.Proof); bExist == true {
		//		if strings.Contains(CustomizedDIDProof.VerificationMethod, issuer) {
		//			return v.checkDIDVerifiableCredential(receiverID, issuer, payload)
		//		}
		//	}
		//}
		//receiverID is did, but issuer may have one or more controllers  todo more controllers
		return checkDIDVerifiableCredential(evm, receiverID, issuer, payload)
	} else {
		return checkCustomizedDIDVerifiableCredential(evm, receiverID, payload)
	}
}

func checkRevokeVerifiableCredential(evm *EVM, payload *did.DIDPayload) error {
	credentialID := payload.Payload

	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)
	lastTXData, err := evm.StateDB.GetLastVerifiableCredentialTxData(buf.Bytes())

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

		return checkDIDVerifiableCredential(evm, owner, issuer, payload)
	}

	return nil
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

func checkDIDAllMethod(evm *EVM, receiver, issuer string, credPayload *did.DIDPayload) (*did.Proof, error) {
	//var DIDProofArray []*id.Proof
	proof := credPayload.Proof
	if credPayload.Header.Operation == did.Revoke_Verifiable_Credential_Operation {
		//如果Proof是数组，在revoke的情况下Proof的签名可以是receiver或者issuer的
		//receiver或者issuer都即可能是did也可能是短名字
		//则VerificationMethod指定的应该是issuer的key
		//receiver或者issuer都即可能是did也可能是短名字
		verifMethod := proof.VerificationMethod
		if isIDVerifMethodMatch(evm, verifMethod, issuer) || isIDVerifMethodMatch(evm, verifMethod, receiver) {
			return &proof, nil
		}
		return nil, errors.New("revoke  Proof and id is not matched")
	} else if credPayload.Header.Operation == did.Declare_Verifiable_Credential_Operation {
		if !isIDVerifMethodMatch(evm, proof.VerificationMethod, receiver) {
			return nil, errors.New("proof  receiver not match")
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

	issuerTxData, err := GetLastCustomizedDIDTxData(evm, issuer)
	if err != nil {
		return false
	}
	if issuerTxData == nil {
		return false
	}
	Controller := issuerTxData.Operation.DIDDoc.Controller
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

// Is VerificationMethod of proof array and ID  matched
func isIDsVerifMethodMatch(evm *EVM, Proof interface{}, ID string) bool {
	//var DIDProofArray []*id.Proof
	if DIDProofArray, bDIDProofArray := Proof.([]*did.Proof); bDIDProofArray == true {
		for _, proof := range DIDProofArray {
			if !isIDVerifMethodMatch(evm, proof.VerificationMethod, ID) {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

//receiveDID is did
//issuer can be did or customizeddid(one/more controller)
//if it is revoke  issuer can deactive
//VerificationMethod should be did
func checkDIDVerifiableCredential(evm *EVM, receiveDID, issuerID string,
	credPayload *did.DIDPayload) error {
	receiverDIDTx, err := GetLastDIDTxData(evm, receiveDID)
	if err != nil {
		return err
	}
	if receiverDIDTx == nil {
		return errors.New("isRegiseredDID DID not exist in level db")
	}
	//issuerID is did or not
	//issuerIsDID := v.isResiteredDID(issuerID)
	verifyDIDDoc := receiverDIDTx.Operation.DIDDoc
	var proof *did.Proof
	if proof, err = checkDIDAllMethod(evm, receiveDID, issuerID, credPayload); err != nil {
		return err
	}

	//get  public key
	publicKeyBase58 := getPublicKey(proof.VerificationMethod,
		verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("checkDIDVerifiableCredential Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)

	//var code []byte
	code, err := getCodeByPubKey(publicKeyByte)
	if err != nil {
		return err
	}
	signature, _ := base64url.DecodeString(proof.Signature)

	var success bool
	success, err = VerifyByVM(credPayload, code, signature)

	if err != nil {
		return err
	}
	if !success {
		return errors.New("[VM] Check Sig FALSE")
	}

	if err = checkVerifiableCredentials(evm, receiveDID, []did.VerifiableCredential{*credPayload.CredentialDoc.VerifiableCredential},
		verifyDIDDoc.Authentication, verifyDIDDoc.PublicKey, nil); err != nil {
		return err
	}
	return nil
}


func checkCustomizedDIDVerifiableCredential(evm *EVM, customizedDID string, payload *did.DIDPayload) error {
	//1, if it is "create" use now m/n and public key otherwise use last time m/n and public key
	//var verifyDoc *id.DIDDoc
	verifyDoc, err := getVerifyDocMultisign(evm, customizedDID)
	if err != nil {
		return err
	}

	//M,
	//var N int
	N := 0
	if verifyDoc.MultiSig != "" {
		_, N, err = GetMultisignMN(verifyDoc.MultiSig)
		if err != nil {
			return err
		}
	}
	//doc := customizedDIDPayload.DIDDoc

	//2,Proof VerificationMethod must be in DIDDoc Authentication or
	//is come from controller

	DIDProofArray, err := checkCustomizedDIDAllVerificationMethod(evm, verifyDoc, payload.Proof)
	if err != nil {
		return err
	}

	//3, proof multisign verify
	err = checkCustomIDInnerProof(evm, DIDProofArray, payload, N, verifyDoc)
	if err != nil {
		//return err
	}
	//4, Verifiable credential
	if err = checkVerifiableCredentials(evm, verifyDoc.ID, payload.DIDDoc.VerifiableCredential,
		verifyDoc.Authentication, verifyDoc.PublicKey, verifyDoc.Controller); err != nil {
		return err
	}
	return nil
}
