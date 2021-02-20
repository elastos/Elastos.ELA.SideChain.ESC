package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/crypto"
)
// Common errors.
var (
	ErrNotFound         = errors.New("leveldb: not found")
)

func CheckRegisterDID(evm *EVM, doc *did.Operation, height uint32, mainChainHeight uint32) error {
	//payload type check
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
	//if height < v.didParam.CheckRegisterDIDHeight {
	//	if err := v.checkVerificationMethodV0(&doc.Proof,
	//		doc.PayloadInfo); err != nil {
	//		return err
	//	}
	//} else {
	//	if err := v.checkVerificationMethodV1(doc.Proof.VerificationMethod,
	//		doc.PayloadInfo); err != nil {
	//		return err
	//	}
	//}
	// todo checkVerificationMethodV2 use pubkeyCount++

	//get  public key
	publicKeyBase58 := getPublicKey(doc.Proof.VerificationMethod,
		doc.PayloadInfo.Authentication, doc.PayloadInfo.PublicKey)
	if publicKeyBase58 == "" {
		return errors.New("Not find proper publicKeyBase58")
	}
	//get code
	//var publicKeyByte []byte
	publicKeyByte := base58.Decode(publicKeyBase58)
	//
	////var code []byte
	//code, err := getCodeByPubKey(publicKeyByte)
	//if err != nil {
	//	return err
	//}
	signature, _ := base64url.DecodeString(doc.Proof.Signature)

	//var success bool
	//success, err = v.VerifyByVM(doc, code, signature)
	//if err != nil {
	//	return err
	//}
	//if !success {
	//	return errors.New("checkRegisterDID [VM]  Check Sig FALSE")
	//}

	pk, err := crypto.DecodePoint(publicKeyByte)
	if err != nil {
		return err
	}
	err = crypto.Verify(*pk, doc.GetData(), signature)
	if err != nil {
		return err
	}
	//if height >= v.didParam.VerifiableCredentialHeight {
	//	payloadInfo := doc.PayloadInfo
	//	if err = v.checkVeriﬁableCredential(payloadInfo.ID, payloadInfo.VerifiableCredential,
	//		payloadInfo.Authentication, payloadInfo.PublicKey, nil); err != nil {
	//		return err
	//	}
	//}
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
		if err.Error() == ErrNotFound.Error() {
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


func GetLastDIDTxData(evm *EVM, issuerDID string) (*did.TranasactionData, error) {
	did := GetDIDFromUri(issuerDID)
	if did == "" {
		return nil, errors.New("WRONG DID FORMAT")
	}
	buf := new(bytes.Buffer)
	buf.WriteString(did)
	lastTXData, err := evm.StateDB.GetLastDIDTxData(buf.Bytes())

	if err != nil {
		if err.Error() == ErrNotFound.Error() {
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