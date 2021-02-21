package did

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"

	"github.com/elastos/Elastos.ELA/common"
)

const DIDInfoVersion = 0x00

//const VerifiableCredentialVersion = 0x01

const DID_ELASTOS_PREFIX = "did:elastos:"
const ID_STRING = "id"

const (
	Create_DID_Operation     = "create"
	Update_DID_Operation     = "update"
	Deactivate_DID_Operation = "deactivate"
	Transfer_DID_Operation = "transfer"
)

// header of DID transaction payload
type DIDHeaderInfo struct {
	Specification string `json:"specification"`
	Operation     string `json:"operation"`
	PreviousTxid  string `json:"previousTxid,omitempty"`
}

func (d *DIDHeaderInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Specification); err != nil {
		return errors.New("[DIDHeaderInfo], Specification serialize failed.")
	}

	if err := common.WriteVarString(w, d.Operation); err != nil {
		return errors.New("[DIDHeaderInfo], Operation serialize failed.")
	}
	if d.Operation == Update_DID_Operation {
		if err := common.WriteVarString(w, d.PreviousTxid); err != nil {
			return errors.New("[DIDHeaderInfo], PreviousTxid serialize failed.")
		}
	}

	return nil
}

func (d *DIDHeaderInfo) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Specification, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDHeaderInfo], Specification deserialize failed.")
	}

	d.Operation, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDHeaderInfo], Operation deserialize failed.")
	}
	if d.Operation == Update_DID_Operation {
		d.PreviousTxid, err = common.ReadVarString(r)
		if err != nil {
			return errors.New("[DIDHeaderInfo], PreviousTxid deserialize failed.")
		}
	}

	return nil
}

// Proof of DID transaction payload
type DIDProofInfo struct {
	Type string `json:"type,omitempty"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}


func (d *DIDProofInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Type); err != nil {
		return errors.New("[DIDProofInfo], Type serialize failed.")
	}

	if err := common.WriteVarString(w, d.VerificationMethod); err != nil {
		return errors.New("[DIDProofInfo], VerificationMethod serialize failed.")
	}

	if err := common.WriteVarString(w, d.Signature); err != nil {
		return errors.New("[DIDProofInfo], Signature serialize failed.")
	}
	return nil
}

func (d *DIDProofInfo) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Type, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], Type deserialize failed.")
	}

	d.VerificationMethod, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], VerificationMethod deserialize failed.")
	}

	d.Signature, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDProofInfo], Signature deserialize failed.")
	}
	return nil
}

// public keys of payload in DID transaction payload
type DIDPublicKeyInfo struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

type VerifiableCredentialData struct {
	ID                string      `json:"id"`
	Type              []string    `json:"type,omitempty"`
	Issuer            string      `json:"issuer,omitempty"`
	IssuanceDate      string      `json:"issuanceDate,omitempty"`
	ExpirationDate    string      `json:"expirationDate,omitempty"`
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
}


func (p *VerifiableCredentialData) GetData() []byte {
	data, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	return data
}

func (p *VerifiableCredentialData) CompleteCompact(did string) {
	if IsCompact(p.Issuer) {
		p.Issuer = did + p.Issuer
	}
	if IsCompact(p.ID) {
		p.ID = did + p.ID
	}

	creSub := p.CredentialSubject.(map[string]interface{})
	realIssuer := ""
	for k, v := range creSub {
		if k == ID_STRING {
			realIssuer = v.(string)
			break
		}
	}
	if realIssuer == "" {
		creSub[ID_STRING] = did
	}
}

// Proof of DID transaction payload
type InnerDIDProofInfo struct {
	Type               string `json:"type,omitempty"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}

type VerifiableCredentialDoc struct {
	*VerifiableCredential `json:"verifiableCredential,omitempty"`
}

type VerifiableCredential struct {
	*VerifiableCredentialData
	Proof InnerDIDProofInfo `json:"proof,omitempty"`
}

func (p *VerifiableCredential) GetDIDProofInfo() *InnerDIDProofInfo {
	return &p.Proof
}

// payload in DID transaction payload
type DIDPayloadInfo struct {
	ID                   string                 `json:"id"`
	PublicKey            []DIDPublicKeyInfo     `json:"publicKey"`
	Authentication       []interface{}          `json:"authentication"`
	Authorization        []interface{}          `json:"authorization"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	Expires              string                 `json:"expires"`
}


// payload of DID transaction
type Operation struct {
	Header  DIDHeaderInfo `json:"header"`
	Payload string        `json:"payload"`
	Proof   DIDProofInfo  `json:"proof"`

	PayloadInfo *DIDPayloadInfo
}


func (p *Operation) Serialize(w io.Writer, version byte) error {
	if err := p.Header.Serialize(w, version); err != nil {
		return errors.New("[Operation], Header serialize failed," + err.Error())
	}

	if err := common.WriteVarString(w, p.Payload); err != nil {
		return errors.New("[Operation], Payload serialize failed")
	}

	if err := p.Proof.Serialize(w, version); err != nil {
		return errors.New("[Operation], Proof serialize failed," + err.Error())
	}

	return nil
}

func (p *Operation) Deserialize(r io.Reader, version byte) error {
	if err := p.Header.Deserialize(r, version); err != nil {
		return errors.New("[DIDInfo], Header deserialize failed" + err.Error())
	}

	payload, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDInfo], payload deserialize failed")
	}
	p.Payload = payload

	if err := p.Proof.Deserialize(r, version); err != nil {
		return errors.New("[DIDInfo], Proof deserialize failed," + err.Error())
	}
	// get DIDPayloadInfo from payload data
	pBytes, err := base64url.DecodeString(p.Payload)
	if err != nil {
		return errors.New("[DIDInfo], payload decode failed")
	}
	payloadInfo := new(DIDPayloadInfo)
	if err := json.Unmarshal(pBytes, payloadInfo); err != nil {
		return errors.New("[DIDInfo], payload unmarshal failed")
	}
	p.PayloadInfo = payloadInfo
	return nil
}

func (p *Operation) GetData() []byte {
	var dataString string
	if p.Header.Operation == Update_DID_Operation {
		dataString = p.Header.Specification + p.Header.Operation + p.Header.
			PreviousTxid + p.Payload

	} else {
		dataString = p.Header.Specification + p.Header.Operation + p.Payload

	}
	return []byte(dataString)
}


type TranasactionData struct {
	TXID      string    `json:"txid"`
	Timestamp string    `json:"timestamp"`
	Operation Operation `json:"operation"`
}

func (p *TranasactionData) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, p.TXID); err != nil {
		return errors.New("[TranasactionData], TXID serialize failed")
	}

	if err := common.WriteVarString(w, p.Timestamp); err != nil {
		return errors.New("[TranasactionData], Timestamp serialize failed")
	}

	if err := p.Operation.Serialize(w, version); err != nil {
		return errors.New("[TranasactionData] Operation serialize failed," +
			"" + err.Error())
	}

	return nil
}

func IsCompact(target string) bool {
	if !strings.HasPrefix(target, DID_ELASTOS_PREFIX) {
		return true
	}
	return false
}