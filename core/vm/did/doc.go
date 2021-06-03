package did

import (
	"errors"
	"io"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/didjson"

	"github.com/elastos/Elastos.ELA/common"
)

// payload in DID transaction payload
type DIDDoc struct {
	*DIDPayloadData
	Proof interface{} `json:"proof,omitempty"`
}

type VerifiableCredentialDoc struct {
	*VerifiableCredential `json:"verifiableCredential,omitempty"`
}

type VerifiableCredential struct {
	*VerifiableCredentialData
	Proof CredentialProof `json:"proof,omitempty"`
}

type VerifiableCredentialTxData struct {
	TXID      string     `json:"txid"`
	Timestamp string     `json:"timestamp"`
	Operation DIDPayload `json:"operation"`
}

func (p *VerifiableCredential) GetDIDProofInfo() *CredentialProof {
	return &p.Proof
}

func (p *VerifiableCredential) CompleteCompact(did string) {
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

type VerifiableCredentialData struct {
	ID                string      `json:"id"`
	Type              []string    `json:"type,omitempty"`
	Issuer            string      `json:"issuer,omitempty"`
	IssuanceDate      string      `json:"issuanceDate,omitempty"`
	ExpirationDate    string      `json:"expirationDate,omitempty"`
	CredentialSubject interface{} `json:"credentialSubject,omitempty"`
}

func (p *VerifiableCredentialData) GetData() []byte {
	data, err := didjson.Marshal(p)
	if err != nil {
		return nil
	}
	return data
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
	//user define extra property
	//ExtraProperty interface{} `json:"extraProperty,omitempty"`
}

type DIDPayloadData struct {
	ID                   string                 `json:"id"`
	Controller           interface{}            `json:"controller,omitempty"`
	MultiSig             string                 `json:"multisig,omitempty"`
	PublicKey            []DIDPublicKeyInfo     `json:"publicKey,omitempty"`
	Authentication       []interface{}          `json:"authentication,omitempty"`
	Authorization        []interface{}          `json:"authorization,omitempty"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
	Service              []Service              `json:"service,omitempty"`
	Expires              string                 `json:"expires"`
}

func (c *DIDPayloadData) GetData() []byte {
	data, err := didjson.Marshal(c)
	if err != nil {
		return nil
	}
	println("data ", string(data))
	return data
}

// public keys of payload in DID transaction payload
type DIDPublicKeyInfo struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}


func (p *DIDPublicKeyInfo) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, p.ID); err != nil {
		return errors.New("[DIDPublicKeyInfo], ID serialize failed.")
	}
	if err := common.WriteVarString(w, p.Type); err != nil {
		return errors.New("[DIDPublicKeyInfo], Type serialize failed.")
	}
	if err := common.WriteVarString(w, p.Controller); err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller serialize failed.")
	}
	if err := common.WriteVarString(w, p.PublicKeyBase58); err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 serialize failed.")
	}

	return nil
}

func (p *DIDPublicKeyInfo) Deserialize(r io.Reader, version byte) error {
	id, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], ID deserialize failed")
	}
	p.ID = id

	typePkInfo, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Type deserialize failed")
	}
	p.Type = typePkInfo

	controller, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], Controller deserialize failed")
	}
	p.Controller = controller

	pkBase58, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPublicKeyInfo], PublicKeyBase58 deserialize failed")
	}
	p.PublicKeyBase58 = pkBase58

	return nil
}


func IsCompact(target string) bool {
	if !strings.HasPrefix(target, DID_ELASTOS_PREFIX) {
		return true
	}
	return false
}



