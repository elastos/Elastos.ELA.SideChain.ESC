package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA/common"
	"io"
)

const DIDVersion = 0x00
const VerifiableCredentialVersion = 0x00

const (
	Create_DID_Operation                    = "create"
	Update_DID_Operation                    = "update"
	Transfer_DID_Operation                  = "transfer"
	Deactivate_DID_Operation                = "deactivate"
	Declare_Verifiable_Credential_Operation = "declare"
	Revoke_Verifiable_Credential_Operation  = "revoke"
	DID_ELASTOS_PREFIX                      = "did:elastos:"
	ID_STRING                               = "id"
)

// payload of DID transaction
type DIDPayload struct {
	Header  Header `json:"header"`
	Payload string `json:"payload"`
	Proof   Proof  `json:"proof"`

	DIDDoc        *DIDDoc
	CredentialDoc *VerifiableCredentialDoc
	Ticket        *CustomIDTicket
}

type DIDTransactionData struct {
	TXID      string     `json:"txid"`
	Timestamp string     `json:"timestamp"`
	Operation DIDPayload `json:"operation"`
}

// header of Customized DID transaction payload
type Header struct {
	Specification string `json:"specification"`
	Operation     string `json:"operation"`
	PreviousTxid  string `json:"previousTxid,omitempty"`
	Ticket        string `json:"ticket,omitempty"`
}


func (d *Header) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Specification); err != nil {
		return errors.New("[Header], Specification serialize failed.")
	}

	if err := common.WriteVarString(w, d.Operation); err != nil {
		return errors.New("[Header], Operation serialize failed.")
	}
	if d.Operation == Update_DID_Operation {
		if err := common.WriteVarString(w, d.PreviousTxid); err != nil {
			return errors.New("[Header], PreviousTxid serialize failed.")
		}
	}
	if d.Operation == Transfer_DID_Operation {
		if err := common.WriteVarString(w, d.Ticket); err != nil {
			return errors.New("[Header], Ticket serialize failed")
		}
	}
	return nil
}

func (d *Header) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Specification, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[Header], Specification deserialize failed.")
	}

	d.Operation, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[Header], Operation deserialize failed.")
	}
	if d.Operation == Update_DID_Operation {
		d.PreviousTxid, err = common.ReadVarString(r)
		if err != nil {
			return errors.New("[Header], PreviousTxid deserialize failed.")
		}
	}
	if d.Operation == Transfer_DID_Operation {
		d.Ticket, err = common.ReadVarString(r)
		if err != nil {
			return errors.New("[Header], Ticket deserialize failed")
		}
	}
	return nil
}

type CustomIDTicket struct {
	CustomID      string      `json:"id"`
	To            string      `json:"to"`
	TransactionID string      `json:"txid"`
	Proof         interface{} `json:"proof"`
}

func (c *CustomIDTicket) GetData() []byte {
	dataString := c.CustomID + c.To + c.TransactionID
	return []byte(dataString)
}



func (p *DIDPayload) GetDIDDoc() *DIDDoc {
	return p.DIDDoc
}

func (p *DIDPayload) Data(version byte) []byte {
	switch p.Header.Operation {
	case Create_DID_Operation, Update_DID_Operation, Transfer_DID_Operation, Deactivate_DID_Operation:
		buf := new(bytes.Buffer)
		if err := p.Header.Serialize(buf, version); err != nil {
			return nil
		}
		if err := common.WriteVarString(buf, p.Payload); err != nil {
			return nil
		}
		return buf.Bytes()
	case Declare_Verifiable_Credential_Operation, Revoke_Verifiable_Credential_Operation:
		buf := new(bytes.Buffer)
		if err := p.Header.Serialize(buf, version); err != nil {
			return nil
		}
		if err := common.WriteVarString(buf, p.Payload); err != nil {
			return nil
		}
		return buf.Bytes()
	}
	return []byte{}
}


func (p *DIDPayload) Serialize(w io.Writer, version byte) error {
	if err := p.Header.Serialize(w, version); err != nil {
		return errors.New("[DIDPayload], Header serialize failed," + err.Error())
	}

	if err := common.WriteVarString(w, p.Payload); err != nil {
		return errors.New("[DIDPayload], Payload serialize failed")
	}

	//serialize CustomizedDIDProof
	if err := p.Proof.Serialize(w, DIDVersion); err != nil {
		return errors.New("[DIDPayload], Proof serialize failed")
	}

	return nil
}

func (p *DIDPayload) Deserialize(r io.Reader, version byte) error {
	if err := p.Header.Deserialize(r, version); err != nil {
		return errors.New("[DIDPayload], Header deserialize failed" + err.Error())
	}

	payload, err := common.ReadVarString(r)
	if err != nil {
		return errors.New("[DIDPayload], payload deserialize failed")
	}
	p.Payload = payload

	if err := p.Proof.Deserialize(r, version); err != nil {
		return errors.New("[DIDPayload], Proof deserialize failed")
	}

	// get ticket from header.ticket
	switch p.Header.Operation {
	case Create_DID_Operation, Update_DID_Operation, Deactivate_DID_Operation:
		// get DIDDIDDoc from payload data
		pBytes, err := base64url.DecodeString(p.Payload)
		if err != nil {
			return errors.New("[DIDPayload], payload decode failed")
		}
		DIDDoc := new(DIDDoc)
		if err := json.Unmarshal(pBytes, DIDDoc); err != nil {
			return errors.New("[DIDPayload], payload unmarshal failed")
		}
		p.DIDDoc = DIDDoc
	case Transfer_DID_Operation:
		tBytes, err := base64url.DecodeString(p.Header.Ticket)
		if err != nil {
			return errors.New("[DIDPayload], ticket decode failed")
		}
		ticket := new(CustomIDTicket)
		if err := json.Unmarshal(tBytes, ticket); err != nil {
			return errors.New("[DIDPayload], ticket unmarshal failed")
		}
		p.Ticket = ticket
	case Declare_Verifiable_Credential_Operation, Revoke_Verifiable_Credential_Operation:
		// get DIDDIDDoc from payload data
		pBytes, err := base64url.DecodeString(p.Payload)
		if err != nil {
			return errors.New("[VerifiableCredentialPayload], payload decode failed")
		}
		doc := new(VerifiableCredentialDoc)
		if err := json.Unmarshal(pBytes, doc); err != nil {
			return errors.New("[VerifiableCredentialPayload], payload unmarshal failed")
		}
		p.CredentialDoc = doc
	}

	return nil
}

func (p *DIDPayload) GetData() []byte {
	var dataString string
	switch p.Header.Operation {
	case Update_DID_Operation:
		dataString = p.Header.Specification + p.Header.Operation + p.Header.
			PreviousTxid + p.Payload

	case Create_DID_Operation, Transfer_DID_Operation, Deactivate_DID_Operation:
		dataString = p.Header.Specification + p.Header.Operation + p.Payload

	case Declare_Verifiable_Credential_Operation, Revoke_Verifiable_Credential_Operation:
		dataString = p.Header.Specification + p.Header.Operation + p.Payload
	}

	return []byte(dataString)
}