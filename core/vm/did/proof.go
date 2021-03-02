package did

import (
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

// Proof of DID transaction payload
type Proof struct {
	Type               string `json:"type,omitempty"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}

// Proof of DID transaction payload
type DocProof struct {
	Type           string `json:"type,omitempty"`
	Created        string `json:"created"`
	Creator        string `json:"creator"`
	SignatureValue string `json:"signatureValue"`
}

// Proof of DID transaction payload
type CredentialProof struct {
	Type               string `json:"type,omitempty"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}

// Proof of DID transaction payload
type TicketProof struct {
	Type               string `json:"type,omitempty"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	SignatureValue     string `json:"signatureValue"`
}

func (d *Proof) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Type); err != nil {
		return errors.New("[Proof], Type serialize failed.")
	}

	if err := common.WriteVarString(w, d.VerificationMethod); err != nil {
		return errors.New("[Proof], VerificationMethod serialize failed.")
	}

	if err := common.WriteVarString(w, d.Signature); err != nil {
		return errors.New("[Proof], Signature serialize failed.")
	}
	return nil
}

func (d *Proof) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Type, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[Proof], Type deserialize failed.")
	}

	d.VerificationMethod, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[Proof], VerificationMethod deserialize failed.")
	}

	d.Signature, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[Proof], Signature deserialize failed.")
	}
	return nil
}

func (d *DocProof) Serialize(w io.Writer, version byte) error {
	if err := common.WriteVarString(w, d.Type); err != nil {
		return errors.New("[DocProof], Type serialize failed.")
	}
	if err := common.WriteVarString(w, d.Created); err != nil {
		return errors.New("[DocProof], Created serialize failed.")
	}
	if err := common.WriteVarString(w, d.Creator); err != nil {
		return errors.New("[DocProof], Created serialize failed.")
	}
	if err := common.WriteVarString(w, d.SignatureValue); err != nil {
		return errors.New("[DocProof], Signature serialize failed.")
	}
	return nil
}

func (d *DocProof) Deserialize(r io.Reader, version byte) error {
	var err error
	d.Type, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DocProof], Type deserialize failed.")
	}
	d.Created, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DocProof], Created deserialize failed.")
	}
	d.Creator, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DocProof], Creator deserialize failed.")
	}
	d.SignatureValue, err = common.ReadVarString(r)
	if err != nil {
		return errors.New("[DocProof], SignatureValue deserialize failed.")
	}
	return nil
}
