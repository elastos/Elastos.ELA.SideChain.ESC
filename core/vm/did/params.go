package did

import "github.com/elastos/Elastos.ELA/common"

const FeeRate int64 = 10000000000

type DIDParams struct {
	// CheckRegisterDIDHeight defines the height to check RegisterDID transactions.
	CheckRegisterDIDHeight uint32

	// VerifiableCredentialHeight defines the height to VeriﬁableCredential.
	VerifiableCredentialHeight uint32

	// CustomIDFeeRate defines the default fee rate of registerCustomID transaction
	CustomIDFeeRate common.Fixed64

	IsTest bool
}

var MainNetDIDParams = DIDParams{
	CheckRegisterDIDHeight:     2000000,
	VerifiableCredentialHeight: 2000000,
	CustomIDFeeRate:            200000,
}

var TestNetDIDParams = DIDParams{
	CheckRegisterDIDHeight:     528000,
	VerifiableCredentialHeight: 420000,
	CustomIDFeeRate:            200000,
}

var RegNetDIDParams = DIDParams{
	CheckRegisterDIDHeight:     528000,
	VerifiableCredentialHeight: 420000,
	CustomIDFeeRate:            200000,
}