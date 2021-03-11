package did

import "github.com/elastos/Elastos.ELA/common"

const FeeRate int64 = 10000000000

type DIDParams struct {
	// CustomIDFeeRate defines the default fee rate of registerCustomID transaction
	CustomIDFeeRate common.Fixed64

	IsTest bool
}

var MainNetDIDParams = DIDParams{
	CustomIDFeeRate:            200000,
}

var TestNetDIDParams = DIDParams{
	CustomIDFeeRate:            200000,
}

var RegNetDIDParams = DIDParams{
	CustomIDFeeRate:            200000,
}