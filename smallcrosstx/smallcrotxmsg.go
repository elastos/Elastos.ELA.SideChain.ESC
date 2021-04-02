package smallcrosstx

type SmallCrossTx struct {
	RawTxID string
	RawTx string
	Signatures []string
}

type ETSmallCrossTx struct {
	RawTx string
	Signature string
}