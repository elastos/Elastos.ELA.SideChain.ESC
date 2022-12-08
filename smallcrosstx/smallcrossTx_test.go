package smallcrosstx

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/stretchr/testify/assert"
)

func TestSmallCrossTx_Deserialize(t *testing.T) {
	tx := &SmallCrossTx{
		RawTxID:     "215c669bf8fd2a7d8ebf9d2689428c1ed1e2a85c8292e6ee0032ae7732619606",
		RawTx:       "3e1b0efac4212580f1014ed68f8c432ed886b4888065e26dad8023feecc9c468",
		Signatures:  []string{"123", "456"},
		BlockHeight: 889898,
	}

	data := bytes.NewBuffer([]byte{})
	err := tx.Serialize(data)
	assert.NoError(t, err)
	hexString := common.BytesToHexString(data.Bytes())
	fmt.Println(common.BytesToHexString(data.Bytes()))

	tx2 := &SmallCrossTx{}
	tx2.Deserialize(data)
	assert.Equal(t, tx.RawTxID, tx2.RawTxID)
	assert.Equal(t, tx.RawTx, tx2.RawTx)
	assert.Equal(t, tx.Signatures, tx2.Signatures)
	assert.Equal(t, tx.BlockHeight, tx2.BlockHeight)

	byteData, err := common.HexStringToBytes(hexString)
	assert.NoError(t, err)
	data = bytes.NewBuffer(byteData[:len(byteData)-2])
	tx3 := &SmallCrossTx{}
	err = tx3.Deserialize(data)
	assert.Error(t, err)
}
