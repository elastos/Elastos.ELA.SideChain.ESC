package pledgeBill

import (
	"encoding/binary"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/smallcrosstx"
)

func GetIndexByKey(Key string) (uint64, error) {
	transactionDBMutex.Lock()
	defer transactionDBMutex.Unlock()

	data, err := spvTransactiondb.Get([]byte(Key))
	if err.Error() == smallcrosstx.ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(data) != 8 {
		return 0, nil
	}
	return binary.BigEndian.Uint64(data), nil
}

func EncodeUnTransactionNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}
