package chainbridge_abi

import (
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
)

func GetSetArbitersABI() (abi.ABI, error) {
	definition := "[{\"inputs\": [{\"internalType\": \"address[]\",\"name\": \"_addressList\",\"type\": \"address[]\"},{\"internalType\": \"uint256\",\"name\": \"_addressCount\",\"type\": \"uint256\"},{\"internalType\": \"bytes[]\",\"name\": \"_sigList\",\"type\": \"bytes[]\"}],\"name\": \"setArbiterList\",\"outputs\": [],\"stateMutability\": \"nonpayable\",\"type\": \"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetArbitersABI() (abi.ABI, error) {
	definition := "[{\"inputs\":[],\"name\":\"getArbiterList\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetSignaturesABI() (abi.ABI, error) {
	definition := "[{\"inputs\": [],\"name\": \"getArbiterSigs\",\"outputs\": [{\"internalType\": \"bytes[]\",\"name\": \"\",\"type\": \"bytes[]\"}],\"stateMutability\": \"view\",\"type\": \"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetTotalCountABI() (abi.ABI, error) {
	definition := "[{\"inputs\": [],\"name\": \"getArbiterCount\",\"outputs\": [{\"internalType\": \"uint256\",\"name\": \"\",\"type\": \"uint256\"}],\"stateMutability\": \"view\",\"type\": \"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func UpdateArbiterABI() (abi.ABI, error) {
	definition := "[{\"anonymous\": false,\"inputs\": [{\"indexed\": false,\"internalType\": \"uint256\",\"name\": \"_addressCount\",\"type\": \"uint256\"}],\"name\": \"SetArbiterList\",\"type\": \"event\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}
