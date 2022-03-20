package chainbridge_abi

import (
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
)

func GetExecuteProposalAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"chainID\",\"type\":\"uint64\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes[]\",\"name\":\"sig\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes\",\"name\":\"superSig\",\"type\":\"bytes\"}],\"name\":\"executeProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetLayer2DepositAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"destinationChainID\",\"type\":\"uint64\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"deposit\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetDepositRecordABI() (abi.ABI, error) {
	definition := "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"_destinationChainID\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"_resourceID\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"_depositNonce\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_depositer\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"_fee\",\"type\":\"uint256\"}],\"name\":\"DepositRecordERC20OrWETH\",\"type\":\"event\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetArbitersABI() (abi.ABI, error) {
	definition := "[{\"inputs\":[],\"name\":\"getAbiterList\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetSignaturesABI() (abi.ABI, error) {
	definition := "[{\"inputs\": [],\"name\": \"getAbiterSigs\",\"outputs\": [{\"internalType\": \"bytes[]\",\"name\": \"\",\"type\": \"bytes[]\"}],\"stateMutability\": \"view\",\"type\": \"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetTotalCountABI() (abi.ABI, error) {
	definition := "[{\"inputs\": [],\"name\": \"getAbiterCount\",\"outputs\": [{\"internalType\": \"uint256\",\"name\": \"\",\"type\": \"uint256\"}],\"stateMutability\": \"view\",\"type\": \"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func UpdateArbiterABI() (abi.ABI, error) {
	definition := "[{\"anonymous\": false,\"inputs\": [{\"indexed\": false,\"internalType\": \"uint256\",\"name\": \"_addressCount\",\"type\": \"uint256\"}],\"name\": \"SetAbiterList\",\"type\": \"event\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}
