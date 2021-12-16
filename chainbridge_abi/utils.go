package chainbridge_abi

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"strings"
)

func GetExecuteProposalAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes[]\",\"name\":\"sig\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes\",\"name\":\"superSig\",\"type\":\"bytes\"}],\"name\":\"executeProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetExecuteBatchProposalAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64[]\",\"name\":\"depositNonce\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"data\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes32[]\",\"name\":\"resourceID\",\"type\":\"bytes32[]\"},{\"internalType\":\"bytes[]\",\"name\":\"sig\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes\",\"name\":\"superSig\",\"type\":\"bytes\"}],\"name\":\"executeProposalBatch\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetLayer2DepositAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"destinationChainID\",\"type\":\"uint8\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"}],\"name\":\"deposit\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetExecuteProposalNoSig() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"}],\"name\":\"executeProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetProposal() (abi.ABI, error)  {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"originChainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes32\",\"name\":\"dataHash\",\"type\":\"bytes32\"}],\"name\":\"getProposal\",\"outputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"_resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"_dataHash\",\"type\":\"bytes32\"},{\"internalType\":\"enum Bridge.ProposalStatus\",\"name\":\"_status\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_proposedBlock\",\"type\":\"uint256\"}],\"internalType\":\"struct Bridge.Proposal\",\"name\":\"\",\"type\":\"tuple\" }],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetDepositRecordABI() (abi.ABI, error)  {
	definition := "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint8\",\"name\":\"_destinationChainID\",\"type\":\"uint8\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"_resourceID\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"_depositNonce\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_depositer\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"_amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"_fee\",\"type\":\"uint256\"}],\"name\":\"DepositRecord\",\"type\":\"event\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetChangeSuperSignerABI() (abi.ABI, error)  {
	definition := "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_oldSuperSigner\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"_newSuperSigner\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"_nodePublickey\",\"type\":\"bytes\"}],\"name\":\"ChangeSuperSigner\",\"type\":\"event\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetExecuteBatchNoSigABI() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64[]\",\"name\":\"depositNonce\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"data\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes32[]\",\"name\":\"resourceID\",\"type\":\"bytes32[]\"}],\"name\":\"executeProposalBatch\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetCurrentSuperSignerABI() (abi.ABI, error) {
	definition := "[{\"inputs\":[],\"name\":\"getCurrentSuperSigner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetSuperSignerNodePublickey() (abi.ABI, error) {
	definition := "[{\"inputs\":[],\"name\":\"getSuperSignerNodePublickey\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetTestExecuteProposalAbi() (abi.ABI, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64[]\",\"name\":\"depositNonce\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"data\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes32[]\",\"name\":\"resourceID\",\"type\":\"bytes32[]\"}],\"name\":\"test\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}