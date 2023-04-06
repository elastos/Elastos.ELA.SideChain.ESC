package pledgeBill

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"strings"
)

func GetMintTickFunABI() (abi.ABI, error) {
	definition := "[{\n      \"inputs\": [\n        {\n          \"internalType\": \"address\",\n          \"name\": \"to\",\n          \"type\": \"address\"\n        },\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"tokenId\",\n          \"type\": \"uint256\"\n        },\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"txHash\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"name\": \"mintTick\",\n      \"outputs\": [],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    }]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}

func GetTickFromTokenIdABI() (abi.ABI, error) {
	definition := "[{\n      \"inputs\": [\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"tokenId\",\n          \"type\": \"uint256\"\n        }\n      ],\n      \"name\": \"getTickFromTokenId\",\n      \"outputs\": [\n        {\n          \"components\": [\n            {\n              \"internalType\": \"address\",\n              \"name\": \"owner\",\n              \"type\": \"address\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"amount\",\n              \"type\": \"uint256\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"startTimeSpan\",\n              \"type\": \"uint256\"\n            },\n            {\n              \"internalType\": \"string\",\n              \"name\": \"supperNode\",\n              \"type\": \"string\"\n            },\n            {\n              \"internalType\": \"bytes32\",\n              \"name\": \"txHash\",\n              \"type\": \"bytes32\"\n            },\n            {\n              \"internalType\": \"string\",\n              \"name\": \"withDrawTo\",\n              \"type\": \"string\"\n            }\n          ],\n          \"internalType\": \"struct StakeTicket.TickInfo\",\n          \"name\": \"\",\n          \"type\": \"tuple\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    }]"
	a, err := abi.JSON(strings.NewReader(definition))
	return a, err
}
