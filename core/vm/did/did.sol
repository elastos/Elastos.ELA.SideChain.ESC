pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

contract DID {
    constructor() {}

   //params[0] DIDDocumennt params[1] txType
    function operationDID(uint256 useGas, uint256 txType, string memory didDocument) public {
        uint method = 22;
        uint offSet = 32;
        uint outputSize = 32;
        uint256[1] memory result;
        uint256 inputSize = 0;


        string memory ttype = string(toBytesEth(txType));
        string memory input = strConcat(ttype, didDocument);

        inputSize = bytes(input).length + offSet;
        assembly {
            if iszero(staticcall(useGas, method, input, inputSize, result, outputSize)) {
                revert(0,0)
            }
        }

        require(result[0] == 1);
    }

    function toBytesEth(uint256 x) private returns (bytes memory b) {
        b = new bytes(32);
        for (uint i = 0; i < 32; i++) {
            b[i] = byte(uint8(x / (2**(8*(31 - i)))));
        }
    }

     function strConcat(string memory a, string memory b) private returns (string memory) {
        bytes memory ba = bytes(a);
        bytes memory bb = bytes(b);
        string memory ret = new string(ba.length + bb.length);
        bytes memory bret = bytes(ret);
        uint k = 0;
        for (uint i = 0; i < ba.length; i++)bret[k++] = ba[i];
        for (uint i = 0; i < bb.length; i++) bret[k++] = bb[i];
        return ret;
   }
}