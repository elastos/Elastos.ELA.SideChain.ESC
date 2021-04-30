pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

contract DID {

    constructor() {

    }
    function publishDidTransaction(string memory data) public  {
        uint method = 22;
        uint offSet = 32;
        uint outputSize = 32;
        uint256[1] memory result;
        uint256 inputSize = 0;
        uint256  leftGas =  gasleft();

        // string memory ttype = string(toBytesEth(txType));
        // string memory input = strConcat(ttype, didDocument);
        string memory input = didDocument;
        inputSize = bytes(input).length + offSet;

        assembly {
            if iszero(staticcall(leftGas, method, input, inputSize, result, outputSize)) {
                //  revert(0,0)
            }
        }
        if (result[0] != 1) {
             revert("diderror");
        }
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