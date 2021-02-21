pragma solidity >=0.7.0 <0.8.0;

contract DID {
    
    constructor() {}

    function operationDID(uint256 useGas, string memory operation) public view {
        uint method = 22;
        uint offSet = 32;
        uint outputSize = 32;
        
        uint256[1] memory result;
     
        uint256 inpuSize = bytes(operation).length + offSet;
      
        assembly {
            if iszero(staticcall(useGas, method, operation, inpuSize, result, outputSize)) {
                revert(0,0)
            }
        }
       
        require(result[0] == 1);
    }
    
}