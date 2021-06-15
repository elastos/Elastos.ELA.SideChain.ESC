pragma solidity >0.7.0 <0.8.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/solc-0.7/contracts/proxy/Proxy.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/solc-0.7/contracts/utils/Address.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/solc-0.7/contracts/access/Ownable.sol";

contract DID_Proxy is Ownable, Proxy  {
  address private implementation;
  event Upgraded(address indexed implementation);

  constructor(address implementation) {
    _setImplementation(implementation);
   }
    
   function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "UpgradeableBeacon: implementation is not a contract");
        implementation = newImplementation;
    }
    
    function _upgradeTo(address newImplementation) public virtual onlyOwner {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }
    
    function _implementation() internal view virtual override  returns (address) {
        return implementation;
    }
    
}
