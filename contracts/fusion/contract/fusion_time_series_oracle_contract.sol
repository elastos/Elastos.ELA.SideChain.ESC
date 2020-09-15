pragma solidity ^0.5.0;

import "github.com/starkware-libs/veedo/blob/master/contracts/BeaconContract.sol";

contract Beacon{
    function getLatestRandomness()external view returns(uint256,bytes32){}
    
}

contract FusionLedgerTimeSeriesOracle {

    address public oracleAddress;
  
    address public BeaconContractAddress=0x79474439753C7c70011C3b00e06e559378bAD040;

    constructor (address _oracleAddress) public {
    oracleAddress = _oracleAddress;
    }
  
    function setBeaconContractAddress(address _address) public  {
        BeaconContractAddress=_address;
    }
    
    function generateRandomNumber() public view returns(bytes32){
        uint blockNumber;
        bytes32 randomNumber;
        Beacon beacon=Beacon(BeaconContractAddress);
        (blockNumber,randomNumber)=beacon.getLatestRandomness();
        return randomNumber;
    }

    
    //Time Series Average Index
    uint public time_series_average_number;
    
    //function setting Time Series Avarge from the Data Source
    function setTimeSeriesAverage(uint _number) public {
        time_series_average_number = block.timestamp + _number;
    }
    
    //getter for the Time Sries Average Index
    function getTimeSeriesAverage() public view returns (uint) {
      
      require(msg.sender == oracleAddress);

        if ((bytes32(block.number))> generateRandomNumber()) {
    
        return time_series_average_number;
      }
    }
}
