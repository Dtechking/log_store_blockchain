// SPDX-License-Identifier: MIT
pragma solidity ^0.5.1;

contract LogFileReader {
    string public netLogData;
    mapping(address => string) public logData;

    constructor() public {}

    function requestFileData(string memory fileData) public {
        require(bytes(fileData).length > 0, "Invalid fileData");
        
        logData[msg.sender] = fileData;
    }

    function getLogData() public view returns (string memory) {
        return logData[msg.sender];
    }
}
