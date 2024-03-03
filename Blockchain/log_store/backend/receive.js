const Web3 = require('web3');
const fs = require('fs');

const web3 = new Web3('http://localhost:7545'); // Replace with your Ganache RPC endpoint
const privateKey = '0xce7cc23b0b87fe4fe2f93b53edf4ff839a84f8538217af5094d8af8dea254053'; // Replace with your private key
const account = web3.eth.accounts.privateKeyToAccount(privateKey);
web3.eth.accounts.wallet.add(account);

const abi = [
    {
      "constant": true,
      "inputs": [
        {
          "name": "",
          "type": "address"
        }
      ],
      "name": "encryptedLogs",
      "outputs": [
        {
          "name": "",
          "type": "bytes"
        }
      ],
      "payable": false,
      "stateMutability": "view",
      "type": "function"
    },
    {
      "constant": true,
      "inputs": [],
      "name": "netLogData",
      "outputs": [
        {
          "name": "",
          "type": "string"
        }
      ],
      "payable": false,
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "payable": false,
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "constant": false,
      "inputs": [
        {
          "name": "fileData",
          "type": "string"
        }
      ],
      "name": "requestFileData",
      "outputs": [],
      "payable": false,
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "constant": true,
      "inputs": [],
      "name": "getEncryptedLogData",
      "outputs": [
        {
          "name": "",
          "type": "bytes"
        }
      ],
      "payable": false,
      "stateMutability": "view",
      "type": "function"
    }
  ];// Insert your ABI
  

const contractAddress = '0x1e2b6f494bbCDe26C1A1480d3341B272aB1fEB4b'; // Replace with your contract address
const contract = new web3.eth.Contract(abi, contractAddress);

async function retrieveLogData() {
  try {
    const result = await contract.methods.getLogData().call({ from: account.address });

    // Store the result in a file
    fs.writeFileSync('./logData.txt', result);

    console.log('Log data retrieved and stored in logData.txt');
  } catch (error) {
    console.error('Error retrieving log data:', error);
  }
}

retrieveLogData();
