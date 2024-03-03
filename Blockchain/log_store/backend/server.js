// Install required packages:
// npm install express web3 multer

const express = require('express');
const multer = require('multer');
const { Web3 } = require('web3');
const fs = require('fs');

const app = express();
const port = 3000;

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const web3 = new Web3('http://localhost:7545');
const privateKey = '0x38476fb9c600e361d00fa9d371baf64a143c37dde55b08af4fdbdd2f9706bda8'; // Replace with your private key
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


const contractAddress = '0x79cA7699AD5c85F4724812f7aF7A3D575aA37b65'; // Insert your contract address
const contract = new web3.eth.Contract(abi, contractAddress);

app.use(express.json());

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const filePath = req.body.filePath;
    const fileData = fs.readFileSync(filePath, 'utf-8');

    const transaction = contract.methods.requestFileData(fileData).send({
      from: account.address,
      gas: 10000000000, // Adjust the gas limit accordingly
    });

    const receipt = await transaction;
    res.json({ success: true, transactionHash: receipt.transactionHash });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
