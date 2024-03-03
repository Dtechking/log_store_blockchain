const axios = require('axios');
const fs = require('fs');

const filePath = '/home/dtechking/Documents/Network Project Python/encrypted_logs/encrypted_log.encrypted';

axios.post('http://localhost:3000/upload', { filePath })
  .then(response => console.log(response.data))
  .catch(error => console.error(error));
