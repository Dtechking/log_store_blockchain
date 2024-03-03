const axios = require('axios');
const fs = require('fs');
const path = require('path');

const storedLogsDir = '/home/dtechking/Documents/Network Project Python/encrypted_logs';  // Update this path

function uploadLog(logFileName) {
    const filePath = path.join(storedLogsDir, logFileName);

    axios.post('http://localhost:3000/upload', { filePath })
        .then(response => {
            console.log(response.data);
        })
        .catch(error => console.error(error));
}

// Monitor the stored_logs directory for new logs and upload them
fs.watch(storedLogsDir, (eventType, filename) => {
  try {
      console.log(`Event type: ${eventType}, Filename: ${filename}`);
      if (filename && eventType === 'rename') {
          uploadLog(filename);
      }
  } catch (error) {
      console.error(`Error: ${error.message}`);
  }
});

