#!/bin/bash

LOG_DIR="./captured_logs"
PROCESSED_DIR="./processed_logs"

while true; do
    for log_file in $LOG_DIR/*.json; do
        if [ -e "$log_file" ]; then
            # Compress and encrypt the log
            python3 log_compress_cli.py "$log_file"
            echo "File Compressed..."
            sleep 5
            # Move the processed log to the processed_logs directory
            mv "$log_file" "$PROCESSED_DIR/."
            echo "File moved..."
            # Wait for a few seconds before processing the next log
            sleep 3
        fi
    done
    # Wait before processing new logs
    sleep 2
done
