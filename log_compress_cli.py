import json
import os
from cryptography.fernet import Fernet

# Replace 'SECRET_KEY' with your own key
SECRET_KEY = b'HCis_x7ogE9rxMjWkzjnM_dQ4xcvnlDubz2y9z6wmO8='
cipher_suite = Fernet(SECRET_KEY)

def preprocess_log(log_file_path):
    try:
        with open(log_file_path, 'r') as file:
            log_data = json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return []
    
    processed_logs = []  # Initialize the list

    key_mapping = {
        "PacketNumber": "PNo", "Timestamp": "TS", "SourceMAC": "SMAC",
        "DestinationMAC": "DMAC", "SourceIP": "SIP", "DestinationIP": "DIP",
        "SourcePort": "SP", "DestinationPort": "DP", "Info": "Info",
        "HexRepresentation": "HexRep", "Length": "L"
    }

    for log_entry in log_data:
        processed_entry = {
            key_mapping[key]: log_entry.get(key, "N/A") for key, value in key_mapping.items()
        }
        processed_logs.append(processed_entry)

    return processed_logs

def logs_encode(logs):
    encoded_logs = []
    previous_log = {}

    for log in logs:
        encoded_log = {}

        for key, value in log.items():
            if key in previous_log:
                # Perform delta encoding
                encoded_log[key] = value if value != previous_log[key] else ""
            else:
                encoded_log[key] = value

        encoded_logs.append(encoded_log)
        previous_log = log

    return encoded_logs

def encrypt_logs(logs, secret_key, output_path):
    """
    Encrypt the logs using Fernet symmetric encryption and save to a new file.
    """
    encrypted_logs = cipher_suite.encrypt(json.dumps(logs).encode())
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_logs)

def main(log_file_path):
    # Preprocess the log file
    preprocessed_logs = preprocess_log(log_file_path)

    # Perform delta encoding
    encoded_logs = logs_encode(preprocessed_logs)

    # Save the compressed log data
    compressed_file_path = f'./compressed_logs/compressed_log_{len(os.listdir("./compressed_logs")) + 1}.json'
    with open(compressed_file_path, 'w') as compressed_file:
        json.dump(encoded_logs, compressed_file, indent=2)

    # Encrypt the compressed log data and save to a new file
    encrypted_file_path = f'./encrypted_logs/encrypted_log_{len(os.listdir("./encrypted_logs")) + 1}.encrypted'
    encrypt_logs(encoded_logs, SECRET_KEY, encrypted_file_path)

    print(f"Secret Key: {SECRET_KEY}")
    print(f"Log compressed and encrypted successfully: {compressed_file_path}")
    print(f"Encrypted log saved to: {encrypted_file_path}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python log_compress.py <log_file_path>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    main(log_file_path)
