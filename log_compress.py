import json
from cryptography.fernet import Fernet
import os 

# Replace 'YOUR_SECRET_KEY' with your own key
SECRET_KEY = Fernet.generate_key()
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

def encrypt_logs(logs, secret_key):
    """
    Encrypt the logs using Fernet symmetric encryption.
    """
    encrypted_logs = cipher_suite.encrypt(json.dumps(logs).encode())
    with open('./encrypted_logs/encrypted_log.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_logs)

def main():
    log_file_path = './captured_logs/packet_logs.json'

    # Preprocess the log file
    preprocessed_logs = preprocess_log(log_file_path)

    # Perform delta encoding
    encoded_logs = logs_encode(preprocessed_logs)

    # Save the compressed log data
    with open('./compressed_logs/compressed_log_1.json', 'w') as compressed_file:
        json.dump(encoded_logs, compressed_file, indent=2)

    # Encrypt the compressed log data
    encrypt_logs(encoded_logs, SECRET_KEY)

if __name__ == "__main__":
    main()
