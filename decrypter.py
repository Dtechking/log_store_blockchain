import os
import json
from cryptography.fernet import Fernet

def decrypt_logs(encrypted_file_path, secret_key):
    cipher_suite = Fernet(secret_key)

    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_logs = encrypted_file.read()

    # Decrypt the logs
    decrypted_logs = cipher_suite.decrypt(encrypted_logs)

    # Parse the decrypted JSON data
    try:
        decrypted_data = json.loads(decrypted_logs)
        return decrypted_data
    except json.JSONDecodeError as e:
        print(f"Error decoding decrypted JSON: {e}")
        return None

def decrypt_all_logs(encrypted_logs_dir, secret_key):
    decrypted_logs = {}

    # Iterate through all files in the encrypted_logs directory
    for filename in os.listdir(encrypted_logs_dir):
        if filename.endswith(".encrypted"):
            file_path = os.path.join(encrypted_logs_dir, filename)

            # Decrypt each file
            decrypted_data = decrypt_logs(file_path, secret_key)
            
            if decrypted_data:
                decrypted_logs[filename] = decrypted_data

    return decrypted_logs

def main():
    encrypted_logs_dir = './encrypted_logs'  # Update with your folder path
    secret_key = b'HCis_x7ogE9rxMjWkzjnM_dQ4xcvnlDubz2y9z6wmO8='  # Replace with your Fernet symmetric encryption key

    decrypted_logs = decrypt_all_logs(encrypted_logs_dir, secret_key)

    if decrypted_logs:
        print("Decrypted Logs:")
        for filename, data in decrypted_logs.items():
            print(f"File: {filename}")
            print(json.dumps(data, indent=2))
            print("-" * 50)

if __name__ == "__main__":
    main()
