import os
import hashlib

def calculate_sha256(file_path):
    try:
        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256()
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_directory(directory, suspicious_hashes):
    found = False  
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning: {file_path}")  
            file_hash = calculate_sha256(file_path)
            if file_hash:
                print(f"Hash: {file_hash}")  
                if file_hash in suspicious_hashes:
                    print(f"[ALERT] Suspicious file detected: {file_path}")
                    found = True
                else:
                    print(f"[SAFE] {file_path}")

    if not found:
        print("No suspicious files found.")

if __name__ == "__main__":
    suspicious_hashes = {
        "d41d8cd98f00b204e9800998ecf8427e",  
    }
    scan_directory("/home/nikhil-gupta", suspicious_hashes)
