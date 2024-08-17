import os
import json
import getpass
from tqdm import tqdm
from hashlib import sha256
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def generate_key(password, salt):
    ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8, hash_len=32)
    return ph.hash(password + salt.hex()).encode('utf-8')[:32]

def decrypt_file(file_name, password):
    try:
        if not os.path.isfile(file_name):
            raise FileNotFoundError(f"File '{file_name}' does not exist.")
        
        with open(file_name, "rb") as file:
            salt = file.read(16)
            iv = file.read(12)
            metadata_tag = file.read(16)
            metadata_length = int.from_bytes(file.read(4), 'big')
            encrypted_metadata = file.read(metadata_length)
            hmac_digest = file.read(32)
            encrypted_data = file.read()
        
        key = generate_key(password, salt)
        
        try:
            cipher_metadata = Cipher(algorithms.AES(key), modes.GCM(iv, metadata_tag), backend=default_backend())
            decryptor_metadata = cipher_metadata.decryptor()
            metadata = decryptor_metadata.update(encrypted_metadata) + decryptor_metadata.finalize()
            metadata = json.loads(metadata)
        except Exception:
            raise ValueError("Invalid password or corrupted file. Integrity check failed.")
        
        hmac_key = bytes.fromhex(metadata["hmac_key"])
        
        hmac_instance = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        hmac_instance.update(encrypted_data)
        hmac_instance.verify(hmac_digest)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = bytearray()
        chunk_size = 1024
        for i in tqdm(range(0, len(encrypted_data), chunk_size), desc="Decrypting"):
            chunk = encrypted_data[i:i+chunk_size]
            decrypted_data.extend(decryptor.update(chunk))
        decrypted_data.extend(decryptor.finalize())
        
        original_name = metadata["original_name"]
        original_hash = metadata["original_hash"]

        if sha256(decrypted_data).hexdigest() != original_hash:
            raise ValueError("File integrity check failed. The decrypted file does not match the original hash.")
        
        with open(original_name, "wb") as file:
            file.write(decrypted_data)
        
        os.remove(file_name)
        
        print(f"File '{file_name}' has been decrypted and saved as '{original_name}'.")

    except FileNotFoundError as fnf_error:
        print(fnf_error)
    except InvalidSignature:
        print("Invalid password or corrupted file. Integrity check failed.")
    except ValueError as e:
        print(f"Decryption error: {e}")
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

if __name__ == "__main__":
    file_name = input("Enter the name of the file to decrypt: ")
    password = getpass.getpass("Enter the password: ")
    
    decrypt_file(file_name, password)
