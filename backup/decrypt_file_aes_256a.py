from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key(password, salt):
    """Derive a secret key from the given password and salt using PBKDF2 HMAC SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def decrypt_file(file_name, password, output_name):
    """Decrypt the given encrypted file using AES-256 encryption."""
    with open(file_name, "rb") as file:
        # Read the salt (16 bytes), IV (16 bytes), and encrypted data
        salt = file.read(16)
        iv = file.read(16)
        encrypted_data = file.read()

    # Generate the key using the password and salt
    key = generate_key(password, salt)

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Write the decrypted data to a new file
    with open(output_name, "wb") as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    # Set the encrypted file name and password
    encrypted_file_name = "Horses_Catalog.pdf"  # the fake name for the encrypted file
    password = "123456"  # replace with your password
    
    # Set the decrypted file name
    decrypted_file_name = "file_to_encrypt.txt"  # replace with desired decrypted file name

    # Decrypt the file
    decrypt_file(encrypted_file_name, password, decrypted_file_name)

