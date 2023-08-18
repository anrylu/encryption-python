import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def string_to_aes_key(passphrase, salt):
    """Generates a key using PBKDF2."""
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
    )
    return kdf.derive(passphrase.encode('utf-8')), salt


def encrypt_message(passphrase, msg):
    """Encrypts data using AES-256-GCM."""
    iv = os.urandom(12)
    key, salt = string_to_aes_key(passphrase, None)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(msg.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')


def decrypt_message(passphrase, ciphertext):
    """Decrypts ciphertext using AES-256-GCM."""
    data = base64.b64decode(ciphertext)
    salt = data[:16]
    iv = data[16:28]
    key, _ = string_to_aes_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data[28:])
    return plaintext.decode('utf-8')
