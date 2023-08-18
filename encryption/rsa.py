from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import base64

def generate_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Export private key to PEM format and encode to base64
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Export public key to PEM format and encode to base64
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return base64.b64encode(private_pem).decode('utf-8'), base64.b64encode(public_pem).decode('utf-8')


def convert_public_key(public_key_encoded):
    decoded_public_pem = base64.b64decode(public_key_encoded)
    return serialization.load_pem_public_key(decoded_public_pem)


def convert_private_key(private_key_encoded):
    decoded_private_pem = base64.b64decode(private_key_encoded)
    return serialization.load_pem_private_key(decoded_private_pem, password=None)


def encrypt_message(public_key_encoded, msg):
    public_key = convert_public_key(public_key_encoded)
    ciphertext = public_key.encrypt(
        msg.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext)


def decrypt_message(private_key_encoded, ciphertext):
    private_key = convert_private_key(private_key_encoded)
    cipherdata = base64.b64decode(ciphertext)
    decrypted_data = private_key.decrypt(
        cipherdata,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')
