import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Convert private key to bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return base64.b64encode(private_bytes).decode('utf-8'), base64.b64encode(public_bytes).decode('utf-8')


def convert_public_key(public_key_encoded):
    decoded_public_bytes = base64.b64decode(public_key_encoded)
    return ed25519.Ed25519PublicKey.from_public_bytes(decoded_public_bytes)


def convert_private_key(private_key_encoded):
    decoded_private_bytes = base64.b64decode(private_key_encoded)
    return ed25519.Ed25519PrivateKey.from_private_bytes(decoded_private_bytes)


def sign(private_key_encoded, msg):
    """Signs a message using Ed25519."""
    private_key = convert_private_key(private_key_encoded)
    signature = private_key.sign(msg.encode('utf-8'))
    return base64.b64encode(signature).decode('utf-8')


def verify(public_key_encoded, msg, signature_encoded):
    """Verifies a signature using Ed25519."""
    signature = base64.b64decode(signature_encoded)
    public_key = convert_public_key(public_key_encoded)
    valid = True
    try:
        public_key.verify(signature, msg.encode('utf-8'))
    except InvalidSignature:
        valid = False
    return valid
