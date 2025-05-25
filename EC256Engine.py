from typing import Tuple, Union
import os

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as import_error:
    raise ImportError(f"Failed to import module: {import_error}")
import base64


def generate_ec256_key_pair() -> Tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem


def encrypt_with_public_key(plain_data: bytes, public_key: bytes, encode_base64: bool = False) -> bytes:
    if not isinstance(plain_data, bytes):
        raise TypeError("plain_data must be bytes")
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")

    try:
        pem_public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    except ValueError as pem_load_error:
        raise ValueError(f"Invalid PEM format or the key data is corrupted: {pem_load_error}")
    except Exception as key_load_error:
        raise ValueError(f"Error loading the EC public key: {key_load_error}")

    try:
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), pem_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plain_data) + encryptor.finalize()

        ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        result = ephemeral_public_key + iv + ciphertext
    except Exception as encryption_error:
        raise ValueError(f"Encryption failed: {encryption_error}")

    if encode_base64:
        try:
            return base64.b64encode(result)
        except Exception as base64_encode_error:
            raise ValueError(f"Failed to encode ciphertext: {base64_encode_error}")
    return result


def decrypt_with_private_key(encrypted_data: bytes, private_key: bytes, decode_base64: bool = False) -> bytes:
    if not isinstance(encrypted_data, bytes):
        raise TypeError("encrypted_data must be bytes")
    if not isinstance(private_key, bytes):
        raise TypeError("private_key must be bytes")

    if decode_base64:
        try:
            encrypted_data = base64.b64decode(encrypted_data)
        except Exception as base64_decode_error:
            raise ValueError(f"Failed to decode Base64 encoded data: {base64_decode_error}")

    try:
        loaded_private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
    except ValueError as pem_load_error:
        raise ValueError(f"Invalid PEM format or the key data is corrupted: {pem_load_error}")
    except Exception as key_load_error:
        raise ValueError(f"Error loading the EC private key: {key_load_error}")

    try:
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            encrypted_data[:33]
        )
        iv = encrypted_data[33:49]
        ciphertext = encrypted_data[49:]

        shared_key = loaded_private_key.exchange(ec.ECDH(), ephemeral_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as decryption_error:
        raise ValueError(f"Decryption failed: {decryption_error}")

    return decrypted_data


def test_ec256_encryption_decryption():
    private_key_pem, public_key_pem = generate_ec256_key_pair()

    while True:
        data_length = os.urandom(1)[0] % 4096 + 1
        original_data = os.urandom(data_length)

        encrypted_data = encrypt_with_public_key(original_data, public_key_pem)

        decrypted_data = decrypt_with_private_key(encrypted_data, private_key_pem)

        assert original_data == decrypted_data, f"Decrypted data does not match the original! Length: {data_length} bytes"


