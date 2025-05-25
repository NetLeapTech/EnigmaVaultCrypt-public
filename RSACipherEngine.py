try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
    from cryptography.hazmat.primitives import serialization, hashes
except ImportError as import_error:
    raise ImportError(f"Failed to import module: {import_error}")
import base64
def generate_rsa_key_pair(public_exponent=65537, key_size=4096):
    if not isinstance(public_exponent, int) or public_exponent < 3 or public_exponent % 2 == 0:
        raise ValueError("public_exponent must be an odd integer greater than or equal to 3")

    if not isinstance(key_size, int) or key_size < 512:
        raise ValueError("key_size must be an integer greater than or equal to 512")

    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
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


def encrypt_with_public_key(plain_data, public_key, max_length=446, encode_base64=False):
    if not isinstance(plain_data, bytes):
        raise TypeError("plain_data must be bytes")

    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")

    if len(plain_data) >= max_length:
        raise ValueError(f"plain_data must be shorter than {max_length} bytes, but got {len(plain_data)} bytes")

    try:
        pem_public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )
    except ValueError as pem_load_error:
        raise ValueError(f"Invalid PEM format or the key data is corrupted: {pem_load_error}")
    except Exception as key_load_error:
        raise ValueError(f"Error loading the RSA public key: {key_load_error}")

    try:
        ciphertext = pem_public_key.encrypt(
            plain_data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as encryption_value_error:
        raise ValueError(f"Encryption failed due to an invalid input: {encryption_value_error}")
    except TypeError as encryption_type_error:
        raise ValueError(f"Encryption failed due to a type error: {encryption_type_error}")
    except Exception as encryption_error:
        raise ValueError(f"Encryption failed: {encryption_error}")

    if not encode_base64:
        return ciphertext

    try:
        encoded_ciphertext = base64.b64encode(ciphertext)
        return encoded_ciphertext
    except TypeError as base64_encode_type_error:
        raise ValueError(f"Failed to encode ciphertext due to a type error: {base64_encode_type_error}")
    except Exception as base64_encode_error:
        raise ValueError(f"Failed to encode ciphertext: {base64_encode_error}")


def decrypt_with_private_key(encrypted_data, private_key, max_key_length=450, decode_base64=False):
    if not isinstance(encrypted_data, (bytes, str)):
        raise TypeError("encrypted_data must be bytes or string, but got type '{}'".format(type(encrypted_data).__name__))

    if not isinstance(private_key, bytes):
        raise TypeError("private_key must be bytes, but got type '{}'".format(type(private_key).__name__))

    if len(private_key) < max_key_length:
        raise ValueError(f"private_key must be no longer than {max_key_length} bytes, but got {len(private_key)} bytes")

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
        raise ValueError(f"Error loading the RSA private key: {key_load_error}")

    try:
        decrypted_data_bytes = loaded_private_key.decrypt(
            encrypted_data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as decryption_error:
        raise ValueError(f"Decryption failed: {decryption_error}")

    return decrypted_data_bytes

