import struct
import base64
from typing import Union, Tuple, Any

try:
    from hashlib import sha256
    from Cryptodome.Hash import SHA256, SHA512
    from Cryptodome.Cipher import ChaCha20, ChaCha20_Poly1305
    from Cryptodome.Random import get_random_bytes
except ImportError as import_error:
    raise ImportError(f"Failed to import module: {import_error}")


def generate_chacha20_key_bytes(key: int = 32) -> bytes:
    return get_random_bytes(key)


def encrypt_chacha20(plain_data: Union[str, bytes, int, float], key: bytes, base64_status: bool = False, salt: bytes = b"RickLangBun5050") -> Union[bytes, str]:
    if isinstance(plain_data, str):
        try:
            plain_data_bytes = bytes([0x01]) + plain_data.encode('utf-8')
        except UnicodeEncodeError as string_encode_error:
            raise ValueError("Failed to encode string to bytes: {}".format(string_encode_error)) from string_encode_error
    elif isinstance(plain_data, bytes):
        try:
            plain_data_bytes = bytes([0x02]) + plain_data
        except Exception as byte_processing_error:
            raise ValueError("Failed to process byte data: {}".format(byte_processing_error)) from byte_processing_error
    elif isinstance(plain_data, int):
        try:
            plain_data_bytes = bytes([0x03]) + struct.pack('>q', plain_data)
        except struct.error as integer_packing_error:
            raise ValueError("Failed to pack integer data: {}".format(integer_packing_error)) from integer_packing_error
    elif isinstance(plain_data, float):
        try:
            plain_data_bytes = bytes([0x04]) + struct.pack('>d', plain_data)
        except struct.error as float_packing_error:
            raise ValueError("Failed to pack float data: {}".format(float_packing_error)) from float_packing_error
    else:
        raise TypeError("Unsupported data type: {}".format(type(plain_data)))

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    nonce = get_random_bytes(12)

    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_data = cipher.encrypt(plain_data_bytes)
    except Exception as encryption_error:
        raise ValueError("Encryption failed: {}".format(encryption_error)) from encryption_error

    try:
        hash_value = sha256(encrypted_data + salt).digest()
    except Exception as hash_computation_error:
        raise ValueError("Hash computation failed: {}".format(hash_computation_error)) from hash_computation_error

    encrypted_data_with_hash = nonce + encrypted_data + hash_value

    if not base64_status:
        return encrypted_data_with_hash
    try:
        return base64.b64encode(encrypted_data_with_hash)
    except Exception as base64_error:
        raise Exception(f"An error occurred during base64 encoding: {base64_error}")


def decrypt_chacha20(encrypted_data_with_hash: bytes, key: bytes, base64_status: bool = False, salt: bytes = b"RickLangBun5050") -> Union[str, bytes, int, float]:
    if not isinstance(encrypted_data_with_hash, bytes):
        raise TypeError("encrypted_data_with_hash must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")

    if base64_status:
        try:
            encrypted_data_with_hash = base64.b64decode(encrypted_data_with_hash)
        except Exception as base64_error:
            raise Exception(f"An error occurred during base64 decoding: {base64_error}")

    try:
        nonce = encrypted_data_with_hash[:12]
        hash_value = encrypted_data_with_hash[-32:]
        encrypted_data = encrypted_data_with_hash[12:-32]
    except Exception as data_split_error:
        raise ValueError("Failed to split encrypted data: {}".format(data_split_error)) from data_split_error

    try:
        computed_hash = sha256(encrypted_data + salt).digest()
        if computed_hash != hash_value:
            raise ValueError("Invalid hash value. Data may be corrupted.")
    except Exception as hash_computation_error:
        raise ValueError("Hash computation failed: {}".format(hash_computation_error)) from hash_computation_error

    try:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plain_data_bytes = cipher.decrypt(encrypted_data)
    except Exception as decryption_error:
        raise ValueError("Decryption failed: {}".format(decryption_error)) from decryption_error

    try:
        type_byte = plain_data_bytes[0]
        if (type_byte == 0x01):
            plain_data = plain_data_bytes[1:].decode('utf-8')
        elif (type_byte == 0x02):
            plain_data = plain_data_bytes[1:]
        elif (type_byte == 0x03):
            plain_data = struct.unpack('>q', plain_data_bytes[1:])[0]
        elif (type_byte == 0x04):
            plain_data = struct.unpack('>d', plain_data_bytes[1:])[0]
        else:
            raise TypeError("Unsupported data type: {}".format(type_byte))
    except UnicodeDecodeError as string_decode_error:
        raise ValueError("Failed to decode string data: {}".format(string_decode_error)) from string_decode_error
    except struct.error as data_unpacking_error:
        raise ValueError("Failed to unpack data: {}".format(data_unpacking_error)) from data_unpacking_error
    except Exception as data_processing_error:
        raise ValueError("Failed to process decrypted data: {}".format(data_processing_error)) from data_processing_error

    return plain_data


def encrypt_chacha20_Poly1305(plain_data: bytes, key: bytes, aad: bytes = b"RickLangBun5050") -> bytes:
    if not isinstance(plain_data, bytes):
        raise TypeError("plain_data must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")

    nonce = get_random_bytes(12)

    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    except Exception as cipher_creation_error:
        raise ValueError("Failed to create cipher") from cipher_creation_error

    try:
        cipher.update(aad)
    except Exception as aad_update_error:
        raise ValueError("Failed to update AAD") from aad_update_error

    try:
        ciphertext, tag = cipher.encrypt_and_digest(plain_data)
    except Exception as encryption_error:
        raise ValueError("Encryption and digest failed") from encryption_error

    return nonce + ciphertext + tag


def decrypt_chacha20_Poly1305(encrypted_data: bytes, key: bytes, aad: bytes = b"RickLangBun5050") -> bytes:
    if not isinstance(encrypted_data, bytes):
        raise TypeError("encrypted_data must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")

    try:
        nonce = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
    except Exception as data_split_error:
        raise ValueError("Failed to split encrypted data") from data_split_error

    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    except Exception as cipher_creation_error:
        raise ValueError("Failed to create cipher") from cipher_creation_error

    try:
        cipher.update(aad)
    except Exception as aad_update_error:
        raise ValueError("Failed to update AAD") from aad_update_error

    try:
        plain_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
    except Exception as decryption_error:
        raise ValueError("Decryption failed") from decryption_error

    return plain_data