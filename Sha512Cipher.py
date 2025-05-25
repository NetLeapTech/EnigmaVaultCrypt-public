import hashlib
import time
import base64
import random
import string
import os

try:
    from cryptography.fernet import Fernet
except ImportError as import_error:
    raise ImportError(f"Failed to import module: {import_error}")
from typing import Union, ByteString


def generate_fernet_key(sequence_bytes: bytes, time_stamp: int) -> Fernet:
    time_bytes = time_stamp.to_bytes(8, byteorder='big')
    merged_bytes = sequence_bytes + time_bytes
    generated_key = hashlib.sha256(merged_bytes).digest()
    return Fernet(base64.urlsafe_b64encode(generated_key))


def sha512_encrypt_data(input_data: Union[str, bytes], sequence: bytes = b"RickLangBun5050") -> bytes:
    if isinstance(input_data, str):
        input_bytes = input_data.encode()
    elif isinstance(input_data, bytes):
        input_bytes = input_data
    else:
        raise ValueError("Unsupported data type")

    hash_512 = hashlib.sha512()
    hash_512.update(input_bytes)
    hash_digest = hash_512.digest()

    encoded = bytearray(hash_digest)
    for index in range(len(encoded)):
        encoded[index] ^= sequence[index % len(sequence)]

    current_time = int(time.time())
    encryptor = generate_fernet_key(sequence, current_time)
    secure_data = encryptor.encrypt(bytes(encoded))
    time_data = current_time.to_bytes(8, byteorder='big')

    return secure_data + time_data


def sha512_decrypt_data(encrypted_content: bytes, data_check: Union[str, bytes], sequence: bytes = b"RickLangBun5050") -> bytes:
    secured_data = encrypted_content[:-8]
    time_data = encrypted_content[-8:]
    retrieved_time = int.from_bytes(time_data, byteorder='big')

    decryptor = generate_fernet_key(sequence, retrieved_time)
    decoded_data = decryptor.decrypt(secured_data)

    decoded_array = bytearray(decoded_data)
    for index in range(len(decoded_array)):
        decoded_array[index] ^= sequence[index % len(sequence)]

    expected_hash = hashlib.sha512(data_check.encode() if isinstance(data_check, str) else data_check).digest()
    if bytes(decoded_array) != expected_hash:
        raise ValueError("Decryption failed or data has been tampered with")

    return bytes(decoded_array)

