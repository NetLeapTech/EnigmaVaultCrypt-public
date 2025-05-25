import base64
import os
import secrets
from typing import Tuple, Union, Any
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Hash import SHA256
    from Cryptodome.Util.Padding import pad, unpad
except ImportError as import_error:
    raise ImportError(f"Failed to import module: {import_error}")


def generate_aes_256_cbc_bytes() -> Tuple[bytes, bytes]:
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    return key, iv


def encrypt_with_salt_and_hash(data: bytes, salt: bytes) -> bytes:
    sha256_hasher = SHA256.new()
    sha256_hasher.update(salt + data)
    hash_value = sha256_hasher.digest()
    half_hash_size = len(hash_value) // 2
    hash_part1 = hash_value[:half_hash_size]
    hash_part2 = hash_value[half_hash_size:]
    key_length = 4
    key = secrets.token_bytes(key_length)
    encrypted_xor_data = bytes(a ^ b for a, b in zip(data, key * (len(data) // key_length + 1)))
    encrypted_data = bytes([key_length]) + key + encrypted_xor_data
    return hash_part1 + encrypted_data + hash_part2


def encrypt_aes_256_cbc(plain_data: Any, key_size_bits: bytes, initial_vector: bytes, base64_status: bool = False, sha256_salt: bytes = b"RickLangBun5050") -> bytes:
    if isinstance(plain_data, int):
        try:
            byte_data = str(plain_data).encode('utf-8')
        except Exception as encoding_int_error:
            raise Exception(f"Error encoding integer data: {encoding_int_error}")
        data_type = b'\x01'
    elif isinstance(plain_data, float):
        try:
            byte_data = str(plain_data).encode('utf-8')
        except Exception as encoding_float_error:
            raise Exception(f"Error encoding float data: {encoding_float_error}")
        data_type = b'\x02'
    elif isinstance(plain_data, complex):
        try:
            byte_data = str(plain_data).encode('utf-8')
        except Exception as encoding_complex_error:
            raise Exception(f"Error encoding complex data: {encoding_complex_error}")
        data_type = b'\x03'
    elif isinstance(plain_data, bool):
        try:
            byte_data = str(plain_data).encode('utf-8')
        except Exception as encoding_bool_error:
            raise Exception(f"Error encoding boolean data: {encoding_bool_error}")
        data_type = b'\x04'
    elif isinstance(plain_data, str):
        try:
            byte_data = plain_data.encode('utf-8')
        except Exception as encoding_string_error:
            raise Exception(f"Error encoding string data: {encoding_string_error}")
        data_type = b'\x05'
    elif isinstance(plain_data, bytes):
        byte_data = plain_data
        data_type = b'\x06'
    else:
        raise TypeError("Unsupported data type. Supported types are: integers, floats, complex numbers, booleans, strings, and bytes.")

    try:
        padded_plain_data = pad(byte_data, AES.block_size)
    except Exception as padding_error:
        raise Exception(f"An error occurred during padding: {padding_error}. Please check if byte_data is a valid byte sequence.")

    try:
        cipher = AES.new(key_size_bits, AES.MODE_CBC, initial_vector)
        encrypted_data = cipher.encrypt(padded_plain_data)
    except ValueError as value_error:
        raise ValueError(f"Value error: {value_error}. Please check if key_size_bits is a valid key size (16, 24, or 32 bytes), and if initial_vector is 16 bytes long.")
    except TypeError as type_error:
        raise TypeError(f"Type error: {type_error}. Please check if key_size_bits and initial_vector are of byte type or byte sequence.")
    except Exception as aes_creation_error:
        raise Exception(f"An unexpected error occurred while creating the AES cipher: {aes_creation_error}")

    try:
        final_encrypted_data = data_type + encrypted_data
    except Exception as data_combination_error:
        raise Exception(f"Error combining data type and encrypted data: {data_combination_error}. This is usually a developer or machine issue.")

    try:
        encrypted_output = encrypt_with_salt_and_hash(final_encrypted_data, sha256_salt)
    except Exception as final_encryption_error:
        raise Exception(f"An error occurred during the final encryption with salt and hash: {final_encryption_error}. This usually happens when the data exceeds the maximum length after encryption.")

    if not base64_status:
        return encrypted_output

    try:
        return base64.b64encode(encrypted_output)
    except Exception as base64_error:
        raise Exception(f"An error occurred during base64 encoding: {base64_error}")


def decrypt_with_salt_and_hash(encrypted_data: bytes, salt: bytes) -> bytes:
    hash_size = 32
    half_hash_size = hash_size // 2
    hash_part1 = encrypted_data[:half_hash_size]
    hash_part2 = encrypted_data[-half_hash_size:]
    core_encrypted_data = encrypted_data[half_hash_size:-half_hash_size]
    key_length = core_encrypted_data[0]
    key = core_encrypted_data[1:1 + key_length]
    decrypted_xor_data = core_encrypted_data[1 + key_length:]
    original_data = bytes(a ^ b for a, b in zip(decrypted_xor_data, key * (len(decrypted_xor_data) // key_length + 1)))
    sha256_hasher = SHA256.new()
    sha256_hasher.update(salt + original_data)
    if sha256_hasher.digest() != hash_part1 + hash_part2:
        raise ValueError("SHA256 did not match as expected.")
    return original_data


def decrypt_aes_256_cbc(encrypted_data: bytes, key_size_bits: bytes, initial_vector: bytes, base64_status: bool = False, sha256_salt: bytes = b"RickLangBun5050") -> Any:
    if not isinstance(encrypted_data, bytes) or not (16 <= len(encrypted_data) <= 4096):
        raise TypeError("Incorrect data type, this error is usually triggered only when attempting to tamper with the data.")

    if base64_status:
        try:
            encrypted_data = base64.b64decode(encrypted_data)
        except Exception as base64_error:
            raise Exception(f"An error occurred during base64 decoding: {base64_error}")

    try:
        data_with_type = decrypt_with_salt_and_hash(encrypted_data, sha256_salt)
    except TypeError as type_error:
        raise TypeError(f"Type error: {type_error}. Please check if encrypted_data and salt are in bytes type.")
    except ValueError as value_error:
        raise ValueError(f"Value error: {value_error}. This might be due to a data integrity check failure or insufficient data length.")
    except IndexError as index_error:
        raise IndexError(f"Index error: {index_error}. This error may be thrown when slicing encrypted_data or core_encrypted_data out of range. Please check if the length of encrypted_data is sufficient to split into hash_part1 and hash_part2.")
    except ZeroDivisionError as zero_div_error:
        raise ZeroDivisionError(f"ZeroDivision error: {zero_div_error}. This might occur if key_length is zero when calculating decrypted_xor_data. Please ensure key_length is not zero.")
    except Exception as general_error:
        raise Exception(f"An unexpected error occurred: {general_error}. An unforeseen error occurred.")

    data_type = data_with_type[:1]
    encrypted_real_data = data_with_type[1:]

    try:
        cipher = AES.new(key_size_bits, AES.MODE_CBC, initial_vector)
        decrypted_padded_data = cipher.decrypt(encrypted_real_data)
    except ValueError as value_error:
        raise ValueError(f"Value error: {value_error}. Please check if key_size_bits is a valid key size (16, 24, or 32 bytes), and if initial_vector is 16 bytes long.")
    except TypeError as type_error:
        raise TypeError(f"Type error: {type_error}. Please check if key_size_bits and initial_vector are of byte type or byte sequence.")
    except Exception as cipher_creation_error:
        raise Exception(f"An unexpected error occurred while creating the AES cipher: {cipher_creation_error}")

    try:
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
    except Exception as unpadding_error:
        raise Exception(f"An error occurred during unpadding: {unpadding_error}. This step usually doesn't fail. If it does, the data might be tampered with or a different padding method was used.")

    try:
        if data_type == b'\x01':
            return int.from_bytes(decrypted_data, 'big')
        elif data_type == b'\x02':
            return float(decrypted_data.decode())
        elif data_type == b'\x03':
            return complex(decrypted_data.decode())
        elif data_type == b'\x04':
            return bool(int.from_bytes(decrypted_data, 'big'))
        elif data_type == b'\x05':
            return decrypted_data.decode('utf-8')
        elif data_type == b'\x06':
            return bytes(decrypted_data)
    except Exception as data_conversion_error:
        raise Exception(f"Error converting decrypted data to original type: {data_conversion_error}. This is usually a developer or machine issue.")

    raise TypeError(f"Data was not encrypted by the AES Engine, unknown type encountered: {decrypted_data}")