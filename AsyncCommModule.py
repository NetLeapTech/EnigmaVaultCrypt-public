import asyncio
import time
import hashlib
import os
import json
from typing import Tuple, Optional
from datetime import datetime
from EnigmaVaultCrypt import PacketCryptoEngine
from EnigmaVaultCrypt import PacketCryptoEnginePlus
from EnigmaVaultCrypt import RSACipherEngine, AES256CBCEngine

MAX_PACKET_LENGTH = 4096

DEFAULT_HANDSHAKE_TYPE = b"SimpleHandshake2022"
DEFAULT_VERIFICATION_STRING = "SimpleVerification2022"
SIMPLE_DEFAULT_TIMEOUT = 4.0
SIMPLE_DEFAULT_MAX_LENGTH = 4096

INITIAL_HANDSHAKE_BYTES = b"SecureHandshake2022"
RSA_FIXED_BYTES = b"RSAVerification2022"
SALT_LENGTH = 64
SECURE_DEFAULT_TIMEOUT = 4.0
SECURE_DEFAULT_MAX_LENGTH = 4096

class EncryptionError(Exception):
    def __init__(self, message: str, original_error: Exception = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self):
        if self.original_error:
            return f"{self.message} - Original error: {str(self.original_error)}"
        return self.message

class DecryptionError(Exception):
    def __init__(self, message: str, original_error: Exception = None):
        self.message = message
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self):
        if self.original_error:
            return f"{self.message} - Original error: {str(self.original_error)}"
        return self.message

async def async_receive_packet(reader: asyncio.StreamReader, timeout: float = 4.0, max_length: int = MAX_PACKET_LENGTH) -> bytes:
    try:
        data_length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout)
        data_length = PacketCryptoEngine.decode_packet_length(data_length_bytes)
        if data_length <= 0 or data_length > max_length:
            raise ValueError(f"Invalid data length received: {data_length}")

        received_data = await asyncio.wait_for(reader.readexactly(data_length), timeout)
        decrypted_data = PacketCryptoEngine.decrypt_packet_basic(received_data)
        return decrypted_data

    except asyncio.IncompleteReadError:
        raise ConnectionError("Connection closed before receiving complete packet data")
    except asyncio.TimeoutError:
        raise TimeoutError(f"Timeout while reading packet from the reader after {timeout} seconds")
    except ValueError as value_error:
        raise ValueError(f"Error in receiving packet: {value_error}")
    except ConnectionResetError:
        raise ConnectionResetError("Connection was reset by the peer during packet reception")
    except DecryptionError as decryption_error:
        raise DecryptionError(f"Error decrypting packet: {decryption_error}")
    except Exception as unexpected_error:
        raise RuntimeError(f"Unexpected error in receiving packet: {type(unexpected_error).__name__} - {unexpected_error}")


async def async_send_packet(writer: asyncio.StreamWriter, send_data: bytes, max_length: int = MAX_PACKET_LENGTH) -> None:
    if not isinstance(send_data, bytes):
        raise TypeError(f"Expected 'send_data' to be of type 'bytes', but got {type(send_data).__name__} instead: {send_data}")

    if len(send_data) > max_length:
        raise ValueError(f"Data length exceeds maximum allowed length: {len(send_data)} > {max_length}")

    try:
        encrypted_data = PacketCryptoEngine.encrypt_packet_basic(send_data)
        encrypted_data_length = PacketCryptoEngine.encode_packet_length(len(encrypted_data))
        writer.write(encrypted_data_length + encrypted_data)
        await writer.drain()
    except asyncio.WriteError as write_error:
        raise asyncio.WriteError(f"Error writing to stream: {write_error}")
    except EncryptionError as encryption_error:
        raise EncryptionError(f"Error encrypting packet: {encryption_error}")
    except Exception as unexpected_error:
        raise RuntimeError(f"Unexpected error in sending packet: {type(unexpected_error).__name__} - {unexpected_error}")


async def async_receive_packet_plus(reader: asyncio.StreamReader, timeout: float = 4.0, max_length: int = MAX_PACKET_LENGTH) -> bytes:
    try:
        data_length_bytes = await asyncio.wait_for(reader.readexactly(68), timeout)
        data_length = PacketCryptoEnginePlus.decode_packet_length_plus(data_length_bytes)
        if data_length <= 0 or data_length > max_length:
            raise ValueError(f"Invalid data length received for plus packet: {data_length}")

        received_data = await asyncio.wait_for(reader.readexactly(data_length), timeout)
        decrypted_data = PacketCryptoEnginePlus.decrypt_packet_basic_plus(received_data, data_length)
        return decrypted_data

    except asyncio.IncompleteReadError:
        raise ConnectionError("Connection closed before receiving complete plus packet data")
    except asyncio.TimeoutError:
        raise TimeoutError(f"Timeout while reading plus packet from the reader after {timeout} seconds")
    except ValueError as value_error:
        raise ValueError(f"Error in receiving plus packet: {value_error}")
    except ConnectionResetError:
        raise ConnectionResetError("Connection was reset by the peer during plus packet reception")
    except DecryptionError as decryption_error:
        raise DecryptionError(f"Error decrypting plus packet: {decryption_error}")
    except Exception as unexpected_error:
        raise RuntimeError(f"Unexpected error in receiving plus packet: {type(unexpected_error).__name__} - {unexpected_error}")


async def async_send_packet_plus(writer: asyncio.StreamWriter, send_data: bytes, max_length: int = MAX_PACKET_LENGTH) -> None:
    if not isinstance(send_data, bytes):
        raise TypeError(f"Expected 'send_data' to be of type 'bytes', but got {type(send_data).__name__} instead: {send_data}")

    if len(send_data) > max_length:
        raise ValueError(f"Data length exceeds maximum allowed length for plus packet: {len(send_data)} > {max_length}")

    try:
        encrypted_data = PacketCryptoEnginePlus.encrypt_packet_basic_plus(send_data)
        encrypted_data_length = PacketCryptoEnginePlus.encode_packet_length_plus(len(encrypted_data))
        writer.write(encrypted_data_length + encrypted_data)
        await writer.drain()
    except asyncio.WriteError as write_error:
        raise asyncio.WriteError(f"Error writing plus packet to stream: {write_error}")
    except EncryptionError as encryption_error:
        raise EncryptionError(f"Error encrypting plus packet: {encryption_error}")
    except Exception as unexpected_error:
        raise RuntimeError(f"Unexpected error in sending plus packet: {type(unexpected_error).__name__} - {unexpected_error}")


async def async_receive_packet_generic(reader: asyncio.StreamReader, timeout: float = 4.0, is_plus: bool = False, max_length: int = MAX_PACKET_LENGTH) -> bytes:
    if is_plus:
        return await async_receive_packet_plus(reader, timeout, max_length)
    else:
        return await async_receive_packet(reader, timeout, max_length)


async def async_send_packet_generic(writer: asyncio.StreamWriter, send_data: bytes, is_plus: bool = False, max_length: int = MAX_PACKET_LENGTH) -> None:
    if is_plus:
        await async_send_packet_plus(writer, send_data, max_length)
    else:
        await async_send_packet(writer, send_data, max_length)


async def simple_server_handshake(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handshake_type: bytes = DEFAULT_HANDSHAKE_TYPE,
        verification_string: str = DEFAULT_VERIFICATION_STRING,
        is_plus: bool = False,
        timeout: float = SIMPLE_DEFAULT_TIMEOUT,
        max_length: int = SIMPLE_DEFAULT_MAX_LENGTH
) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    try:
        received_handshake = await async_receive_packet_generic(reader, timeout=timeout, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error receiving handshake type: {str(e)}"

    if received_handshake != handshake_type:
        return None, None, "Invalid handshake type"

    try:
        private_key_pem, public_key_pem = RSACipherEngine.generate_rsa_key_pair()
        await async_send_packet_generic(writer, public_key_pem, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error generating or sending RSA key: {str(e)}"

    try:
        encrypted_aes = await async_receive_packet_generic(reader, timeout=timeout, is_plus=is_plus, max_length=max_length)
        aes_key_iv = RSACipherEngine.decrypt_with_private_key(encrypted_aes, private_key_pem)
        aes_key, aes_iv = aes_key_iv[:32], aes_key_iv[32:]
    except Exception as e:
        return None, None, f"Error receiving or decrypting AES key: {str(e)}"

    try:
        encrypted_verification = AES256CBCEngine.encrypt_aes_256_cbc(verification_string, aes_key, aes_iv)
        await async_send_packet_generic(writer, encrypted_verification, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error encrypting or sending verification string: {str(e)}"

    return aes_key, aes_iv, None


async def simple_client_handshake(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handshake_type: bytes = DEFAULT_HANDSHAKE_TYPE,
        verification_string: str = DEFAULT_VERIFICATION_STRING,
        is_plus: bool = False,
        timeout: float = SIMPLE_DEFAULT_TIMEOUT,
        max_length: int = SIMPLE_DEFAULT_MAX_LENGTH
) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    try:
        await async_send_packet_generic(writer, handshake_type, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error sending handshake type: {str(e)}"

    try:
        server_public_key = await async_receive_packet_generic(reader, timeout=timeout, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error receiving server's public key: {str(e)}"

    try:
        aes_key, aes_iv = AES256CBCEngine.generate_aes_256_cbc_bytes()
        encrypted_aes = RSACipherEngine.encrypt_with_public_key(aes_key + aes_iv, server_public_key)
        await async_send_packet_generic(writer, encrypted_aes, is_plus=is_plus, max_length=max_length)
    except Exception as e:
        return None, None, f"Error generating or sending AES key: {str(e)}"

    try:
        encrypted_verification = await async_receive_packet_generic(reader, timeout=timeout, is_plus=is_plus, max_length=max_length)
        decrypted_verification = AES256CBCEngine.decrypt_aes_256_cbc(encrypted_verification, aes_key, aes_iv)
        if decrypted_verification != verification_string:
            return None, None, "Invalid verification string"
    except Exception as e:
        return None, None, f"Error receiving or verifying verification string: {str(e)}"

    return aes_key, aes_iv, None
