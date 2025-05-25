import hashlib
import itertools
import base64
def encode_packet_length(packet_length):
    if not isinstance(packet_length, int):
        raise TypeError(f"Packet length must be an integer. Received type: {type(packet_length).__name__}, value: {packet_length}")

    if packet_length > 4098:
        raise ValueError(f"Packet length must not exceed 4098. Received value: {packet_length}")

    OBFUSCATION_CONSTANTS = [
        (0xDEADBEEF * 0xCAFEBABE) & 0xFFFFFFFF,
        (0xABCDEF01 * 0xFEDCBA98) & 0xFFFFFFFF,
        (0xBAADF00D * 0x8BADF00D) & 0xFFFFFFFF,
        (0xFACEFEED * 0xBADDCAFE) & 0xFFFFFFFF,
    ]

    try:
        packet_length_bytes = packet_length.to_bytes(4, 'big')
        encoded_segments = [(int.from_bytes(packet_length_bytes, 'big') + constant) % 0x100000000 for constant in OBFUSCATION_CONSTANTS[:1]]
        encoded_bytes = b''.join(segment.to_bytes(4, 'big') for segment in encoded_segments)
    except OverflowError as overflow_error:
        raise OverflowError("Failed to convert packet length to bytes or calculate encoded segments") from overflow_error
    except Exception as unexpected_error:
        raise RuntimeError("An unexpected error occurred during encoding") from unexpected_error

    return encoded_bytes


def decode_packet_length(encoded_segment_bytes):
    if not isinstance(encoded_segment_bytes, bytes):
        raise TypeError(f"Encoded segment must be bytes. Received type: {type(encoded_segment_bytes).__name__}, value: {encoded_segment_bytes}")

    if len(encoded_segment_bytes) != 4:
        raise ValueError(f"Encoded segment must be a bytes object of length 4. Received length: {len(encoded_segment_bytes)}, value: {encoded_segment_bytes}")

    OBFUSCATION_CONSTANTS = [
        (0xDEADBEEF * 0xCAFEBABE) & 0xFFFFFFFF,
        (0xABCDEF01 * 0xFEDCBA98) & 0xFFFFFFFF,
        (0xBAADF00D * 0x8BADF00D) & 0xFFFFFFFF,
        (0xFACEFEED * 0xBADDCAFE) & 0xFFFFFFFF,
    ]

    try:
        segments = [int.from_bytes(encoded_segment_bytes[i:i + 4], 'big') for i in range(0, len(encoded_segment_bytes), 4)]
        decoded_length = (segments[0] - OBFUSCATION_CONSTANTS[0]) % 0x100000000
    except ValueError as value_error:
        raise ValueError("Failed to decode bytes or convert to integer") from value_error
    except Exception as unexpected_error:
        raise TypeError("An unexpected error occurred during decoding") from unexpected_error

    return decoded_length


def encrypt_packet_basic(packet_payload, base64_status=True, salt=b"RickLangbun5050"):
    if not isinstance(packet_payload, bytes):
        raise TypeError(f"Packet payload must be bytes. Received type: {type(packet_payload).__name__}, value: {packet_payload}")

    max_length = 4096 - 4 - 32 - 1018
    if len(packet_payload) > max_length:
        raise ValueError(f"Packet payload too long; must not exceed {max_length} bytes. Received length: {len(packet_payload)}, value: {packet_payload}")

    pattern = b'Rick'
    try:
        packet_payload = bytes(b ^ p for b, p in zip(packet_payload, itertools.cycle(pattern)))
    except Exception as xor_error:
        raise RuntimeError("Failed to apply XOR encryption with the pattern") from xor_error

    sha256 = hashlib.sha256()
    try:
        sha256.update(packet_payload + salt)
        checksum = sha256.digest()
    except Exception as checksum_error:
        raise RuntimeError("Failed to calculate SHA-256 checksum") from checksum_error

    if base64_status:
        try:
            packet_payload = base64.b64encode(packet_payload)
        except Exception as base64_error:
            raise ValueError("Failed to base64 encode the packet payload") from base64_error

    return packet_payload + checksum


def decrypt_packet_basic(encrypted_packet, base64_status=True, salt=b"RickLangbun5050"):
    if not isinstance(encrypted_packet, bytes):
        raise TypeError(f"Encrypted packet must be bytes. Received type: {type(encrypted_packet).__name__}, value: {encrypted_packet}")

    if len(encrypted_packet) <= 32:
        raise ValueError(f"Encrypted packet is too short to contain a valid checksum. Received length: {len(encrypted_packet)}, value: {encrypted_packet}")

    packet_payload = encrypted_packet[:-32]
    received_checksum = encrypted_packet[-32:]

    if base64_status:
        try:
            packet_payload = base64.b64decode(packet_payload)
        except Exception as base64_error:
            raise ValueError("Failed to base64 decode the encrypted packet") from base64_error

    sha256 = hashlib.sha256()
    try:
        sha256.update(packet_payload + salt)
        calculated_checksum = sha256.digest()
    except Exception as checksum_error:
        raise RuntimeError("Failed to calculate SHA-256 checksum") from checksum_error

    if received_checksum != calculated_checksum:
        raise ValueError("Checksum does not match; data may be corrupted.")

    pattern = b'Rick'
    try:
        decrypted_payload = bytes(b ^ p for b, p in zip(packet_payload, itertools.cycle(pattern)))
    except Exception as xor_error:
        raise RuntimeError("Failed to apply XOR decryption with the pattern") from xor_error

    return decrypted_payload

