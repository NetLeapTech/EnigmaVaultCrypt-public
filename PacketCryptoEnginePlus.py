import secrets
import base64
import hashlib
import itertools
import random
import os
def encode_packet_length_plus(packet_length):
    if not isinstance(packet_length, int):
        raise TypeError(f"Packet length must be an integer. Received type: {type(packet_length).__name__}, value: {packet_length}")

    if packet_length > 4029:
        raise ValueError(f"Packet length must not exceed 4098. Received value: {packet_length}")

    OBFUSCATION_CONSTANTS_PLUS = [
        (0xDEADBEEF * 0xCAFEBABE ^ 0x12345678) & 0xFFFFFFFF,
        (0xABCDEF01 * 0xFEDCBA98 ^ 0x87654321) & 0xFFFFFFFF,
        (0xBAADF00D * 0x8BADF00D ^ 0xA5A5A5A5) & 0xFFFFFFFF,
        (0xFACEFEED * 0xBADDCAFE ^ 0x5A5A5A5A) & 0xFFFFFFFF,
        (0x0BADF00D * 0xB16B00B5 ^ 0xC0FFEE00) & 0xFFFFFFFF,
        (0xFEEDFACE * 0xDEADC0DE ^ 0x0BADC0DE) & 0xFFFFFFFF,
        (0xBAADF00D * 0xDEADC0DE ^ 0xABAD1DEA) & 0xFFFFFFFF,
        (0x1BADB002 * 0x8BADF00D ^ 0xD15EA5E5) & 0xFFFFFFFF,
        (0xCAFEBABE * 0xFACEFEED ^ 0x0D15EA5E) & 0xFFFFFFFF,
        (0xFEEDFACE * 0xDEADC0DE ^ 0xBAADF00D) & 0xFFFFFFFF,
        (0xB16B00B5 * 0xCAFEBABE ^ 0xDEADC0DE) & 0xFFFFFFFF,
        (0xDEADC0DE * 0x1BADB002 ^ 0xB16B00B5) & 0xFFFFFFFF,
        (0xFACEFEED * 0x0BADF00D ^ 0xABAD1DEA) & 0xFFFFFFFF,
        (0x8BADF00D * 0xFEEDFACE ^ 0xD15EA5E5) & 0xFFFFFFFF,
        (0xCAFEBABE * 0xB16B00B5 ^ 0x0D15EA5E) & 0xFFFFFFFF,
        (0x0BADF00D * 0xFACEFEED ^ 0xBAADF00D) & 0xFFFFFFFF,
    ]

    try:
        random_value = secrets.randbits(32)
        packet_length_bytes = packet_length.to_bytes(4, 'big')
        encoded_segments = []
        for constant in OBFUSCATION_CONSTANTS_PLUS:
            intermediate_value = int.from_bytes(packet_length_bytes, 'big') + constant + random_value
            encoded_segment = (intermediate_value % 0x100000000) ^ constant
            encoded_segments.append(encoded_segment)

        encoded_bytes = b''.join(segment.to_bytes(4, 'big') for segment in encoded_segments)
    except OverflowError as overflow_error:
        raise OverflowError("Failed to convert packet length to bytes or calculate encoded segments") from overflow_error
    except Exception as unexpected_error:
        raise RuntimeError("An unexpected error occurred during encoding") from unexpected_error

    return random_value.to_bytes(4, 'big') + encoded_bytes


def decode_packet_length_plus(encoded_bytes):
    if not isinstance(encoded_bytes, bytes):
        raise TypeError(f"Encoded segment must be bytes. Received type: {type(encoded_bytes).__name__}, value: {encoded_bytes}")

    if len(encoded_bytes) != 68:
        raise ValueError(f"Encoded segment must be a bytes object of length 68. Received length: {len(encoded_bytes)}, value: {encoded_bytes}")

    OBFUSCATION_CONSTANTS_PLUS = [
        (0xDEADBEEF * 0xCAFEBABE ^ 0x12345678) & 0xFFFFFFFF,
        (0xABCDEF01 * 0xFEDCBA98 ^ 0x87654321) & 0xFFFFFFFF,
        (0xBAADF00D * 0x8BADF00D ^ 0xA5A5A5A5) & 0xFFFFFFFF,
        (0xFACEFEED * 0xBADDCAFE ^ 0x5A5A5A5A) & 0xFFFFFFFF,
        (0x0BADF00D * 0xB16B00B5 ^ 0xC0FFEE00) & 0xFFFFFFFF,
        (0xFEEDFACE * 0xDEADC0DE ^ 0x0BADC0DE) & 0xFFFFFFFF,
        (0xBAADF00D * 0xDEADC0DE ^ 0xABAD1DEA) & 0xFFFFFFFF,
        (0x1BADB002 * 0x8BADF00D ^ 0xD15EA5E5) & 0xFFFFFFFF,
        (0xCAFEBABE * 0xFACEFEED ^ 0x0D15EA5E) & 0xFFFFFFFF,
        (0xFEEDFACE * 0xDEADC0DE ^ 0xBAADF00D) & 0xFFFFFFFF,
        (0xB16B00B5 * 0xCAFEBABE ^ 0xDEADC0DE) & 0xFFFFFFFF,
        (0xDEADC0DE * 0x1BADB002 ^ 0xB16B00B5) & 0xFFFFFFFF,
        (0xFACEFEED * 0x0BADF00D ^ 0xABAD1DEA) & 0xFFFFFFFF,
        (0x8BADF00D * 0xFEEDFACE ^ 0xD15EA5E5) & 0xFFFFFFFF,
        (0xCAFEBABE * 0xB16B00B5 ^ 0x0D15EA5E) & 0xFFFFFFFF,
        (0x0BADF00D * 0xFACEFEED ^ 0xBAADF00D) & 0xFFFFFFFF,
    ]

    try:
        random_value = int.from_bytes(encoded_bytes[:4], 'big')
        encoded_segment_bytes = encoded_bytes[4:]
        segments = [int.from_bytes(encoded_segment_bytes[i:i + 4], 'big') for i in range(0, len(encoded_segment_bytes), 4)]

        decoded_segments = []
        for segment, constant in zip(segments, OBFUSCATION_CONSTANTS_PLUS):
            intermediate_value = (segment ^ constant)
            decoded_segment = (intermediate_value - random_value - constant) % 0x100000000
            decoded_segments.append(decoded_segment)

        packet_length_bytes = decoded_segments[0].to_bytes(4, 'big')
        decoded_length = int.from_bytes(packet_length_bytes, 'big')
    except ValueError as value_error:
        raise ValueError("Failed to decode bytes or convert to integer") from value_error
    except Exception as unexpected_error:
        raise TypeError("An unexpected error occurred during decoding") from unexpected_error

    return decoded_length


def test_packet_length_plus():
    import random
    while True:
        a = random.randint(1, 4029)
        b = encode_packet_length_plus(a)
        c = decode_packet_length_plus(b)
        if a != c:
            print(a,c)
            break


def encrypt_packet_basic_plus(packet_payload, base64_status=True, salt=b"RickLangbun5050"):
    if not isinstance(packet_payload, bytes):
        raise TypeError("Packet payload must be bytes. Received type: {}, value: {}".format(type(packet_payload).__name__, packet_payload))

    max_length = 4096 - 68 - 32 - 1018
    if len(packet_payload) > max_length:
        raise ValueError("Packet payload too long; must not exceed {} bytes. Received length: {}, value: {}".format(max_length, len(packet_payload), packet_payload))

    if base64_status:
        try:
            packet_payload = base64.b64encode(packet_payload)
        except Exception as base64_error:
            raise ValueError("Failed to base64 encode the packet payload") from base64_error

    random_bytes_length = secrets.randbelow(4096 - 68 - 32 - len(packet_payload))
    random_bytes = secrets.token_bytes(random_bytes_length)
    packet_payload += random_bytes
    packet_payload += random_bytes_length.to_bytes(4, 'big')

    pattern = salt[:4]
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

    combined_data = packet_payload + checksum

    seed = len(combined_data) + int.from_bytes(salt[-4:], 'big')
    random.seed(seed)
    data_list = list(combined_data)
    random.shuffle(data_list)

    return bytes(data_list)


def decrypt_packet_basic_plus(packet_payload, packet_len, base64_status=True, salt=b"RickLangbun5050"):
    if not isinstance(packet_payload, bytes):
        raise TypeError("Packet payload must be bytes. Received type: {}, value: {}".format(type(packet_payload).__name__, packet_payload))

    seed = packet_len + int.from_bytes(salt[-4:], 'big')
    random.seed(seed)
    data_list = list(packet_payload)
    indices = list(range(len(data_list)))
    random.shuffle(indices)
    unshuffled_data_list = [None] * len(data_list)
    for original, shuffled in enumerate(indices):
        unshuffled_data_list[shuffled] = data_list[original]

    data_list = unshuffled_data_list

    try:
        packet_payload = bytes([x for x in data_list[:-32] if x is not None])
        received_checksum = bytes([x for x in data_list[-32:] if x is not None])
    except:
        raise TypeError("data_list contains unexpected types: (list[None]) or other non-byte values.")

    sha256 = hashlib.sha256()
    try:
        sha256.update(packet_payload + salt)
        calculated_checksum = sha256.digest()
    except Exception as checksum_error:
        raise RuntimeError("Failed to calculate SHA-256 checksum") from checksum_error

    if calculated_checksum != received_checksum:
        raise ValueError("Invalid checksum. Data may be corrupted.")

    pattern = salt[:4]
    try:
        packet_payload = bytes(b ^ p for b, p in zip(packet_payload, itertools.cycle(pattern)))
    except Exception as xor_error:
        raise RuntimeError("Failed to apply XOR decryption with the pattern") from xor_error

    random_bytes_length = int.from_bytes(packet_payload[-4:], 'big')
    original_packet_payload = packet_payload[:-random_bytes_length-4]

    if base64_status:
        try:
            original_packet_payload = base64.b64decode(original_packet_payload)
        except Exception as base64_error:
            raise ValueError("Failed to base64 decode the packet payload") from base64_error

    return original_packet_payload

