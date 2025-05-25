from . import AES256CBCEngine
from . import AsyncCommModule
from . import ChaCha20CipherEngine
from . import EC256Engine
from . import IniconfigModule
from . import IPFetcherModule
from . import PacketCryptoEngine
from . import PacketCryptoEnginePlus
from . import RSACipherEngine
from . import Sha512Cipher

__all__ = [
    'AES256CBCEngine',
    'AsyncCommModule',
    'ChaCha20CipherEngine',
    'EC256Engine',
    'IniconfigModule',
    'IPFetcherModule',
    'PacketCryptoEngine',
    'PacketCryptoEnginePlus',
    'RSACipherEngine',
    'Sha512Cipher'
]

__version__ = "1.0.0"

__doc__ = """
EnigmaVaultCrypt: A comprehensive cryptographic library. (Version {})

This package provides various cryptographic algorithms and utility modules including:
- AES256CBCEngine: AES-256 encryption in CBC mode
- AsyncCommModule: Asynchronous communication functionality
- ChaCha20CipherEngine: ChaCha20 stream cipher
- EC256Engine: Elliptic Curve cryptography engine
- IniconfigModule: Secure configuration file management
- IPFetcherModule: Secure IP address retrieval and handling
- PacketCryptoEngine: Basic packet encryption
- PacketCryptoEnginePlus: Enhanced packet encryption
- RSACipherEngine: RSA public-key cryptography
- Sha512Cipher: SHA-512 hashing

For usage examples and more information, please refer to the documentation.
""".format(__version__)
