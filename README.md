# EnigmaVaultCrypt 🛡️

![License](https://img.shields.io/badge/License-Custom-red.svg)

A comprehensive Python cryptographic library for educational purposes.

## ⚠️ Important Disclaimer

This project is **strictly for educational and learning purposes**. The code has not undergone formal security audits and may contain vulnerabilities. Do not use in production environments or for processing sensitive data.

## Overview

EnigmaVaultCrypt provides a collection of cryptographic implementations for studying encryption concepts and techniques. The library offers various cryptographic engines and utility modules for academic exploration.

## Features

* AES-256-CBC encryption with salt and hash verification
* ChaCha20 stream cipher implementation
* RSA public-key cryptography
* Elliptic Curve (EC-256) cryptography
* SHA-512 hashing functionality
* Secure packet encryption (basic and enhanced)
* Asynchronous communication module
* Configuration management utilities

## Requirements

* Python 3.6+
* pycryptodome
* cryptography

## Installation

```bash
pip install EnigmaVaultCrypt
```

## Basic Usage Example

```python
from EnigmaVaultCrypt import AES256CBCEngine

# Generate key and initialization vector
key, iv = AES256CBCEngine.generate_aes_256_cbc_bytes()

# Encrypt data
encrypted_data = AES256CBCEngine.encrypt_aes_256_cbc("Secret message", key, iv)

# Decrypt data
decrypted_data = AES256CBCEngine.decrypt_aes_256_cbc(encrypted_data, key, iv)
```

## License

This project is licensed under a custom license. See the [LICENSE](LICENSE) file for details.

## Contact

For academic inquiries: `ricklangbun@tutanota.com`
