# NovaVault Pro
### Enterprise-Grade Hybrid Encryption GUI Application

---

## Executive Summary

NovaVault Pro is a secure, high-performance, GUI-based encryption platform built in Python.  
It implements modern cryptographic standards using a hybrid encryption model to ensure confidentiality, integrity, authenticity, and performance efficiency.

The application is engineered for secure file and folder encryption while maintaining low CPU and memory utilization — even when processing large datasets.

---

## Core Security Architecture

### Hybrid Encryption Model

NovaVault Pro uses a layered cryptographic approach:

- **AES-256-GCM** for authenticated data encryption  
- **RSA-4096** (or ECC) for symmetric key protection  
- **SHA-256** for integrity verification  
- **Digital Signatures** for authenticity validation  

Each encryption session:

1. Generates a new random AES-256 key
2. Encrypts file/folder data using AES-GCM (Authenticated Encryption)
3. Encrypts the AES key using the recipient's RSA public key
4. Signs the encrypted package using the private key
5. Generates SHA-256 hash fingerprint

This ensures:

- Confidentiality
- Integrity
- Authenticity
- Forward secrecy per session

---

## Graphical User Interface

Built with:

- **PySide6 (recommended)**  
- or **Tkinter (lightweight alternative)**  

### Main Interface Options

- Encrypt
- Decrypt
- Generate Key Pair
- Exit

### GUI Characteristics

- Clean, modern, minimal design
- Fully responsive during heavy operations
- Background worker threads
- Real-time progress indicator
- No blocking main thread

---

## Encryption Workflow

1. User selects file or folder (auto-detection)
2. System compresses data (ZIP, maximum compression)
3. Data encrypted using AES-256-GCM
4. AES key encrypted using RSA-4096 public key
5. Encrypted package digitally signed
6. Output saved with `.nova` extension
7. Optional secure delete of original (multi-pass overwrite)

### Output Metadata

- Public key fingerprint
- SHA-256 integrity hash
- Signature verification status

---

## Decryption Workflow

1. Select `.nova` encrypted file
2. Provide private key + password
3. Verify digital signature
4. Decrypt AES key using private RSA key
5. Decrypt data
6. Verify SHA-256 hash integrity
7. Restore original file/folder structure

### Integrity Result Display

- Verified
- Tampered
- Invalid Signature
- Incorrect Key

---

## Key Management

### RSA-4096 Key Pair Generation

Outputs:

- `public_key.pem`
- `private_key.pem` (password-protected)

### Features

- SHA-256 fingerprint display
- Private key encryption with password
- Import existing key pairs
- Secure key validation

---

## Performance Engineering

NovaVault Pro is designed for efficiency:

- Chunk-based streaming encryption
- No full file memory loading
- Multithreaded background processing
- Stable CPU consumption
- Controlled memory footprint
- Efficient compression-before-encryption pipeline

This prevents system overload even during large folder encryption.

---

## Advanced Security Features

- Secure file deletion (multi-pass overwrite)
- Digital signature verification
- SHA-256 integrity comparison
- Minimal secure logging
- Exception handling:
  - Invalid private key
  - Corrupted file
  - Signature mismatch
  - Unauthorized access attempt

---

## Technical Requirements

- Python 3.10+
- `cryptography` library
- Cross-platform compatibility (Windows / Linux / macOS)
- Modular architecture
- Separation between:
  - GUI Layer
  - Cryptographic Engine
  - Key Management Module

---

## Security Compliance Principles

- Authenticated Encryption (AEAD)
- Zero plaintext persistence
- Password-protected private keys
- Per-session symmetric key generation
- No insecure cryptographic primitives
- No hardcoded secrets

---

## File Extension

Encrypted output files use:

