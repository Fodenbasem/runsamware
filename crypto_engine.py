"""
NovaCrypt Crypto Engine
Enterprise-grade hybrid encryption module

Security Features:
- AES-256-GCM for symmetric encryption (authenticated encryption)
- RSA-4096 for encrypting the symmetric key
- Digital signatures for authentication
- SHA-256 for integrity verification
- Chunk-based streaming for large file handling
"""

import os
import io
import json
import zipfile
import hashlib
import secrets
from typing import Tuple, Optional, Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Constants
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for streaming
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits for GCM
SALT_SIZE = 32
KDF_ITERATIONS = 100000

# .nova file format version
NOVA_FORMAT_VERSION = "1.0"


@dataclass
class EncryptionResult:
    """Result of encryption operation"""
    success: bool
    output_path: str
    key_fingerprint: str
    file_hash: str
    signature_verified: bool
    original_size: int
    encrypted_size: int
    error: Optional[str] = None


@dataclass
class DecryptionResult:
    """Result of decryption operation"""
    success: bool
    output_path: str
    integrity_verified: bool
    signature_verified: bool
    original_filename: str
    error: Optional[str] = None


class CryptoEngine:
    """
    Hybrid encryption engine using AES-256-GCM + RSA-4096
    """
    
    def __init__(self):
        self._aes_key = None
        self._private_key = None
        self._public_key = None
    
    # ==================== Key Generation ====================
    
    @staticmethod
    def generate_rsa_keypair(password: str) -> Tuple[bytes, bytes]:
        """
        Generate RSA-4096 key pair with password protection
        
        Args:
            password: Password to protect private key
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate RSA-4096 key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Derive encryption key from password using PBKDF2
        salt = os.urandom(SALT_SIZE)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Serialize private key with password protection
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key)
        )
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def load_private_key(private_pem: bytes, password: str) -> rsa.RSAPrivateKey:
        """
        Load and decrypt private key from PEM data
        
        Args:
            private_pem: Private key in PEM format
            password: Password to decrypt the key
            
        Returns:
            RSA private key object
        """
        # Derive decryption key from password
        salt = private_pem[:SALT_SIZE] if private_pem[:SALT_SIZE] != salt else b''
        
        # For PKCS8 format, we need to handle salt differently
        # The salt is not stored in the PEM, we use a fixed salt for derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'novacrypt_salt',  # Fixed salt for key derivation
            iterations=KDF_ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=key,
            backend=default_backend()
        )
        
        return private_key
    
    @staticmethod
    def load_public_key(public_pem: bytes) -> rsa.RSAPublicKey:
        """
        Load public key from PEM data
        
        Args:
            public_pem: Public key in PEM format
            
        Returns:
            RSA public key object
        """
        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
        return public_key
    
    @staticmethod
    def get_key_fingerprint(public_pem: bytes) -> str:
        """
        Get SHA-256 fingerprint of public key
        
        Args:
            public_pem: Public key in PEM format
            
        Returns:
            Hex string of SHA-256 hash
        """
        return hashlib.sha256(public_pem).hexdigest()
    
    # ==================== Encryption ====================
    
    def encrypt_file(self, 
                     input_path: str, 
                     output_path: str,
                     public_pem: bytes,
                     private_pem: bytes,
                     password: str,
                     progress_callback: Optional[Callable[[float, str], None]] = None,
                     secure_delete: bool = False) -> EncryptionResult:
        """
        Encrypt a file using hybrid encryption
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output (.nova)
            public_pem: Public key for encryption
            private_pem: Private key for signing
            password: Password for private key
            progress_callback: Optional callback for progress updates
            secure_delete: Whether to securely delete original
            
        Returns:
            EncryptionResult with details
        """
        try:
            # Get file info
            file_size = os.path.getsize(input_path)
            original_filename = os.path.basename(input_path)
            
            if progress_callback:
                progress_callback(0, "Starting encryption...")
            
            # Generate random AES-256 key
            self._aes_key = os.urandom(AES_KEY_SIZE)
            
            if progress_callback:
                progress_callback(5, "AES key generated")
            
            # Load keys
            public_key = self.load_public_key(public_pem)
            private_key = self.load_private_key(private_pem, password)
            
            if progress_callback:
                progress_callback(10, "Keys loaded")
            
            # Compress data
            compressed_data = self._compress_file(input_path, progress_callback, 10, 40)
            
            if progress_callback:
                progress_callback(40, "Data compressed")
            
            # Encrypt data with AES-256-GCM
            encrypted_data, nonce, auth_tag = self._encrypt_aes_gcm(compressed_data)
            
            if progress_callback:
                progress_callback(60, "Data encrypted with AES-256-GCM")
            
            # Encrypt AES key with RSA
            encrypted_aes_key = self._encrypt_aes_key(self._aes_key, public_key)
            
            if progress_callback:
                progress_callback(70, "AES key encrypted with RSA")
            
            # Calculate SHA-256 hash of encrypted data
            data_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            # Sign the encrypted data
            signature = self._sign_data(encrypted_data, private_key)
            
            if progress_callback:
                progress_callback(80, "Digital signature created")
            
            # Create .nova file
            self._create_nova_file(
                output_path,
                original_filename,
                encrypted_data,
                encrypted_aes_key,
                nonce,
                auth_tag,
                signature,
                data_hash,
                public_pem
            )
            
            if progress_callback:
                progress_callback(95, "Writing encrypted file...")
            
            # Secure delete original if requested
            if secure_delete:
                self._secure_delete(input_path)
            
            encrypted_size = os.path.getsize(output_path)
            key_fingerprint = self.get_key_fingerprint(public_pem)
            
            if progress_callback:
                progress_callback(100, "Encryption complete!")
            
            return EncryptionResult(
                success=True,
                output_path=output_path,
                key_fingerprint=key_fingerprint,
                file_hash=data_hash,
                signature_verified=True,
                original_size=file_size,
                encrypted_size=encrypted_size
            )
            
        except Exception as e:
            return EncryptionResult(
                success=False,
                output_path="",
                key_fingerprint="",
                file_hash="",
                signature_verified=False,
                original_size=0,
                encrypted_size=0,
                error=str(e)
            )
    
    def encrypt_folder(self,
                       input_folder: str,
                       output_path: str,
                       public_pem: bytes,
                       private_pem: bytes,
                       password: str,
                       progress_callback: Optional[Callable[[float, str], None]] = None,
                       secure_delete: bool = False) -> EncryptionResult:
        """
        Encrypt a folder using hybrid encryption
        
        Args:
            input_folder: Path to folder to encrypt
            output_path: Path for encrypted output (.nova)
            public_pem: Public key for encryption
            private_pem: Private key for signing
            password: Password for private key
            progress_callback: Optional callback for progress updates
            secure_delete: Whether to securely delete original
            
        Returns:
            EncryptionResult with details
        """
        try:
            # Get folder info
            total_size = sum(os.path.getsize(os.path.join(dirpath, filename))
                           for dirpath, _, filenames in os.walk(input_folder)
                           for filename in filenames)
            
            if progress_callback:
                progress_callback(0, "Starting folder encryption...")
            
            # Generate random AES-256 key
            self._aes_key = os.urandom(AES_KEY_SIZE)
            
            if progress_callback:
                progress_callback(5, "AES key generated")
            
            # Load keys
            public_key = self.load_public_key(public_pem)
            private_key = self.load_private_key(private_pem, password)
            
            if progress_callback:
                progress_callback(10, "Keys loaded")
            
            # Compress folder to ZIP
            compressed_data = self._compress_folder(input_folder, progress_callback, 10, 40)
            
            if progress_callback:
                progress_callback(40, "Folder compressed")
            
            # Encrypt data with AES-256-GCM
            encrypted_data, nonce, auth_tag = self._encrypt_aes_gcm(compressed_data)
            
            if progress_callback:
                progress_callback(60, "Data encrypted with AES-256-GCM")
            
            # Encrypt AES key with RSA
            encrypted_aes_key = self._encrypt_aes_key(self._aes_key, public_key)
            
            if progress_callback:
                progress_callback(70, "AES key encrypted with RSA")
            
            # Calculate SHA-256 hash of encrypted data
            data_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            # Sign the encrypted data
            signature = self._sign_data(encrypted_data, private_key)
            
            if progress_callback:
                progress_callback(80, "Digital signature created")
            
            # Create .nova file
            original_filename = os.path.basename(input_folder)
            self._create_nova_file(
                output_path,
                original_filename,
                encrypted_data,
                encrypted_aes_key,
                nonce,
                auth_tag,
                signature,
                data_hash,
                public_pem,
                is_folder=True
            )
            
            if progress_callback:
                progress_callback(95, "Writing encrypted file...")
            
            # Secure delete original if requested
            if secure_delete:
                self._secure_delete_folder(input_folder)
            
            encrypted_size = os.path.getsize(output_path)
            key_fingerprint = self.get_key_fingerprint(public_pem)
            
            if progress_callback:
                progress_callback(100, "Folder encryption complete!")
            
            return EncryptionResult(
                success=True,
                output_path=output_path,
                key_fingerprint=key_fingerprint,
                file_hash=data_hash,
                signature_verified=True,
                original_size=total_size,
                encrypted_size=encrypted_size
            )
            
        except Exception as e:
            return EncryptionResult(
                success=False,
                output_path="",
                key_fingerprint="",
                file_hash="",
                signature_verified=False,
                original_size=0,
                encrypted_size=0,
                error=str(e)
            )
    
    # ==================== Decryption ====================
    
    def decrypt_file(self,
                     input_path: str,
                     output_path: str,
                     public_pem: bytes,
                     private_pem: bytes,
                     password: str,
                     progress_callback: Optional[Callable[[float, str], None]] = None) -> DecryptionResult:
        """
        Decrypt a .nova file
        
        Args:
            input_path: Path to .nova file
            output_path: Path for decrypted output
            public_pem: Public key for verification
            private_pem: Private key for decryption
            password: Password for private key
            progress_callback: Optional callback for progress updates
            
        Returns:
            DecryptionResult with details
        """
        try:
            if progress_callback:
                progress_callback(0, "Starting decryption...")
            
            # Parse .nova file
            (original_filename, is_folder, encrypted_data, 
             encrypted_aes_key, nonce, auth_tag, 
             signature, stored_hash, nova_public_pem) = self._parse_nova_file(input_path)
            
            if progress_callback:
                progress_callback(10, "File parsed")
            
            # Verify public key matches
            if public_pem != nova_public_pem:
                return DecryptionResult(
                    success=False,
                    output_path="",
                    integrity_verified=False,
                    signature_verified=False,
                    original_filename=original_filename,
                    error="Public key does not match. Use the correct key pair."
                )
            
            # Verify digital signature
            signature_valid = self._verify_signature(encrypted_data, signature, nova_public_pem)
            
            if not signature_valid:
                return DecryptionResult(
                    success=False,
                    output_path="",
                    integrity_verified=False,
                    signature_verified=False,
                    original_filename=original_filename,
                    error="Digital signature verification failed. File may be tampered."
                )
            
            if progress_callback:
                progress_callback(20, "Signature verified")
            
            # Load private key
            private_key = self.load_private_key(private_pem, password)
            
            if progress_callback:
                progress_callback(30, "Private key loaded")
            
            # Decrypt AES key
            self._aes_key = self._decrypt_aes_key(encrypted_aes_key, private_key)
            
            if progress_callback:
                progress_callback(40, "AES key decrypted")
            
            # Decrypt data
            decrypted_data = self._decrypt_aes_gcm(encrypted_data, nonce, auth_tag)
            
            if progress_callback:
                progress_callback(60, "Data decrypted")
            
            # Verify integrity
            computed_hash = hashlib.sha256(encrypted_data).hexdigest()
            integrity_verified = (computed_hash == stored_hash)
            
            if not integrity_verified:
                return DecryptionResult(
                    success=False,
                    output_path="",
                    integrity_verified=False,
                    signature_verified=True,
                    original_filename=original_filename,
                    error="Integrity verification failed. File may be corrupted or tampered."
                )
            
            if progress_callback:
                progress_callback(70, "Integrity verified")
            
            # Decompress data
            if is_folder:
                self._decompress_folder(decrypted_data, output_path)
            else:
                self._decompress_file(decrypted_data, output_path, original_filename)
            
            if progress_callback:
                progress_callback(100, "Decryption complete!")
            
            return DecryptionResult(
                success=True,
                output_path=output_path,
                integrity_verified=integrity_verified,
                signature_verified=signature_valid,
                original_filename=original_filename
            )
            
        except Exception as e:
            return DecryptionResult(
                success=False,
                output_path="",
                integrity_verified=False,
                signature_verified=False,
                original_filename="",
                error=str(e)
            )
    
    # ==================== Helper Methods ====================
    
    def _compress_file(self, file_path: str, 
                       progress_callback: Optional[Callable] = None,
                       start_progress: float = 0, 
                       end_progress: float = 100) -> bytes:
        """
        Compress a file using ZIP with maximum compression
        """
        file_size = os.path.getsize(file_path)
        compressed = io.BytesIO()
        
        with zipfile.ZipFile(compressed, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.write(file_path, os.path.basename(file_path))
            
            if progress_callback:
                progress = (end_progress - start_progress) * 0.5 + start_progress
                progress_callback(progress, "Compressing file...")
        
        return compressed.getvalue()
    
    def _compress_folder(self, folder_path: str,
                         progress_callback: Optional[Callable] = None,
                         start_progress: float = 0,
                         end_progress: float = 100) -> bytes:
        """
        Compress a folder using ZIP with maximum compression
        """
        compressed = io.BytesIO()
        file_count = sum([len(files) for r, d, files in os.walk(folder_path)])
        processed = 0
        
        with zipfile.ZipFile(compressed, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(folder_path))
                    zf.write(file_path, arcname)
                    
                    processed += 1
                    if progress_callback and file_count > 0:
                        progress = start_progress + (end_progress - start_progress) * (processed / file_count) * 0.5
                        progress_callback(progress, f"Compressing: {arcname}")
        
        return compressed.getvalue()
    
    def _decompress_file(self, data: bytes, output_dir: str, original_filename: str):
        """
        Decompress a single file
        """
        compressed = io.BytesIO(data)
        
        with zipfile.ZipFile(compressed, 'r') as zf:
            zf.extractall(output_dir)
    
    def _decompress_folder(self, data: bytes, output_dir: str):
        """
        Decompress folder data
        """
        compressed = io.BytesIO(data)
        
        with zipfile.ZipFile(compressed, 'r') as zf:
            zf.extractall(output_dir)
    
    def _encrypt_aes_gcm(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Returns:
            Tuple of (encrypted_data, nonce, auth_tag)
        """
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(self._aes_key)
        
        # GCM mode includes authentication
        encrypted = aesgcm.encrypt(nonce, data, None)
        
        # Split encrypted data and auth tag (last 16 bytes)
        encrypted_data = encrypted[:-16]
        auth_tag = encrypted[-16:]
        
        return encrypted_data, nonce, auth_tag
    
    def _decrypt_aes_gcm(self, encrypted_data: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM
        """
        aesgcm = AESGCM(self._aes_key)
        
        # Combine encrypted data and auth tag
        ciphertext_with_tag = encrypted_data + auth_tag
        
        return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    
    def _encrypt_aes_key(self, aes_key: bytes, public_key) -> bytes:
        """
        Encrypt AES key using RSA public key
        """
        encrypted = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    
    def _decrypt_aes_key(self, encrypted_aes_key: bytes, private_key) -> bytes:
        """
        Decrypt AES key using RSA private key
        """
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
    
    def _sign_data(self, data: bytes, private_key) -> bytes:
        """
        Sign data using RSA private key
        """
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    
    def _verify_signature(self, data: bytes, signature: bytes, public_pem: bytes) -> bool:
        """
        Verify digital signature
        """
        try:
            public_key = self.load_public_key(public_pem)
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def _create_nova_file(self, output_path: str, original_filename: str,
                          encrypted_data: bytes, encrypted_aes_key: bytes,
                          nonce: bytes, auth_tag: bytes, signature: bytes,
                          data_hash: str, public_pem: bytes, is_folder: bool = False):
        """
        Create .nova encrypted file format
        
        Format:
        - Magic bytes: b'NOVA\x00'
        - Version: 4 bytes
        - Flags: 4 bytes (is_folder, etc.)
        - Original filename length: 4 bytes
        - Original filename: variable
        - Public key length: 4 bytes
        - Public key: variable
        - Encrypted AES key length: 4 bytes
        - Encrypted AES key: variable
        - Nonce: 12 bytes
        - Auth tag: 16 bytes
        - Data hash: 32 bytes (SHA-256)
        - Signature length: 4 bytes
        - Signature: variable
        - Encrypted data length: 8 bytes
        - Encrypted data: variable
        """
        import struct
        
        with open(output_path, 'wb') as f:
            # Magic bytes
            f.write(b'NOVA\x00')
            
            # Version
            f.write(struct.pack('<I', 1))
            
            # Flags
            flags = 1 if is_folder else 0
            f.write(struct.pack('<I', flags))
            
            # Original filename
            filename_bytes = original_filename.encode('utf-8')
            f.write(struct.pack('<I', len(filename_bytes)))
            f.write(filename_bytes)
            
            # Public key
            f.write(struct.pack('<I', len(public_pem)))
            f.write(public_pem)
            
            # Encrypted AES key
            f.write(struct.pack('<I', len(encrypted_aes_key)))
            f.write(encrypted_aes_key)
            
            # Nonce
            f.write(nonce)
            
            # Auth tag
            f.write(auth_tag)
            
            # Data hash
            f.write(data_hash.encode('utf-8'))
            
            # Signature
            f.write(struct.pack('<I', len(signature)))
            f.write(signature)
            
            # Encrypted data
            f.write(struct.pack('<Q', len(encrypted_data)))
            f.write(encrypted_data)
    
    def _parse_nova_file(self, input_path: str) -> Tuple:
        """
        Parse .nova file
        
        Returns:
            Tuple of (original_filename, is_folder, encrypted_data,
                     encrypted_aes_key, nonce, auth_tag,
                     signature, data_hash, public_pem)
        """
        import struct
        
        with open(input_path, 'rb') as f:
            # Magic bytes
            magic = f.read(5)
            if magic != b'NOVA\x00':
                raise ValueError("Invalid .nova file format")
            
            # Version
            version = struct.unpack('<I', f.read(4))[0]
            
            # Flags
            flags = struct.unpack('<I', f.read(4))[0]
            is_folder = bool(flags & 1)
            
            # Original filename
            filename_len = struct.unpack('<I', f.read(4))[0]
            original_filename = f.read(filename_len).decode('utf-8')
            
            # Public key
            pubkey_len = struct.unpack('<I', f.read(4))[0]
            public_pem = f.read(pubkey_len)
            
            # Encrypted AES key
            aes_key_len = struct.unpack('<I', f.read(4))[0]
            encrypted_aes_key = f.read(aes_key_len)
            
            # Nonce
            nonce = f.read(NONCE_SIZE)
            
            # Auth tag
            auth_tag = f.read(16)
            
            # Data hash
            data_hash = f.read(32).decode('utf-8')
            
            # Signature
            sig_len = struct.unpack('<I', f.read(4))[0]
            signature = f.read(sig_len)
            
            # Encrypted data
            data_len = struct.unpack('<Q', f.read(8))[0]
            encrypted_data = f.read(data_len)
        
        return (original_filename, is_folder, encrypted_data,
                encrypted_aes_key, nonce, auth_tag,
                signature, data_hash, public_pem)
    
    def _secure_delete(self, file_path: str, passes: int = 3):
        """
        Securely delete a file by overwriting with random data
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
        """
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)
    
    def _secure_delete_folder(self, folder_path: str, passes: int = 3):
        """
        Securely delete a folder and its contents
        """
        for root, dirs, files in os.walk(folder_path, topdown=False):
            for name in files:
                file_path = os.path.join(root, name)
                self._secure_delete(file_path, passes)
            os.rmdir(root)


def calculate_file_hash(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        Hex string of SHA-256 hash
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    
    return sha256.hexdigest()


def calculate_data_hash(data: bytes) -> str:
    """
    Calculate SHA-256 hash of data
    
    Args:
        data: Bytes to hash
        
    Returns:
        Hex string of SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()
