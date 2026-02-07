#!/usr/bin/env python3
"""
Encrypted File Vault - A Secure File Encryption CLI Tool
=========================================================

This tool provides military-grade file encryption using industry-standard
cryptographic primitives. Designed to demonstrate understanding of secure
coding practices and cryptographic implementations.

Author: Portfolio Project for Defense/Intelligence Internship Applications
Security Level: AES-256 with authenticated encryption (GCM mode)

SECURITY ARCHITECTURE:
----------------------
1. Key Derivation: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
   - Fallback to PBKDF2-HMAC-SHA256 if Argon2 unavailable
2. Encryption: AES-256-GCM (authenticated encryption with associated data)
3. Integrity: Built-in via GCM mode (GHASH-based authentication tag)
4. Randomness: os.urandom() - cryptographically secure PRNG from OS

THREAT MODEL:
-------------
- Protects against: Unauthorized file access, data exfiltration, tampering
- Assumes: Secure execution environment, trusted system memory
- Does not protect against: Compromised host, keyloggers, cold boot attacks
"""

import argparse
import getpass
import hashlib
import hmac
import os
import re
import secrets
import shutil
import struct
import sys
import tarfile
import tempfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

# Cryptographic library imports with graceful fallback
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("ERROR: cryptography library not installed.")
    print("Install with: pip install cryptography")
    sys.exit(1)

# Argon2 is preferred for key derivation (memory-hard function)
try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# =============================================================================
# CRYPTOGRAPHIC CONSTANTS
# =============================================================================
# These values are chosen based on current security best practices (2024)

# AES-256 requires a 256-bit (32-byte) key
AES_KEY_SIZE = 32  # bytes

# GCM nonce should be 96 bits (12 bytes) for optimal security
# Using a larger nonce reduces the collision resistance
GCM_NONCE_SIZE = 12  # bytes

# Salt for key derivation - 128 bits minimum recommended by NIST
# We use 256 bits (32 bytes) for additional security margin
SALT_SIZE = 32  # bytes

# GCM authentication tag size - 128 bits provides strong integrity
GCM_TAG_SIZE = 16  # bytes

# PBKDF2 iterations - OWASP recommends minimum 600,000 for SHA-256 (2023)
# Higher iterations = slower brute force attacks
PBKDF2_ITERATIONS = 600_000

# Argon2id parameters (OWASP recommendations for password hashing)
# Memory: 64 MiB - makes GPU attacks expensive
# Time: 3 iterations - balance between security and usability
# Parallelism: 4 threads - utilize modern CPUs
ARGON2_MEMORY_COST = 65536  # 64 MiB in KiB
ARGON2_TIME_COST = 3        # iterations
ARGON2_PARALLELISM = 4      # threads

# Secure deletion overwrite passes (DoD 5220.22-M recommends 3-7 passes)
# We use 3 passes: random, zeros, random for balance of security and speed
SECURE_DELETE_PASSES = 3

# File format version for future compatibility
FILE_FORMAT_VERSION = 1

# Magic bytes to identify encrypted vault files
VAULT_MAGIC = b'VAULT01'  # 7 bytes


# =============================================================================
# PASSWORD POLICY
# =============================================================================
class PasswordPolicy:
    """
    Enforces password strength requirements following NIST SP 800-63B guidelines.

    NIST 800-63B (2020) recommendations:
    - Minimum 8 characters (we require 12 for higher security)
    - Check against common password lists
    - No composition rules (but we add them for defense-in-depth)
    - Allow up to 64+ characters

    For high-security applications, we add complexity requirements.
    """

    MIN_LENGTH = 12  # NIST minimum is 8, we require 12 for sensitive data
    MAX_LENGTH = 128  # Prevent DoS via extremely long passwords

    # Common weak passwords (subset - production would use larger list)
    COMMON_PASSWORDS = {
        'password', 'password123', '123456789012', 'qwertyuiop12',
        'letmein12345', 'admin1234567', 'welcome12345', 'monkey123456',
        'dragon123456', 'master123456', 'password1234', 'trustno1234',
    }

    @classmethod
    def validate(cls, password: str) -> Tuple[bool, str]:
        """
        Validate password against security policy.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters"

        if len(password) > cls.MAX_LENGTH:
            return False, f"Password must not exceed {cls.MAX_LENGTH} characters"

        # Check for lowercase, uppercase, digit, and special character
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        complexity_count = sum([has_lower, has_upper, has_digit, has_special])

        if complexity_count < 3:
            return False, (
                "Password must contain at least 3 of: "
                "lowercase, uppercase, digit, special character"
            )

        # Check against common passwords
        if password.lower() in cls.COMMON_PASSWORDS:
            return False, "Password is too common. Choose a stronger password."

        return True, "Password meets security requirements"

    @classmethod
    def get_strength(cls, password: str) -> str:
        """
        Estimate password strength for user feedback.

        This is a simplified entropy estimation. Real-world implementations
        should use more sophisticated analysis (zxcvbn library recommended).
        """
        length = len(password)
        charset_size = 0

        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 20

        # Simplified entropy calculation: log2(charset^length)
        import math
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        if entropy < 40:
            return "WEAK"
        elif entropy < 60:
            return "MODERATE"
        elif entropy < 80:
            return "STRONG"
        else:
            return "VERY STRONG"


# =============================================================================
# KEY DERIVATION
# =============================================================================
class KeyDerivation:
    """
    Secure key derivation from passwords using memory-hard functions.

    Why Key Derivation Functions (KDFs)?
    ------------------------------------
    Passwords have low entropy compared to cryptographic keys. A KDF:
    1. Stretches the password into a fixed-size key
    2. Adds computational cost to slow brute-force attacks
    3. Uses salt to prevent rainbow table attacks
    4. Memory-hard functions (Argon2) resist GPU/ASIC attacks

    Argon2id vs PBKDF2:
    -------------------
    - Argon2id: Winner of Password Hashing Competition (2015)
      - Memory-hard: Requires significant RAM, making parallel attacks expensive
      - Side-channel resistant: Combines Argon2i (data-independent) and Argon2d
      - Recommended by OWASP for new applications

    - PBKDF2: NIST-approved, widely supported
      - CPU-bound only: Vulnerable to GPU acceleration
      - Still acceptable with high iteration counts
      - Used as fallback when Argon2 unavailable
    """

    @staticmethod
    def derive_key_argon2(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key using Argon2id (preferred method).

        Argon2id parameters chosen per OWASP guidelines:
        - memory_cost: 64 MiB - significant enough to deter GPU attacks
        - time_cost: 3 iterations - provides good security margin
        - parallelism: 4 threads - utilizes modern multi-core CPUs

        The 'id' variant combines:
        - Argon2i: Data-independent addressing (side-channel resistant)
        - Argon2d: Data-dependent addressing (tradeoff-resistant)
        """
        if not ARGON2_AVAILABLE:
            raise RuntimeError("Argon2 not available")

        # hash_secret_raw provides raw bytes output for use as key material
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=AES_KEY_SIZE,  # 32 bytes for AES-256
            type=Type.ID  # Argon2id variant
        )
        return key

    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key using PBKDF2-HMAC-SHA256 (fallback method).

        PBKDF2 (Password-Based Key Derivation Function 2):
        - Applies HMAC iteratively to increase computation cost
        - Each iteration depends on the previous, preventing parallelization
        - 600,000 iterations recommended by OWASP (2023) for SHA-256

        Limitations:
        - Not memory-hard: Can be accelerated with GPUs/ASICs
        - For high-security applications, Argon2id is preferred
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @classmethod
    def derive_key(cls, password: str, salt: bytes, use_argon2: bool = True) -> bytes:
        """
        Derive encryption key with automatic fallback.

        Priority:
        1. Argon2id (if available and requested)
        2. PBKDF2-HMAC-SHA256 (fallback)
        """
        if use_argon2 and ARGON2_AVAILABLE:
            return cls.derive_key_argon2(password, salt)
        return cls.derive_key_pbkdf2(password, salt)


# =============================================================================
# ENCRYPTION ENGINE
# =============================================================================
class EncryptionEngine:
    """
    AES-256-GCM authenticated encryption implementation.

    Why AES-256-GCM?
    ----------------
    - AES (Advanced Encryption Standard): NIST-approved, extensively analyzed
    - 256-bit key: Quantum-resistant (Grover's algorithm reduces to 128-bit)
    - GCM (Galois/Counter Mode): Provides both confidentiality AND integrity

    GCM Mode Benefits:
    ------------------
    1. Authenticated Encryption (AEAD):
       - Encryption and integrity verification in one operation
       - Prevents tampering, truncation, and bit-flipping attacks

    2. Parallelizable:
       - Counter mode allows parallel encryption of blocks
       - Efficient on modern multi-core processors

    3. Additional Authenticated Data (AAD):
       - Can authenticate metadata without encrypting it
       - We use AAD for version info and timestamps

    Security Considerations:
    ------------------------
    - NEVER reuse nonce with same key (catastrophic failure)
    - We use random 96-bit nonces with collision probability < 2^-32
    - For extremely high-volume encryption, consider nonce-misuse-resistant
      modes like AES-GCM-SIV
    """

    def __init__(self, key: bytes):
        """
        Initialize encryption engine with derived key.

        Args:
            key: 32-byte (256-bit) key from key derivation function
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

        self.aesgcm = AESGCM(key)
        # Store key reference for secure cleanup
        self._key = key

    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Additional data to authenticate (not encrypted)

        Returns:
            Tuple of (nonce, ciphertext_with_tag)

        Security Notes:
        - Nonce is generated using os.urandom() (CSPRNG)
        - 96-bit nonce provides birthday bound of ~2^32 messages per key
        - Ciphertext includes 128-bit authentication tag
        """
        # Generate cryptographically secure random nonce
        # os.urandom() sources from:
        # - Linux: /dev/urandom (getrandom syscall)
        # - Windows: CryptGenRandom
        # - macOS: /dev/urandom (arc4random)
        nonce = os.urandom(GCM_NONCE_SIZE)

        # AESGCM.encrypt() returns ciphertext || tag
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)

        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
        """
        Decrypt and verify data using AES-256-GCM.

        Args:
            nonce: 12-byte nonce used during encryption
            ciphertext: Ciphertext with authentication tag
            associated_data: Additional authenticated data (must match encryption)

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails

        Security Notes:
        - Decryption will fail if ANY bit is modified (ciphertext, tag, or AAD)
        - This prevents padding oracle attacks and tampering
        """
        return self.aesgcm.decrypt(nonce, ciphertext, associated_data)

    def secure_cleanup(self):
        """
        Attempt to securely clear key material from memory.

        IMPORTANT LIMITATION:
        ---------------------
        Python's memory management makes secure memory cleanup difficult:
        1. Objects may be copied during operations
        2. Garbage collector timing is unpredictable
        3. Memory may be swapped to disk

        This is a best-effort cleanup. For true secure memory:
        - Use OS-level memory locking (mlock)
        - Consider languages with explicit memory control (C, Rust)
        - Use hardware security modules (HSM) for key storage

        Defense-in-depth: We still attempt cleanup to reduce exposure window.
        """
        if hasattr(self, '_key') and self._key:
            # Overwrite key bytes (limited effectiveness in Python)
            try:
                # Create mutable bytearray and zero it
                key_array = bytearray(self._key)
                for i in range(len(key_array)):
                    key_array[i] = 0
            except Exception:
                pass  # Best effort - don't fail on cleanup
            finally:
                self._key = None


# =============================================================================
# SECURE FILE OPERATIONS
# =============================================================================
class SecureFileOps:
    """
    Secure file handling with integrity verification and secure deletion.

    This class implements:
    1. Encrypted file format with metadata
    2. Secure file deletion (overwrite before delete)
    3. Integrity verification via authenticated encryption
    """

    @staticmethod
    def generate_file_header(
        original_filename: str,
        kdf_type: str,
        salt: bytes
    ) -> bytes:
        """
        Generate encrypted file header containing metadata.

        File Format (Version 1):
        ========================
        Bytes 0-6:   Magic bytes "VAULT01" (file identification)
        Bytes 7:     Version number (1 byte, unsigned)
        Bytes 8-11:  Timestamp (4 bytes, Unix epoch, big-endian)
        Bytes 12:    KDF type (1 byte: 0=PBKDF2, 1=Argon2)
        Bytes 13-14: Filename length (2 bytes, big-endian)
        Bytes 15+:   Original filename (UTF-8 encoded)
        Following:   Salt (32 bytes)
        Following:   Nonce (12 bytes)
        Following:   Ciphertext with tag

        Why this format?
        - Magic bytes allow quick file type identification
        - Version enables future format upgrades
        - Storing filename allows recovery without original name
        - Salt must be stored (not secret, but unique per file)
        """
        timestamp = int(datetime.utcnow().timestamp())
        filename_bytes = original_filename.encode('utf-8')
        filename_len = len(filename_bytes)

        if filename_len > 65535:
            raise ValueError("Filename too long")

        kdf_byte = 1 if kdf_type == 'argon2' else 0

        # Pack header using struct for precise binary format
        # >: big-endian, 7s: 7-char string, B: unsigned byte, I: unsigned int
        # H: unsigned short, followed by variable-length filename
        header = struct.pack(
            f'>7sBIBH{filename_len}s',
            VAULT_MAGIC,
            FILE_FORMAT_VERSION,
            timestamp,
            kdf_byte,
            filename_len,
            filename_bytes
        )

        return header + salt

    @staticmethod
    def parse_file_header(data: bytes) -> dict:
        """
        Parse encrypted file header and extract metadata.

        Returns:
            Dictionary with: magic, version, timestamp, kdf_type,
                           original_filename, salt, header_size
        """
        if len(data) < 7:
            raise ValueError("File too small to be valid vault file")

        magic = data[:7]
        if magic != VAULT_MAGIC:
            raise ValueError("Not a valid vault file (magic bytes mismatch)")

        # Parse fixed-size header fields
        version = data[7]
        if version != FILE_FORMAT_VERSION:
            raise ValueError(f"Unsupported file format version: {version}")

        timestamp = struct.unpack('>I', data[8:12])[0]
        kdf_byte = data[12]
        filename_len = struct.unpack('>H', data[13:15])[0]

        # Extract variable-length filename
        filename_end = 15 + filename_len
        filename_bytes = data[15:filename_end]
        original_filename = filename_bytes.decode('utf-8')

        # Extract salt
        salt_end = filename_end + SALT_SIZE
        salt = data[filename_end:salt_end]

        return {
            'magic': magic,
            'version': version,
            'timestamp': datetime.utcfromtimestamp(timestamp),
            'kdf_type': 'argon2' if kdf_byte == 1 else 'pbkdf2',
            'original_filename': original_filename,
            'salt': salt,
            'header_size': salt_end
        }

    @staticmethod
    def secure_delete(file_path: Path, passes: int = SECURE_DELETE_PASSES) -> bool:
        """
        Securely delete a file by overwriting before deletion.

        Implements a simplified version of DoD 5220.22-M sanitization:
        - Pass 1: Overwrite with random data
        - Pass 2: Overwrite with zeros
        - Pass 3: Overwrite with random data

        IMPORTANT LIMITATIONS:
        ----------------------
        1. SSD/Flash Storage:
           - Wear leveling may preserve original data in other blocks
           - TRIM commands may not immediately erase data
           - For SSDs, full-disk encryption is more reliable

        2. Journaling File Systems:
           - File data may exist in journal
           - Metadata may reveal file existence

        3. Copy-on-Write File Systems (ZFS, Btrfs):
           - Original blocks preserved until space needed
           - Snapshots may contain original data

        4. Cloud/Network Storage:
           - No guarantee of physical overwrite
           - Backups may retain copies

        For maximum security on traditional HDDs, this provides reasonable
        assurance. For SSDs, consider using the drive's secure erase command.
        """
        if not file_path.exists():
            return False

        try:
            file_size = file_path.stat().st_size

            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    if pass_num % 2 == 0:
                        # Random data pass
                        # Write in chunks to handle large files
                        remaining = file_size
                        while remaining > 0:
                            chunk_size = min(remaining, 1024 * 1024)  # 1 MB chunks
                            f.write(os.urandom(chunk_size))
                            remaining -= chunk_size
                    else:
                        # Zero pass
                        remaining = file_size
                        while remaining > 0:
                            chunk_size = min(remaining, 1024 * 1024)
                            f.write(b'\x00' * chunk_size)
                            remaining -= chunk_size

                    # Force write to disk
                    f.flush()
                    os.fsync(f.fileno())

            # Finally, delete the file
            file_path.unlink()
            return True

        except Exception as e:
            print(f"Warning: Secure delete failed: {e}")
            # Fallback to regular deletion
            try:
                file_path.unlink()
            except Exception:
                pass
            return False


# =============================================================================
# VAULT OPERATIONS
# =============================================================================
class Vault:
    """
    Main vault operations: encrypt, decrypt, and manage files.

    This class orchestrates the encryption workflow:
    1. Password validation and key derivation
    2. File reading and encryption
    3. Encrypted file format handling
    4. Directory archiving for batch encryption
    """

    def __init__(self, password: str, use_argon2: bool = True):
        """
        Initialize vault with password.

        The password is not stored - only used for key derivation.
        Each file encryption generates a unique salt and thus unique key.
        """
        # Validate password strength
        is_valid, message = PasswordPolicy.validate(password)
        if not is_valid:
            raise ValueError(f"Password policy violation: {message}")

        self.password = password
        self.use_argon2 = use_argon2 and ARGON2_AVAILABLE
        self.kdf_type = 'argon2' if self.use_argon2 else 'pbkdf2'

        # Track strength for user feedback
        self.password_strength = PasswordPolicy.get_strength(password)

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Optional[Path] = None,
        secure_delete_original: bool = False
    ) -> Path:
        """
        Encrypt a single file.

        Args:
            input_path: Path to file to encrypt
            output_path: Output path (default: input_path + '.vault')
            secure_delete_original: Securely delete original after encryption

        Returns:
            Path to encrypted file

        Encryption Process:
        1. Generate random salt (32 bytes)
        2. Derive key from password + salt
        3. Read plaintext file
        4. Create associated data (file metadata for authentication)
        5. Encrypt with AES-256-GCM
        6. Write header + nonce + ciphertext
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if not input_path.is_file():
            raise ValueError(f"Not a regular file: {input_path}")

        # Generate output path if not specified
        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.vault')
        else:
            output_path = Path(output_path)

        # Generate unique salt for this file
        # Each file gets its own salt = unique key derivation
        # This means same password produces different keys per file
        salt = os.urandom(SALT_SIZE)

        # Derive encryption key
        print(f"  Deriving key using {self.kdf_type.upper()}...")
        key = KeyDerivation.derive_key(self.password, salt, self.use_argon2)

        # Initialize encryption engine
        engine = EncryptionEngine(key)

        try:
            # Read input file
            print(f"  Reading input file...")
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            # Generate file header (includes salt)
            header = SecureFileOps.generate_file_header(
                original_filename=input_path.name,
                kdf_type=self.kdf_type,
                salt=salt
            )

            # Associated data for authentication
            # This data is NOT encrypted but IS authenticated
            # Any modification will cause decryption to fail
            aad = header

            # Encrypt the file content
            print(f"  Encrypting with AES-256-GCM...")
            nonce, ciphertext = engine.encrypt(plaintext, aad)

            # Write encrypted file
            print(f"  Writing encrypted file...")
            with open(output_path, 'wb') as f:
                f.write(header)
                f.write(nonce)
                f.write(ciphertext)

            # Secure delete original if requested
            if secure_delete_original:
                print(f"  Securely deleting original...")
                SecureFileOps.secure_delete(input_path)

            return output_path

        finally:
            # Clean up key material from memory
            engine.secure_cleanup()
            # Attempt to clear plaintext (best effort)
            if 'plaintext' in locals():
                del plaintext

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Optional[Path] = None,
        secure_delete_encrypted: bool = False
    ) -> Path:
        """
        Decrypt an encrypted vault file.

        Args:
            input_path: Path to encrypted .vault file
            output_path: Output path (default: restore original filename)
            secure_delete_encrypted: Securely delete vault file after decryption

        Returns:
            Path to decrypted file

        Decryption Process:
        1. Parse file header to extract metadata and salt
        2. Derive key from password + salt (same as encryption)
        3. Extract nonce and ciphertext
        4. Decrypt and verify with AES-256-GCM
        5. Write plaintext to output
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")

        # Read encrypted file
        print(f"  Reading encrypted file...")
        with open(input_path, 'rb') as f:
            data = f.read()

        # Parse header
        print(f"  Parsing file header...")
        header_info = SecureFileOps.parse_file_header(data)

        # Determine output path
        if output_path is None:
            output_path = input_path.parent / header_info['original_filename']
        else:
            output_path = Path(output_path)

        # Handle output file already existing
        if output_path.exists():
            output_path = output_path.with_name(
                f"{output_path.stem}_decrypted{output_path.suffix}"
            )

        # Use the KDF type from the file
        use_argon2 = header_info['kdf_type'] == 'argon2'
        if use_argon2 and not ARGON2_AVAILABLE:
            raise RuntimeError(
                "This file was encrypted with Argon2, but Argon2 is not available. "
                "Install with: pip install argon2-cffi"
            )

        # Derive key using salt from file
        print(f"  Deriving key using {header_info['kdf_type'].upper()}...")
        key = KeyDerivation.derive_key(
            self.password,
            header_info['salt'],
            use_argon2
        )

        # Initialize decryption engine
        engine = EncryptionEngine(key)

        try:
            # Extract nonce and ciphertext
            header_size = header_info['header_size']
            nonce_end = header_size + GCM_NONCE_SIZE
            nonce = data[header_size:nonce_end]
            ciphertext = data[nonce_end:]

            # Associated data must match what was used during encryption
            aad = data[:header_size]

            # Decrypt and verify
            print(f"  Decrypting and verifying integrity...")
            try:
                plaintext = engine.decrypt(nonce, ciphertext, aad)
            except Exception as e:
                raise ValueError(
                    "Decryption failed. Possible causes:\n"
                    "  - Incorrect password\n"
                    "  - File has been tampered with\n"
                    "  - File is corrupted"
                ) from e

            # Write decrypted file
            print(f"  Writing decrypted file...")
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            # Secure delete encrypted file if requested
            if secure_delete_encrypted:
                print(f"  Securely deleting encrypted file...")
                SecureFileOps.secure_delete(input_path)

            return output_path

        finally:
            engine.secure_cleanup()
            if 'plaintext' in locals():
                del plaintext

    def encrypt_directory(
        self,
        dir_path: Path,
        output_path: Optional[Path] = None,
        secure_delete_original: bool = False
    ) -> Path:
        """
        Encrypt an entire directory by creating an encrypted archive.

        Process:
        1. Create tarball of directory (preserves structure, permissions)
        2. Encrypt the tarball as a single file
        3. Optionally secure delete original directory

        Why tar first?
        - Preserves directory structure, permissions, timestamps
        - Single encryption operation is more efficient
        - Reduces metadata leakage (individual file sizes hidden)
        """
        dir_path = Path(dir_path)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        if not dir_path.is_dir():
            raise ValueError(f"Not a directory: {dir_path}")

        # Generate output path
        if output_path is None:
            output_path = dir_path.with_suffix('.tar.vault')
        else:
            output_path = Path(output_path)

        print(f"  Creating archive of directory...")

        # Create tarball in memory to avoid temp file on disk
        tar_buffer = BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            tar.add(dir_path, arcname=dir_path.name)

        tar_data = tar_buffer.getvalue()
        tar_buffer.close()

        # Generate salt and derive key
        salt = os.urandom(SALT_SIZE)
        print(f"  Deriving key using {self.kdf_type.upper()}...")
        key = KeyDerivation.derive_key(self.password, salt, self.use_argon2)

        engine = EncryptionEngine(key)

        try:
            # Generate header for the archive
            header = SecureFileOps.generate_file_header(
                original_filename=dir_path.name + '.tar.gz',
                kdf_type=self.kdf_type,
                salt=salt
            )

            aad = header

            print(f"  Encrypting archive with AES-256-GCM...")
            nonce, ciphertext = engine.encrypt(tar_data, aad)

            print(f"  Writing encrypted archive...")
            with open(output_path, 'wb') as f:
                f.write(header)
                f.write(nonce)
                f.write(ciphertext)

            # Secure delete original directory if requested
            if secure_delete_original:
                print(f"  Securely deleting original directory...")
                # Recursively secure delete all files
                for file_path in dir_path.rglob('*'):
                    if file_path.is_file():
                        SecureFileOps.secure_delete(file_path)
                # Remove empty directories
                shutil.rmtree(dir_path, ignore_errors=True)

            return output_path

        finally:
            engine.secure_cleanup()
            del tar_data

    def decrypt_directory(
        self,
        input_path: Path,
        output_dir: Optional[Path] = None,
        secure_delete_encrypted: bool = False
    ) -> Path:
        """
        Decrypt an encrypted directory archive.

        Process:
        1. Decrypt the vault file to get tarball
        2. Extract tarball to restore directory structure
        3. Optionally secure delete encrypted archive
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Encrypted archive not found: {input_path}")

        # Determine output directory
        if output_dir is None:
            output_dir = input_path.parent
        else:
            output_dir = Path(output_dir)

        # Read and parse encrypted file
        print(f"  Reading encrypted archive...")
        with open(input_path, 'rb') as f:
            data = f.read()

        header_info = SecureFileOps.parse_file_header(data)

        # Derive key
        use_argon2 = header_info['kdf_type'] == 'argon2'
        print(f"  Deriving key using {header_info['kdf_type'].upper()}...")
        key = KeyDerivation.derive_key(
            self.password,
            header_info['salt'],
            use_argon2
        )

        engine = EncryptionEngine(key)

        try:
            header_size = header_info['header_size']
            nonce_end = header_size + GCM_NONCE_SIZE
            nonce = data[header_size:nonce_end]
            ciphertext = data[nonce_end:]
            aad = data[:header_size]

            print(f"  Decrypting and verifying integrity...")
            try:
                tar_data = engine.decrypt(nonce, ciphertext, aad)
            except Exception:
                raise ValueError("Decryption failed - incorrect password or corrupted file")

            # Extract tarball
            print(f"  Extracting archive...")
            tar_buffer = BytesIO(tar_data)
            with tarfile.open(fileobj=tar_buffer, mode='r:gz') as tar:
                # Security: Validate paths to prevent path traversal attacks
                for member in tar.getmembers():
                    member_path = Path(output_dir) / member.name
                    # Ensure extracted path is within output directory
                    try:
                        member_path.resolve().relative_to(output_dir.resolve())
                    except ValueError:
                        raise ValueError(f"Path traversal detected: {member.name}")

                tar.extractall(path=output_dir)

            extracted_path = output_dir / header_info['original_filename'].replace('.tar.gz', '')

            # Secure delete encrypted file if requested
            if secure_delete_encrypted:
                print(f"  Securely deleting encrypted archive...")
                SecureFileOps.secure_delete(input_path)

            return extracted_path

        finally:
            engine.secure_cleanup()
            if 'tar_data' in locals():
                del tar_data


# =============================================================================
# CLI INTERFACE
# =============================================================================
def get_password(confirm: bool = False, prompt: str = "Password: ") -> str:
    """
    Securely prompt for password.

    Uses getpass to disable terminal echo, preventing shoulder surfing.
    Optionally confirms password by requiring re-entry.
    """
    password = getpass.getpass(prompt)

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            raise ValueError("Passwords do not match")

    return password


def print_banner():
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    ENCRYPTED FILE VAULT                       ║
    ║                   AES-256-GCM + Argon2id                      ║
    ║                                                               ║
    ║  Military-grade encryption for sensitive file protection      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_security_info():
    """Display security configuration information."""
    print("\n[Security Configuration]")
    print(f"  Encryption: AES-256-GCM (authenticated encryption)")
    print(f"  Key Derivation: {'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256'}")
    if ARGON2_AVAILABLE:
        print(f"    - Memory: {ARGON2_MEMORY_COST // 1024} MiB")
        print(f"    - Iterations: {ARGON2_TIME_COST}")
        print(f"    - Parallelism: {ARGON2_PARALLELISM} threads")
    else:
        print(f"    - Iterations: {PBKDF2_ITERATIONS:,}")
    print(f"  Secure Delete: {SECURE_DELETE_PASSES}-pass overwrite")
    print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Encrypted File Vault - Secure file encryption using AES-256-GCM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Encrypt a file:
    %(prog)s encrypt secret.pdf

  Decrypt a file:
    %(prog)s decrypt secret.pdf.vault

  Encrypt with secure deletion of original:
    %(prog)s encrypt secret.pdf --shred

  Encrypt a directory:
    %(prog)s encrypt-dir sensitive_folder/

  Decrypt a directory archive:
    %(prog)s decrypt-dir sensitive_folder.tar.vault

  Show security configuration:
    %(prog)s info
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Encrypt file command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input', help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_parser.add_argument(
        '--shred', action='store_true',
        help='Securely delete original file after encryption'
    )
    encrypt_parser.add_argument(
        '--pbkdf2', action='store_true',
        help='Use PBKDF2 instead of Argon2 for key derivation'
    )

    # Decrypt file command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input', help='Encrypted file to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file path')
    decrypt_parser.add_argument(
        '--shred', action='store_true',
        help='Securely delete encrypted file after decryption'
    )

    # Encrypt directory command
    encrypt_dir_parser = subparsers.add_parser(
        'encrypt-dir', help='Encrypt a directory'
    )
    encrypt_dir_parser.add_argument('input', help='Directory to encrypt')
    encrypt_dir_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_dir_parser.add_argument(
        '--shred', action='store_true',
        help='Securely delete original directory after encryption'
    )
    encrypt_dir_parser.add_argument(
        '--pbkdf2', action='store_true',
        help='Use PBKDF2 instead of Argon2 for key derivation'
    )

    # Decrypt directory command
    decrypt_dir_parser = subparsers.add_parser(
        'decrypt-dir', help='Decrypt a directory archive'
    )
    decrypt_dir_parser.add_argument('input', help='Encrypted archive to decrypt')
    decrypt_dir_parser.add_argument('-o', '--output', help='Output directory')
    decrypt_dir_parser.add_argument(
        '--shred', action='store_true',
        help='Securely delete encrypted archive after decryption'
    )

    # Info command
    subparsers.add_parser('info', help='Show security configuration')

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return

    if args.command == 'info':
        print_banner()
        print_security_info()
        return

    print_banner()

    try:
        # Get password with confirmation for encryption
        confirm_password = args.command in ('encrypt', 'encrypt-dir')
        password = get_password(confirm=confirm_password)

        # Determine KDF type
        use_argon2 = True
        if hasattr(args, 'pbkdf2') and args.pbkdf2:
            use_argon2 = False

        # Create vault instance
        vault = Vault(password, use_argon2=use_argon2)
        print(f"\n[Password Strength: {vault.password_strength}]")

        if args.command == 'encrypt':
            print(f"\nEncrypting: {args.input}")
            output = vault.encrypt_file(
                Path(args.input),
                Path(args.output) if args.output else None,
                secure_delete_original=args.shred
            )
            print(f"\n[SUCCESS] Encrypted file saved to: {output}")

        elif args.command == 'decrypt':
            print(f"\nDecrypting: {args.input}")
            output = vault.decrypt_file(
                Path(args.input),
                Path(args.output) if args.output else None,
                secure_delete_encrypted=args.shred
            )
            print(f"\n[SUCCESS] Decrypted file saved to: {output}")

        elif args.command == 'encrypt-dir':
            print(f"\nEncrypting directory: {args.input}")
            output = vault.encrypt_directory(
                Path(args.input),
                Path(args.output) if args.output else None,
                secure_delete_original=args.shred
            )
            print(f"\n[SUCCESS] Encrypted archive saved to: {output}")

        elif args.command == 'decrypt-dir':
            print(f"\nDecrypting directory archive: {args.input}")
            output = vault.decrypt_directory(
                Path(args.input),
                Path(args.output) if args.output else None,
                secure_delete_encrypted=args.shred
            )
            print(f"\n[SUCCESS] Directory extracted to: {output}")

        # Security reminder
        print("\n[SECURITY NOTE] Clear your terminal history if password was visible.")

    except ValueError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[ABORTED] Operation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
