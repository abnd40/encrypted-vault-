# Encrypted File Vault

A secure command-line file encryption tool implementing military-grade cryptographic standards. This project demonstrates practical application of cryptographic principles, secure coding practices, and defense-in-depth security architecture.

## Overview

Encrypted File Vault provides confidential file storage through authenticated encryption, ensuring both data privacy and integrity. The tool supports single file encryption, directory archiving, and secure file deletion using industry-standard algorithms approved by NIST and recommended by OWASP.

**Key Security Features:**
- AES-256-GCM authenticated encryption (AEAD)
- Argon2id memory-hard key derivation (PHC winner)
- HMAC-based integrity verification via GCM authentication tags
- Secure file deletion with multi-pass overwriting
- Defense against common cryptographic attacks

## Security Architecture

### Encryption: AES-256-GCM

**Why AES-256?**
- Advanced Encryption Standard approved by NIST (FIPS 197)
- 256-bit key provides 128-bit security against quantum attacks (Grover's algorithm)
- Extensively cryptanalyzed with no practical attacks found after 20+ years
- Hardware acceleration (AES-NI) available on modern processors

**Why Galois/Counter Mode (GCM)?**
- Authenticated Encryption with Associated Data (AEAD)
- Provides confidentiality, integrity, and authenticity in a single operation
- Prevents tampering, bit-flipping, and padding oracle attacks
- Parallelizable for high performance on multi-core systems
- 128-bit authentication tag prevents forgery with probability < 2^-128

```
┌─────────────────────────────────────────────────────────────────┐
│                    AES-256-GCM Encryption                       │
├─────────────────────────────────────────────────────────────────┤
│  Plaintext ──┐                                                  │
│              ├──► AES-256-GCM ──► Ciphertext + Auth Tag         │
│  Key ────────┤         │                                        │
│  Nonce ──────┤         │                                        │
│  AAD ────────┘         ▼                                        │
│                   Authentication                                │
│                   (GHASH-based)                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Derivation: Argon2id

**Why Argon2id?**
- Winner of the Password Hashing Competition (2015)
- Memory-hard function: requires significant RAM, making GPU/ASIC attacks expensive
- Argon2id variant combines:
  - **Argon2i**: Data-independent memory access (side-channel resistant)
  - **Argon2d**: Data-dependent memory access (tradeoff resistant)
- Recommended by OWASP for password hashing (2024)

**Configuration (OWASP Guidelines):**
| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Memory | 64 MiB | Sufficient to deter GPU attacks |
| Iterations | 3 | Adequate security margin |
| Parallelism | 4 | Utilize multi-core CPUs |
| Hash Length | 32 bytes | 256-bit key for AES-256 |

**Fallback: PBKDF2-HMAC-SHA256**
- NIST-approved (SP 800-132)
- 600,000 iterations (OWASP 2023 recommendation)
- Used when Argon2 is unavailable

### Integrity Verification

GCM mode provides built-in integrity through its authentication tag:
- 128-bit GHASH-based authentication
- Any modification to ciphertext, nonce, or AAD causes authentication failure
- Prevents:
  - Bit-flipping attacks
  - Truncation attacks
  - Replay attacks (when combined with unique nonces)
  - Padding oracle attacks

### Secure File Deletion

Implements DoD 5220.22-M-inspired sanitization:

```
Pass 1: Random data overwrite
Pass 2: Zero byte overwrite
Pass 3: Random data overwrite
Final:  File deletion
```

**Limitations on Modern Storage:**
- SSD/Flash: Wear leveling may preserve data in other blocks
- Copy-on-Write filesystems (ZFS, Btrfs): Original blocks preserved
- Journaling filesystems: Data may exist in journal
- Recommended: Use full-disk encryption for comprehensive protection

### Password Policy

Following NIST SP 800-63B guidelines with additional requirements:

| Requirement | Value | Rationale |
|-------------|-------|-----------|
| Minimum Length | 12 characters | Exceeds NIST minimum of 8 |
| Maximum Length | 128 characters | Prevent DoS attacks |
| Complexity | 3 of 4 character types | Defense in depth |
| Blocklist | Common passwords checked | Prevent dictionary attacks |

## Encrypted File Format

```
┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size     │ Field                                     │
├────────┼──────────┼───────────────────────────────────────────┤
│ 0      │ 7 bytes  │ Magic bytes: "VAULT01"                    │
│ 7      │ 1 byte   │ Format version                            │
│ 8      │ 4 bytes  │ Timestamp (Unix epoch, big-endian)        │
│ 12     │ 1 byte   │ KDF type (0=PBKDF2, 1=Argon2)             │
│ 13     │ 2 bytes  │ Filename length (big-endian)              │
│ 15     │ Variable │ Original filename (UTF-8)                 │
│ ...    │ 32 bytes │ Salt                                      │
│ ...    │ 12 bytes │ Nonce (IV)                                │
│ ...    │ Variable │ Ciphertext + Authentication Tag (16 bytes)│
└────────────────────────────────────────────────────────────────┘
```

**Design Decisions:**
- Magic bytes enable file type identification
- Version field allows future format upgrades
- Original filename stored for recovery
- Salt stored per-file (not secret, must be unique)
- Header authenticated via GCM's AAD mechanism

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/encrypted-vault.git
cd encrypted-vault

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `cryptography>=41.0.0` | AES-GCM encryption, PBKDF2 |
| `argon2-cffi>=23.1.0` | Argon2id key derivation |

## Usage

### Basic Commands

```bash
# Encrypt a file
python vault.py encrypt document.pdf

# Decrypt a file
python vault.py decrypt document.pdf.vault

# Encrypt with secure deletion of original
python vault.py encrypt secret.txt --shred

# Encrypt a directory
python vault.py encrypt-dir sensitive_folder/

# Decrypt a directory archive
python vault.py decrypt-dir sensitive_folder.tar.vault

# View security configuration
python vault.py info
```

### Command Reference

#### `encrypt` - Encrypt a single file
```bash
python vault.py encrypt <file> [-o OUTPUT] [--shred] [--pbkdf2]

Options:
  -o, --output    Specify output file path (default: <file>.vault)
  --shred         Securely delete original after encryption
  --pbkdf2        Use PBKDF2 instead of Argon2 for key derivation
```

#### `decrypt` - Decrypt a vault file
```bash
python vault.py decrypt <file.vault> [-o OUTPUT] [--shred]

Options:
  -o, --output    Specify output file path (default: original filename)
  --shred         Securely delete vault file after decryption
```

#### `encrypt-dir` - Encrypt a directory
```bash
python vault.py encrypt-dir <directory> [-o OUTPUT] [--shred] [--pbkdf2]

Options:
  -o, --output    Specify output archive path (default: <dir>.tar.vault)
  --shred         Securely delete original directory after encryption
  --pbkdf2        Use PBKDF2 instead of Argon2
```

#### `decrypt-dir` - Decrypt a directory archive
```bash
python vault.py decrypt-dir <archive.tar.vault> [-o OUTPUT] [--shred]

Options:
  -o, --output    Specify output directory (default: current directory)
  --shred         Securely delete archive after extraction
```

### Example Session

```bash
$ python vault.py encrypt classified_report.pdf

    ╔═══════════════════════════════════════════════════════════════╗
    ║                    ENCRYPTED FILE VAULT                       ║
    ║                   AES-256-GCM + Argon2id                      ║
    ║                                                               ║
    ║  Military-grade encryption for sensitive file protection      ║
    ╚═══════════════════════════════════════════════════════════════╝

Password:
Confirm password:

[Password Strength: STRONG]

Encrypting: classified_report.pdf
  Deriving key using ARGON2...
  Reading input file...
  Encrypting with AES-256-GCM...
  Writing encrypted file...

[SUCCESS] Encrypted file saved to: classified_report.pdf.vault

[SECURITY NOTE] Clear your terminal history if password was visible.
```

## Threat Model

### Protections Provided

| Threat | Mitigation |
|--------|------------|
| Unauthorized file access | AES-256-GCM encryption |
| Data tampering | GCM authentication tag |
| Password guessing | Memory-hard KDF (Argon2id) |
| Rainbow table attacks | Random 256-bit salt per file |
| Nonce reuse | Random 96-bit nonce per encryption |
| Weak passwords | Password policy enforcement |
| Data remnants | Secure multi-pass deletion |

### Known Limitations

| Limitation | Description | Mitigation |
|------------|-------------|------------|
| Memory safety | Python's GC may leave key material in memory | Best-effort cleanup; use OS memory locking for production |
| Cold boot attacks | RAM contents may persist after shutdown | Use full-disk encryption; enable memory scrambling |
| Keyloggers | Compromised host captures passwords | Use hardware security keys; trusted boot |
| SSD secure delete | Wear leveling preserves data | Use full-disk encryption |
| Side-channel attacks | Timing attacks possible | Argon2id provides partial resistance |
| Quantum computing | AES-256 reduced to 128-bit security | Still considered secure (128-bit sufficient) |

### What This Tool Does NOT Protect Against

- Compromised execution environment (malware, rootkits)
- Physical access attacks during execution
- Coercion/rubber-hose cryptanalysis
- Weak master passwords chosen by users
- Metadata leakage (file sizes, access times)

## Cryptographic Design Decisions

### Why These Algorithms?

| Component | Choice | Alternatives Considered |
|-----------|--------|------------------------|
| Block Cipher | AES-256 | ChaCha20 (good alternative for non-AES-NI systems) |
| Mode | GCM | CCM (slower), OCB (patent concerns), XTS (for disk encryption) |
| KDF | Argon2id | bcrypt (not memory-hard), scrypt (more complex configuration) |
| HMAC | Via GCM | Encrypt-then-MAC (additional complexity) |

### Nonce Handling

- 96-bit random nonces provide ~2^32 message birthday bound per key
- Each file has unique salt = unique derived key = fresh nonce space
- For extremely high-volume encryption, consider nonce-misuse-resistant modes (AES-GCM-SIV)

### Associated Authenticated Data (AAD)

The file header (magic bytes, version, timestamp, filename, salt) is:
- **Authenticated**: Tampering causes decryption failure
- **Not encrypted**: Allows file identification without decryption

This is intentional - metadata authentication prevents attacks while allowing file management.

## Development

### Project Structure

```
encrypted-vault/
├── vault.py           # Main CLI application
├── requirements.txt   # Python dependencies
└── README.md          # This documentation
```

### Code Quality

The implementation follows secure coding practices:

- **Input validation**: All user inputs validated before use
- **Error handling**: Cryptographic errors don't leak information
- **Memory management**: Best-effort key material cleanup
- **Type hints**: Enhanced code readability and IDE support
- **Documentation**: Extensive comments explaining cryptographic concepts

### Running Security Analysis

```bash
# Install security linter
pip install bandit

# Run security analysis
bandit -r vault.py

# Check for common vulnerabilities
pip install safety
safety check
```

## References

### Standards and Guidelines

- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - Galois/Counter Mode (GCM)
- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) - Password-Based Key Derivation
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Academic References

- Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*
- Biryukov, A., Dinu, D., & Khovratovich, D. (2016). *Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications*

## Technologies Used

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.8+ | Core language |
| cryptography | 41.0+ | Cryptographic primitives |
| argon2-cffi | 23.1+ | Memory-hard key derivation |
| OpenSSL | (via cryptography) | Backend cryptographic operations |

## License

This project is released under the MIT License. See LICENSE file for details.

---

*This project demonstrates understanding of applied cryptography, secure software development, and security engineering principles. Developed as a portfolio project for defense/intelligence sector internship applications.*
