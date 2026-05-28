# envault — Encrypt and decrypt .env files with military-grade encryption

**Never commit your `.env` files in plaintext again.**

`envault` lets you encrypt your environment variable files with AES-256-GCM and a password of your choice. Push the encrypted `.env.enc` file to any repo safely — only people with the password can decrypt it.

## Why?

Because `*.env` in `.gitignore` is easy to forget. And secrets in git history? That's already a breach waiting to happen.

## Features

- **AES-256-GCM** authenticated encryption with Scrypt key derivation
- **Integrity checksum** — detects tampering or corruption
- **Password confirmation** on encrypt to prevent typos
- **Safe overwrite** prompts when output file already exists
- **Password rotation** — re-encrypt with a new password without manual steps
- **File metadata** embedded in the encrypted blob (original filename, timestamp, checksum)
- **Status command** — inspect encrypted files without decrypting
- Single zero-dependency file (only needs `cryptography` package)

## Installation

```bash
pip install cryptography
```

Or clone and use directly:

```bash
git clone https://github.com/IndraTensei/envault.git
cd envault
pip install cryptography
python envault.py encrypt .env
```

## Quick Start

```bash
# Encrypt your .env file
python envault.py encrypt .env
# Enter password: ******
# Confirm: ******
# → .env.enc created

# Decrypt it back
python envault.py decrypt .env.enc
# Enter password: ******
# → .env restored

# Check file info without decrypting
python envault.py status .env.enc

# Change the password
python envault.py rotate .env.enc
```

## Commands

| Command | Description |
|---------|-------------|
| `encrypt [.env] [-o out]` | Encrypt a file (default: `.env` → `.env.enc`) |
| `decrypt <file> [-o out]` | Decrypt a file |
| `status <file>` | Show encrypted file metadata |
| `rotate <file>` | Re-encrypt with a new password |

## File Format

The encrypted file has this structure:

```
[MAGIC: 4 bytes "ENVA"]
[SALT: 16 bytes]
[NONCE: 12 bytes]
[CIPHERTEXT: variable]
  └── [METADATA_LEN: 4 bytes]
  └── [METADATA: JSON]
  └── [PLAINTEXT: your file content]
```

All crypto uses **AES-256-GCM** with a key derived via **Scrypt** (N=131072, r=8, p=1).

## Usage in CI/CD

```bash
# Store encrypted env + password as CI secrets
envault decrypt .env.enc -o .env
```

## License

MIT — use it, fork it, make it yours.
