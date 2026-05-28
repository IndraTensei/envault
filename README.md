# envault — Encrypt and decrypt .env files with military-grade encryption

**Never commit your `.env` files in plaintext again.**

`envault` lets you encrypt your environment variable files with AES-256-GCM and a password of your choice. Push the encrypted `.env.enc` file to any repo safely — only people with the password can decrypt it.

## Why?

Because `*.env` in `.gitignore` is easy to forget. And secrets in git history? That's already a breach waiting to happen.

## Features

- **AES-256-GCM** authenticated encryption with Scrypt key derivation
- **Multi-profile support** — manage `production`, `staging`, `dev` configs in one repo
- **`.env` diff viewer** — compare key names between two encrypted files without exposing values
- **Key/value audit** — list all keys, verify required keys exist, without decrypting
- **Git hook integration** — one command to block plaintext `.env` commits permanently
- **`.envvaultrc` config** — define profiles, paths, defaults per project so you never type flags twice
- **Watch mode** — auto re-encrypts on save during development
- **Integrity checksum** — detects tampering or corruption
- **Password rotation** — re-encrypt with a new password without manual steps

## Installation

```bash
pip install cryptography
```

Or:

```bash
git clone https://github.com/IndraTensei/envault.git
cd envault
pip install cryptography
python envault.py encrypt .env
```

## Quick Start

```bash
# 1. Initialize config (auto-detects .env files)
envault init

# 2. Encrypt your main .env
envault encrypt .env

# 3. Encrypt with profile
envault encrypt .env --profile production
# → .env.enc.production

# 4. Decrypt
envault decrypt .env.enc
envault decrypt .env.enc.production -o .env

# 5. Compare keys between two environments (no values exposed!)
envault diff .env.enc .env.enc.production

# 6. Audit — verify all expected keys are present
envault audit .env.enc --expect DATABASE_URL API_KEY REDIS_URL

# 7. Block plaintext .env commits permanently
envault install-hooks

# 8. Watch mode — auto re-encrypt on save
envault watch .env --interval 2

# 9. Rotate password
envault rotate .env.enc

# 10. Check file info without decrypting
envault status .env.enc
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create `.envvaultrc` with auto-detected profiles |
| `encrypt <file> [--profile <name>] [-o out]` | Encrypt a file |
| `decrypt <file> [-o out]` | Decrypt a file |
| `status <file>` | Show encrypted file metadata |
| `rotate <file>` | Re-encrypt with a new password |
| `diff <file1> <file2>` | Compare key names between files |
| `audit <file> [--expect KEY ...]` | List keys, optionally verify expected set |
| `install-hooks` | Install git pre-commit hook |
| `watch <file> [--interval N]` | Auto re-encrypt on change |

## Multi-Profile Workflow

```bash
# .envvaultrc
{
  "profiles": {
    "production": {
      "source": ".env",
      "encrypted": ".env.enc.production"
    },
    "staging": {
      "source": ".env",
      "encrypted": ".env.enc.staging"
    }
  }
}

# Encrypt each profile
envault encrypt .env --profile production   → .env.enc.production
envault encrypt .env --profile staging      → .env.enc.staging

# Compare what's different
envault diff .env.enc.production .env.enc.staging
```

## File Format

```
[MAGIC: 4 bytes "ENVA"]
[SALT: 16 bytes]
[NONCE: 12 bytes]
[CIPHERTEXT: variable]
  └── [METADATA_LEN: 4 bytes]
  └── [METADATA: JSON (checksum, filename, timestamp, profile)]
  └── [PLAINTEXT: your file content]
```

All crypto uses **AES-256-GCM** with a key derived via **Scrypt** (N=131072, r=8, p=1).

## Git Pre-Commit Hook

Once installed with `envault install-hooks`, any attempt to commit a plaintext `.env` file will be blocked:

```
🚫 envault: blocked commit — plaintext .env files staged:
   ❌ .env

   Encrypt them first:
     envault encrypt .env

   Or bypass with: git commit --no-verify
```

Bypass available with `--no-verify` for emergencies.

## License

MIT — use it, fork it, make it yours.
