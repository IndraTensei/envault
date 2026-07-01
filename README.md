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
- **Password strength meter** — real-time feedback on encryption password quality
- **Multi-format export** — export encrypted env vars to JSON, YAML, shell, Docker, or Kubernetes
- **Template rendering** — generate `.env` files from `.env.template` using encrypted secrets
- **Version history** — snapshot, list, restore, and prune encrypted file versions with `envault history`
- **Doctor diagnostics** — `envault doctor` audits your entire setup for security issues and best practices

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

# 11. Export to various formats
envault export .env.enc --format json -o config.json
envault export .env.enc --format kubernetes -o k8s-secret.yaml

# 12. Render .env from a template
envault template .env.template --source .env.enc.production -o .env
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create `.envvaultrc` with auto-detected profiles |
| `encrypt <file> [--profile <name>] [-o out]` | Encrypt a file (with password strength feedback) |
| `decrypt <file> [-o out]` | Decrypt a file |
| `status <file>` | Show encrypted file metadata |
| `rotate <file>` | Re-encrypt with a new password |
| `diff <file1> <file2>` | Compare key names between files |
| `audit <file> [--expect KEY ...]` | List keys, optionally verify expected set |
| `install-hooks` | Install git pre-commit hook |
| `watch <file> [--interval N]` | Auto re-encrypt on change |
| `export <file> [--format FMT] [-o out]` | Export to JSON/YAML/shell/Docker/K8s/dotenv |
| `template <tpl> --source <src> [-o out]` | Render .env.template from encrypted values |
| `history <file> [--action ACTION]` | Manage version history (list/snapshot/restore/prune) |
| `doctor` | Diagnose setup and security health |
| `bulk <dir> [--operation encrypt|decrypt]` | Batch encrypt or decrypt .env files in a directory |
| `validate <file> [--schema SCHEMA]` | Validate .env file against a schema definition |
| `verify <file>` | Verify encrypted file integrity without full decryption |

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

## Export Formats

The `export` command transforms your encrypted `.env` into various deployment-ready formats:

```bash
# JSON — great for Node.js, Python, config management
envault export .env.enc --format json -o config.json
# {"DATABASE_URL": "postgres://...", "API_KEY": "..."}

# YAML — clean structured config
envault export .env.enc --format yaml -o config.yaml
# DATABASE_URL: postgres://...
# API_KEY: ...

# Shell — source directly in scripts
envault export .env.enc --format shell -o source-me.sh
source source-me.sh

# Docker — use with --env-file
envault export .env.enc --format docker -o docker.env
docker run --env-file docker.env myapp

# Kubernetes — generates a Secret manifest
envault export .env.enc --format kubernetes -o secret.yaml
kubectl apply -f secret.yaml

# Dotenv — roundtrip to standard .env format
envault export .env.enc --format dotenv -o output.env
```

## Template Rendering

Create a `.env.template` file that acts as a scaffold for new developers or CI pipelines. Use `{{KEY}}` placeholders that get filled in from an encrypted source:

```bash
# .env.template
DATABASE_URL={{DATABASE_URL}}
API_KEY={{API_KEY}}
REDIS_URL={{REDIS_URL}}
LOG_LEVEL=info
NEW_RELIC_LICENSE_KEY=
```

```bash
# Render it — DATABASE_URL, API_KEY, REDIS_URL get filled from the encrypted file
# LOG_LEVEL and NEW_RELIC_LICENSE_KEY are preserved as-is
envault template .env.template --source .env.enc.production -o .env
```

This is perfect for onboarding — commit the template to git, share the encrypted file securely, and new team members can generate their `.env` without ever seeing the password.

## Version History

`envault history` keeps a versioned backup of your encrypted `.env` files so you can roll back mistakes:

```bash
# Save a snapshot of the current encrypted file
envault history .env.enc --action snapshot

# List all snapshots
envault history .env.enc
# 📋 History for .env.enc (3 snapshots)
#    Location: .envvault-history/
#
#      2024-06-09 10:00:00 UTC  (1,234 bytes)  [20240609-100000]
#      2024-06-10 14:30:00 UTC  (1,245 bytes)  [20240610-143000]
#   →  2024-06-11 09:15:00 UTC  (1,250 bytes)  [20240611-091500]

# Restore a specific snapshot (current state is auto-backed up first)
envault history .env.enc --action restore --restore 20240610-143000

# Prune old snapshots, keeping only the most recent 10
envault history .env.enc --action prune --keep 10
```

Snapshots are stored in `.envault-history/` alongside your encrypted file. The current state is always backed up before a restore, so you can never lose data.

## Batch Operations

`envault bulk` allows you to encrypt or decrypt multiple `.env` files in a directory at once:

```bash
# Encrypt all .env files in current directory
envault bulk . --operation encrypt

# Decrypt all .enc files in ./envs directory
envault bulk ./envs --operation decrypt

# Specify output directory
envault bulk . --operation encrypt --output-dir ./encrypted
```

This is useful when managing multiple environment files across different services or microservices.

## Schema Validation

`envault validate` validates `.env` files against a JSON schema definition:

```bash
# Validate with explicit schema file
envault validate .env --schema .env.schema.json

# Validate encrypted file (will prompt for password)
envault validate .env.enc --schema production.schema.json
```

Schema format (`.env.schema.json`):
```json
{
  "required": ["DATABASE_URL", "API_KEY", "SECRET_KEY"],
  "patterns": {
    "DATABASE_URL": "^postgres://",
    "API_KEY": "^[A-Za-z0-9]{32,}$"
  },
  "types": {
    "PORT": "integer",
    "DEBUG": "boolean",
    "DATABASE_URL": "url"
  }
}
```

If no schema is specified, envault looks for `<file>.schema.json` in the same directory.

Validation checks:
- Required keys are present
- Values match specified regex patterns
- Values are of the correct type (integer, boolean, url)

## Verify Integrity

`envault verify` checks encrypted file integrity without fully decrypting:

```bash
envault verify .env.enc
```

This command:
- Validates file format and magic bytes
- Checks file permissions (warns if world-readable)
- Optionally verifies checksum and metadata (with password)

Use this to quickly check if an encrypted file is valid and hasn't been corrupted, without exposing the decrypted contents.

## Doctor Diagnostics

`envault doctor` is your security health check. Run it to audit your entire setup:

```bash
envault doctor
# 🏥 envault doctor — checking your setup
#    Directory: /home/user/myproject
#    envault v1.3.0
#
# 📂 Scanning for plaintext .env files...
#    ✅ No unprotected plaintext .env files found
#
# 🔐 Checking encrypted files...
#    ✅ Found 2 encrypted file(s)
#    ✅ .env.enc permissions OK
#    ⚠️  .env.enc.staging is world-readable (chmod 600 .env.enc.staging)
#
# 📝 Checking .envvaultrc...
#    ✅ .envvaultrc exists
#    ✅ Configured profiles: production, staging
#
# 🪝 Checking git hooks...
#    ✅ envault pre-commit hook installed
#    ✅ Git repository detected
#
# 🙈 Checking .gitignore...
#    ✅ .env files are in .gitignore
#
# 🕐 Checking version history...
#    ✅ .env.enc: 3 history snapshot(s)
#
# ==================================================
#    Health Score: 🟢 92/100 — Great shape!
#    ✅ 7 passed  |  ⚠️  1 warnings  |  ❌ 0 issues
```

It checks for plaintext `.env` leaks, file permissions, config validity, git hook installation, `.gitignore` coverage, and version history — then gives you a health score.

## Password Strength Feedback

When encrypting interactively, envault now analyzes your password and shows real-time strength feedback:

```
🔑 Enter encryption password:
   Password strength: 🟡 Good
      💡 Mix uppercase, lowercase, numbers, and symbols
🔑 Confirm password:
```

Weak passwords trigger a confirmation prompt encouraging you to pick something stronger.

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
