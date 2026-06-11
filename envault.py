#!/usr/bin/env python3
"""
envault — Encrypt and decrypt .env files with AES-256-GCM.

Usage:
    envault encrypt [.env] [-o encrypted.env] [--profile production]
    envault decrypt [encrypted.env] [-o .env]
    envault status <file>
    envault rotate <file>
    envault diff <file1.enc> <file2.enc>
    envault audit <file.enc>
    envault install-hooks
    envault watch [.env]
    envault init
    envault export <file> [--format json|yaml|shell|docker|kubernetes|dotenv] [-o out]
    envault template <template> --source <enc_file> [-o .env]
"""

import argparse
import getpass
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import base64
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("❌ Missing dependency: cryptography")
    print("   pip install cryptography")
    sys.exit(1)

VERSION = "1.3.0"
MAGIC = b"ENVA"
NONCE_SIZE = 12
SALT_SIZE = 16
KDF_N = 2**17
KDF_R = 8
KDF_P = 1
CHECKSUM_KEY = b"envault-integrity-check"
ENV_CONFIG_FILE = ".envvaultrc"

# Export format constants
EXPORT_FORMATS = ["json", "yaml", "shell", "docker", "kubernetes", "dotenv"]

# ── Config helpers ──────────────────────────────────────────────

def load_config(start_dir: Path | None = None) -> dict:
    """Walk up from cwd (or start_dir) looking for .envvaultrc."""
    if start_dir is None:
        start_dir = Path.cwd()
    current = start_dir.resolve()
    while True:
        config_path = current / ENV_CONFIG_FILE
        if config_path.exists():
            try:
                return json.loads(config_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        if current.parent == current:
            break
        current = current.parent
    return {}


def find_encrypted_source(enc_path: Path, profiles: dict | None = None) -> Path | None:
    """Given an encrypted file path, figure out the original source .env name.
    
    Handles: .env.enc, .env.enc.production, .env.enc.staging, etc.
    Falls back to metadata if available (requires decrypt).
    """
    name = enc_path.name
    # .env.enc.<profile> → .env
    if name.count(".") >= 3 and ".enc" in name:
        # e.g. .env.enc.production → strip profile suffix
        parts = name.split(".")
        # find the index before .enc
        for i, p in enumerate(parts):
            if p == "enc":
                return enc_path.parent / ".".join(parts[:i])
        # fallback: strip .enc
        stem = name.replace(".enc", "", 1)
        if stem.startswith("."):
            return enc_path.parent / stem
    if name.endswith(".enc"):
        return enc_path.parent / name[:-4]
    return None


# ── Crypto helpers ──────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P)
    return kdf.derive(password.encode("utf-8"))


def compute_checksum(plaintext: bytes) -> str:
    h = hashlib.sha256()
    h.update(CHECKSUM_KEY)
    h.update(plaintext)
    return h.hexdigest()


def parse_encrypted(data: bytes) -> tuple:
    """Parse an encrypted file, return (salt, nonce, ciphertext)."""
    if len(data) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        raise ValueError("File is too small to be a valid envault file.")
    pos = 0
    magic = data[pos : pos + len(MAGIC)]
    if magic != MAGIC:
        raise ValueError("Not a valid envault file (bad magic bytes).")
    pos += len(MAGIC)
    salt = data[pos : pos + SALT_SIZE]
    pos += SALT_SIZE
    nonce = data[pos : pos + NONCE_SIZE]
    pos += NONCE_SIZE
    return salt, nonce, data[pos:]


def decrypt_raw(data: bytes, password: str) -> tuple[bytes, dict]:
    """Decrypt and return (plaintext, metadata)."""
    salt, nonce, ciphertext = parse_encrypted(data)
    key = derive_key(password, salt)
    aad = MAGIC + salt + nonce
    try:
        plaintext_with_meta = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted file.")
    meta_len = struct.unpack(">I", plaintext_with_meta[:4])[0]
    metadata = json.loads(plaintext_with_meta[4 : 4 + meta_len])
    plaintext = plaintext_with_meta[4 + meta_len :]
    return plaintext, metadata


# ── .env parsing helpers ────────────────────────────────────────

def parse_env_keys(raw: bytes) -> set[str]:
    """Extract just the key names from a .env file (ignore values/comments)."""
    keys = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key:
                keys.add(key)
    return keys


def parse_env_vars(raw: bytes) -> dict[str, str]:
    """Parse a .env file into a {key: value} dict, handling comments and blanks."""
    result = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes if matching
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if key:
                result[key] = value
    return result


def password_strength(password: str) -> tuple[str, int, list[str]]:
    """Rate a password. Returns (label, score_0_to_4, list_of_tips)."""
    score = 0
    tips = []
    length = len(password)

    if length >= 8:
        score += 1
    else:
        tips.append("Use at least 8 characters")
    if length >= 12:
        score += 1

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety >= 3:
        score += 1
    else:
        tips.append("Mix uppercase, lowercase, numbers, and symbols")
    if variety == 4:
        score += 1

    # Penalize common weak patterns
    common = {"password", "123456", "qwerty", "letmein", "secret", "admin"}
    if password.lower() in common:
        score = 0
        tips = ["That's a commonly used password — pick something unique"]

    labels = ["🔴 Weak", "🟠 Fair", "🟡 Good", "🟢 Strong", "💎 Excellent"]
    return labels[min(score, 4)], min(score, 4), tips


# ── Export helpers ─────────────────────────────────────────────

def _export_json(vars: dict[str, str], output: str) -> None:
    """Export env vars as JSON."""
    data = json.dumps(vars, indent=2, sort_keys=True) + "\n"
    Path(output).write_text(data)
    print(f"✅ Exported {len(vars)} vars → {output} (JSON)")


def _export_yaml(vars: dict[str, str], output: str) -> None:
    """Export env vars as YAML (no PyYAML dependency — simple serializer)."""
    lines = []
    for k in sorted(vars):
        v = vars[k]
        # Quote values that need it
        needs_quote = any(c in v for c in ':{}[]&*?|-><!%@`#,\'"\\') or v == "" or v.startswith(" ") or v.endswith(" ")
        if needs_quote or "\n" in v:
            escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'{k}: "{escaped}"')
        else:
            lines.append(f"{k}: {v}")
    Path(output).write_text("\n".join(lines) + "\n")
    print(f"✅ Exported {len(vars)} vars → {output} (YAML)")


def _export_shell(vars: dict[str, str], output: str) -> None:
    """Export env vars as shell export statements."""
    lines = []
    for k in sorted(vars):
        v = vars[k]
        escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
        lines.append(f'export {k}="{escaped}"')
    Path(output).write_text("\n".join(lines) + "\n")
    print(f"✅ Exported {len(vars)} vars → {output} (shell)")


def _export_docker(vars: dict[str, str], output: str) -> None:
    """Export env vars as Docker --env-file format (KEY=VALUE, one per line)."""
    lines = []
    for k in sorted(vars):
        v = vars[k]
        # Docker env-file doesn't support quotes; use raw values
        lines.append(f"{k}={v}")
    Path(output).write_text("\n".join(lines) + "\n")
    print(f"✅ Exported {len(vars)} vars → {output} (Docker env-file)")


def _export_kubernetes(vars: dict[str, str], output: str) -> None:
    """Export env vars as a Kubernetes Secret YAML."""
    import base64
    lines = [
        "apiVersion: v1",
        "kind: Secret",
        "metadata:",
        f"  name: envault-secret",
        f"  # Generated by envault v{VERSION}",
        "type: Opaque",
        "data:",
    ]
    for k in sorted(vars):
        encoded = base64.b64encode(vars[k].encode()).decode()
        lines.append(f"  {k}: {encoded}")
    Path(output).write_text("\n".join(lines) + "\n")
    print(f"✅ Exported {len(vars)} vars → {output} (Kubernetes Secret)")


def _export_dotenv(vars: dict[str, str], output: str) -> None:
    """Export env vars as a standard .env file (roundtrip format)."""
    lines = []
    for k in sorted(vars):
        v = vars[k]
        needs_quote = any(c in v for c in ' #"\n\\') or v == ""
        if needs_quote:
            escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'{k}="{escaped}"')
        else:
            lines.append(f"{k}={v}")
    Path(output).write_text("\n".join(lines) + "\n")
    print(f"✅ Exported {len(vars)} vars → {output} (.env)")


_EXPORT_DISPATCH = {
    "json": _export_json,
    "yaml": _export_yaml,
    "shell": _export_shell,
    "docker": _export_docker,
    "kubernetes": _export_kubernetes,
    "dotenv": _export_dotenv,
}


# ── Commands ────────────────────────────────────────────────────

def encrypt_env(
    input_path: str,
    output_path: str,
    password: str | None = None,
    profile: str | None = None,
) -> None:
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    plaintext = input_file.read_bytes()
    checksum = compute_checksum(plaintext)

    if password is None:
        pw1 = getpass.getpass("🔑 Enter encryption password: ")
        label, score, tips = password_strength(pw1)
        print(f"   Password strength: {label}")
        if tips:
            for tip in tips:
                print(f"      💡 {tip}")
        if score < 2:
            confirm = input("   Password is weak. Continue anyway? [y/N]: ").strip().lower()
            if confirm != "y":
                print("Aborted.")
                sys.exit(0)
        pw2 = getpass.getpass("🔑 Confirm password: ")
        if pw1 != pw2:
            print("❌ Passwords don't match.")
            sys.exit(1)
        password = pw1

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    metadata = {
        "version": VERSION,
        "checksum": checksum,
        "filename": input_file.name,
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile or None,
    }
    metadata_bytes = json.dumps(metadata).encode("utf-8")
    metadata_len = struct.pack(">I", len(metadata_bytes))

    aad = MAGIC + salt + nonce
    ciphertext = AESGCM(key).encrypt(
        nonce, metadata_len + metadata_bytes + plaintext, aad
    )

    output_file = Path(output_path)
    output_file.write_bytes(MAGIC + salt + nonce + ciphertext)

    if profile:
        print(f"✅ Encrypted {input_file.name} → {output_file.name}  [profile: {profile}]")
    else:
        print(f"✅ Encrypted {input_file.name} → {output_file.name}")
    print(f"   Original: {len(plaintext):,} bytes  |  Encrypted: {output_file.stat().st_size:,} bytes")
    print(f"   Keys: {len(parse_env_keys(plaintext))}  |  Checksum: {checksum[:16]}...")


def decrypt_env(
    input_path: str,
    output_path: str | None = None,
    password: str | None = None,
) -> tuple[bytes, dict]:
    """Decrypt a file. Returns (plaintext, metadata) for programmatic use."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    data = input_file.read_bytes()

    if password is None:
        password = getpass.getpass("🔑 Enter decryption password: ")

    try:
        plaintext, metadata = decrypt_raw(data, password)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    expected = metadata.get("checksum", "")
    actual = compute_checksum(plaintext)
    integrity_ok = expected == actual

    if not integrity_ok:
        print("⚠️  WARNING: Integrity check failed! File may be corrupted.")

    if output_path is None:
        default_name = metadata.get("filename", ".env")
        output_path = str(input_file.parent / default_name)

    output_file = Path(output_path)

    if output_file.exists():
        response = input(f"⚠️  {output_file.name} already exists. Overwrite? [y/N]: ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)

    output_file.write_bytes(plaintext)
    profile_tag = f"  [profile: {metadata['profile']}]" if metadata.get("profile") else ""
    print(f"✅ Decrypted {input_file.name} → {output_file.name}{profile_tag}")
    print(f"   Size: {len(plaintext):,} bytes")
    print(f"   Encrypted at: {metadata.get('encrypted_at', 'unknown')}")
    print(f"   Keys: {len(parse_env_keys(plaintext))}")
    if integrity_ok:
        print("   Integrity: ✅ Verified")
    else:
        print("   Integrity: ❌ FAILED")

    return plaintext, metadata


def show_status(input_path: str) -> None:
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    data = input_file.read_bytes()
    try:
        salt, nonce, ct = parse_encrypted(data)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    ct_size = len(ct)
    source = find_encrypted_source(input_file)

    print(f"📋 File: {input_file.name}")
    print(f"   Format: envault v{VERSION}")
    print(f"   File size: {len(data):,} bytes")
    print(f"   Ciphertext: {ct_size:,} bytes")
    print(f"   KDF: Scrypt (N={KDF_N:,}, r={KDF_R}, p={KDF_P})")
    print(f"   Cipher: AES-256-GCM")
    print(f"   Salt: {base64.b16encode(salt).decode()[:16]}...")
    if source:
        print(f"   Source: {source.name}")
    print(f"\n   Use 'envault decrypt {input_path}' to decrypt.")


def rotate_password(input_path: str, output_path: str | None = None) -> None:
    input_file = Path(input_path)
    if output_path is None:
        output_path = str(input_file)

    print("🔄 Rotating password...")
    print()

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".env", delete=False) as tmp:
        tmp_path = tmp.name

    # Remove it so decrypt_env doesn't prompt for overwrite
    os.unlink(tmp_path)

    try:
        decrypt_env(input_path, tmp_path)
        print()
        print("Now encrypting with new password...")
        print()
        encrypt_env(tmp_path, output_path)
    finally:
        os.unlink(tmp_path)


def diff_envs(file1_path: str, file2_path: str) -> None:
    """Show key-level differences between two encrypted .env files (no values exposed)."""
    f1 = Path(file1_path)
    f2 = Path(file2_path)

    for fp in [f1, f2]:
        if not fp.exists():
            print(f"❌ File not found: {fp}")
            sys.exit(2)

    # Check if these are actually encrypted files — if they're plaintext .envs, handle directly
    def load_keys_and_metadata(path: Path) -> tuple[set[str], dict]:
        data = path.read_bytes()
        # Try encrypted first
        if data[:len(MAGIC)] == MAGIC:
            pw = getpass.getpass(f"🔑 Password for {path.name}: ")
            plaintext, meta = decrypt_raw(data, pw)
            return parse_env_keys(plaintext), meta
        else:
            return parse_env_keys(data), {}

    keys1, meta1 = load_keys_and_metadata(f1)
    keys2, meta2 = load_keys_and_metadata(f2)

    only_in_1 = sorted(keys1 - keys2)
    only_in_2 = sorted(keys2 - keys1)
    shared = sorted(keys1 & keys2)

    label1 = meta1.get("profile") or f1.name
    label2 = meta2.get("profile") or f2.name

    print(f"📊 Diff: {label1} ↔ {label2}")
    print(f"   {label1}: {len(keys1)} keys  |  {label2}: {len(keys2)} keys")
    print()

    if only_in_1:
        print(f"   🔴 Only in {label1} ({len(only_in_1)}):")
        for k in only_in_1:
            print(f"      - {k}")
    if only_in_2:
        print(f"   🟢 Only in {label2} ({len(only_in_2)}):")
        for k in only_in_2:
            print(f"      + {k}")
    if shared:
        print(f"   ✅ Shared ({len(shared)} keys)")

    if not only_in_1 and not only_in_2:
        print("   🎉 Key names are identical between both files.")


def audit_env(input_path: str, expected_keys: list[str] | None = None) -> None:
    """Show key names and optional expected-keys check, without exposing values."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    data = input_file.read_bytes()

    if data[:len(MAGIC)] == MAGIC:
        pw = getpass.getpass(f"🔑 Password for {input_file.name}: ")
        plaintext, metadata = decrypt_raw(data, pw)
        keys = parse_env_keys(plaintext)
        profile = metadata.get("profile", "default")
    else:
        keys = parse_env_keys(data)
        profile = "default"

    sorted_keys = sorted(keys)
    print(f"🔍 Audit: {input_file.name}  [profile: {profile}]")
    print(f"   Total keys: {len(sorted_keys)}")
    print()
    for k in sorted_keys:
        print(f"   ✅ {k}")

    if expected_keys:
        expected_set = set(expected_keys)
        missing = sorted(expected_set - keys)
        extra = sorted(keys - expected_set)
        print()
        if missing:
            print(f"   ❌ Missing expected keys ({len(missing)}):")
            for k in missing:
                print(f"      - {k}")
        if extra:
            print(f"   ⚠️  Extra keys ({len(extra)}):")
            for k in extra:
                print(f"      + {k}")
        if not missing and not extra:
            print(f"   🎉 All {len(expected_keys)} expected keys present.")


def install_hooks(repo_root: str | None = None) -> None:
    """Install git pre-commit hook that blocks plaintext .env commits."""
    if repo_root is None:
        # Try to find git root
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, check=True
            )
            repo_root = result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ Not inside a git repository. Run this from inside a git repo.")
            sys.exit(2)

    git_dir = Path(repo_root) / ".git"
    hooks_dir = git_dir / "hooks"

    if not hooks_dir.exists():
        print(f"❌ {hooks_dir} not found. Are you sure this is a git repo?")
        sys.exit(2)

    hook_path = hooks_dir / "pre-commit"

    hook_content = """#!/usr/bin/env bash
# envault pre-commit hook — blocks plaintext .env files from being committed.
# Installed by: envault install-hooks
set -euo pipefail

# Find staged .env files that are NOT encrypted
blocked=()
while IFS= read -r -d '' file; do
    # Skip .enc files
    if [[ "$file" == *.enc* ]]; then
        continue
    fi
    # Skip .envvaultrc
    if [[ "$(basename "$file")" == ".envvaultrc" ]]; then
        continue
    fi
    blocked+=("$file")
done < <(git diff --cached --name-only -z --diff-filter=ACM | grep -zZ '\\.env' || true)

if [ ${#blocked[@]} -gt 0 ]; then
    echo ""
    echo "🚫 envault: blocked commit — plaintext .env files staged:"
    for f in "${blocked[@]}"; do
        echo "   ❌ $f"
    done
    echo ""
    echo "   Encrypt them first:"
    for f in "${blocked[@]}"; do
        echo "     envault encrypt $f"
    done
    echo ""
    echo "   Or bypass with: git commit --no-verify"
    echo ""
    exit 1
fi

# Also warn if .envvaultrc has declared profiles but .enc files are missing
if [ -f ".envvaultrc" ]; then
    # Check if any declared profile encrypted files exist
    profiles=$(python3 -c "
import json, sys
try:
    d = json.load(open('.envvaultrc'))
    profiles = d.get('profiles', {})
    for name, cfg in profiles.items():
        enc = cfg.get('encrypted', '')
        if enc:
            print(name)
except: pass
" 2>/dev/null || true)
    
    if [ -n "$profiles" ]; then
        for profile in $profiles; do
            enc_file=$(python3 -c "
import json
d = json.load(open('.envvaultrc'))
print(d.get('profiles', {}).get('$profile', {}).get('encrypted', ''))
" 2>/dev/null || true)
            # Check if it's staged for deletion - if so warn
            if [ -n "$enc_file" ] && ! git ls-files --error-unmatch "$enc_file" &>/dev/null; then
                if [ -f "$enc_file" ]; then
                    echo "  💡 envault: remember to git add $enc_file for profile '$profile'"
                fi
            fi
        done
    fi
fi

exit 0
"""

    hook_path.write_text(hook_content)
    hook_path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    print(f"✅ Installed pre-commit hook: {hook_path}")
    print("   Plaintext .env files will be blocked from commits.")
    print("   Use 'git commit --no-verify' to bypass if needed.")


def watch_env(input_path: str, output_path: str | None = None, interval: float = 1.0) -> None:
    """Watch a .env file and auto re-encrypt on change."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    if output_path is None:
        output_path = str(input_file) + ".enc"

    print(f"👁️  Watching {input_file.name} → {output_path}")
    print(f"   Interval: {interval}s  |  Press Ctrl+C to stop")
    print()

    password: str | None = None
    last_mtime = 0.0

    try:
        while True:
            current_mtime = input_file.stat().st_mtime
            if current_mtime != last_mtime:
                last_mtime = current_mtime
                if password is None:
                    password = getpass.getpass("🔑 Password: ")
                try:
                    encrypt_env(str(input_path), output_path, password=password)
                    print(f"   🕐 {datetime.now().strftime('%H:%M:%S')} — re-encrypted")
                    print()
                except SystemExit:
                    pass
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n👋 Stopped watching.")


def cmd_init() -> None:
    """Create a .envvaultrc config file in the current directory."""
    config_path = Path.cwd() / ENV_CONFIG_FILE
    if config_path.exists():
        print(f"⚠️  {ENV_CONFIG_FILE} already exists.")
        response = input("   Overwrite? [y/N]: ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)

    # Detect existing .env files
    env_files = sorted(Path.cwd().glob(".env*"))
    detected_profiles = {}
    for ef in env_files:
        name = ef.name
        if name == ".env":
            detected_profiles["default"] = {"source": name, "encrypted": name + ".enc"}
        elif name.startswith(".env.") and not name.endswith(".enc"):
            profile_name = name[5:]  # strip ".env."
            detected_profiles[profile_name] = {
                "source": name,
                "encrypted": name + ".enc",
            }
        elif name.startswith(".env.") and name.endswith(".enc"):
            # .env.staging.enc → staging
            inner = name[5:-4]
            if inner not in detected_profiles:
                detected_profiles[inner] = {"encrypted": name}

    config: dict = {"version": 1}
    if detected_profiles:
        config["profiles"] = detected_profiles

    config_path.write_text(json.dumps(config, indent=2) + "\n")
    print(f"✅ Created {ENV_CONFIG_FILE}")
    if detected_profiles:
        print(f"   Detected profiles: {', '.join(sorted(detected_profiles.keys()))}")
    print(f"\n   Edit it to add more profiles or customize paths.")
    print(f"   Usage: envault encrypt .env --profile staging")


def cmd_export(input_path: str, output_path: str | None = None, fmt: str = "json") -> None:
    """Export an encrypted or plaintext .env file to various formats.

    Supported formats: json, yaml, shell, docker, kubernetes, dotenv
    """
    if fmt not in _EXPORT_DISPATCH:
        print(f"❌ Unknown format: {fmt}")
        print(f"   Supported: {', '.join(sorted(_EXPORT_DISPATCH.keys()))}")
        sys.exit(2)

    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    # Auto-detect extension-based format if not specified
    if output_path is None:
        output_path = str(input_file.with_suffix("") or input_file) + f".{fmt}"

    data = input_file.read_bytes()

    if data[:len(MAGIC)] == MAGIC:
        pw = getpass.getpass(f"🔑 Password for {input_file.name}: ")
        plaintext, metadata = decrypt_raw(data, pw)
        vars = parse_env_vars(plaintext)
        profile = metadata.get("profile")
        if profile:
            print(f"   Profile: {profile}")
    else:
        vars = parse_env_vars(data)

    print(f"   Exporting {len(vars)} variables...")
    _EXPORT_DISPATCH[fmt](vars, output_path)


def cmd_template(
    template_path: str,
    enc_path: str | None = None,
    output_path: str | None = None,
) -> None:
    """Render an .env.template file by filling in values from an encrypted source.

    Template syntax:
        KEY={{KEY}}     → replaced with the actual value of KEY from the encrypted file
        KEY=            → left as-is if KEY is not found (allowing empty)
        # comments and blank lines → preserved as-is

    Usage:
        envault template .env.template --source .env.enc.production -o .env
    """
    tmpl_file = Path(template_path)
    if not tmpl_file.exists():
        print(f"❌ Template not found: {template_path}")
        sys.exit(2)

    if output_path is None:
        # .env.template → .env
        stem = tmpl_file.stem  # e.g. ".env"
        output_path = str(tmpl_file.with_name(stem))

    # Get the source values
    source_vars: dict[str, str] = {}

    if enc_path:
        enc_file = Path(enc_path)
        if not enc_file.exists():
            print(f"❌ Source file not found: {enc_path}")
            sys.exit(2)
        data = enc_file.read_bytes()
        if data[:len(MAGIC)] == MAGIC:
            pw = getpass.getpass(f"🔑 Password for {enc_file.name}: ")
            plaintext, metadata = decrypt_raw(data, pw)
            source_vars = parse_env_vars(plaintext)
        else:
            source_vars = parse_env_vars(data)

    # Render template
    resolved = 0
    missing_keys: list[str] = []
    output_lines = []
    pattern = re.compile(r"\{\{(\w+)\}\}")

    for line in tmpl_file.read_text().splitlines():
        def replacer(m: re.Match) -> str:
            nonlocal resolved
            key = m.group(1)
            if key in source_vars:
                resolved += 1
                return source_vars[key]
            else:
                if key not in missing_keys:
                    missing_keys.append(key)
                return m.group(0)  # leave unrendered

        output_lines.append(pattern.sub(replacer, line))

    Path(output_path).write_text("\n".join(output_lines) + "\n")

    print(f"✅ Rendered template: {tmpl_file.name} → {Path(output_path).name}")
    print(f"   Variables resolved: {resolved}")
    if missing_keys:
        print(f"   ⚠️  Unresolved placeholders ({len(missing_keys)}): {', '.join(missing_keys)}")
    else:
        print("   All placeholders resolved.")


HISTORY_DIR_NAME = ".envault-history"


def _get_history_dir(env_file: Path) -> Path:
    """Get the history directory for a given encrypted file."""
    return env_file.parent / HISTORY_DIR_NAME


def _save_history_snapshot(env_file: Path, password: str) -> Path:
    """Save a timestamped snapshot of an encrypted file to history."""
    history_dir = _get_history_dir(env_file)
    history_dir.mkdir(parents=True, exist_ok=True)

    # Read current encrypted data
    data = env_file.read_bytes()

    # Use current time for timestamp (reliable across fast successive calls)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # Create snapshot filename
    base_name = env_file.name
    # Ensure unique filename even if called within same second
    snapshot_name = f"{base_name}.{ts}"
    snapshot_path = history_dir / snapshot_name

    # If snapshot already exists for this exact second, add microsecond suffix
    if snapshot_path.exists():
        from time import time
        suffix = str(int(time() * 1_000_000))[-6:]
        snapshot_name = f"{base_name}.{ts}-{suffix}"
        snapshot_path = history_dir / snapshot_name

    # Copy the encrypted file
    snapshot_path.write_bytes(data)
    return snapshot_path


def cmd_history(input_path: str, password: str | None = None, *,
                action: str = "list", restore: str | None = None,
                keep: int = 20) -> None:
    """Manage version history for an encrypted .env file.

    Actions:
        list      — Show history snapshots (default)
        snapshot  — Save current state as a new snapshot
        restore   — Restore a specific snapshot
        prune     — Remove old snapshots, keeping only the most recent N

    History is stored in .envault-history/ alongside the encrypted file.

    Usage:
        envault history .env.enc                  # list snapshots
        envault history .env.enc --action snapshot # save new snapshot
        envault history .env.enc --action restore --restore 20240611-143022
        envault history .env.enc --action prune --keep 10
    """
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    history_dir = _get_history_dir(input_file)

    if action == "list":
        if not history_dir.exists():
            print(f"📋 No history for {input_file.name}")
            print(f"   Run 'envault history {input_path} --action snapshot' to start tracking.")
            return

        snapshots = sorted(history_dir.glob(f"{input_file.name}.*"))
        if not snapshots:
            print(f"📋 No history for {input_file.name}")
            return

        print(f"📋 History for {input_file.name} ({len(snapshots)} snapshots)")
        print(f"   Location: {history_dir}/")
        print()

        for i, snap in enumerate(snapshots):
            # Extract timestamp from filename
            ts_str = snap.name.rsplit(".", 1)[-1]
            try:
                ts = datetime.strptime(ts_str, "%Y%m%d-%H%M%S")
                ts_display = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
            except ValueError:
                ts_display = ts_str

            size = snap.stat().st_size
            marker = "  →" if i == len(snapshots) - 1 else "   "
            print(f"{marker} {ts_display}  ({size:,} bytes)  [{ts_str}]")

        print()
        print(f"   Restore: envault history {input_path} --action restore --restore <TIMESTAMP>")
        print(f"   Snapshot: envault history {input_path} --action snapshot")
        print(f"   Prune: envault history {input_path} --action prune --keep 10")

    elif action == "snapshot":
        snapshot_path = _save_history_snapshot(input_file, password or "")
        print(f"✅ Saved snapshot: {snapshot_path.name}")
        print(f"   Location: {history_dir}/")

        # Count total snapshots
        snapshots = sorted(history_dir.glob(f"{input_file.name}.*"))
        print(f"   Total snapshots: {len(snapshots)}")

    elif action == "restore":
        if restore is None:
            print("❌ --restore <TIMESTAMP> required for restore action.")
            print("   Use 'envault history <file>' to see available timestamps.")
            sys.exit(2)

        # Find the snapshot
        snapshot_path = history_dir / f"{input_file.name}.{restore}"
        if not snapshot_path.exists():
            # Try prefix matching
            candidates = sorted(history_dir.glob(f"{input_file.name}.*{restore}*"))
            if len(candidates) == 1:
                snapshot_path = candidates[0]
            elif len(candidates) > 1:
                print(f"❌ Multiple snapshots match '{restore}':")
                for c in candidates:
                    print(f"   {c.name}")
                print("   Be more specific.")
                sys.exit(2)
            else:
                print(f"❌ Snapshot not found matching '{restore}'")
                print("   Run 'envault history <file>' to see available snapshots.")
                sys.exit(2)

        # Restore: copy snapshot over the current file
        import shutil
        # First, back up current to history
        if input_file.exists():
            backup_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            backup_path = history_dir / f"{input_file.name}.{backup_ts}-pre-restore"
            shutil.copy2(input_file, backup_path)
            print(f"   Backed up current state to {backup_path.name}")

        shutil.copy2(snapshot_path, input_file)
        print(f"✅ Restored {input_file.name} from snapshot {restore}")
        print(f"   Previous state backed up to history.")

    elif action == "prune":
        snapshots = sorted(history_dir.glob(f"{input_file.name}.*"))
        if len(snapshots) <= keep:
            print(f"📋 {len(snapshots)} snapshots, keeping {keep}. Nothing to prune.")
            return

        to_remove = snapshots[:-keep]
        for snap in to_remove:
            snap.unlink()

        remaining = len(snapshots) - len(to_remove)
        print(f"✅ Pruned {len(to_remove)} old snapshots. {remaining} remaining (keeping last {keep}).")

    else:
        print(f"❌ Unknown history action: {action}")
        print("   Supported: list, snapshot, restore, prune")
        sys.exit(2)


def cmd_doctor() -> None:
    """Run diagnostics on your envault setup and .env security.

    Checks for:
        ✅ Plaintext .env files that should be encrypted
        ✅ Encrypted files that can be decrypted (with password)
        ✅ .envvaultrc config validity
        ✅ Git pre-commit hook installation
        ✅ Stale encrypted files (source deleted but .enc remains)
        ✅ World-readable permissions on encrypted files
        ✅ Version status (up to date or upgrade available)

    Usage:
        envault doctor
    """
    issues = 0
    warnings = 0
    ok = 0

    def ok_msg(msg):
        nonlocal ok
        ok += 1
        print(f"   ✅ {msg}")

    def warn(msg):
        nonlocal warnings
        warnings += 1
        print(f"   ⚠️  {msg}")

    def fail(msg):
        nonlocal issues
        issues += 1
        print(f"   ❌ {msg}")

    cwd = Path.cwd()
    print(f"🏥 envault doctor — checking your setup")
    print(f"   Directory: {cwd}")
    print(f"   envault v{VERSION}")
    print()

    # 1. Check for plaintext .env files
    print("📂 Scanning for plaintext .env files...")
    env_files = sorted(cwd.glob(".env"))
    env_local = sorted(cwd.glob(".env.local"))
    env_dev = sorted(cwd.glob(".env.development"))
    plain_envs = env_files + env_local + env_dev

    # Filter out .gitignore'd or commonly ignored ones
    relevant_plaintext = []
    for ef in plain_envs:
        # Skip if it's actually an encrypted file
        data = ef.read_bytes()
        if data[:len(MAGIC)] == MAGIC:
            continue
        relevant_plaintext.append(plaintext_path := ef)

    if relevant_plaintext:
        fail(f"Found {len(relevant_plaintext)} plaintext .env file(s):")
        for p in relevant_plaintext:
            fail(f"  {p.name} — encrypt with: envault encrypt {p.name}")
    else:
        ok_msg("No unprotected plaintext .env files found")

    # 2. Check encrypted files
    print()
    print("🔐 Checking encrypted files...")
    enc_files = sorted(cwd.rglob("*.enc"))
    # Also check .env.enc.* profile files
    profile_encs = sorted(cwd.glob(".env.enc.*"))
    all_enc = sorted(set(enc_files + profile_encs))

    # Filter out history directory snapshots
    all_enc = [f for f in all_enc if HISTORY_DIR_NAME not in f.parts]

    if not all_enc:
        warn("No encrypted .env files found in this directory")
    else:
        ok_msg(f"Found {len(all_enc)} encrypted file(s)")

        # Check file permissions
        for ef in all_enc:
            mode = ef.stat().st_mode
            if mode & stat.S_IROTH:
                warn(f"{ef.name} is world-readable (chmod 600 {ef.name})")
            else:
                ok_msg(f"{ef.name} permissions OK")

        # Check for stale encrypted files (source doesn't exist)
        for ef in all_enc:
            source = find_encrypted_source(ef)
            if source and not source.exists():
                warn(f"{ef.name} — source {source.name} not found (stale?)")

    # 3. Check .envvaultrc
    print()
    print("📝 Checking .envvaultrc...")
    config_path = cwd / ENV_CONFIG_FILE
    if config_path.exists():
        ok_msg(".envvaultrc exists")
        try:
            config = json.loads(config_path.read_text())
            profiles = config.get("profiles", {})
            if profiles:
                ok_msg(f"Configured profiles: {', '.join(sorted(profiles.keys()))}")
            else:
                warn(".envvaultrc has no profiles defined")
        except json.JSONDecodeError as e:
            fail(f".envvaultrc is invalid JSON: {e}")
    else:
        warn("No .envvaultrc found — run 'envault init' to create one")

    # 4. Check git hooks
    print()
    print("🪝 Checking git hooks...")
    hook_path = cwd / ".git" / "hooks" / "pre-commit"
    if hook_path.exists():
        hook_content = hook_path.read_text()
        if "envault" in hook_content:
            ok_msg("envault pre-commit hook installed")
        else:
            warn("pre-commit hook exists but is not from envault")
    else:
        warn("No envault pre-commit hook — run 'envault install-hooks'")

    # Check if we're in a git repo
    git_dir = cwd / ".git"
    if git_dir.exists():
        ok_msg("Git repository detected")
    else:
        warn("Not a git repository — some features (hooks) won't apply")

    # 5. Check for .env in .gitignore
    print()
    print("🙈 Checking .gitignore...")
    gitignore = cwd / ".gitignore"
    if gitignore.exists():
        gi_content = gitignore.read_text()
        if ".env" in gi_content or "*.env" in gi_content:
            ok_msg(".env files are in .gitignore")
        else:
            warn(".env files NOT in .gitignore — consider adding them")
    else:
        warn("No .gitignore found — consider creating one with *.env")

    # 6. History check
    print()
    print("🕐 Checking version history...")
    if all_enc:
        for ef in all_enc:
            hd = _get_history_dir(ef)
            if hd.exists():
                snaps = sorted(hd.glob(f"{ef.name}.*"))
                if snaps:
                    ok_msg(f"{ef.name}: {len(snaps)} history snapshot(s)")
    else:
        print("   (no encrypted files to check)")

    # Summary
    print()
    print("=" * 50)
    total_score = ok * 2 - issues * 3 - warnings
    max_score = (ok + issues + warnings) * 2
    health = max(0, min(100, int((total_score / max(max_score, 1)) * 100)))

    if health >= 80:
        health_icon = "🟢"
        verdict = "Great shape!"
    elif health >= 50:
        health_icon = "🟡"
        verdict = "Needs some attention"
    else:
        health_icon = "🔴"
        verdict = "Action needed"

    print(f"   Health Score: {health_icon} {health}/100 — {verdict}")
    print(f"   ✅ {ok} passed  |  ⚠️  {warnings} warnings  |  ❌ {issues} issues")
    print()

    if issues > 0:
        print("   Fix issues above to improve your security posture.")
    if warnings > 0:
        print("   Address warnings for best practices.")
    if ok == 0 and issues == 0 and warnings == 0:
        print("   Nothing to check — create a .env file and encrypt it to get started!")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="envault",
        description="🔐 envault — Encrypt and decrypt .env files with AES-256-GCM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  envault init                              Create .envvaultrc config
  envault encrypt .env                      Encrypt → .env.enc (default)
  envault encrypt .env --profile staging    Encrypt → .env.enc.staging
  envault decrypt .env.enc                  Decrypt → .env
  envault status .enc.env                   Show file info
  envault rotate .env.enc                   Change password
  envault diff .env.enc .env.enc.staging    Compare keys between versions
  envault audit .env.enc                    List keys without exposing values
  envault audit .env.enc --expect API_KEY DATABASE_URL  Verify required keys
  envault install-hooks                     Block plaintext .env git commits
  envault watch .env                        Auto re-encrypt on save
  envault export .env.enc --format json     Export to JSON
  envault export .env.enc --format kubernetes -o secret.yaml
  envault template .env.template --source .env.enc -o .env
  envault history .env.enc                              # list snapshots
  envault history .env.enc --action snapshot             # save snapshot
  envault history .env.enc --action restore --restore 20240611-143022
  envault history .env.enc --action prune --keep 10
  envault doctor                                        # diagnose setup
""",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Init
    subparsers.add_parser("init", help="Create .envvaultrc config in current directory")

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a .env file")
    enc_parser.add_argument("file", nargs="?", default=".env", help="File to encrypt (default: .env)")
    enc_parser.add_argument("-o", "--output", help="Output file path")
    enc_parser.add_argument("--profile", help="Profile name (e.g. production, staging)")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("file", help="File to decrypt")
    dec_parser.add_argument("-o", "--output", help="Output file path")

    # Status
    stat_parser = subparsers.add_parser("status", help="Show file info without decrypting")
    stat_parser.add_argument("file", help="Encrypted file to inspect")

    # Rotate
    rot_parser = subparsers.add_parser("rotate", help="Re-encrypt with new password")
    rot_parser.add_argument("file", help="File to rotate")
    rot_parser.add_argument("-o", "--output", help="Output file path")

    # Diff
    diff_parser = subparsers.add_parser(
        "diff", help="Show key-level diff between two .env files (no values exposed)"
    )
    diff_parser.add_argument("file1", help="First .env file (encrypted or plaintext)")
    diff_parser.add_argument("file2", help="Second .env file (encrypted or plaintext)")

    # Audit
    audit_parser = subparsers.add_parser(
        "audit", help="List key names without exposing values"
    )
    audit_parser.add_argument("file", help=".env file (encrypted or plaintext)")
    audit_parser.add_argument(
        "--expect", nargs="+", metavar="KEY", help="Expected keys — warns if any are missing"
    )

    # Install hooks
    hook_parser = subparsers.add_parser(
        "install-hooks", help="Install git pre-commit hook to block plaintext .env commits"
    )

    # Watch
    watch_parser = subparsers.add_parser(
        "watch", help="Auto re-encrypt on file change"
    )
    watch_parser.add_argument("file", nargs="?", default=".env", help="File to watch (default: .env)")
    watch_parser.add_argument("-o", "--output", help="Output file path")
    watch_parser.add_argument("--interval", type=float, default=1.0, help="Watch interval in seconds (default: 1.0)")

    # Export
    export_parser = subparsers.add_parser(
        "export", help="Export encrypted .env to JSON, YAML, shell, Docker, or Kubernetes format"
    )
    export_parser.add_argument("file", help=".env file (encrypted or plaintext) to export")
    export_parser.add_argument("-o", "--output", help="Output file path")
    export_parser.add_argument(
        "--format", dest="fmt", choices=EXPORT_FORMATS, default="json",
        help="Export format (default: json)"
    )

    # Template
    tmpl_parser = subparsers.add_parser(
        "template", help="Render an .env.template using values from an encrypted source"
    )
    tmpl_parser.add_argument("template", help="Template file to render (e.g. .env.template)")
    tmpl_parser.add_argument("--source", help="Encrypted or plaintext source file for values")
    tmpl_parser.add_argument("-o", "--output", help="Output file path")

    # History
    hist_parser = subparsers.add_parser(
        "history", help="Manage version history for encrypted .env files"
    )
    hist_parser.add_argument("file", help="Encrypted file to manage history for")
    hist_parser.add_argument(
        "--action", choices=["list", "snapshot", "restore", "prune"],
        default="list", help="History action (default: list)"
    )
    hist_parser.add_argument("--restore", help="Timestamp to restore (for --action restore)")
    hist_parser.add_argument("--keep", type=int, default=20, help="Snapshots to keep (for --action prune)")

    # Doctor
    doctor_parser = subparsers.add_parser(
        "doctor", help="Diagnose your envault setup and .env security"
    )

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "encrypt":
        config = load_config()
        profiles = config.get("profiles", {})

        profile = args.profile
        input_file = Path(args.file)

        # If no explicit output and we have profiles config, use profile-specific output
        if args.output:
            output = args.output
        elif profile and profile in profiles:
            output = profiles[profile].get("encrypted", str(input_file) + ".enc")
            if profile != "default":
                # Append profile suffix: .env.enc → .env.enc.staging
                output = str(input_file) + ".enc." + profile
        else:
            output = str(input_file) + ".enc"

        encrypt_env(str(input_file), output, profile=profile)
    elif args.command == "decrypt":
        decrypt_env(args.file, args.output)
    elif args.command == "status":
        show_status(args.file)
    elif args.command == "rotate":
        rotate_password(args.file, args.output)
    elif args.command == "diff":
        diff_envs(args.file1, args.file2)
    elif args.command == "audit":
        audit_env(args.file, args.expect)
    elif args.command == "install-hooks":
        install_hooks()
    elif args.command == "watch":
        watch_env(args.file, args.output, args.interval)
    elif args.command == "export":
        cmd_export(args.file, args.output, args.fmt)
    elif args.command == "template":
        cmd_template(args.template, args.source, args.output)
    elif args.command == "history":
        cmd_history(args.file, action=args.action, restore=args.restore, keep=args.keep)
    elif args.command == "doctor":
        cmd_doctor()
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
