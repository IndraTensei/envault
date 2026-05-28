#!/usr/bin/env python3
"""
envault — Encrypt and decrypt .env files with AES-256-GCM.

Usage:
    envault encrypt [.env] [-o encrypted.env]
    envault decrypt [encrypted.env] [-o .env]
    envault status [.env]
    envault rotate [.env] — re-encrypt with new password
"""

import argparse
import getpass
import hashlib
import json
import os
import struct
import sys
import base64
from pathlib import Path
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("❌ Missing dependency: cryptography")
    print("   pip install cryptography")
    sys.exit(1)

VERSION = "1.0.0"
MAGIC = b"ENVA"
NONCE_SIZE = 12
SALT_SIZE = 16
KDF_N = 2**17  # 131072
KDF_R = 8
KDF_P = 1
CHECKSUM_KEY = b"envault-integrity-check"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
    )
    return kdf.derive(password.encode("utf-8"))


def compute_checksum(plaintext: bytes) -> str:
    """Compute a SHA-256 checksum of plaintext for integrity verification."""
    h = hashlib.sha256()
    h.update(CHECKSUM_KEY)
    h.update(plaintext)
    return h.hexdigest()


def encrypt_env(input_path: str, output_path: str, password: str | None = None) -> None:
    """Encrypt a .env file and write the result."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    plaintext = input_file.read_bytes()
    checksum = compute_checksum(plaintext)

    if password is None:
        pw1 = getpass.getpass("🔑 Enter encryption password: ")
        pw2 = getpass.getpass("🔑 Confirm password: ")
        if pw1 != pw2:
            print("❌ Passwords don't match.")
            sys.exit(1)
        password = pw1

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    # Build metadata
    metadata = {
        "version": VERSION,
        "checksum": checksum,
        "filename": input_file.name,
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
    }
    metadata_bytes = json.dumps(metadata).encode("utf-8")
    metadata_len = struct.pack(">I", len(metadata_bytes))

    # Encrypt: metadata_len + metadata + plaintext
    associated_data = MAGIC + salt + nonce
    ciphertext = AESGCM(key).encrypt(
        nonce, metadata_len + metadata_bytes + plaintext, associated_data
    )

    # Write: MAGIC + salt + nonce + ciphertext
    output_file = Path(output_path)
    output_file.write_bytes(MAGIC + salt + nonce + ciphertext)

    size_orig = len(plaintext)
    size_enc = output_file.stat().st_size
    print(f"✅ Encrypted {input_file.name} → {output_file.name}")
    print(f"   Original: {size_orig:,} bytes  |  Encrypted: {size_enc:,} bytes")
    print(f"   Checksum: {checksum[:16]}...")


def decrypt_env(input_path: str, output_path: str | None = None, password: str | None = None) -> None:
    """Decrypt an envault-encrypted file."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    data = input_file.read_bytes()

    if len(data) < len(MAGIC) + SALT_SIZE + NONCE_SIZE:
        print("❌ File is too small to be a valid envault file.")
        sys.exit(1)

    # Parse header
    pos = 0
    magic = data[pos : pos + len(MAGIC)]
    if magic != MAGIC:
        print("❌ Not a valid envault file (bad magic bytes). Did you try to decrypt a regular .env file?")
        sys.exit(1)
    pos += len(MAGIC)

    salt = data[pos : pos + SALT_SIZE]
    pos += SALT_SIZE
    nonce = data[pos : pos + NONCE_SIZE]
    pos += NONCE_SIZE
    ciphertext = data[pos:]

    if password is None:
        password = getpass.getpass("🔑 Enter decryption password: ")

    key = derive_key(password, salt)
    associated_data = MAGIC + salt + nonce

    try:
        plaintext_with_meta = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except Exception:
        print("❌ Decryption failed. Wrong password or corrupted file.")
        sys.exit(1)

    # Parse metadata
    meta_len = struct.unpack(">I", plaintext_with_meta[:4])[0]
    metadata = json.loads(plaintext_with_meta[4 : 4 + meta_len])
    plaintext = plaintext_with_meta[4 + meta_len :]

    # Verify checksum
    expected_checksum = metadata.get("checksum", "")
    actual_checksum = compute_checksum(plaintext)
    integrity_ok = expected_checksum == actual_checksum

    if not integrity_ok:
        print("⚠️  WARNING: Integrity check failed! File may be corrupted.")

    # Determine output path
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
    print(f"✅ Decrypted {input_file.name} → {output_file.name}")
    print(f"   Size: {len(plaintext):,} bytes")
    print(f"   Encrypted at: {metadata.get('encrypted_at', 'unknown')}")
    if integrity_ok:
        print("   Integrity: ✅ Verified")
    else:
        print("   Integrity: ❌ FAILED")


def show_status(input_path: str) -> None:
    """Show metadata from an encrypted file without decrypting."""
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"❌ File not found: {input_path}")
        sys.exit(2)

    data = input_file.read_bytes()
    if len(data) < len(MAGIC) + SALT_SIZE + NONCE_SIZE + 4:
        print("❌ File is too small to be a valid envault file.")
        sys.exit(1)

    pos = 0
    magic = data[pos : pos + len(MAGIC)]
    if magic != MAGIC:
        print("❌ Not a valid envault file.")
        sys.exit(1)
    pos += len(MAGIC)

    salt = data[pos : pos + SALT_SIZE]
    nonce = data[pos + SALT_SIZE : pos + SALT_SIZE + NONCE_SIZE]
    ciphertext_size = len(data) - pos - SALT_SIZE - NONCE_SIZE

    # We can't decrypt metadata without the password, but we can show file info
    print(f"📋 File: {input_file.name}")
    print(f"   Format: envault v{VERSION}")
    print(f"   File size: {len(data):,} bytes")
    print(f"   Ciphertext: {ciphertext_size:,} bytes")
    print(f"   KDF: Scrypt (N={KDF_N:,}, r={KDF_R}, p={KDF_P})")
    print(f"   Cipher: AES-256-GCM")
    print(f"   Salt: {base64.b16encode(salt).decode()[:16]}...")
    print(f"   Nonce: {base64.b16encode(nonce).decode()}")

    # Try to extract metadata (it's in the ciphertext, but metadata_len is the first 4 bytes
    # of the decrypted content — we can try with empty password to at least confirm structure)
    try:
        # Attempt decryption with empty password just to show if file is structured right
        # This will fail silently; we just show the basic info
        pass
    except Exception:
        pass

    print(f"\n   Use 'envault decrypt {input_path}' to decrypt.")


def rotate_password(input_path: str, output_path: str | None = None) -> None:
    """Re-encrypt a file with a new password."""
    input_file = Path(input_path)
    if output_path is None:
        output_path = str(input_file)

    print("🔄 Rotating password...")
    print()

    # First decrypt to a temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".env", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        decrypt_env(input_path, tmp_path)
        print()
        print("Now encrypting with new password...")
        print()
        encrypt_env(tmp_path, output_path)
    finally:
        os.unlink(tmp_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="envault",
        description="🔐 envault — Encrypt and decrypt .env files with AES-256-GCM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  envault encrypt .env                    Encrypt .env → .env.enc
  envault encrypt .env -o secrets.env.enc Encrypt .env → secrets.env.enc
  envault decrypt .env.enc                Decrypt .env.enc → .env
  envault decrypt .env.enc -o .env.prod   Decrypt .env.enc → .env.prod
  envault status .env.enc                 Show file info without decrypting
  envault rotate .env.enc                 Change the encryption password
""",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a .env file")
    enc_parser.add_argument("file", nargs="?", default=".env", help="File to encrypt (default: .env)")
    enc_parser.add_argument("-o", "--output", help="Output file path")

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

    args = parser.parse_args()

    if args.command == "encrypt":
        output = args.output or (args.file + ".enc")
        encrypt_env(args.file, output)
    elif args.command == "decrypt":
        decrypt_env(args.file, args.output)
    elif args.command == "status":
        show_status(args.file)
    elif args.command == "rotate":
        rotate_password(args.file, args.output)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
