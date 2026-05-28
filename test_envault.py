#!/usr/bin/env python3
"""Comprehensive test suite for envault."""

import envault
import getpass
import json
import os
import sys
import io
import tempfile
import subprocess
from pathlib import Path

PW = 'testpass123'
passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
    except Exception as e:
        failed += 1
        print(f"  FAIL: {name}: {e}")


print("=== envault test suite ===\n")

# Setup
lines = [
    "DATABASE_URL=postgresql://user:***@localhost:5432/mydb",
    "API_KEY=***",
    "REDIS_URL=redis://localhost:6379",
]
test_env_content = "\n".join(lines) + "\n"
test_staging_content = test_env_content + "NEW_FEATURE_FLAG=true\n"

Path("test.env").write_text(test_env_content)
Path("test_staging.env").write_text(test_staging_content)

# 1. Encrypt default
print("1. Encrypt default profile")


def t1():
    getpass.getpass = lambda prompt="": PW
    envault.encrypt_env("test.env", "t1.enc")
    assert Path("t1.enc").exists()
    print("   OK")


test("encrypt_default", t1)

# 2. Encrypt with profile
print("2. Encrypt with profile")


def t2():
    getpass.getpass = lambda prompt="": PW
    envault.encrypt_env("test.env", "t2.enc", profile="production")
    assert Path("t2.enc").exists()
    print("   OK")


test("encrypt_profile", t2)

# 3. Decrypt + content match
print("3. Decrypt + content match")


def t3():
    getpass.getpass = lambda prompt="": PW
    envault.decrypt_env("t1.enc", "t3_dec.env")
    assert Path("t3_dec.env").read_text() == Path("test.env").read_text()
    print("   OK")


test("decrypt", t3)

# 4. Decrypt shows profile tag
print("4. Decrypt shows profile tag")


def t4():
    getpass.getpass = lambda prompt="": PW
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.decrypt_env("t2.enc", "t4_dec.env")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "production" in out, f"Profile tag missing: {out}"
    print("   OK")


test("decrypt_profile_tag", t4)

# 5. Wrong password rejected
print("5. Wrong password rejected")


def t5():
    original = getpass.getpass
    getpass.getpass = lambda prompt="": "wrongpw"
    try:
        envault.decrypt_env("t1.enc", "should_not_exist.env")
        raise AssertionError("Should have exited")
    except SystemExit as e:
        assert e.code == 1
    finally:
        getpass.getpass = original
    assert not Path("should_not_exist.env").exists()
    print("   OK")


test("wrong_password", t5)

# 6. Diff key names
print("6. Diff key names")


def t6():
    getpass.getpass = lambda prompt="": PW
    envault.encrypt_env("test.env", "diff_a.enc")
    envault.encrypt_env("test_staging.env", "diff_b.enc")
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.diff_envs("diff_a.enc", "diff_b.enc")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "NEW_FEATURE_FLAG" in out, f"Missing key in diff: {out}"
    assert "Shared" in out
    print(f"   OK\n{out}")


test("diff", t6)

# 7. Audit values hidden
print("7. Audit values hidden")


def t7():
    getpass.getpass = lambda prompt="": PW
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.audit_env("diff_a.enc")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "DATABASE_URL" in out
    assert "postgresql://" not in out, "Value leaked!"
    assert "sk_test" not in out, "Value leaked!"
    print("   OK")


test("audit_hidden", t7)

# 8. Audit expected keys
print("8. Audit expected keys")


def t8():
    getpass.getpass = lambda prompt="": PW
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.audit_env(
            "diff_a.enc", expected_keys=["DATABASE_URL", "MISSING_KEY"]
        )
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "MISSING_KEY" in out and "Missing" in out
    print("   OK")


test("audit_expect", t8)

# 9. Status command
print("9. Status command")


def t9():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.show_status("t1.enc")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "AES-256-GCM" in out and "Scrypt" in out
    print("   OK")


test("status", t9)

# 10. Init config
print("10. Init config")


def t10():
    p = Path(".envvaultrc")
    if p.exists():
        p.unlink()
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_init()
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert p.exists()
    cfg = json.loads(p.read_text())
    assert "version" in cfg
    print("   OK")


test("init", t10)

# 11. Git hook install
print("11. Git hook install")


def t11():
    tmpdir = tempfile.mkdtemp()
    subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True)
    envault.install_hooks(repo_root=tmpdir)
    hp = Path(tmpdir) / ".git" / "hooks" / "pre-commit"
    assert hp.exists(), "Hook not created"
    assert "envault" in hp.read_text()
    assert os.access(str(hp), os.X_OK), "Hook not executable"
    print("   OK")


test("hooks", t11)

# 12. Config load
print("12. Config load")


def t12():
    cfg = envault.load_config()
    assert "version" in cfg
    print("   OK")


test("config", t12)

# 13. Rotate password
print("13. Rotate password")


def t13():
    getpass.getpass = lambda prompt="": PW
    envault.encrypt_env("test.env", "rotate_test.enc")
    calls = iter([PW, "newpass456", "newpass456"])
    getpass.getpass = lambda prompt="": next(calls)
    envault.rotate_password("rotate_test.enc")
    getpass.getpass = lambda prompt="": "newpass456"
    envault.decrypt_env("rotate_test.enc", "rotated_dec.env")
    assert Path("rotated_dec.env").read_text() == Path("test.env").read_text()
    print("   OK")


test("rotate", t13)

# Cleanup
for f in [
    "test.env", "test_staging.env", "t1.enc", "t2.enc",
    "t3_dec.env", "t4_dec.env", "diff_a.enc", "diff_b.enc",
    "rotate_test.enc", "rotated_dec.env",
    ".envvaultrc", ".envvaultrc.json", "should_not_exist.env",
]:
    Path(f).unlink(missing_ok=True)

print(f"\n=== Results: {passed} passed, {failed} failed ===")
if failed:
    sys.exit(1)
