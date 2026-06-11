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

PW = 'T3st!Pass#Secure9'
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
    new_pw = "N3w!Rot@ted#Key9"
    calls = iter([PW, new_pw, new_pw])
    getpass.getpass = lambda prompt="": next(calls)
    envault.rotate_password("rotate_test.enc")
    getpass.getpass = lambda prompt="": new_pw
    envault.decrypt_env("rotate_test.enc", "rotated_dec.env")
    assert Path("rotated_dec.env").read_text() == Path("test.env").read_text()
    print("   OK")


test("rotate", t13)

# 14. Password strength — weak
print("14. Password strength — weak")


def t14():
    label, score, tips = envault.password_strength("abc")
    assert score < 2, f"Expected weak score, got {score}"
    assert len(tips) > 0, "Expected tips for weak password"
    print("   OK")


test("strength_weak", t14)

# 15. Password strength — strong
print("15. Password strength — strong")


def t15():
    label, score, tips = envault.password_strength("MyS3cur3!P@ssw0rd#2024")
    assert score >= 3, f"Expected strong score, got {score}"
    assert "Excellent" in label or "Strong" in label
    print("   OK")


test("strength_strong", t15)

# 16. Password strength — common password
print("16. Password strength — common password")


def t16():
    label, score, tips = envault.password_strength("password")
    assert score == 0, f"Expected 0 for common password, got {score}"
    assert any("commonly" in t.lower() or "unique" in t.lower() for t in tips)
    print("   OK")


test("strength_common", t16)

# 17. parse_env_vars
print("17. parse_env_vars")


def t17():
    raw = b"KEY1=value1\nKEY2=hello world\n# comment\n\nKEY3='quoted'\n"
    result = envault.parse_env_vars(raw)
    assert result["KEY1"] == "value1"
    assert result["KEY2"] == "hello world"
    assert result["KEY3"] == "quoted"
    assert "# comment" not in result
    print("   OK")


test("parse_env_vars", t17)

# 18. Export JSON
print("18. Export JSON")


def t18():
    getpass.getpass = lambda prompt="": PW
    envault.encrypt_env("test.env", "export_test.enc")
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out.json", "json")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out.json").exists()
    data = json.loads(Path("export_out.json").read_text())
    assert "DATABASE_URL" in data
    assert data["API_KEY"] == "***"
    print("   OK")


test("export_json", t18)

# 19. Export YAML
print("19. Export YAML")


def t19():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out.yaml", "yaml")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out.yaml").exists()
    content = Path("export_out.yaml").read_text()
    assert "DATABASE_URL:" in content
    assert "API_KEY:" in content
    print("   OK")


test("export_yaml", t19)

# 20. Export shell
print("20. Export shell")


def t20():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out.sh", "shell")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out.sh").exists()
    content = Path("export_out.sh").read_text()
    assert 'export DATABASE_URL="' in content
    assert 'export API_KEY="' in content
    print("   OK")


test("export_shell", t20)

# 21. Export Docker
print("21. Export Docker")


def t21():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out_docker.env", "docker")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out_docker.env").exists()
    content = Path("export_out_docker.env").read_text()
    assert "DATABASE_URL=" in content
    assert "export " not in content  # Docker format doesn't use export
    print("   OK")


test("export_docker", t21)

# 22. Export Kubernetes
print("22. Export Kubernetes")


def t22():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out_k8s.yaml", "kubernetes")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out_k8s.yaml").exists()
    content = Path("export_out_k8s.yaml").read_text()
    assert "apiVersion: v1" in content
    assert "kind: Secret" in content
    assert "type: Opaque" in content
    print("   OK")


test("export_kubernetes", t22)

# 23. Export dotenv
print("23. Export dotenv")


def t23():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("export_test.enc", "export_out_dot.env", "dotenv")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("export_out_dot.env").exists()
    content = Path("export_out_dot.env").read_text()
    assert "DATABASE_URL=" in content
    print("   OK")


test("export_dotenv", t23)

# 24. Export from plaintext (no password needed)
print("24. Export from plaintext")


def t24():
    Path("plain_export.env").write_text("FOO=bar\nBAZ=qux\n")
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_export("plain_export.env", "plain_out.json", "json")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    data = json.loads(Path("plain_out.json").read_text())
    assert data["FOO"] == "bar"
    assert data["BAZ"] == "qux"
    print("   OK")


test("export_plaintext", t24)

# 25. Template rendering
print("25. Template rendering")


def t25():
    # Create a template file
    Path("test_template.env").write_text(
        "DATABASE_URL={{DATABASE_URL}}\n"
        "API_KEY={{API_KEY}}\n"
        "REDIS_URL={{REDIS_URL}}\n"
        "LOG_LEVEL=info\n"
        "UNKNOWN={{NONEXISTENT}}\n"
    )
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_template("test_template.env", "export_test.enc", "rendered.env")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert Path("rendered.env").exists()
    content = Path("rendered.env").read_text()
    assert "DATABASE_URL=postgresql://user:***@localhost:5432/mydb" in content
    assert "API_KEY=***" in content
    assert "LOG_LEVEL=info" in content
    assert "{{NONEXISTENT}}" in content  # unresolved stays as-is
    assert "resolved" in out.lower() or "Resolved" in out
    print("   OK")


test("template_render", t25)

# 26. Template rendering from plaintext source
print("26. Template from plaintext source")


def t26():
    Path("plain_source.env").write_text("TPL_KEY=hello\n")
    Path("test_template2.env").write_text("RESULT={{TPL_KEY}}\n")
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_template("test_template2.env", "plain_source.env", "rendered2.env")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    content = Path("rendered2.env").read_text()
    assert "RESULT=hello" in content
    print("   OK")


test("template_plaintext_source", t26)

# 27. Export unknown format error
print("27. Export unknown format error")


def t27():
    try:
        envault.cmd_export("export_test.enc", "out.txt", "xml")
        raise AssertionError("Should have exited")
    except SystemExit as e:
        assert e.code == 2
    print("   OK")


test("export_bad_format", t27)

# 28. Version bump check
print("28. Version bump check")


def t28():
    assert envault.VERSION == "1.3.0", f"Expected 1.3.0, got {envault.VERSION}"
    print("   OK")


test("version_bump", t28)


# 29. History — snapshot
print("29. History — snapshot")

def t29():
    envault.encrypt_env("test.env", "hist_test.enc")
    # Save a snapshot
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_history("hist_test.enc", action="snapshot")
    finally:
        sys.stdout = old
    # Check history dir exists
    hist_dir = Path(".envault-history")
    assert hist_dir.exists(), "History directory not created"
    snaps = sorted(hist_dir.glob("hist_test.enc.*"))
    assert len(snaps) >= 1, f"Expected at least 1 snapshot, got {len(snaps)}"
    print("   OK")

test("history_snapshot", t29)

# 30. History — list
print("30. History — list")

def t30():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_history("hist_test.enc", action="list")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "snapshots" in out
    print("   OK")

test("history_list", t30)

# 31. History — prune
print("31. History — prune")

def t31():
    # Create a few more snapshots
    for _ in range(3):
        envault.cmd_history("hist_test.enc", action="snapshot")
    hist_dir = Path(".envault-history")
    snaps = sorted(hist_dir.glob("hist_test.enc.*"))
    # Prune to keep only 2
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_history("hist_test.enc", action="prune", keep=2)
    finally:
        sys.stdout = old
    snaps_after = sorted(hist_dir.glob("hist_test.enc.*"))
    # Should have at most 2 (plus any -pre-restore etc)
    non_restore = [s for s in snaps_after if "-pre-restore" not in s.name and "-prune" not in s.name]
    assert len(non_restore) <= 2, f"Expected <= 2 after prune, got {len(non_restore)}"
    print("   OK")

test("history_prune", t31)

# 32. History — restore
print("32. History — restore")

def t32():
    hist_dir = Path(".envault-history")
    snaps = sorted(hist_dir.glob("hist_test.enc.*"))
    # Get the oldest non-restore snapshot
    non_restore = [s for s in snaps if "-pre-restore" not in s.name and "-prune" not in s.name]
    if len(non_restore) < 1:
        print("   SKIP (no snapshots)")
        return
    # Extract timestamp from the first snapshot
    ts_str = non_restore[0].name.rsplit(".", 1)[-1]
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_history("hist_test.enc", action="restore", restore=ts_str)
    finally:
        sys.stdout = old
    assert Path("hist_test.enc").exists()
    print("   OK")

test("history_restore", t32)

# 33. History — list empty file
print("33. History — list (no history yet)")

def t33():
    envault.encrypt_env("test.env", "hist_empty.enc")
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_history("hist_empty.enc", action="list")
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "No history" in out
    print("   OK")

test("history_list_empty", t33)

# 34. Doctor — runs without error
print("34. Doctor — runs without error")

def t34():
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    try:
        envault.cmd_doctor()
        out = buf.getvalue()
    finally:
        sys.stdout = old
    assert "Health Score" in out
    assert "envault v1.3.0" in out
    print("   OK")

test("doctor_runs", t34)

# 35. Doctor — detects plaintext .env
print("35. Doctor — detects plaintext .env")

def t35():
    # Create a plaintext .env file
    Path("doctor_test.env").write_text("SECRET=value\n")
    try:
        old = sys.stdout
        sys.stdout = buf = io.StringIO()
        try:
            envault.cmd_doctor()
            out = buf.getvalue()
        finally:
            sys.stdout = old
        assert "plaintext" in out.lower() or "doctor_test.env" in out
    finally:
        Path("doctor_test.env").unlink(missing_ok=True)
    print("   OK")

test("doctor_detects_plaintext", t35)


# Cleanup
for f in [
    "test.env", "test_staging.env", "t1.enc", "t2.enc",
    "t3_dec.env", "t4_dec.env", "diff_a.enc", "diff_b.enc",
    "rotate_test.enc", "rotated_dec.env",
    ".envvaultrc", ".envvaultrc.json", "should_not_exist.env",
    "export_test.enc", "export_out.json", "export_out.yaml",
    "export_out.sh", "export_out_docker.env", "export_out_k8s.yaml",
    "export_out_dot.env", "plain_export.env", "plain_out.json",
    "test_template.env", "rendered.env", "plain_source.env",
    "test_template2.env", "rendered2.env",
    "hist_test.enc", "hist_empty.enc", "doctor_test.env",
]:
    Path(f).unlink(missing_ok=True)
# Clean up history directory
import shutil
shutil.rmtree(".envault-history", ignore_errors=True)

print(f"\n=== Results: {passed} passed, {failed} failed ===")
if failed:
    sys.exit(1)
