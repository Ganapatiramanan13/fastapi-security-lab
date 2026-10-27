"""
Focused regression tests for secure_app's startup configuration validation.

secure_app/auth.py refuses to start unless SECURE_APP_JWT_SECRET is set and
is at least _MIN_SECRET_LENGTH (32) characters: it raises RuntimeError at
IMPORT time (module-level), before secure_app.main ever runs
Base.metadata.create_all. These tests confirm that fail-fast behavior.

Why subprocess + isolated env + temp cwd:
  - Each case must import secure_app.auth under a PRECISELY controlled
    SECURE_APP_JWT_SECRET. Importing in-process is unreliable (the module
    caches after first import, and this test session's conftest.py has
    already set a valid secret). A fresh subprocess re-runs the
    module-level validation every time.
  - The subprocess environment is built from scratch (NOT inherited from
    os.environ), so a valid SECURE_APP_JWT_SECRET in the developer's
    environment cannot leak in and mask the missing-secret case.
  - Importing secure_app.auth constructs only a lazy SQLAlchemy engine; it
    does NOT open or create any SQLite file (that happens in
    secure_app.main's create_all, which these tests never import or reach).
    As a second safeguard the subprocess runs in an isolated temp cwd, so
    even a relative DB path could not resolve to the real
    ./secure_app/secure.db. This file never imports secure_app in-process
    and uses no database fixtures.
"""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Import the module that performs startup validation; print a marker only
# if validation passed (i.e. the import did not raise).
_IMPORT_PROGRAM = "import secure_app.auth; print('IMPORT_OK')"

# Exactly _MIN_SECRET_LENGTH characters — the minimum the app accepts.
VALID_SECRET = "a" * 32
SHORT_SECRET = "short"  # 5 chars, well under the 32-char minimum


def _base_env() -> dict:
    """
    Minimal environment for starting Python on this platform, deliberately
    WITHOUT any inherited SECURE_APP_JWT_SECRET. PYTHONPATH makes the
    secure_app package importable from the isolated temp cwd.
    """
    env = {
        "PYTHONPATH": str(REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    # Carry only the OS essentials the interpreter needs to start; these
    # never include the secret under test.
    for key in (
        "SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP",
        "LD_LIBRARY_PATH", "HOME",
    ):
        if key in os.environ:
            env[key] = os.environ[key]
    env.pop("SECURE_APP_JWT_SECRET", None)  # belt and suspenders
    return env


def _run_import(secret, tmp_path) -> subprocess.CompletedProcess:
    env = _base_env()
    if secret is not None:
        env["SECURE_APP_JWT_SECRET"] = secret
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_PROGRAM],
        env=env,
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )


class TestSecureStartupConfig:
    """REGRESSION: secure_app must fail fast on a missing/weak JWT secret."""

    def test_missing_secret_fails_import(self, tmp_path):
        result = _run_import(None, tmp_path)
        assert result.returncode != 0
        assert "IMPORT_OK" not in result.stdout
        assert "SECURE_APP_JWT_SECRET" in result.stderr
        assert "not set" in result.stderr

    def test_undersized_secret_fails_import(self, tmp_path):
        result = _run_import(SHORT_SECRET, tmp_path)
        assert result.returncode != 0
        assert "IMPORT_OK" not in result.stdout
        assert "shorter than 32" in result.stderr

    def test_valid_secret_imports_cleanly(self, tmp_path):
        # Positive control: proves the two failures above are specifically
        # the secret validation, not an unrelated import error.
        result = _run_import(VALID_SECRET, tmp_path)
        assert result.returncode == 0, result.stderr
        assert "IMPORT_OK" in result.stdout
