"""
Shared pytest configuration for the security test suite.

This file's only job: make sure secure_app can even be imported.
secure_app.auth (Stage 12) intentionally refuses to start unless
SECURE_APP_JWT_SECRET is set in the environment (its fail-safe fix for
the weak-hardcoded-secret vulnerability). For test runs we don't need a
persistent, deployment-grade secret — we generate a fresh strong one
for this test session only, satisfying that same fail-safe check
honestly rather than weakening it.

This does not modify either app's security behavior — it only supplies
the environment secure_app already requires to run at all.
"""

import os
import secrets

os.environ.setdefault("SECURE_APP_JWT_SECRET", secrets.token_hex(32))
