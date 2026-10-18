# Weak JWT Secret — Token Forgery and Account Impersonation

## 1. Summary

The vulnerable application signs JSON Web Tokens (JWTs) using a hardcoded secret: `supersecret`. Because this secret is present in publicly accessible source code, an attacker who knows it can forge tokens that the application accepts.

The secure implementation loads its signing secret from an environment variable, validates its strength, and refuses to start if the secret is missing or too short.

## 2. Affected Component

- **Component:** JWT signing and verification in `vulnerable_app/auth.py`
- **Affected endpoint:** `GET /admin`
- **OWASP mapping:** API2:2023 — Broken Authentication

## 3. Root Cause

The vulnerable application defines its JWT signing secret directly in source code:

`JWT_SECRET_KEY = "supersecret"`

JWT signatures provide integrity only when the signing key remains secret. Anyone who knows the signing secret can create a token with claims chosen by that person and generate a valid signature.

## 4. Reproduction

Perform this test only against the intentionally vulnerable application running locally.

1. Start the vulnerable application and use the supplied demo data.
2. Log in as Alice and request `/admin` using her legitimate token to establish the baseline.
3. Run `exploits/exploit_weak_jwt.py`.
4. Inspect the script's results to compare a forged token using Alice's subject ID with a forged token using the actual administrator's subject ID.

### Important observation

The application obtains the user's role from the database using the JWT's `sub` claim. It does not trust a `role` claim in the token.

Consequently, forging a token with `sub="1"` and `role="admin"` does not make Alice an administrator. However, forging a valid token with `sub="3"` can impersonate the administrator if ID `3` is the seeded administrator's database ID.

### Vulnerable result

The forged administrator token is accepted by the vulnerable application, allowing access to `/admin` without the administrator's password.

## 5. Security Impact

An attacker who knows the exposed signing secret can forge valid tokens and impersonate accounts. This can result in unauthorized access to privileged functionality and sensitive information.

## 6. Remediation

The secure application:

1. Loads the JWT signing secret from `SECURE_APP_JWT_SECRET`.
2. Requires a sufficiently long secret.
3. Refuses to start when the secret is missing or shorter than 32 characters.
4. Verifies token signatures and rejects tokens signed using the vulnerable application's secret.

A token signed with `supersecret` is rejected by the secure application with HTTP `401 Unauthorized`.

## 7. Verification

The exploit script demonstrates the vulnerable behavior. Automated tests verify the expected secure authentication behavior, including rejection of invalid tokens.

Run the exploit only against the local vulnerable application:

```bash
python exploits/exploit_weak_jwt.py
```

## 8. Key Learning

JWT claims must not be trusted merely because they appear inside a token. The server must validate the signature using a securely managed key. A hardcoded signing secret undermines the integrity of every token that relies on it.
