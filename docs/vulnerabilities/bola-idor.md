# BOLA / IDOR — Broken Object Level Authorization

## 1. Summary

The vulnerable API allows an authenticated user to retrieve another user's record by changing the `user_id` path parameter. The secure implementation enforces object-level authorization and rejects unauthorized cross-user access.

## 2. Affected Endpoint

- **Method:** `GET`
- **Path:** `/users/{user_id}`
- **OWASP mapping:** API1:2023 — Broken Object Level Authorization

## 3. Root Cause

The vulnerable endpoint verifies that the caller has a valid JWT but does not verify that the caller owns the requested object or has administrator privileges.

Authentication alone does not authorize access to every user's data.

## 4. Reproduction

Perform this test only against the intentionally vulnerable application running locally.

1. Log in as Alice using the demo credentials.
2. Obtain Alice's bearer token.
3. Send a request to `GET /users/1` using Alice's token to confirm her own record is accessible.
4. Change the path parameter to `GET /users/2` while keeping the same token.
5. Compare the response.

### Vulnerable result

Alice's token receives HTTP `200 OK` when requesting Bob's record.

Evidence: `evidence/01-bola-vulnerable.png`

### Secure result

The secure application checks ownership or administrator privileges. Alice receives HTTP `403 Forbidden` when requesting Bob's record.

Evidence:
- `evidence/02-bola-secure.png`
- `evidence/08-bola-burp-secure.png`

## 5. Security Impact

An attacker with a valid account could access other users' records by changing object identifiers. Depending on the data exposed, this could lead to unauthorized disclosure of personal information.

## 6. Remediation

The secure endpoint checks authorization for each requested object. Access is permitted only when the caller owns the requested record or has the administrator role.

The authorization check occurs before retrieving the target record, preventing unauthorized callers from using the endpoint to enumerate user records.

## 7. Verification

Automated security tests verify both behaviors:

- The vulnerable application reproduces the unauthorized cross-user access.
- The secure application returns `403 Forbidden` for unauthorized access.

## 8. Key Learning

A valid JWT proves authentication; it does not automatically grant permission to access every resource. Every endpoint that accepts an object identifier must enforce object-level authorization.
