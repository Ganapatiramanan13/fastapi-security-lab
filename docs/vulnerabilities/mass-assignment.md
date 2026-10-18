# Mass Assignment — Unauthorized Role Modification

## 1. Summary

The vulnerable API allows a user to modify their own profile and change fields that should be controlled by the server, including their `role`. By submitting `"role": "admin"`, an ordinary user can escalate their privileges.

The secure implementation uses a strict request schema and explicit field assignment to prevent unauthorized property changes.

## 2. Affected Endpoint

- **Method:** `PUT`
- **Path:** `/users/{user_id}`
- **OWASP mapping:** Broken Object Property Level Authorization is a relevant classification for unauthorized access to sensitive object properties. Mass assignment is the specific implementation pattern demonstrated in this lab.

## 3. Root Cause

The vulnerable endpoint checks that the caller owns the profile being updated, but then assigns every field supplied in the request body to the database object.

The update logic does not distinguish between user-editable properties, such as `username` and `email`, and privileged properties, such as `role`.

## 4. Reproduction

Perform these steps only against the intentionally vulnerable application running locally.

1. Log in as Alice and obtain her bearer token.
2. Send `PUT /users/1` with Alice's token.
3. Include this JSON request body:

   ```json
   {
     "email": "alice_new@example.com",
     "role": "admin"
   }
   ```

4. Inspect the response and then request `GET /admin` using Alice's token.

### Vulnerable result

The vulnerable API accepts the `role` property, changes Alice's role to `admin`, and allows her to access the admin endpoint.

Evidence:
- `evidence/09-mass-assignment-burp-vulnerable.png`
- `evidence/10-mass-assignment-burp-privilege-escalation.png`

## 5. Security Impact

An ordinary authenticated user can escalate privileges without administrator approval. Depending on the application, this could grant access to privileged operations, sensitive data, or administrative functionality.

## 6. Remediation

The secure application applies two controls:

1. The `UserUpdate` schema permits only `username` and `email`, with `ConfigDict(extra="forbid")` rejecting unexpected properties.
2. The endpoint explicitly assigns only the allowed fields rather than iterating over arbitrary request keys.

The secure API rejects an attempted `role` modification with HTTP `422 Unprocessable Entity`.

## 7. Verification

- The vulnerable application demonstrates that Alice can change her role to `admin`.
- The secure application rejects the unexpected `role` property.
- A subsequent profile request confirms Alice's role remains `user`.

Evidence:
- `evidence/11-mass-assignment-burp-secure.png`
- `evidence/12-mass-assignment-secure-role-unchanged.png`

## 8. Key Learning

Ownership checks alone do not make an update endpoint safe. The server must also control which properties the client is permitted to modify. Explicit request schemas and field allowlists prevent clients from changing privileged properties.
