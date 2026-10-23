# Improper Input Validation (Orders API)

## Overview

`vulnerable_app`'s `POST /orders` endpoint computes an order's line total
from a client-supplied `quantity` and `unit_price` without validating that
those values are positive. The request schema (`vulnerable_app/schemas.py:
OrderCreate`) accepts a plain `int` quantity and a plain `float` unit price
with no lower bound, so a normal authenticated user can submit a negative
quantity and have the server compute and persist an impossible order — for
example, a line total of `-500.0`. This is an ordinary input-validation /
data-integrity defect, not an authorization flaw: the caller is allowed to
create their own order, but the application never checks that the order's
values are valid.

## Affected Endpoint

- **Method:** `POST`
- **Endpoint:** `/orders`
- **Application affected:** `vulnerable_app` (fixed in `secure_app`)
- **Related endpoint:** `GET /orders/{order_id}` (retrieval; ownership is
  enforced in both apps and is **not** part of this vulnerability).

## Preconditions

- The caller is authenticated with a valid JWT (any ordinary user; no admin
  rights and no token forgery are required).
- The vulnerable app is running and seeded locally
  (`http://127.0.0.1:8000`).

## Vulnerability Description

`vulnerable_app/schemas.py` declares the create-order body with no value
constraints:

```python
class OrderCreate(BaseModel):
    product: str
    quantity: int
    unit_price: float
```

`vulnerable_app/routers/orders.py` then multiplies the two inputs to form
the stored total, with no business-rule check:

```python
total = order.quantity * order.unit_price  # no validation of the inputs
db_order = Order(user_id=current_user.id, product=order.product,
                 quantity=order.quantity, unit_price=order.unit_price,
                 amount=total, status="pending")
```

The owner (`user_id`) is taken from the authenticated user and the total is
computed server-side, so this endpoint does **not** expose owner spoofing or
a client-dictated total. The single defect is that `quantity` and
`unit_price` are never constrained to sensible values. A `quantity` of `-5`
passes the type check (it is a valid integer) but violates the business rule
that an order quantity must be positive.

## Reproduction Steps

With the vulnerable app seeded and running on `127.0.0.1:8000`:

1. Log in as Alice (`alice` / `alice_password123`) via `POST /login` and
   obtain a valid token.
2. Send a control order: `POST /orders` with
   `{"product": "Mouse", "quantity": 2, "unit_price": 10.0}` — returns
   `201` with `amount = 20.0`.
3. Send the invalid order: `POST /orders` with
   `{"product": "Mouse", "quantity": -5, "unit_price": 100.0}`.

`exploits/exploit_improper_input_validation.py` performs exactly these
steps and prints a `RESULT` line. The same behavior is pinned by
`tests/test_vulnerable_security.py::TestVulnerableInputValidation`.

## Actual Vulnerable Response

The invalid request is accepted:

```
HTTP status code: 201
Response JSON: {'id': 5, 'user_id': 1, 'product': 'Mouse', 'quantity': -5,
               'unit_price': 100.0, 'amount': -500.0, 'status': 'pending',
               'created_at': '...'}
```

A follow-up `GET /orders/5` confirms the negative total was persisted, not
just echoed.

## Security Impact

An order with a negative (or zero) quantity and a negative total is a
data-integrity violation. In a real system, a persisted negative line total
can corrupt downstream accounting, totals, invoices, or balance
calculations, and — depending on how totals feed billing or refunds — could
translate into financial loss (for example, a negative total that is later
treated as a credit). The request otherwise looks completely legitimate (an
authenticated user creating their own order), so it is easy to miss in
review that only tests "can the user create an order?" without checking
"are the order's values valid?".

This is an integrity/availability-of-correct-data concern, not a
confidentiality breach or a privilege escalation.

## Severity Assessment

**Severity: Medium.** Rationale: exploitation is trivial (a single
authenticated request, no special privileges) and the integrity impact on
stored business data is real and immediate. It is not rated High because, on
its own, it does not grant unauthorized access, escalate privileges, or
expose other users' data; the concrete financial impact depends on how the
stored total is consumed downstream, which is outside this lab's scope. No
CVSS score is asserted here because the downstream business impact is
environment-dependent; the Medium rating reflects the lab's isolated
behavior (trivial to trigger, local integrity damage) rather than a
calculated vector.

## OWASP API Security Top 10 Mapping

This is primarily an **input-validation** defect rather than an
authorization defect, so it is deliberately **not** mapped to an
object-/property-level authorization category (API1/API3). The applicable
mapping, where one is used, is the general weakness that the API does not
validate incoming data against expected constraints. OWASP's API Security
Top 10 does not have a dedicated "improper input validation" entry in the
2023 edition; this finding is better described by its CWE mapping below.
Mislabeling it as an authorization vulnerability would misrepresent the
root cause, which is missing value validation, not a broken access check.

## CWE Mapping

- **CWE-20: Improper Input Validation** — the endpoint does not validate the
  `quantity`/`unit_price` inputs against the constraints required for them to
  be meaningful.
- **CWE-1284: Improper Validation of Specified Quantity in Input** — the
  specific case here: a quantity value is used in a calculation without
  verifying it falls in the expected (positive) range.

## Secure Implementation and Remediation

`secure_app` fixes this entirely at the schema boundary
(`secure_app/schemas.py`), so invalid input is rejected with `422` before
the endpoint body runs:

```python
class OrderCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product: str = Field(min_length=1, max_length=200)
    quantity: int = Field(gt=0, le=1_000_000)
    unit_price: float = Field(gt=0, le=1_000_000, allow_inf_nan=False)
```

- `quantity` must be a positive integer within a sane upper bound
  (`<= 1,000,000`).
- `unit_price` must be greater than zero, **finite**, and `<= 1,000,000`.
  `allow_inf_nan=False` rejects `NaN` and `+/-Infinity` with `422`
  instead of letting them reach persistence — which previously caused
  an unhandled `500` for `NaN`, or stored a non-finite total for
  `Infinity`.
- `product` must be a non-empty, length-bounded string.
- `extra="forbid"` rejects any unexpected field (for example a
  client-supplied `user_id`, `amount`, or `total`), so the client can
  neither choose the order owner nor dictate the stored total.

**Returning a clean `422` for non-finite input:** Python's JSON parser (used by Starlette) accepts the non-standard literals `NaN`, `Infinity` and `-Infinity`, so those values reach the schema and are rejected by `allow_inf_nan=False`. Pydantic echoes the offending value in its error detail, and Starlette renders JSON responses with `allow_nan=False`; serializing a non-finite value in the error body would itself raise and surface as a `500`. `secure_app/main.py` therefore registers a `RequestValidationError` handler that stringifies any non-finite float in the error payload, so the rejection is reported as a normal `422` rather than a `500`.

**Why the upper bounds matter (overflow):** even with non-finite inputs
rejected, a finite but extreme `unit_price` (for example `1e308`) could
otherwise overflow the server-side multiplication to `inf`, which was
then stored and serialized as `null`. Bounding both `quantity` and
`unit_price` to `1,000,000` caps the computed total at `1e12` — far
within float range — so the total is always finite. These limits are
deliberately generous for this educational order lab (up to one million
units at up to one million per unit) and exist to keep the calculation
well-defined, not to model a real catalog.

**Money precision (separate consideration):** `amount` is a binary
`float`, so values such as `0.1 * 3` are stored as
`0.30000000000000004`. Storage and retrieval are consistent, and this is
out of scope for this input-validation fix. Representing money as
`Decimal` or integer minor units is the correct long-term approach and
is noted here as a separate design task, not a change made in this
stage.

The endpoint logic (`secure_app/routers/orders.py`) is otherwise identical
to the vulnerable app's: the owner is taken from `current_user` and the
total is computed server-side as `quantity * unit_price`. `GET
/orders/{order_id}` enforces object-level authorization (owner-or-admin,
else `403`), so ordinary input validation is kept distinct from the
retrieval authorization check.

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableInputValidation`
  documents the vulnerable behavior: a valid order is created with a
  server-calculated total; a negative quantity is accepted and persists a
  negative total; a client-supplied `user_id` is ignored (owner stays the
  authenticated user).
- `tests/test_secure_security.py::TestSecureInputValidation` verifies the
  fix: a valid order succeeds with the correct server-calculated total;
  negative quantity, zero quantity, negative price, a missing required
  field, malformed JSON, and an unexpected field each return `422` (no
  `500`); and a user cannot retrieve another user's order
  (`403`) while retrieving their own succeeds (`200`).
- `tests/test_secure_security.py::TestSecureNonFiniteInputValidation`
  verifies the hardening fix: a `unit_price` of `NaN`, `Infinity`, or
  `-Infinity`, a non-finite `quantity`, and a finite overflow value
  (`1e308`) each return `422`; no order is persisted after a rejected
  request; and a large-but-bounded order (total up to `1e12`) still
  succeeds with a finite amount.
- Full suite result after this fix: **41 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_improper_input_validation.py` against the local
apps (they are rendered captures of real output, not native screenshots):

- `evidence/16-iiv-vulnerable.png` — the exploit against the vulnerable app
  (`:8000`): the control order returns `201` with `amount = 20.0`, and the
  invalid order (`quantity = -5`) is accepted with `201` and
  `amount = -500.0`.
- `evidence/17-iiv-secure.png` — the same exploit against the secure app
  (`:8001`): the control order returns `201`, and the invalid order is
  rejected with `422` (`"Input should be greater than 0"`).

## Vulnerable vs Secure

| Aspect | Vulnerable App | Secure App |
|---|---|---|
| Create schema | `quantity: int`, `unit_price: float`, no bounds | `quantity > 0`, `unit_price > 0`, `extra="forbid"` |
| `POST /orders` with `quantity=-5` | `201`, `amount = -500.0` persisted | `422`, nothing created |
| Owner of created order | Derived from token (server-side) | Derived from token (server-side) |
| Client-supplied `user_id` | Ignored (not applied) | Rejected with `422` (`extra="forbid"`) |
| Total | Computed server-side | Computed server-side |
| `GET /orders/{id}` ownership | Owner-or-admin, else `403` | Owner-or-admin, else `403` |

## Interview Takeaway

- Why type validation is not value validation: `-5` is a perfectly valid
  integer, so a type-only schema accepts it; business rules (positive
  quantity, positive price) must be stated explicitly.
- Why this is an input-validation defect, not an authorization one: the user
  is authorized to create their own order; what is missing is validation of
  the order's values, so it maps to CWE-20/CWE-1284, not to an OWASP
  object-/property-level authorization category.
- Why validating at the schema boundary (Pydantic `Field` constraints +
  `extra="forbid"`) is stronger than ad-hoc checks in the handler: invalid
  input is rejected before any business logic runs, and unexpected fields
  cannot smuggle in owner or total values.
- Why the total is computed server-side and the owner is taken from the
  authenticated identity: never trust a client to supply a value the server
  can derive authoritatively.
