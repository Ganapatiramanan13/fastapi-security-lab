"""
Pydantic schemas for the SECURE app.

Identical baseline to vulnerable_app/schemas.py at this stage: request
schemas only accept fields a client should reasonably send, and response
schemas never include password_hash.

In later stages, this is where the *fix* for mass assignment will live:
schemas here will stay strict (no client-writable "role" or "status"
fields) even as the vulnerable app's schemas are loosened to demonstrate
the flaw.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# ---------- User schemas ----------

class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    """Fields required to create a new user."""
    password: str


class UserOut(UserBase):
    """Fields returned to the client. Never includes password_hash."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str


class UserUpdate(BaseModel):
    """
    Fields accepted by PUT /users/{user_id}.

    FIX (compare to vulnerable_app.schemas.UserUpdate — Mass Assignment,
    OWASP API3:2023 — Broken Object Property Level Authorization):

    This is a strict ALLOWLIST. Only "username" and "email" exist on
    this model at all — there is no "role" field here, so a client can
    never set it through this endpoint no matter what JSON they send.

    `model_config = ConfigDict(extra="forbid")` goes one step further:
    if the client includes ANY field this schema doesn't define (e.g.
    "role", "id", "password_hash"), Pydantic itself rejects the whole
    request with HTTP 422 before our endpoint code ever runs. The
    unexpected field is caught at the validation boundary, not by
    remembering to check for it in application logic.
    """
    model_config = ConfigDict(extra="forbid")

    # username, when provided, must be non-empty. Pydantic rejects ""
    # with HTTP 422 at the validation boundary, before the endpoint runs.
    # None still means "leave username unchanged".
    username: str | None = Field(default=None, min_length=1)
    email: str | None = None


# ---------- Order schemas ----------

class OrderCreate(BaseModel):
    """
    Fields a client sends to POST /orders in the SECURE app.

    FIX (compare to vulnerable_app — Improper Input Validation, CWE-20 /
    CWE-1284):
      - `extra="forbid"` rejects any field this schema does not declare
        (e.g. a client-supplied `user_id`, `amount`, or `total`) with
        HTTP 422, so the client can neither choose the owner nor dictate
        the stored total.
      - `quantity` must be a positive integer within a sane upper bound
        (<= 1,000,000). Non-finite values (NaN/Infinity) are not valid
        integers and are rejected during type coercion.
      - `unit_price` must be greater than zero, finite (NaN and
        Infinity are rejected via `allow_inf_nan=False`), and at most
        1,000,000. The quantity and unit_price upper bounds together
        keep the server-calculated total finite (<= 1e12), so a
        non-finite `amount` can never be computed or stored.
      - `product` must be a non-empty, length-bounded string.
    The total is never accepted from the client; it is computed
    server-side (see routers/orders.py).
    """
    model_config = ConfigDict(extra="forbid")

    product: str = Field(min_length=1, max_length=200)
    quantity: int = Field(gt=0, le=1_000_000)
    unit_price: float = Field(gt=0, le=1_000_000, allow_inf_nan=False)


class OrderOut(BaseModel):
    """What we return for an order. `amount` is the server-calculated total."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    product: str
    quantity: int
    unit_price: float
    amount: float
    status: str
    created_at: datetime


# ---------- Login schemas ----------

class LoginRequest(BaseModel):
    """What the client sends to POST /login."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """
    What we send back on successful login: a JWT access token plus
    basic account info. See auth.py for how the signing secret is
    handled securely (loaded from the environment, never hardcoded).
    """
    message: str
    access_token: str
    token_type: str
    user: UserOut
