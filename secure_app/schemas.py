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

from pydantic import BaseModel, ConfigDict


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
    OWASP API6:2023):

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

    username: str | None = None
    email: str | None = None


# ---------- Order schemas ----------

class OrderBase(BaseModel):
    product: str
    amount: float


class OrderCreate(OrderBase):
    """Fields required to create a new order."""
    pass


class OrderOut(OrderBase):
    """Fields returned to the client."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    status: str


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
