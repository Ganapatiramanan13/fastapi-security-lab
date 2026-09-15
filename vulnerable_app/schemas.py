"""
Pydantic schemas for the VULNERABLE app.

These control what data comes IN through the API (request bodies) and
what data goes OUT (response bodies). At this stage they are plain and
safe: request schemas only expose the fields a client should reasonably
send, and response schemas never include password_hash.

Mass assignment vulnerabilities will be introduced later by *loosening*
a request schema (e.g. letting a client set "role" directly) — not by
changing this baseline.
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

    VULNERABILITY (intentional — Mass Assignment, OWASP API6:2023 /
    "Unrestricted Access to Sensitive Business Flows" family, classic
    OWASP API3:2019 Excessive Data Exposure's mirror-image cousin):

    Every field here is optional so a client can update just one field
    at a time — that part is normal. The problem is WHICH fields are
    exposed: "role" has no business being client-writable. A profile
    update endpoint should only ever let a user change their own
    display info (username/email), never a privileged field that
    controls what they're allowed to do in the system.

    Because this schema includes "role", and the endpoint (see
    routers/users.py) applies every field the client sends without an
    allowlist, a normal user can grant themselves admin rights in a
    single request. The fix (a later stage) is to remove "role" from
    the client-facing update schema entirely and only ever set it
    through a separate, admin-only code path.
    """
    username: str | None = None
    email: str | None = None
    role: str | None = None


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
    What we send back on successful login.

    Stage 4: now includes a JWT access token. The client is expected to
    send this back as "Authorization: Bearer <access_token>" on future
    requests to protected endpoints (added in later stages).

    See auth.py for why JWT_SECRET_KEY is intentionally weak at this
    stage — that's a vulnerability being studied, not a mistake.
    """
    message: str
    access_token: str
    token_type: str
    user: UserOut
