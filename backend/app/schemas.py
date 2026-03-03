# app/schemas.py
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, EmailStr, field_validator

# ── Auth ──────────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_max_length(cls, v: str) -> str:
        if len(v) > 72:
            raise ValueError("Password must be 72 characters or fewer (bcrypt limit).")
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v

class UserOut(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime
    model_config = {"from_attributes": True}

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ── Predict ───────────────────────────────────────────────────────────────────
class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty.")
        return v

class PredictResponse(BaseModel):
    url: str
    result: str
    confidence: float
    reason: str

# ── History ───────────────────────────────────────────────────────────────────
class ScanOut(BaseModel):
    id: UUID
    url: str
    result: str
    confidence: float
    reason: str
    created_at: datetime
    model_config = {"from_attributes": True}