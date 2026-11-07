import logging
from typing import Optional
from dataclasses import dataclass
import jwt
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import SUPABASE_JWT_SECRET

logger = logging.getLogger("dpi.auth")
security = HTTPBearer(auto_error=False)

@dataclass
class AuthUser:
    id: str
    email: Optional[str] = None
    role: Optional[str] = "authenticated"

def decode_token(token: str) -> Optional[AuthUser]:
    """
    Decodes and verifies a Supabase JWT access token.
    Falls back to unverified decode in development if SUPABASE_JWT_SECRET is empty.
    """
    try:
        if SUPABASE_JWT_SECRET:
            payload = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False}
            )
        else:
            # Development fallback when JWT secret hasn't been set in .env
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_aud": False}
            )

        user_id = payload.get("sub")
        if not user_id:
            return None

        return AuthUser(
            id=str(user_id),
            email=payload.get("email"),
            role=payload.get("role", "authenticated")
        )
    except Exception as e:
        logger.warning(f"Failed to decode or verify authentication token: {e}")
        return None

def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[AuthUser]:
    """
    FastAPI dependency that returns the authenticated AuthUser or None if anonymous.
    """
    if not credentials or not credentials.credentials:
        return None
    return decode_token(credentials.credentials)

def get_current_user(
    user: Optional[AuthUser] = Depends(get_optional_user)
) -> AuthUser:
    """
    FastAPI dependency that enforces authentication. Raises 401 if unauthenticated.
    """
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please sign in with Email, Google, or GitHub.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
