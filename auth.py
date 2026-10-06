import time
import bcrypt
import jwt
from fastapi import Header, HTTPException
from config import JWT_SECRET


def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_pw(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def make_token(user_id: int) -> str:
    payload = {"sub": str(user_id), "exp": int(time.time()) + 8 * 3600}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def current_user(authorization: str = Header(None)) -> int:
    """FastAPI dependency: returns the logged-in user's id or raises 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not logged in")

    try:
        data = jwt.decode(
            authorization[7:],
            JWT_SECRET,
            algorithms=["HS256"]
        )
        return int(data["sub"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")