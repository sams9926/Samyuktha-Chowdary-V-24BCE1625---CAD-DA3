import os

ORACLE_USER = os.environ.get("ORACLE_USER", "vault")
ORACLE_PASSWORD = os.environ.get("ORACLE_PASSWORD", "vault123")
ORACLE_DSN = os.environ.get("ORACLE_DSN", "localhost:1521/XEPDB1")

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-me")
SIGN_KEY = os.environ.get("SIGN_KEY", "dev-sign-key-change-me")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")

STORAGE_DIR = "storage"

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Refuse to start in production with the development default secrets
if os.environ.get("VT_ENV") == "production":
    _missing = [n for n in ("JWT_SECRET", "SIGN_KEY", "ORACLE_PASSWORD", "BASE_URL")
                if not os.environ.get(n)]
    if _missing:
        raise RuntimeError("Refusing to start in production without: " + ", ".join(_missing))