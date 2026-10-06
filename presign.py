import hmac
import hashlib

from config import SIGN_KEY, BASE_URL


def sign(share_id: int, expires: int) -> str:
    """HMAC-SHA256 over 'id:expires' using a secret only the server knows."""
    msg = f"{share_id}:{expires}".encode()

    return hmac.new(
        SIGN_KEY.encode(),
        msg,
        hashlib.sha256
    ).hexdigest()


def make_link(share_id: int, expires: int) -> str:
    return (
        f"{BASE_URL}/v/{share_id}"
        f"?e={expires}&sig={sign(share_id, expires)}"
    )


def signature_ok(
    share_id: int,
    expires: int,
    sig: str
) -> bool:
    # compare_digest prevents timing attacks when comparing signatures
    return hmac.compare_digest(
        sign(share_id, expires).encode(),
        (sig or "").encode()
    )
