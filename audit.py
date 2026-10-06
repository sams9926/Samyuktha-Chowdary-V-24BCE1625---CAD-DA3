import hashlib
import threading
from datetime import datetime, timezone
from db import query, query_one, execute

_lock = threading.Lock()


def _hash(prev, ts, actor, action, target, details):
    raw = f"{prev}|{ts}|{actor}|{action}|{target}|{details}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _clip(s, max_bytes):
    """Oracle never stores '' (it becomes NULL) and VARCHAR2 limits are in BYTES."""
    s = s or "-"
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", errors="ignore")


def audit(actor, action, target="-", details="-"):
    # Clip BEFORE hashing so that what we hash == what is stored
    actor, action = _clip(actor, 255), _clip(action, 50)
    target, details = _clip(target, 255), _clip(details, 500)

    with _lock:   # prevents two requests forking the chain (run ONE server worker)
        last = query_one(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC FETCH FIRST 1 ROWS ONLY")
        prev = last["entry_hash"] if last else "GENESIS"
        ts = datetime.now(timezone.utc).isoformat()
        h = _hash(prev, ts, actor, action, target, details)
        execute(
            """INSERT INTO audit_log(ts, actor, action, target, details, prev_hash, entry_hash)
               VALUES (:ts, :actor, :action, :target, :details, :prev, :h)""",
            {"ts": ts, "actor": actor, "action": action, "target": target,
             "details": details, "prev": prev, "h": h})


def verify_chain(cp_id=None, cp_hash=None):
    """Recompute every hash from the start.
    Optionally compare against a checkpoint (entry id + hash) the user pinned earlier."""
    prev, count, last_id, seen = "GENESIS", 0, None, None
    for r in query("SELECT * FROM audit_log ORDER BY id"):
        rid = int(r["id"])
        expected = _hash(prev, r["ts"], r["actor"], r["action"], r["target"], r["details"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"ok": False, "reason": "chain_broken", "broken_at": rid, "entries": count}
        prev, count, last_id = r["entry_hash"], count + 1, rid
        if cp_id is not None and rid == cp_id:
            seen = r["entry_hash"]

    res = {"ok": True, "entries": count, "head": prev, "head_id": last_id, "checkpoint": None}
    if cp_id is not None:
        if seen is None:
            return {"ok": False, "reason": "checkpoint_missing", "entries": count}
        if seen != cp_hash:
            return {"ok": False, "reason": "checkpoint_mismatch", "entries": count}
        res["checkpoint"] = "ok"
    return res