import os
import re
import time
import io
from PIL import Image

from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import STORAGE_DIR
from db import query, query_one, execute, insert
from auth import hash_pw, check_pw, make_token, current_user
from audit import audit, verify_chain
from presign import make_link, signature_ok
from mail import send_share_mail
from fingerprint import personalise, extract_id, extract_text

import asyncio
from contextlib import asynccontextmanager

from s3sim import (
    get_owned_bucket,
    get_owned_object,
    get_owned_version,
    validate_content,
    delete_all_versions,
    put_object,
    restore_version,
    run_lifecycle,
    ALLOWED_MIME,
    ALLOWED_EXT,
    MAX_BYTES
)


os.makedirs(STORAGE_DIR, exist_ok=True)


async def lifecycle_loop():
    """Background job: apply lifecycle rules every hour (like S3 does daily)."""
    while True:
        await asyncio.sleep(3600)
        try:
            await asyncio.to_thread(run_lifecycle)
        except Exception as e:
            print("lifecycle error:", e)


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(lifecycle_loop())
    yield
    task.cancel()


app = FastAPI(title="VaultTrace", lifespan=lifespan)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")   # no MIME sniffing
    resp.headers.setdefault("X-Frame-Options", "DENY")             # no clickjacking
    resp.headers.setdefault("Referrer-Policy", "no-referrer")      # links never leak in Referer
    return resp


DUMMY_HASH = hash_pw("not-a-real-password")   # used to equalise timing for unknown emails
_login_fails = {}                              # "email|ip" -> failure timestamps
MAX_FAILS, WINDOW = 5, 300                     # 5 failures per 5 minutes


def _recent_fails(key):
    now = time.time()
    lst = [t for t in _login_fails.get(key, []) if now - t < WINDOW]
    if lst:
        _login_fails[key] = lst
    else:
        _login_fails.pop(key, None)
    return lst

def email_of(uid):
    return query_one(
        "SELECT email FROM users WHERE id = :i",
        {"i": uid}
    )["email"]


# ======================= AUTH =======================

class Creds(BaseModel):
    email: str
    password: str


@app.post("/api/register")
def register(c: Creds):
    email = c.email.strip().lower()

    if "@" not in email or len(email) > 255 or len(c.password) < 6:
        raise HTTPException(400, "Enter a valid email and a password of 6+ characters")
    if len(c.password.encode()) > 72:
        raise HTTPException(400, "Password is too long (max 72 bytes)")

    if query_one(
        "SELECT id FROM users WHERE email = :e",
        {"e": email}
    ):
        raise HTTPException(
            400,
            "Email already registered"
        )

    uid = insert(
        """
        INSERT INTO users(email, password_hash)
        VALUES (:e, :p)
        RETURNING id INTO :new_id
        """,
        {
            "e": email,
            "p": hash_pw(c.password)
        }
    )

    audit(
        email,
        "REGISTER",
        f"user {uid}"
    )

    return {"ok": True}


@app.post("/api/login")
def login(c: Creds, request: Request):
    email = c.email.strip().lower()
    ip = request.client.host if request.client else "?"
    key = f"{email}|{ip}"

    if len(_recent_fails(key)) >= MAX_FAILS:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")

    u = query_one("SELECT id, password_hash FROM users WHERE email = :e", {"e": email})
    too_long = len(c.password.encode()) > 72

    # Always run one bcrypt check, even for unknown emails, so response time
    # doesn't reveal whether an account exists.
    ok = (not too_long) and check_pw(
        c.password,
        u["password_hash"] if u else DUMMY_HASH
    )

    if not u or not ok:
        _login_fails.setdefault(key, []).append(time.time())
        audit(email, "LOGIN_FAILED", "-", f"ip={ip}")

        if len(_recent_fails(key)) == MAX_FAILS:
            audit(
                email,
                "LOGIN_LOCKOUT",
                "-",
                f"5 failures in 5 min, ip={ip}"
            )

        raise HTTPException(401, "Wrong email or password")

    _login_fails.pop(key, None)
    audit(email, "LOGIN", f"user {u['id']}", f"ip={ip}")
    return {"token": make_token(u["id"])}


@app.get("/api/me")
def me(uid: int = Depends(current_user)):
    return query_one(
        "SELECT id, email FROM users WHERE id = :i",
        {"i": uid}
    )


# ======================= BUCKETS =======================

class BucketIn(BaseModel):
    name: str
    versioning: bool = True
    lifecycle_days: Optional[int] = None


BUCKET_RE = re.compile(
    r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$"
)


@app.get("/api/buckets")
def list_buckets(uid: int = Depends(current_user)):
    return query(
        """
        SELECT
            b.id,
            b.name,
            b.versioning,
            b.lifecycle_days,
            b.created_at,
            (
                SELECT COUNT(*)
                FROM objects o
                WHERE o.bucket_id = b.id
            ) AS object_count
        FROM buckets b
        WHERE b.user_id = :u
        ORDER BY b.id DESC
        """,
        {"u": uid}
    )


@app.post("/api/buckets")
def create_bucket(
    b: BucketIn,
    uid: int = Depends(current_user)
):
    name = b.name.strip().lower()

    if not BUCKET_RE.match(name):
        raise HTTPException(
            400,
            "Bucket name: 3-63 chars, lowercase letters, digits and hyphens only"
        )

    if b.lifecycle_days is not None and b.lifecycle_days < 1:
        raise HTTPException(
            400,
            "Auto-delete days must be 1 or more"
        )

    if query_one(
        """
        SELECT id
        FROM buckets
        WHERE user_id = :u AND name = :n
        """,
        {
            "u": uid,
            "n": name
        }
    ):
        raise HTTPException(
            400,
            "You already have a bucket with that name"
        )

    bid = insert(
        """
        INSERT INTO buckets(
            user_id,
            name,
            versioning,
            lifecycle_days
        )
        VALUES (
            :u,
            :n,
            :v,
            :d
        )
        RETURNING id INTO :new_id
        """,
        {
            "u": uid,
            "n": name,
            "v": 1 if b.versioning else 0,
            "d": b.lifecycle_days
        }
    )

    audit(
        email_of(uid),
        "CREATE_BUCKET",
        name,
        f"versioning={b.versioning}, lifecycle={b.lifecycle_days}"
    )

    return {
        "id": bid,
        "name": name
    }


# ======================= OBJECTS =======================

@app.get("/api/buckets/{bid}/objects")
def list_objects(
    bid: int,
    uid: int = Depends(current_user)
):
    get_owned_bucket(bid, uid)

    return query(
        """
        SELECT
            o.id,
            o.obj_key,
            o.created_at,
            (
                SELECT COUNT(*)
                FROM versions x
                WHERE x.object_id = o.id
            ) AS version_count,
            lv.id AS latest_version_id,
            lv.version_no AS latest_version,
            lv.size_bytes,
            lv.mime,
            lv.uploaded_at
        FROM objects o
        JOIN versions lv
            ON lv.object_id = o.id
            AND lv.version_no = (
                SELECT MAX(version_no)
                FROM versions
                WHERE object_id = o.id
            )
        WHERE o.bucket_id = :b
        ORDER BY o.id DESC
        """,
        {"b": bid}
    )


@app.post("/api/buckets/{bid}/objects")
async def upload(
    bid: int,
    file: UploadFile,
    uid: int = Depends(current_user)
):
    bucket = get_owned_bucket(bid, uid)

    filename = os.path.basename(
        file.filename or ""
    ).strip()[:255]

    if not filename:
        raise HTTPException(
            400,
            "Missing filename"
        )

    ext = os.path.splitext(filename)[1].lower()
    mime = (file.content_type or "").lower()

    if ext not in ALLOWED_EXT or mime not in ALLOWED_MIME:
        raise HTTPException(
            400,
            "Only PNG, JPG, WEBP images and .txt files are allowed"
        )

    data = await file.read()

    if len(data) == 0:
        raise HTTPException(
            400,
            "File is empty"
        )

    if len(data) > MAX_BYTES:
        raise HTTPException(
            413,
            "File too large (max 10 MB)"
        )

    validate_content(
        data,
        mime
    )

    r = put_object(
        bucket,
        filename,
        data,
        mime
    )

    audit(
        email_of(uid),
        "PUT_OBJECT",
        f"{bucket['name']}/{filename}@v{r['version_no']}",
        f"{len(data)} bytes, sha256={r['sha256'][:12]}"
    )

    return {
        "key": filename,
        "version": r["version_no"]
    }


@app.get("/api/versions/{vid}/download")
def download(
    vid: int,
    uid: int = Depends(current_user)
):
    v = get_owned_version(
        vid,
        uid
    )

    audit(
        email_of(uid),
        "OWNER_DOWNLOAD",
        f"{v['obj_key']}@v{v['version_no']}"
    )

    return FileResponse(
        v["path"],
        media_type=v["mime"],
        filename=v["obj_key"]
    )


@app.delete("/api/objects/{oid}")
def delete_object(
    oid: int,
    uid: int = Depends(current_user)
):
    o = get_owned_object(
        oid,
        uid
    )

    delete_all_versions(
        oid
    )

    execute(
        "DELETE FROM objects WHERE id = :o",
        {"o": oid}
    )

    audit(
        email_of(uid),
        "DELETE_OBJECT",
        o["obj_key"]
    )

    return {
        "ok": True
    }

# ======================= BUCKET SETTINGS =======================

class SettingsIn(BaseModel):
    versioning: bool
    lifecycle_days: Optional[int] = None


@app.put("/api/buckets/{bid}/settings")
def bucket_settings(
    bid: int,
    s: SettingsIn,
    uid: int = Depends(current_user)
):
    b = get_owned_bucket(bid, uid)

    if s.lifecycle_days is not None and s.lifecycle_days < 1:
        raise HTTPException(
            400,
            "Auto-delete days must be 1 or more"
        )

    execute(
        "UPDATE buckets SET versioning = :v, lifecycle_days = :d WHERE id = :b",
        {
            "v": 1 if s.versioning else 0,
            "d": s.lifecycle_days,
            "b": bid
        }
    )

    audit(
        email_of(uid),
        "BUCKET_SETTINGS",
        b["name"],
        f"versioning={s.versioning}, lifecycle={s.lifecycle_days}"
    )

    return {"ok": True}


# ======================= VERSIONS =======================

@app.get("/api/objects/{oid}/versions")
def list_versions(
    oid: int,
    uid: int = Depends(current_user)
):
    get_owned_object(oid, uid)

    rows = query(
        """SELECT id,
                  version_no,
                  size_bytes,
                  mime,
                  uploaded_at,
                  SUBSTR(sha256, 1, 10) AS sha_short
           FROM versions
           WHERE object_id = :o
           ORDER BY version_no DESC""",
        {"o": oid}
    )

    for i, r in enumerate(rows):
        r["is_latest"] = (i == 0)

    return rows


@app.post("/api/versions/{vid}/restore")
def restore(
    vid: int,
    uid: int = Depends(current_user)
):
    v = get_owned_version(vid, uid)
    bucket = get_owned_bucket(v["bucket_id"], uid)

    if not bucket["versioning"]:
        raise HTTPException(
            400,
            "Versioning is off for this bucket"
        )

    latest = query_one(
        "SELECT MAX(version_no) AS m FROM versions WHERE object_id = :o",
        {"o": v["object_id"]}
    )["m"]

    if v["version_no"] == latest:
        raise HTTPException(
            400,
            "That is already the current version"
        )

    r = restore_version(v, bucket)

    audit(
        email_of(uid),
        "RESTORE_VERSION",
        f"{bucket['name']}/{v['obj_key']}",
        f"v{v['version_no']} copied to new v{r['version_no']}"
    )

    return {"new_version": r["version_no"]}


@app.delete("/api/versions/{vid}")
def delete_version(
    vid: int,
    uid: int = Depends(current_user)
):
    v = get_owned_version(vid, uid)

    try:
        os.remove(v["path"])
    except FileNotFoundError:
        pass

    execute(
        "DELETE FROM versions WHERE id = :v",
        {"v": vid}
    )

    left = query_one(
        "SELECT COUNT(*) AS c FROM versions WHERE object_id = :o",
        {"o": v["object_id"]}
    )["c"]

    if left == 0:
        execute(
            "DELETE FROM objects WHERE id = :o",
            {"o": v["object_id"]}
        )

    audit(
        email_of(uid),
        "DELETE_VERSION",
        f"{v['obj_key']}@v{v['version_no']}"
    )

    return {
        "ok": True,
        "object_removed": left == 0
    }


# ======================= LIFECYCLE TIME MACHINE =======================

@app.post("/api/lifecycle/run")
def lifecycle(
    days: int = 0,
    dry_run: bool = False,
    uid: int = Depends(current_user)
):
    if days < 0 or days > 3650:
        raise HTTPException(
            400,
            "Days must be between 0 and 3650"
        )

    expired = run_lifecycle(
        simulate_days=days,
        uid=uid,
        dry_run=dry_run
    )

    audit(
        email_of(uid),
        "LIFECYCLE_PREVIEW" if dry_run else "LIFECYCLE_RUN",
        "-",
        f"simulated +{days} days, {len(expired)} version(s)"
    )

    return {
        "expired": expired,
        "dry_run": dry_run
    }

# ======================= SHARING (owner side) =======================

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ShareIn(BaseModel):
    recipient: str
    hours: int = 24
    max_views: int = 3
    send_email: bool = False


def share_state(s):
    """The one place that decides whether a link works right now."""
    if s["version_id"] is None:
        return "gone"

    if s["revoked"]:
        return "revoked"

    if int(s["expires_at"]) <= time.time():
        return "expired"

    if int(s["view_count"]) >= int(s["max_views"]):
        return "exhausted"

    return "active"


@app.post("/api/versions/{vid}/share")
def create_share(
    vid: int,
    s: ShareIn,
    uid: int = Depends(current_user)
):
    v = get_owned_version(vid, uid)
    bucket = get_owned_bucket(v["bucket_id"], uid)

    recipient = s.recipient.strip()[:255]

    if not recipient:
        raise HTTPException(
            400,
            "Enter a recipient name or email"
        )

    if not 1 <= s.hours <= 720:
        raise HTTPException(
            400,
            "Expiry must be between 1 and 720 hours"
        )

    if not 1 <= s.max_views <= 100:
        raise HTTPException(
            400,
            "Max views must be between 1 and 100"
        )

    label = (
        f"{bucket['name']}/{v['obj_key']}@v{v['version_no']}"
    )[:400]

    expires = int(time.time()) + s.hours * 3600

    sid = int(
        insert(
            """INSERT INTO shares(
                   version_id,
                   owner_id,
                   file_label,
                   recipient,
                   max_views,
                   expires_at
               )
               VALUES (
                   :v,
                   :o,
                   :l,
                   :r,
                   :m,
                   :e
               )
               RETURNING id INTO :new_id""",
            {
                "v": vid,
                "o": uid,
                "l": label,
                "r": recipient,
                "m": s.max_views,
                "e": expires
            }
        )
    )

    link = make_link(sid, expires)
    owner = email_of(uid)

    audit(
        owner,
        "CREATE_SHARE",
        label,
        f"share {sid} to {recipient}, "
        f"{s.hours}h, {s.max_views} views"
    )

    result = {
        "id": sid,
        "link": link,
        "expires_at": expires,
        "email_sent": False,
        "email_error": None
    }

    if s.send_email:

        if not EMAIL_RE.match(recipient):

            result["email_error"] = (
                "Recipient is not an email address"
            )

        else:

            try:

                send_share_mail(
                    recipient,
                    owner,
                    v["obj_key"],
                    link,
                    expires
                )

                result["email_sent"] = True

                audit(
                    owner,
                    "EMAIL_SHARE",
                    label,
                    f"share {sid} emailed to {recipient}"
                )

            except Exception as ex:

                result["email_error"] = str(ex)[:200]

    return result


@app.get("/api/shares")
def list_shares(
    uid: int = Depends(current_user)
):
    rows = query(
        """SELECT id,
                  recipient,
                  file_label,
                  max_views,
                  view_count,
                  expires_at,
                  revoked,
                  version_id,
                  created_at
           FROM shares
           WHERE owner_id = :u
           ORDER BY id DESC""",
        {"u": uid}
    )

    for r in rows:

        r["id"] = int(r["id"])
        r["expires_at"] = int(r["expires_at"])
        r["state"] = share_state(r)

        # Recomputed every time; never stored in Oracle.
        r["link"] = make_link(
            r["id"],
            r["expires_at"]
        )

    return rows


@app.post("/api/shares/{sid}/revoke")
def revoke_share(
    sid: int,
    uid: int = Depends(current_user)
):
    s = query_one(
        """SELECT id, recipient, file_label
           FROM shares
           WHERE id = :i
             AND owner_id = :u""",
        {
            "i": sid,
            "u": uid
        }
    )

    if not s:
        raise HTTPException(
            404,
            "Share not found"
        )

    execute(
        "UPDATE shares SET revoked = 1 WHERE id = :i",
        {"i": sid}
    )

    audit(
        email_of(uid),
        "REVOKE_SHARE",
        s["file_label"] or f"share {sid}",
        f"share {sid} to {s['recipient']}"
    )

    return {"ok": True}


# ======================= SHARING (recipient side, NO login) =======================

def _load_share(sid):
    return query_one(
        """SELECT s.id,
                  s.recipient,
                  s.file_label,
                  s.max_views,
                  s.view_count,
                  s.expires_at,
                  s.revoked,
                  s.version_id,
                  v.path,
                  v.mime,
                  o.obj_key
           FROM shares s
           LEFT JOIN versions v
             ON s.version_id = v.id
           LEFT JOIN objects o
             ON v.object_id = o.id
           WHERE s.id = :i""",
        {"i": sid}
    )


def _verified_share(sid, e, sig):
    """Signature first (cheap, no database).
    Same error for bad signature and no such share.
    """
    if not signature_ok(sid, e, sig):
        raise HTTPException(
            403,
            "This link is invalid"
        )

    s = _load_share(sid)

    if not s:
        raise HTTPException(
            403,
            "This link is invalid"
        )

    return s


@app.get("/v/{sid}")
def viewer_page(sid: int):

    # The page itself reveals nothing and counts nothing.
    return FileResponse(
        "static/view.html",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
        }
    )


@app.get("/api/s/{sid}/info")
def share_info(
    sid: int,
    e: int,
    sig: str
):
    s = _verified_share(
        sid,
        e,
        sig
    )

    state = share_state(s)

    out = {
        "state": state
    }

    if state == "active":

        out.update(
            file_name=s["obj_key"],
            kind=(
                "image"
                if s["mime"].startswith("image/")
                else "text"
            ),
            expires_at=int(s["expires_at"]),
            views_left=(
                int(s["max_views"])
                - int(s["view_count"])
            )
        )

    return out


@app.post("/api/s/{sid}/open")
def share_open(
    sid: int,
    e: int,
    sig: str,
    request: Request
):
    s = _verified_share(
        sid,
        e,
        sig
    )

    who = f"recipient:{s['recipient']}"
    label = s["file_label"] or f"share {sid}"

    ip = (
        request.client.host
        if request.client
        else "?"
    )

    # ONE atomic statement checks everything AND consumes a view.
    used = execute(
        """UPDATE shares
           SET view_count = view_count + 1
           WHERE id = :i
             AND revoked = 0
             AND version_id IS NOT NULL
             AND view_count < max_views
             AND expires_at > :now""",
        {
            "i": sid,
            "now": int(time.time())
        }
    )

    if used == 0:

        state = share_state(
            _load_share(sid)
        )

        audit(who, "VIEW_DENIED", label, f"share {sid}, {state}, ip={ip}")

        raise HTTPException(
            410,
            f"This link is no longer available ({state})"
        )

    try:

        with open(s["path"], "rb") as f:
            raw = f.read()

    except FileNotFoundError:

        execute(
            "UPDATE shares "
            "SET view_count = view_count - 1 "
            "WHERE id = :i",
            {"i": sid}
        )

        raise HTTPException(
            410,
            "The file is no longer available"
        )
        

    try:
        out, mime = personalise(raw, s["mime"], {"id": sid, "recipient": s["recipient"]})
    except Exception as ex:
        # fail CLOSED: never hand out an untraceable original, and don't burn the view
        execute("UPDATE shares SET view_count = view_count - 1 WHERE id = :i", {"i": sid})
        audit(who, "VIEW_ERROR", label, f"share {sid}: could not prepare file ({type(ex).__name__})")
        raise HTTPException(500, "Could not prepare the document. Your view was not used.")

    now = query_one(
        """SELECT view_count, max_views
           FROM shares
           WHERE id = :i""",
        {"i": sid}
    )

    left = (
        int(now["max_views"])
        - int(now["view_count"])
    )

    audit(
        who,
        "VIEW_SHARE",
        label,
        f"share {sid}, view {int(now['view_count'])}/{int(now['max_views'])}, ip={ip}, "
        f"ua={request.headers.get('user-agent', '-')[:80]}"
    )

    return Response(
        content=out,
        media_type=mime,
        headers={
            "X-Views-Left": str(left),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff"
        }
    )

# ======================= LEAK TRACER =======================

@app.post("/api/trace")
async def trace(file: UploadFile, uid: int = Depends(current_user)):
    data = await file.read()

    if not data:
        raise HTTPException(400, "File is empty")

    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File too large (max 10 MB)")

    name = os.path.basename(file.filename or "file")
    ext = os.path.splitext(name)[1].lower()

    try:
        if ext in (".png", ".jpg", ".jpeg", ".webp"):
            kind = "image"
            sid = extract_id(Image.open(io.BytesIO(data)))

        elif ext == ".txt":
            kind = "text"
            sid = extract_text(
                data.decode("utf-8", errors="ignore")
            )

        else:
            raise HTTPException(
                400,
                "The tracer supports PNG, JPG, WEBP and .txt files"
            )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            400,
            "Could not read that file"
        )

    owner = email_of(uid)

    # Only the OWNER of a share can trace it.
    s = None

    if sid is not None:
        s = query_one(
            """
            SELECT id, recipient, file_label, created_at,
                   max_views, view_count, expires_at,
                   revoked, version_id
            FROM shares
            WHERE id = :i
              AND owner_id = :u
            """,
            {
                "i": sid,
                "u": uid
            }
        )

    if not s:
        audit(
            owner,
            "TRACE",
            name,
            "no fingerprint found"
        )

        if kind == "image":
            hint = (
                "No hidden ID found. The image may be a screenshot, "
                "recompressed (WhatsApp, JPEG), cropped sideways, "
                "or an original that was never shared through VaultTrace. "
                "Check it by eye for the recipient's watermark."
            )
        else:
            hint = (
                "No hidden ID found. The text may have been retyped, "
                "passed through a tool that strips invisible characters, "
                "or is an original that was never shared through VaultTrace."
            )

        return {
            "found": False,
            "kind": kind,
            "hint": hint
        }

    views = query(
        """
        SELECT ts, details
        FROM audit_log
        WHERE action = 'VIEW_SHARE'
          AND details LIKE :p
        ORDER BY id
        """,
        {
            "p": f"share {sid},%"
        }
    )

    audit(
        owner,
        "TRACE",
        name,
        f"traced to share {sid} ({s['recipient']})"
    )

    s["id"] = int(s["id"])
    s["expires_at"] = int(s["expires_at"])

    return {
        "found": True,
        "kind": kind,
        "share_id": s["id"],
        "recipient": s["recipient"],
        "file_label": s["file_label"],
        "shared_at": s["created_at"],
        "state": share_state(s),
        "views": views
    }


# ======================= AUDIT LOG =======================

@app.get("/api/audit")
def audit_list(limit: int = 100, uid: int = Depends(current_user)):
    """Entries relevant to THIS user: their own actions, recipients opening THEIR shares,
    and lifecycle expiries in THEIR buckets. (The hash chain itself is global.)"""
    limit = max(1, min(limit, 500))
    return query(
        """SELECT id, ts, actor, action, target, details, SUBSTR(entry_hash, 1, 12) AS hash_short
           FROM audit_log
           WHERE actor = :email
              OR (actor LIKE 'recipient:%'
                  AND REGEXP_SUBSTR(details, '^share ([0-9]+)', 1, 1, NULL, 1)
                      IN (SELECT TO_CHAR(id) FROM shares WHERE owner_id = :u))
              OR (actor = 'system'
                  AND SUBSTR(target, 1, INSTR(target, '/') - 1)
                      IN (SELECT name FROM buckets WHERE user_id = :u))
           ORDER BY id DESC
           FETCH FIRST :lim ROWS ONLY""",
        {"email": email_of(uid), "u": uid, "lim": limit})


@app.get("/api/audit/verify")
def audit_verify(cp_id: Optional[int] = None, cp_hash: Optional[str] = None,
                 uid: int = Depends(current_user)):
    res = verify_chain(cp_id, cp_hash)
    audit(
        email_of(uid),
        "AUDIT_VERIFY",
        "-",
        "OK" if res["ok"] else f"FAILED: {res.get('reason')}"
    )
    return res

# IMPORTANT: keep this LAST so it doesn't swallow the /api routes
app.mount(
    "/",
    StaticFiles(
        directory="static",
        html=True
    ),
    name="static"
)