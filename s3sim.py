import io
import os

import hashlib
from fastapi import HTTPException
from PIL import Image

from config import STORAGE_DIR
from db import query, query_one, execute, insert
from audit import audit

ALLOWED_MIME = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "text/plain"
}

ALLOWED_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".txt"
}

MAX_BYTES = 10_000_000  # 10 MB


# ---------- ownership checks ----------
# Every query is tied to the logged-in user.

def get_owned_bucket(bucket_id, uid):
    b = query_one(
        "SELECT * FROM buckets WHERE id = :b AND user_id = :u",
        {"b": bucket_id, "u": uid}
    )

    if not b:
        raise HTTPException(404, "Bucket not found")

    return b


def get_owned_object(object_id, uid):
    o = query_one(
        """
        SELECT o.*
        FROM objects o
        JOIN buckets b ON o.bucket_id = b.id
        WHERE o.id = :o AND b.user_id = :u
        """,
        {"o": object_id, "u": uid}
    )

    if not o:
        raise HTTPException(404, "File not found")

    return o


def get_owned_version(version_id, uid):
    v = query_one(
        """
        SELECT v.*, o.obj_key, o.bucket_id
        FROM versions v
        JOIN objects o ON v.object_id = o.id
        JOIN buckets b ON o.bucket_id = b.id
        WHERE v.id = :v AND b.user_id = :u
        """,
        {"v": version_id, "u": uid}
    )

    if not v:
        raise HTTPException(404, "Version not found")

    return v


# ---------- validation ----------

def validate_content(data: bytes, mime: str):
    """Make sure the bytes really are what the type claims."""

    try:
        if mime.startswith("image/"):
            Image.open(io.BytesIO(data)).verify()
        else:
            data.decode("utf-8")

    except Exception:
        raise HTTPException(
            400,
            "File content does not match its type"
        )


# ---------- storage operations ----------

def delete_all_versions(object_id):
    """Remove every version of an object (files on disk + rows)."""

    for v in query(
        "SELECT path FROM versions WHERE object_id = :o",
        {"o": object_id}
    ):
        try:
            os.remove(v["path"])
        except FileNotFoundError:
            pass

    execute(
        "DELETE FROM versions WHERE object_id = :o",
        {"o": object_id}
    )


def put_object(bucket, filename, data: bytes, mime: str):
    """
    Save a file into a bucket.

    Creates a new version when versioning is ON.
    Overwrites when versioning is OFF.
    """

    bucket_id = int(bucket["id"])

    obj = query_one(
        """
        SELECT id
        FROM objects
        WHERE bucket_id = :b AND obj_key = :k
        """,
        {
            "b": bucket_id,
            "k": filename
        }
    )

    if obj:
        object_id = int(obj["id"])

    else:
        object_id = int(
            insert(
                """
                INSERT INTO objects(bucket_id, obj_key)
                VALUES (:b, :k)
                RETURNING id INTO :new_id
                """,
                {
                    "b": bucket_id,
                    "k": filename
                }
            )
        )

    # Versioning OFF = overwrite
    if not bucket["versioning"]:
        delete_all_versions(object_id)

    last = query_one(
        """
        SELECT NVL(MAX(version_no), 0) AS m
        FROM versions
        WHERE object_id = :o
        """,
        {"o": object_id}
    )["m"]

    ver_no = int(last) + 1

    # Store files under IDs, never under the user's filename.
    # This prevents path traversal such as ../../etc/passwd.
    folder = os.path.join(
        STORAGE_DIR,
        str(bucket_id),
        str(object_id)
    )

    os.makedirs(folder, exist_ok=True)

    path = os.path.join(
        folder,
        f"v{ver_no}"
    )

    with open(path, "wb") as f:
        f.write(data)

    sha = hashlib.sha256(data).hexdigest()

    version_id = int(
        insert(
            """
            INSERT INTO versions(
                object_id,
                version_no,
                path,
                size_bytes,
                mime,
                sha256
            )
            VALUES (
                :o,
                :n,
                :p,
                :s,
                :m,
                :h
            )
            RETURNING id INTO :new_id
            """,
            {
                "o": object_id,
                "n": ver_no,
                "p": path,
                "s": len(data),
                "m": mime,
                "h": sha
            }
        )
    )

    return {
        "object_id": object_id,
        "version_id": version_id,
        "version_no": ver_no,
        "sha256": sha
    }
def restore_version(v, bucket):
    """Restore = copy an old version's bytes into a NEW latest version.
    History is never rewritten (this is how S3 does it too)."""
    with open(v["path"], "rb") as f:
        data = f.read()
    return put_object(bucket, v["obj_key"], data, v["mime"])


def run_lifecycle(simulate_days=0, uid=None, dry_run=False):
    """Delete versions older than their bucket's auto-delete rule.

    simulate_days pretends that many extra days have passed (the demo time machine).
    dry_run=True only reports what WOULD expire, without deleting anything.
    """
    sql = "SELECT id, name, lifecycle_days FROM buckets WHERE lifecycle_days IS NOT NULL"
    params = {}

    if uid is not None:
        sql += " AND user_id = :u"
        params["u"] = uid

    expired = []

    for b in query(sql, params):
        # A version expires when:
        # age > rule  <=>  age + simulated > rule
        limit_days = int(b["lifecycle_days"]) - int(simulate_days)

        old = query(
            """SELECT v.id, v.path, v.version_no, o.obj_key
               FROM versions v JOIN objects o ON v.object_id = o.id
               WHERE o.bucket_id = :b
                 AND v.uploaded_at < CAST(SYSTIMESTAMP AS TIMESTAMP)
                     - NUMTODSINTERVAL(:lim, 'DAY')
               ORDER BY v.id""",
            {"b": b["id"], "lim": limit_days}
        )

        for v in old:
            expired.append({
                "bucket": b["name"],
                "key": v["obj_key"],
                "version": v["version_no"]
            })

            if dry_run:
                continue

            try:
                os.remove(v["path"])
            except FileNotFoundError:
                pass

            execute(
                "DELETE FROM versions WHERE id = :v",
                {"v": v["id"]}
            )

            audit(
                "system",
                "LIFECYCLE_EXPIRE",
                f"{b['name']}/{v['obj_key']}@v{v['version_no']}",
                f"rule={b['lifecycle_days']}d, simulated +{simulate_days}d"
            )

        if not dry_run:
            # An object with no versions left no longer exists.
            execute(
                """DELETE FROM objects o
                   WHERE o.bucket_id = :b
                     AND NOT EXISTS (
                         SELECT 1 FROM versions x
                         WHERE x.object_id = o.id
                     )""",
                {"b": b["id"]}
            )

    return expired

