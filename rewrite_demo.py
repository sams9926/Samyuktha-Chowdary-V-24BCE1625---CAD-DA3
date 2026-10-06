"""Edit an old audit entry AND recompute every hash after it, like an attacker who
understands the scheme. Usage:  python rewrite_demo.py <entry_id> <new_actor>"""
import sys
from db import query, execute
from audit import _hash

target_id, new_actor = int(sys.argv[1]), sys.argv[2]

prev = "GENESIS"

for r in query("SELECT * FROM audit_log ORDER BY id"):
    actor = new_actor if int(r["id"]) == target_id else r["actor"]

    h = _hash(
        prev,
        r["ts"],
        actor,
        r["action"],
        r["target"],
        r["details"]
    )

    execute(
        "UPDATE audit_log SET actor = :a, prev_hash = :p, entry_hash = :h WHERE id = :i",
        {
            "a": actor,
            "p": prev,
            "h": h,
            "i": int(r["id"])
        }
    )

    prev = h

print("Chain rewritten consistently from the start.")