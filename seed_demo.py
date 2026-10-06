import io
import os
from PIL import Image, ImageDraw

from auth import hash_pw
from db import query_one, insert
from s3sim import put_object
from audit import audit
from fingerprint import _font

EMAIL = "demo@vaulttrace.app"
PASSWORD = os.environ.get("DEMO_PASSWORD", "demo1234")

u = query_one("SELECT id FROM users WHERE email = :e", {"e": EMAIL})
if u:
    uid = int(u["id"])
else:
    uid = int(insert(
        "INSERT INTO users(email, password_hash) VALUES (:e, :p) RETURNING id INTO :new_id",
        {"e": EMAIL, "p": hash_pw(PASSWORD)}))
    audit(EMAIL, "REGISTER", f"user {uid}", "seeded demo account")

bucket = query_one("SELECT * FROM buckets WHERE user_id = :u AND name = 'hr-documents'", {"u": uid})
if not bucket:
    insert("""INSERT INTO buckets(user_id, name, versioning, lifecycle_days)
              VALUES (:u, 'hr-documents', 1, 30) RETURNING id INTO :new_id""", {"u": uid})
    bucket = query_one("SELECT * FROM buckets WHERE user_id = :u AND name = 'hr-documents'", {"u": uid})


def missing(key):
    return not query_one("SELECT id FROM objects WHERE bucket_id = :b AND obj_key = :k",
                         {"b": int(bucket["id"]), "k": key})


if missing("offer-letter.txt"):
    text = ("CONFIDENTIAL - OFFER LETTER\n\n"
            "Dear Candidate, we are pleased to offer you the position of Software Engineer.\n"
            "Your annual compensation will be as discussed during the final interview round.\n"
            "Please keep this letter private until your joining date is confirmed in writing.\n"
            "This document is shared with you through a secure, access-controlled link.\n"
            "Do not forward it to anyone outside your immediate family.\n")
    r = put_object(bucket, "offer-letter.txt", text.encode(), "text/plain")
    audit(EMAIL, "PUT_OBJECT", f"hr-documents/offer-letter.txt@v{r['version_no']}", "seeded")

if missing("marksheet.png"):
    img = Image.new("RGB", (900, 520))
    d = ImageDraw.Draw(img)
    for y in range(520):
        d.line([(0, y), (900, y)], fill=(30, 41 + y // 12, 82 + y // 8))
    d.text((50, 60), "CONFIDENTIAL - SEMESTER MARKSHEET", font=_font(30), fill=(255, 255, 255))
    for i, line in enumerate(["Name: Demo Student", "Register No: 24XXX0000", "CGPA: 9.1",
                              "Result: PASS WITH DISTINCTION"]):
        d.text((50, 150 + i * 60), line, font=_font(26), fill=(230, 235, 255))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    r = put_object(bucket, "marksheet.png", buf.getvalue(), "image/png")
    audit(EMAIL, "PUT_OBJECT", f"hr-documents/marksheet.png@v{r['version_no']}", "seeded")

print(f"Seeded. Log in as {EMAIL} with password '{PASSWORD}'.")
print("On a public server, set DEMO_PASSWORD to something strong, and delete this account afterwards.")