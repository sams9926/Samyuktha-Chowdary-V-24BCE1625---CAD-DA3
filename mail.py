import smtplib
from datetime import datetime
from email.message import EmailMessage

from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD


def send_share_mail(to, owner_email, file_name, link, expires_at):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError(
            "Email is not configured (set SMTP_USER and SMTP_PASSWORD)"
        )

    when = datetime.fromtimestamp(expires_at).strftime(
        "%d %b %Y, %H:%M"
    )

    msg = EmailMessage()

    msg["Subject"] = "A secure document was shared with you"
    msg["From"] = SMTP_USER
    msg["To"] = to
    msg["Reply-To"] = owner_email

    msg.set_content(
        f"{owner_email} shared a document with you: {file_name}\n\n"
        f"Open it here (limited views, expires {when}):\n"
        f"{link}\n\n"
        "This link is personal to you and every access is logged."
    )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        timeout=15
    ) as s:
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.send_message(msg)
        