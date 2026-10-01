import os
import imaplib
import email
import re
from dotenv import load_dotenv

load_dotenv()

EMAIL = os.getenv("GMAIL_ADDRESS")
APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
mail.login(EMAIL, APP_PASSWORD)

print("Gmail connection successful!")

# Inbox select
mail.select("INBOX")

# Search emails containing CVE
status, messages = mail.search(
    None,
    '(OR SUBJECT "CVE" BODY "CVE-")'
)

if status != "OK":
    print("Could not search Gmail.")
    mail.logout()
    raise SystemExit

email_ids = messages[0].split()

print(f"CVE-related emails found: {len(email_ids)}")

for email_id in email_ids:
    status, data = mail.fetch(email_id, "(RFC822)")

    if status != "OK":
        continue

    raw_email = data[0][1]
    msg = email.message_from_bytes(raw_email)

    subject = msg.get("Subject", "")
    sender = msg.get("From", "")

    # Search CVE IDs such as CVE-2026-12345
    text = subject

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    text += "\n" + part.get_payload(
                        decode=True
                    ).decode(errors="ignore")
                except Exception:
                    pass
    else:
        try:
            text += "\n" + msg.get_payload(
                decode=True
            ).decode(errors="ignore")
        except Exception:
            pass

    cves = sorted(set(
        re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    ))

    if cves:
        print("\n------------------------------")
        print("CVE EMAIL FOUND")
        print("From:", sender)
        print("Subject:", subject)
        print("CVE IDs:", ", ".join(cves))

mail.logout()

print("\nCVE email scan completed.")
