from email import policy
from email.parser import BytesParser
import re

URL_RE = re.compile(r"""https?://[^\s<>"']+""")


def parse_eml(data: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(data)

    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""

    urls = URL_RE.findall(text)

    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "urls": urls,
        "attachments": [
            part.get_filename()
            for part in msg.walk()
            if part.get_filename()
        ],
    }