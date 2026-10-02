from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
import re


URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def text(self):
        return " ".join(self.parts)


def _extract_body(message):
    plain = []
    html = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and isinstance(content, str):
                plain.append(content)
            elif ctype == "text/html" and isinstance(content, str):
                parser = TextExtractor()
                parser.feed(content)
                html.append(parser.text())
    else:
        content = message.get_content()
        if isinstance(content, str):
            if message.get_content_type() == "text/html":
                parser = TextExtractor()
                parser.feed(content)
                html.append(parser.text())
            else:
                plain.append(content)

    return "\n".join(plain or html)


def parse_eml(file_bytes):
    message = BytesParser(policy=policy.default).parsebytes(file_bytes)

    sender = parseaddr(message.get("From", ""))[1] or message.get("From", "")
    recipient = parseaddr(message.get("To", ""))[1] or message.get("To", "")

    body = _extract_body(message)
    urls = sorted(set(URL_RE.findall(body)))
    emails = sorted(set(EMAIL_RE.findall(body)))

    headers = {
        "from": message.get("From", ""),
        "return_path": message.get("Return-Path", ""),
        "reply_to": message.get("Reply-To", ""),
        "message_id": message.get("Message-ID", ""),
        "authentication_results": " | ".join(message.get_all("Authentication-Results", [])),
        "received_spf": " | ".join(message.get_all("Received-SPF", [])),
        "date": message.get("Date", ""),
    }

    attachments = []
    for part in message.iter_attachments():
        attachments.append({
            "filename": part.get_filename() or "unnamed",
            "content_type": part.get_content_type(),
        })

    return {
        "subject": message.get("Subject", "(no subject)"),
        "sender": sender,
        "recipient": recipient,
        "body": body,
        "urls": urls,
        "emails": emails,
        "headers": headers,
        "attachments": attachments,
    }
