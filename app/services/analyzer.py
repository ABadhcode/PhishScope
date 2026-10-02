from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "click", "work", "support", "rest", "cam", "xyz", "live"
}

PRESSURE_WORDS = {
    "urgent", "immediately", "verify", "suspended", "expire", "password",
    "invoice", "payment", "click", "login", "security alert", "unusual activity"
}

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".img", ".lnk"
}


def _domain(email_address):
    if "@" not in email_address:
        return ""
    return email_address.rsplit("@", 1)[-1].lower().strip(">")


def _url_features(url):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []

    try:
        ipaddress.ip_address(host)
        findings.append(("IP address used as hostname", 18))
    except ValueError:
        pass

    if "xn--" in host:
        findings.append(("Punycode domain detected", 18))

    if host.count(".") >= 4:
        findings.append(("Unusually deep subdomain structure", 8))

    if "@" in url:
        findings.append(("URL contains @ symbol", 12))

    if len(url) > 120:
        findings.append(("Very long URL", 7))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append((f"High-risk TLD: .{tld}", 8))

    return findings


def analyze(parsed):
    findings = []
    score = 0

    headers = parsed["headers"]
    auth = (headers.get("authentication_results") or "").lower()
    spf = (headers.get("received_spf") or "").lower()

    if "spf=fail" in auth or "fail" in spf:
        findings.append(("SPF authentication failed", 20, "email-auth"))
    elif "spf=softfail" in auth or "softfail" in spf:
        findings.append(("SPF softfail reported", 10, "email-auth"))

    if "dkim=fail" in auth:
        findings.append(("DKIM authentication failed", 15, "email-auth"))

    if "dmarc=fail" in auth:
        findings.append(("DMARC authentication failed", 20, "email-auth"))

    from_domain = _domain(parsed["sender"])
    return_domain = _domain(headers.get("return_path", ""))
    reply_domain = _domain(headers.get("reply_to", ""))

    if from_domain and return_domain and from_domain != return_domain:
        findings.append(("From and Return-Path domains differ", 10, "header"))

    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(("Reply-To points to a different domain", 12, "header"))

    for url in parsed["urls"][:20]:
        for label, weight in _url_features(url):
            findings.append((f"{label}: {url}", weight, "url"))

        host = (urlparse(url).hostname or "").lower()
        if from_domain and host and not (host == from_domain or host.endswith("." + from_domain)):
            findings.append((f"Linked domain differs from sender domain: {host}", 6, "url"))

    body_lower = parsed["body"].lower()
    pressure_hits = sorted({word for word in PRESSURE_WORDS if word in body_lower})
    if len(pressure_hits) >= 2:
        findings.append((
            "Urgency / credential-pressure language: " + ", ".join(pressure_hits[:6]),
            min(14, 3 * len(pressure_hits)),
            "content"
        ))

    for attachment in parsed["attachments"]:
        name = attachment["filename"].lower()
        for ext in RISKY_ATTACHMENT_EXTENSIONS:
            if name.endswith(ext):
                findings.append((f"Potentially risky attachment type: {attachment['filename']}", 20, "attachment"))
                break

    for _, weight, _ in findings:
        score += weight

    score = min(score, 100)

    if score >= 70:
        verdict = "High risk"
    elif score >= 40:
        verdict = "Suspicious"
    elif score >= 20:
        verdict = "Needs review"
    else:
        verdict = "Low risk"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "ioc_count": len(parsed["urls"]) + len(parsed["emails"]),
    }
