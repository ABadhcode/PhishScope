from urllib.parse import urlparse
import re

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".zip", ".iso"}
URGENT_WORDS = {"urgent", "immediately", "suspended", "verify", "expire", "locked", "action required"}

def analyze_email(data):
    score = 0
    findings = []

    auth = (data.get("authentication_results", "") + " " + data.get("received_spf", "")).lower()
    for item in ("spf", "dkim", "dmarc"):
        if f"{item}=fail" in auth or f"{item}: fail" in auth:
            findings.append(f"{item.upper()} authentication failure detected.")
            score += 15

    frm = data.get("from", "").lower()
    rp = data.get("return_path", "").lower()
    if frm and rp and frm.split("@")[-1].strip("> ") != rp.split("@")[-1].strip("> "):
        findings.append("From and Return-Path domains do not match.")
        score += 15

    reply = data.get("reply_to", "").lower()
    if reply and frm and reply.split("@")[-1].strip("> ") != frm.split("@")[-1].strip("> "):
        findings.append("Reply-To and From domains do not match.")
        score += 15

    body_words = " ".join(data.get("urls", [])).lower()
    if any(word in body_words for word in URGENT_WORDS):
        findings.append("Urgency or account-action language appears in extracted URLs.")
        score += 10

    for url in data.get("urls", []):
        p = urlparse(url)
        host = p.hostname or ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            findings.append(f"URL uses an IP address: {host}")
            score += 20
        if "xn--" in host:
            findings.append("Punycode detected in an extracted URL.")
            score += 20

    for name in data.get("attachments", []):
        if any(name.lower().endswith(ext) for ext in RISKY_EXTENSIONS):
            findings.append(f"Potentially risky attachment type: {name}")
            score += 15

    score = min(score, 100)
    verdict = "High Risk" if score >= 60 else "Suspicious" if score >= 30 else "Low Risk"
    return score, verdict, findings or ["No strong indicators detected by the current rule set."]
