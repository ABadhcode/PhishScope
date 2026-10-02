from urllib.parse import urlparse, parse_qs, unquote
import ipaddress
import re

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "support", "live", "buzz", "shop"
}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "password", "account", "secure",
    "update", "signin", "wallet", "payment", "invoice", "refund",
    "confirm", "credential", "mfa", "unlock"
}
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "continue", "return", "dest"}

def analyze_url(raw_url: str):
    url = raw_url.strip()
    findings = []
    score = 0

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    path_query = unquote((parsed.path or "") + ("?" + parsed.query if parsed.query else ""))

    if not host:
        return {"url": url, "score": 100, "verdict": "Invalid URL", "findings": ["The URL does not contain a valid hostname."]}

    try:
        ipaddress.ip_address(host)
        findings.append("Hostname is an IP address rather than a domain.")
        score += 25
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("Punycode is present in the hostname.")
        score += 25

    if "@" in url:
        findings.append("URL contains '@', which can obscure the real destination.")
        score += 20

    if len(url) > 120:
        findings.append("URL is unusually long.")
        score += 10
    elif len(url) > 80:
        findings.append("URL is longer than typical.")
        score += 5

    labels = host.split(".")
    if len(labels) >= 4:
        findings.append("Hostname contains many subdomain levels.")
        score += 10

    tld = labels[-1] if len(labels) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(f"Top-level domain '.{tld}' is commonly seen in suspicious or abuse-prone URLs.")
        score += 10

    if scheme != "https":
        findings.append("URL does not use HTTPS.")
        score += 10

    keyword_hits = sorted({k for k in SUSPICIOUS_KEYWORDS if k in path_query.lower()})
    if keyword_hits:
        findings.append("Suspicious URL keywords detected: " + ", ".join(keyword_hits))
        score += min(20, 5 * len(keyword_hits))

    params = set(parse_qs(parsed.query).keys())
    redirect_hits = sorted(params & REDIRECT_PARAMS)
    if redirect_hits:
        findings.append("Redirect-style query parameters detected: " + ", ".join(redirect_hits))
        score += 10

    if "%" in url:
        findings.append("Encoded characters are present in the URL.")
        score += 5

    if parsed.port not in (None, 80, 443):
        findings.append(f"Non-standard destination port detected: {parsed.port}.")
        score += 15

    score = min(100, score)
    if score >= 60:
        verdict = "High Risk"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "findings": findings or ["No obvious structural phishing indicators were detected by the passive checks."],
        "hostname": host,
        "scheme": scheme,
        "path": parsed.path or "/",
        "host_is_ip": host_is_ip,
        "length": len(url),
    }
