from app.services.analyzer import analyze


def test_auth_failures_raise_score():
    parsed = {
        "sender": "security@example.com",
        "body": "urgent verify password immediately",
        "urls": [],
        "emails": [],
        "attachments": [],
        "headers": {
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "received_spf": "",
            "return_path": "<mailer@other.example>",
            "reply_to": "",
        },
    }

    result = analyze(parsed)

    assert result["score"] >= 50
    assert result["verdict"] in {"Suspicious", "High risk"}
