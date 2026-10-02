# PhishScope

PhishScope is a small phishing-triage web application built for SOC analyst practice. It accepts `.eml` files, extracts common indicators, evaluates selected email-authentication and URL characteristics, and stores a case record for analyst review.

The project intentionally does **not** visit extracted URLs or execute attachments.

## Why I built it

Phishing investigations are a common SOC workflow. I wanted a project that demonstrates more than a static threat score: parsing evidence, documenting why a message is suspicious, preserving IOCs, and recording an analyst disposition.

## Features

- Parse RFC 822 / `.eml` files
- Extract sender, recipient, subject, URLs, email addresses, and attachment metadata
- Inspect SPF / DKIM / DMARC results when present in message headers
- Detect basic sender / Return-Path / Reply-To mismatches
- Identify selected suspicious URL characteristics
- Flag potentially risky attachment extensions
- Generate an explainable rule-based risk score
- Create a local investigation case with analyst notes and status
- SQLite case storage
- No automatic URL fetching

## Stack

- Python
- Flask
- SQLite
- Jinja
- HTML / CSS

## Run locally

```bash
python -m venv .venv
```

Activate the environment, then install dependencies:

```bash
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`.

## Deploy

### Render

1. Push this repository to GitHub.
2. Create a new **Web Service** on Render.
3. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn run:app`
4. Deploy.

For a public deployment, move the database to persistent storage or use a managed database.

## Scoring model

The score is intentionally transparent rather than ML-based. Every triggered rule produces a visible finding and a fixed weight. A message can therefore be reviewed without treating the score as ground truth.

Examples include:

- SPF / DKIM / DMARC failures
- From / Return-Path mismatch
- Reply-To mismatch
- IP-address URLs
- Punycode domains
- Very long URLs
- Selected risky TLDs
- Urgency / credential-pressure language
- Risky attachment extensions

This is a triage aid, not a replacement for manual analysis.

## Security choices

- Maximum upload size is 2 MB
- Uploaded messages are parsed in memory
- Extracted URLs are displayed as text only
- Attachments are never written to disk or executed
- Jinja auto-escaping is used for rendered content
- No remote enrichment is enabled by default

## Ideas for a second version

- VirusTotal or URLhaus enrichment through optional API keys
- WHOIS / domain-age context
- MISP export
- STIX 2.1 IOC export
- Authentication-Results parser with structured SPF/DKIM/DMARC evidence
- User authentication and analyst ownership
- PostgreSQL for production deployments
- Docker packaging

## Resume description

**PhishScope — Phishing Investigation & Triage Platform**

Built a Flask-based phishing investigation application that parses `.eml` files, extracts IOCs and email authentication evidence, evaluates explainable phishing indicators, assigns a triage risk score, and supports SOC-style case notes and disposition tracking. Designed the workflow to avoid automatically visiting suspicious links or executing attachments.

## Disclaimer

Use this project only for defensive security analysis and training with email samples you are authorized to inspect.
