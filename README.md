# PhishScope

PhishScope is a small SOC-style phishing investigation and triage platform.

## Investigation modes

- Email triage: upload `.eml` files and inspect headers, authentication evidence, URLs and attachments.
- URL triage: paste a suspicious URL and perform passive structural analysis.
- Risk scoring with explainable findings.
- Case history, analyst notes and status tracking.

## Safety

PhishScope never visits submitted URLs and never executes attachments. URL analysis is local parsing only.

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:5000

## Resume description

Built a Flask-based phishing investigation and triage platform that analyzes `.eml` files and suspicious URLs using explainable indicators, risk scoring and SOC-style case tracking. Designed the workflow to avoid automatically visiting suspicious links or executing attachments.
