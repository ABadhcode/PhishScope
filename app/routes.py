import json
from flask import Blueprint, render_template, request, redirect, url_for, flash
from .db import get_db
from .services.email_parser import parse_eml
from .services.analyzer import analyze_email
from .services.url_analyzer import analyze_url

bp = Blueprint("main", __name__)

@bp.get("/")
def dashboard():
    db = get_db()
    cases = db.execute("SELECT * FROM cases ORDER BY created_at DESC LIMIT 20").fetchall()
    db.close()
    return render_template("dashboard.html", cases=cases)

@bp.get("/investigate")
def investigate():
    return render_template("investigate.html")

@bp.post("/investigate/email")
def investigate_email():
    file = request.files.get("email_file")
    if not file or not file.filename.lower().endswith(".eml"):
        flash("Please upload a valid .eml file.", "error")
        return redirect(url_for("main.investigate"))

    data = parse_eml(file.read())
    score, verdict, findings = analyze_email(data)

    db = get_db()
    cur = db.execute(
        """INSERT INTO cases
        (case_type, target, subject, risk_score, verdict, findings)
        VALUES (?, ?, ?, ?, ?, ?)""",
        ("Email", data.get("from", ""), data.get("subject", ""),
         score, verdict, json.dumps(findings))
    )
    case_id = cur.lastrowid
    db.commit()
    db.close()
    return redirect(url_for("main.case", case_id=case_id))

@bp.post("/investigate/url")
def investigate_url():
    raw_url = request.form.get("url", "").strip()
    if not raw_url:
        flash("Enter a URL to analyze.", "error")
        return redirect(url_for("main.investigate"))

    result = analyze_url(raw_url)

    db = get_db()
    cur = db.execute(
        """INSERT INTO cases
        (case_type, target, subject, risk_score, verdict, findings)
        VALUES (?, ?, ?, ?, ?, ?)""",
        ("URL", result["url"], result["hostname"],
         result["score"], result["verdict"], json.dumps(result["findings"]))
    )
    case_id = cur.lastrowid
    db.commit()
    db.close()
    return redirect(url_for("main.case", case_id=case_id))

@bp.route("/case/<int:case_id>", methods=["GET", "POST"])
def case(case_id):
    db = get_db()
    if request.method == "POST":
        notes = request.form.get("notes", "")
        status = request.form.get("status", "Open")
        db.execute("UPDATE cases SET notes=?, status=? WHERE id=?", (notes, status, case_id))
        db.commit()

    row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    db.close()
    if not row:
        return "Case not found", 404

    case_data = dict(row)
    case_data["findings"] = json.loads(case_data["findings"])
    return render_template("case.html", case=case_data)
