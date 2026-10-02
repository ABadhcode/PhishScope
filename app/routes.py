import json
from flask import Blueprint, render_template, request, redirect, url_for, abort
from .db import get_db
from .services.email_parser import parse_eml
from .services.analyzer import analyze

bp = Blueprint("main", __name__)


@bp.route("/")
def dashboard():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM investigations ORDER BY id DESC LIMIT 10"
    ).fetchall()
    stats = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN verdict = 'High risk' THEN 1 ELSE 0 END) AS high_risk,
            SUM(CASE WHEN status != 'Closed' THEN 1 ELSE 0 END) AS open_cases
        FROM investigations
        """
    ).fetchone()
    return render_template("dashboard.html", rows=rows, stats=stats)


@bp.route("/investigate", methods=["GET", "POST"])
def investigate():
    if request.method == "GET":
        return render_template("investigate.html")

    uploaded = request.files.get("eml_file")
    if not uploaded or not uploaded.filename.lower().endswith(".eml"):
        return render_template("investigate.html", error="Upload a valid .eml file.")

    parsed = parse_eml(uploaded.read())
    result = analyze(parsed)

    indicators = {
        "urls": parsed["urls"],
        "emails": parsed["emails"],
        "attachments": parsed["attachments"],
        "findings": result["findings"],
        "headers": parsed["headers"],
    }

    summary = (
        f"{result['verdict']} email with {len(parsed['urls'])} URL(s), "
        f"{len(parsed['attachments'])} attachment(s), and "
        f"{len(result['findings'])} notable finding(s)."
    )

    db = get_db()
    cur = db.execute(
        """
        INSERT INTO investigations
        (subject, sender, recipient, score, verdict, summary, indicators)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            parsed["subject"],
            parsed["sender"],
            parsed["recipient"],
            result["score"],
            result["verdict"],
            summary,
            json.dumps(indicators),
        ),
    )
    db.commit()
    return redirect(url_for("main.case_detail", case_id=cur.lastrowid))


@bp.route("/case/<int:case_id>", methods=["GET", "POST"])
def case_detail(case_id):
    db = get_db()

    if request.method == "POST":
        status = request.form.get("status", "Open")
        notes = request.form.get("notes", "").strip()

        if status not in {"Open", "Investigating", "Closed"}:
            abort(400)

        db.execute(
            "UPDATE investigations SET status = ?, notes = ? WHERE id = ?",
            (status, notes, case_id),
        )
        db.commit()

    row = db.execute(
        "SELECT * FROM investigations WHERE id = ?", (case_id,)
    ).fetchone()

    if row is None:
        abort(404)

    data = dict(row)
    data["indicators"] = json.loads(data["indicators"])
    return render_template("case.html", case=data)
