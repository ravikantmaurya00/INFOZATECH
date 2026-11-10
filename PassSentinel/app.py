"""Flask backend for PassSentinel, the Intelligent Password Strength Analyzer.

Privacy rules: passwords are analysed in memory and never stored or logged.
Only an anonymous rating bucket and bit count are saved for the stats panel.
The breach check uses k-anonymity: the browser sends only the first 5 hex
characters of a SHA-1 hash, and the match happens in the browser.
"""
import os
import re
import secrets
import sqlite3
import string
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from analyzer import analyze, rate

BASE = Path(__file__).parent
DB = Path(os.environ.get("DB_PATH", BASE / "stats.db"))
LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096


def db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY, bucket INTEGER, bits REAL, ts DATETIME DEFAULT CURRENT_TIMESTAMP)")
    return con


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    pw = str((request.get_json(silent=True) or {}).get("password", ""))[:256]
    return jsonify(analyze(pw))


@app.post("/api/record")
def api_record():
    """Store an anonymous bit count (never the password)."""
    bits = float((request.get_json(silent=True) or {}).get("bits", 0))
    if bits <= 0:
        return jsonify(ok=False), 400
    with db() as con:
        con.execute("INSERT INTO checks (bucket, bits) VALUES (?, ?)", (rate(bits), min(bits, 400)))
    return jsonify(ok=True)


@app.get("/api/breach/<prefix>")
def api_breach(prefix):
    """Proxy for the Have I Been Pwned range API (k-anonymity)."""
    if not re.fullmatch(r"[0-9A-Fa-f]{5}", prefix):
        return Response("bad prefix", 400)
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix.upper()}",
        headers={"User-Agent": "PassSentinel", "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return Response(r.read(), mimetype="text/plain")
    except (urllib.error.URLError, TimeoutError):
        return Response("breach service unreachable", 503)


@app.get("/api/generate")
def api_generate():
    length = max(8, min(int(request.args.get("length", 18)), 64))
    pools = [string.ascii_lowercase]
    if request.args.get("upper", "1") == "1": pools.append(string.ascii_uppercase)
    if request.args.get("digits", "1") == "1": pools.append(string.digits)
    if request.args.get("symbols", "1") == "1": pools.append("!@#$%^&*()-_=+[]{};:,.?")
    allchars = "".join(pools)
    chars = [secrets.choice(p) for p in pools]                       # one of each class
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return jsonify(password="".join(chars))


@app.get("/api/stats")
def api_stats():
    with db() as con:
        rows = dict(con.execute("SELECT bucket, COUNT(*) FROM checks GROUP BY bucket").fetchall())
        avg = con.execute("SELECT AVG(bits) FROM checks").fetchone()[0] or 0
    counts = [rows.get(i, 0) for i in range(5)]
    return jsonify(labels=LABELS, counts=counts, total=sum(counts), avg_bits=round(avg, 1))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=int(os.environ.get("PORT", 5000)))
