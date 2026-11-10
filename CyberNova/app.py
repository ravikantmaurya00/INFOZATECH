import os
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

import crypto_core as cc

BASE = Path(__file__).resolve().parent
# Use ./static if it exists; otherwise fall back to the app folder (files saved flat).
WEB_DIR = BASE / "static" if (BASE / "static" / "index.html").exists() else BASE
PORT = int(os.environ.get("PORT", 5050))  # 5050 avoids clashes with other tools using 5000
ALLOWED = {".html", ".css", ".js"}  # never serve .py or other project files

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # 1 MB request cap


def _json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Send a JSON object.")
    return data


def _text(data):
    text = data.get("text", "")
    if not isinstance(text, str) or not text:
        raise ValueError("Enter some text first.")
    return text


def _decrypting(data):
    return data.get("mode") == "decrypt"


@app.post("/api/caesar")
def api_caesar():
    d = _json()
    shift = int(d.get("shift", 3))
    return jsonify(result=cc.caesar(_text(d), shift, _decrypting(d)))


@app.post("/api/caesar/bruteforce")
def api_bruteforce():
    return jsonify(result=cc.caesar_bruteforce(_text(_json())))


@app.post("/api/vigenere")
def api_vigenere():
    d = _json()
    return jsonify(result=cc.vigenere(_text(d), str(d.get("key", "")), _decrypting(d)))


@app.post("/api/aes")
def api_aes():
    d = _json()
    text, pw = _text(d), str(d.get("passphrase", ""))
    if _decrypting(d):
        return jsonify(result=cc.decrypt_text(text, pw))
    return jsonify(result=cc.encrypt_text(text, pw, d.get("kdf", "scrypt")))


@app.errorhandler(ValueError)
def bad_input(e):
    return jsonify(error=str(e)), 400


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="Input is too large (max 1 MB)."), 413


@app.get("/")
@app.get("/index.html")
@app.get("/index")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify(error="Unknown API endpoint."), 404
    return (f"Page not found: {request.path}\nThe app is at the root address, e.g. http://127.0.0.1:{PORT}/\n"
            f"Serving UI from: {WEB_DIR}"), 404, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/health")
def health():
    return jsonify(status="ok", web_dir=str(WEB_DIR), index_found=(WEB_DIR / "index.html").exists())


@app.get("/static/<path:name>")
def assets(name):
    if Path(name).suffix not in ALLOWED:
        abort(404)
    return send_from_directory(WEB_DIR, name)


if __name__ == "__main__":
    if not (WEB_DIR / "index.html").exists():
        raise SystemExit(f"index.html not found in {WEB_DIR}. Put index.html, style.css and app.js in a 'static' folder next to app.py.")
    print(f"Serving UI from: {WEB_DIR}")
    print(f"Open this address in your browser: http://127.0.0.1:{PORT}/")
    app.run(debug=False, host="127.0.0.1", port=PORT)
