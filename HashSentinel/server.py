#!/usr/bin/env python3
"""HASHSENTINEL v3 - local file integrity checker (backend). Python 3.8+, standard library only.

Run:  python server.py   ->  http://127.0.0.1:8000
"""
import fnmatch, hashlib, hmac, json, mimetypes, os, secrets, shutil, sys, time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
DEMO = ROOT / "demo_folder"
WORKSPACE = ROOT / "workspace"          # where files you add from your computer are copied
BASELINE_FILE = DATA / "baseline.json"
HISTORY_FILE = DATA / "history.json"
KEY_FILE = DATA / "secret.key"
WEB_FILES = {"index.html", "style.css", "app.js", "theme.js"}
IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
ALGOS = {"sha256", "sha512", "sha1", "md5"}
MAX_UPLOAD = 200 * 1024 * 1024          # 200 MB per file
HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", 8000))
for d in (DATA, WORKSPACE):
    d.mkdir(exist_ok=True)


# ---------- hashing & scanning ----------
def hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_ignored(rel, patterns):
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def scan_folder(folder, algo, ignore=()):
    """Return ({relative_path: {hash,size,mtime}}, [unreadable paths]). Hashes in parallel."""
    found = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(folder).as_posix()
            if not full.is_symlink() and not is_ignored(rel, ignore):
                found.append((rel, full))

    def work(item):
        rel, full = item
        try:
            st = full.stat()
            return rel, {"hash": hash_file(full, algo), "size": st.st_size, "mtime": st.st_mtime}, None
        except OSError:
            return rel, None, rel

    files, skipped = {}, []
    with ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 2) + 2)) as pool:
        for rel, info, bad in pool.map(work, found):
            if bad:
                skipped.append(bad)
            else:
                files[rel] = info
    return files, skipped


def compare(old, new):
    added = {p: new[p] for p in new.keys() - old.keys()}
    deleted = {p: old[p] for p in old.keys() - new.keys()}
    modified = {p: {"old": old[p], "new": new[p]} for p in old.keys() & new.keys()
                if old[p]["hash"] != new[p]["hash"]}
    moved, by_hash = [], {v["hash"]: p for p, v in deleted.items()}
    for p in sorted(added):  # same content under a new name = moved/renamed
        src = by_hash.get(added[p]["hash"])
        if src and src in deleted:
            moved.append({"from": src, "to": p, "hash": added[p]["hash"], "size": added[p]["size"]})
            del added[p], deleted[src]
    return {
        "added": [{"path": p, **v} for p, v in sorted(added.items())],
        "deleted": [{"path": p, **v} for p, v in sorted(deleted.items())],
        "modified": [{"path": p, **v} for p, v in sorted(modified.items())],
        "moved": moved,
        "unchanged": len(old.keys() & new.keys()) - len(modified),
    }


# ---------- storage & baseline signing ----------
def read_json(path, default):
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), "utf-8")
    tmp.replace(path)


def secret():
    if not KEY_FILE.exists():
        KEY_FILE.write_text(secrets.token_hex(32))
    return KEY_FILE.read_text().strip().encode()


def sign(b):
    payload = json.dumps({k: b[k] for k in ("folder", "algo", "created", "ignore", "files")}, sort_keys=True)
    return hmac.new(secret(), payload.encode(), "sha256").hexdigest()


def verified(b):
    return bool(b.get("sig")) and hmac.compare_digest(b["sig"], sign(b))


def baseline_meta(b):
    if not b:
        return None
    return {"folder": b["folder"], "algo": b["algo"], "created": b["created"], "count": len(b["files"]),
            "ignore": b.get("ignore", []), "verified": verified(b)}


def valid_folder(value):
    # Accept pasted paths such as "C:\Users\me\Docs" (with quotes), ~/Docs or %USERPROFILE%\Docs.
    raw = str(value or "").strip().strip("\"'").strip()
    folder = Path(os.path.expandvars(raw)).expanduser() if raw else None
    if folder is None or not folder.is_dir():
        raise ValueError("Folder not found: %s. Check the path (for example C:\\Users\\you\\Documents or /home/you/Documents)." % (raw or "(empty)"))
    return folder.resolve()


def make_baseline(folder, algo, ignore):
    if algo not in ALGOS:
        raise ValueError("Unsupported algorithm.")
    files, skipped = scan_folder(folder, algo, ignore)
    b = {"folder": str(folder), "algo": algo, "created": time.time(), "ignore": ignore, "files": files}
    b["sig"] = sign(b)
    write_json(BASELINE_FILE, b)
    return b, skipped


# ---------- workspace (files added from the user's computer) ----------
def safe_rel(raw):
    parts = [p for p in unquote(raw or "").replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." or ":" in p or p.startswith("~") for p in parts):
        raise ValueError("Invalid file path.")
    return "/".join(parts)


def workspace_target(rel):
    target = (WORKSPACE / rel).resolve()
    if WORKSPACE.resolve() not in target.parents:
        raise ValueError("Invalid file path.")
    return target


def list_workspace():
    out = []
    for dirpath, _, names in os.walk(WORKSPACE):
        for n in names:
            p = Path(dirpath) / n
            out.append({"path": p.relative_to(WORKSPACE).as_posix(), "size": p.stat().st_size, "mtime": p.stat().st_mtime})
    return sorted(out, key=lambda f: f["path"])


def prune_empty_dirs():
    for dirpath, _, _ in os.walk(WORKSPACE, topdown=False):
        if Path(dirpath) != WORKSPACE and not any(Path(dirpath).iterdir()):
            Path(dirpath).rmdir()


# ---------- demo folder ----------
DEMO_FILES = {
    "readme.txt": "Quarterly report project\n",
    "config.ini": "[server]\nhost = localhost\nport = 8080\n",
    "notes.txt": "Meeting notes\n- budget approved\n",
    "data/users.csv": "id,name\n1,Asha\n2,Ravi\n",
    "scripts/backup.sh": "#!/bin/sh\necho backing up\n",
}


def demo_action(step):
    if step == "reset":
        shutil.rmtree(DEMO, ignore_errors=True)
        for rel, text in DEMO_FILES.items():
            p = DEMO / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, "utf-8")
        return "Demo folder created with 5 files."
    if not DEMO.is_dir():
        raise ValueError("Create the demo folder first.")
    if step == "edit":
        with open(DEMO / "config.ini", "a", encoding="utf-8") as f:
            f.write("debug = true\n")
        return "Edited config.ini."
    if step == "add":
        (DEMO / "new_file.txt").write_text("I was not here before.\n", "utf-8")
        return "Added new_file.txt."
    if step == "delete":
        (DEMO / "notes.txt").unlink(missing_ok=True)
        return "Deleted notes.txt."
    if step == "move":
        src = DEMO / "readme.txt"
        if src.exists():
            src.rename(DEMO / "README_renamed.txt")
        return "Renamed readme.txt to README_renamed.txt."
    raise ValueError("Unknown demo step.")


# ---------- HTTP ----------
class Handler(BaseHTTPRequestHandler):
    server_version = "HASHSENTINEL/3.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def _send(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):  # blocks DNS rebinding: only answer requests addressed to localhost
        return self.headers.get("Host", "").split(":")[0] in {"127.0.0.1", "localhost"}

    def state(self):
        return {"baseline": baseline_meta(read_json(BASELINE_FILE, None)),
                "history": read_json(HISTORY_FILE, [])[-20:][::-1],
                "demoPath": str(DEMO), "workspacePath": str(WORKSPACE), "workspace": list_workspace()}

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "Forbidden"})
        path = urlparse(self.path).path
        if path == "/api/state":
            return self._send(200, self.state())
        name = "index.html" if path in ("/", "") else path.lstrip("/").split("/")[-1]
        if name not in WEB_FILES:
            return self._send(404, {"error": "Not found"})
        target = next((d / name for d in (STATIC, ROOT) if (d / name).is_file()), None)
        if target is None:
            return self._send(404, {"error": "Can't find %s. Keep index.html, style.css, app.js and theme.js in a 'static' folder next to server.py." % name})
        self._send(200, target.read_bytes(), (mimetypes.guess_type(name)[0] or "text/plain") + "; charset=utf-8")

    def do_POST(self):
        # Custom header = browsers refuse to send it cross-site without a CORS preflight (CSRF guard).
        if not self._host_ok() or self.headers.get("X-FIC") != "1":
            return self._send(403, {"error": "Forbidden"})
        url = urlparse(self.path)
        try:
            if url.path == "/api/upload":
                return self._send(200, self.upload(url))
            length = min(int(self.headers.get("Content-Length", 0)), 1_000_000)
            body = json.loads(self.rfile.read(length) or b"{}")
            routes = {"/api/baseline": self.create_baseline, "/api/accept": self.accept, "/api/scan": self.run_scan,
                      "/api/demo": self.demo, "/api/reset": self.reset, "/api/workspace/delete": self.ws_delete,
                      "/api/workspace/clear": self.ws_clear}
            if url.path not in routes:
                return self._send(404, {"error": "Not found"})
            self._send(200, routes[url.path](body))
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # keep the server alive
            self._send(500, {"error": "Unexpected error: %s" % e})

    # --- handlers ---
    def upload(self, url):
        rel = safe_rel(parse_qs(url.query).get("path", [""])[0])
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            raise ValueError("Missing file size.")
        remaining = int(length)
        if remaining > MAX_UPLOAD:
            raise ValueError("%s is larger than the %d MB limit." % (rel, MAX_UPLOAD // 1048576))
        target = workspace_target(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        existed = target.exists()
        tmp = target.with_name(target.name + ".part")
        with open(tmp, "wb") as f:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        if remaining:
            tmp.unlink(missing_ok=True)
            raise ValueError("Upload was interrupted. Try again.")
        tmp.replace(target)
        return {"path": rel, "replaced": existed}

    def ws_delete(self, body):
        target = workspace_target(safe_rel(body.get("path")))
        if target.is_file():
            target.unlink()
            prune_empty_dirs()
        return {"workspace": list_workspace()}

    def ws_clear(self, body):
        shutil.rmtree(WORKSPACE, ignore_errors=True)
        WORKSPACE.mkdir(exist_ok=True)
        return {"workspace": []}

    def create_baseline(self, body):
        folder = WORKSPACE if body.get("workspace") else valid_folder(body.get("folder"))
        if body.get("workspace") and not list_workspace():
            raise ValueError("Add at least one file first.")
        ignore = [p.strip() for p in body.get("ignore", []) if p.strip()][:50]
        b, skipped = make_baseline(folder.resolve(), body.get("algo", "sha256"), ignore)
        write_json(HISTORY_FILE, [])
        return {"baseline": baseline_meta(b), "skipped": skipped}

    def accept(self, body):
        old = read_json(BASELINE_FILE, None)
        if not old:
            raise ValueError("Create a baseline first.")
        b, skipped = make_baseline(valid_folder(old["folder"]), old["algo"], old.get("ignore", []))
        return {"baseline": baseline_meta(b), "skipped": skipped}

    def run_scan(self, body):
        b = read_json(BASELINE_FILE, None)
        if not b:
            raise ValueError("Create a baseline before scanning.")
        folder, started = valid_folder(b["folder"]), time.time()
        files, skipped = scan_folder(folder, b["algo"], b.get("ignore", []))
        diff, ok = compare(b["files"], files), verified(b)
        entry = {"time": time.time(), "folder": b["folder"], "verified": ok, "added": len(diff["added"]),
                 "modified": len(diff["modified"]), "deleted": len(diff["deleted"]), "moved": len(diff["moved"]),
                 "unchanged": diff["unchanged"]}
        history = (read_json(HISTORY_FILE, []) + [entry])[-200:]
        write_json(HISTORY_FILE, history)
        return {"report": {**diff, "algo": b["algo"], "folder": b["folder"], "skipped": skipped, "baselineVerified": ok,
                           "ignore": b.get("ignore", []), "scannedAt": entry["time"], "baselineCreated": b["created"],
                           "seconds": round(time.time() - started, 3), "total": len(files)},
                "history": history[-20:][::-1]}

    def demo(self, body):
        return {"message": demo_action(body.get("step", "")), "path": str(DEMO)}

    def reset(self, body):
        for f in (BASELINE_FILE, HISTORY_FILE):
            f.unlink(missing_ok=True)
        return {"message": "Baseline and history cleared."}


if __name__ == "__main__":
    print("HASHSENTINEL running at http://%s:%d  (Ctrl+C to stop)" % (HOST, PORT))
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
