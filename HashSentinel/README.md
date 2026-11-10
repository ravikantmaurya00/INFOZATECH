# HASHSENTINEL

A local web app that fingerprints files (the baseline), then re-scans and flags every
**modified, added, deleted and renamed/moved** file. Python standard library only, no installs.

## Run
```
python server.py             # then open http://127.0.0.1:8000
PORT=9000 python server.py   # optional: different port
```
Open the address in your browser. Do not double-click `index.html`: it needs the server.
Keep `index.html`, `style.css`, `app.js` and `theme.js` in the `static/` folder beside `server.py`.

## Demo A: add files from your computer
1. Drop files or a folder on the page (or **Choose files / Choose a folder**).
2. Click **Create baseline from these files**.
3. Edit a file on your PC, add another, remove one, then add the edited files again
   (same name replaces the copy).
4. Click **Scan now**.

## Demo B: protect any folder
Paste a folder path (quotes are fine, e.g. `"C:\Users\you\Documents"`) and click **Create baseline**.
Leave the path empty to use the files you added above. A built-in demo folder is also provided.

## Features
- Themes: System, Light, Dark, Midnight (remembered in your browser)
- Upload files or folders with drag and drop into `workspace/`; originals untouched
- SHA-256 / SHA-512 / SHA-1 / MD5, hashed in parallel
- Ignore patterns, e.g. `*.log, cache/*`
- HMAC-signed baseline: hand-editing `data/baseline.json` triggers a warning
- Accept changes, auto-scan (10 / 30 / 60 s), history, filter + search, JSON and CSV export
- Toast messages so every action gives visible feedback

## Security
Binds to 127.0.0.1 only; rejects non-localhost Host headers; POSTs need a custom header
(CSRF guard); upload paths are sanitised and confined to `workspace/`; 200 MB per-file limit;
symlinks are never followed.
