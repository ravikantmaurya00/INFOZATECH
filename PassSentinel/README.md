# PassSentinel — Intelligent Password Strength Analyzer (Flask + HTML/CSS/JavaScript)

## Run
    python -m venv venv
    source venv/bin/activate        # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    python app.py                   # open http://127.0.0.1:5000
    pytest                          # run tests

## Structure
    app.py            Flask routes: analyze, breach proxy, generator, stats
    analyzer.py       Entropy engine with pattern penalties
    templates/        index.html
    static/           style.css, script.js
    tests/            pytest tests

## Features
- Python entropy engine (words, leetspeak, sequences, keyboard walks, years, repeats)
- Breach check via Have I Been Pwned k-anonymity (only 5 hash chars leave the browser)
- Server-side generator using Python's `secrets`
- SQLite anonymous stats dashboard (no passwords stored)
- Crack-time estimates for three attack scenarios, light/dark themes

## Ideas to extend
Rate limiting (Flask-Limiter), Docker, user accounts, passphrase generator, larger wordlists.

## Deploy on Render
1. Push this folder to a GitHub repository.
2. On render.com choose New > Web Service (or Blueprint, which reads render.yaml) and connect the repo.
3. Build command: `pip install -r requirements.txt`   Start command: `gunicorn app:app`
4. Deploy. Note: on the free plan the SQLite stats file is reset on each deploy or restart.
