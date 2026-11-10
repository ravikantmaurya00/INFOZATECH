# CyberNova: Encryption & Decryption Toolkit

Web toolkit demonstrating classical ciphers (Caesar, Vigenère) and modern authenticated
encryption (AES-256-GCM) with passphrase-derived keys (scrypt or PBKDF2-HMAC-SHA256).

## Run
    python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    pytest                    # optional: run the tests
    python app.py             # open http://127.0.0.1:5000

## Security design (talking points)
- AES-256-GCM: confidentiality plus integrity; a wrong passphrase or modified data fails cleanly.
- Random 16-byte salt and 12-byte nonce per message, so the same input never encrypts the same way twice.
- scrypt (N=2^15, r=8, p=1) or PBKDF2 (600k iterations) slow down passphrase guessing.
- The header (KDF, cost, salt, nonce) is bound to the ciphertext as GCM associated data.
- Decrypt enforces min/max KDF cost, so a crafted message can't force huge CPU/memory use.
- Request size limit, input validation, one generic decryption error, and no secrets logged or stored.
- Caesar brute-force view shows why classical ciphers are not secure.

## Ideas to extend
File encryption (chunked streaming), RSA/X25519 hybrid encryption, Argon2id (argon2-cffi),
rate limiting (Flask-Limiter), Docker, a CLI with argparse.

Educational project. Classical ciphers are not secure; use the AES mode for real data, and run behind HTTPS if hosted.
