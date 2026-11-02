# Secure Authentication Lab

A small local authentication service demonstrating password hashing, server-side input validation, rate limiting, generic authentication errors, secure session-cookie settings, logout and automated tests.

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The service listens only on `127.0.0.1:5000`. Initialize the local database automatically on startup. Try:
```bash
curl -i http://127.0.0.1:5000/health
curl -i -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"demo_user","password":"a-long-demo-password"}'
curl -i -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo_user","password":"a-long-demo-password"}'
```

## Automated tests

```bash
python -m unittest discover -s tests -v
```

## Important deployment notes

- Set `SECRET_KEY` to a cryptographically random secret from a secret manager.
- Set `COOKIE_SECURE=1` only when serving over HTTPS; the lab default is for localhost.
- The sample rate limiter is in-memory and resets on restart. Use a shared persistent limiter such as Redis in a multi-worker deployment.
- Add CSRF protection if browser clients use cookie-authenticated state-changing routes across origins.
- Use HTTPS, monitoring, backups, dependency updates and a production-grade database before deployment.
- This is a learning lab, not a production-ready identity provider.
