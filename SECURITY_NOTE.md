# Authentication Security Note

## Controls implemented
1. **Password storage:** passwords are hashed with scrypt (`hashlib.scrypt`, n=2^14, r=8, p=1) using a random 16-byte salt per password. Verification uses constant-time comparison. Plaintext passwords are never stored.
2. **Server-side validation:** usernames are 3-32 characters (letters, digits, underscore, case-insensitive unique); passwords must be 12-128 characters; request bodies are capped at 4 KB and must be JSON objects.
3. **Rate limiting:** login is limited to 5 attempts per client+username and 20 per client in each 60-second window (the client-wide limit stops attackers rotating usernames). Excess requests receive HTTP 429.
4. **Generic errors and timing:** unknown users and wrong passwords return the same message, and a dummy hash is checked for unknown users so response time does not reveal which usernames exist.
5. **Session protection:** a signed (HMAC-SHA256) token with a 15-minute expiry, backed by a server-side session record. Cookie flags: `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` when `COOKIE_SECURE=1`.
6. **Logout:** deletes the server-side session and expires the cookie, so a copied cookie stops working immediately.
7. **Database safety:** all SQL uses parameterized queries.
8. **Response headers:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'none'`.

## Test evidence
12 automated tests cover password hashing and salting, login, validation, generic login failures, rate limiting (including username rotation), token tampering, token expiry, logout revocation, duplicate registration, and an end-to-end HTTP flow (cookie flags, `/me`, logout, security headers). Output is in `TEST_OUTPUT.txt`.

## Limitations / next steps
- The in-memory rate limiter resets on restart and is per-process; production needs a shared store such as Redis.
- Registration returns 409 for existing usernames, which still allows some username enumeration; production would use email verification.
- Set a stable `SECRET_KEY` from a secret manager (otherwise a random one is generated at startup and sessions reset on restart) and enable `COOKIE_SECURE=1` behind HTTPS.
- Add CSRF tokens or origin checks for browser clients using cookie authentication across origins.
- Add password reset with single-use expiring tokens, MFA, audit logging, monitoring, and account recovery.
- Use HTTPS, a production database, backups, dependency scanning, and a security review before any real deployment.
- Do not deploy this lab as-is or use real user credentials.
