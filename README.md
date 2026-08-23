# Vulnerable Test App (for scanner practice only)

A tiny Node/Express app with **intentionally planted security bugs**, built
so you can practice pointing tools like Snyk, npm audit, OWASP ZAP, or
Pentest-Tools at something and see what gets flagged — before you run them
against a real client site.

⚠️ **Do not deploy this anywhere public.** Run it only on `localhost`.
⚠️ **Do not copy these patterns into real projects** — they're here to be
broken, not imitated.

## Setup

```bash
npm install
npm start
```

Then visit `http://localhost:3000`.

## What's planted, and where

| # | Vulnerability | File | Try it |
|---|---|---|---|
| 1 | Hardcoded JWT secret in source | `server.js` | — |
| 2 | Hardcoded API key in source | `server.js` | — |
| 3 | Weak password hashing (MD5, unsalted) | `server.js` | — |
| 4 | SQL Injection | `server.js` (`/search`) | `/search?term=' OR '1'='1` |
| 5 | Reflected XSS | `server.js` (`/greet`) | `/greet?name=<script>alert(1)</script>` |
| 6 | Weak auth / no rate limiting | `server.js` (`/login`) | POST with any credentials repeatedly |
| 7 | Insecure cookie flags | `server.js` (`/login`) | Inspect cookie in DevTools |
| 8 | Broken access control (IDOR) | `server.js` (`/profile/:id`) | `/profile/1`, `/profile/2` — no auth check |
| 9 | Verbose error / stack trace leakage | `server.js` (error handler) | Trigger any DB error |
| 10 | Secrets committed in `.env` | `.env` | — |
| 11 | Outdated vulnerable dependencies | `package.json` | Old `jsonwebtoken` and `lodash` versions with known CVEs |

## What to do with it

1. Run **Snyk** against the project folder (`snyk test` via CLI, or upload/connect
   the repo if using their web app) — it should flag the outdated
   `jsonwebtoken` and `lodash` versions (#11) plus some code-level issues if
   using Snyk Code.
2. Run **npm audit** — same dependency findings, no AI needed, good sanity check.
3. Run **OWASP ZAP** or **Pentest-Tools** against `http://localhost:3000` while
   it's running — should catch the XSS, SQLi, and missing security headers.
4. Compare what each tool catches vs. misses. Static tools (Snyk, npm audit)
   read the code; dynamic tools (ZAP) attack the running app — they catch
   different things, which is exactly why using both matters.
5. Try fixing each one yourself using the code patterns from earlier in our
   conversation, then re-run the scan to confirm the finding is gone.
