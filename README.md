# Meridian Bank

A full stack demo bank with a responsive dashboard, SQLite persistence, USD transfers, simulated BTC trading, account registration, and a role-protected admin console.

**Demo funds only.** BTC prices are fixed simulations; there is no blockchain integration or real money movement.

## Run
Requires Python 3.12+; no third-party packages.
```sh
python server.py
```
Open http://localhost:8000. Register a customer account (starts with $10,000 demo funds) or use:
- Customer: alex@meridian.demo / MeridianDemo123!
- Recipient: sam@meridian.demo / MeridianDemo123!
- Admin: admin@meridian.demo / MeridianAdmin123!

Set ADMIN_PASSWORD before first run to replace the demo admin password. Seed customer passwords remain public demo credentials. Database is stored at data/meridian.db (override with DB_PATH). HOST defaults to 127.0.0.1; PORT defaults to 8000. Use a persistent volume for data when deploying.

## Test
```sh
python -m unittest discover -s tests -v
```
GitHub Actions runs API integration tests on pushes and pull requests.

## Features
- Registration, password hashing (scrypt), expiring server sessions, HttpOnly SameSite cookies.
- Integer cents and satoshis; atomic transfers and trade ledger entries.
- Transfer receipts, transaction search, CSV export.
- Buy/sell simulated BTC at a disclosed fixed $67,500/BTC rate.
- Admin customer balances, transaction audit, freeze/unfreeze controls.
- CSRF origin validation and required JSON mutation requests; login rate limiting.
- Responsive interface with accessible forms and explicit demo labels.

## Deployment
For a private demo, run behind an HTTPS reverse proxy and set COOKIE_SECURE=1. This is an educational demo, not production banking software. There are no real cards, deposits, external transfers, live prices, KYC, or blockchain withdrawals. Demo sessions expire after 12 hours. Frozen users cannot log in or transact. Admin actions are audited. Keep the database and backups private.
