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

## Deploy to Railway (including from your phone)

1. Sign into https://railway.com with GitHub. Choose **New Project → Deploy from GitHub repo → mensahenoch020-sketch/Meridian**. Grant Railway repository access if requested.
2. Before the first successful start, open the service **Variables** and set `ADMIN_PASSWORD` to your own strong password. The Dockerfile already sets `HOST=0.0.0.0`, `COOKIE_SECURE=1`, and `DB_PATH=/data/meridian.db`. Railway supplies `PORT` automatically.
3. Add a **Volume** to this service, with mount path **/data**. Keep one replica: SQLite needs the same persistent volume for all requests. Without the volume, accounts and transactions can be lost on redeploy.
4. Deploy (or redeploy after adding the variables and volume). The repository includes Docker build settings and a public `/health` readiness check.
5. Go to **Settings → Networking → Public Networking → Generate Domain**. Use the service's Railway `PORT` as the target if prompted. Open the generated HTTPS URL on your phone.
6. Sign in with `alex@meridian.demo / MeridianDemo123!`, or register. Admin login is `admin@meridian.demo` with the `ADMIN_PASSWORD` you set.

If the service already initialized its persistent database, changing ADMIN_PASSWORD alone does not change the saved admin password: this setting only seeds new databases. Set it before first startup.

Railway hosting/volumes may require account credits or a paid plan. No Railway credentials belong in this repository. The app is intentionally a demo; customer seed logins are public.

## Interface and account operations
Meridian uses its own navy/slate visual identity and inline SVG icon system, with mobile bottom navigation. Login credentials are documented here rather than displayed publicly on the login screen. The application retains a simulation notice: it does not move real funds or Bitcoin.

Administrators can set customer USD or BTC balances under **Admin console → Set account balance**. A reason is required. Each change atomically records the ledger difference and an audit entry containing previous/new balances, actor, reason, and reference. Zero balances are supported; negative balances and edits to admin accounts are rejected.

CI runs API tests plus mobile Chromium flows for login, transfers, BTC trading, and balance editing. Interface screenshots are attached as the `meridian-interface` workflow artifact. Railway services linked to the main branch can deploy this update automatically.

## Sign-in troubleshooting on Railway
Accounts are seeded automatically; no separate Railway user setup is needed. Check the deployment is running the latest main commit and open the generated **HTTPS** domain. If the UI reports an address configuration error, set `PUBLIC_ORIGIN` to that exact origin (for example `https://meridian-production.up.railway.app`), then redeploy. Railway's `RAILWAY_PUBLIC_DOMAIN` is also supported automatically.

Signup requires a name, unused email, and a password of 12–128 characters. Errors now appear within the login form. Rate limits are isolated per account and peer, so a shared Railway proxy cannot lock every account together.

Customer seed login is `alex@meridian.demo / MeridianDemo123!`. Admin uses `admin@meridian.demo` and the password saved when the database was first created. Changing ADMIN_PASSWORD after that does not reset it. Do not delete your persistent volume to troubleshoot login; that would erase accounts and transactions. Inspect Railway logs for server failures.
