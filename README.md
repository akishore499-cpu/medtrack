# MedTrack

Medicine schedule, dose reminders and missed-dose alerts. Works on phone and desktop.

## Run it
Requires Node.js 18+.

    npm install
    npm start

Open http://localhost:3000, create an account and add a medicine.

## Stack
- Frontend: plain HTML, CSS and JavaScript (`public/index.html`). No build step, loads instantly.
- Backend: Node.js + Express REST API (`server.js`).
- Database: SQLite file `medtrack.db` (created automatically). Tables: users, sessions, medicines, logs.

## How it works
- Each dose is `upcoming`, `due` (15 min before to 60 min after the time), `taken`, `skipped` or `missed`.
- The server marks a dose `missed` automatically when the window passes with no log.
- The page checks every 30 seconds and when you return to the tab. New due or missed doses trigger a popup, a toast, a sound and a browser notification.
- Extras: 7-day adherence chart, optional end dates, food instructions, multiple accounts with hashed passwords.

## Limits and next steps
- Background alerts use Web Push. Tap "Turn on alerts" once on each device. The server must be running, and phones need an HTTPS address (localhost on the same computer works without one). For testing on a phone, use a tunnel such as ngrok or Cloudflare Tunnel.
- The app can be installed to a phone home screen (it ships a web manifest and service worker). 
- Rate limiting, security headers, HTTPS support, and password reset are built in. Put these settings in a file named `.env` next to `server.js` (copy `.env.example`, one `NAME=value` per line, restart after changes). Docker also works: `docker build -t medtrack .` then `docker run -p 3000:3000 -v medtrack-data:/data --env-file .env medtrack`. You can also set `DB_PATH` to store the database elsewhere.

| Variable | Purpose |
|---|---|
| `HTTPS_KEY`, `HTTPS_CERT` | Paths to a key and certificate file. The server then runs on HTTPS. |
| `TRUST_PROXY=1`, `FORCE_HTTPS=1` | Use both when a host such as Render or nginx provides HTTPS for you. Redirects HTTP to HTTPS. |
| `BASE_URL` | Your public address, like `https://meds.example.com`. Used in reset emails. Always set it in production. |
| `SMTP_URL`, `MAIL_FROM` | Email sending, for password reset. Example: `smtps://user:app-password@smtp.gmail.com` |

**Bill upload:** The Add medicine page shows an "Upload bill" card, but it is switched off in this version and does nothing when pressed. Reading a medicine bill automatically is planned for a later stage. Medicines are added by hand for now. (`demo-site.html` shows how the bill flow is planned to look.)

**Passwords:** 8+ characters with a letter and a number, typed twice when creating or resetting, with an eye icon to show what was typed. The password is asked again for deleting a medicine and deleting the account. Settings > My medicines > Account and security lets patients change the password, sign out of all devices or delete the account.

**Presentation demo:** open `demo-site.html` in any browser (no server needed). It shows every page with sample data. Use the buttons or the left/right arrow keys.

**Demo:** with the server running, open `http://localhost:3000/demo.html` to see phone, tablet and desktop sizes side by side with sample data and no login.

- Without email set up, reset links are printed in the server window instead.
- Still recommended before real patients use it: run it on a managed host with backups of `medtrack.db`, and get a privacy review, since this is health data.
- MedTrack stores the dose the user enters. It does not give medical advice.
