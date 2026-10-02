# Relay

Relay is a small HTTPS-to-SMTP mail relay with a minimal admin interface.

Many websites cannot send email themselves. GoDaddy, for example, blocks outgoing SMTP on ports 25,
465 and 587. These sites can still make HTTPS requests. So each site POSTs its message to Relay
over HTTPS, and Relay sends it through **that site's own SMTP mailbox**. Each website or program
is an **app** in Relay, with its own SMTP settings, sender address, limits and API key.

Relay runs at **https://relay.companysite.site** on Namecheap shared hosting: cPanel "Setup
Node.js App" (CloudLinux Node.js Selector behind LiteSpeed), with MariaDB.

This README has two audiences:

- **The owner**, who deploys and runs Relay: sections 2–4 and 6–14.
- **Developers of the client sites**: section 5 (API reference), and section 6 for the existing
  legacy PHP app.

Throughout, `USER` stands for your cPanel username.

## Contents

1. [Overview](#1-overview)
2. [Requirements](#2-requirements)
3. [Deploying on Namecheap (cPanel)](#3-deploying-on-namecheap-cpanel)
   - [Step 0: Check outbound SMTP first](#step-0-check-outbound-smtp-first)
   - [Step 1: Subdomain and HTTPS](#step-1-subdomain-and-https)
   - [Step 2: MySQL database](#step-2-mysql-database)
   - [Step 3: Get the code with Git](#step-3-get-the-code-with-git)
   - [Step 4: Create the Node.js application](#step-4-create-the-nodejs-application)
   - [Step 5: Install dependencies](#step-5-install-dependencies)
   - [Step 6: Write .env](#step-6-write-env)
   - [Step 7: Create the tables (migrations)](#step-7-create-the-tables-migrations)
   - [Step 8: Restart and check that it runs](#step-8-restart-and-check-that-it-runs)
   - [Step 9: Hourly cleanup cron job (required)](#step-9-hourly-cleanup-cron-job-required)
   - [Step 10: First sign-in and the System page](#step-10-first-sign-in-and-the-system-page)
   - [Step 11: Remove the bootstrap password](#step-11-remove-the-bootstrap-password)
   - [Step 12: Smoke tests](#step-12-smoke-tests)
   - [Restarting](#restarting)
   - [Logs](#logs)
   - [Upgrading Relay](#upgrading-relay)
   - [Changing the Node.js version](#changing-the-nodejs-version)
4. [Configuration reference (.env)](#4-configuration-reference-env)
5. [API reference (for client sites)](#5-api-reference-for-client-sites)
6. [Migrating the legacy PHP app](#6-migrating-the-legacy-php-app)
7. [Admin guide](#7-admin-guide)
8. [Rotating keys and secrets](#8-rotating-keys-and-secrets)
9. [Backups and restore](#9-backups-and-restore)
10. [Security notes](#10-security-notes)
11. [Troubleshooting](#11-troubleshooting)
12. [Node.js versions](#12-nodejs-versions)
13. [Local development and tests](#13-local-development-and-tests)
14. [Project layout](#14-project-layout)

---

## 1. Overview

```
 client site (PHP / Node / anything that can make HTTPS requests)
     |  HTTPS POST /v1/send   (Authorization: Bearer <api key>, JSON)
     |  HTTPS POST /send.php  (HMAC-signed, legacy PHP app)
     v
 LiteSpeed web server (Namecheap)    TLS, ModSecurity, adds X-Forwarded-For / -Proto
     v
 Relay (Node.js + Express)  <---->  MariaDB: apps, keys, message log, idempotency,
     |                              rate counters, admin users, sessions, audit log
     |  SMTP (465 SSL/TLS or 587 STARTTLS), one fresh connection per message to one
     |  resolved address, certificates verified, at most 50 s per send,
     |  the HTTP request waits for the SMTP result
     v
 the site's own mailbox (Microsoft 365, Gmail, cPanel mail, ...)  --->  recipients
```

What happens to a `POST /v1/send`:

1. Per-IP rate limit, then the API key is checked. The body is only read after that.
2. Then these checks run in order:
   - the app is enabled
   - the IP allowlist matches
   - the message is valid (addresses, size, attachments)
   - the `message_id` was not already used (idempotency)
   - the app's per-minute and per-day limits are not exceeded
3. A log row is written with status `sending`.
4. The message is sent through the app's SMTP server. The row becomes `sent` or `failed`, or
   `unknown` when the connection broke after the message data was sent, because the mail server
   may have accepted it anyway ([5.4](#54-idempotency-and-retries)).
5. Relay answers `{"ok": true, "id": "msg_..."}` or `{"ok": false, "error": "..."}`.

Key points:

- **Synchronous.** The HTTP response tells the client whether the app's SMTP server accepted the
  message. There is no queue. Relay gives up on a mail server after at most
  `SMTP_SEND_DEADLINE_MS` (50 s).
- **State lives in MySQL.** This covers sessions, rate counters and idempotency, so several Node
  processes can run side by side. LiteSpeed may start more than one.
- **Never stored:** message bodies and attachments. The log keeps time, app, recipients, subject,
  size, status, and the SMTP response or error, for 90 days.
- **Secrets at rest.**
  - SMTP passwords, legacy API keys and 2FA secrets are encrypted with AES-256-GCM under
    `MASTER_KEY`.
  - Normal API keys are stored only as SHA-256 hashes.
  - Admin passwords use bcrypt.
- **The sender cannot be spoofed.** Every message is sent as the app's configured From name and
  address. A `/v1/send` caller may only pick between the app's From address and its configured
  "other allowed From addresses".
- **Admin interface** at `/admin`:
  - apps, keys, test email, message log, stats, audit log
  - admin users, optional TOTP two-factor authentication
  - a System page for deployment checks

## 2. Requirements

- Namecheap shared hosting with cPanel **Setup Node.js App**, and SSH access or cPanel Terminal.
  SSH on Namecheap uses port 21098; enable it under cPanel > Manage Shell / SSH Access.
- **Node.js 24** (20 and 22 also work; see [Node.js versions](#12-nodejs-versions)).
- MariaDB 10.3+ or MySQL 5.7+. Namecheap provides MariaDB 11.4.
- A subdomain with an SSL certificate: `relay.companysite.site`.
- **Outbound SMTP from the hosting account** to every mail server the apps will use. Check this
  first ([Step 0](#step-0-check-outbound-smtp-first)).

## 3. Deploying on Namecheap (cPanel)

### Step 0: Check outbound SMTP first

Relay is useless if the hosting account cannot open SMTP connections. Some shared hosts block
outbound SMTP the same way GoDaddy does. Check this before anything else, from the hosting
account itself, with `scripts/smtp-probe.js`. It has no dependencies.

1. Open cPanel > Terminal, or connect over SSH: `ssh -p 21098 USER@<server name>`. Download the
   probe from the repository into your home directory (or upload `scripts/smtp-probe.js` there
   with cPanel > File Manager > Upload):

   ```sh
   cd ~ && curl -fsSLO https://raw.githubusercontent.com/thimiraperera/relay/main/scripts/smtp-probe.js
   ```
2. Find a Node.js binary. CloudLinux keeps them under `/opt/alt`:

   ```sh
   ls -d /opt/alt/alt-nodejs*/root/usr/bin/node
   ```

   If nothing is listed, do Step 0 right after [Step 4](#step-4-create-the-nodejs-application)
   instead. Then run `node scripts/smtp-probe.js ...` inside the app's virtual environment.
3. Probe every SMTP server your apps will use, on the port they will use:

   ```sh
   N=/opt/alt/alt-nodejs24/root/usr/bin/node
   $N ~/smtp-probe.js smtp.office365.com 587
   $N ~/smtp-probe.js smtp.gmail.com 465
   $N ~/smtp-probe.js mail.clientdomain.com 465
   ```

   Port 465 (or `--tls`) uses implicit TLS. Other ports connect in plain TCP, read the greeting,
   send `EHLO` and, if STARTTLS is offered, upgrade. The certificate is checked the way Relay
   checks it. The probe never logs in and never sends mail. Exit code: 0 = reachable, 1 = problem,
   2 = usage error.

A good result looks like this:

```
DNS      OK    smtp.office365.com -> 52.98.0.2 (first of 10 IPv4 addresses; Relay connects to this one)
               IPv4: 52.98.0.2, 40.99.10.98, 52.96.1.18, 40.99.9.162, 52.98.3.66, 40.101.12.2, 52.97.146.162,
                     40.104.30.2, 52.98.5.226, 40.99.212.2
               IPv6: 2603:1036:302:4a::2, 2603:1036:302:46::2
CONNECT  OK    TCP connection to 52.98.0.2:587 established in 45 ms
GREETING OK    220 SI2PR02CA0042.outlook.office365.com Microsoft ESMTP MAIL Service ready ...
EHLO     OK    as [127.0.0.1]; offers: STARTTLS
STARTTLS OK    TLSv1.3; certificate names: *.office365.com, outlook.com, ... ; issuer: DigiCert Inc; valid until 2027-01-10
EHLO     OK    after STARTTLS; offers: AUTH LOGIN XOAUTH2
AUTH     OK    username/password login offered (LOGIN); Relay would use LOGIN
SIZE     INFO  the server accepts messages up to 150.0 MB (after MIME encoding)

RESULT   OK    smtp.office365.com:587 is reachable from this machine; use encryption "STARTTLS" with this port in the app settings.
               Only 52.98.0.2 was tested. Relay connects to the first IPv4 address of each DNS answer, and that
               can change between lookups: run again with --all to test all 10 IPv4 addresses.
```

**Which address is tested.** Relay resolves the SMTP host name itself and makes **exactly one
connect attempt per send**: to the first IPv4 address in the DNS answer, or to the first IPv6
address if the name has no IPv4 address. It never falls back to another address. The probe
resolves the name the same way, lists every address, and tests the one Relay would use.

Big providers return many addresses, and DNS servers often change their order from one lookup to
the next, so later sends may use a different address. Add `--all` to test every address in turn:

```sh
$N ~/smtp-probe.js smtp.office365.com 587 --all
```

It runs the same checks for each address and ends with a summary. Any IPv4 address that fails
makes the result `FAIL`, because some sends would then fail. IPv6 addresses are tested too, but
while the name has IPv4 addresses Relay never uses them, so their failures are only `INFO`. A
blocked address costs up to 15 s, so `--all` can take a few minutes.

What the failures mean:

| Probe says | Meaning |
|---|---|
| `CONNECT FAIL TIMEOUT after 15 s` | Almost always the host's outbound firewall drops the connection. Open a ticket (below). |
| `CONNECT FAIL BLOCKED (EPERM)` | A firewall on the server itself refuses it (cPanel "SMTP Restrictions" or similar). Open a ticket. |
| `CONNECT FAIL ECONNREFUSED` | Wrong port, the server is down, or a firewall rejects the connection. Check the port; if it is right, open a ticket. |
| `GREETING FAIL TIMEOUT` | Connected, but nothing answered. Either a firewall or proxy is holding the connection (typical for port 25), or the port needs `--tls`. |
| `GREETING WARN ... comes from this machine itself` | The host silently redirects outbound SMTP to its own mail server. Open a ticket. |
| `DNS FAIL` | The host name is wrong. |
| `TLS FAIL certificate not accepted` | Relay would fail with `ESOCKET`. Use the host name printed on the certificate, which on cPanel mail hosting is often the server name, e.g. `server123.web-hosting.com`. |
| `TLS FAIL the server did not answer with TLS` | You used `--tls` on a STARTTLS port: run without it. |
| `AUTH WARN AUTH is offered only as XOAUTH2` (or another mechanism) | Relay logs in with a username and password, using PLAIN, LOGIN or CRAM-MD5. A server that offers none of them will probably refuse the login (`EAUTH`). For Microsoft 365 see [section 10](#10-security-notes). |
| With `--all`: `SUMMARY FAIL 7 of 10 IPv4 addresses passed` | Some of the provider's addresses are blocked or down. Sends fail whenever DNS lists one of those first. Include the full output in the ticket. |

If outbound SMTP is blocked, open a ticket with Namecheap support (Hosting > Live chat / ticket).
Paste the probe output into it:

> Subject: Please allow outbound SMTP submission from my hosting account
>
> Hello. On my shared hosting account (cPanel user `USER`, server `<server name>`) I run a
> Node.js application, relay.companysite.site. It sends transactional email for my own websites
> through each website's own mailbox, using authenticated SMTP submission (TLS, username and
> password). Outbound connections from my account to these servers time out or are refused:
>
> - smtp.office365.com port 587 (STARTTLS)
> - mail.clientdomain.com port 465 (SSL/TLS)
>
> The output of a connection test run from my account is below. Please allow outbound TCP
> connections from my account to these hosts and ports (or to ports 465 and 587 in general).
> This is authenticated submission with each site's own credentials, at most a few hundred
> messages a day. It is not bulk mail and not direct delivery to recipients' servers on port 25.
>
> `<probe output>`

Run the probe again once support confirms the change.

### Step 1: Subdomain and HTTPS

1. **cPanel > Domains > Create A New Domain**: enter `relay.companysite.site` and **untick**
   "Share document root". cPanel suggests a document root such as
   `/home/USER/relay.companysite.site`. That folder only holds the web server's `.htaccess`. The
   application lives elsewhere (Step 3).
2. If `companysite.site` uses DNS outside this hosting account, add an `A` record for `relay`
   pointing at the server's IP address.
3. **cPanel > SSL/TLS Status**: select the subdomain and click **Run AutoSSL**. Wait until it
   shows a valid certificate.
4. **cPanel > Domains**: switch on **Force HTTPS Redirect** for `relay.companysite.site`.
   Relay also enforces HTTPS itself (`FORCE_HTTPS=true`).

### Step 2: MySQL database

1. **cPanel > MySQL Databases**, or the Database Wizard:
   - Create the database `relay`. Its full name will be `USER_relay`.
   - Create a user `relay` (full name `USER_relay`) with a long generated password.
   - Add the user to the database with **ALL PRIVILEGES**.
2. Note the full prefixed names and the password for `.env`. If the password contains `#`,
   spaces or quotes, it must be quoted in `.env` (see [Step 6](#step-6-write-env)).

### Step 3: Get the code with Git

The code is deployed from the Git repository with **cPanel > Git Version Control**. The
repository folder on the server is also the application root, so updating means pulling the new
commits and restarting. That folder must be **outside `public_html` and outside the subdomain's
document root**, for example `/home/USER/relay`. Then `.env`, the code and the logs can never be
downloaded over the web.

The repository holds only the software. `.gitignore` keeps out `.env` (all passwords and keys),
`node_modules`, logs and `tmp/`, so those files are created on the server and are never
overwritten by a pull.

**3a. Publish the repository (once, on your computer).** Create an empty repository named `relay`
on GitHub (no README, licence or `.gitignore`, so it stays empty), then push:

```sh
git remote add origin https://github.com/thimiraperera/relay.git
git push -u origin main
```

**3b. Clone it on the server.** **cPanel > Files > Git Version Control > Create**:

| Field | Value |
|---|---|
| Clone a Repository | **on** |
| Clone URL | `https://github.com/thimiraperera/relay.git` |
| Repository Path | `/home/USER/relay` (the folder must not exist yet) |
| Repository Name | `relay` |

Click **Create** and wait for the clone to finish. `/home/USER/relay` now contains `app.js`,
`package.json`, `src/`, `migrations/`, `scripts/` and so on.

Do not create a `node_modules` folder there. The Node.js Selector creates `node_modules` itself
(Step 5), as a link into the app's virtual environment, and refuses to install when a real
folder exists.

### Step 4: Create the Node.js application

**cPanel > Setup Node.js App > Create Application**:

| Field | Value |
|---|---|
| Node.js version | the highest **24.x** offered |
| Application mode | **Production** |
| Application root | `relay` (that is, `/home/USER/relay`) |
| Application URL | `relay.companysite.site`, path left empty |
| Application startup file | `app.js` |
| Passenger log file | leave empty |
| Environment variables | **none**: every setting goes in `.env` (Step 6) |

Click **Create**. The application page then shows the command to enter its virtual environment.
Copy it: you will use it for SSH sessions, migrations and the cron job.

```sh
source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay
```

`24` is the Node.js major version. The app cannot start yet, and that is expected. Until
Step 5, `stderr.log` shows `Cannot find module ...`. After Step 5, and until `.env` exists
(Step 6), it shows `Invalid configuration`, starting with
`could not read /home/USER/relay/.env (ENOENT)`.

### Step 5: Install dependencies

On the application page click **Run NPM Install** and wait for it to finish. Over SSH you can
run this instead:

```sh
source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay
npm install --omit=dev
```

### Step 6: Write .env

`.env` in the application root is the **single source of settings**. The web app, the cron job,
SSH sessions and cPanel "Run JS script" all read it. Leave the environment-variable list in
cPanel **empty**: a variable set there overrides `.env` for the web app only, so the cron job and
the scripts would see different values.

```sh
source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay
cp .env.example .env
chmod 600 .env
npm run gen-secrets      # prints MASTER_KEY=... and SESSION_SECRET=... lines
nano .env                # or edit it in cPanel File Manager
```

Without SSH:

1. In File Manager, copy `.env.example` to `.env`, edit it, and set Permissions to `600`.
   - File Manager hides names that start with a dot. Click **Settings** (top right) and tick
     **Show Hidden Files (dotfiles)** to see `.env.example` and `.env`.
   - The file must be named exactly `.env` (not `env` or `.env.txt`) and sit in
     `/home/USER/relay`, next to `app.js`, not in the document root.
2. Use **Run JS script > gen-secrets** on the application page to generate the secrets.
   Alternatively, run `node scripts/gen-secrets.js` on your own computer.

Fill in at least these settings:

```ini
NODE_ENV=production
PUBLIC_BASE_URL=https://relay.companysite.site
DB_HOST=localhost
DB_NAME=USER_relay
DB_USER=USER_relay
DB_PASSWORD='the database password'
MASTER_KEY=<from gen-secrets>
SESSION_SECRET=<from gen-secrets>
ADMIN_BOOTSTRAP_EMAIL=you@companysite.site
ADMIN_BOOTSTRAP_PASSWORD='a long temporary password'
FORCE_HTTPS=true
COOKIE_SECURE=true
TRUST_PROXY=1
```

Notes:

- **Quote values that contain `#`, spaces or quotes**, using single quotes. An unquoted `#`
  starts a comment, so `DB_PASSWORD=ab#cd` is read as `ab`. Spaces around values are dropped.
- **Keep a copy of `.env` now**, in a password manager or other encrypted store. Without
  `MASTER_KEY`, the stored SMTP passwords, legacy API keys and 2FA secrets cannot be decrypted,
  not even from a database backup. See [Backups](#9-backups-and-restore).
- Relay logs a warning at startup if `.env` is readable by group or others.
- If `.env` is missing or cannot be read, startup says so as the first problem, for example
  `could not read /home/USER/relay/.env (ENOENT); settings come only from the environment`
  (`EACCES`: the file is not readable by your cPanel user).
- Every setting is listed in [section 4](#4-configuration-reference-env) and in `.env.example`.

### Step 7: Create the tables (migrations)

```sh
source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay
npm run migrate
# Applied migrations: 001_initial
```

Without SSH, use **Run JS script > migrate** on the application page. Running it again is
harmless; it then prints `Database is up to date (no pending migrations).`

You can also set `AUTO_MIGRATE=true` in `.env` to apply migrations at startup. Running them by hand
is recommended, so you see the result.

### Step 8: Restart and check that it runs

Click **Restart** on the application page (other methods: [Restarting](#restarting)). Then:

- `https://relay.companysite.site/v1/health` must show `{"ok":true}`. This check does not touch
  the database.
- `https://relay.companysite.site/admin` must show the sign-in page. This page needs the database.

If you get a LiteSpeed error page ("503 Service Unavailable" or "Incomplete response received from
application"), read `/home/USER/relay/stderr.log`. Configuration mistakes are listed there one per
line, after `Invalid configuration:`. If `LOG_FILE` is set, the same reason is also appended there
as one `ERROR startup failed` line. If `stderr.log` is empty or missing, run `npm run migrate` (or
Run JS script > migrate): it reads the same `.env` and prints the same lines.

### Step 9: Hourly cleanup cron job (required)

LiteSpeed stops idle Node.js apps after a few minutes, so Relay's in-process timer cannot be
relied on. The cron job is what does the following:

- marks interrupted sends as `unknown`
- deletes expired sessions, old idempotency keys, rate counters, and log entries older than
  `LOG_RETENTION_DAYS`

First create a folder for the job's output:

```sh
mkdir -p /home/USER/relay/logs
```

Then add the job under **cPanel > Cron Jobs**. Common Settings: **Once Per Hour (`0 * * * *`)**.
Command:

```sh
/bin/bash -c 'source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay && npm run cleanup' >> /home/USER/relay/logs/cron.log 2>&1
```

- `24` in the path is the Node.js major version. **Edit this line whenever you change the app's
  Node.js version** (see [Changing the Node.js version](#changing-the-nodejs-version)).
- Each run appends one line of JSON counts to `cron.log`, for example
  `{"unknownMarked":0,"sessionsDeleted":3,...}`. Errors also go there.
- Admin > System shows **Last cron run** and **Last cleanup by any trigger**. Its warnings track
  the cron job itself. Relay also runs cleanup in-process a minute after every start, which would
  otherwise hide a dead cron job. Admin > System warns when:
  - no cron run has been recorded yet. This is normal until the first full hour after you add
    the job.
  - the last cron run is more than 3 hours old.
  - the cron job runs, but no cleanup has finished in the last 3 hours (it fails each time).

### Step 10: First sign-in and the System page

At startup, Relay creates the bootstrap admin from `ADMIN_BOOTSTRAP_EMAIL` and
`ADMIN_BOOTSTRAP_PASSWORD`, but only when no admin exists yet. Sign in at
`https://relay.companysite.site/admin` and open **System**. Check:

- **Runtime** shows `LiteSpeed (lsnode)`, **Node.js** shows v24, and **NODE_ENV** shows
  `production`.
- **Database**:
  - **Server version** is shown.
  - **max_user_connections**: `DB_CONNECTION_LIMIT` (5 per process) must stay well below it.
  - **wait_timeout** is shown.
- **Request as seen by Relay**:
  - Client IP is **your own public IP**. If it shows `127.0.0.1` or the server's own address,
    `TRUST_PROXY` is too low.
  - `req.secure` is `true` and `req.protocol` is `https`.
  - `X-Forwarded-Proto` is `https`.
- **Run IP check** sends two requests: one normal, and one with a forged
  `X-Forwarded-For: 198.51.100.77` header. The possible results:
  - **"OK — your IP is ... and the forged header was ignored"**: correct.
  - **"Spoofable — lower TRUST_PROXY"**: any client can fake its IP, which defeats IP allowlists
    and per-IP limits. Lower `TRUST_PROXY` (1 is right behind Namecheap's LiteSpeed) and restart.
    If it is still spoofable at `1`, do not rely on IP allowlists, and ask support how
    X-Forwarded-For is set.
  - **"Client IP unavailable"**: check `TRUST_PROXY`.
- **Warnings** at the top. After Step 11, and once the cron job from Step 9 has run (at the next
  full hour), this list should be empty.

### Step 11: Remove the bootstrap password

1. Delete the values of `ADMIN_BOOTSTRAP_EMAIL` and `ADMIN_BOOTSTRAP_PASSWORD` in `.env`, then
   restart. Until you do, the password sits in a file, and Admin > System and the startup log keep
   warning about it.
2. **Account > Set up two-factor**: scan the QR code with an authenticator app, then enter a code
   to turn it on.
3. **Users > Add an admin**: add a second admin, so that one lost password or phone is not a
   lockout.
4. Admins can be created or reset from SSH at any time:

   ```sh
   node scripts/create-admin.js you@companysite.site --name "Your Name"
   node scripts/create-admin.js you@companysite.site --reset-2fa   # reset the password and turn off 2FA (lost phone)
   ```

   - In a terminal, the script asks for the password twice and does not show it.
   - Where there is no terminal, it reads the `RELAY_ADMIN_PASSWORD` environment variable for
     that one command.
   - A reset signs that admin out everywhere.

### Step 12: Smoke tests

Smoke tests prove that the whole path works on the real host, with realistic content:
LiteSpeed, ModSecurity, the request size limits, Relay, the SMTP server and the receiving
mailbox.

**Quick checks** (from any computer):

```sh
curl -i https://relay.companysite.site/v1/health
#   HTTP 200, {"ok":true}
curl -i -X POST https://relay.companysite.site/v1/send
#   HTTP 401, {"ok":false,"error":"missing api key"}
curl -sI http://relay.companysite.site/admin
#   a redirect to https://relay.companysite.site/admin
```

**Full messages through both endpoints.**

1. In the admin, create two temporary apps that use a mailbox you control:
   - "Smoke test", a normal app
   - "Smoke test (legacy)", with **Legacy signing (/send.php)** ticked
2. Generate a key for each, and press **Send test email** on each.
3. On your own computer (Node.js 18 or newer), save the script below as `relay-smoke.js`. It is
   not part of Relay, and it needs no dependencies. It sends one realistic HTML email (inline
   styles, a table, links, an image URL, Sinhala and Tamil text) with a **~9.5 MB PDF**:
   - through `/v1/send`
   - again with the same `message_id`, to check idempotency
   - through `/send.php`, signed the way the PHP app signs, with PHP-style `\/` escaping

   ```sh
   # bash / macOS / Linux
   export RELAY_V1_KEY='rly_...'        # key of "Smoke test"
   export RELAY_LEGACY_KEY='rly_...'    # key of "Smoke test (legacy)"
   node relay-smoke.js https://relay.companysite.site you@yourdomain.com
   ```

   ```powershell
   # Windows PowerShell
   $env:RELAY_V1_KEY = 'rly_...'; $env:RELAY_LEGACY_KEY = 'rly_...'
   node relay-smoke.js https://relay.companysite.site you@yourdomain.com
   ```

   To send a real PDF of about 9.5 MB instead of a generated one, add its path as a third
   argument.

<details>
<summary><code>relay-smoke.js</code></summary>

```js
'use strict';
// Relay smoke test: one realistic HTML message with a ~9.5 MB PDF through
// /v1/send and /send.php. Node 18+, no dependencies. Keys come from environment
// variables: RELAY_V1_KEY (normal app) and/or RELAY_LEGACY_KEY (legacy-signing app).
//   node relay-smoke.js https://relay.companysite.site you@example.com [file.pdf]
const crypto = require('node:crypto');
const fs = require('node:fs');

const [baseArg, to, pdfPath] = process.argv.slice(2);
if (!baseArg || !to) {
  console.error('usage: node relay-smoke.js <relay base URL> <your email> [file.pdf]');
  process.exit(2);
}
const base = baseArg.replace(/\/+$/, '');
const run = new Date().toISOString().replace(/\D/g, '').slice(0, 14);

// A valid one-page PDF padded with an unused random stream up to `size` bytes.
function makePdf(size) {
  const parts = [];
  const offsets = [];
  let length = 0;
  const add = (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
    parts.push(buf);
    length += buf.length;
  };
  const obj = (n, body) => {
    offsets[n] = length;
    add(`${n} 0 obj\n`);
    add(body);
    add('\nendobj\n');
  };
  const text = 'BT /F1 24 Tf 72 720 Td (Relay smoke test) Tj ET';
  add('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n');
  obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
  obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  obj(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>');
  obj(4, `<< /Length ${text.length} >>\nstream\n${text}\nendstream`);
  obj(5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const pad = crypto.randomBytes(Math.max(0, size - length - 400));
  obj(6, Buffer.concat([Buffer.from(`<< /Length ${pad.length} >>\nstream\n`), pad, Buffer.from('\nendstream')]));
  const xref = length;
  add('xref\n0 7\n0000000000 65535 f \n');
  for (let n = 1; n <= 6; n++) add(`${String(offsets[n]).padStart(10, '0')} 00000 n \n`);
  add(`trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
  return Buffer.concat(parts);
}

const pdf = pdfPath ? fs.readFileSync(pdfPath) : makePdf(Math.round(9.5 * 1024 * 1024));
const rows = Array.from({ length: 40 }, (_, i) =>
  `<tr><td style="padding:6px;border:1px solid #ddd">Item ${i + 1}</td>` +
  `<td style="padding:6px;border:1px solid #ddd;text-align:right">LKR ${(i * 1234.5).toFixed(2)}</td></tr>`
).join('\n');
const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Account opening</title>
<style>body{font-family:Arial,sans-serif;color:#222}.btn{background:#0b5394;color:#fff;padding:10px 16px;text-decoration:none}</style>
</head><body>
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto">
<tr><td><img src="https://www.example.com/logo.png" alt="Logo" width="160" height="40"></td></tr>
<tr><td><h1 style="font-size:20px">Dear A. Customer,</h1>
<p>Thank you for your application (reference <b>APP-${run}</b>). Your documents are attached as a PDF.</p>
<p>ආයුබෝවන් · வணக்கம் · "quotes", 'apostrophes', &amp; and &lt;brackets&gt;</p>
<table style="border-collapse:collapse;width:100%">${rows}</table>
<p><a class="btn" href="https://www.example.com/track?ref=APP-${run}&amp;lang=en">Track your application</a></p>
<p style="font-size:12px;color:#777">This is an automated message. Please do not reply.</p>
</td></tr></table></body></html>`;
const attachment = { filename: 'application-form.pdf', content_type: 'application/pdf', content_base64: pdf.toString('base64') };
console.log(`PDF ${(pdf.length / 1048576).toFixed(2)} MB, HTML ${(Buffer.byteLength(html) / 1024).toFixed(1)} KB`);

async function post(label, path, headers, body) {
  const started = Date.now();
  let res;
  try {
    res = await fetch(base + path, { method: 'POST', headers, body, signal: AbortSignal.timeout(120000) });
  } catch (err) {
    console.log(`${label}: request failed: ${(err.cause && (err.cause.code || err.cause.message)) || err.message}`);
    return null;
  }
  const text = await res.text();
  const type = res.headers.get('content-type') || '(none)';
  console.log(`${label}: HTTP ${res.status} in ${Date.now() - started} ms, Content-Type ${type}` +
    (res.headers.get('idempotent-replayed') ? ', Idempotent-Replayed: true' : ''));
  console.log(`  ${text.slice(0, 400).replace(/\s+/g, ' ')}`);
  if (!type.includes('application/json')) {
    console.log('  -> Not JSON: the web server or ModSecurity answered, not Relay (see README, smoke tests).');
  }
  return res.status;
}

(async () => {
  const v1Key = process.env.RELAY_V1_KEY;
  const legacyKey = process.env.RELAY_LEGACY_KEY;
  if (!v1Key && !legacyKey) console.log('Set RELAY_V1_KEY and/or RELAY_LEGACY_KEY.');

  if (v1Key) {
    const body = JSON.stringify({
      to,
      subject: `Relay smoke test ${run} (/v1/send)`,
      html,
      message_id: `smoke-${run}-v1`,
      attachments: [attachment],
    });
    const headers = { Authorization: `Bearer ${v1Key}`, 'Content-Type': 'application/json' };
    if ((await post('/v1/send', '/v1/send', headers, body)) === 200) {
      await post('/v1/send repeat (same message_id, must not send again)', '/v1/send', headers, body);
    }
  }

  if (legacyKey) {
    // Escape "/" like PHP's json_encode, so the request looks like the PHP app's.
    const body = JSON.stringify({
      message_id: `smoke-${run}-legacy`,
      to,
      to_name: 'Smoke Test',
      subject: `Relay smoke test ${run} (/send.php)`,
      html,
      attachments: [attachment],
    }).replace(/\//g, '\\/');
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = crypto.createHmac('sha256', legacyKey).update(`${timestamp}.${body}`).digest('hex');
    await post('/send.php', '/send.php', {
      'Content-Type': 'application/json',
      'X-Relay-Timestamp': timestamp,
      'X-Relay-Signature': `sha256=${signature}`,
    }, body);
  }
})();
```

</details>

A good run looks like this:

```
PDF 9.50 MB, HTML 6.7 KB
/v1/send: HTTP 200 in 1132 ms, Content-Type application/json; charset=utf-8
  {"ok":true,"id":"msg_3da38e95e2746623f2bfb167"}
/v1/send repeat (same message_id, must not send again): HTTP 200 in 267 ms, Content-Type application/json; charset=utf-8, Idempotent-Replayed: true
  {"ok":true,"id":"msg_3da38e95e2746623f2bfb167"}
/send.php: HTTP 200 in 1043 ms, Content-Type application/json; charset=utf-8
  {"ok":true}
```

Two emails should arrive, each with the PDF attached. **Admin > Logs** shows both as `sent`,
about 9.5 MB each. On the wire the email is about 13 MB, because MIME encodes attachments in
base64. So the mailbox provider must accept messages of that size: Microsoft 365 and Gmail do,
but some small mail hosts do not. Those reject with `smtp error: EMESSAGE 552`.

**Recognising a web-server block.** Relay itself always answers with JSON. A response with
`Content-Type: text/html` never reached Relay:

| You see | Cause |
|---|---|
| `406 Not Acceptable`, HTML page mentioning **Mod_Security** | A ModSecurity rule matched. HTML in a JSON body often triggers the XSS rules. |
| `403 Forbidden` HTML page | A ModSecurity/WAF rule, or a blocked IP |
| `413 Request Entity Too Large` HTML page | The web server's request body limit |
| `503` / `502` HTML page, or "Incomplete response received from application" | Relay is not running or crashed: read `stderr.log` |
| `413 {"ok":false,"error":"request too large"}` (JSON) | Relay's own request limit (`MAX_MESSAGE_BYTES`) |
| `413 {"ok":false,"error":"message too large"}` (JSON) | The app's or Relay's message size limit |

If the web server blocks the smoke test, open a ticket:

> Subject: ModSecurity / request size limit blocks JSON API requests on relay.companysite.site
>
> Hello. My Node.js application at https://relay.companysite.site receives HTTPS POST requests
> with JSON bodies (email HTML plus base64 attachments, up to about 15 MB) on two URLs only:
> `/v1/send` and `/send.php`. Some requests are blocked by the web server before they reach the
> application. The client gets HTTP `<406/403/413>` with an HTML page instead of the
> application's JSON. Example: `<date and time with time zone>`, client IP `<ip>`, URL `<url>`.
>
> Could you please whitelist the ModSecurity rule(s) that fired, for these two URLs on
> relay.companysite.site, and make sure request bodies up to 16 MB are accepted there? Please
> tell me which rule IDs you changed.

Afterwards, untick **Enabled** on both smoke-test apps, or revoke their keys. Keep the apps for
the next smoke test after an upgrade.

### Restarting

Restart after every change to `.env` and after every upgrade. Any of these works:

1. **cPanel > Setup Node.js App > Restart** (on the application's row or page).
2. Over SSH, for a Passenger-style restart on the next request:
   `mkdir -p /home/USER/relay/tmp && touch /home/USER/relay/tmp/restart.txt`
3. Over SSH: `cloudlinux-selector restart --json --interpreter nodejs --app-root relay`

LiteSpeed also stops the app after a few idle minutes and starts it again on the next request. The
first request after a pause therefore takes a few seconds longer.

**Restart in a quiet period.** A restart can interrupt a send that is in progress:

- On shutdown, Relay stops taking new requests and waits up to 20 s for the ones in progress.
  While an SMTP send is still running it waits longer, up to `SMTP_SEND_DEADLINE_MS` + 10 s
  (60 s with the defaults), so the send can finish and its caller gets the real answer.
  LiteSpeed may stop the process sooner than that; this has not been checked on the host.
- A send that Relay's own deadline (`SMTP_SEND_DEADLINE_MS`) cuts off during that wait is
  recorded at once. If the message data had already gone to the mail server, its row becomes
  `unknown` immediately and the caller gets `502 smtp error: ETIMEDOUT (outcome unknown)`. If the
  deadline hit before that (while connecting, logging in or giving the recipients), the row
  becomes `failed` and a retry with the same `message_id` may send it again.
- A send that never finishes because the process was killed (LiteSpeed stopping it hard, or a
  crash), or because Relay gave up waiting, stays `sending` in Admin > Logs. Once it is 10 minutes
  old, the next cleanup run marks it `unknown`. A retry gets `409 message_id is already being
  sent` during those 10 minutes.
- An `unknown` row means the mail server may have received the email, so its `message_id` stays
  locked for `IDEMPOTENCY_DAYS` (7 days): a retry gets `409 message_id outcome unknown`
  ([5.4](#54-idempotency-and-retries)).
- If Relay itself gave up waiting, `stderr.log` (and `LOG_FILE`, if set) has this line, with the
  number of sends it left behind:

  ```
  2026-10-02T08:15:30.120Z WARN shutdown abandoned SMTP sends still in flight; their outcome will be unknown {"count":1}
  ```

So restart when no sends are expected, and not during or right after a large batch. Afterwards:

1. Open Admin > Logs and look at the rows from around the restart: the **Sending** filter, and the
   **Failed (incl. rejected, unknown)** filter for `unknown` rows.
2. For each `sending` or `unknown` row, check with the recipient whether the email arrived. It may
   have arrived even though the outcome is unknown.
3. Only if it did not arrive, send it again with a **new** `message_id`. Relay stores no bodies,
   so the resend has to come from the sending site; for the legacy PHP app, from that app.

### Logs

| Where | What |
|---|---|
| `/home/USER/relay/stderr.log` | Relay's own log: startup, warnings, errors, SMTP failures, API authentication failures. Relay writes everything to stderr, and LiteSpeed's lsnode stores stderr here. |
| `LOG_FILE` (optional) | A second copy of the same lines, in a file you choose, e.g. `/home/USER/relay/logs/relay.log`. A failed start (for example `Invalid configuration`) is also recorded there, as one `ERROR startup failed` line. |
| `/home/USER/relay/logs/cron.log` | Output of the hourly cleanup (Step 9). |
| **Admin > Logs** | The message log in the database: time, app, source, recipients, subject, size, status, SMTP response or error. Kept for `LOG_RETENTION_DAYS`. |
| **Admin > Audit** | Every configuration change: who, what, when. |
| cPanel > Metrics > Errors | Web server errors, including ModSecurity blocks. |

Log lines look like this:

```
2026-10-01T11:31:43.674Z WARN api auth failed {"route":"api","reason":"missing api key","ip":"203.0.113.9"}
```

- Logs never contain message bodies, attachments, API keys or passwords.
- If `LOG_FILE` cannot be written (a directory, a missing permission, an invalid path), Relay keeps
  running and logs to stderr only. `stderr.log` then shows
  `WARN LOG_FILE cannot be written; logging to stderr only {"path":"...","code":"EACCES"}`.
- Relay rotates none of these files. If `stderr.log` or `LOG_FILE` grow large, empty them with
  `: > /home/USER/relay/stderr.log`.
- **`LSNODE_CONSOLE_LOG`** is a LiteSpeed setting, not a Relay setting. Without it, lsnode
  discards the app's stdout. Relay does not need it, because it logs to stderr. If you want
  stdout kept too, set `LSNODE_CONSOLE_LOG=/home/USER/relay/logs/console.log` as an environment
  variable in the cPanel application page. This is the one exception to "keep the cPanel variables
  empty": LiteSpeed's loader reads it before Relay reads `.env`.

### Upgrading Relay

1. Back up the database and `.env` ([section 9](#9-backups-and-restore)).
2. On your computer, commit and `git push` the changes.
3. **cPanel > Git Version Control > Manage** (the `relay` repository) **> Pull or Deploy >
   Update from Remote**. This pulls the new commits into `/home/USER/relay`; `.env`, logs and
   `node_modules` are untouched because Git ignores them. If cPanel refuses because of local
   changes, someone edited files on the server: undo those edits (or commit them on your
   computer instead) and pull again.
4. If `package.json` changed: **Setup Node.js App > Run NPM Install**.
5. If a new file appeared in `migrations/`: `npm run migrate`, or Run JS script > migrate.
   Running it when nothing is new is harmless.
6. Restart in a quiet period ([Restarting](#restarting)). Then check that Admin > System shows
   the new **Relay version** and no warnings, and that Admin > Logs has no `sending` or `unknown`
   rows from around the restart.
7. Run the smoke test.

### Changing the Node.js version

1. **Setup Node.js App > edit the application > Node.js version**, then save.
2. **Run NPM Install** again.
3. **Update the cron job** and anything else that uses the activate line. The virtual environment
   path contains the major version, for example `/home/USER/nodevenv/relay/24/` becomes
   `/home/USER/nodevenv/relay/26/`.
4. Restart in a quiet period ([Restarting](#restarting)) and check Admin > System, plus Admin >
   Logs for `sending` or `unknown` rows from around the restart. After the next full hour, check
   that Admin > System shows a recent **Last cron run**, or look at the end of
   `/home/USER/relay/logs/cron.log`. A wrong Node version in the cron path only shows up there.

---

## 4. Configuration reference (.env)

Everything is read from `.env` in the application root, as described in
[Step 6](#step-6-write-env). An empty value means "use the default". Restart after changes.
`.env.example` lists the same settings, with comments.

| Variable | Default | Notes |
|---|---|---|
| `NODE_ENV` | `production` | `production` turns on the HTTPS defaults and refuses unsafe settings. Use `development` only locally. |
| `PUBLIC_BASE_URL` | required in production (`http://localhost:3000` otherwise) | `https://relay.companysite.site`: scheme and host, no path. Must be `https://` when `FORCE_HTTPS` is on in production. Used for redirects, the CSRF origin check and the snippets. |
| `PORT` | `3000` | Only for `npm start` locally; LiteSpeed assigns its own socket. |
| `RELAY_TIMEZONE` | `Asia/Colombo` | IANA zone. Defines the "day" for per-day limits, Logs, Stats and the dates shown in the admin. |
| `DB_HOST` / `DB_PORT` | `localhost` / `3306` | TCP connection to MySQL/MariaDB. |
| `DB_SOCKET` | (none) | Unix socket path (e.g. `/var/lib/mysql/mysql.sock`). When set, it replaces host/port. |
| `DB_NAME`, `DB_USER` | required | The full cPanel names, e.g. `USER_relay`. |
| `DB_PASSWORD` | empty | Quote it if it contains `#`, spaces or quotes. |
| `DB_CONNECTION_LIMIT` | `5` | 2–50 connections per Node process (migrations, cleanup and key rotation need two). Keep the total over all processes well below `max_user_connections`. |
| `AUTO_MIGRATE` | `false` | Apply pending migrations at startup. |
| `MASTER_KEY` | required | 32 random bytes as 64 hex characters (or base64). Encrypts SMTP passwords, legacy API keys and 2FA secrets. Generate with `npm run gen-secrets`. **Never just replace it**: see [section 8](#rotating-the-master-key). |
| `MASTER_KEY_PREVIOUS` | (none) | Only during a master key rotation. |
| `SESSION_SECRET` | required | At least 32 characters. Signs admin session cookies; changing it signs everyone out. |
| `ADMIN_BOOTSTRAP_EMAIL` / `ADMIN_BOOTSTRAP_PASSWORD` | (none) | Set both or neither. The password needs 12–72 bytes. Creates the first admin when none exists. Remove after first use. |
| `FORCE_HTTPS` | `true` in production | Plain-HTTP GET/HEAD requests are redirected to `PUBLIC_BASE_URL` (308). Other plain-HTTP requests are refused with 403. Also sends HSTS (1 year). `GET /v1/health` is exempt. |
| `COOKIE_SECURE` | `true` in production | The session cookie is only sent over HTTPS. |
| `TRUST_PROXY` | `1` | Express "trust proxy": a hop count, or a comma-separated list of proxy IPs/CIDRs (or `loopback`, `linklocal`, `uniquelocal`). `1` is right behind Namecheap's LiteSpeed. `true` is refused in production. |
| `LOG_FILE` | (none) | Optional file that receives a copy of every log line, and the reason for a failed start. Not rotated. If it cannot be written, Relay warns on stderr and carries on without it. |
| `MAX_MESSAGE_BYTES` | `10485760` (10 MiB) | 1024 to 26214400 (25 MiB). Relay-wide cap per message, counted as in [5.6](#56-limits): subject + html + text + display names + each attachment's decoded size plus 1 KB plus 6 bytes per byte of its filename. Apps can set a lower cap. The raw request limit is derived from it: 1.4 × this + 1 MiB, which is 15 MiB by default. |
| `SMTP_TIMEOUT_MS` | `30000` | 1000–120000. Timeout for each SMTP phase: the DNS lookup, the connect attempt, the greeting, each reply, inactivity. Relay makes **one** connect attempt per send, to one address: the host's first IPv4 address, else its first IPv6 address. |
| `SMTP_SEND_DEADLINE_MS` | `50000` | 5000–300000. Hard limit for one whole send, from the DNS lookup to the server's final reply. When it passes, Relay closes the connection and the send fails with `ETIMEDOUT`; if the message data had already been sent, the outcome is unknown ([5.4](#54-idempotency-and-retries)). Keep it below the clients' timeout (60 s recommended). Shutdown waits up to this + 10 s for sends in progress. |
| `RATE_LIMIT_IP_PER_MINUTE` | `120` | Requests per minute per client IP (IPv6: per /64), for each of `/v1/send` and `/send.php`. |
| `DEFAULT_MAX_RECIPIENTS` | `50` | 1–1000. Default "maximum recipients" for new apps. |
| `LOG_RETENTION_DAYS` | `90` | 1–3650, and at least `IDEMPOTENCY_DAYS` (a smaller value stops the app at startup). Message log retention; enforced by the cleanup job. |
| `IDEMPOTENCY_DAYS` | `7` | 1–90, and at most `LOG_RETENTION_DAYS`. How long a `message_id` is remembered. |
| `LEGACY_MAX_SKEW_SECONDS` | `300` | 30–3600. Largest allowed `X-Relay-Timestamp` difference on `/send.php`. |
| `SESSION_IDLE_MINUTES` | `120` | 5–10080. Admin sessions end after this much inactivity... |
| `SESSION_ABSOLUTE_HOURS` | `12` | 1–720. ...and at the latest this long after sign-in. |
| `CLEANUP_INTERVAL_MINUTES` | `360` | 0–10080 (0 = off). In-process cleanup timer. It only supplements the required cron job. |

Boolean values accept `true/false`, `1/0`, `yes/no` and `on/off`. Invalid values stop the app at
startup, and every problem is listed in `stderr.log` (and in `LOG_FILE`, if set). A missing or
unreadable `.env` is reported as the first problem: `could not read <path> (<code>)`.

Not `.env` settings:

- `LSNODE_CONSOLE_LOG`: a LiteSpeed setting (see [Logs](#logs)).
- `RELAY_ADMIN_PASSWORD`: a one-off input to `scripts/create-admin.js`.
- `TEST_DB_*`: in `.env.test`, used by the test suite.

---

## 5. API reference (for client sites)

### 5.1 Basics

- **Base URL:** `https://relay.companysite.site`. Always use `https://`. A plain-HTTP POST is
  refused (`403 https required`) or redirected by the web server, and many HTTP clients turn a
  redirected POST into a GET.
- **One API key per app**, issued by the Relay admin. A key looks like `rly_` followed by 43
  letters, digits, `-` or `_` (47 characters in all), and is shown only once.
  - Keep it on your server, out of version control, browser JavaScript and mobile apps.
  - During a key change the old key keeps working for the grace period the admin chose (none,
    1 hour or 24 hours).
- **Which endpoint:** new integrations use `POST /v1/send` with a Bearer key. `POST /send.php`
  exists for the existing HMAC-signed PHP integration and other apps the admin marks "Legacy
  signing".
  - A legacy-signing app's key does **not** work on `/v1/send`.
  - A normal key does not work on `/send.php`.
- **Synchronous:** Relay answers once the app's SMTP server has accepted or refused the message,
  usually within 1–5 seconds. A slow mail server gets up to 30 seconds per SMTP step, and Relay
  gives up on it after at most 50 seconds in all (`SMTP_SEND_DEADLINE_MS`).
  - Use a connect timeout of 10 s and a total timeout of **60 s**.
  - Send a `message_id`. A retry with the same id never sends the message twice, whatever
    happened to the first attempt ([5.4](#54-idempotency-and-retries)). When Relay cannot tell
    whether the first attempt was delivered, the retry is refused rather than sent again.
- **Responses** are JSON with `Cache-Control: no-store`.
  - `/v1/send` answers `{"ok": true, "id": "..."}` or `{"ok": false, "error": "..."}`.
  - `/send.php` answers `{"ok": true}` or `{"error": "..."}`.
  - Error texts are short, stable, lower-case strings ([5.7](#57-errors)).
- **Ready-made code:** each app's page in the admin has copy-paste snippets (curl, PHP, Node) for
  that app's endpoint.

### 5.2 POST /v1/send

```http
POST /v1/send HTTP/1.1
Host: relay.companysite.site
Authorization: Bearer rly_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: application/json

{
  "to": ["A. Customer <customer@example.com>"],
  "cc": "accounts@example.com",
  "subject": "Your order #1234 has shipped",
  "html": "<p>Your order <b>#1234</b> is on its way.</p>",
  "text": "Your order #1234 is on its way.",
  "reply_to": "support@example.com",
  "message_id": "order-1234-shipped",
  "attachments": [
    { "filename": "invoice-1234.pdf", "content_type": "application/pdf", "content_base64": "JVBERi0xLjcK..." }
  ]
}
```

Headers:

- `Authorization: Bearer <key>`. The scheme name is case-insensitive.
- `Content-Type: application/json`, with no charset or a UTF charset. Anything else gives `415`.
- Do not compress the body: a compressed body (`Content-Encoding: gzip`, `deflate` or `br`) gives
  `415`.

| Field | Type | Required | Rules |
|---|---|---|---|
| `to` | string or array of strings | **yes** | One or more addresses. A string may hold several, comma-separated. Display names are allowed: `Name <a@example.com>`. An array may have at most *max recipients* items, each at most 1000 characters. |
| `cc`, `bcc` | string or array of strings | no | Same format. Bcc recipients receive the message without a Bcc header. |
| `subject` | string | **yes** | Not empty, at most 998 characters. Line breaks and control characters become spaces. |
| `html` | string | `html` or `text` | The HTML body. |
| `text` | string | `html` or `text` | The plain-text body. If missing, it is generated from `html` (images left out, links shown with their URL, each table row on its own line). Text-only messages are fine. |
| `reply_to` | string | no | One address. Default: the app's "Default Reply-To", if set. |
| `from` | string | no | Must equal the app's From address or one of its "other allowed From addresses" (case-insensitive). Otherwise the request fails with `400 from not allowed`. Only the address is used; the display name always comes from the app settings. |
| `attachments` | array | no | `[{ "filename", "content_base64", "content_type"? }]`: see [5.5](#55-attachments). |
| `message_id` | string (1–191 characters) or non-negative integer | no, **recommended** | Your idempotency key, e.g. `"order-1234-shipped"`: see [5.4](#54-idempotency-and-retries). |

Rules that apply to every field:

- `null` counts the same as leaving a field out.
- Unknown fields are ignored. That includes `headers`, `sender` and `envelope`: callers cannot
  set headers or the SMTP envelope.
- Recipients: the unique to + cc + bcc addresses must not exceed the app's maximum (default 50).
  Addresses are compared case-insensitively. An address listed more than once is sent to once,
  in the first place it appears (to, then cc, then bcc).
- Addresses must be plain ASCII `local@domain` with a real top-level domain.
  - Not allowed: IP-literal domains, quoted local parts, or several addresses separated only by
    spaces.
  - Write international domain names in punycode (`xn--...`).

The email that goes out:

- **From:** the app's From name, plus the app's From address (or the allowed `from`).
- **Reply-To:** `reply_to`, or the app's default.
- **Message-ID:** `<msg_...@<from domain>>`.
- **Body:** HTML and text alternatives, plus the attachments.
- MAIL FROM is the From address, and RCPT TO is the union of to, cc and bcc.

**Success:**

```json
HTTP/1.1 200 OK
{"ok":true,"id":"msg_3da38e95e2746623f2bfb167"}
```

`id` is Relay's message id; the admin can search the log for it. If the request repeats a
`message_id` whose first attempt was sent, the response is the **same id** with the header
`Idempotent-Replayed: true`, and nothing is sent.

**Failure:** `{"ok":false,"error":"<reason>"}` with a 4xx/5xx status ([5.7](#57-errors)).

curl:

```sh
curl -sS --connect-timeout 10 --max-time 60 https://relay.companysite.site/v1/send \
  -H "Authorization: Bearer $RELAY_API_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary '{"to":"customer@example.com","subject":"Hello","html":"<p>Hello</p>","message_id":"hello-0001"}'
```

PHP (curl extension):

```php
<?php
function relay_send(string $apiKey, array $message): array
{
    $body = json_encode($message);
    if ($body === false) {
        return ['ok' => false, 'error' => 'json_encode failed: ' . json_last_error_msg()];
    }
    $ch = curl_init('https://relay.companysite.site/v1/send');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $apiKey, 'Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 60,
    ]);
    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $result = is_string($response) ? json_decode($response, true) : null;
    if ($status === 200 && is_array($result) && !empty($result['ok'])) {
        return ['ok' => true, 'id' => $result['id']];
    }
    $error = is_array($result) && isset($result['error']) ? $result['error'] : (curl_error($ch) ?: 'HTTP ' . $status);
    return ['ok' => false, 'status' => $status, 'error' => $error];
}

$relayApiKey = 'rly_...';   // from your site's configuration, not from version control
$result = relay_send($relayApiKey, [
    'to'         => 'customer@example.com',
    'subject'    => 'Your order #1234 has shipped',
    'html'       => '<p>Your order <b>#1234</b> is on its way.</p>',
    'message_id' => 'order-1234-shipped',
]);
```

### 5.3 POST /send.php (legacy, HMAC-signed)

This is the endpoint of the existing legacy PHP app. Its request format is fixed. It works
only for apps that the admin marked **Legacy signing**.

```http
POST /send.php HTTP/1.1
Host: relay.companysite.site
Content-Type: application/json
X-Relay-Timestamp: 1790000000
X-Relay-Signature: sha256=eafd235b81c6d1a6cf54aef0bdc19260252f2137e65d4e93745b70a2f8d2e1ab

{"message_id":"app-1001","to":"customer@example.com","to_name":"A. Customer","subject":"Your account","html":"<p>Welcome<\/p>"}
```

**Signing algorithm**

1. Build the JSON body **once**, as a string. Send exactly these bytes, and do not let a library
   re-encode them.
2. `timestamp` = the current Unix time in **seconds**, as decimal digits (not milliseconds).
3. `signature` = the lower-case hex HMAC-SHA256 of the bytes `timestamp + "." + body`. The secret
   is the API key itself, as UTF-8.
4. Send the headers `X-Relay-Timestamp: <timestamp>` and `X-Relay-Signature: sha256=<signature>`.
   The `sha256=` prefix is lower-case; the hex may be either case.

**How Relay verifies it**

1. The headers are checked before the body is read:
   - missing or malformed → `401 missing or malformed signature headers`
   - timestamp more than `LEGACY_MAX_SKEW_SECONDS` (300 s) away from the relay's clock, in either
     direction → `401 timestamp out of range`
2. Relay reads the raw body. The `Content-Type` does not matter: PHP curl's default
   `application/x-www-form-urlencoded`, or none at all, is fine.
3. It computes the HMAC over the timestamp header text as received (trimmed), a dot, and the raw
   body bytes. It does this for every valid key (active or in grace) of every legacy-signing app,
   and compares in constant time. The matching key identifies the app. No match →
   `401 invalid signature`.

**Test vector:** check your implementation against these values.

| | |
|---|---|
| API key | `rly_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG` |
| `X-Relay-Timestamp` | `1790000000` |
| Body (exact bytes, as PHP `json_encode` writes them) | `{"message_id":"app-1001","to":"customer@example.com","to_name":"A. Customer","subject":"Your account","html":"<p>Welcome<\/p>"}` |
| `X-Relay-Signature` | `sha256=eafd235b81c6d1a6cf54aef0bdc19260252f2137e65d4e93745b70a2f8d2e1ab` |

**Body fields**

| Field | Type | Required | Rules |
|---|---|---|---|
| `message_id` | string (1–191 characters) or non-negative integer | no, **strongly recommended** | Idempotency key. `""` and `null` mean "none". |
| `to` | string, or an array with one string | **yes** | Exactly one address, otherwise `400 exactly one recipient required`. |
| `to_name` | string | no | Display name, used when `to` has none. Line breaks become spaces; a name longer than 998 characters is cut, not refused. |
| `subject` | string | **yes** | May be empty. |
| `html` | string | **yes** | Not empty. The text part is generated from it. |
| `attachments` | array | no | Same as `/v1/send` ([5.5](#55-attachments)). |

`cc`, `bcc`, `from`, `reply_to`, `text` and any other fields are ignored. From and Reply-To come
from the app settings.

**Responses**

- `200 {"ok":true}` on success. A repeated `message_id` whose first attempt was sent gets the same
  answer, and nothing is sent.
- Failures: `{"error":"<reason>"}` with a 4xx/5xx status.
- Other methods (GET and so on) get `405 {"error":"method not allowed"}`.

**Without a `message_id`**, Relay remembers each accepted signature until its timestamp expires
(timestamp + 300 s + 60 s). Sending the identical signed request again within that time gives
`409 replayed request`. A genuine retry therefore needs a fresh timestamp and signature, and
Relay cannot tell that it is a retry, so the email may be sent twice. **Always send a
`message_id`.**

PHP example:

```php
<?php
// Sends one message through Relay's signed /send.php endpoint. Requires the curl extension.
function relay_send_legacy(string $apiKey, array $message): array
{
    $body = json_encode($message);              // sign and send exactly this string
    if ($body === false) {
        return ['ok' => false, 'error' => 'json_encode failed: ' . json_last_error_msg()];
    }
    $timestamp = (string) time();                // seconds
    $signature = hash_hmac('sha256', $timestamp . '.' . $body, $apiKey);

    $ch = curl_init('https://relay.companysite.site/send.php');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'X-Relay-Timestamp: ' . $timestamp,
            'X-Relay-Signature: sha256=' . $signature,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 60,
    ]);
    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $result = is_string($response) ? json_decode($response, true) : null;
    if ($status === 200 && is_array($result) && !empty($result['ok'])) {
        return ['ok' => true];
    }
    $error = is_array($result) && isset($result['error']) ? $result['error'] : (curl_error($ch) ?: 'HTTP ' . $status);
    return ['ok' => false, 'status' => $status, 'error' => $error];
}

$relayApiKey = 'rly_...';   // the legacy app's key, from configuration
$result = relay_send_legacy($relayApiKey, [
    'message_id'  => 'application-1001-welcome',
    'to'          => 'customer@example.com',
    'to_name'     => 'A. Customer',
    'subject'     => 'Your account application',
    'html'        => '<p>Dear customer, ...</p>',
    'attachments' => [[
        'filename'       => 'application.pdf',
        'content_type'   => 'application/pdf',
        'content_base64' => base64_encode(file_get_contents('/path/to/application.pdf')),
    ]],
]);
```

### 5.4 Idempotency and retries

A `message_id` identifies one logical email, for example `order-1234-shipped`.

- Ids are **per app**: two apps can use the same id independently.
- An id is remembered for `IDEMPOTENCY_DAYS` (7 days).
- Ids are compared exactly, so they are case-sensitive. `123` and `"123"` are the same id.

When a request repeats an id within the window, what happens depends on the first attempt:

| First attempt with this `message_id` | The repeat gets | What to do |
|---|---|---|
| **sent** | `200` with the first result, and **nothing is sent again**. `/v1/send` returns the first `id` plus `Idempotent-Replayed: true`. | Nothing: it was delivered to the mail server. |
| **still sending** (less than 10 minutes old) | `409 message_id is already being sent` | Wait a minute and retry with the same id. |
| **failed** (SMTP error, `502 smtp error: <code>`) | a new attempt, which takes over the id | Retrying with the same id is the right thing. |
| **rejected** (validation or limits, `4xx`) | a new attempt | Fix the request and send it again with the same id. |
| **unknown outcome**: the connection to the mail server broke or timed out **after the message data was sent** (that attempt answered `502 smtp error: <code> (outcome unknown)`), or the relay process stopped mid-send (a restart or crash), or the attempt has shown "sending" for more than 10 minutes | `409 message_id outcome unknown` for the rest of the window | The mail server may have accepted the email, so Relay will not risk sending it twice. Check with the recipient or the admin; if it did not arrive, send it with a **new** `message_id`. |

The id is matched on its own; the content is not compared. A *different* email with a reused id
inside the window gets the first result and is **not** sent. Make ids unique per email, not per
customer or per form.

How a client should react to each status:

| Response | Retry? |
|---|---|
| `200` | Done. |
| `400`, `401`, `403`, `404`, `405`, `413`, `415` | No; fix the request, the key or the configuration first. |
| `409 message_id is already being sent` | Yes, with the same id, after about a minute. |
| `409 message_id outcome unknown` | Not with the same id (see above). |
| `409 replayed request` | Only by building a new signed request. |
| `429` | Yes, after the number of seconds in the `Retry-After` header. |
| `500`, `502 smtp error: <code>[ <reply code>]`, `502 smtp password not configured` | Yes, later, **with the same `message_id`**. A retry never sends twice: if the first attempt did get through after all, the retry gets its result or a `409`. |
| `502 smtp error: <code> (outcome unknown)` | **Not with the same id**: it gets `409 message_id outcome unknown`. The mail server may have accepted the message. Check with the recipient; if it did not arrive, send it with a **new** `message_id`. |
| Your own timeout, or a connection error (no answer from Relay) | Yes, **with the same `message_id`**. If Relay is still sending, the retry gets `409 message_id is already being sent`; if the first attempt was sent, `200` with its result; if it failed, a new attempt; if its outcome is unknown, `409 message_id outcome unknown`. |

Without a `message_id`, Relay cannot recognise a retry: after a timeout, a connection error or an
"outcome unknown" answer, the retry may send the email a second time.

### 5.5 Attachments

`"attachments": [{ "filename": "invoice.pdf", "content_base64": "...", "content_type": "application/pdf" }]`

- **The type comes from the filename extension** (case-insensitive), and the file content must
  match that type. `content_type` is optional and ignored, so `application/octet-stream` is fine.
  Relay sends the canonical type from the table below.
- `content_base64` is standard base64 (`A–Z a–z 0–9 + /`, `=` padding). Line breaks and spaces
  are allowed. A `data:` prefix and base64url are not allowed.
- `filename`: any path is dropped, and line breaks become spaces. It must be 1–200 characters.
- Empty files are rejected. There is no limit on the number of attachments, only on the message
  size, in which each attachment counts as its decoded size plus 1 KB (1024 bytes) for its MIME
  headers plus 6 bytes per UTF-8 byte of its filename, which the headers carry twice, encoded
  ([5.6](#56-limits)).
- Attachments are regular attachments. Inline `cid:` images are not supported, so reference images
  in the HTML by `https://` URL.

| Extension | Sent as | Content check |
|---|---|---|
| `pdf` | `application/pdf` | `%PDF-` within the first 1024 bytes |
| `jpg`, `jpeg` | `image/jpeg` | JPEG signature |
| `png` | `image/png` | PNG signature |
| `gif` | `image/gif` | `GIF87a` / `GIF89a` |
| `webp` | `image/webp` | `RIFF....WEBP` |
| `heic`, `heif` | `image/heic`, `image/heif` | HEIF `ftyp` brand |
| `bmp` | `image/bmp` | `BM` |
| `tif`, `tiff` | `image/tiff` | TIFF signature |
| `csv` | `text/csv` | no NUL bytes (UTF-16 with a BOM is fine) |
| `txt` | `text/plain` | no NUL bytes (UTF-16 with a BOM is fine) |
| `docx` | Word (`application/vnd.openxmlformats-officedocument.wordprocessingml.document`) | ZIP signature |
| `xlsx` | Excel (`application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) | ZIP signature |

Everything else is refused with `400 attachment type not allowed: <ext>`. That includes `svg`,
`html`, `zip`, `exe`, and the old `doc`/`xls` formats. A file whose content does not match its
extension gets `400 attachment content does not match file type`.

### 5.6 Limits

| Limit | Value | Error |
|---|---|---|
| Message size | The app's "Maximum message size" (default 10 MB) and the relay-wide `MAX_MESSAGE_BYTES` (default 10 MiB, at most 25 MiB). Size = UTF-8 bytes of subject + html + text as sent, plus every display name you send (`to`, `cc`, `bcc`, `reply_to`; on `/send.php` the recipient's name), plus for each attachment its decoded size + 1 KB (1024 bytes) + 6 bytes per UTF-8 byte of its filename (a 20-character ASCII name adds 120 bytes; non-ASCII characters take 2-4 bytes each). The From name and the text Relay generates from html do not count. 1 MB = 1,048,576 bytes. | `413 message too large` |
| Request size | Raw HTTP body ≤ 1.4 × `MAX_MESSAGE_BYTES` + 1 MiB (15 MiB by default), to allow for base64 (+33 %) and JSON escaping | `413 request too large` |
| Recipients | Unique to + cc + bcc ≤ the app's maximum (default 50). `/send.php`: exactly one. | `400 too many recipients (max N)` |
| Per app | The app's messages per minute (default 30) and per day (default 1000). The day runs from midnight to midnight in `RELAY_TIMEZONE`. | `429 rate limit exceeded (per minute)` / `(per day)` + `Retry-After` |
| Per client IP | `RATE_LIMIT_IP_PER_MINUTE` (120) requests per minute on each endpoint | `429 too many requests` + `Retry-After` |
| Subject | 998 characters (`/v1/send`) | `400 subject too long` |
| Recipient name (`/send.php`) | 998 characters | none: a longer name is cut |
| `message_id` | 1–191 characters | `400 invalid message_id` |

Which requests count against the per-app limits:

- Requests that fail validation, and repeats of an already sent `message_id`, do not count.
- Accepted requests count even if the SMTP server then refuses the message.
- Admin test emails do not count.

Remember the receiving side too: a 9.5 MB attachment is about 12.7 MB as base64 in the request,
and about 13 MB as an email.

### 5.7 Errors

`/v1/send` answers `{"ok":false,"error":"<text>"}`. `/send.php` answers `{"error":"<text>"}`.

| Status | `error` | Endpoint | Meaning |
|---|---|---|---|
| 400 | `invalid json body` | both | The body is not a JSON object. |
| 400 | `invalid request body` | both | The body could not be read. |
| 400 | `to is required` | /v1 | No recipient. |
| 400 | `invalid to address`, `invalid cc address`, `invalid bcc address`, `invalid reply_to address`, `invalid from address` | both (legacy: `to` only) | An address is malformed. |
| 400 | `exactly one recipient required` | /send.php | `to` holds zero or several addresses. |
| 400 | `too many recipients (max N)` | /v1 | More unique recipients than the app allows. |
| 400 | `from not allowed` | /v1 | `from` is not the app's From or an allowed address. |
| 400 | `subject is required`, `subject must be a string`, `subject too long` | both (`too long`: /v1) | |
| 400 | `html or text is required`, `html must be a string`, `text must be a string` | /v1 | |
| 400 | `html is required` | /send.php | |
| 400 | `invalid message_id` | both | Not a string or integer of 1–191 characters. |
| 400 | `attachments must be an array`, `invalid attachment`, `invalid attachment filename`, `attachment type not allowed: <ext>`, `attachment is not valid base64`, `attachment is empty`, `attachment content does not match file type` | both | See [5.5](#55-attachments). |
| 401 | `missing api key`, `invalid api key` | /v1 | Sent with `WWW-Authenticate: Bearer`. The key is wrong, revoked or expired, or belongs to a legacy-signing app. |
| 401 | `missing or malformed signature headers`, `timestamp out of range`, `invalid signature` | /send.php | See [5.3](#53-post-sendphp-legacy-hmac-signed). |
| 403 | `app disabled` | both | The admin switched the app off. |
| 403 | `ip not allowed` | both | The client IP is not in the app's IP allowlist. |
| 403 | `https required` | both | The request came over plain HTTP. |
| 404 | `not found` | /v1 | Wrong URL. |
| 405 | `method not allowed` | /send.php | Only POST is accepted. |
| 409 | `message_id is already being sent` | both | See [5.4](#54-idempotency-and-retries). |
| 409 | `message_id outcome unknown` | both | See [5.4](#54-idempotency-and-retries). |
| 409 | `replayed request` | /send.php | The same signed request without a `message_id`, sent again. |
| 413 | `message too large` | both | Over the app's or the relay's message size limit. |
| 413 | `request too large` | both | The HTTP body is over the request limit. |
| 415 | `content-type must be application/json` | /v1 | |
| 415 | `unsupported charset` | /v1 | Use UTF-8. |
| 415 | `content-encoding not supported` | both | Do not compress the body. |
| 429 | `too many requests` | both | Per-IP limit. See `Retry-After`. |
| 429 | `rate limit exceeded (per minute)`, `rate limit exceeded (per day)` | both | Per-app limit. See `Retry-After`; for the daily limit, that is the seconds until local midnight. |
| 500 | `internal error` | both | Unexpected relay error, for example the database is down. Retry later. |
| 502 | `smtp error: <code>[ <reply code>]`, e.g. `smtp error: EAUTH 535`, `smtp error: ETIMEDOUT` | both | The app's SMTP server failed or refused the message, and it was not delivered. The full server reply is in Admin > Logs. Retry later with the same `message_id`. |
| 502 | `smtp error: <code> (outcome unknown)`, e.g. `smtp error: ETIMEDOUT (outcome unknown)` | both | The connection broke or timed out **after the message data was sent**, so the server may have accepted it. The log row is `unknown` and the `message_id` stays locked. Do not retry with the same id ([5.4](#54-idempotency-and-retries)). |
| 502 | `smtp password not configured` | both | The app's SMTP settings changed and the password was not re-entered. Ask the admin. |

Common SMTP codes:

| Code | Meaning |
|---|---|
| `EAUTH` | Login refused |
| `ESOCKET` | Connection or TLS failure, including certificate errors |
| `ETIMEDOUT` | No answer within `SMTP_TIMEOUT_MS` (30 s) in one step, or the whole send took longer than `SMTP_SEND_DEADLINE_MS` (50 s) |
| `EDNS` | The SMTP host name does not resolve, or DNS did not answer in time |
| `ETLS` | STARTTLS required but not offered |
| `EENVELOPE` | Sender or all recipients refused |
| `EMESSAGE` | Message refused, for example because it is too large or classed as spam |
| `ECONNECTION` | The connection closed unexpectedly |

### 5.8 GET /v1/health

`GET https://relay.companysite.site/v1/health` returns `200 {"ok":true}`. It needs no
authentication and does not touch the database, which makes it suitable for uptime monitors.
Relay exempts it from its own HTTPS redirect, but the web server's Force HTTPS Redirect still
applies, so monitor the `https://` URL.

---

## 6. Migrating the legacy PHP app

The existing legacy PHP app must keep working unchanged: **only its relay URL and its
key change**. Relay's `/send.php` accepts exactly the request format the app already uses: the
same headers, signature and JSON.

1. **Step 0:** run `smtp-probe.js` from the hosting account against the SMTP server the legacy app
   mailbox uses.
2. **Admin > Apps > New app.** Fill in:
   - **Name:** e.g. "Account opening (legacy PHP)".
   - **SMTP server:** that app's mailbox host, port, encryption, username and password.
   - **From address and From name:** what the emails should show. The From address usually has to
     be the mailbox itself.
   - **Legacy signing (/send.php):** **ticked**.
   - **Limits:** messages per minute and per day above the app's real peak.
   - **IP allowlist** (optional, recommended): the PHP server's fixed outgoing IP address.

   Save.
3. On the app page, click **Generate API key**. Copy the key now; it is shown only once.
4. **Send test email** to yourself from the app page.
5. In the PHP app's configuration, change **only**:
   - the relay URL → `https://relay.companysite.site/send.php`
   - the key → the new key

   Change nothing else.
6. Run one real account-opening flow. Check that **Admin > Logs** shows it with source `legacy`
   and status `sent`, and that the email arrived.
7. Keep the old URL and key at hand until you are satisfied, so you can switch back.

Points to check on the PHP side:

- **Clock:** the PHP server's clock must be within 5 minutes of real time. Use NTP.
- **One recipient per request.** `to_name` is used as the display name. `cc`, `bcc`, `from`,
  `reply_to` and `text` are ignored.
- **Attachment types** must be in the [allowed list](#55-attachments). For example, if the app
  attaches `.doc` or `.zip` files, those requests fail with `400 attachment type not allowed: doc`.
- **Size:** each request must fit the app's size limit (default 10 MB): subject, html, the
  recipient's name, and each attachment's decoded size plus 1 KB and 6 bytes per filename byte
  ([5.6](#56-limits)).
- **Duplicates:** with a `message_id`, retries never send twice within 7 days, and once the first
  attempt was sent the response is `200 {"ok":true}` again. Without one, only exact replays are
  blocked (see [5.3](#53-post-sendphp-legacy-hmac-signed)).
- **`{"error":"smtp error: <code> (outcome unknown)"}` (502):** the mail server may have received
  the email. A retry with the same `message_id` gets `409 message_id outcome unknown`, so check
  with the customer before sending it again under a new id ([5.4](#54-idempotency-and-retries)).
- **Content-Type** does not matter. The app's existing curl call may send
  `application/x-www-form-urlencoded`.

Notes:

- Legacy keys are stored encrypted (recoverable), not hashed, because the relay needs the plain
  key to check the HMAC. An IP allowlist is the best extra protection for this app.
- Turning **Legacy signing** on or off revokes all of the app's keys when you save; the form asks
  you to confirm. Generate a new key and update the PHP app afterwards.
- To change the key later: **Regenerate key** with a grace period (1 hour or 24 hours), update
  the PHP config, and the old key stops working when the grace period ends
  ([section 8](#8-rotating-keys-and-secrets)).

---

## 7. Admin guide

Sign in at `https://relay.companysite.site/admin`.

- Sessions end after `SESSION_IDLE_MINUTES` (120) of inactivity, and at the latest
  `SESSION_ABSOLUTE_HOURS` (12) after sign-in.
- Sign-in is rate-limited per IP address (an IPv6 address counts with its whole /48) and per
  account.
- Admins with two-factor authentication enter a 6-digit code after the password.
- A sign-in page left open too long answers "The sign-in form expired. Sign in again." with a
  fresh form.
- **Sign out** ends the session on that device only, and for good: a page still loading on that
  device cannot bring it back. To end your sessions on all other devices, change your password
  under Account.

### Apps (`/admin`)

The list shows each app's name, Enabled/Legacy badges, today's sent and failed counts, and when
it was last used. **New app** opens the settings form:

- **General**
  - **Name:** required.
  - **Notes:** for admins only.
  - **Enabled:** a disabled app's requests get `403 app disabled`; test emails still work.
  - **Legacy signing (/send.php):** see [section 6](#6-migrating-the-legacy-php-app).
- **SMTP server**
  - **Host** and **Port**.
  - **Encryption:**
    - SSL/TLS, usually port 465
    - STARTTLS, usually port 587
    - None (unencrypted)

    Certificates are always verified.
  - **Username:** leave it empty for a server that needs no login.
  - **SMTP password:**
    - It is stored encrypted and never shown again.
    - On the app page the field is **Change SMTP password**. Leave it blank to keep the stored
      password.
    - **If you change the host, port, encryption or username without entering the password in the
      same save, the stored password is cleared.** The app then fails with
      `502 smtp password not configured` until you enter it again. This stops a saved password
      from being sent to a different server.
- **Sender**
  - **From address:** every message uses it. Most SMTP servers only accept their own mailbox here.
  - **From name:** callers cannot change it.
  - **Other allowed From addresses:** up to 20. A `/v1/send` caller may choose one of them as
    `from`.
  - **Default Reply-To.**
- **Limits and access**
  - **Messages per minute:** default 30.
  - **Messages per day:** default 1000.
  - **Maximum message size (MB):** default 10, at most `MAX_MESSAGE_BYTES`.
  - **Maximum recipients per message:** default 50.
  - **IP allowlist:** one IP address or CIDR range per line, up to 50. Empty means any address.

### App page

- **API keys:** a table with prefix, status (active / grace / revoked / expired), created, last
  used and expires.
  - **Generate API key** (only when there is no active key) shows the full key **once**, on a
    page that is not cached. Copy it there; afterwards only the prefix is shown.
  - **Regenerate key** creates a new key. The old one stays valid for the chosen grace period:
    none, 1 hour (the default) or 24 hours.
  - **Revoke** stops a key immediately.
  - If the keys changed after you opened the page (say a colleague regenerated them, or a form was
    submitted twice), you get "keys changed since the page was loaded; reload and try again".
- **Send test email:** sends "Relay test: \<app name\>" to the address you enter. It works even
  when the app is disabled. It ignores the IP allowlist and does not count against the limits. The
  result shows the SMTP server's reply, or the exact error.
- **Code snippets:** curl, PHP and Node examples for this app's endpoint, with `YOUR_API_KEY` as
  the placeholder.
- **Recent changes:** the last 10 audit entries for the app.
- The header shows when the app was created, when its settings were last updated, and when it
  was last used.
- **Saving settings** is refused if someone else saved this app's settings after you opened the
  page: "Settings changed since you loaded this page; reload and try again." Nothing is saved then.

### Logs (`/admin/logs`)

One row per message: time, app, source (`api`, `legacy` or `test`), recipients, subject, size,
status, and the SMTP response or error. The row also shows Relay's `msg_...` id and the client's
`message_id`. 50 rows per page.

- **Filters:** app, status, day range, and "Recipient contains".
- **Statuses:**

  | Status | Meaning |
  |---|---|
  | `sent` | Accepted by the SMTP server. |
  | `failed` | SMTP error. |
  | `rejected` | Refused by Relay: validation, limits, disabled app, IP not allowed. |
  | `unknown` | The connection broke or timed out after the message data was sent, or the send was cut off by a restart or crash. The email may have been delivered. Its `message_id` stays locked ([5.4](#54-idempotency-and-retries)). |
  | `sending` | In progress. A row that stays `sending` for more than 10 minutes was cut off; the cleanup job then marks it `unknown`. |

  The "failed" filter shows failed, rejected and unknown together.
- Rejected requests are logged only after the API key was accepted. When one app gets a flood
  of them, at most 60 rejected rows per minute (or the app's per-minute limit, if higher) are
  written for it; the rest are only counted (Admin > System shows today's count per app).
- Bodies and attachments are never stored. Entries are deleted after `LOG_RETENTION_DAYS` (90).

### Stats (`/admin/stats`)

Sent and failed per app per day, over 7, 14, 30 or 90 days, optionally for one app. "Failed"
includes rejected and unknown; the breakdown is shown in small text. Totals are at the bottom.

### Audit (`/admin/audit`)

Every configuration change and security event: who, what, when, and from which IP. It covers:

- sign-ins and failed sign-ins
- app create, update, enable and disable
- SMTP password changes
- key create, regenerate and revoke
- test emails
- admin and 2FA changes
- master key rotation

Changed fields are shown as `field: from → to`. Secrets appear only as `[changed]`.
`/admin/audit?app=<id>` narrows the log to one app. In the "who" column, `system` is Relay itself
or one of its command-line scripts, and `anonymous` is a sign-in attempt by someone not yet signed
in, shown with the email address that was typed.

### Users (`/admin/users`)

- **Add an admin:**
  - The password needs at least 12 characters. Give it to the person over a separate channel;
    they can change it under Account.
  - You must enter your own current password.
- **Disable / Enable.** Both need your current password. You cannot disable yourself or the last
  enabled admin.
- **Reset password.** Tick "Also turn off two-factor authentication (lost device)" if needed. This
  needs your current password.
- A reset or disable signs that admin out everywhere.
- Entering your current password for these actions (and on the Account page) allows 10 wrong
  entries per 15 minutes; correct entries do not count. After that you get "Too many attempts.
  Try again later.", even with the right password, until the current 15-minute period ends.

### Account (`/admin/account`)

- **Change password.** This signs you out on your other devices.
- **Set up two-factor:**
  1. Enter your password.
  2. Scan the QR code, or type in the key, with an authenticator app (TOTP, 6 digits, 30 s).
  3. Enter a code to turn it on.

  The key is shown only on that page.
- **Turn off two-factor** needs your password.
- If you lose your phone, another admin resets your password with "turn off two-factor". Or, over
  SSH: `node scripts/create-admin.js <email> --reset-2fa`.

### System (`/admin/system`)

- **Versions:** Relay, Node.js, runtime, `NODE_ENV`, public URL, time zone and local time, uptime.
- **Database:** version, `max_user_connections`, `wait_timeout`.
- **Cleanup:** the last run of the cron job, the last cleanup by any trigger (the cron job or the
  in-process timer), and its result.
- **API authentication failures:** today's count per endpoint, and the last failure (reason, IP,
  time). Below them, the rejected requests not written to the log today, per app (see
  [Logs](#logs-adminlogs)).
- **Warnings:**
  - bootstrap credentials still set
  - `TRUST_PROXY=true`
  - HTTPS or secure cookies off
  - the hourly cleanup cron job has no recorded run, has not run in the last 3 hours, or runs
    without finishing a cleanup
  - the database query failed
- **The request as Relay sees it**, and the **IP check**
  ([Step 10](#step-10-first-sign-in-and-the-system-page)).

---

## 8. Rotating keys and secrets

### API keys

Routine change, without downtime:

1. App page > **Regenerate key**, grace **1 hour** (or **24 hours** if the site takes longer to
   update). Copy the new key.
2. Put the new key in the site's configuration.
3. In the keys table, the new key's **last used** time starts to update. The old key shows
   **grace** until it expires, then **expired**.

The same works for legacy-signing apps: during the grace period both keys verify.

**If a key leaked:** **Regenerate key** with grace **none**, or **Revoke**. The leaked key, and any
other key still in grace, stops working at once.

Revoke a leaked key even if the app is disabled or has an IP allowlist. Those refuse the key
holder's requests, but the key itself is still valid, so every request with it still adds a
`rejected` row to the message log. Relay limits these rows (at most 60 per minute, or the app's
per-minute limit if higher, and a few KB each), but only revoking the key stops them.

### Rotating the master key

`MASTER_KEY` encrypts the SMTP passwords, legacy API keys and 2FA secrets. Do not just replace
it. Rotate it like this:

1. Back up the database and `.env` ([section 9](#9-backups-and-restore)).
2. Generate a new key: `npm run gen-secrets`, and use only the `MASTER_KEY` line.
3. In `.env`, set `MASTER_KEY_PREVIOUS=<the current key>` and `MASTER_KEY=<the new key>`.
   **Restart.** From now on new secrets are written with the new key, and existing ones still
   decrypt with the previous key.
4. Re-encrypt everything. There is no npm script for this, so run it with node:

   ```sh
   source /home/USER/nodevenv/relay/24/bin/activate && cd /home/USER/relay
   node scripts/rotate-master-key.js
   # {"smtpPasswords":4,"apiKeys":1,"totpSecrets":2,"failed":0}
   # Done. You can now remove MASTER_KEY_PREVIOUS from .env and restart the app.
   ```

   The rotation is audited (`system.master_key_rotate`) and is safe to run again.
5. If `failed` is above 0, the script exits with code 1. Some secrets could be decrypted with
   neither key and were left unchanged. Fix them by hand:
   - re-enter those apps' SMTP passwords
   - regenerate those legacy keys
   - turn off and set up again those admins' 2FA (Users > Reset password with "turn off
     two-factor", or `create-admin.js --reset-2fa`)
6. Remove `MASTER_KEY_PREVIOUS` from `.env` and restart. Update your `.env` backup.

Keep the old key **with the old database backups** for as long as you keep those backups; they
were encrypted with it.

### Session secret

Replace `SESSION_SECRET` and restart. Every admin is signed out; nothing else changes.

### If `.env` may have leaked

Rotate everything:

- the master key (above)
- `SESSION_SECRET`
- the database password (in cPanel, then in `.env`)
- every app's SMTP password, at the mail provider and then in Relay
- the API keys of the legacy-signing apps

Normal API keys are stored only as hashes, so they are not in `.env` or the database in a usable
form.

---

## 9. Backups and restore

What to back up:

- **The database** holds everything Relay knows: apps, key hashes, encrypted secrets, admin users,
  the log and the audit log.
- **`.env`** holds `MASTER_KEY` and the other secrets.
- The code can be uploaded again.

Back these two up **separately**:

- A database backup without `MASTER_KEY` cannot reveal SMTP passwords.
- A database backup without `.env` cannot restore them either.

**Database:**

- Daily, or at least before every upgrade or rotation.
- In the UI: **cPanel > Backup > Download a MySQL Database Backup** (`USER_relay`), or phpMyAdmin >
  Export.
- Over SSH or cron, put the credentials in a private option file first.
  `/home/USER/.relay-backup.cnf`, `chmod 600`:

  ```ini
  [client]
  user=USER_relay
  password='the database password'
  ```

  Then, for example as a daily cron job:

  ```sh
  mkdir -p /home/USER/backups && chmod 700 /home/USER/backups
  mysqldump --defaults-extra-file=/home/USER/.relay-backup.cnf --single-transaction --no-tablespaces USER_relay | gzip > /home/USER/backups/relay-$(date +\%F).sql.gz
  find /home/USER/backups -name 'relay-*.sql.gz' -mtime +14 -delete
  ```

  In a cPanel cron command, `%` must be written as `\%`, as above. On MariaDB 11, `mariadb-dump`
  is the same tool as `mysqldump`.
- Keep copies off the server too. The backups contain recipients and subjects (personal data),
  so store them privately.

**`.env`:**

- Download a copy after every change.
- Keep it in a password manager or another encrypted store, not next to the database backups.

**Restore:**

1. Create the database and user (Step 2), and import the dump: phpMyAdmin > Import, or
   `gunzip -c relay-....sql.gz | mysql --defaults-extra-file=... USER_relay`.
2. Clone the code again (Step 3) and put back `.env` with the **same `MASTER_KEY`**.
3. Run NPM Install, `npm run migrate` (applies only newer migrations), then restart.

**If `MASTER_KEY` is lost:**

- Normal API keys keep working, because they are hashes.
- Every app's SMTP password must be entered again.
- Legacy-signing apps need new keys.
- Admins with 2FA need `node scripts/create-admin.js <email> --reset-2fa`.

---

## 10. Security notes

- **HTTPS only.**
  - `FORCE_HTTPS=true` redirects or refuses plain HTTP and sends HSTS for one year.
  - `COOKIE_SECURE=true` keeps the session cookie off plain HTTP.
  - Admin pages send a strict Content-Security-Policy, refuse framing, and protect every form
    with a CSRF token and an Origin check.
- **`TRUST_PROXY`** decides which `X-Forwarded-For` entry is the client.
  - `1` is right behind Namecheap's LiteSpeed.
  - A higher value, or `true`, lets clients fake their IP. That bypasses IP allowlists and per-IP
    limits, and `true` is refused in production.
  - Run the IP check on Admin > System after every hosting change. If you put a CDN or another
    proxy in front of Relay, adjust `TRUST_PROXY` and check again.
- **Encryption "none"** sends the SMTP username, password and every message across the network
  in clear text. Use it only for a mail server on the same machine or a trusted private network.
  The app form shows a warning when it is selected.
- **Microsoft 365:** Microsoft has announced that **Basic authentication for SMTP AUTH (client
  submission to smtp.office365.com) is disabled by default from the end of December 2026**.
  - Relay logs in with a username and password only (AUTH PLAIN, LOGIN or CRAM-MD5, no OAuth). Apps
    that use a Microsoft 365 mailbox will fail with `smtp error: EAUTH 535` once it is off for
    their tenant.
  - Before then, either move those apps to an SMTP service that still accepts a password (for
    example the domain's cPanel mailbox or a transactional email provider), or have the tenant
    admin keep SMTP AUTH enabled for those mailboxes while Microsoft allows it.
  - Check the Microsoft 365 message center for the current dates.
- **Gmail / Google Workspace** require an app password (with 2-Step Verification) for SMTP
  login.
- **API keys:**
  - Normal keys are stored only as SHA-256 hashes; only the first 12 characters are kept for
    display.
  - Legacy keys are stored encrypted, because the HMAC needs them. Protect those apps with an IP
    allowlist where possible.
  - Keys are shown once, and never logged or audited.
  - A leaked key must be revoked: disabling the app or an IP allowlist does not stop its holder
    from adding `rejected` rows to the log ([section 8](#api-keys)).
- **Secrets are bound to their row.** An SMTP password only decrypts for the same app, host,
  port, encryption and username, so a ciphertext copied elsewhere, or a host edited directly in
  the database, makes it fail safely.
- **The sender cannot be spoofed.** The From address comes from the app settings. Mail goes out
  through the app's own mailbox, so its SPF/DKIM/DMARC alignment stays as it is for that mailbox.
- **Personal data:** the log keeps recipients and subjects for `LOG_RETENTION_DAYS` (90). It is
  visible to every admin, so give each person their own admin account, with 2FA.
- **Files:**
  - `.env` must be `chmod 600`.
  - The application root stays outside `public_html` and the subdomain's document root.
  - Never put secrets in the cPanel environment-variable list, in code, or in email.

---

## 11. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| LiteSpeed "503" or "Incomplete response received from application" | Relay did not start | Read `/home/USER/relay/stderr.log`. `Invalid configuration:` lists every bad `.env` value. Fix, then restart. If `stderr.log` is empty, run `npm run migrate`: it prints the same lines. |
| Startup: `could not read /home/USER/relay/.env (ENOENT)`, followed by "... is required" lines | `.env` is missing, misnamed (`env`, `.env.txt`) or in the wrong folder | Create `.env` in `/home/USER/relay`, next to `app.js`. In File Manager, tick Settings > **Show Hidden Files (dotfiles)** to see it. |
| Startup: `could not read /home/USER/relay/.env (EACCES)` | Your cPanel user cannot read the file | Make your cPanel user its owner, then `chmod 600 /home/USER/relay/.env`. |
| `Cannot find module 'express'` (or similar) in `stderr.log` | Dependencies not installed | Run NPM Install. Make sure the app root has no real `node_modules` folder. |
| Run NPM Install complains about `node_modules` | A real `node_modules` folder exists in the app root (created by hand or uploaded) | Delete `/home/USER/relay/node_modules`, then Run NPM Install. |
| `ER_ACCESS_DENIED_ERROR` / "Access denied for user" | Wrong DB name/user/password, or the user is not added to the database. TCP to `localhost` may also be refused. | Use the full prefixed names, and quote a password containing `#`. Check the user's privileges. If it still fails, set `DB_SOCKET=/var/lib/mysql/mysql.sock`. |
| `ECONNREFUSED`, for example `connect ECONNREFUSED 127.0.0.1:3306`, or with `DB_HOST=localhost` both addresses: `ECONNREFUSED: connect ECONNREFUSED ::1:3306; connect ECONNREFUSED 127.0.0.1:3306` | MySQL is not listening on TCP there | Set `DB_SOCKET=/var/lib/mysql/mysql.sock`. Leave `DB_HOST=localhost`: cPanel database users are granted for `localhost`. |
| Sign-in page reloads forever, "The sign-in form expired. Sign in again." every time, or "Invalid or expired form" after signing in | The session cookie is not set, because Relay does not see HTTPS | Keep `FORCE_HTTPS=true`, `COOKIE_SECURE=true` and `TRUST_PROXY=1`. Open Admin > System, or the log: `X-Forwarded-Proto is https but not trusted` means `TRUST_PROXY` is too low, and `cannot detect HTTPS` means the proxy sends no `X-Forwarded-Proto`. Always use `https://`. |
| Browser says "too many redirects" | `TRUST_PROXY` is `0` or `false`, so Relay never sees that the request came over HTTPS and keeps redirecting | Set `TRUST_PROXY=1` and restart. |
| IP check says "Spoofable" | `TRUST_PROXY` too high, or `true` | Lower it to `1`. |
| Log: `client IP unavailable; check TRUST_PROXY` | No usable client address, so per-IP limits are skipped | Check `TRUST_PROXY` and the System page. |
| `502 smtp error: ETIMEDOUT`, or `ESOCKET` right at connect, for every message of an app | Outbound SMTP is blocked from the hosting account | Run `smtp-probe.js` ([Step 0](#step-0-check-outbound-smtp-first)), then open a ticket. |
| `502 smtp error: ETIMEDOUT` or `ESOCKET` at connect for **some** messages of an app, while others go through | One of the mail provider's addresses is blocked or down. Relay connects to the first address of each DNS answer, and that order changes. | Run `smtp-probe.js <host> <port> --all` and send the output to Namecheap support. |
| `502 smtp error: <code> (outcome unknown)`; the log row is `unknown` | The connection broke or timed out after the message data was sent. The server may have accepted it. | Check with the recipient. If it did not arrive, send it again with a new `message_id` ([5.4](#54-idempotency-and-retries)). If this is frequent, the server is slow to confirm large messages: check the error text in Admin > Logs. |
| `502 smtp error: ESOCKET` with "certificate", "self-signed" or "altnames" in Admin > Logs | The SMTP server's certificate does not match the host name, or is invalid | Use the host name on the certificate. On cPanel mail this is often the server name (e.g. `server123.web-hosting.com`). `smtp-probe.js` prints the names. |
| `502 smtp error: ESOCKET` "wrong version number" | SSL/TLS selected for a STARTTLS port (587) | Use STARTTLS for 587, or SSL/TLS with port 465. |
| `502 smtp error: ETIMEDOUT` on port 465 with STARTTLS selected | The server waits for TLS first | Choose SSL/TLS for port 465. |
| `502 smtp error: ETLS` | STARTTLS selected, but the server does not offer it | Use SSL/TLS on 465. Use "none" only for a local server. |
| `502 smtp error: EAUTH 535` | Wrong username or password; or SMTP AUTH disabled for the Microsoft 365 mailbox/tenant; or Gmail without an app password | Enter the password again ("Change SMTP password"). Check the provider's SMTP AUTH setting ([section 10](#10-security-notes)). |
| `502 smtp error: EENVELOPE 550/553` | The server refuses the From address (it is not the mailbox's own address or alias), or all recipients | Set the From address to the mailbox address. |
| `502 smtp error: EMESSAGE 552` / `554` | Message too large for that server, or refused as spam/policy | Make it smaller; check content. |
| `502 smtp password not configured` | SMTP host, port, encryption or username were changed without re-entering the password | Enter the password on the app page. |
| Response is an HTML page (406, 403, 413) instead of JSON | ModSecurity or a web-server limit blocked the request before Relay | See [Step 12](#step-12-smoke-tests) and the ticket text there. |
| `401 invalid signature` (/send.php) | Wrong key; the key was revoked by a legacy-signing toggle or regenerate; the body changed after signing; or the key belongs to a non-legacy app | Use the current key of the legacy app. Sign exactly the bytes you send. Check against the [test vector](#53-post-sendphp-legacy-hmac-signed). |
| `401 timestamp out of range` | The client clock is off by more than 5 minutes, or the timestamp is in milliseconds | Sync the clock with NTP, and send seconds. |
| `401 invalid api key` with a key that used to work | The key was revoked, or its grace period ended; or it belongs to a legacy-signing app (use /send.php); or it has stray spaces or line breaks | Check the keys table on the app page. |
| `403 ip not allowed` | The client's outgoing IP is not in the allowlist, or has changed | Find the IP the relay saw, in phpMyAdmin: `SELECT created_at, client_ip, error FROM messages WHERE status = 'rejected' ORDER BY id DESC LIMIT 20;`. Or ask the site's host for its outgoing IP. |
| `409 message_id outcome unknown` | An earlier attempt with this id ended with an unknown outcome: the connection broke after the message data was sent, or a restart or crash cut the send off | See [5.4](#54-idempotency-and-retries). Confirm whether it arrived; resend with a new id if needed. After a restart, see [Restarting](#restarting). |
| Admin > System: "No run of the hourly cleanup cron job has been recorded" / "The hourly cleanup cron job has not run in the last 3 hours" | The cron job is missing or broken, e.g. the Node version changed and the path still says `24`. The warning tracks the cron job itself, not the in-process timer. Right after you add the job, the first warning is normal until the next full hour. | Check `/home/USER/relay/logs/cron.log` and fix the cron command ([Step 9](#step-9-hourly-cleanup-cron-job-required)). |
| Admin > System: "The cron job runs, but no cleanup has finished in the last 3 hours" | Cleanup fails each time | Read the error at the end of `/home/USER/relay/logs/cron.log`. |
| `WARN LOG_FILE cannot be written; logging to stderr only` in `stderr.log` | `LOG_FILE` points to a directory, or to a place your user cannot write | Fix `LOG_FILE` (for example `/home/USER/relay/logs/relay.log`) and restart. Until then, logs go to `stderr.log` only. |
| `.env is readable by group or others` in the log | Permissions too open | `chmod 600 /home/USER/relay/.env` |
| Startup log: `ADMIN_BOOTSTRAP_EMAIL/ADMIN_BOOTSTRAP_PASSWORD are set but admins already exist` | Bootstrap credentials left in `.env` | Remove them ([Step 11](#step-11-remove-the-bootstrap-password)). |
| First request after a pause is slow | LiteSpeed stopped the idle app and is starting it | Normal. |
| Locked out (lost password and 2FA, no other admin) | | Over SSH: `node scripts/create-admin.js <email> --reset-2fa` |

---

## 12. Node.js versions

- **Choose Node.js 24** in Setup Node.js App. It is the current LTS line, supported until April
  2028.
- **Node.js 20 reached end of life in April 2026** and no longer gets security fixes. Relay still
  runs on it, but do not deploy on it.
- **Node.js 22** is supported until April 2027.
- Relay needs Node.js 20 or newer (`"engines": { "node": ">=20.0.0" }`) and uses no native
  modules, so moving between 20, 22 and 24 needs only the steps in
  [Changing the Node.js version](#changing-the-nodejs-version), including the cron path.

---

## 13. Local development and tests

Requirements: Node.js 20 or newer (24 recommended), and MariaDB 10.3+ or MySQL 5.7+.

```sh
npm install
node scripts/gen-secrets.js            # MASTER_KEY / SESSION_SECRET for your .env
```

Create a database and user, then put a `.env` in the project root:

```ini
NODE_ENV=development
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=relay_dev
DB_USER=relay
DB_PASSWORD='...'
MASTER_KEY=...
SESSION_SECRET=...
ADMIN_BOOTSTRAP_EMAIL=you@example.com
ADMIN_BOOTSTRAP_PASSWORD='a long local password'
```

With `NODE_ENV=development`:

- `PUBLIC_BASE_URL` defaults to `http://localhost:3000`.
- `FORCE_HTTPS` and `COOKIE_SECURE` default to off.

```sh
npm run migrate
npm start                               # http://localhost:3000/admin
```

To see outgoing mail without sending it anywhere, run a local catch-all SMTP server such as
Mailpit on `localhost:1025`. Point an app at host `localhost`, port `1025`, encryption "none", and
an empty username.

**Tests.** Run them with `npm test`, which is `node scripts/reset-test-db.js && node --test`.
They use `node:test`, supertest, and fake SMTP servers that the tests start themselves. No
network is needed.

- The database tests need `.env.test` in the project root:

  ```ini
  TEST_DB_HOST=127.0.0.1
  TEST_DB_PORT=3306
  TEST_DB_USER=relay_test_user
  TEST_DB_PASSWORD=change-me
  TEST_DB_NAME=relay_test
  ```

- `scripts/reset-test-db.js` **drops and recreates `TEST_DB_NAME`** before every run, so use a
  dedicated database.
- Without `TEST_DB_NAME`, the database tests are skipped, and a loud
  `DB TESTS WILL BE SKIPPED` warning is printed.

Other scripts:

| Command | What it does |
|---|---|
| `npm run migrate` | Apply pending migrations. |
| `npm run cleanup` | One cleanup run (what the cron job does). |
| `npm run create-admin -- <email> [--name "X"] [--reset-2fa]` | Create an admin, or reset an admin's password. |
| `npm run gen-secrets` | Print a fresh `MASTER_KEY` and `SESSION_SECRET`. |
| `node scripts/rotate-master-key.js` | Re-encrypt stored secrets with the current `MASTER_KEY` ([section 8](#rotating-the-master-key)). |
| `node scripts/smtp-probe.js <host> <port> [--tls] [--no-ehlo] [--all]` | Check SMTP reachability from this machine: the address Relay would use, or with `--all` every address ([Step 0](#step-0-check-outbound-smtp-first)). |

---

## 14. Project layout

```
app.js                    startup file for cPanel / LiteSpeed (and npm start)
.env.example              every setting, with comments
migrations/               SQL migrations (001_initial.sql)
scripts/                  migrate, cleanup, create-admin, rotate-master-key,
                          gen-secrets, smtp-probe, reset-test-db
src/config.js             loads and validates .env
src/server.js, src/app.js HTTP server, Express app, shutdown
src/routes/               api.js (/v1), legacy.js (/send.php), admin/*
src/services/             send pipeline, mailer, keys, rate limits, cleanup, ...
src/repos/                SQL access, one module per table
src/lib/                  crypto, secrets, validation helpers, TOTP, logger, ...
src/middleware/           security headers, sessions, CSRF, auth, rate limiting
src/views/, public/       admin pages (EJS), CSS and JS
docs/                     SPEC.md (requirements and design decisions)
test/                     node:test suites
```
