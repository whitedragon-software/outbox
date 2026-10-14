# Outbox

A single-file Cloudflare Worker that sends email through Resend from your own
domains: a compose form with live HTML preview, a complete send history in D1
with rendered previews, and a usage dashboard that reads live from Resend so
the numbers always match the provider's. All four pages share one dashboard
shell — sidebar navigation on desktop, a top bar on mobile — with a
light/dark theme toggle, light by default. Optional password login; the
sending-domain list lives in the database and is managed entirely from the
dashboard.

```
https://outbox.<username>.workers.dev/
```

- `_worker.js`: the Worker. Deploy this file as-is; no build step, no
  dependencies, no schema to run — it creates its own database tables on
  first use.
- `wrangler.jsonc`: config for CLI deploys only. The dashboard route needs
  none of it.
- `CHANGELOG.md`: what changed in each build.

---

## Deploy

Paste `_worker.js` into the Worker editor in the Cloudflare dashboard:
create a Worker, replace the boilerplate with the file's contents, then add
under Settings the `RESEND_KEY` secret and a D1 binding named `DB` — and,
optionally, a `PASSWORD` secret (login screen). Deploy, open the Worker's
URL, go to **Domains**, and add your first sending domain. Done — no config
file, no CLI. The free tier is enough.

Or deploy from the command line with a `wrangler.jsonc` (comments allowed):

```jsonc
{
  "name": "outbox",
  "main": "_worker.js",
  "compatibility_date": "2024-09-01",
  // sending domains are managed in the dashboard at /domains
  "d1_databases": [
    {
      // the binding must be named DB; the database can be called anything
      "binding": "DB",
      "database_name": "email-db",
      "database_id": "<your-database-id>"
    }
  ]
}
```

```
npx wrangler secret put RESEND_KEY
npx wrangler secret put PASSWORD   # optional
npx wrangler deploy
```

Wrangler picks up `wrangler.jsonc` automatically — no flag needed. If you
ever have both a `wrangler.toml` and a `wrangler.jsonc` in the folder,
delete one, or Wrangler will complain about the ambiguity.

Every domain you add must also be verified in Resend (its dashboard,
Domains tab), or sends from it fail.

### Optional: access protection

Two independent mechanisms; either one is enough, and both unset means the
app is open.

**Password (`PASSWORD` secret).** Every page redirects to a login screen.
A correct password sets a signed session cookie — HttpOnly, Secure,
SameSite=Lax, valid 30 days — and returns you to the page you originally
asked for. The cookie's signing key is derived from the password, so
changing `PASSWORD` immediately logs out every browser everywhere. A
"Log out" link appears in the sidebar.

**Token (`AUTH_TOKEN` secret).** Pages require `?token=…`; API calls
require the `X-Auth-Token` header. Handy for curl and scripts, and for
browsers where cookies get wiped.

| Path | Purpose |
|---|---|
| `/` | Compose form. Open as `/?token=…` when a token is set. |
| `/login` | Password login (only active when `PASSWORD` is set). |
| `/logout` | Clears the session cookie (the sidebar's "Log out" link). |
| `/sent` | History, newest first; click a message to expand the full body. |
| `/usage` | Live usage dashboard, read from Resend on every load. |
| `/domains` | The sending-domain list — add, remove, set the default. |
| `POST /send` | JSON API. Token in the `X-Auth-Token` header, or the session cookie. |
| `POST /usage/sync` | Refresh delivery details for the 25 most recent sends. |
| `POST /domains/add` | Add a sending domain: `{"domain":"example.com"}`. |
| `POST /domains/remove` | Remove one — the last remaining domain is refused. |
| `POST /domains/default` | Mark a domain as the default. |

Pages take the token via `?token=`; the form and dashboard then pass it
along in the `X-Auth-Token` header automatically, so links between pages
keep working. With `PASSWORD` set and no `AUTH_TOKEN`, the POST endpoints
need the session cookie — programmatic callers must log in first and send
the cookie along.

---

## Using it

Open the Worker's URL, fill in the form, send. The "From address" field is
the local part only — the domain comes from your list on the **Domains**
page: the one you marked with *Set default*, or the oldest entry until you
pick one. With more than one domain, a picker appears next to the field;
the final address is shown live in the hint under the field and in the
sidebar. Multiple recipients, comma-separated. Every attempt is logged,
including failures with Resend's error message.

For HTML email, check *Send as HTML* and paste your markup into the message
box, then press **Preview** to see it rendered exactly as the recipient
will — in a sandboxed frame, so scripts never run. *Back to editing*
returns to the source; toggling the HTML checkbox re-renders the preview
live. The preview also works for plain text (shown as it will arrive).

Programmatic use — `text`, `html`, or both (both = HTML with a plain-text
fallback part, which is friendliest to spam filters):

```
curl -X POST https://outbox.<username>.workers.dev/send \
  -H "Content-Type: application/json" \
  -d '{"to":"name@example.com","subject":"Hi",
       "html":"<p>Hello <b>from Outbox</b></p>",
       "text":"Hello from Outbox"}'
```

An optional `from_domain` field selects the sending domain; anything not
on your list is rejected with a 400 naming the allowed domains.

The `/usage` dashboard pulls the most recent sends straight from Resend's own
records, so its counts agree with Resend's dashboard even for emails sent
before the history feature existed — those get back-filled into `/sent` on
the first visit. On `/sent`, HTML messages display as the rendered preview
automatically, with the raw source collapsed under a *Source* drop-down.

---

## How it works

**Sending.** Input is validated (recipients, subject, body, Reply-To) before
anything leaves the Worker; the message must be `text` or `html`. The `from`
address is built as `local@` plus the chosen domain — the picker on the
form, `from_domain` in the API, the default otherwise — with the local part
sanitized and the domain checked against the stored list; Resend's response
is passed through — a 401 means a bad key, a 403 usually means the domain
isn't verified in Resend yet.

**Domains.** The sending-domain list is a D1 table, edited only at
`/domains` — environment variables are never consulted. Add and remove as
you like; the default is whichever domain you mark with *Set default*
(the oldest entry until you pick one, and again if the default is removed).
Removing the last domain is refused. The list only gates what Outbox
offers; verifying a domain with Resend still happens in their dashboard.
Without a DB binding, `/domains` says so, and with no domains configured
the compose page links to `/domains` instead of a dead form — nothing
dead-ends.

**Access.** Optional, two ways: a `PASSWORD` secret gates every page behind
a login screen (signed 30-day session cookie whose key is derived from the
password — rotating it revokes every session at once), and `AUTH_TOKEN`
covers programmatic access (`?token=` on pages, `X-Auth-Token` on POSTs).
Either credential is enough; with neither set, Outbox is open. All secret
comparisons — header token, query token, password, cookie signature — are
constant-time, and a failed login pauses half a second.

**History.** Every send attempt — success *and* failure — is written to D1
in the same request. The `emails` table is created automatically on first
use (`CREATE TABLE IF NOT EXISTS`, so it never touches existing data), the
`delivery_status` and `content_type` columns are added by `ALTER TABLE`
migrations whose "duplicate column" errors are expected and swallowed, and
the same first-use bootstrap creates the `domains` and `settings` tables.
DB writes are wrapped so a logging failure never turns a delivered email
into an error: the form shows a "could not save to history" warning
instead. When both `text` and `html` are sent, the HTML part is what gets
archived.

**Usage.** `/usage` calls Resend's list endpoint on every page load and
computes all numbers from Resend's own records — the one exception is
"Rejected (worker log)", since sends Resend refused outright never enter
Resend's list. The Worker then reconciles D1 against Resend's list,
importing sends it never logged and refreshing delivery statuses;
reconciliation is best-effort and never blocks the page. If Resend is
unreachable, the page falls back to D1 stats with a red warning naming the
data source. The response shape is handled defensively (`{"data": [...]}`
or a bare array); if Resend changes it, `/usage` degrades to the fallback
rather than breaking.

**Previews.** Both the compose-page preview and the `/sent` history preview
use an iframe with an empty `sandbox` attribute — scripts, forms and
navigation inside the message cannot run. The message body is also
HTML-escaped everywhere it appears outside those frames. Preview panes stay
white in both themes: that is how the recipient sees the message.

**Pages.** All four pages share one dashboard shell: sidebar navigation on
desktop (current page highlighted, configured domains shown at the bottom)
that collapses into a sticky top bar with tab navigation below 860 px, plus
a light/dark theme toggle — light is the default, the choice is remembered
per browser in localStorage, and the system color-scheme preference is
deliberately not auto-detected. Everything is inline in the same file — no
external assets, no client-side dependencies; the icons are inline SVG.
Inline scripts read `DOMAINS` and `TOKEN` from Worker-side interpolations.

---

## Editing and verifying `_worker.js`

The page scripts live inside template literals, so **`node --check` on the
outer file does not validate them.** A syntax error in an inline script
kills that page in the browser while the Worker still deploys clean. The
outer file is also an ES module, so check it as `.mjs`. Always run both:

```
cp _worker.js .check.mjs && node --check .check.mjs && rm .check.mjs

python3 - << 'PY'
import re
src = open('_worker.js').read()
scripts = re.findall(r'<script>\n(.*?)</script>', src, re.DOTALL)
for i, s in enumerate(scripts):
    s = re.sub(r'\$\{[^}]*\}', 'null', s)
    open(f'.page{i}.mjs', 'w').write(s)
print(len(scripts), 'inline scripts extracted')
PY

for f in .page*.mjs; do node --check "$f"; done
rm -f .page*.mjs
```

There are four inline scripts: the shared theme script (it also drives the
login page's toggle — the login form itself is plain HTML, no script), the
compose script, the usage script and the domains script. The `${...}`
substitutions (`DOMAINS`, `TOKEN`) are Worker-side interpolations —
runtime-valid but invalid standalone JavaScript — so the extraction
replaces them with `null` before checking.

---

## Quick test checklist

1. Fresh deploy: the compose page points you to `/domains`; add a domain
   there, and the hint under "From address" reads `noreply@<that domain>`
   and updates as you type.
2. Send a test email: green confirmation with a Resend ID.
3. `/sent`: the message is there, newest first; click it — from, to,
   subject and full body render; delivery status appears after a usage sync.
4. `/usage`: the "Sent (per Resend)" count matches the Resend dashboard,
   including emails sent before the history feature existed.
5. Break something on purpose: an unverified domain or bad key shows the
   real Resend error in the form, and the failed attempt is logged in
   `/sent` with a red dot.
6. With `AUTH_TOKEN` set: `/` without a token returns 401; `/?token=…`
   loads and the send button still works; `/sent`, `/usage` and `/domains`
   follow the sidebar links without losing the token.
7. Missing `RESEND_KEY`: a plain-text configuration error, not a 1102
   crash.
8. Check "Send as HTML", paste `<p><b>bold</b> and <i>italic</i></p>`, press
   Preview: the rendered text appears; "Back to editing" returns to the
   source. Send it: the email arrives formatted, and `/sent` shows the
   rendered preview with the source collapsed under the *Source* drop-down.
9. Toggle *Dark mode* (sidebar on desktop, top bar on mobile): every page
   switches theme, the button flips to *Light mode*, and reload keeps the
   choice; rendered email previews stay white either way. Shrink the window
   below ~860 px (or use the browser device toolbar): the sidebar collapses
   into a sticky top bar with Compose / Sent / Usage / Domains tabs, and
   the usage chart scrolls sideways instead of squashing its labels.
10. With `PASSWORD` set: `/` redirects to `/login`; a wrong password shows
    the error and stays put; the right one lands you on the page you
    originally requested; "Log out" (sidebar link) clears the session and
    the next visit redirects again. Change the password and reload — the
    old session is dead.
11. `/domains`: add a second domain — it appears in the compose picker and
    the sidebar footer; press *Set default* on it — it becomes the picker's
    preselection and the domain used when `from_domain` is omitted; remove
    it — gone for good. Try removing the last remaining domain: refused.
    `POST /send` with a `from_domain` not on the list returns a 400 naming
    the allowed domains.

---

## Limitations

- **Without `AUTH_TOKEN` and `PASSWORD`, anyone with the URL can send email
  from your domain through your key.** There is no rate limiting on `/send`.
  Set one of them before sharing the URL.
- The token travels in the query string (`?token=…`), which can land in
  browser history and access logs. Comparisons are constant-time now, but
  the exposure itself remains — prefer `PASSWORD` login in browsers and
  keep `AUTH_TOKEN` for scripts.
- Login has no lockout: the half-second delay on a wrong password slows
  brute force but doesn't stop it. Pick a long password.
- Sessions can't be revoked individually — only all at once, by changing
  `PASSWORD`. The cookie is `Secure`, so over plain HTTP (e.g.
  `wrangler dev`) some browsers won't store it.
- Logging out is a plain GET link, so anything that gets your browser to
  follow a `/logout` link logs you out — an annoyance, not a leak.
- Domains can only be added at `/domains`, which needs the `DB` binding —
  without a database, no domains can be configured and sending is disabled.
  Adding a domain here only puts it on Outbox's list: Resend still has to
  verify it (their dashboard), otherwise you get Resend's 403.
- `/usage` shows the **100 most recent** sends Resend has on record; older
  history is not included (the page says so when it applies). Each page
  view costs one Resend API read, which counts against their rate limits.
- "Rejected (worker log)" only counts failures *this worker* saw. If the
  same key is used by other apps, their sends appear in the Resend numbers
  but their failures are invisible here.
- No attachments, no templates, no rich-text editor — HTML is written by
  hand, and nothing sanitizes what you send (it's your own content going
  to your own recipients). `Reply-To` is a single address.
- When both `text` and `html` are sent, only the HTML part is archived.
- At most 50 recipients per send.
- Resend's free plan allows 100 emails/day; the "Last 24 hours" card on
  `/usage` is the number to watch. D1 free-tier row limits are far above
  personal-mail volume.
- History, stats and the domain list reflect one database per environment:
  `wrangler dev` writes to the local D1 copy, production to the remote one.
  Sends made in dev do not appear in the deployed `/sent` (they still show
  in `/usage`, since that reads from Resend), and domain edits made in dev
  don't reach the deployed list.
- Dark mode is a per-browser preference (localStorage): it does not sync
  between devices, and with JavaScript disabled the pages stay light. The
  system color-scheme preference is never auto-detected, so a dark-mode OS
  still gets the light theme until you toggle.
