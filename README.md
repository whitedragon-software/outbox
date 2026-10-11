# Outbox

A single-file Cloudflare Worker that sends email through Resend from your own
domain: a white-background compose form, a complete send history in D1, and a
usage dashboard that reads live from Resend so the numbers always match the
provider's.

```
https://outbox.<username>.workers.dev/
```

- `src/index.js`: the Worker. Every page, endpoint and query lives in this
  one file; no build step, no dependencies.
- `wrangler.toml`: worker name, `DOMAIN1`, the D1 binding.
- `schema.sql`: reference copy of the table. Optional — the Worker creates
  and migrates the table automatically on first use.

---

## Deploy

```
wrangler deploy
```

or paste `src/index.js` into the Worker editor in the Cloudflare dashboard.
The free tier is enough.

Required configuration:

| Name | Kind | Purpose |
|---|---|---|
| `RESEND_KEY` | secret (`wrangler secret put RESEND_KEY`) | Resend API key. |
| `DOMAIN1` | var | The verified sending domain, e.g. `mydomain.com`. |
| `DB` | D1 binding | Send history. Any name for the database; the binding must be `DB`. |

### Optional: token protection

Set an `AUTH_TOKEN` secret and every page and endpoint requires it:

```
wrangler secret put AUTH_TOKEN
```

**Unset, Outbox behaves exactly as before.**

| Path | Purpose |
|---|---|
| `/` | Compose form. Open as `/?token=...` when a token is set. |
| `/sent` | History, newest first; click a message to expand the full body. |
| `/usage` | Live usage dashboard, read from Resend on every load. |
| `POST /send` | JSON API. Send the token in the `X-Auth-Token` header. |
| `POST /usage/sync` | Refresh delivery details for the 25 most recent sends. |

Pages take the token via `?token=`; the form and dashboard then pass it along
in the `X-Auth-Token` header automatically, so links between pages keep
working.

---

## Using it

Open the Worker's URL, fill in the form, send. The "From address" field is
the local part only — the domain is always `DOMAIN1`, shown live in the hint
under the field. Multiple recipients, comma-separated. Every attempt is
logged, including failures with Resend's error message.

Programmatic use:

```
curl -X POST https://outbox.<username>.workers.dev/send \
  -H "Content-Type: application/json" \
  -d '{"to":"name@example.com","subject":"Hi","text":"Hello from Outbox"}'
```

The `/usage` dashboard pulls the most recent sends straight from Resend's own
records, so its counts agree with Resend's dashboard even for emails sent
before the history feature existed — those get back-filled into `/sent` on
the first visit.

---

## How it works

**Sending.** Input is validated (recipients, subject, body, Reply-To) before
anything leaves the Worker. The `from` address is built as
`local@DOMAIN1` with the local part sanitized; Resend's response is passed
through — a 401 means a bad key, a 403 usually means the domain isn't
verified in Resend yet.

**History.** Every send attempt — success *and* failure — is written to D1
in the same request. The `emails` table is created automatically on first
use (`CREATE TABLE IF NOT EXISTS`, so it never touches existing data), and
the `delivery_status` column is added by an `ALTER TABLE` whose
"duplicate column" error is expected and swallowed. DB writes are wrapped
so a logging failure never turns a delivered email into an error: the form
shows a "could not save to history" warning instead.

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

**Pages.** All three pages are inline HTML in the same file — white
background, no external assets, no client-side dependencies. Inline scripts
read `DOMAIN` and `TOKEN` from Worker-side interpolations.

---

## Editing and verifying `src/index.js`

The page scripts live inside template literals, so **`node --check` on the
outer file does not validate them.** A syntax error in an inline script
kills that page in the browser while the Worker still deploys clean. The
outer file is also an ES module, so check it as `.mjs`. Always run both:

```
cp src/index.js .check.mjs && node --check .check.mjs && rm .check.mjs

python3 - << 'PY'
import re
src = open('src/index.js').read()
scripts = re.findall(r'<script>\n(.*?)</script>', src, re.DOTALL)
for i, s in enumerate(scripts):
    s = re.sub(r'\$\{[^}]*\}', 'null', s)
    open(f'.page{i}.mjs', 'w').write(s)
print(len(scripts), 'inline scripts extracted')
PY

node --check .page0.mjs
node --check .page1.mjs
```

The `${...}` substitutions (`DOMAIN`, `TOKEN`) are Worker-side interpolations —
runtime-valid but invalid standalone JavaScript — so the extraction replaces
them with `null` before checking.

---

## Quick test checklist

1. Compose page loads; the hint under "From address" reads
   `noreply@DOMAIN1` and updates as you type.
2. Send a test email: green confirmation with a Resend ID.
3. `/sent`: the message is there, newest first; click it — from, to,
   subject and full body render; delivery status appears after a usage sync.
4. `/usage`: the "Sent (per Resend)" count matches the Resend dashboard,
   including emails sent before the history feature existed.
5. Break something on purpose: an unverified domain or bad key shows the
   real Resend error in the form, and the failed attempt is logged in
   `/sent` with a red dot.
6. With `AUTH_TOKEN` set: `/` without a token returns 401; `/?token=...`
   loads and the send button still works; `/sent` and `/usage` follow the
   links without losing the token.
7. Missing `RESEND_KEY` or `DOMAIN1`: a plain-text configuration error,
   not a 1102 crash.

---

## Limitations

- **Without `AUTH_TOKEN`, anyone with the URL can send email from your
  domain through your key.** There is no rate limiting on `/send`. Set the
  token before sharing the URL.
- The token travels in the query string (`?token=...`), which can land in
  browser history and access logs, and the comparison is not timing-safe.
  It keeps casual visitors out; it is not hardened access control.
- `/usage` shows the **100 most recent** sends Resend has on record; older
  history is not included (the page says so when it applies). Each page
  view costs one Resend API read, which counts against their rate limits.
- "Rejected (worker log)" only counts failures *this worker* saw. If the
  same key is used by other apps, their sends appear in the Resend numbers
  but their failures are invisible here.
- Plain-text bodies only: no HTML composing, no attachments, no
  templates. `Reply-To` is a single address.
- At most 50 recipients per send.
- Resend's free plan allows 100 emails/day; the "Last 24 hours" card on
  `/usage` is the number to watch. D1 free-tier row limits are far above
  personal-mail volume.
- History and stats reflect one database per environment: `wrangler dev`
  writes to the local D1 copy, production to the remote one. Sends made in
  dev do not appear in the deployed `/sent` (they still show in `/usage`,
  since that reads from Resend).
