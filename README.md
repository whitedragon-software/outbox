# Outbox

A single-file Cloudflare Worker that sends email through Resend from your own
domain: a white-background compose form with live HTML preview, a complete
send history in D1 with rendered previews, and a usage dashboard that reads
live from Resend so the numbers always match the provider's.

```
https://outbox.<username>.workers.dev/
```

- `_worker.js`: the Worker. Deploy this file as-is; no build step, no
  dependencies, no schema to run — it creates its own database table on
  first use.
- `wrangler.jsonc`: config for CLI deploys only. The dashboard route needs
  none of it.
- `CHANGELOG.md`: what changed in each build.

---

## Deploy

Paste `_worker.js` into the Worker editor in the Cloudflare dashboard:
create a Worker, replace the boilerplate with the file's contents, then add
under Settings the variables `RESEND_KEY` (as an encrypted secret) and
`DOMAIN1` (plain text), and a D1 binding named `DB`. Done — no config file,
no CLI. The free tier is enough.

Or deploy from the command line with a `wrangler.jsonc` (comments allowed):

```jsonc
{
  "name": "outbox",
  "main": "_worker.js",
  "compatibility_date": "2024-09-01",
  "vars": {
    // must be a domain verified in Resend
    "DOMAIN1": "yourdomain.com"
  },
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
npx wrangler deploy
```

Wrangler picks up `wrangler.jsonc` automatically — no flag needed. If you
ever have both a `wrangler.toml` and a `wrangler.jsonc` in the folder,
delete one, or Wrangler will complain about the ambiguity.

`DOMAIN1` must be a domain verified in Resend (Domains tab).

### Optional: token protection

Set an `AUTH_TOKEN` secret and every page and endpoint requires it:

```
npx wrangler secret put AUTH_TOKEN
```

(or add `AUTH_TOKEN` as a secret in the dashboard). **Unset, Outbox behaves
exactly as before.**

| Path | Purpose |
|---|---|
| `/` | Compose form. Open as `/?token=…` when a token is set. |
| `/sent` | History, newest first; click a message to expand the full body. |
| `/usage` | Live usage dashboard, read from Resend on every load. |
| `POST /send` | JSON API. Send the token in the `X-Auth-Token` header. |
| `POST /usage/sync` | Refresh delivery details for the 25 most recent sends. |

Pages take the token via `?token=`; the form and dashboard then pass it
along in the `X-Auth-Token` header automatically, so links between pages
keep working.

---

## Using it

Open the Worker's URL, fill in the form, send. The "From address" field is
the local part only — the domain is always `DOMAIN1`, shown live in the hint
under the field. Multiple recipients, comma-separated. Every attempt is
logged, including failures with Resend's error message.

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

The `/usage` dashboard pulls the most recent sends straight from Resend's own
records, so its counts agree with Resend's dashboard even for emails sent
before the history feature existed — those get back-filled into `/sent` on
the first visit. On `/sent`, HTML messages display as the rendered preview
automatically, with the raw source collapsed under a *Source* drop-down.

---

## How it works

**Sending.** Input is validated (recipients, subject, body, Reply-To) before
anything leaves the Worker; the message must be `text` or `html`. The `from`
address is built as `local@DOMAIN1` with the local part sanitized; Resend's
response is passed through — a 401 means a bad key, a 403 usually means the
domain isn't verified in Resend yet.

**History.** Every send attempt — success *and* failure — is written to D1
in the same request. The `emails` table is created automatically on first
use (`CREATE TABLE IF NOT EXISTS`, so it never touches existing data), and
the `delivery_status` and `content_type` columns are added by `ALTER TABLE`
migrations whose "duplicate column" errors are expected and swallowed. DB
writes are wrapped so a logging failure never turns a delivered email into
an error: the form shows a "could not save to history" warning instead.
When both `text` and `html` are sent, the HTML part is what gets archived.

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
HTML-escaped everywhere it appears outside those frames.

**Pages.** All three pages are inline HTML in the same file — white
background, no external assets, no client-side dependencies. Inline scripts
read `DOMAIN` and `TOKEN` from Worker-side interpolations.

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

node --check .page0.mjs
node --check .page1.mjs
```

The `${...}` substitutions (`DOMAIN`, `TOKEN`) are Worker-side interpolations —
runtime-valid but invalid standalone JavaScript — so the extraction replaces
them with `null` before checking.

---

## Quick test checklist

1. Compose page loads with the title "Outbox"; the hint under "From address"
   reads `noreply@DOMAIN1` and updates as you type.
2. Send a test email: green confirmation with a Resend ID.
3. `/sent`: the message is there, newest first; click it — from, to,
   subject and full body render; delivery status appears after a usage sync.
4. `/usage`: the "Sent (per Resend)" count matches the Resend dashboard,
   including emails sent before the history feature existed.
5. Break something on purpose: an unverified domain or bad key shows the
   real Resend error in the form, and the failed attempt is logged in
   `/sent` with a red dot.
6. With `AUTH_TOKEN` set: `/` without a token returns 401; `/?token=…`
   loads and the send button still works; `/sent` and `/usage` follow the
   links without losing the token.
7. Missing `RESEND_KEY` or `DOMAIN1`: a plain-text configuration error,
   not a 1102 crash.
8. Check "Send as HTML", paste `<p><b>bold</b> and <i>italic</i></p>`, press
   Preview: the rendered text appears; "Back to editing" returns to the
   source. Send it: the email arrives formatted, and `/sent` shows the
   rendered preview with the source collapsed under the *Source* drop-down.

---

## Limitations

- **Without `AUTH_TOKEN`, anyone with the URL can send email from your
  domain through your key.** There is no rate limiting on `/send`. Set the
  token before sharing the URL.
- The token travels in the query string (`?token=…`), which can land in
  browser history and access logs, and the comparison is not timing-safe.
  It keeps casual visitors out; it is not hardened access control.
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
- History and stats reflect one database per environment: `wrangler dev`
  writes to the local D1 copy, production to the remote one. Sends made in
  dev do not appear in the deployed `/sent` (they still show in `/usage`,
  since that reads from Resend).
