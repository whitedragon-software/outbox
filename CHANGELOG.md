# Changelog

## 0.8.0

### Added
- CSV export of the send history: `GET /sent/export` (authed like the
  pages, so it works as a plain link) plus an "Export CSV" link on
  `/sent`. One row per attempt — successes and failures alike — with id,
  date, status, delivery status, Resend ID, from, to, reply-to, subject,
  content type, archived body and error. RFC 4180 quoting, UTF-8 with BOM
  so Excel keeps non-ASCII subjects intact, CRLF line endings, filename
  `outbox-export-YYYY-MM-DD.csv`. The export covers the entire archive,
  not just the newest 200 shown on `/sent`.

## 0.7.2

### Added
- Default-domain setting: "Set default" on any non-default row at
  `/domains` (stored in the `settings` table). The default is the domain
  preselected in the compose picker and assumed when `POST /send` omits
  `from_domain`. `POST /domains/default` with `{"domain":"example.com"}`
  does it programmatically. Removing the default domain falls back to the
  oldest entry.

### Changed
- Domains are configured only in the dashboard: the `DOMAIN1`/`DOMAIN2`
  variables no longer feed the list in any way — add domains at
  `/domains`. Lists seeded by earlier versions keep what they have.
- Trimmed page taglines: compose reads "Delivered via Resend", the usage
  dashboard "Live from Resend", and the Domains page dropped its explainer
  lines.
- Efficiency: `/usage` runs reconciliation, the rejected count and the
  domain read concurrently; `/sent` reads history and domains together;
  reconciliation looks up only the resend IDs present in Resend's list
  instead of every logged send; the delivery sync checks its 25 emails
  concurrently in batches of five (rate-limit friendly); `/send` runs its
  cheap validation before touching the database; the D1 fallback counts
  run in parallel.
- `/domains` without a DB binding now renders the page with a notice
  instead of a bare error, so the flow never dead-ends.

## 0.7.1

### Added
- Domain management in the dashboard at `/domains`: the sending-domain
  list lives in D1 (new `domains` table) and is edited there — add and
  remove, with the first entry marked as the default. `DOMAIN1`/`DOMAIN2`
  are imported into the list once on first run; afterwards the page is
  the source of truth, and removing a domain really removes it. The
  compose picker, the sidebar footer and `POST /send` validation all
  follow the stored list; `from_domain` outside it is a 400 naming the
  allowed domains. Removing the last remaining domain is refused.
  JSON endpoints `POST /domains/add` and `POST /domains/remove`, authed
  like the other POSTs. Without a DB binding, the environment variables
  keep working directly, as before.

### Changed
- "Log out" in the sidebar is now a link to `GET /logout`, which clears
  the session and returns to `/login`; `POST /logout` still works.
- With no domains configured, the compose page shows an in-page
  "add a domain" prompt instead of a plain error.

## 0.7.0

### Added
- Password protection: set a `PASSWORD` secret and every page sits behind
  a login screen. A correct password sets a signed session cookie —
  HttpOnly, Secure, SameSite=Lax, 30 days — whose signing key is derived
  from the password, so changing the password invalidates every session
  ever issued. A "Log out" button appears in the sidebar. `AUTH_TOKEN`
  keeps working alongside it: either credential grants access, and
  token-only setups behave exactly as before. With both unset the app
  stays open; with `PASSWORD` set and no `AUTH_TOKEN`, `POST /send` and
  `/usage/sync` need the session cookie.
- Second sending domain: set an optional `DOMAIN2` var and the compose
  form grows a domain picker next to the From address (the live preview
  follows it); `POST /send` accepts an optional `from_domain`, validated
  against the configured domains and defaulting to `DOMAIN1`. The sidebar
  footer lists every configured domain. Single-domain setups are
  unchanged.

### Changed
- Secret comparisons (`AUTH_TOKEN` in the header or query string, the
  login password, the session cookie) are now constant-time — previously
  a documented limitation. Failed logins also pause 500 ms.

## 0.6.0

### Added
- Dark mode with a light default: a "Dark mode / Light mode" toggle in the
  sidebar switches every page; the choice is remembered per browser in
  localStorage. The system color-scheme preference is deliberately not
  auto-detected — the first visit is always light. Light mode keeps the
  original palette; dark mode uses contrast-adjusted equivalents of the
  same green/red status colors.
- Mobile support: below 860 px the sidebar collapses into a sticky top bar
  (brand + theme toggle, with Compose / Sent / Usage as horizontally
  scrollable tabs); the usage chart scrolls sideways instead of squashing
  its date labels; stat cards and the delivery/recipients panels reflow to
  one column.

### Changed
- Dashboard layout for all three pages: a persistent sidebar with the
  current page highlighted, an Outbox brand mark, and the sending domain
  shown at the bottom. Page content sits in the main area under its own
  heading ("New message", "Sent messages", "API key usage") instead of a
  lone centered card; the inter-page links moved into the sidebar.
- All styling now runs on CSS custom properties so both themes share one
  ruleset. Rendered email previews — the sandboxed iframes and the compose
  plain-text preview — deliberately stay white in both themes: that is how
  the recipient sees the message.

## 0.5.0

### Added
- HTML email: a "Send as HTML" checkbox on the compose form, and `text`,
  `html` or both in the `POST /send` API — when both are given, the plain
  text is sent as the fallback part. Existing text-only calls are unchanged.
- Preview on the compose page: the Preview button renders the message as
  the recipient will see it — a sandboxed iframe for HTML (scripts blocked),
  plain text otherwise — and toggles back to editing. Toggling the HTML
  checkbox while previewing re-renders live.
- The compose page title is now "Outbox".
- `/sent` shows HTML messages as the rendered sandboxed preview
  automatically; the raw source sits collapsed under a "Source" drop-down.
  HTML messages are marked in the summary line.
- `content_type` column, added by the same idempotent migration as
  `delivery_status`. Rows imported from Resend during reconciliation are
  typed by whether Resend had `text` or `html` for them.

## 0.4.0

### Added
- `/usage` now reads live from Resend on every page load: the total, last
  24 h / 7 d / 30 d, the 14-day chart, delivery statuses and top recipients
  are all computed from Resend's own records (the 100 most recent sends).
- D1 reconciliation on every `/usage` visit: sends Resend knows about that
  the worker never logged are imported with their real timestamps and
  subjects, and stored delivery statuses are refreshed. Best-effort — it
  never blocks the page.
- "Rejected (worker log)" stat card, for attempts Resend refused outright:
  those never enter Resend's own list, so only the worker saw them.
- "Refresh from Resend" button on the dashboard.

### Changed
- Resend is now the source of truth for all send counts; D1 is the
  fallback. If Resend is unreachable, `/usage` shows local database stats
  with a red warning naming the data source instead of failing.

### Fixed
- Usage counts could disagree with Resend (three sent, one shown): the
  dashboard previously counted D1 rows, which only knew about sends logged
  after 0.2.0 — emails sent before that, or from `wrangler dev` (which
  writes to the local database copy), were invisible. Reconciliation also
  back-fills those missing sends into `/sent` on the first `/usage` visit.

## 0.3.0

### Added
- Usage dashboard at `/usage`: total attempts, sent, failed, last 24 h,
  7 days and 30 days, a 14-day bar chart (dark = sent, red = failed,
  hover for details) and the top recipients from the most recent 500
  messages.
- Delivery statuses from Resend: a sync button checks the 25 most recent
  sent emails and records the latest event (`delivered`, `bounce`,
  `complained`…). Statuses also show on the `/sent` page.
- `delivery_status` column, added by an idempotent migration
  (`ALTER TABLE`; the "duplicate column" error is expected and swallowed),
  so existing databases keep their data.
- Navigation links between the compose, history and usage pages.

## 0.2.1

### Fixed
- `D1_ERROR: no such table: emails` on a fresh database: the `emails` table
  is now created automatically on first use, before both the insert and the
  history query. Running a schema by hand is no longer required.

## 0.2.0

### Added
- Send history in D1 (binding `DB`): every attempt — success *and* failure —
  is written in the same request, with the full body, from/to addresses,
  Reply-To, subject, Resend ID, status, error message and timestamp.
- `/sent` page: the last 200 messages, newest first; click a message to
  expand the full body. Green dot for sent, red for failed, with the Resend
  error shown inline.
- DB writes are wrapped so a logging failure never turns a delivered email
  into a false error — the compose form shows a "could not save to history"
  warning instead.

## 0.1.0

### Added
- Initial release: a single-file Cloudflare Worker that sends email
  through the Resend API. No build step, no dependencies; the free tier
  is enough.
- White-background compose form: To (multiple, comma-separated, max 50),
  optional From name and local part (the domain is always `DOMAIN1`, with
  a live preview of the final address), optional Reply-To, subject and
  message.
- `POST /send` JSON endpoint for programmatic use.
- Input validation (recipients, subject, body, Reply-To); the from local
  part is sanitized to `[a-z0-9._-]` and defaults to `noreply`.
- Resend errors are passed through to the form: 401 means a bad key, 403
  usually means the domain isn't verified in Resend yet.
- Optional `AUTH_TOKEN` protection: pages require `?token=…`, API calls
  the `X-Auth-Token` header. **Unset, everything behaves as before.**
- Configuration: `RESEND_KEY` (secret), `DOMAIN1` (var).
