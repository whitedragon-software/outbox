# Changelog

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
