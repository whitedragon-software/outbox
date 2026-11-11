const RESEND_ENDPOINT = "https://api.resend.com/emails";
const RESEND_LIST_LIMIT = 100;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const MAX_RECIPIENTS = 50;

// Attachments (0.12.0): stored in D1 with the attempt, sent via Resend in
// the same request. 2 MB is D1's hard per-row/BLOB cap, so a single file
// stays well under it; Resend allows 40 MB per message after base64
// encoding, and base64 adds a third, so the raw total stops at 25 MB.
const MAX_ATTACHMENTS = 10;
const MAX_ATTACHMENT_BYTES = 1572864;                  // 1.5 MB per file
const MAX_ATTACHMENTS_TOTAL = 26214400;                // 25 MB raw per message
const DEFAULT_DB_CAP_BYTES = 10 * 1024 * 1024 * 1024;  // D1 cap, Workers Paid (Free: 500 MB)

// Attachment summary per archived message, computed inside the /sent query:
// the count for the list line, and id<US>filename<US>size triples (US =
// char(31), a separator that cannot appear in real filenames' pairing) for
// the expanded view. GROUP_CONCAT needs the separator spelled out — with
// the default it would join multiple attachments with commas and the
// triples would fall apart.
const ATTACHMENT_SUBSELECTS =
  "(SELECT COUNT(*) FROM attachments a WHERE a.email_id = emails.id) AS attachment_count, " +
  "(SELECT COALESCE(GROUP_CONCAT(a.id || char(31) || a.filename || char(31) || a.size, char(31)), '') " +
  "FROM attachments a WHERE a.email_id = emails.id) AS attachment_files ";

// PASSWORD login sessions: 30-day signed cookies.
const SESSION_MAX_AGE_S = 30 * 24 * 60 * 60;
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_S * 1000;
const LOGIN_FAIL_DELAY_MS = 500;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// RFC 4180: quote a CSV field only when it contains a comma, quote, CR or
// LF; embedded quotes are doubled. null/undefined become empty fields.
function csvField(v) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

// 1536 -> "1.5 KB", 1048576 -> "1.0 MB" — the units the storage meter and
// the attachment lists are shown in.
function humanBytes(n) {
  let v = Number(n) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return (u === 0 ? String(v) : v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + units[u];
}

// Uint8Array -> base64, in chunks so large files don't blow the argument
// limit of String.fromCharCode.
function bytesToBase64(bytes) {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

// "a@b.com, c@d.com " -> ["a@b.com", "c@d.com"]; empty pieces dropped.
// Used for To, Cc and Bcc alike — all three accept the same format.
function splitAddresses(v) {
  return String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function redirect(location, status = 302) {
  return new Response(null, {
    status,
    headers: { Location: location, "Cache-Control": "no-store" },
  });
}

function sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// --- Access control (AUTH_TOKEN and/or PASSWORD) ------------------------
// Compares two strings without leaking contents through timing: hash both,
// then compare the digests with a data-independent loop.
async function constantTimeEqual(a, b) {
  const enc = new TextEncoder();
  const digests = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(String(a))),
    crypto.subtle.digest("SHA-256", enc.encode(String(b))),
  ]);
  const x = new Uint8Array(digests[0]);
  const y = new Uint8Array(digests[1]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

let sessionKeyCache = null;

// The session signing key is derived from PASSWORD itself, so rotating the
// password invalidates every cookie ever issued.
async function sessionKey(env) {
  if (sessionKeyCache) return sessionKeyCache;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode("outbox-session-key:" + env.PASSWORD)
  );
  sessionKeyCache = await crypto.subtle.importKey(
    "raw", digest, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
  return sessionKeyCache;
}

async function sessionHmacHex(env, message) {
  const key = await sessionKey(env);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.prototype.map.call(new Uint8Array(sig), function (b) {
    return ("0" + b.toString(16)).slice(-2);
  }).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 16).slice(-2), 16) || parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function hasValidSession(request, env) {
  if (!env.PASSWORD) return false;
  const m = /(?:^|;\s*)outbox_session=([0-9]+\.[0-9a-f]{64})/.exec(
    request.headers.get("Cookie") || ""
  );
  if (!m) return false;
  const parts = m[1].split(".");
  if (parseInt(parts[0], 10) < Date.now()) return false;
  const key = await sessionKey(env);
  return crypto.subtle.verify(
    "HMAC",
    key,
    hexToBytes(parts[1]),
    new TextEncoder().encode("outbox-session." + parts[0])
  );
}

// POST endpoints: the X-Auth-Token header (when AUTH_TOKEN is set) or a
// valid login session (when PASSWORD is set). With neither configured the
// endpoint stays open, exactly as before.
async function isAuthorized(request, env) {
  if (!env.AUTH_TOKEN && !env.PASSWORD) return true;
  if (env.AUTH_TOKEN && (await constantTimeEqual(request.headers.get("x-auth-token") || "", env.AUTH_TOKEN))) {
    return true;
  }
  if (env.PASSWORD && (await hasValidSession(request, env))) return true;
  return false;
}

// Pages: a valid ?token= (when AUTH_TOKEN is set) or a login session.
async function pageAuthOk(request, env, url) {
  if (!env.AUTH_TOKEN && !env.PASSWORD) return true;
  if (env.AUTH_TOKEN && (await constantTimeEqual(url.searchParams.get("token") || "", env.AUTH_TOKEN))) {
    return true;
  }
  if (env.PASSWORD && (await hasValidSession(request, env))) return true;
  return false;
}

// Returns null when a page request may proceed; otherwise the response to
// send instead — a login redirect when PASSWORD protection is on, or the
// old plain 401 for AUTH_TOKEN-only setups.
async function requirePage(request, env, url) {
  if (await pageAuthOk(request, env, url)) return null;
  if (env.PASSWORD) {
    return redirect("/login?next=" + encodeURIComponent(url.pathname + url.search));
  }
  return new Response("Unauthorized", { status: 401 });
}

// The post-login destination must be a same-site path: it starts with "/",
// is not protocol-relative ("//"), and carries no header-breaking chars.
function safeNext(raw) {
  const s = String(raw || "");
  if (!s.startsWith("/") || s.startsWith("//") || /[\r\n]/.test(s)) return "/";
  return s;
}

// --- Auto schema creation + migration -----------------------------------
let schemaReady = false;

async function ensureSchema(env) {
  if (schemaReady || !env.DB) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS emails (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "resend_id TEXT, " +
      "from_address TEXT NOT NULL, " +
      "to_addresses TEXT NOT NULL, " +
      "cc_addresses TEXT, " +
      "bcc_addresses TEXT, " +
      "reply_to TEXT, " +
      "subject TEXT NOT NULL, " +
      "body TEXT NOT NULL, " +
      "content_type TEXT, " +
      "status TEXT NOT NULL DEFAULT 'sent', " +
      "error TEXT, " +
      "created_at TEXT NOT NULL DEFAULT (datetime('now'))" +
      ")"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_emails_created ON emails (created_at DESC)"
  ).run();
  // Migrations for databases created by older builds. "Duplicate column"
  // errors are expected once a column exists, so those are swallowed.
  try {
    await env.DB.prepare("ALTER TABLE emails ADD COLUMN delivery_status TEXT").run();
  } catch (e) {
    if (!String(e.message || e).includes("duplicate column")) throw e;
  }
  try {
    await env.DB.prepare("ALTER TABLE emails ADD COLUMN content_type TEXT").run();
  } catch (e) {
    if (!String(e.message || e).includes("duplicate column")) throw e;
  }
  try {
    await env.DB.prepare("ALTER TABLE emails ADD COLUMN cc_addresses TEXT").run();
  } catch (e) {
    if (!String(e.message || e).includes("duplicate column")) throw e;
  }
  try {
    await env.DB.prepare("ALTER TABLE emails ADD COLUMN bcc_addresses TEXT").run();
  } catch (e) {
    if (!String(e.message || e).includes("duplicate column")) throw e;
  }

  // The sending-domain list and settings, managed on the /domains page.
  // Domains are never imported from environment variables.
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS domains (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "domain TEXT NOT NULL UNIQUE, " +
      "created_at TEXT NOT NULL DEFAULT (datetime('now'))" +
      ")"
  ).run();
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS settings (" +
      "key TEXT PRIMARY KEY, " +
      "value TEXT NOT NULL" +
      ")"
  ).run();

  // Attachments (0.12.0): the bytes of every attached file, linked to the
  // emails row of the attempt that carried it.
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS attachments (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "email_id INTEGER NOT NULL, " +
      "filename TEXT NOT NULL, " +
      "content_type TEXT, " +
      "size INTEGER NOT NULL, " +
      "data BLOB NOT NULL" +
      ")"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_attachments_email ON attachments (email_id)"
  ).run();

  schemaReady = true;
}

// The effective sending-domain list, the default first. Read from D1 in a
// single query; empty until domains are added at /domains. Without a DB
// binding there are no domains (the /domains page says so).
async function getDomains(env) {
  if (!env.DB) return [];
  await ensureSchema(env);
  try {
    const r = await env.DB.prepare(
      "SELECT d.domain FROM domains d " +
      "LEFT JOIN settings s ON s.key = 'default_domain' AND s.value = d.domain " +
      "ORDER BY CASE WHEN s.value IS NOT NULL THEN 0 ELSE 1 END, d.id ASC"
    ).all();
    if (r && r.results) return r.results.map(function (row) { return row.domain; });
  } catch {}
  return [];
}

// --- Routing ------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const showLogout = !!env.PASSWORD;

    // Login (only active when PASSWORD is set)
    if (url.pathname === "/login") {
      if (!env.PASSWORD) return redirect("/");

      if (request.method === "GET") {
        if (await hasValidSession(request, env)) {
          return redirect(safeNext(url.searchParams.get("next")));
        }
        return new Response(renderLoginPage(safeNext(url.searchParams.get("next")), null), {
          headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
        });
      }

      if (request.method === "POST") {
        let form = null;
        try {
          form = await request.formData();
        } catch {}
        const password = form ? String(form.get("password") || "") : "";
        const next = safeNext(form ? form.get("next") : "/");

        if (password && (await constantTimeEqual(password, env.PASSWORD))) {
          const exp = Date.now() + SESSION_MAX_AGE_MS;
          const sig = await sessionHmacHex(env, "outbox-session." + exp);
          return new Response(null, {
            status: 303,
            headers: {
              Location: next,
              "Cache-Control": "no-store",
              "Set-Cookie":
                "outbox_session=" + exp + "." + sig +
                "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + SESSION_MAX_AGE_S,
            },
          });
        }

        await sleep(LOGIN_FAIL_DELAY_MS);
        return new Response(renderLoginPage(next, "Wrong password — try again."), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
        });
      }
    }

    // Log out: clears the session cookie and returns to the login page.
    // GET is what the sidebar link uses; POST is kept for older callers.
    if (url.pathname === "/logout" && (request.method === "GET" || request.method === "POST")) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: env.PASSWORD ? "/login" : "/",
          "Cache-Control": "no-store",
          "Set-Cookie": "outbox_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        },
      });
    }

    // The email form
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      if (!env.RESEND_KEY) {
        return new Response(
          "Worker is not configured. Set the RESEND_KEY environment variable.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      const token = url.searchParams.get("token") || "";
      const domains = await getDomains(env);

      if (domains.length === 0) {
        const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";
        const content =
          '<div class="page-head"><h1>New message</h1>' +
          '<p class="sub">Delivered via Resend</p></div>' +
          '<div class="card">' +
          '<div class="warn">No sending domains are configured yet.</div>' +
          '<p class="muted">Add your first domain to start sending.</p>' +
          '<a class="btn" href="/domains' + tokenParam + '">Add a domain</a>' +
          "</div>";
        return new Response(
          renderShell({
            title: "Outbox",
            active: "compose",
            token: token,
            domains: domains,
            showLogout: showLogout,
            content: content,
          }),
          { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
        );
      }

      return new Response(renderPage(domains, token, showLogout), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Sent-messages history (with search, and the import-result banner
    // parameters that POST /sent/import redirects back with)
    if (request.method === "GET" && url.pathname === "/sent") {
      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      const token = url.searchParams.get("token") || "";
      if (!env.DB) {
        return new Response(
          "No D1 database is bound as DB.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      await ensureSchema(env);

      // Search: a free-text query (matched against the message columns with
      // LIKE, user wildcards escaped) and/or a status filter. With neither
      // parameter the query is exactly what older builds ran.
      const q = String(url.searchParams.get("q") || "").trim();
      const statusParam = String(url.searchParams.get("status") || "").trim();
      const status = statusParam === "sent" || statusParam === "failed" ? statusParam : "";
      const filtered = q !== "" || status !== "";

      // Import outcome, carried here by the redirect after POST
      // /sent/import. Any of the count parameters present means: show it.
      const countParam = function (name) {
        const v = url.searchParams.get(name);
        return v !== null && /^\d+$/.test(v) ? parseInt(v, 10) : null;
      };
      const notice = {
        imported: countParam("imported"),
        skipped: countParam("skipped"),
        invalid: countParam("invalid"),
        errs: String(url.searchParams.get("errs") || ""),
      };
      const showNotice =
        notice.imported !== null || notice.skipped !== null || notice.invalid !== null;

      // History, the domain list and (when searching) the total match
      // count are independent — read them all at once.
      let rows = [];
      let domains = [];
      let totalMatches = null;
      try {
        const reads = [getDomains(env)];
        if (filtered) {
          const where = [];
          const binds = [];
          if (q !== "") {
            const likeCols = [
              "subject", "body", "to_addresses", "cc_addresses", "bcc_addresses",
              "from_address", "reply_to", "resend_id", "error",
            ];
            const pattern =
              "%" + q.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_") + "%";
            where.push("(" + likeCols.map(function (c) { return c + " LIKE ? ESCAPE '\\'"; }).join(" OR ") + ")");
            binds.push(pattern);
          }
          if (status !== "") {
            where.push("status = ?");
            binds.push(status);
          }
          const whereSql = where.length ? " WHERE " + where.join(" AND ") : "";
          reads.push(
            env.DB.prepare("SELECT *, " + ATTACHMENT_SUBSELECTS + "FROM emails" + whereSql + " ORDER BY id DESC LIMIT 200")
              .bind(...binds).all(),
            env.DB.prepare("SELECT COUNT(*) AS c FROM emails" + whereSql).bind(...binds).first()
          );
        } else {
          reads.push(env.DB.prepare("SELECT *, " + ATTACHMENT_SUBSELECTS + "FROM emails ORDER BY id DESC LIMIT 200").all());
        }
        const settled = await Promise.all(reads);
        domains = settled[0];
        rows = (settled[1] && settled[1].results) || [];
        if (filtered) totalMatches = settled[2] ? (settled[2].c || 0) : rows.length;
      } catch (err) {
        return new Response("Failed to read from D1: " + err.message, { status: 500 });
      }

      return new Response(
        renderSentPage(rows, token, domains, showLogout, {
          q: q,
          status: status,
          filtered: filtered,
          totalMatches: totalMatches,
          notice: showNotice ? notice : null,
          importError: String(url.searchParams.get("import_error") || ""),
        }),
        { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
      );
    }

    // CSV export of the full send history
    if (request.method === "GET" && url.pathname === "/sent/export") {
      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      if (!env.DB) {
        return new Response(
          "No D1 database is bound as DB.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      await ensureSchema(env);

      let rows = [];
      try {
        // The whole archive, not just the newest 200 shown on /sent.
        const result = await env.DB.prepare("SELECT * FROM emails ORDER BY id DESC").all();
        rows = result.results || [];
      } catch (err) {
        return new Response("Failed to read from D1: " + err.message, { status: 500 });
      }

      const header =
        "id,date,status,delivery_status,resend_id,from,to,cc,bcc,reply_to,subject,content_type,body,error";
      const lines = rows.map(function (r) {
        return [
          r.id, r.created_at, r.status, r.delivery_status, r.resend_id,
          r.from_address, r.to_addresses, r.cc_addresses, r.bcc_addresses,
          r.reply_to, r.subject,
          r.content_type, r.body, r.error,
        ].map(csvField).join(",");
      });

      // UTF-8 BOM so Excel decodes non-ASCII subjects correctly; CRLF
      // line endings per RFC 4180.
      const csv = "\uFEFF" + [header].concat(lines).join("\r\n") + "\r\n";
      const filename = "outbox-export-" + new Date().toISOString().slice(0, 10) + ".csv";

      return new Response(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="' + filename + '"',
          "Cache-Control": "no-store",
        },
      });
    }

    // Import sent emails from a CSV file — exactly the format
    // GET /sent/export writes. Appended to the archive with dedup.
    if (request.method === "POST" && url.pathname === "/sent/import") {
      return handleImport(request, env, url);
    }

    // Download one stored attachment. Authed like the pages: the links on
    // /sent carry ?token=, since a download link cannot send headers either.
    if (request.method === "GET" && url.pathname.startsWith("/attachments/")) {
      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      if (!env.DB) {
        return new Response("No D1 database is bound as DB.", {
          status: 500,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }
      await ensureSchema(env);
      const m = /^\/attachments\/(\d+)$/.exec(url.pathname);
      if (!m) return new Response("Not found", { status: 404 });

      let row = null;
      try {
        row = await env.DB.prepare(
          "SELECT filename, content_type, size, data FROM attachments WHERE id = ?"
        ).bind(Number(m[1])).first();
      } catch (err) {
        return new Response("Failed to read from D1: " + err.message, { status: 500 });
      }
      if (!row) {
        return new Response("Attachment not found", {
          status: 404,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }

      const raw = row.data;
      const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw || 0);
      const name = String(row.filename || "attachment");
      const asciiName = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
      const safeType = /^[\w.\/+ -]{1,100}$/.test(String(row.content_type || ""))
        ? String(row.content_type)
        : "application/octet-stream";
      return new Response(bytes, {
        headers: {
          "Content-Type": safeType,
          "Content-Disposition":
            'attachment; filename="' + asciiName + '"; filename*=UTF-8\'\'' + encodeURIComponent(name),
          "Content-Length": String(bytes.byteLength),
          "Cache-Control": "no-store",
        },
      });
    }

    // Usage dashboard — reads live from Resend (with D1 as fallback)
    if (request.method === "GET" && url.pathname === "/usage") {
      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      const token = url.searchParams.get("token") || "";
      if (!env.RESEND_KEY) {
        return new Response(
          "RESEND_KEY is not set.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      if (env.DB) await ensureSchema(env);

      const resend = await getResendStats(env);
      let stats;
      let domains;

      if (resend.ok) {
        // Reconciliation, the rejected count and the domain list are
        // independent — run them concurrently, not one after another.
        const settled = await Promise.all([
          env.DB ? reconcileFromResend(env, resend.list) : Promise.resolve(),
          getDomains(env),
          countRejected(env),
        ]);
        domains = settled[1];
        stats = resend.stats;
        stats.cards.push({ num: settled[2], lbl: "Rejected (worker log)", bad: true });
      } else {
        stats = env.DB ? await getD1Stats(env) : emptyStats();
        stats.warning =
          "Could not read from Resend (" + resend.error + ") — showing local database stats instead.";
        domains = await getDomains(env);
      }

      // The storage meter reads D1 directly; Resend being unreachable
      // doesn't affect it, and no database means no card at all.
      const storage = env.DB ? await getStorageInfo(env) : null;

      return new Response(renderUsagePage(stats, token, domains, showLogout, storage), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Refresh delivery details for the most recent emails
    if (request.method === "POST" && url.pathname === "/usage/sync") {
      if (!(await isAuthorized(request, env))) {
        return json({ success: false, error: "Unauthorized." }, 401);
      }
      if (!env.DB) {
        return json({ success: false, error: "No D1 database is bound as DB." }, 500);
      }
      if (!env.RESEND_KEY) {
        return json({ success: false, error: "RESEND_KEY is not set." }, 500);
      }

      await ensureSchema(env);
      const result = await syncDeliveryStatuses(env);
      return json({ success: true, checked: result.checked, byStatus: result.byStatus });
    }

    // Save (or clear) the database size limit shown on the Usage page.
    // Written to the settings table — the meter reads it from there, no
    // environment variable is involved.
    if (request.method === "POST" && url.pathname === "/usage/cap") {
      if (!(await isAuthorized(request, env))) {
        return json({ success: false, error: "Unauthorized." }, 401);
      }
      if (!env.DB) {
        return json({ success: false, error: "No D1 database is bound as DB." }, 500);
      }
      await ensureSchema(env);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ success: false, error: "Request body must be valid JSON." }, 400);
      }

      const parsed = parseCapInput(body && body.cap);
      if (parsed.error) return json({ success: false, error: parsed.error }, 400);

      try {
        await env.DB.prepare("DELETE FROM settings WHERE key = 'db_cap_mb'").run();
        if (parsed.mb !== undefined) {
          await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('db_cap_mb', ?)")
            .bind(String(parsed.mb))
            .run();
        }
      } catch (err) {
        return json({ success: false, error: "Could not save the limit: " + err.message }, 500);
      }
      return json({ success: true, cap_mb: parsed.mb === undefined ? null : parsed.mb });
    }

    // Domain management page
    if (request.method === "GET" && url.pathname === "/domains") {
      const denied = await requirePage(request, env, url);
      if (denied) return denied;
      const token = url.searchParams.get("token") || "";

      // Without a DB binding nothing can be managed — but show the page
      // with a notice instead of a dead 500, so the flow never dead-ends.
      if (!env.DB) {
        const content =
          '<div class="page-head"><h1>Domains</h1></div>' +
          '<div class="card">' +
          '<div class="warn">Domain management needs a D1 database bound as DB.</div>' +
          '<p class="muted">Bind a database, then add your sending domains here.</p>' +
          "</div>";
        return new Response(
          renderShell({
            title: "Domains — Outbox",
            active: "domains",
            token: token,
            domains: [],
            showLogout: showLogout,
            content: content,
          }),
          { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }
        );
      }

      const domains = await getDomains(env);
      return new Response(renderDomainsPage(domains, token, showLogout), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Add a sending domain
    if (request.method === "POST" && url.pathname === "/domains/add") {
      if (!(await isAuthorized(request, env))) {
        return json({ success: false, error: "Unauthorized." }, 401);
      }
      if (!env.DB) {
        return json({ success: false, error: "No D1 database is bound as DB." }, 500);
      }
      await ensureSchema(env);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ success: false, error: "Request body must be valid JSON." }, 400);
      }

      const domain = String((body && body.domain) || "")
        .trim()
        .toLowerCase()
        .replace(/\.$/, "");
      if (!DOMAIN_RE.test(domain) || domain.length > 253) {
        return json(
          { success: false, error: "That does not look like a domain (e.g. example.com)." },
          400
        );
      }

      try {
        const existing = await env.DB.prepare("SELECT id FROM domains WHERE domain = ?")
          .bind(domain)
          .first();
        if (existing) {
          return json({ success: false, error: domain + " is already on the list." }, 400);
        }
        await env.DB.prepare("INSERT INTO domains (domain) VALUES (?)").bind(domain).run();
      } catch (err) {
        return json({ success: false, error: "Could not save the domain: " + err.message }, 500);
      }
      return json({ success: true, domain: domain });
    }

    // Remove a sending domain (the last one is refused — compose needs it)
    if (request.method === "POST" && url.pathname === "/domains/remove") {
      if (!(await isAuthorized(request, env))) {
        return json({ success: false, error: "Unauthorized." }, 401);
      }
      if (!env.DB) {
        return json({ success: false, error: "No D1 database is bound as DB." }, 500);
      }
      await ensureSchema(env);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ success: false, error: "Request body must be valid JSON." }, 400);
      }

      const domain = String((body && body.domain) || "").trim().toLowerCase();
      if (!domain) {
        return json({ success: false, error: "Which domain?" }, 400);
      }

      try {
        const countRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM domains").first();
        if (countRow && countRow.c && countRow.c <= 1) {
          return json(
            { success: false, error: "At least one domain must remain — add another before removing this one." },
            400
          );
        }
        const result = await env.DB.prepare("DELETE FROM domains WHERE domain = ?")
          .bind(domain)
          .run();
        if (!result.meta || !result.meta.changes) {
          return json({ success: false, error: domain + " is not on the list." }, 400);
        }
      } catch (err) {
        return json({ success: false, error: "Could not update the list: " + err.message }, 500);
      }
      // If the default domain was just removed, the setting is dropped so
      // the oldest entry takes over. Best-effort.
      try {
        await env.DB.prepare(
          "DELETE FROM settings WHERE key = 'default_domain' AND value = ?"
        ).bind(domain).run();
      } catch {}
      return json({ success: true });
    }

    // Set the default sending domain
    if (request.method === "POST" && url.pathname === "/domains/default") {
      if (!(await isAuthorized(request, env))) {
        return json({ success: false, error: "Unauthorized." }, 401);
      }
      if (!env.DB) {
        return json({ success: false, error: "No D1 database is bound as DB." }, 500);
      }
      await ensureSchema(env);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ success: false, error: "Request body must be valid JSON." }, 400);
      }

      const domain = String((body && body.domain) || "").trim().toLowerCase();
      if (!domain) {
        return json({ success: false, error: "Which domain?" }, 400);
      }

      try {
        const existing = await env.DB.prepare("SELECT id FROM domains WHERE domain = ?")
          .bind(domain)
          .first();
        if (!existing) {
          return json({ success: false, error: domain + " is not on the list." }, 400);
        }
        await env.DB.prepare("DELETE FROM settings WHERE key = 'default_domain'").run();
        await env.DB.prepare(
          "INSERT INTO settings (key, value) VALUES ('default_domain', ?)"
        ).bind(domain).run();
      } catch (err) {
        return json({ success: false, error: "Could not save the default: " + err.message }, 500);
      }
      return json({ success: true });
    }

    // The send endpoint
    if (request.method === "POST" && url.pathname === "/send") {
      return handleSend(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

// --- Sending + automatic DB write ---------------------------------------
async function handleSend(request, env) {
  // Optional protection: the X-Auth-Token header, or a PASSWORD login session.
  if (!(await isAuthorized(request, env))) {
    return json({ success: false, error: "Unauthorized." }, 401);
  }

  // Two intake formats: the compose form posts multipart/form-data (file
  // uploads can't ride in JSON), the API stays pure JSON — its attachments
  // are {filename, content(base64), content_type?} objects. Both end up as
  // the same `fields` map plus a `files` list of raw byte arrays.
  const isMultipart = String(request.headers.get("content-type") || "")
    .toLowerCase()
    .includes("multipart/form-data");
  const FIELD_KEYS = ["to", "cc", "bcc", "from_name", "from_local", "from_domain", "reply_to", "subject", "text", "html"];
  let fields = {};
  const files = [];
  if (isMultipart) {
    let form;
    try {
      form = await request.formData();
    } catch {
      return json({ success: false, error: "The upload could not be read." }, 400);
    }
    for (const key of FIELD_KEYS) {
      fields[key] = String(form.get(key) || "");
    }
    for (const f of form.getAll("attachments")) {
      if (typeof f === "string") continue;
      if (!f.name && !f.size) continue; // nothing picked
      files.push({
        name: f.name || "attachment",
        type: f.type || "",
        bytes: new Uint8Array(await f.arrayBuffer()),
      });
    }
  } else {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, error: "Request body must be valid JSON." }, 400);
    }
    body = body && typeof body === "object" ? body : {};
    for (const key of FIELD_KEYS) {
      fields[key] = String(body[key] || "");
    }
    const apiFiles = Array.isArray(body.attachments) ? body.attachments : [];
    for (const a of apiFiles) {
      if (!a || typeof a !== "object") continue;
      let bytes = null;
      try {
        const bin = atob(String(a.content || "").replace(/\s+/g, ""));
        bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      } catch {
        return json({ success: false, error: "attachments[].content must be valid base64." }, 400);
      }
      files.push({ name: String(a.filename || "attachment"), type: String(a.content_type || ""), bytes: bytes });
    }
  }

  const recipients = splitAddresses(fields.to);
  const cc = splitAddresses(fields.cc);
  const bcc = splitAddresses(fields.bcc);
  const subject = fields.subject.trim();
  const text = fields.text.trim();
  const html = fields.html.trim();
  const replyTo = fields.reply_to.trim();
  const fromName = fields.from_name.trim().replace(/["<>]/g, "");
  const fromLocal =
    (fields.from_local || "noreply").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "") ||
    "noreply";

  // Cheap validation first — nothing below touches the database until the
  // payload is otherwise well-formed.
  if (recipients.length === 0 || !recipients.every((e) => EMAIL_RE.test(e))) {
    return json({ success: false, error: "Please provide valid recipient email address(es)." }, 400);
  }
  if (cc.length > 0 && !cc.every((e) => EMAIL_RE.test(e))) {
    return json({ success: false, error: "Please provide valid Cc email address(es)." }, 400);
  }
  if (bcc.length > 0 && !bcc.every((e) => EMAIL_RE.test(e))) {
    return json({ success: false, error: "Please provide valid Bcc email address(es)." }, 400);
  }
  // One shared cap across all three lists — Resend allows 50 recipients
  // per message counting To, Cc and Bcc together.
  if (recipients.length + cc.length + bcc.length > MAX_RECIPIENTS) {
    return json(
      { success: false, error: "Too many recipients (max " + MAX_RECIPIENTS + " across To, Cc and Bcc)." },
      400
    );
  }
  if (!subject) return json({ success: false, error: "Subject is required." }, 400);
  if (!text && !html) {
    return json({ success: false, error: "Message cannot be empty (provide text or html)." }, 400);
  }
  if (replyTo && !EMAIL_RE.test(replyTo)) {
    return json({ success: false, error: "Reply-To must be a valid email address." }, 400);
  }

  // Attachment caps: enforced before anything is stored or sent. The
  // per-file limit keeps every row under D1's 2 MB hard cap; the total
  // keeps the base64 payload under Resend's 40 MB message limit.
  if (files.length > MAX_ATTACHMENTS) {
    return json(
      { success: false, error: "Too many attachments (max " + MAX_ATTACHMENTS + " files)." },
      400
    );
  }
  let totalBytes = 0;
  for (const f of files) {
    if (f.bytes.byteLength > MAX_ATTACHMENT_BYTES) {
      return json(
        { success: false, error: '"' + f.name + '" is ' + humanBytes(f.bytes.byteLength) + " — single files are capped at " + humanBytes(MAX_ATTACHMENT_BYTES) + "." },
        400
      );
    }
    totalBytes += f.bytes.byteLength;
  }
  if (totalBytes > MAX_ATTACHMENTS_TOTAL) {
    return json(
      { success: false, error: "Attachments total " + humanBytes(totalBytes) + " — the per-message cap is " + humanBytes(MAX_ATTACHMENTS_TOTAL) + "." },
      400
    );
  }

  // The sending domain must be on the stored list; the first entry is the
  // default. One DB read, only for valid payloads.
  const allowedDomains = await getDomains(env);
  if (allowedDomains.length === 0) {
    return json(
      { success: false, error: "No sending domains are configured — add one on the Domains page." },
      400
    );
  }
  const fromDomain = String(fields.from_domain || allowedDomains[0]).trim().toLowerCase();
  if (!allowedDomains.includes(fromDomain)) {
    return json(
      { success: false, error: "from_domain must be one of: " + allowedDomains.join(", ") + "." },
      400
    );
  }

  const from = fromName
    ? fromName + " <" + fromLocal + "@" + fromDomain + ">"
    : fromLocal + "@" + fromDomain;

  const payload = { from, to: recipients, subject };
  if (text) payload.text = text;
  if (html) payload.html = html;
  if (replyTo) payload.reply_to = replyTo;
  if (cc.length) payload.cc = cc;
  if (bcc.length) payload.bcc = bcc;
  if (files.length) {
    payload.attachments = files.map(function (f) {
      const a = { filename: f.name, content: bytesToBase64(f.bytes) };
      if (f.type) a.content_type = f.type;
      return a;
    });
  }

  await ensureSchema(env);

  // What gets archived: the HTML part when present, otherwise the text.
  const storedBody = html || text;
  const contentType = html ? "html" : "text";

  // One flow for every outcome: Resend is called, the attempt is archived,
  // and the files that rode with it are stored next to it. Both archive
  // writes are best-effort — a logging problem never breaks a delivered
  // email; the response just carries a warning flag.
  let res = null;
  let resendId = null;
  let status = "sent";
  let errMsg = null;
  let httpStatus = 200;
  try {
    res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + env.RESEND_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    status = "failed";
    errMsg = "Could not reach Resend: " + err.message;
    httpStatus = 502;
  }

  if (res) {
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      resendId = (data && data.id) || null;
    } else {
      status = "failed";
      errMsg = (data && data.message) || "Resend returned HTTP " + res.status + ".";
      httpStatus = 502;
    }
  }

  const rowId = await logEmail(env, resendId, from, recipients, cc, bcc, replyTo,
    subject, storedBody, contentType, status, errMsg);
  const attachmentsSaved = files.length ? await storeAttachments(env, rowId, files) : true;

  const out = { success: status === "sent", id: resendId, saved: rowId !== null };
  if (files.length) out.attachments_saved = attachmentsSaved;
  if (errMsg) out.error = errMsg;
  return json(out, httpStatus);
}

// Links the attachment files to the archived attempt. Returns false
// (without throwing) when they could not be stored, mirroring logEmail.
async function storeAttachments(env, rowId, files) {
  if (!env.DB || rowId === null) return false;
  await ensureSchema(env);
  try {
    const statements = files.map(function (f) {
      return env.DB.prepare(
        "INSERT INTO attachments (email_id, filename, content_type, size, data) VALUES (?, ?, ?, ?, ?)"
      ).bind(rowId, f.name, f.type || null, f.bytes.byteLength, f.bytes);
    });
    for (let i = 0; i < statements.length; i += 50) {
      await env.DB.batch(statements.slice(i, i + 50));
    }
    return true;
  } catch {
    return false;
  }
}

// Writes the message into D1 and returns the new row's id, so the
// attachments can be linked to it. Returns null (without throwing) if the
// database is unavailable, so a logging problem never breaks the send.
async function logEmail(env, resendId, from, recipients, cc, bcc, replyTo, subject, body, contentType, status, error) {
  if (!env.DB) return null;
  await ensureSchema(env);
  try {
    const result = await env.DB.prepare(
      "INSERT INTO emails (resend_id, from_address, to_addresses, cc_addresses, bcc_addresses, reply_to, subject, body, content_type, status, error) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(resendId, from, recipients.join(", "),
        cc && cc.length ? cc.join(", ") : null,
        bcc && bcc.length ? bcc.join(", ") : null,
        replyTo || null, subject, body, contentType, status, error)
      .run();
    return result && result.meta && result.meta.last_row_id ? result.meta.last_row_id : null;
  } catch {
    return null;
  }
}

// --- CSV import (POST /sent/import) --------------------------------------
// Accepts exactly the format GET /sent/export writes: the same 14 columns
// (the header must name all of them, in any order), RFC 4180 quoting, UTF-8
// with or without a BOM, CRLF or LF. The import is append-only with
// duplicate protection: a row is written whenever it differs in any content
// field — timestamp, status, delivery status, from, to, cc, bcc, reply-to,
// subject, content type, body, error or Resend ID — and only records
// identical in every one of those fields are skipped. Identical rows are
// recognised against the archive by id or resend_id, by full content when
// the row carries no resend_id, and against earlier rows of the same file.
// The id from the CSV is reused only when it is still free; everything else
// is stored under a fresh autoincrement id, so nothing already in the
// archive is ever modified or deleted. Nothing is re-sent through Resend
// and no schema change is involved.

const IMPORT_COLUMNS = [
  "id", "date", "status", "delivery_status", "resend_id", "from", "to",
  "cc", "bcc", "reply_to", "subject", "content_type", "body", "error",
];
const MAX_IMPORT_BYTES = 25 * 1024 * 1024;

const IMPORT_INSERT_SQL =
  "INSERT INTO emails (id, created_at, status, delivery_status, resend_id, from_address, " +
  "to_addresses, cc_addresses, bcc_addresses, reply_to, subject, content_type, body, error) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const IMPORT_INSERT_AUTO_SQL =
  "INSERT INTO emails (created_at, status, delivery_status, resend_id, from_address, " +
  "to_addresses, cc_addresses, bcc_addresses, reply_to, subject, content_type, body, error) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

// null/undefined and "" are the same thing once a value leaves the database
// or the CSV, so every comparison normalizes both sides through this.
function normValue(v) {
  return v === null || v === undefined ? "" : String(v);
}

// Parses a CSV string into rows of string fields. RFC 4180: a field may be
// double-quoted and then contain commas, doubled quotes and newlines;
// records end with CRLF, LF or a lone CR; the UTF-8 BOM is stripped.
function parseCsv(text) {
  const s = String(text || "").replace(/^\uFEFF/, "");
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuotes) {
      if (ch === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field); field = "";
    } else if (ch === "\r" || ch === "\n") {
      row.push(field); field = "";
      rows.push(row); row = [];
      if (ch === "\r" && s[i + 1] === "\n") i++;
    } else {
      field += ch;
    }
  }
  if (field !== "" || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

// Turns parsed CSV rows into validated records. Returns { error } for
// structural problems that refuse the whole file, or { records, reasons,
// invalid } — records ready to merge, reasons explaining every rejected
// row by row number.
function parseImportCsv(text) {
  const rows = parseCsv(text);
  if (rows.length === 0) return { error: "That file is empty." };

  const header = rows[0].map(function (c) { return c.trim().toLowerCase(); });
  if (header.length !== IMPORT_COLUMNS.length) {
    return {
      error: "The header row must name exactly the " + IMPORT_COLUMNS.length +
        " columns of an Outbox export (id, date, status, ...).",
    };
  }
  const col = {};
  for (let c = 0; c < header.length; c++) col[header[c]] = c;
  for (const name of IMPORT_COLUMNS) {
    if (col[name] === undefined) {
      return {
        error: 'The header row is missing the "' + name + '" column — this does not look like an Outbox export.',
      };
    }
  }

  const records = [];
  const reasons = [];
  let invalid = 0;
  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r];
    const rowNo = r + 1; // line number as a spreadsheet shows it
    if (cells.length === 1 && cells[0].trim() === "") {
      invalid++;
      reasons.push("Row " + rowNo + ": empty row.");
      continue;
    }
    if (cells.length !== IMPORT_COLUMNS.length) {
      invalid++;
      reasons.push("Row " + rowNo + ": expected " + IMPORT_COLUMNS.length + " columns, found " + cells.length + ".");
      continue;
    }
    const cell = function (name) { return normValue(cells[col[name]]); };
    const id = cell("id").trim();
    if (id !== "" && !/^\d+$/.test(id)) {
      invalid++;
      reasons.push("Row " + rowNo + ": id must be empty or a number.");
      continue;
    }
    const status = cell("status").trim().toLowerCase();
    if (status !== "sent" && status !== "failed") {
      invalid++;
      reasons.push('Row ' + rowNo + ': status must be "sent" or "failed".');
      continue;
    }
    records.push({
      rowNo: rowNo,
      id: id,
      created_at: cell("date").trim(),
      status: status,
      delivery_status: cell("delivery_status").trim(),
      resend_id: cell("resend_id").trim(),
      from_address: cell("from"),
      to_addresses: cell("to"),
      cc_addresses: cell("cc"),
      bcc_addresses: cell("bcc"),
      reply_to: cell("reply_to"),
      subject: cell("subject"),
      content_type: cell("content_type").trim(),
      body: cell("body"),
      error: cell("error"),
    });
  }
  return { records: records, reasons: reasons, invalid: invalid };
}

// The fingerprint of a CSV record: every content field in a fixed order
// (everything except the surrogate id). Stored rows hash through
// rowFingerprint with NULLs normalized to "", so a missing value compares
// equal no matter which side it comes from.
function importTupleKey(c) {
  return JSON.stringify([
    c.created_at, c.status, c.delivery_status, c.from_address, c.to_addresses,
    c.cc_addresses, c.bcc_addresses, c.reply_to, c.subject, c.content_type,
    c.body, c.error, c.resend_id,
  ]);
}

function rowFingerprint(row) {
  return JSON.stringify([
    normValue(row.created_at), normValue(row.status), normValue(row.delivery_status),
    normValue(row.from_address), normValue(row.to_addresses), normValue(row.cc_addresses),
    normValue(row.bcc_addresses), normValue(row.reply_to), normValue(row.subject),
    normValue(row.content_type), normValue(row.body), normValue(row.error),
    normValue(row.resend_id),
  ]);
}

// After the import the browser is sent back to /sent, which renders the
// outcome as a banner. The token rides along so token-auth setups can
// still open the page.
function importRedirect(url, result, error) {
  const params = new URLSearchParams();
  const token = url.searchParams.get("token") || "";
  if (token) params.set("token", token);
  if (error) {
    params.set("import_error", String(error).slice(0, 300));
  } else {
    params.set("imported", String(result.imported));
    params.set("skipped", String(result.skipped));
    params.set("invalid", String(result.invalid));
    if (result.reasons && result.reasons.length) {
      let errs = result.reasons.slice(0, 3).join(" | ");
      if (result.reasons.length > 3 || errs.length > 380) errs = errs.slice(0, 380) + "...";
      params.set("errs", errs);
    }
  }
  const qs = params.toString();
  return redirect("/sent" + (qs ? "?" + qs : ""), 303);
}

// The import endpoint. A multipart upload cannot send the X-Auth-Token
// header, so it authenticates like a page does: the PASSWORD session
// cookie, or the ?token= carried in the form's action URL.
async function handleImport(request, env, url) {
  if (!(await pageAuthOk(request, env, url))) {
    if (env.PASSWORD) return redirect("/login?next=" + encodeURIComponent("/sent"));
    return new Response("Unauthorized", { status: 401 });
  }
  if (!env.DB) return importRedirect(url, null, "No D1 database is bound as DB.");
  await ensureSchema(env);

  let form;
  try {
    form = await request.formData();
  } catch {
    return importRedirect(url, null, "The upload could not be read.");
  }
  const file = form.get("csv");
  if (!file || typeof file === "string") {
    return importRedirect(url, null, "Choose a CSV file first.");
  }
  if (file.size > MAX_IMPORT_BYTES) {
    return importRedirect(url, null, "That file is larger than 25 MB — split it first.");
  }

  let text;
  try {
    text = await file.text();
  } catch {
    return importRedirect(url, null, "The file could not be read as text.");
  }

  const parsed = parseImportCsv(text);
  if (parsed.error) return importRedirect(url, null, parsed.error);

  const recs = parsed.records;
  const reasons = parsed.reasons.slice();
  let invalid = parsed.invalid;
  let imported = 0;
  let skipped = 0;

  // Pass 1 — preload the archive rows this file can be matched against:
  // every stored id and resend_id the file mentions, fetched in chunks of
  // 50 with their content fingerprints.
  const idNums = [];
  const seenIds = new Set();
  const resendIds = [];
  const seenResends = new Set();
  const existingIds = new Set();
  for (const rec of recs) {
    if (rec.id !== "" && !seenIds.has(rec.id)) { seenIds.add(rec.id); idNums.push(Number(rec.id)); }
    if (rec.resend_id !== "" && !seenResends.has(rec.resend_id)) {
      seenResends.add(rec.resend_id);
      resendIds.push(rec.resend_id);
    }
  }

  const byId = new Map();
  const byRid = new Map();
  const FP_COLS =
    "id, resend_id, created_at, status, delivery_status, from_address, " +
    "to_addresses, cc_addresses, bcc_addresses, reply_to, subject, " +
    "content_type, body, error";
  try {
    for (let i = 0; i < idNums.length; i += 50) {
      const chunk = idNums.slice(i, i + 50);
      const marks = chunk.map(function () { return "?"; }).join(",");
      const found = await env.DB.prepare(
        "SELECT " + FP_COLS + " FROM emails WHERE id IN (" + marks + ")"
      ).bind(...chunk).all();
      for (const row of found.results || []) {
        existingIds.add(Number(row.id));
        byId.set(Number(row.id), rowFingerprint(row));
      }
    }
    for (let i = 0; i < resendIds.length; i += 50) {
      const chunk = resendIds.slice(i, i + 50);
      const marks = chunk.map(function () { return "?"; }).join(",");
      const found = await env.DB.prepare(
        "SELECT " + FP_COLS + " FROM emails WHERE resend_id IN (" + marks + ")"
      ).bind(...chunk).all();
      for (const row of found.results || []) {
        if (!byRid.has(row.resend_id)) byRid.set(row.resend_id, rowFingerprint(row));
      }
    }
  } catch (err) {
    return importRedirect(url, null, "Could not read the database: " + err.message);
  }

  // Pass 2 — decide, don't write. The first occurrence of a record wins:
  // identical rows are skipped, rows that differ in any content field are
  // queued as new inserts.
  const nowSql = new Date().toISOString().slice(0, 19).replace("T", " ");
  const seenContent = new Set();
  const toInsert = [];

  for (const c of recs) {
    const key = importTupleKey(c);
    if (
      seenContent.has(key) ||
      (c.id !== "" && byId.get(Number(c.id)) === key) ||
      (c.resend_id !== "" && byRid.get(c.resend_id) === key)
    ) {
      skipped++;
      continue;
    }
    if (c.resend_id === "") {
      // No Resend ID to match on — identical content in the archive is the
      // one duplicate shape left to catch. NULL and "" normalize equal.
      try {
        const dup = await env.DB.prepare(
          "SELECT 1 FROM emails WHERE IFNULL(created_at,'') = ? AND status = ? " +
          "AND IFNULL(delivery_status,'') = ? AND from_address = ? AND to_addresses = ? " +
          "AND IFNULL(cc_addresses,'') = ? AND IFNULL(bcc_addresses,'') = ? " +
          "AND IFNULL(reply_to,'') = ? AND subject = ? AND IFNULL(content_type,'') = ? " +
          "AND body = ? AND IFNULL(error,'') = ? LIMIT 1"
        ).bind(
          c.created_at, c.status, c.delivery_status, c.from_address, c.to_addresses,
          c.cc_addresses, c.bcc_addresses, c.reply_to, c.subject, c.content_type,
          c.body, c.error
        ).first();
        if (dup) { skipped++; continue; }
      } catch (err) {
        return importRedirect(url, null, "Could not read the database: " + err.message);
      }
    }
    seenContent.add(key);
    toInsert.push(c);
    imported++;
  }

  // Pass 3 — write in batches of 50. The CSV id is honored only when it is
  // still free; a colliding row gets a fresh autoincrement id, so nothing
  // already in the archive is modified or deleted.
  if (toInsert.length) {
    try {
      const statements = toInsert.map(function (c) {
        const binds = [
          c.created_at !== "" ? c.created_at : nowSql,
          c.status,
          c.delivery_status === "" ? null : c.delivery_status,
          c.resend_id === "" ? null : c.resend_id,
          c.from_address,
          c.to_addresses,
          c.cc_addresses === "" ? null : c.cc_addresses,
          c.bcc_addresses === "" ? null : c.bcc_addresses,
          c.reply_to === "" ? null : c.reply_to,
          c.subject,
          c.content_type === "" ? null : c.content_type,
          c.body,
          c.error === "" ? null : c.error,
        ];
        if (c.id !== "" && !existingIds.has(Number(c.id))) {
          return env.DB.prepare(IMPORT_INSERT_SQL).bind(Number(c.id), ...binds);
        }
        return env.DB.prepare(IMPORT_INSERT_AUTO_SQL).bind(...binds);
      });
      for (let i = 0; i < statements.length; i += 50) {
        await env.DB.batch(statements.slice(i, i + 50));
      }
    } catch (err) {
      return importRedirect(url, null, "Could not write to the database: " + err.message);
    }
  }

  return importRedirect(url, { imported: imported, skipped: skipped, invalid: invalid, reasons: reasons });
}

// --- Live stats straight from Resend ------------------------------------
async function getResendStats(env) {
  let body;
  try {
    const res = await fetch(
      "https://api.resend.com/emails?limit=" + RESEND_LIST_LIMIT,
      { headers: { Authorization: "Bearer " + env.RESEND_KEY } }
    );
    if (!res.ok) {
      return { ok: false, error: "Resend API returned HTTP " + res.status };
    }
    body = await res.json().catch(() => null);
  } catch (err) {
    return { ok: false, error: "network error: " + err.message };
  }

  const list = body && Array.isArray(body.data) ? body.data : Array.isArray(body) ? body : [];
  if (!Array.isArray(list)) {
    return { ok: false, error: "unexpected response format" };
  }

  const now = Date.now();
  const DAY = 86400000;
  let last24h = 0, last7d = 0, last30d = 0;
  const dayMap = {};
  const recip = {};
  const statusMap = {};

  for (const e of list) {
    if (!e) continue;
    const t = e.created_at ? new Date(e.created_at).getTime() : NaN;
    if (!isNaN(t)) {
      const age = now - t;
      if (age <= DAY) last24h++;
      if (age <= 7 * DAY) last7d++;
      if (age <= 30 * DAY) last30d++;
      const key = new Date(t).toISOString().slice(0, 10);
      dayMap[key] = (dayMap[key] || 0) + 1;
    }
    const ev = e.last_event || e.status || null;
    if (ev) statusMap[ev] = (statusMap[ev] || 0) + 1;
    const tos = Array.isArray(e.to) ? e.to : e.to ? [String(e.to)] : [];
    for (const a of tos) {
      const s = String(a).trim();
      if (s) recip[s] = (recip[s] || 0) + 1;
    }
  }

  const perDay = [];
  const today = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
    const key = d.toISOString().slice(0, 10);
    perDay.push({ day: key, count: dayMap[key] || 0, failed: 0 });
  }

  const delivery = Object.keys(statusMap)
    .map(function (k) { return { s: k, c: statusMap[k] }; })
    .sort(function (a, b) { return b.c - a.c; });

  const topRecipients = Object.keys(recip)
    .map(function (k) { return [k, recip[k]]; })
    .sort(function (a, b) { return b[1] - a[1]; })
    .slice(0, 5);

  return {
    ok: true,
    list: list,
    stats: {
      source: "resend",
      warning: null,
      note:
        list.length >= RESEND_LIST_LIMIT
          ? "Showing the " + RESEND_LIST_LIMIT + " most recent emails Resend has on record — older sends are not included."
          : null,
      cards: [
        { num: list.length, lbl: "Sent (per Resend)" },
        { num: last24h, lbl: "Last 24 hours" },
        { num: last7d, lbl: "Last 7 days" },
        { num: last30d, lbl: "Last 30 days" },
      ],
      perDay: perDay,
      delivery: delivery,
      topRecipients: topRecipients,
    },
  };
}

// Back-fills D1 with emails Resend knows about that the worker never logged,
// and refreshes stored delivery statuses. Best-effort: never throws.
async function reconcileFromResend(env, list) {
  if (!env.DB || !Array.isArray(list)) return;
  try {
    // Only the resend IDs present in this list can match anything — look
    // up exactly those rows (in chunks) instead of every send ever logged.
    const ids = [];
    for (const e of list) {
      if (e && e.id) ids.push(String(e.id));
    }
    if (ids.length === 0) return;

    const existing = {};
    for (let i = 0; i < ids.length; i += 50) {
      const chunk = ids.slice(i, i + 50);
      const placeholders = chunk.map(function () { return "?"; }).join(",");
      const r = await env.DB.prepare(
        "SELECT id, resend_id, delivery_status FROM emails WHERE resend_id IN (" + placeholders + ")"
      )
        .bind(...chunk)
        .all();
      for (const row of r.results || []) existing[row.resend_id] = row;
    }

    for (const e of list) {
      if (!e || !e.id) continue;
      const ev = e.last_event || null;
      const row = existing[e.id];

      if (row) {
        if (ev && row.delivery_status !== ev) {
          await env.DB.prepare("UPDATE emails SET delivery_status = ? WHERE id = ?")
            .bind(ev, row.id).run();
        }
        continue;
      }

      const tos = Array.isArray(e.to) ? e.to : e.to ? [String(e.to)] : [];
      const ccs = Array.isArray(e.cc) ? e.cc : e.cc ? [String(e.cc)] : [];
      const bccs = Array.isArray(e.bcc) ? e.bcc : e.bcc ? [String(e.bcc)] : [];
      const replyTo = Array.isArray(e.reply_to)
        ? e.reply_to.join(", ")
        : e.reply_to
        ? String(e.reply_to)
        : null;
      const created = e.created_at ? new Date(e.created_at) : new Date();
      const createdSql = isNaN(created.getTime())
        ? new Date().toISOString().slice(0, 19).replace("T", " ")
        : created.toISOString().slice(0, 19).replace("T", " ");
      const storedBody = e.text ? String(e.text) : e.html ? String(e.html) : "(imported from Resend)";
      const contentType = e.text ? "text" : e.html ? "html" : null;

      await env.DB.prepare(
        "INSERT INTO emails (resend_id, from_address, to_addresses, cc_addresses, bcc_addresses, reply_to, subject, body, content_type, status, error, created_at, delivery_status) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent', NULL, ?, ?)"
      )
        .bind(
          e.id,
          String(e.from || "unknown"),
          tos.join(", "),
          ccs.length ? ccs.join(", ") : null,
          bccs.length ? bccs.join(", ") : null,
          replyTo,
          String(e.subject || "(no subject)"),
          storedBody,
          contentType,
          createdSql,
          ev
        )
        .run();
    }
  } catch {
    // Reconciliation is best-effort; never break the dashboard over it
  }
}

// "Rejected (worker log)": attempts Resend refused outright — they never
// enter Resend's list, so only the worker saw them.
async function countRejected(env) {
  if (!env.DB) return 0;
  try {
    const r = await env.DB.prepare(
      "SELECT COUNT(*) AS c FROM emails WHERE status = 'failed'"
    ).first();
    return r && r.c ? r.c : 0;
  } catch {
    return 0;
  }
}

// --- D1 fallback stats (used only if Resend is unreachable) -------------
async function getD1Stats(env) {
  const scalar = async (sql) => {
    try {
      const r = await env.DB.prepare(sql).first();
      return r && r.c ? r.c : 0;
    } catch {
      return 0;
    }
  };

  const counts = await Promise.all([
    scalar("SELECT COUNT(*) AS c FROM emails"),
    scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'sent'"),
    scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'failed'"),
    scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-1 day')"),
    scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-7 days')"),
    scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-30 days')"),
  ]);
  const total = counts[0];
  const sent = counts[1];
  const failed = counts[2];
  const last24h = counts[3];
  const last7d = counts[4];
  const last30d = counts[5];

  const perDayMap = {};
  try {
    const r = await env.DB.prepare(
      "SELECT date(created_at) AS day, COUNT(*) AS c, " +
      "SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS f " +
      "FROM emails WHERE created_at >= datetime('now', '-13 days') GROUP BY day"
    ).all();
    for (const row of r.results || []) {
      perDayMap[row.day] = { c: row.c || 0, f: row.f || 0 };
    }
  } catch {}

  const perDay = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
    const key = d.toISOString().slice(0, 10);
    const entry = perDayMap[key];
    perDay.push({ day: key, count: entry ? entry.c : 0, failed: entry ? entry.f : 0 });
  }

  const recipCounts = {};
  try {
    const r = await env.DB.prepare(
      "SELECT to_addresses FROM emails ORDER BY id DESC LIMIT 500"
    ).all();
    for (const row of r.results || []) {
      for (const addr of String(row.to_addresses || "").split(",")) {
        const a = addr.trim();
        if (a) recipCounts[a] = (recipCounts[a] || 0) + 1;
      }
    }
  } catch {}
  const topRecipients = Object.keys(recipCounts)
    .map(function (k) { return [k, recipCounts[k]]; })
    .sort(function (a, b) { return b[1] - a[1]; })
    .slice(0, 5);

  let delivery = [];
  try {
    const r = await env.DB.prepare(
      "SELECT delivery_status AS s, COUNT(*) AS c " +
      "FROM emails WHERE delivery_status IS NOT NULL GROUP BY delivery_status ORDER BY c DESC"
    ).all();
    delivery = r.results || [];
  } catch {}

  return {
    source: "d1",
    warning: null,
    note: null,
    cards: [
      { num: total, lbl: "Total attempts" },
      { num: sent, lbl: "Sent OK" },
      { num: failed, lbl: "Failed", bad: true },
      { num: last24h, lbl: "Last 24 hours" },
      { num: last7d, lbl: "Last 7 days" },
      { num: last30d, lbl: "Last 30 days" },
    ],
    perDay: perDay,
    delivery: delivery,
    topRecipients: topRecipients,
  };
}

function emptyStats() {
  return {
    source: "d1",
    warning: null,
    note: null,
    cards: [],
    perDay: [],
    delivery: [],
    topRecipients: [],
  };
}

// Checks the 25 most recent sent emails against Resend's API and records
// their latest delivery event (delivered / bounced / complained / ...).
// The lookups are independent — they run concurrently, in batches of five
// to stay friendly to Resend's rate limits.
async function syncDeliveryStatuses(env) {
  let results = [];
  try {
    const r = await env.DB.prepare(
      "SELECT id, resend_id FROM emails " +
      "WHERE status = 'sent' AND resend_id IS NOT NULL ORDER BY id DESC LIMIT 25"
    ).all();
    results = r.results || [];
  } catch {}

  let checked = 0;
  const byStatus = {};
  for (let i = 0; i < results.length; i += 5) {
    const batch = results.slice(i, i + 5);
    await Promise.all(
      batch.map(async function (row) {
        try {
          const res = await fetch(
            "https://api.resend.com/emails/" + encodeURIComponent(row.resend_id),
            { headers: { Authorization: "Bearer " + env.RESEND_KEY } }
          );
          if (!res.ok) return;
          const body = await res.json().catch(() => null);
          const d = body && body.data ? body.data : body;
          const ev = d && (d.last_event || d.status) ? (d.last_event || d.status) : "unknown";
          await env.DB.prepare("UPDATE emails SET delivery_status = ? WHERE id = ?")
            .bind(ev, row.id).run();
          checked++;
          byStatus[ev] = (byStatus[ev] || 0) + 1;
        } catch {
          // Skip this email and keep going
        }
      })
    );
  }
  return { checked, byStatus };
}

// --- Database storage (the /usage meter) ---------------------------------
// D1 does not expose a database's on-disk size to the Worker, so "used" is
// computed from the data itself: attachment bytes plus an estimate of the
// message rows (column lengths plus a per-row overhead allowance). When D1
// answers the page_count/page_size pragmas — not in its supported PRAGMA
// list, so this can quietly fail — the real file size is shown instead.
// The cap the meter divides by is the limit saved on the Usage page
// (settings table); until one is saved the Workers Paid maximum is assumed.

// Turns what the Size limit field contains into megabytes: "500 MB",
// "10 GB", a bare number (megabytes). Empty means "back to the default".
// Anything else is refused, with an example in the message.
function parseCapInput(raw) {
  const s = String(raw === undefined || raw === null ? "" : raw).trim().toLowerCase();
  if (s === "") return { clear: true };
  const m = /^([0-9]+(?:\.[0-9]+)?)\s*(kb|mb|gb)?$/.exec(s);
  if (!m) {
    return { error: 'Use a size like "500 MB" or "10 GB" — a number alone is megabytes.' };
  }
  let mb = Number(m[1]);
  if (m[2] === "kb") mb /= 1024;
  if (m[2] === "gb") mb *= 1024;
  mb = Math.round(mb);
  if (mb < 1) return { error: "The limit must be at least 1 MB." };
  if (mb > 10240) {
    return { error: "D1 caps a single database at 10 GB — the limit cannot be set higher." };
  }
  return { mb: mb };
}

async function getStorageInfo(env) {
  const out = {
    files: 0,
    attachmentBytes: 0,
    textBytes: 0,
    dbBytes: null,
    capBytes: DEFAULT_DB_CAP_BYTES,
    capIsDefault: true,
  };
  try {
    const a = await env.DB.prepare(
      "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM attachments"
    ).first();
    out.files = (a && a.n) || 0;
    out.attachmentBytes = (a && a.b) || 0;
  } catch {}
  // The saved limit — the Size limit field writes it here as megabytes.
  // Nothing stored (or an unreadable value) keeps the default cap.
  try {
    const c = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = 'db_cap_mb'"
    ).first();
    const mb = Number(c && c.value);
    if (mb > 0) {
      out.capBytes = mb * 1024 * 1024;
      out.capIsDefault = false;
    }
  } catch {}
  try {
    const t = await env.DB.prepare(
      "SELECT COALESCE(SUM(" +
      "LENGTH(COALESCE(body, '')) + LENGTH(COALESCE(subject, '')) + " +
      "LENGTH(COALESCE(to_addresses, '')) + LENGTH(COALESCE(cc_addresses, '')) + " +
      "LENGTH(COALESCE(bcc_addresses, '')) + LENGTH(COALESCE(from_address, '')) + " +
      "LENGTH(COALESCE(reply_to, '')) + LENGTH(COALESCE(resend_id, '')) + " +
      "LENGTH(COALESCE(delivery_status, '')) + LENGTH(COALESCE(content_type, '')) + " +
      "LENGTH(COALESCE(error, '')) + 96), 0) AS b FROM emails"
    ).first();
    out.textBytes = (t && t.b) || 0;
  } catch {}
  try {
    const pc = await env.DB.prepare("PRAGMA page_count").first();
    const ps = await env.DB.prepare("PRAGMA page_size").first();
    const pageCount = pc ? Number(pc.page_count !== undefined ? pc.page_count : Object.values(pc)[0]) : 0;
    const pageSize = ps ? Number(ps.page_size !== undefined ? ps.page_size : Object.values(ps)[0]) : 0;
    if (pageCount > 0 && pageSize > 0) out.dbBytes = pageCount * pageSize;
  } catch {}
  return out;
}

// --- Pages: shared dashboard shell --------------------------------------
// All pages render through renderShell(): sidebar navigation on desktop
// that collapses into a sticky top bar with tab navigation below 860px,
// plus a light/dark theme toggle. Light is the default; the choice is
// stored per browser in localStorage ("outbox-theme"); the system
// color-scheme preference is deliberately not auto-detected. All colors go
// through CSS custom properties. Rendered email previews (the sandboxed
// iframes and the plain-text preview) deliberately stay white in both
// themes — that is how the recipient sees the message.

const ICON_BRAND =
  '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<rect x="2.5" y="4.75" width="19" height="14.5" rx="2.5"/><path d="M3 6.5l9 6.5 9-6.5"/></svg>';
const ICON_COMPOSE =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>';
const ICON_SENT =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M22 12h-6l-2 3h-4l-2-3H2"/>' +
  '<path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>';
const ICON_USAGE =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg>';
const ICON_DOMAINS =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>' +
  '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>';
const ICON_MOON =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
const ICON_SUN =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<circle cx="12" cy="12" r="4"/>' +
  '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const ICON_LOGOUT =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>' +
  '<polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';

// Restores the saved theme before first paint, and flips it on any click of
// #theme-toggle (the shell and the login page both carry that button).
const THEME_SCRIPT = `<script>
(function () {
  try {
    var t = localStorage.getItem("outbox-theme");
    if (t === "dark" || t === "light") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {}
  document.addEventListener("click", function (e) {
    var el = e.target;
    while (el && el.nodeType === 1) {
      if (el.id === "theme-toggle") {
        var root = document.documentElement;
        var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("outbox-theme", next); } catch (err) {}
        return;
      }
      if (el === document.body) return;
      el = el.parentNode;
    }
  });
})();
</script>`;

const SHARED_CSS = `
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html { color-scheme: light; }
  html[data-theme="dark"] { color-scheme: dark; }

  :root {
    --bg: #ffffff;
    --bg-soft: #fafafa;
    --fg: #1a1a1a;
    --muted: #6f6f74;
    --border: #e7e7e7;
    --border-strong: #c9c9c9;
    --card: #ffffff;
    --accent: #1a1a1a;
    --accent-hover: #000000;
    --accent-fg: #ffffff;
    --ghost-bg: #ffffff;
    --ghost-hover: #f2f2f2;
    --input-bg: #ffffff;
    --input-border: #c9c9c9;
    --focus: #1a1a1a;
    --hover: #f2f2f2;
    --ok: #0a7d32;
    --err: #c0392b;
    --err-soft: rgba(192, 57, 43, 0.07);
    --chart-bar: #1a1a1a;
    --code-bg: #fafafa;
    --code-border: #f0f0f0;
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
  }
  html[data-theme="dark"] {
    --bg: #101214;
    --bg-soft: #15171b;
    --fg: #e6e6e6;
    --muted: #9b9ba3;
    --border: #26292e;
    --border-strong: #3d4147;
    --card: #15171b;
    --accent: #e8e8e8;
    --accent-hover: #ffffff;
    --accent-fg: #141518;
    --ghost-bg: transparent;
    --ghost-hover: #1f2226;
    --input-bg: #0f1113;
    --input-border: #3d4147;
    --focus: #e6e6e6;
    --hover: #1f2226;
    --ok: #3cb371;
    --err: #e0655c;
    --err-soft: rgba(224, 101, 92, 0.12);
    --chart-bar: #d7d7d7;
    --code-bg: #0f1113;
    --code-border: #26292e;
    --shadow: none;
  }

  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  .shell { display: flex; min-height: 100vh; }

  .sidebar {
    flex: none;
    width: 232px;
    background: var(--bg-soft);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 18px 14px 16px;
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 2px 8px 16px;
    font-size: 16px;
    font-weight: 700;
    letter-spacing: -0.01em;
  }
  .brand-icon {
    flex: none;
    width: 34px;
    height: 34px;
    border: 1px solid var(--border-strong);
    border-radius: 9px;
    background: var(--card);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .nav { display: flex; flex-direction: column; gap: 4px; }
  .nav-link {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    border-radius: 8px;
    color: var(--fg);
    text-decoration: none;
    font-size: 14px;
    font-weight: 500;
  }
  .nav-link svg { flex: none; opacity: 0.7; }
  .nav-link:hover { background: var(--hover); }
  .nav-link.active { background: var(--accent); color: var(--accent-fg); font-weight: 600; }
  .nav-link.active svg { opacity: 1; }

  .side-bottom { margin-top: auto; padding-top: 14px; display: flex; flex-direction: column; gap: 10px; }
  .theme-toggle {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 9px 10px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--ghost-bg);
    color: var(--fg);
    font: inherit;
    font-size: 13.5px;
    font-weight: 500;
    cursor: pointer;
  }
  .theme-toggle:hover { background: var(--ghost-hover); }
  .theme-toggle .when-light,
  .theme-toggle .when-dark { display: none; align-items: center; gap: 9px; }
  html:not([data-theme="dark"]) .theme-toggle .when-light { display: flex; }
  html[data-theme="dark"] .theme-toggle .when-dark { display: flex; }
  .logout-btn {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    padding: 9px 10px;
    border: 1px solid var(--border-strong);
    border-radius: 8px;
    background: var(--ghost-bg);
    color: var(--fg);
    font: inherit;
    font-size: 13.5px;
    font-weight: 500;
    text-decoration: none;
    cursor: pointer;
  }
  .logout-btn:hover { background: var(--ghost-hover); }
  .side-foot { padding: 0 10px; font-size: 12px; color: var(--muted); line-height: 1.5; }
  .foot-domain {
    color: var(--fg);
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .foot-domain + .foot-domain { margin-top: 1px; }

  .main { flex: 1; min-width: 0; padding: 34px 24px 60px; }
  .content { max-width: 720px; margin: 0 auto; }
  .content.narrow { max-width: 620px; }
  .content.wide { max-width: 1020px; }
  .page-head { margin: 0 0 20px; }
  .page-head h1 { font-size: 21px; margin: 0 0 4px; letter-spacing: -0.01em; }
  .page-head .sub { color: var(--muted); font-size: 14px; margin: 0; }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    box-shadow: var(--shadow);
  }
  .card h2 { font-size: 14px; margin: 0 0 12px; }
  .grid-2 { margin-top: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

  .btn {
    padding: 10px 16px;
    font: inherit;
    font-size: 14px;
    font-weight: 600;
    color: var(--accent-fg);
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 8px;
    cursor: pointer;
  }
  .btn:hover:not(:disabled) { background: var(--accent-hover); border-color: var(--accent-hover); }
  .btn:disabled { opacity: 0.6; cursor: default; }
  .btn.block { width: 100%; }
  .btn.small { padding: 8px 14px; font-size: 13px; }
  .btn.ghost { color: var(--fg); background: var(--ghost-bg); border-color: var(--border-strong); }
  .btn.ghost:hover:not(:disabled) { background: var(--ghost-hover); border-color: var(--border-strong); }
  a.btn { display: inline-block; text-decoration: none; }

  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px; }
  input, textarea, select {
    width: 100%;
    padding: 10px 12px;
    font: inherit;
    font-size: 14px;
    color: var(--fg);
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: 8px;
  }
  select { cursor: pointer; }
  input:focus, textarea:focus, select:focus { outline: 2px solid var(--focus); outline-offset: -1px; border-color: var(--focus); }
  input[type="checkbox"] { width: 16px; height: 16px; padding: 0; margin: 0; accent-color: var(--accent); }
  textarea { min-height: 150px; resize: vertical; }

  .status { margin-top: 16px; font-size: 14px; min-height: 20px; }
  .status.success { color: var(--ok); }
  .status.error { color: var(--err); }
  .muted { color: var(--muted); font-size: 13px; }
  .warn {
    border: 1px solid var(--err);
    background: var(--err-soft);
    color: var(--err);
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    margin: 0 0 16px;
  }

  a:focus-visible, button:focus-visible, summary:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

  @media (min-width: 861px) {
    .main { padding: 40px 40px 72px; }
  }
  @media (max-width: 640px) {
    .grid-2 { grid-template-columns: 1fr; }
  }
  @media (max-width: 860px) {
    .shell { flex-direction: column; }
    .sidebar {
      width: 100%;
      height: auto;
      position: sticky;
      top: 0;
      z-index: 30;
      border-right: none;
      border-bottom: 1px solid var(--border);
      padding: 10px 14px;
      display: grid;
      grid-template-columns: 1fr auto;
      grid-template-areas: "brand side" "nav nav";
      row-gap: 6px;
      align-items: center;
      overflow: visible;
    }
    .brand { grid-area: brand; padding: 2px 0; font-size: 15px; }
    .brand-icon { width: 30px; height: 30px; border-radius: 8px; }
    .side-bottom { grid-area: side; margin-top: 0; padding-top: 0; flex-direction: row; gap: 6px; align-items: center; }
    .side-foot { display: none; }
    .theme-toggle { width: auto; padding: 8px 12px; }
    .logout-btn { width: auto; padding: 8px 12px; }
    .nav {
      grid-area: nav;
      flex-direction: row;
      gap: 6px;
      overflow-x: auto;
      padding-bottom: 2px;
      scrollbar-width: none;
    }
    .nav::-webkit-scrollbar { display: none; }
    .nav-link { flex: none; padding: 8px 12px; font-size: 13.5px; }
    .main { padding: 22px 16px 52px; }
    .card { padding: 18px; }
  }
  @media (max-width: 480px) {
    .theme-toggle .btn-label, .logout-btn .btn-label { display: none; }
  }
`;

// o: { title, active, token, domains, showLogout, width, content, extraCss, script }
function renderShell(o) {
  const token = o.token || "";
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";
  const navLink = function (href, key, label, icon) {
    const active = o.active === key;
    return (
      '<a class="nav-link' + (active ? " active" : "") + '" href="' + href + '"' +
      (active ? ' aria-current="page"' : "") + ">" +
      icon + "<span>" + label + "</span></a>"
    );
  };
  const nav =
    navLink("/" + tokenParam, "compose", "Compose", ICON_COMPOSE) +
    navLink("/sent" + tokenParam, "sent", "Sent", ICON_SENT) +
    navLink("/usage" + tokenParam, "usage", "Usage", ICON_USAGE) +
    navLink("/domains" + tokenParam, "domains", "Domains", ICON_DOMAINS);
  const footDomains = (o.domains || [])
    .map(function (d) { return '<div class="foot-domain">' + escapeHtml(d) + "</div>"; })
    .join("");
  const foot = '<div class="side-foot">' + footDomains + "delivered via Resend</div>";
  const logout = o.showLogout
    ? '<a class="logout-btn" href="/logout">' +
      ICON_LOGOUT + '<span class="btn-label">Log out</span></a>'
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${o.title}</title>
<style>
 ${SHARED_CSS}
 ${o.extraCss || ""}
</style>
 ${THEME_SCRIPT}
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <span class="brand-icon">${ICON_BRAND}</span>
      <span>Outbox</span>
    </div>
    <nav class="nav">${nav}</nav>
    <div class="side-bottom">
      <button type="button" class="theme-toggle" id="theme-toggle" aria-label="Switch color theme">
        <span class="when-light">${ICON_MOON}<span class="btn-label">Dark mode</span></span>
        <span class="when-dark">${ICON_SUN}<span class="btn-label">Light mode</span></span>
      </button>
      ${logout}
      ${foot}
    </div>
  </aside>
  <main class="main">
    <div class="content ${o.width || ""}">${o.content}</div>
  </main>
</div>
 ${o.script || ""}
</body>
</html>`;
}

// The login page stands apart from the shell (no navigation until you are
// in), but shares its CSS and the theme toggle. Plain HTML form POST — the
// page itself needs no script.
function renderLoginPage(next, error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log in — Outbox</title>
<style>
 ${SHARED_CSS}
  .login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px 16px; }
  .login-card { width: 100%; max-width: 340px; }
  .login-brand { display: flex; align-items: center; gap: 10px; font-size: 16px; font-weight: 700; letter-spacing: -0.01em; }
  .login-card .sub { color: var(--muted); font-size: 14px; margin: 6px 0 4px; }
  .login-card .warn { margin: 0 0 8px; }
  .login-card .btn { margin-top: 18px; }
  .login-hint { margin: 14px 0 0; text-align: center; }
  .login-theme { position: fixed; top: 14px; right: 14px; }
  .login-theme .theme-toggle { width: auto; padding: 8px 12px; }
</style>
 ${THEME_SCRIPT}
</head>
<body>
<div class="login-theme">
  <button type="button" class="theme-toggle" id="theme-toggle" aria-label="Switch color theme">
    <span class="when-light">${ICON_MOON}<span class="btn-label">Dark mode</span></span>
    <span class="when-dark">${ICON_SUN}<span class="btn-label">Light mode</span></span>
  </button>
</div>
<div class="login-wrap">
  <div class="card login-card">
    <div class="login-brand"><span class="brand-icon">${ICON_BRAND}</span><span>Outbox</span></div>
    <p class="sub">Enter the password to continue.</p>
    ${error ? '<div class="warn">' + escapeHtml(error) + "</div>" : ""}
    <form method="post" action="/login">
      <label for="password">Password</label>
      <input id="password" type="password" name="password" required autofocus autocomplete="current-password">
      <input type="hidden" name="next" value="${escapeHtml(next)}">
      <button type="submit" class="btn block">Log in</button>
    </form>
    <p class="muted login-hint">Stays signed in for 30 days on this browser.</p>
  </div>
</div>
</body>
</html>`;
}

function renderPage(domains, token, showLogout) {
  const domainsJson = JSON.stringify(domains).replace(/</g, "\\u003c");
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");

  // The picker appears with two or more domains; the first is the default.
  const domainOptions = domains
    .map(function (d, i) {
      return (
        '<option value="' + escapeHtml(d) + '"' + (i === 0 ? " selected" : "") + ">" +
        escapeHtml(d) + "</option>"
      );
    })
    .join("");
  const fromControl = domains.length > 1
    ? '<div class="from-row">' +
      '<input id="from_local" type="text" value="noreply">' +
      '<select id="from_domain" aria-label="Sending domain">' + domainOptions + "</select></div>"
    : '<input id="from_local" type="text" value="noreply">';

  const content = `
<div class="page-head">
  <h1>New message</h1>
  <p class="sub">Delivered via Resend</p>
</div>
<div class="card">
  <form id="send-form">
    <label for="to">To</label>
    <input id="to" type="text" placeholder="name@example.com (comma-separate for multiple)" required>
    <label for="cc">Cc</label>
    <input id="cc" type="text" placeholder="Optional, comma-separate for multiple">
    <label for="bcc">Bcc</label>
    <input id="bcc" type="text" placeholder="Optional, comma-separate for multiple">
    <label for="from_name">From name</label>
    <input id="from_name" type="text" placeholder="Optional, e.g. My App">
    <label for="from_local">From address</label>
    ${fromControl}
    <div class="hint" id="from-preview"></div>
    <label for="reply_to">Reply-To</label>
    <input id="reply_to" type="email" placeholder="Optional">
    <label for="subject">Subject</label>
    <input id="subject" type="text" required>
    <label for="message" id="message-label">Message</label>
    <textarea id="message" required></textarea>
    <div class="row">
      <label class="checkrow"><input type="checkbox" id="as_html"> Send as HTML</label>
      <button type="button" id="preview-btn" class="btn ghost small">Preview</button>
    </div>
    <iframe id="preview-frame" class="preview-frame" sandbox="" hidden></iframe>
    <pre id="preview-text" class="preview-text" hidden></pre>
    <label for="attachments">Attachments</label>
    <div class="attach-row">
      <input id="attachments" type="file" multiple aria-label="Files to attach">
      <label for="attachments" class="btn ghost small">Add files</label>
    </div>
    <ul id="attachment-list" class="attach-list" hidden></ul>
    <div class="hint" id="attachment-hint">Optional — up to 10 files, 1.5 MB each, 25 MB total. Archived with the message in D1 and sent via Resend.</div>
    <button id="submit-btn" type="submit" class="btn block">Send email</button>
  </form>
  <div class="status" id="status"></div>
</div>`;

  const extraCss = `
  .hint { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .from-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .from-row input { flex: 1 1 150px; min-width: 0; }
  .from-row select { flex: 0 1 auto; max-width: 100%; }
  .row { display: flex; justify-content: space-between; align-items: center; margin-top: 14px; gap: 12px; flex-wrap: wrap; }
  .checkrow { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; margin: 0; cursor: pointer; }
  .preview-frame, .preview-text {
    width: 100%;
    border: 1px solid var(--input-border);
    border-radius: 8px;
    margin-top: 12px;
  }
  /* Rendered previews stay white in both themes: that is how the
     recipient sees the message. */
  .preview-frame { height: 260px; display: block; background: #ffffff; }
  .preview-text {
    min-height: 150px;
    padding: 12px;
    white-space: pre-wrap;
    word-wrap: break-word;
    font: inherit;
    font-size: 14px;
    color: #1a1a1a;
    background: #ffffff;
  }
  #submit-btn { margin-top: 22px; }
  /* The picker is one button: the real input is visually hidden (but stays
     keyboard-reachable — :focus-within moves the focus outline onto the
     button), and every picked file is listed underneath with a Remove. */
  .attach-row input[type="file"] {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
    border: 0;
  }
  .attach-row label { display: inline-block; margin: 0; }
  .attach-row:focus-within label { outline: 2px solid var(--focus); outline-offset: 2px; }
  .attach-list { list-style: none; margin: 10px 0 0; padding: 0; }
  .attach-list li {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13.5px;
  }
  .attach-list li:last-child { border-bottom: none; }
  .attach-list .att-name { flex: 1 1 auto; min-width: 0; overflow-wrap: anywhere; }
  .attach-list .att-size { flex: none; color: var(--muted); }
  .attach-list button {
    flex: none;
    border: none;
    background: none;
    color: var(--err);
    font: inherit;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    padding: 2px 4px;
  }
  .attach-list button:hover { text-decoration: underline; }
  .hint.err { color: var(--err); }
`;

  const script = `<script>
(function () {
  var DOMAINS = ${domainsJson};
  var TOKEN = ${tokenJson};
  var form = document.getElementById("send-form");
  var statusBox = document.getElementById("status");
  var localInput = document.getElementById("from_local");
  var domainSel = document.getElementById("from_domain");
  var fromPreview = document.getElementById("from-preview");
  var btn = document.getElementById("submit-btn");
  var htmlBox = document.getElementById("as_html");
  var msgLabel = document.getElementById("message-label");
  var messageBox = document.getElementById("message");
  var previewBtn = document.getElementById("preview-btn");
  var previewFrame = document.getElementById("preview-frame");
  var previewText = document.getElementById("preview-text");
  var previewing = false;
  var attInput = document.getElementById("attachments");
  var attHint = document.getElementById("attachment-hint");
  var attList = document.getElementById("attachment-list");
  var ATT_MAX_FILES = 10;
  var ATT_MAX_FILE = 1572864;  /* 1.5 MB — kept in sync with the server */
  var ATT_MAX_TOTAL = 26214400; /* 25 MB */
  var ATT_HINT = "Optional — up to 10 files, 1.5 MB each, 25 MB total. Archived with the message in D1 and sent via Resend.";
  // A file input replaces its whole selection on every pick, which is why
  // a second pass used to cover the first. The list therefore lives in the
  // "picked" array instead: every change ADDS to it and then clears the
  // input, which also makes re-picking the very same file fire the next
  // change.
  var picked = [];

  function fmtSize(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
    if (n >= 1024) return Math.round(n / 1024) + " KB";
    return n + " B";
  }

  function pickedBytes() {
    var t = 0;
    for (var i = 0; i < picked.length; i++) t += picked[i].size;
    return t;
  }

  function sameFile(a, b) {
    return a.name === b.name && a.size === b.size && a.lastModified === b.lastModified;
  }

  // One row per picked file, each with its own Remove button. Rows are
  // built with createElement/textContent — filenames are never trusted
  // as HTML.
  function renderAttachmentList() {
    while (attList.firstChild) attList.removeChild(attList.firstChild);
    for (var i = 0; i < picked.length; i++) {
      (function (idx) {
        var li = document.createElement("li");
        var name = document.createElement("span");
        name.className = "att-name";
        name.textContent = picked[idx].name;
        var size = document.createElement("span");
        size.className = "att-size";
        size.textContent = fmtSize(picked[idx].size);
        var rm = document.createElement("button");
        rm.type = "button";
        rm.textContent = "Remove";
        rm.addEventListener("click", function () {
          picked.splice(idx, 1);
          showPicked("");
        });
        li.appendChild(name);
        li.appendChild(size);
        li.appendChild(rm);
        attList.appendChild(li);
      })(i);
    }
    attList.hidden = picked.length === 0;
  }

  // "N files, X total" — plus, when a pick had to refuse files, why.
  function showPicked(refused) {
    renderAttachmentList();
    if (!picked.length) {
      attHint.textContent = refused || ATT_HINT;
      attHint.className = refused ? "hint err" : "hint";
      return;
    }
    attHint.textContent = picked.length + " file" + (picked.length === 1 ? "" : "s") + ", " +
      fmtSize(pickedBytes()) + " total" + (refused ? " — " + refused : "");
    attHint.className = refused ? "hint err" : "hint";
  }

  attInput.addEventListener("change", function () {
    var incoming = Array.prototype.slice.call(attInput.files);
    attInput.value = "";  // reset now so any later pick fires a fresh change
    var refused = [];
    for (var i = 0; i < incoming.length; i++) {
      var f = incoming[i];
      var dup = false;
      for (var j = 0; j < picked.length; j++) {
        if (sameFile(picked[j], f)) { dup = true; break; }
      }
      if (dup) {
        refused.push('"' + f.name + '" is already on the list');
      } else if (f.size > ATT_MAX_FILE) {
        refused.push('"' + f.name + '" is over ' + fmtSize(ATT_MAX_FILE) + " and was not added");
      } else if (picked.length >= ATT_MAX_FILES) {
        refused.push('"' + f.name + '" would exceed ' + ATT_MAX_FILES + " files and was not added");
      } else if (pickedBytes() + f.size > ATT_MAX_TOTAL) {
        refused.push('"' + f.name + '" would push the total over ' + fmtSize(ATT_MAX_TOTAL) + " and was not added");
      } else {
        picked.push(f);
      }
    }
    showPicked(refused.length ? refused.join("; ") : "");
  });

  function updatePreview() {
    var local = (localInput.value || "").trim().toLowerCase() || "noreply";
    var domain = domainSel ? domainSel.value : DOMAINS[0];
    fromPreview.textContent = "Will be sent as: " + local + "@" + domain;
  }
  localInput.addEventListener("input", updatePreview);
  if (domainSel) domainSel.addEventListener("change", updatePreview);
  updatePreview();

  function renderPreview() {
    if (htmlBox.checked) {
      previewFrame.hidden = false;
      previewText.hidden = true;
      previewFrame.srcdoc = messageBox.value || "<p>(empty message)</p>";
    } else {
      previewFrame.hidden = true;
      previewText.hidden = false;
      previewText.textContent = messageBox.value || "(empty message)";
    }
  }

  function exitPreview() {
    previewing = false;
    previewFrame.hidden = true;
    previewText.hidden = true;
    messageBox.hidden = false;
    previewBtn.textContent = "Preview";
  }

  htmlBox.addEventListener("change", function () {
    msgLabel.textContent = htmlBox.checked ? "Message (HTML)" : "Message";
    if (previewing) renderPreview();
  });

  previewBtn.addEventListener("click", function () {
    if (previewing) {
      exitPreview();
    } else {
      previewing = true;
      renderPreview();
      messageBox.hidden = true;
      previewBtn.textContent = "Back to editing";
    }
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (picked.length > ATT_MAX_FILES || pickedBytes() > ATT_MAX_TOTAL) {
      statusBox.textContent = "Error: the attachment list breaks the caps — remove a file and try again.";
      statusBox.className = "status error";
      return;
    }
    btn.disabled = true;
    btn.textContent = "Sending...";
    statusBox.textContent = "";
    statusBox.className = "status";

    var fd = new FormData();
    fd.append("to", document.getElementById("to").value);
    fd.append("cc", document.getElementById("cc").value);
    fd.append("bcc", document.getElementById("bcc").value);
    fd.append("from_name", document.getElementById("from_name").value);
    fd.append("from_local", localInput.value);
    fd.append("reply_to", document.getElementById("reply_to").value);
    fd.append("subject", document.getElementById("subject").value);
    if (domainSel) fd.append("from_domain", domainSel.value);
    fd.append(htmlBox.checked ? "html" : "text", messageBox.value);
    for (var i = 0; i < picked.length; i++) {
      fd.append("attachments", picked[i]);
    }

    fetch("/send", {
      method: "POST",
      headers: { "X-Auth-Token": TOKEN },
      body: fd
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data.success) {
          var msg = "Email sent!" + (data.id ? " (Resend ID: " + data.id + ")" : "");
          if (data.saved === false) msg += " — warning: could not save to history.";
          if (data.attachments_saved === false) msg += " — warning: attachments could not be saved to history.";
          statusBox.textContent = msg;
          statusBox.className = "status success";
          form.reset();
          picked = [];
          attInput.value = "";
          showPicked("");
          updatePreview();
          msgLabel.textContent = "Message";
          exitPreview();
        } else {
          statusBox.textContent = "Error: " + (data.error || "Unknown error");
          statusBox.className = "status error";
        }
      })
      .catch(function (err) {
        statusBox.textContent = "Error: " + err.message;
        statusBox.className = "status error";
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = "Send email";
      });
  });
})();
</script>`;

  return renderShell({
    title: "Outbox",
    active: "compose",
    token: token,
    domains: domains,
    showLogout: showLogout,
    width: "narrow",
    content: content,
    extraCss: extraCss,
    script: script,
  });
}

function renderDomainsPage(domains, token, showLogout) {
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");

  const listHtml = domains.length
    ? domains
        .map(function (d, i) {
          const isDefault = i === 0;
          return (
            '<div class="domain-row">' +
            '<div class="domain-left">' +
            '<span class="domain-name">' + escapeHtml(d) + "</span>" +
            (isDefault ? '<span class="default-pill">default</span>' : "") +
            "</div>" +
            '<div class="domain-actions">' +
            (isDefault
              ? ""
              : '<button type="button" class="btn ghost small default-btn" data-domain="' +
                escapeHtml(d) + '">Set default</button>') +
            '<button type="button" class="btn ghost small remove-btn" data-domain="' +
            escapeHtml(d) + '">Remove</button>' +
            "</div>" +
            "</div>"
          );
        })
        .join("")
    : '<p class="muted">No domains yet — add the first one above.</p>';

  const content = `
<div class="page-head">
  <h1>Domains</h1>
</div>
<div class="card">
  <form id="add-form">
    <label for="add-domain">Add a domain</label>
    <div class="add-row">
      <input id="add-domain" type="text" placeholder="example.com" autocomplete="off" spellcheck="false">
      <button id="add-btn" type="submit" class="btn">Add</button>
    </div>
  </form>
  <div class="status" id="status"></div>
  <div class="domain-list">${listHtml}</div>
</div>`;

  const extraCss = `
  .add-row { display: flex; gap: 8px; }
  .add-row input { flex: 1; min-width: 0; }
  .add-row .btn { flex: none; }
  .domain-list { margin-top: 18px; }
  .domain-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }
  .domain-row:last-child { border-bottom: none; }
  .domain-left { display: flex; align-items: center; gap: 10px; min-width: 0; flex-wrap: wrap; }
  .domain-name { font-weight: 600; font-size: 14px; overflow-wrap: anywhere; }
  .domain-actions { display: flex; gap: 8px; flex: none; flex-wrap: wrap; }
  .default-pill {
    border: 1px solid var(--border-strong);
    color: var(--muted);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 999px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
`;

  const script = `<script>
(function () {
  var TOKEN = ${tokenJson};
  var form = document.getElementById("add-form");
  var input = document.getElementById("add-domain");
  var addBtn = document.getElementById("add-btn");
  var statusBox = document.getElementById("status");

  function setStatus(msg, cls) {
    statusBox.textContent = msg;
    statusBox.className = "status" + (cls ? " " + cls : "");
  }

  function post(path, payload, btn, onDone) {
    if (btn) btn.disabled = true;
    fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auth-Token": TOKEN },
      body: JSON.stringify(payload)
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (btn) btn.disabled = false;
        if (data.success) { onDone(); return; }
        setStatus("Error: " + (data.error || "Unknown error"), "error");
      })
      .catch(function (err) {
        if (btn) btn.disabled = false;
        setStatus("Error: " + err.message, "error");
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var domain = (input.value || "").trim();
    if (!domain) return;
    post("/domains/add", { domain: domain }, addBtn, function () { location.reload(); });
  });

  function wire(sel, path) {
    var btns = document.querySelectorAll(sel);
    for (var i = 0; i < btns.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          post(path, { domain: btn.getAttribute("data-domain") }, btn, function () {
            location.reload();
          });
        });
      })(btns[i]);
    }
  }
  wire(".remove-btn", "/domains/remove");
  wire(".default-btn", "/domains/default");
})();
</script>`;

  return renderShell({
    title: "Domains — Outbox",
    active: "domains",
    token: token,
    domains: domains,
    showLogout: showLogout,
    width: "narrow",
    content: content,
    extraCss: extraCss,
    script: script,
  });
}

// The /sent page: import and export sit together in the page head, the
// search form sits at the top of the card, then the message list. Plain
// HTML only — no inline script runs on this page.
// view: { q, status, filtered, totalMatches, notice, importError } — the
// last two carry the outcome shown after POST /sent/import.
function renderSentPage(rows, token, domains, showLogout, view) {
  const v = view || { q: "", status: "", filtered: false, totalMatches: null, notice: null, importError: "" };
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";

  const items = rows.length
    ? rows
        .map(function (r) {
          const ok = r.status === "sent";
          const isHtml = r.content_type === "html";
          const attCount = Number(r.attachment_count || 0);
          const attPairs = [];
          if (r.attachment_files) {
            const parts = String(r.attachment_files).split("");
            for (let i = 0; i + 2 < parts.length; i += 3) {
              attPairs.push({ id: parts[i], name: parts[i + 1], size: Number(parts[i + 2]) });
            }
          }
          const attLine = attPairs.length
            ? '<p><strong>Attachments:</strong> ' +
              attPairs
                .map(function (a) {
                  return '<a href="/attachments/' + encodeURIComponent(a.id) + tokenParam + '">' +
                    escapeHtml(a.name) + "</a> <span class=\"muted\">(" + humanBytes(a.size) + ")</span>";
                })
                .join(", ") +
              "</p>"
            : "";
          return (
            '<details class="msg">' +
            "<summary>" +
            '<span class="dot ' + (ok ? "ok" : "fail") + '"></span>' +
            "<strong>" + escapeHtml(r.subject || "") + "</strong>" +
            '<span class="meta">to ' + escapeHtml(r.to_addresses || "") +
            (isHtml ? " &middot; HTML" : "") +
            (attCount ? " &middot; " + attCount + " attachment" + (attCount === 1 ? "" : "s") : "") +
            " &middot; " + escapeHtml(r.created_at || "") + " UTC</span>" +
            "</summary>" +
            '<div class="msg-body">' +
            "<p><strong>From:</strong> " + escapeHtml(r.from_address || "") + "</p>" +
            (r.cc_addresses ? "<p><strong>Cc:</strong> " + escapeHtml(r.cc_addresses) + "</p>" : "") +
            (r.bcc_addresses ? "<p><strong>Bcc:</strong> " + escapeHtml(r.bcc_addresses) + "</p>" : "") +
            (r.reply_to ? "<p><strong>Reply-To:</strong> " + escapeHtml(r.reply_to) + "</p>" : "") +
            (r.resend_id ? "<p><strong>Resend ID:</strong> " + escapeHtml(r.resend_id) + "</p>" : "") +
            (r.delivery_status ? "<p><strong>Delivery:</strong> " + escapeHtml(r.delivery_status) + "</p>" : "") +
            attLine +
            (!ok && r.error ? '<p class="err"><strong>Error:</strong> ' + escapeHtml(r.error) + "</p>" : "") +
            (isHtml
              ? '<iframe class="preview" sandbox="" srcdoc="' + escapeHtml(r.body || "") + '"></iframe>' +
                '<details class="src"><summary>Source</summary>' +
                '<pre class="body">' + escapeHtml(r.body || "") + "</pre></details>"
              : '<pre class="body">' + escapeHtml(r.body || "") + "</pre>") +
            "</div></details>"
          );
        })
        .join("")
    : '<p class="muted">' + (v.filtered ? "No messages match this search." : "No messages sent yet.") + "</p>";

  const matches = v.totalMatches === null ? rows.length : v.totalMatches;
  const sub = v.filtered
    ? "Found " + matches + " matching message" + (matches === 1 ? "" : "s") +
      (matches > rows.length ? " — showing the newest 200." : ".")
    : "Last " + rows.length + " message" + (rows.length === 1 ? "" : "s") + " (most recent first).";

  // Import lives right beside Export: the file input is visually hidden but
  // stays keyboard-reachable (the button keeps the focus outline via
  // :focus-within); clicking "Import CSV" opens the picker directly and
  // picking a file submits the form at once — a single inline onchange
  // attribute, so this page still ships no script block. The action carries
  // ?token= because a multipart upload cannot send the X-Auth-Token header.
  const importForm =
    '<form class="import-form" method="post" action="/sent/import' + tokenParam + '" ' +
    'enctype="multipart/form-data">' +
    '<input id="import-csv" type="file" name="csv" accept=".csv,text/csv" ' +
    'aria-label="CSV file to import" ' +
    'onchange="if (this.files.length) this.form.submit()">' +
    '<label for="import-csv" class="btn ghost small" ' +
    'title="Import a CSV in the export format — identical records are skipped, differing rows are added.">' +
    "Import CSV</label>" +
    "</form>";

  const filterForm =
    '<form class="filter-form" method="GET" action="/sent">' +
    (token ? '<input type="hidden" name="token" value="' + escapeHtml(token) + '">' : "") +
    '<input type="search" name="q" value="' + escapeHtml(v.q) + '" placeholder="Search subject, body, addresses, error..." aria-label="Search sent messages">' +
    '<select name="status" aria-label="Filter by status">' +
    '<option value=""' + (v.status === "" ? " selected" : "") + ">All</option>" +
    '<option value="sent"' + (v.status === "sent" ? " selected" : "") + ">Sent</option>" +
    '<option value="failed"' + (v.status === "failed" ? " selected" : "") + ">Failed</option>" +
    "</select>" +
    '<button type="submit" class="btn small">Search</button>' +
    (v.filtered ? '<a class="btn ghost small" href="/sent' + tokenParam + '">Clear</a>' : "") +
    "</form>";

  let banner = "";
  if (v.importError) {
    banner =
      '<div class="import-notice bad"><strong>Import failed:</strong> ' +
      escapeHtml(v.importError) + "</div>";
  } else if (v.notice) {
    const n = v.notice;
    const parts = [];
    if (n.imported) parts.push(n.imported + " added");
    if (n.skipped) parts.push(n.skipped + " duplicate" + (n.skipped === 1 ? "" : "s") + " skipped");
    if (n.invalid) parts.push(n.invalid + " invalid");
    banner =
      '<div class="import-notice' + (n.invalid ? " bad" : "") + '"><strong>Import finished:</strong> ' +
      escapeHtml(parts.length ? parts.join(", ") : "nothing to add") + "." +
      (n.errs ? '<div class="reasons">' + escapeHtml(n.errs) + "</div>" : "") +
      "</div>";
  }

  const content =
    '<div class="page-head"><div class="head-row">' +
    '<div><h1>Sent messages</h1><p class="sub">' + sub + "</p></div>" +
    '<div class="head-actions">' +
    importForm +
    '<a class="btn ghost small" href="/sent/export' + tokenParam + '">Export CSV</a>' +
    "</div></div></div>" +
    '<div class="card">' +
    banner +
    filterForm +
    items +
    "</div>";

  const extraCss = `
  .head-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .head-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .import-form { display: flex; align-items: center; gap: 0; }
  .import-form input[type="file"] {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
    border: 0;
  }
  .import-form label { display: inline-block; margin: 0; }
  .import-form:focus-within label { outline: 2px solid var(--focus); outline-offset: 2px; }
  .msg-body a { color: var(--fg); font-weight: 600; }
  .msg-body a:hover { color: var(--muted); }
  .filter-form { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 0 0 16px; }
  .filter-form input[type="search"] { flex: 1 1 200px; min-width: 0; }
  .filter-form select { flex: 0 0 auto; width: auto; cursor: pointer; }
  .filter-form .btn { flex: none; }
  .import-notice {
    border: 1px solid var(--ok);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13.5px;
    margin: 0 0 16px;
  }
  .import-notice.bad { border-color: var(--err); }
  .import-notice .reasons { color: var(--muted); font-size: 12.5px; margin-top: 4px; overflow-wrap: anywhere; }
  .msg { border-bottom: 1px solid var(--border); padding: 12px 0; }
  .msg:last-of-type { border-bottom: none; }
  .msg summary { cursor: pointer; list-style: none; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .msg summary::-webkit-details-marker { display: none; }
  .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; align-self: center; }
  .dot.ok { background: var(--ok); }
  .dot.fail { background: var(--err); }
  .meta { color: var(--muted); font-size: 12.5px; width: 100%; margin-left: 17px; }
  .msg-body { margin: 12px 0 4px 17px; font-size: 14px; }
  .msg-body p { margin: 4px 0; }
  .msg-body .err { color: var(--err); }
  /* Rendered email previews stay white in both themes (see compose page). */
  iframe.preview {
    width: 100%;
    height: 240px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #ffffff;
    margin: 10px 0 0;
    display: block;
  }
  details.src { margin-top: 10px; }
  details.src summary { cursor: pointer; font-size: 13px; color: var(--muted); user-select: none; }
  details.src summary:hover { color: var(--fg); }
  pre.body {
    white-space: pre-wrap;
    word-wrap: break-word;
    font: inherit;
    background: var(--code-bg);
    border: 1px solid var(--code-border);
    border-radius: 8px;
    padding: 12px;
    margin: 10px 0 0;
  }
`;

  return renderShell({
    title: "Sent Messages — Outbox",
    active: "sent",
    token: token,
    domains: domains,
    showLogout: showLogout,
    content: content,
    extraCss: extraCss,
    script: "",
  });
}

function renderUsagePage(stats, token, domains, showLogout, storage) {
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");

  const isResend = stats.source === "resend";

  const cards = (stats.cards || [])
    .map(function (c) {
      return (
        '<div class="stat"><div class="num' + (c.bad ? " bad" : "") + '">' + c.num +
        '</div><div class="lbl">' + escapeHtml(c.lbl) + "</div></div>"
      );
    })
    .join("");

  const maxCount = Math.max.apply(
    null,
    [1].concat((stats.perDay || []).map(function (d) { return d.count; }))
  );
  const bars = (stats.perDay || [])
    .map(function (d) {
      const totalH = Math.max(2, Math.round((d.count / maxCount) * 90));
      const failH = d.count > 0 ? Math.round((d.failed / d.count) * totalH) : 0;
      const tip = d.count + " sent" + (d.failed ? ", " + d.failed + " failed" : "");
      return (
        '<div class="bar-col" title="' + escapeHtml(tip) + '">' +
        '<span class="bar-num">' + d.count + "</span>" +
        '<div class="bar" style="height:' + totalH + 'px">' +
        (failH > 0 ? '<div class="bar-fail" style="height:' + Math.max(failH, 3) + 'px"></div>' : "") +
        "</div>" +
        '<span class="bar-label">' + escapeHtml(d.day.slice(5)) + "</span></div>"
      );
    })
    .join("");

  const pillCls = { delivered: "ok", bounce: "fail", bounced: "fail", complained: "fail", rejected: "fail", deferred: "fail" };
  const pills = (stats.delivery || []).length
    ? (stats.delivery || [])
        .map(function (d) {
          return (
            '<span class="pill ' + (pillCls[d.s] || "") + '">' +
            escapeHtml(d.s) + " &middot; " + d.c + "</span>"
          );
        })
        .join("")
    : '<span class="muted">No delivery data available yet.</span>';

  const topRec = (stats.topRecipients || []).length
    ? '<ol class="top">' +
      (stats.topRecipients || [])
        .map(function (r) {
          return "<li><span>" + escapeHtml(r[0]) + '</span><span class="muted">' + r[1] + "</span></li>";
        })
        .join("") +
      "</ol>"
    : '<span class="muted">No recipients yet.</span>';

  const sub = isResend
    ? "Live from Resend"
    : "Local database stats (Resend was unreachable).";

  // Storage meter: how much of the D1 database is still free. The used
  // number is the real file size when D1 answers the introspection
  // pragmas, otherwise the data estimate (attachments + message text).
  // The limit it divides by is whatever was saved in the Size limit field
  // below — stored in the settings table, not a variable.
  let storageCard = "";
  if (storage) {
    const used = storage.dbBytes !== null ? storage.dbBytes : storage.attachmentBytes + storage.textBytes;
    const pct = Math.max(0, Math.min(100, (used / storage.capBytes) * 100));
    const pctText = pct >= 10 ? Math.round(pct) + "%" : pct.toFixed(1) + "%";
    const free = Math.max(0, storage.capBytes - used);
    const source = storage.dbBytes !== null
      ? "the actual database file"
      : "attachment bytes (" + humanBytes(storage.attachmentBytes) + ") plus message text (" + humanBytes(storage.textBytes) + ")";
    const capMb = Math.round(storage.capBytes / 1048576);
    storageCard =
      '<div class="card storage-card">' +
      "<h2>Database storage</h2>" +
      '<div class="storage-line"><strong>' + humanBytes(used) + " used</strong> (" + pctText + ") of " +
      humanBytes(storage.capBytes) + " — <strong>" + humanBytes(free) + " free</strong></div>" +
      '<div class="meter" role="img" aria-label="Database ' + pctText + ' full">' +
      '<div class="meter-fill' + (pct >= 90 ? " bad" : "") + '" style="width:' + Math.max(pct, 0.5) + '%"></div></div>' +
      '<p class="muted">' + storage.files + " attachment" + (storage.files === 1 ? "" : "s") +
      " stored. Measured from " + source + ".</p>" +
      '<div class="cap-form">' +
      '<label for="db-cap">Size limit</label>' +
      '<div class="cap-row">' +
      '<input id="db-cap" type="text" inputmode="decimal" autocomplete="off" spellcheck="false"' +
      ' placeholder="e.g. 500 MB"' +
      (storage.capIsDefault ? "" : ' value="' + capMb + ' MB"') + ">" +
      '<button id="cap-btn" type="button" class="btn small">Save limit</button>' +
      "</div>" +
      '<p class="muted">The limit your D1 database has: 500 MB on the Free plan, 10 GB on Workers Paid. ' +
      'Accepts MB or GB ("500 MB", "10 GB"); a number alone is megabytes. Saving an empty field goes ' +
      "back to the default (" + humanBytes(DEFAULT_DB_CAP_BYTES) + ").</p>" +
      '<div class="status" id="cap-status"></div>' +
      "</div>" +
      "</div>";
  }

  const content =
    '<div class="page-head"><h1>API key usage</h1><p class="sub">' + sub + "</p></div>" +
    (stats.warning ? '<div class="warn">' + escapeHtml(stats.warning) + "</div>" : "") +
    (stats.note ? '<p class="muted">' + escapeHtml(stats.note) + "</p>" : "") +
    '<div class="stat-grid">' + cards + "</div>" +
    '<div class="card">' +
    "<h2>Last 14 days</h2>" +
    '<div class="chart-scroll"><div class="chart">' + bars + "</div></div>" +
    '<p class="muted">Hover a bar for details. Dates are MM-DD (UTC).</p>' +
    "</div>" +
    '<div class="grid-2">' +
    '<div class="card">' +
    "<h2>Delivery status</h2>" +
    "<div>" + pills + "</div>" +
    '<div class="sync-row">' +
    '<button id="refresh-btn" type="button" class="btn small">Refresh from Resend</button>' +
    "</div>" +
    "</div>" +
    '<div class="card">' +
    "<h2>Top recipients</h2>" +
    topRec +
    "</div>" +
    "</div>" +
    storageCard;

  const extraCss = `
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
  }
  .stat {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 12px;
    text-align: center;
    background: var(--card);
    box-shadow: var(--shadow);
  }
  .stat .num { font-size: 24px; font-weight: 700; }
  .stat .num.bad { color: var(--err); }
  .stat .lbl { font-size: 11.5px; color: var(--muted); margin-top: 2px; }

  .chart-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .chart { display: flex; gap: 6px; align-items: flex-end; margin-top: 8px; min-width: 480px; }
  .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; min-width: 0; }
  .bar-num { font-size: 10px; color: var(--muted); margin-bottom: 2px; }
  .bar { position: relative; width: 100%; max-width: 30px; background: var(--chart-bar); border-radius: 3px 3px 0 0; }
  .bar-fail { position: absolute; bottom: 0; left: 0; width: 100%; background: var(--err); }
  .bar-label { font-size: 10px; color: var(--muted); margin-top: 4px; }

  .pill {
    display: inline-block;
    padding: 4px 10px;
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    font-size: 12.5px;
    margin: 0 6px 6px 0;
  }
  .pill.ok { border-color: var(--ok); color: var(--ok); }
  .pill.fail { border-color: var(--err); color: var(--err); }

  ol.top { margin: 0; padding: 0; list-style: none; counter-reset: rec; }
  ol.top li {
    counter-increment: rec;
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 14px;
  }
  ol.top li:last-child { border-bottom: none; }
  ol.top li::before { content: counter(rec); color: var(--muted); font-size: 12px; min-width: 14px; padding-top: 2px; }

  .sync-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 12px; }

  .storage-card { margin-top: 16px; }
  .storage-line { font-size: 14px; margin: 2px 0 10px; }
  .meter { height: 8px; background: var(--border); border-radius: 999px; overflow: hidden; }
  .meter-fill { height: 100%; background: var(--chart-bar); border-radius: 999px; }
  .meter-fill.bad { background: var(--err); }

  .cap-form { margin-top: 16px; }
  .cap-form label { margin: 0 0 6px; }
  .cap-row { display: flex; gap: 8px; }
  .cap-row input { flex: 1; min-width: 0; }
  .cap-row .btn { flex: none; }
  .cap-form .status { margin-top: 8px; min-height: 0; }
`;

  const script = `<script>
(function () {
  var TOKEN = ${tokenJson};
  var btn = document.getElementById("refresh-btn");
  btn.addEventListener("click", function () {
    btn.disabled = true;
    btn.textContent = "Refreshing...";
    fetch("/usage/sync", { method: "POST", headers: { "X-Auth-Token": TOKEN } })
      .then(function () { location.reload(); })
      .catch(function () { location.reload(); });
  });

  // The Size limit field: saving stores the value in the settings table
  // (as megabytes) and reloads so the meter re-renders with it; saving an
  // empty field removes the stored limit.
  var capInput = document.getElementById("db-cap");
  var capBtn = document.getElementById("cap-btn");
  var capStatus = document.getElementById("cap-status");
  if (capBtn && capInput) {
    capBtn.addEventListener("click", saveCap);
    capInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); saveCap(); }
    });
  }

  function saveCap() {
    capBtn.disabled = true;
    capBtn.textContent = "Saving...";
    capStatus.textContent = "";
    capStatus.className = "status";
    fetch("/usage/cap", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auth-Token": TOKEN },
      body: JSON.stringify({ cap: capInput.value })
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data.success) { location.reload(); return; }
        capBtn.disabled = false;
        capBtn.textContent = "Save limit";
        capStatus.textContent = "Error: " + (data.error || "Unknown error");
        capStatus.className = "status error";
      })
      .catch(function (err) {
        capBtn.disabled = false;
        capBtn.textContent = "Save limit";
        capStatus.textContent = "Error: " + err.message;
        capStatus.className = "status error";
      });
  }
})();
</script>`;

  return renderShell({
    title: "API Usage — Outbox",
    active: "usage",
    token: token,
    domains: domains,
    showLogout: showLogout,
    width: "wide",
    content: content,
    extraCss: extraCss,
    script: script,
  });
}
