const RESEND_ENDPOINT = "https://api.resend.com/emails";
const RESEND_LIST_LIMIT = 100;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const MAX_RECIPIENTS = 50;

// PASSWORD login sessions: 30-day signed cookies.
const SESSION_MAX_AGE_S = 30 * 24 * 60 * 60;
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_S * 1000;
const LOGIN_FAIL_DELAY_MS = 500;

// CSV import: the 14 columns /sent/export writes are the only header
// /sent/import accepts, and uploads are capped before they are read.
const IMPORT_COLUMNS = [
  "id", "date", "status", "delivery_status", "resend_id", "from", "to",
  "cc", "bcc", "reply_to", "subject", "content_type", "body", "error",
];
const IMPORT_MAX_MB = 25;
const IMPORT_MAX_BYTES = IMPORT_MAX_MB * 1024 * 1024;

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

// The other half of csvField: parses a CSV string into rows of fields.
// Quoted fields may contain commas, doubled quotes and line breaks; both
// CRLF and LF end a record; a UTF-8 BOM, if present, is stripped.
function parseCsv(text) {
  const s = String(text || "").replace(/^\uFEFF/, "");
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field); field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(field); field = "";
      rows.push(row); row = [];
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
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
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
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

    // Sent-messages history
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

      // Search + filter. ?q= matches across the whole archive, ?status= is
      // "sent" or "failed"; with neither present the query is exactly the
      // old "newest 200". The pattern is always bound, never string-built,
      // and % _ \ inside the search text are escaped so they stay literal
      // (LIKE is case-insensitive for ASCII letters).
      const q = String(url.searchParams.get("q") || "").trim();
      const statusParam = String(url.searchParams.get("status") || "").trim();
      const status =
        statusParam === "sent" || statusParam === "failed" ? statusParam : "";
      const filtered = q !== "" || status !== "";

      let where = "";
      const binds = [];
      if (filtered) {
        const clauses = [];
        if (q !== "") {
          const pattern =
            "%" + q.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_") + "%";
          const likeCols = [
            "subject", "body", "to_addresses", "cc_addresses", "bcc_addresses",
            "from_address", "reply_to", "resend_id", "error",
          ];
          clauses.push(
            "(" + likeCols.map(function (c) { return c + " LIKE ? ESCAPE '\\'"; }).join(" OR ") + ")"
          );
          likeCols.forEach(function () { binds.push(pattern); });
        }
        if (status !== "") {
          clauses.push("status = ?");
          binds.push(status);
        }
        where = " WHERE " + clauses.join(" AND ");
      }

      let rows = [];
      let domains = [];
      let totalMatches = null;
      try {
        // History and the domain list are independent — read both at once
        // (plus the match count when a filter is active).
        const rowsSql = "SELECT * FROM emails" + where + " ORDER BY id DESC LIMIT 200";
        const reads = [
          binds.length
            ? env.DB.prepare(rowsSql).bind(...binds).all()
            : env.DB.prepare(rowsSql).all(),
          getDomains(env),
        ];
        if (filtered) {
          const countSql = "SELECT COUNT(*) AS c FROM emails" + where;
          reads.push(
            binds.length
              ? env.DB.prepare(countSql).bind(...binds).first()
              : env.DB.prepare(countSql).first()
          );
        }
        const settled = await Promise.all(reads);
        rows = settled[0].results || [];
        domains = settled[1];
        totalMatches = filtered && settled[2] ? Number(settled[2].c || 0) : null;
      } catch (err) {
        return new Response("Failed to read from D1: " + err.message, { status: 500 });
      }

      return new Response(
        renderSentPage(rows, token, domains, showLogout, {
          q: q,
          status: status,
          filtered: filtered,
          totalMatches: totalMatches,
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

    // Import sent emails from a CSV in the exact format /sent/export
    // writes. A plain HTML form POST (multipart): the token rides in the
    // action URL, since a file upload cannot set the X-Auth-Token header.
    if (request.method === "POST" && url.pathname === "/sent/import") {
      return handleImport(request, env, url, showLogout);
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

      return new Response(renderUsagePage(stats, token, domains, showLogout), {
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

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Request body must be valid JSON." }, 400);
  }

  const recipients = splitAddresses(body.to);
  const cc = splitAddresses(body.cc);
  const bcc = splitAddresses(body.bcc);
  const subject = String(body.subject || "").trim();
  const text = String(body.text || "").trim();
  const html = String(body.html || "").trim();
  const replyTo = String(body.reply_to || "").trim();
  const fromName = String(body.from_name || "").trim().replace(/["<>]/g, "");
  const fromLocal =
    String(body.from_local || "noreply").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "") ||
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

  // The sending domain must be on the stored list; the first entry is the
  // default. One DB read, only for valid payloads.
  const allowedDomains = await getDomains(env);
  if (allowedDomains.length === 0) {
    return json(
      { success: false, error: "No sending domains are configured — add one on the Domains page." },
      400
    );
  }
  const fromDomain = String(body.from_domain || allowedDomains[0]).trim().toLowerCase();
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

  await ensureSchema(env);

  // What gets archived: the HTML part when present, otherwise the text.
  const storedBody = html || text;
  const contentType = html ? "html" : "text";

  let res;
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
    await logEmail(env, null, from, recipients, cc, bcc, replyTo, subject,
      storedBody, contentType, "failed", "Could not reach Resend: " + err.message);
    return json({ success: false, error: "Could not reach Resend: " + err.message }, 502);
  }

  const data = await res.json().catch(() => ({}));

  if (res.ok) {
    const saved = await logEmail(env, data.id || null, from, recipients, cc, bcc, replyTo,
      subject, storedBody, contentType, "sent", null);
    return json({ success: true, id: data.id || null, saved: saved });
  }

  const errMsg = data.message || "Resend returned HTTP " + res.status + ".";
  await logEmail(env, null, from, recipients, cc, bcc, replyTo, subject,
    storedBody, contentType, "failed", errMsg);
  return json({ success: false, error: errMsg }, 502);
}

// Writes the message into D1. Returns false (without throwing) if the
// database is unavailable, so a logging problem never breaks the send.
async function logEmail(env, resendId, from, recipients, cc, bcc, replyTo, subject, body, contentType, status, error) {
  if (!env.DB) return false;
  await ensureSchema(env);
  try {
    await env.DB.prepare(
      "INSERT INTO emails (resend_id, from_address, to_addresses, cc_addresses, bcc_addresses, reply_to, subject, body, content_type, status, error) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(resendId, from, recipients.join(", "),
        cc && cc.length ? cc.join(", ") : null,
        bcc && bcc.length ? bcc.join(", ") : null,
        replyTo || null, subject, body, contentType, status, error)
      .run();
    return true;
  } catch {
    return false;
  }
}

// --- CSV import (POST /sent/import) --------------------------------------
// Accepts a file in the exact format /sent/export writes and stores only
// rows that are not already present: same id, same Resend ID, or — for
// rows without a Resend ID — same full content. Identical rows inside the
// file itself collapse to the first copy. Rows are skipped, never updated;
// nothing is re-sent and Resend is never called.
async function handleImport(request, env, url, showLogout) {
  // POST auth like the other endpoints, plus the ?token= from the form's
  // action URL — a multipart upload cannot set the X-Auth-Token header.
  const token = url.searchParams.get("token") || "";
  const authed =
    (await isAuthorized(request, env)) ||
    (!!env.AUTH_TOKEN &&
      (await constantTimeEqual(token, env.AUTH_TOKEN)));
  if (!authed) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
  if (!env.DB) {
    return new Response("No D1 database is bound as DB.", {
      status: 500,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  await ensureSchema(env);

  const renderResult = async function (r, status) {
    return new Response(
      renderImportResult(r, token, await getDomains(env), showLogout),
      {
        status: status || 200,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      }
    );
  };
  const refuse = function (message, status) {
    return renderResult({ error: message }, status);
  };

  // Cheap size gate on the declared upload size, before the body is read.
  const declared = parseInt(request.headers.get("content-length") || "0", 10);
  if (declared > IMPORT_MAX_BYTES + 4096) {
    return refuse("That upload is too large (over " + IMPORT_MAX_MB + " MB) — nothing was imported.", 400);
  }

  let form = null;
  try {
    form = await request.formData();
  } catch {}
  const file = form ? form.get("csv") : null;
  if (!file || typeof file === "string") {
    return refuse("No file was uploaded — choose a CSV exported from the Sent page.", 400);
  }
  if (file.size > IMPORT_MAX_BYTES) {
    return refuse("That file is too large (over " + IMPORT_MAX_MB + " MB) — nothing was imported.", 400);
  }

  const table = parseCsv(await file.text());
  const records = table.filter(function (r) {
    return r.length > 1 || (r.length === 1 && r[0].trim() !== "");
  });
  if (records.length < 2) {
    return refuse("That file has no data rows — nothing was imported.", 400);
  }

  // The header must name the same 14 columns the export writes, in any
  // order; anything else is refused before a single row is written.
  const header = records[0].map(function (h) { return h.trim().toLowerCase(); });
  const missing = IMPORT_COLUMNS.filter(function (name) { return header.indexOf(name) === -1; });
  if (missing.length > 0) {
    return refuse(
      "The header row does not match the export format — missing column(s): " +
        missing.join(", ") + ".",
      400
    );
  }
  const col = {};
  IMPORT_COLUMNS.forEach(function (name) { col[name] = header.indexOf(name); });

  // Row-by-row validation: status is the one hard rule. Everything else is
  // stored as it arrives.
  const candidates = [];
  const invalid = [];
  for (let i = 1; i < records.length; i++) {
    const rec = records[i];
    const cell = function (name) {
      const v = rec[col[name]];
      return v === undefined ? "" : String(v);
    };
    if (rec.length < header.length) {
      invalid.push("record " + (i + 1) + ": fewer fields than the header");
      continue;
    }
    const status = cell("status").trim().toLowerCase();
    if (status !== "sent" && status !== "failed") {
      invalid.push("record " + (i + 1) + ": status must be sent or failed");
      continue;
    }
    const idRaw = cell("id").trim();
    candidates.push({
      id: /^[0-9]+$/.test(idRaw) ? parseInt(idRaw, 10) : null,
      resend_id: cell("resend_id").trim(),
      from_address: cell("from"),
      to_addresses: cell("to"),
      cc_addresses: cell("cc"),
      bcc_addresses: cell("bcc"),
      reply_to: cell("reply_to"),
      subject: cell("subject"),
      body: cell("body"),
      content_type: cell("content_type").trim().toLowerCase(),
      status: status,
      error: cell("error"),
      delivery_status: cell("delivery_status").trim().toLowerCase(),
      created_at: cell("date").trim(),
    });
  }

  // Duplicate check, pass 1 — bulk and cheap, chunked like reconciliation:
  // which ids and which Resend IDs already exist in the archive?
  const existingIds = new Set();
  const existingRids = new Set();
  try {
    const idVals = [];
    const ridVals = [];
    for (const c of candidates) {
      if (c.id !== null && idVals.indexOf(c.id) === -1) idVals.push(c.id);
      if (c.resend_id !== "" && ridVals.indexOf(c.resend_id) === -1) ridVals.push(c.resend_id);
    }
    for (let i = 0; i < idVals.length; i += 50) {
      const chunk = idVals.slice(i, i + 50);
      const r = await env.DB.prepare(
        "SELECT id FROM emails WHERE id IN (" + chunk.map(function () { return "?"; }).join(",") + ")"
      ).bind(...chunk).all();
      for (const row of r.results || []) existingIds.add(row.id);
    }
    for (let i = 0; i < ridVals.length; i += 50) {
      const chunk = ridVals.slice(i, i + 50);
      const r = await env.DB.prepare(
        "SELECT resend_id FROM emails WHERE resend_id IN (" + chunk.map(function () { return "?"; }).join(",") + ")"
      ).bind(...chunk).all();
      for (const row of r.results || []) existingRids.add(row.resend_id);
    }
  } catch (err) {
    return refuse("Could not read from D1: " + err.message, 500);
  }

  // Pass 2 — decide. A row is stored only when nothing identical exists:
  // not its id, not its Resend ID, and (when it has no Resend ID) not its
  // full content. The seen-sets carry the same rule across the rows of
  // this file, so a repeat inside the file collapses to the first copy.
  const seenIds = new Set();
  const seenRids = new Set();
  const seenContent = new Set();
  const toInsert = [];
  let skipped = 0;
  for (const c of candidates) {
    if (c.id !== null && (existingIds.has(c.id) || seenIds.has(c.id))) { skipped++; continue; }
    if (c.resend_id !== "" && (existingRids.has(c.resend_id) || seenRids.has(c.resend_id))) {
      skipped++; continue;
    }
    const key = importTupleKey(c);
    if (seenContent.has(key)) { skipped++; continue; }
    if (c.resend_id === "") {
      // No Resend ID to lean on — compare every archived field against the
      // archive. SQLite evaluates the cheap columns first, so bodies are
      // only read for rows that already match on everything else.
      try {
        const dup = await env.DB.prepare(
          "SELECT id FROM emails WHERE " +
            "IFNULL(created_at,'') = ? AND status = ? AND IFNULL(delivery_status,'') = ? " +
            "AND IFNULL(from_address,'') = ? AND IFNULL(to_addresses,'') = ? " +
            "AND IFNULL(cc_addresses,'') = ? AND IFNULL(bcc_addresses,'') = ? " +
            "AND IFNULL(reply_to,'') = ? AND subject = ? AND IFNULL(content_type,'') = ? " +
            "AND IFNULL(body,'') = ? AND IFNULL(error,'') = ? LIMIT 1"
        )
          .bind(
            c.created_at, c.status, c.delivery_status,
            c.from_address, c.to_addresses, c.cc_addresses,
            c.bcc_addresses, c.reply_to, c.subject,
            c.content_type, c.body, c.error
          )
          .first();
        if (dup) { skipped++; seenContent.add(key); continue; }
      } catch (err) {
        return refuse("Could not read from D1: " + err.message, 500);
      }
    }
    seenContent.add(key);
    if (c.resend_id !== "") seenRids.add(c.resend_id);
    if (c.id !== null) seenIds.add(c.id);
    toInsert.push(c);
  }

  // Pass 3 — store, in batches of 50. On a failure the rows already
  // committed stay; the report says exactly how far it got, and a re-run
  // skips everything that made it in.
  let stored = 0;
  try {
    for (let i = 0; i < toInsert.length; i += 50) {
      const batch = [];
      for (const c of toInsert.slice(i, i + 50)) {
        const cols = [];
        const vals = [];
        if (c.id !== null) { cols.push("id"); vals.push(c.id); }
        cols.push("resend_id", "from_address", "to_addresses", "cc_addresses",
          "bcc_addresses", "reply_to", "subject", "body", "content_type",
          "status", "error", "delivery_status");
        vals.push(
          c.resend_id || null, c.from_address, c.to_addresses,
          c.cc_addresses || null, c.bcc_addresses || null, c.reply_to || null,
          c.subject, c.body, c.content_type || null, c.status,
          c.error || null, c.delivery_status || null
        );
        if (c.created_at) { cols.push("created_at"); vals.push(c.created_at); }
        batch.push(
          env.DB.prepare(
            "INSERT INTO emails (" + cols.join(", ") + ") VALUES (" +
            cols.map(function () { return "?"; }).join(", ") + ")"
          ).bind(...vals)
        );
      }
      await env.DB.batch(batch);
      stored += batch.length;
    }
  } catch (err) {
    return renderResult({
      error:
        "The import stopped partway: " + err.message + " — " + stored + " of " +
        toInsert.length + " rows were written (only the non-duplicates). Fix the file and import it again; what is already in the archive is skipped automatically.",
    }, 500);
  }

  return renderResult({
    imported: stored,
    skipped: skipped,
    invalid: invalid,
  });
}

// Content fingerprint for the import's duplicate check: every archived
// field except the row id. Two records count as the same email when all
// of these match.
function importTupleKey(c) {
  return JSON.stringify([
    c.created_at, c.status, c.delivery_status,
    c.from_address, c.to_addresses, c.cc_addresses,
    c.bcc_addresses, c.reply_to, c.subject,
    c.content_type, c.body, c.error,
  ]);
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
    .map(function (k) { return [k, recip[k]]; })
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
    btn.disabled = true;
    btn.textContent = "Sending...";
    statusBox.textContent = "";
    statusBox.className = "status";

    var payload = {
      to: document.getElementById("to").value,
      cc: document.getElementById("cc").value,
      bcc: document.getElementById("bcc").value,
      from_name: document.getElementById("from_name").value,
      from_local: localInput.value,
      reply_to: document.getElementById("reply_to").value,
      subject: document.getElementById("subject").value
    };
    if (domainSel) payload.from_domain = domainSel.value;
    if (htmlBox.checked) {
      payload.html = messageBox.value;
    } else {
      payload.text = messageBox.value;
    }

    fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auth-Token": TOKEN },
      body: JSON.stringify(payload)
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data.success) {
          var msg = "Email sent!" + (data.id ? " (Resend ID: " + data.id + ")" : "");
          if (data.saved === false) msg += " — warning: could not save to history.";
          statusBox.textContent = msg;
          statusBox.className = "status success";
          form.reset();
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

function renderSentPage(rows, token, domains, showLogout, filter) {
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";
  const f = filter || { q: "", status: "", filtered: false, totalMatches: null };

  // Header line: the match count when searching/filtering, the old
  // "Last N messages" line otherwise.
  const sub = f.filtered && f.totalMatches !== null
    ? '<p class="sub">' + f.totalMatches + " match" + (f.totalMatches === 1 ? "" : "es") +
      " across the whole archive" +
      (f.totalMatches > rows.length ? " — showing the newest " + rows.length + "." : ".") +
      "</p>"
    : '<p class="sub">Last ' + rows.length + " message" + (rows.length === 1 ? "" : "s") +
      " (most recent first).</p>";

  // Plain-HTML GET form — the sent page stays script-free. The token rides
  // along in a hidden field so AUTH_TOKEN-only setups keep working.
  const filterForm =
    '<form class="filter" method="get" action="/sent">' +
    (token ? '<input type="hidden" name="token" value="' + escapeHtml(token) + '">' : "") +
    '<input type="search" name="q" value="' + escapeHtml(f.q) +
    '" placeholder="Search subject, body, addresses, error…" aria-label="Search sent messages">' +
    '<select name="status" aria-label="Filter by status">' +
    '<option value=""' + (f.status === "" ? " selected" : "") + ">All statuses</option>" +
    '<option value="sent"' + (f.status === "sent" ? " selected" : "") + ">Sent</option>" +
    '<option value="failed"' + (f.status === "failed" ? " selected" : "") + ">Failed</option>" +
    "</select>" +
    '<button type="submit" class="btn small">Search</button>' +
    (f.filtered ? '<a class="btn ghost small" href="/sent' + tokenParam + '">Clear</a>' : "") +
    "</form>";

  const items = rows.length
    ? rows
        .map(function (r) {
          const ok = r.status === "sent";
          const isHtml = r.content_type === "html";
          return (
            '<details class="msg">' +
            "<summary>" +
            '<span class="dot ' + (ok ? "ok" : "fail") + '"></span>' +
            "<strong>" + escapeHtml(r.subject || "") + "</strong>" +
            '<span class="meta">to ' + escapeHtml(r.to_addresses || "") +
            (isHtml ? " &middot; HTML" : "") +
            " &middot; " + escapeHtml(r.created_at || "") + " UTC</span>" +
            "</summary>" +
            '<div class="msg-body">' +
            "<p><strong>From:</strong> " + escapeHtml(r.from_address || "") + "</p>" +
            (r.cc_addresses ? "<p><strong>Cc:</strong> " + escapeHtml(r.cc_addresses) + "</p>" : "") +
            (r.bcc_addresses ? "<p><strong>Bcc:</strong> " + escapeHtml(r.bcc_addresses) + "</p>" : "") +
            (r.reply_to ? "<p><strong>Reply-To:</strong> " + escapeHtml(r.reply_to) + "</p>" : "") +
            (r.resend_id ? "<p><strong>Resend ID:</strong> " + escapeHtml(r.resend_id) + "</p>" : "") +
            (r.delivery_status ? "<p><strong>Delivery:</strong> " + escapeHtml(r.delivery_status) + "</p>" : "") +
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
    : '<p class="muted">' +
      (f.filtered ? "No messages match this search." : "No messages sent yet.") +
      "</p>";

  // Import: a collapsed plain-HTML form at the bottom of the page. No
  // script — the token rides in the action URL, since a multipart upload
  // cannot set the X-Auth-Token header.
  const importBox =
    '<details class="import-box">' +
    "<summary>Import from CSV</summary>" +
    '<div class="card import-card">' +
    '<p class="muted">Accepts a file in the exact format Export CSV writes. ' +
    "Rows already in the archive — by id, Resend ID or full content — and " +
    "identical rows inside the file are skipped, so importing never " +
    "duplicates anything. Nothing is re-sent.</p>" +
    '<form method="post" action="/sent/import' + tokenParam + '" enctype="multipart/form-data">' +
    '<input type="file" name="csv" accept=".csv,text/csv" required> ' +
    '<button type="submit" class="btn">Import</button>' +
    "</form>" +
    "</div></details>";

  const content = `
<div class="page-head">
  <div class="head-row">
    <div>
      <h1>Sent messages</h1>
      ${sub}
    </div>
    <a class="btn ghost small" href="/sent/export${tokenParam}">Export CSV</a>
  </div>
</div>
<div class="card">
 ${filterForm}
 ${items}
</div>
 ${importBox}`;

  const extraCss = `
  .filter { display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 18px; }
  .filter input[type="search"] { flex: 1 1 200px; width: auto; min-width: 0; }
  .filter select { flex: 0 0 auto; width: auto; }
  .head-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
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
  .import-box { margin-top: 16px; }
  .import-box summary { cursor: pointer; font-size: 13.5px; color: var(--muted); user-select: none; }
  .import-box summary:hover { color: var(--fg); }
  .import-card { margin-top: 10px; }
  .import-card form { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 12px; }
  .import-card input[type="file"] { flex: 1 1 240px; padding: 8px; font-size: 13px; }
  .import-card .btn { flex: none; }
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

// Result page for the CSV import: what was stored, what was skipped and
// why, or the reason nothing was imported at all. Plain HTML — no script.
function renderImportResult(r, token, domains, showLogout) {
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";
  let body;
  if (r.error) {
    body =
      '<div class="warn">' + escapeHtml(r.error) + "</div>" +
      '<p class="muted">Nothing else was changed.</p>';
  } else {
    const invalid = r.invalid || [];
    const notes = invalid
      .slice(0, 5)
      .map(function (n) { return "<li>" + escapeHtml(n) + "</li>"; })
      .join("");
    body =
      (r.imported > 0
        ? '<p class="ok-line">Imported ' + r.imported +
          " message" + (r.imported === 1 ? "" : "s") + ".</p>"
        : "<p>Nothing new to import — every valid row is already in the archive.</p>") +
      (r.skipped > 0
        ? "<p>Skipped " + r.skipped + " row" + (r.skipped === 1 ? "" : "s") +
          " already in the archive or repeated in the file — only one copy of each is kept.</p>"
        : "") +
      (invalid.length > 0
        ? "<p>Ignored " + invalid.length + " invalid row" + (invalid.length === 1 ? "" : "s") + ":</p>" +
          "<ul>" + notes + "</ul>" +
          (invalid.length > 5 ? '<p class="muted">…and ' + (invalid.length - 5) + " more.</p>" : "")
        : "");
  }
  const content =
    '<div class="page-head"><h1>Import sent messages</h1>' +
    '<p class="sub">From a CSV in the export format</p></div>' +
    '<div class="card">' + body +
    '<p class="back-link"><a class="btn ghost small" href="/sent' + tokenParam +
    '">Back to sent messages</a></p>' +
    "</div>";
  return renderShell({
    title: "Import — Outbox",
    active: "sent",
    token: token,
    domains: domains,
    showLogout: showLogout,
    width: "narrow",
    content: content,
    extraCss:
      ".ok-line { color: var(--ok); font-weight: 600; }\n" +
      ".back-link { margin-top: 18px; }",
  });
}

function renderUsagePage(stats, token, domains, showLogout) {
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
    "</div>";

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
