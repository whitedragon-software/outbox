const RESEND_ENDPOINT = "https://api.resend.com/emails";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_RECIPIENTS = 50;

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
      "reply_to TEXT, " +
      "subject TEXT NOT NULL, " +
      "body TEXT NOT NULL, " +
      "status TEXT NOT NULL DEFAULT 'sent', " +
      "error TEXT, " +
      "created_at TEXT NOT NULL DEFAULT (datetime('now'))" +
      ")"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_emails_created ON emails (created_at DESC)"
  ).run();
  // Migration for databases created before the usage feature: add the
  // delivery_status column. "Duplicate column" errors are expected once
  // it already exists, so we swallow that one.
  try {
    await env.DB.prepare("ALTER TABLE emails ADD COLUMN delivery_status TEXT").run();
  } catch (e) {
    if (!String(e.message || e).includes("duplicate column")) throw e;
  }
  schemaReady = true;
}

// --- Routing ------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // The email form
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      if (!env.RESEND_KEY || !env.DOMAIN1) {
        return new Response(
          "Worker is not configured. Set the RESEND_KEY and DOMAIN1 environment variables.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      const token = url.searchParams.get("token") || "";
      if (env.AUTH_TOKEN && token !== env.AUTH_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }

      return new Response(renderPage(env.DOMAIN1, token), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Sent-messages history
    if (request.method === "GET" && url.pathname === "/sent") {
      const token = url.searchParams.get("token") || "";
      if (env.AUTH_TOKEN && token !== env.AUTH_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }
      if (!env.DB) {
        return new Response(
          "No D1 database is bound as DB.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      await ensureSchema(env);

      let rows = [];
      try {
        const result = await env.DB.prepare(
          "SELECT * FROM emails ORDER BY id DESC LIMIT 200"
        ).all();
        rows = result.results || [];
      } catch (err) {
        return new Response("Failed to read from D1: " + err.message, { status: 500 });
      }

      return new Response(renderSentPage(rows, token), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Usage dashboard
    if (request.method === "GET" && url.pathname === "/usage") {
      const token = url.searchParams.get("token") || "";
      if (env.AUTH_TOKEN && token !== env.AUTH_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }
      if (!env.DB) {
        return new Response(
          "No D1 database is bound as DB.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      await ensureSchema(env);
      const stats = await getStats(env);

      return new Response(renderUsagePage(stats, token), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // Sync delivery statuses from Resend
    if (request.method === "POST" && url.pathname === "/usage/sync") {
      if (env.AUTH_TOKEN && request.headers.get("x-auth-token") !== env.AUTH_TOKEN) {
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

    // The send endpoint
    if (request.method === "POST" && url.pathname === "/send") {
      return handleSend(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

// --- Sending + automatic DB write ---------------------------------------
async function handleSend(request, env) {
  // Optional protection: only active if you set an AUTH_TOKEN variable
  if (env.AUTH_TOKEN && request.headers.get("x-auth-token") !== env.AUTH_TOKEN) {
    return json({ success: false, error: "Unauthorized." }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Request body must be valid JSON." }, 400);
  }

  const recipients = String(body.to || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const subject = String(body.subject || "").trim();
  const text = String(body.text || "").trim();
  const replyTo = String(body.reply_to || "").trim();
  const fromName = String(body.from_name || "").trim().replace(/["<>]/g, "");
  const fromLocal =
    String(body.from_local || "noreply").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "") ||
    "noreply";

  if (recipients.length === 0 || !recipients.every((e) => EMAIL_RE.test(e))) {
    return json({ success: false, error: "Please provide valid recipient email address(es)." }, 400);
  }
  if (recipients.length > MAX_RECIPIENTS) {
    return json({ success: false, error: "Too many recipients (max " + MAX_RECIPIENTS + ")." }, 400);
  }
  if (!subject) return json({ success: false, error: "Subject is required." }, 400);
  if (!text) return json({ success: false, error: "Message cannot be empty." }, 400);
  if (replyTo && !EMAIL_RE.test(replyTo)) {
    return json({ success: false, error: "Reply-To must be a valid email address." }, 400);
  }

  const from = fromName
    ? fromName + " <" + fromLocal + "@" + env.DOMAIN1 + ">"
    : fromLocal + "@" + env.DOMAIN1;

  const payload = { from, to: recipients, subject, text };
  if (replyTo) payload.reply_to = replyTo;

  await ensureSchema(env);

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
    await logEmail(env, null, from, recipients, replyTo, subject, text,
      "failed", "Could not reach Resend: " + err.message);
    return json({ success: false, error: "Could not reach Resend: " + err.message }, 502);
  }

  const data = await res.json().catch(() => ({}));

  if (res.ok) {
    const saved = await logEmail(env, data.id || null, from, recipients, replyTo,
      subject, text, "sent", null);
    return json({ success: true, id: data.id || null, saved: saved });
  }

  const errMsg = data.message || "Resend returned HTTP " + res.status + ".";
  await logEmail(env, null, from, recipients, replyTo, subject, text, "failed", errMsg);
  return json({ success: false, error: errMsg }, 502);
}

// Writes the message into D1. Returns false (without throwing) if the
// database is unavailable, so a logging problem never breaks the send.
async function logEmail(env, resendId, from, recipients, replyTo, subject, text, status, error) {
  if (!env.DB) return false;
  await ensureSchema(env);
  try {
    await env.DB.prepare(
      "INSERT INTO emails (resend_id, from_address, to_addresses, reply_to, subject, body, status, error) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(resendId, from, recipients.join(", "), replyTo || null, subject, text, status, error)
      .run();
    return true;
  } catch {
    return false;
  }
}

// --- Usage statistics ----------------------------------------------------
async function getStats(env) {
  const scalar = async (sql) => {
    try {
      const r = await env.DB.prepare(sql).first();
      return r && r.c ? r.c : 0;
    } catch {
      return 0;
    }
  };

  const total = await scalar("SELECT COUNT(*) AS c FROM emails");
  const sent = await scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'sent'");
  const failed = await scalar("SELECT COUNT(*) AS c FROM emails WHERE status = 'failed'");
  const last24h = await scalar(
    "SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-1 day')");
  const last7d = await scalar(
    "SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-7 days')");
  const last30d = await scalar(
    "SELECT COUNT(*) AS c FROM emails WHERE status = 'sent' AND created_at >= datetime('now', '-30 days')");

  // Per-day counts for the last 14 days (UTC), missing days filled with 0
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

  // Top recipients, counted in JS from the most recent 500 messages
  const counts = {};
  try {
    const r = await env.DB.prepare(
      "SELECT to_addresses FROM emails ORDER BY id DESC LIMIT 500"
    ).all();
    for (const row of r.results || []) {
      for (const addr of String(row.to_addresses || "").split(",")) {
        const a = addr.trim();
        if (a) counts[a] = (counts[a] || 0) + 1;
      }
    }
  } catch {}
  const topRecipients = Object.keys(counts)
    .map(function (k) { return [k, counts[k]]; })
    .sort(function (a, b) { return b[1] - a[1]; })
    .slice(0, 5);

  // Delivery status breakdown (populated by the sync button)
  let delivery = [];
  try {
    const r = await env.DB.prepare(
      "SELECT delivery_status AS s, COUNT(*) AS c " +
      "FROM emails WHERE delivery_status IS NOT NULL GROUP BY delivery_status ORDER BY c DESC"
    ).all();
    delivery = r.results || [];
  } catch {}

  return { total, sent, failed, last24h, last7d, last30d, perDay, topRecipients, delivery };
}

// Checks the 25 most recent sent emails against Resend's API and records
// their latest delivery event (delivered / bounced / complained / ...).
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
  for (const row of results) {
    try {
      const res = await fetch(
        "https://api.resend.com/emails/" + encodeURIComponent(row.resend_id),
        { headers: { Authorization: "Bearer " + env.RESEND_KEY } }
      );
      if (!res.ok) continue;
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
  }
  return { checked, byStatus };
}

// --- Pages --------------------------------------------------------------
function renderPage(domain, token) {
  const domainJson = JSON.stringify(domain).replace(/</g, "\\u003c");
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Send Email</title>
<style>
  * { box-sizing: border-box; }
  body {
    background: #ffffff;
    color: #1a1a1a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 40px 16px;
    display: flex;
    justify-content: center;
  }
  .card {
    width: 100%;
    max-width: 520px;
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 10px;
    padding: 32px;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #777; font-size: 14px; margin: 0 0 24px; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px; }
  input, textarea {
    width: 100%;
    padding: 10px 12px;
    font: inherit;
    font-size: 14px;
    border: 1px solid #ccc;
    border-radius: 6px;
    background: #fff;
    color: #1a1a1a;
  }
  input:focus, textarea:focus { outline: 2px solid #1a1a1a; outline-offset: -1px; border-color: #1a1a1a; }
  textarea { min-height: 140px; resize: vertical; }
  .hint { font-size: 12px; color: #888; margin-top: 4px; }
  button {
    margin-top: 20px;
    width: 100%;
    padding: 12px;
    font: inherit;
    font-size: 15px;
    font-weight: 600;
    color: #fff;
    background: #1a1a1a;
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }
  button:disabled { opacity: .6; cursor: default; }
  button:hover:not(:disabled) { background: #000; }
  .status { margin-top: 16px; font-size: 14px; min-height: 20px; }
  .status.success { color: #0a7d32; }
  .status.error { color: #c0392b; }
  .nav { display: inline-block; margin-top: 20px; font-size: 14px; color: #1a1a1a; }
  .nav + .nav { margin-left: 16px; }
</style>
</head>
<body>
<div class="card">
  <h1>Send an email</h1>
  <p class="sub">Delivered via Resend, from your verified domain.</p>
  <form id="send-form">
    <label for="to">To</label>
    <input id="to" type="text" placeholder="name@example.com (comma-separate for multiple)" required>
    <label for="from_name">From name</label>
    <input id="from_name" type="text" placeholder="Optional, e.g. My App">
    <label for="from_local">From address</label>
    <input id="from_local" type="text" value="noreply">
    <div class="hint" id="from-preview"></div>
    <label for="reply_to">Reply-To</label>
    <input id="reply_to" type="email" placeholder="Optional">
    <label for="subject">Subject</label>
    <input id="subject" type="text" required>
    <label for="message">Message</label>
    <textarea id="message" required></textarea>
    <button id="submit-btn" type="submit">Send email</button>
  </form>
  <div class="status" id="status"></div>
  <a class="nav" href="/sent${tokenParam}">Sent messages</a>
  <a class="nav" href="/usage${tokenParam}">Usage</a>
</div>
<script>
(function () {
  var DOMAIN = ${domainJson};
  var TOKEN = ${tokenJson};
  var form = document.getElementById("send-form");
  var statusBox = document.getElementById("status");
  var localInput = document.getElementById("from_local");
  var fromPreview = document.getElementById("from-preview");
  var btn = document.getElementById("submit-btn");

  function updatePreview() {
    var local = (localInput.value || "").trim().toLowerCase() || "noreply";
    fromPreview.textContent = "Will be sent as: " + local + "@" + DOMAIN;
  }
  localInput.addEventListener("input", updatePreview);
  updatePreview();

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    btn.disabled = true;
    btn.textContent = "Sending...";
    statusBox.textContent = "";
    statusBox.className = "status";

    fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auth-Token": TOKEN },
      body: JSON.stringify({
        to: document.getElementById("to").value,
        from_name: document.getElementById("from_name").value,
        from_local: localInput.value,
        reply_to: document.getElementById("reply_to").value,
        subject: document.getElementById("subject").value,
        text: document.getElementById("message").value
      })
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
</script>
</body>
</html>`;
}

function renderSentPage(rows, token) {
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";

  const items = rows.length
    ? rows
        .map(function (r) {
          const ok = r.status === "sent";
          return (
            '<details class="msg">' +
            "<summary>" +
            '<span class="dot ' + (ok ? "ok" : "fail") + '"></span>' +
            "<strong>" + escapeHtml(r.subject || "") + "</strong>" +
            '<span class="meta">to ' + escapeHtml(r.to_addresses || "") +
            " &middot; " + escapeHtml(r.created_at || "") + " UTC</span>" +
            "</summary>" +
            '<div class="msg-body">' +
            "<p><strong>From:</strong> " + escapeHtml(r.from_address || "") + "</p>" +
            (r.reply_to ? "<p><strong>Reply-To:</strong> " + escapeHtml(r.reply_to) + "</p>" : "") +
            (r.resend_id ? "<p><strong>Resend ID:</strong> " + escapeHtml(r.resend_id) + "</p>" : "") +
            (r.delivery_status ? "<p><strong>Delivery:</strong> " + escapeHtml(r.delivery_status) + "</p>" : "") +
            (!ok && r.error ? '<p class="err"><strong>Error:</strong> ' + escapeHtml(r.error) + "</p>" : "") +
            '<pre class="body">' + escapeHtml(r.body || "") + "</pre>" +
            "</div></details>"
          );
        })
        .join("")
    : '<p class="sub">No messages sent yet.</p>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sent Messages</title>
<style>
  * { box-sizing: border-box; }
  body {
    background: #ffffff;
    color: #1a1a1a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 40px 16px;
    display: flex;
    justify-content: center;
  }
  .card {
    width: 100%;
    max-width: 640px;
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 10px;
    padding: 32px;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #777; font-size: 14px; margin: 0 0 24px; }
  .msg { border-bottom: 1px solid #eee; padding: 12px 0; }
  .msg:last-of-type { border-bottom: none; }
  .msg summary { cursor: pointer; list-style: none; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .msg summary::-webkit-details-marker { display: none; }
  .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; align-self: center; }
  .dot.ok { background: #0a7d32; }
  .dot.fail { background: #c0392b; }
  .meta { color: #888; font-size: 12.5px; width: 100%; margin-left: 17px; }
  .msg-body { margin: 12px 0 4px 17px; font-size: 14px; }
  .msg-body p { margin: 4px 0; }
  .msg-body .err { color: #c0392b; }
  pre.body {
    white-space: pre-wrap;
    word-wrap: break-word;
    font: inherit;
    background: #fafafa;
    border: 1px solid #f0f0f0;
    border-radius: 6px;
    padding: 12px;
    margin: 10px 0 0;
  }
  .nav { display: inline-block; margin-top: 20px; font-size: 14px; color: #1a1a1a; }
  .nav + .nav { margin-left: 16px; }
</style>
</head>
<body>
<div class="card">
  <h1>Sent messages</h1>
  <p class="sub">Last ${rows.length} message${rows.length === 1 ? "" : "s"} (most recent first).</p>
  ${items}
  <div>
    <a class="nav" href="/${tokenParam}">&larr; Compose</a>
    <a class="nav" href="/usage${tokenParam}">Usage</a>
  </div>
</div>
</body>
</html>`;
}

function renderUsagePage(stats, token) {
  const tokenParam = token ? "?token=" + encodeURIComponent(token) : "";
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");

  const maxCount = Math.max.apply(null, [1].concat(stats.perDay.map(function (d) { return d.count; })));
  const bars = stats.perDay
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
  const pills = stats.delivery.length
    ? stats.delivery
        .map(function (d) {
          return (
            '<span class="pill ' + (pillCls[d.s] || "") + '">' +
            escapeHtml(d.s) + " &middot; " + d.c + "</span>"
          );
        })
        .join("")
    : '<span class="muted">No delivery data yet — press the sync button below.</span>';

  const topRec = stats.topRecipients.length
    ? "<ol>" +
      stats.topRecipients
        .map(function (r) {
          return "<li><span>" + escapeHtml(r[0]) + '</span><span class="muted">' + r[1] + "</span></li>";
        })
        .join("") +
      "</ol>"
    : '<span class="muted">No recipients yet.</span>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API Usage</title>
<style>
  * { box-sizing: border-box; }
  body {
    background: #ffffff;
    color: #1a1a1a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 40px 16px;
    display: flex;
    justify-content: center;
  }
  .card {
    width: 100%;
    max-width: 720px;
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 10px;
    padding: 32px;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 30px 0 12px; }
  .sub { color: #777; font-size: 14px; margin: 0 0 8px; }
  .muted { color: #888; font-size: 13px; }
  .cards { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
  .stat {
    flex: 1 1 100px;
    border: 1px solid #eee;
    border-radius: 8px;
    padding: 14px 12px;
    text-align: center;
  }
  .stat .num { font-size: 24px; font-weight: 700; }
  .stat .num.bad { color: #c0392b; }
  .stat .lbl { font-size: 11.5px; color: #888; margin-top: 2px; }
  .chart { display: flex; gap: 6px; align-items: flex-end; margin-top: 8px; }
  .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; min-width: 0; }
  .bar-num { font-size: 10px; color: #888; margin-bottom: 2px; }
  .bar { position: relative; width: 100%; max-width: 30px; background: #1a1a1a; border-radius: 3px 3px 0 0; }
  .bar-fail { position: absolute; bottom: 0; left: 0; width: 100%; background: #c0392b; }
  .bar-label { font-size: 10px; color: #888; margin-top: 4px; }
  .pill {
    display: inline-block;
    padding: 4px 10px;
    border: 1px solid #ddd;
    border-radius: 999px;
    font-size: 12.5px;
    margin: 0 6px 6px 0;
  }
  .pill.ok { border-color: #0a7d32; color: #0a7d32; }
  .pill.fail { border-color: #c0392b; color: #c0392b; }
  ol { margin: 0; padding-left: 20px; }
  ol li { display: flex; justify-content: space-between; gap: 12px; padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
  ol li:last-child { border-bottom: none; }
  .sync-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 8px; }
  button {
    padding: 10px 16px;
    font: inherit;
    font-size: 14px;
    font-weight: 600;
    color: #fff;
    background: #1a1a1a;
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }
  button:disabled { opacity: .6; cursor: default; }
  button:hover:not(:disabled) { background: #000; }
  #sync-msg { font-size: 13px; min-height: 18px; }
  .nav { display: inline-block; margin-top: 24px; font-size: 14px; color: #1a1a1a; }
  .nav + .nav { margin-left: 16px; }
</style>
</head>
<body>
<div class="card">
  <h1>API key usage</h1>
  <p class="sub">Everything sent through this worker with your Resend key.</p>

  <div class="cards">
    <div class="stat"><div class="num">${stats.total}</div><div class="lbl">Total attempts</div></div>
    <div class="stat"><div class="num">${stats.sent}</div><div class="lbl">Sent OK</div></div>
    <div class="stat"><div class="num bad">${stats.failed}</div><div class="lbl">Failed</div></div>
    <div class="stat"><div class="num">${stats.last24h}</div><div class="lbl">Last 24 hours</div></div>
    <div class="stat"><div class="num">${stats.last7d}</div><div class="lbl">Last 7 days</div></div>
    <div class="stat"><div class="num">${stats.last30d}</div><div class="lbl">Last 30 days</div></div>
  </div>

  <h2>Last 14 days</h2>
  <div class="chart">${bars}</div>
  <p class="muted">Dark = sent, red = failed. Hover a bar for details. Dates are MM-DD (UTC).</p>

  <h2>Delivery status (from Resend)</h2>
  <div>${pills}</div>
  <div class="sync-row">
    <button id="sync-btn">Sync delivery status from Resend</button>
    <span id="sync-msg"></span>
  </div>
  <p class="muted">Checks your 25 most recent sent emails against Resend and stores the latest event (delivered, bounced, complained&hellip;).</p>

  <h2>Top recipients</h2>
  ${topRec}
  <p class="muted">Based on your most recent 500 messages.</p>
