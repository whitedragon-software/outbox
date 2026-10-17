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

// --- Auto schema creation ----------------------------------------------
// Runs once per worker instance. If the "emails" table doesn't exist yet,
// it is created automatically. CREATE TABLE IF NOT EXISTS is idempotent,
// so this never touches or conflicts with existing data.
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

      // Make sure the table exists before we query it
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

  // Make sure the table exists before the first write
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
    // Send succeeded -> automatically write it to the database
    const saved = await logEmail(env, data.id || null, from, recipients, replyTo,
      subject, text, "sent", null);
    return json({ success: true, id: data.id || null, saved: saved });
  }

  // Send failed -> record the attempt with the error
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
  <a class="nav" href="/sent${tokenParam}">View sent messages &rarr;</a>
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
</style>
</head>
<body>
<div class="card">
  <h1>Sent messages</h1>
  <p class="sub">Last ${rows.length} message${rows.length === 1 ? "" : "s"} (most recent first).</p>
  ${items}
  <a class="nav" href="/${tokenParam}">&larr; Compose new email</a>
</div>
</body>
</html>`;
    }
