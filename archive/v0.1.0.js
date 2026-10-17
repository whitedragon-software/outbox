const RESEND_ENDPOINT = "https://api.resend.com/emails";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_RECIPIENTS = 50;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // The email form (white background)
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      if (!env.RESEND_KEY || !env.DOMAIN1) {
        return new Response(
          "Worker is not configured. Set the RESEND_KEY and DOMAIN1 environment variables.",
          { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } }
        );
      }

      // Optional protection: only active if you set an AUTH_TOKEN variable
      const token = url.searchParams.get("token") || "";
      if (env.AUTH_TOKEN && token !== env.AUTH_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }

      return new Response(renderPage(env.DOMAIN1, token), {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    // The send endpoint (used by the form, or by your own code via POST)
    if (request.method === "POST" && url.pathname === "/send") {
      return handleSend(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

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

  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + env.RESEND_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      return json({ success: true, id: data.id || null });
    }
    return json(
      { success: false, error: data.message || "Resend returned HTTP " + res.status + "." },
      502
    );
  } catch (err) {
    return json({ success: false, error: "Could not reach Resend: " + err.message }, 502);
  }
}

function renderPage(domain, token) {
  const domainJson = JSON.stringify(domain).replace(/</g, "\\u003c");
  const tokenJson = JSON.stringify(token || "").replace(/</g, "\\u003c");

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
          statusBox.textContent = "Email sent!" + (data.id ? " (Resend ID: " + data.id + ")" : "");
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
