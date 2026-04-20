/**
 * MoEngage Tools — Unified Server
 *
 * No credentials stored server-side.
 * All Basic Auth routes receive appId + apiKey per request.
 * DC is fixed to 101.
 *
 * Routes:
 *   /api/moengage/*    → Generic MoEngage proxy  (appId/apiKey via x- headers)
 *   /api/audit/search  → Campaign audit search    (appId/apiKey in body)
 *   /api/cb/search     → CB search                (appId/apiKey in body)
 *   /api/cb/get-ids    → CB fetch by IDs          (appId/apiKey in body)
 *   /api/cb/create     → CB create                (appId/apiKey in body)
 *   /api/auth/*        → Token Manager
 *   /api/flow/*        → Flow proxy (Bearer token)
 */

require("dotenv").config();
const express     = require("express");
const axios       = require("axios");
const cors        = require("cors");
const path        = require("path");
const crypto      = require("crypto");
const rateLimit   = require("express-rate-limit");
const tokenAuth   = require("./token-auth");
const userManager = require("./user-manager");

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Load Users ───────────────────────────────────────────────────────────────
userManager.loadUsers();

// ─── Session Store ────────────────────────────────────────────────────────────
const sessions   = new Map(); // token → { username, expiry }
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 hours

function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { username, expiry: Date.now() + SESSION_TTL });
  return token;
}

function getSession(req) {
  const cookie = req.headers.cookie || "";
  const match  = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  const token  = match ? match[1] : null;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiry) { sessions.delete(token); return null; }
  return session;
}

function getCurrentUser(req) {
  const session = getSession(req);
  if (!session) return null;
  return userManager.findUser(session.username);
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const AUTH_ENABLED = userManager.getUsers().length > 0;

const PUBLIC_PATHS = ["/login", "/logout", "/reset-password", "/forgot-password"];

app.use((req, res, next) => {
  if (!AUTH_ENABLED) return next();
  if (PUBLIC_PATHS.some(p => req.path.startsWith(p))) return next();
  const session = getSession(req);
  if (!session) return res.redirect("/login");

  // Force password reset if flagged
  const user = userManager.findUser(session.username);
  if (user?.mustReset && req.path !== "/reset-password") {
    const token = userManager.createResetToken(session.username);
    return res.redirect(`/reset-password?token=${token}&required=1`);
  }
  next();
});

// Admin-only middleware
function adminOnly(req, res, next) {
  const user = getCurrentUser(req);
  if (!user?.isAdmin) return res.status(403).send("Forbidden — admin only.");
  next();
}

// ─── Body Parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: false }));

// ─── Login Page ───────────────────────────────────────────────────────────────
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>MoEngage Tools — Login</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#141414;border:1px solid #222;border-radius:16px;padding:40px;width:100%;max-width:380px}
    .logo{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#e20074;font-weight:600;margin-bottom:20px}
    h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:6px}
    p{font-size:13px;color:#666;margin-bottom:28px}
    label{display:block;font-size:11px;font-weight:600;color:#666;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}
    input{width:100%;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;color:#f5f5f5;font-size:14px;padding:11px 13px;outline:none;margin-bottom:16px;transition:border-color .2s}
    input:focus{border-color:#e20074}
    button{width:100%;background:#e20074;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;padding:12px;cursor:pointer;transition:opacity .2s}
    button:hover{opacity:.88}
    .error{background:#1a0a0a;border:1px solid #3a1515;border-radius:8px;padding:10px 14px;font-size:13px;color:#f87171;margin-bottom:16px;display:none}
    .error.show{display:block}
    .forgot{text-align:center;margin-top:16px;font-size:12px;color:#555}
    .forgot a{color:#e20074;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">T-Mobile · MoEngage</div>
    <h1>Sign in</h1>
    <p>Internal tools access only.</p>
    <div class="error" id="err">Incorrect username or password.</div>
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" required autofocus/>
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required/>
      <button type="submit">Sign in →</button>
    </form>
    <div class="forgot"><a href="/forgot-password">Forgot password?</a></div>
  </div>
  <script>if(new URLSearchParams(location.search).get('error'))document.getElementById('err').classList.add('show');</script>
</body>
</html>`;

app.get("/login",  (_req, res) => res.send(LOGIN_PAGE));

app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body;
  const user = userManager.validateCredentials(username.trim(), password);
  if (user) {
    const token = createSession(user.username);
    res.setHeader("Set-Cookie", `session=${token}; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}; Path=/`);
    res.redirect("/");
  } else {
    res.redirect("/login?error=1");
  }
});

app.get("/logout", (req, res) => {
  const cookie = req.headers.cookie || "";
  const match  = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (match) sessions.delete(match[1]);
  res.setHeader("Set-Cookie", "session=; HttpOnly; Max-Age=0; Path=/");
  res.redirect("/login");
});

// ─── Forgot Password ──────────────────────────────────────────────────────────
app.get("/forgot-password", (_req, res) => res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>Forgot Password</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#141414;border:1px solid #222;border-radius:16px;padding:40px;width:100%;max-width:380px}.logo{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#e20074;font-weight:600;margin-bottom:20px}h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:6px}p{font-size:13px;color:#666;margin-bottom:28px}label{display:block;font-size:11px;font-weight:600;color:#666;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}input{width:100%;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;color:#f5f5f5;font-size:14px;padding:11px 13px;outline:none;margin-bottom:16px}input:focus{border-color:#e20074}button{width:100%;background:#e20074;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;padding:12px;cursor:pointer}.msg{border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:16px;display:none}.msg.show{display:block}.msg.ok{background:#0a1a0a;border:1px solid #153515;color:#86efac}.msg.err{background:#1a0a0a;border:1px solid #3a1515;color:#f87171}.back{text-align:center;margin-top:16px;font-size:12px;color:#555}.back a{color:#e20074;text-decoration:none}</style>
</head><body><div class="card">
  <div class="logo">T-Mobile · MoEngage</div>
  <h1>Forgot password</h1>
  <p>Enter your username and we'll email you a reset link.</p>
  <div class="msg ok" id="ok">Reset link sent — check your email.</div>
  <div class="msg err" id="err">Username not found or email not configured.</div>
  <form id="form">
    <label>Username</label>
    <input type="text" id="username" required autofocus/>
    <button type="submit">Send reset link →</button>
  </form>
  <div class="back"><a href="/login">← Back to login</a></div>
</div>
<script>
  document.getElementById('form').addEventListener('submit', async e => {
    e.preventDefault();
    const res = await fetch('/forgot-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username: document.getElementById('username').value }) });
    document.getElementById(res.ok ? 'ok' : 'err').classList.add('show');
  });
</script></body></html>`));

app.post("/forgot-password", async (req, res) => {
  try {
    await userManager.sendPasswordResetEmail(req.body.username?.trim());
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "User not found or email not configured." });
  }
});

// ─── Reset Password ───────────────────────────────────────────────────────────
app.get("/reset-password", (req, res) => {
  const { token, required } = req.query;
  const entry = userManager.validateResetToken(token);
  if (!entry) return res.send(`<!DOCTYPE html><html><head><title>Link Expired</title><style>body{font-family:sans-serif;background:#0a0a0a;color:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}a{color:#e20074}</style></head><body><h2>Link expired or invalid</h2><p style="color:#666;margin:12px 0">Reset links are valid for 1 hour.</p><a href="/forgot-password">Request a new one →</a></body></html>`);

  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>Set Password</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#141414;border:1px solid #222;border-radius:16px;padding:40px;width:100%;max-width:380px}.logo{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#e20074;font-weight:600;margin-bottom:20px}h1{font-size:22px;font-weight:700;color:#fff;margin-bottom:6px}p{font-size:13px;color:#666;margin-bottom:28px}label{display:block;font-size:11px;font-weight:600;color:#666;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}input{width:100%;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:8px;color:#f5f5f5;font-size:14px;padding:11px 13px;outline:none;margin-bottom:16px}input:focus{border-color:#e20074}button{width:100%;background:#e20074;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;padding:12px;cursor:pointer}.hint{font-size:12px;color:#555;margin-bottom:16px}.msg{border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:16px;display:none}.msg.show{display:block}.msg.err{background:#1a0a0a;border:1px solid #3a1515;color:#f87171}${required === "1" ? ".notice{background:#0d1a0d;border:1px solid #1a3a1a;border-radius:8px;padding:10px 14px;font-size:12px;color:#86efac;margin-bottom:20px}" : ""}</style>
</head><body><div class="card">
  <div class="logo">T-Mobile · MoEngage</div>
  <h1>Set your password</h1>
  ${required === "1" ? '<div class="notice">👋 Welcome! Please set a new password to continue.</div>' : ""}
  <div class="msg err" id="err"></div>
  <form id="form">
    <label>New Password</label>
    <input type="password" id="p1" placeholder="Min 8 characters" required/>
    <label>Confirm Password</label>
    <input type="password" id="p2" required/>
    <p class="hint">Min 8 characters, must include a number or symbol.</p>
    <button type="submit">Save password →</button>
  </form>
</div>
<script>
  document.getElementById('form').addEventListener('submit', async e => {
    e.preventDefault();
    const p1 = document.getElementById('p1').value;
    const p2 = document.getElementById('p2').value;
    const err = document.getElementById('err');
    err.classList.remove('show');
    if (p1 !== p2) { err.textContent = 'Passwords do not match.'; err.classList.add('show'); return; }
    if (p1.length < 8) { err.textContent = 'Min 8 characters required.'; err.classList.add('show'); return; }
    const res = await fetch('/reset-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token: '${token}', password: p1 }) });
    const data = await res.json();
    if (res.ok) { window.location.href = '/login?reset=1'; }
    else { err.textContent = data.error || 'Failed. Try again.'; err.classList.add('show'); }
  });
</script></body></html>`);
});

app.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;
  const entry = userManager.consumeResetToken(token);
  if (!entry) return res.status(400).json({ error: "Token expired or invalid." });
  if (!password || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  try {
    await userManager.updatePassword(entry.username, password);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────
app.get("/admin", adminOnly, (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

app.get("/admin/users", adminOnly, (_req, res) => {
  const users = userManager.getUsers().map(({ password: _, ...u }) => u); // strip password
  res.json(users);
});

app.post("/admin/users", adminOnly, async (req, res) => {
  const { username, email, displayName, isAdmin } = req.body;
  if (!username || !email) return res.status(400).json({ error: "username and email are required." });
  try {
    const { user } = await userManager.createUser({ username, email, displayName, isAdmin });
    res.json({ ok: true, username: user.username, note: "Welcome email sent." });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/admin/users/:username", adminOnly, async (req, res) => {
  const me = getCurrentUser(req);
  if (me?.username === req.params.username) return res.status(400).json({ error: "Cannot delete your own account." });
  try {
    await userManager.deleteUser(req.params.username);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/admin/users/:username/reset", adminOnly, async (req, res) => {
  try {
    await userManager.sendPasswordResetEmail(req.params.username);
    res.json({ ok: true, note: "Reset email sent." });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});




// DC fixed to 101
const MOE_API_BASE  = "https://api-101.moengage.com";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function basicAuth(appId, apiKey) {
  return "Basic " + Buffer.from(`${appId}:${apiKey}`).toString("base64");
}

function moeHeaders(appId, apiKey) {
  return {
    Authorization:  basicAuth(appId, apiKey),
    "Content-Type": "application/json",
    "MOE-APPID":    appId,
  };
}

function missingCreds(res) {
  return res.status(400).json({
    error: "appId and apiKey are required. Pass them in the request.",
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rate limit reached. Please wait before retrying.", retryAfter: 60 },
});

// ─── Static Files ─────────────────────────────────────────────────────────────
const reactBuildPath = path.join(__dirname, "client", "build");
app.use("/template-builder", express.static(reactBuildPath));
app.get("/template-builder/*", (_req, res) =>
  res.sendFile(path.join(reactBuildPath, "index.html"))
);
app.use(express.static(path.join(__dirname, "public")));

// ─── Generic MoEngage Proxy  /api/moengage/* ─────────────────────────────────
// Credentials passed as request headers:
//   x-app-id:  <appId>
//   x-api-key: <apiKey>
// This keeps the request body free to be forwarded as-is to MoEngage.

app.use("/api/moengage/*", apiLimiter);
app.all("/api/moengage/*", async (req, res) => {
  const appId  = req.headers["x-app-id"];
  const apiKey = req.headers["x-api-key"];
  if (!appId || !apiKey) return missingCreds(res);

  const targetPath = req.params[0];
  const targetUrl  = `${MOE_API_BASE}/${targetPath}`;

  try {
    const response = await axios({
      method:  req.method,
      url:     targetUrl,
      headers: moeHeaders(appId, apiKey),
      params:  req.query,
      data:    req.body,
      timeout: 30000,
    });
    res.status(response.status).json(response.data);
  } catch (err) {
    const status = err.response?.status || 500;
    const data   = err.response?.data   || { error: err.message };
    if (status === 503) {
      return res.status(503).json({
        error: "MoEngage service temporarily unavailable",
        retryAfter: 5,
        original: data,
      });
    }
    res.status(status).json(data);
  }
});

// ─── Campaign Audit  /api/audit/search ───────────────────────────────────────
// Body: { appId, apiKey, terms[], limit?, offset? }

app.post("/api/audit/search", apiLimiter, async (req, res) => {
  const { appId, apiKey, terms = [], limit = 50, offset = 0 } = req.body;
  if (!appId || !apiKey) return missingCreds(res);
  if (!Array.isArray(terms) || terms.length === 0) {
    return res.status(400).json({ error: "Provide at least one search term." });
  }

  try {
    const results = {};
    for (const term of terms) {
      const response = await axios.get(
        `${MOE_API_BASE}/v1/${appId}/campaigns`,
        {
          headers: moeHeaders(appId, apiKey),
          params:  { search: term, limit, offset },
          timeout: 30000,
        }
      );
      results[term] = response.data;
    }
    res.json(results);
  } catch (err) {
    res.status(err.response?.status || 500).json(
      err.response?.data || { error: err.message }
    );
  }
});

// ─── Content Block Migration  /api/cb/* ──────────────────────────────────────
// All routes: body must include { appId, apiKey, ...payload }

// Search blocks in an env
app.post("/api/cb/search", apiLimiter, async (req, res) => {
  const { appId, apiKey, ...payload } = req.body;
  if (!appId || !apiKey) return missingCreds(res);
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/v1/external/campaigns/content-blocks/search`,
      payload,
      { headers: moeHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Fetch full content block details by IDs
app.post("/api/cb/get-ids", apiLimiter, async (req, res) => {
  const { appId, apiKey, ids = [], is_raw_content_required = true } = req.body;
  if (!appId || !apiKey) return missingCreds(res);
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/v1/external/campaigns/content-blocks/get-by-ids`,
      { ids, is_raw_content_required },
      { headers: moeHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Create a content block in target env
app.post("/api/cb/create", apiLimiter, async (req, res) => {
  const { appId, apiKey, ...payload } = req.body;
  if (!appId || !apiKey) return missingCreds(res);
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/v1/external/campaigns/content-blocks`,
      payload,
      { headers: moeHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// ─── Content Block + Campaign Search (content_block_search.html) ─────────────
// This single utility handles both modes via a tab switcher.
// Credentials passed as headers: Authorization (Basic) + MOE-APPKEY

function searchHeaders(req) {
  return {
    Authorization:  req.headers["authorization"] || "",
    "Content-Type": "application/json",
    "MOE-APPKEY":   req.headers["moe-appkey"] || req.headers["moe-appid"] || "",
  };
}

// Content Block search (list/search all blocks)
app.post("/proxy", apiLimiter, async (req, res) => {
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/v1/external/campaigns/content-blocks/search`,
      req.body,
      { headers: searchHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Content Block get by IDs (fetch full content)
app.post("/proxy-get-ids", apiLimiter, async (req, res) => {
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/v1/external/campaigns/content-blocks/get-by-ids`,
      req.body,
      { headers: searchHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Campaign search (Email / SMS / Push across all campaigns)
app.post("/proxy-campaigns", apiLimiter, async (req, res) => {
  try {
    const response = await axios.post(
      `${MOE_API_BASE}/core-services/v1/campaigns/search`,
      req.body,
      { headers: searchHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});


// Original proxy.js pattern: Authorization + MOE-APPKEY + X-Moe-Dc headers

function legacyCbHeaders(req) {
  return {
    Authorization:  req.headers["authorization"]  || "",
    "Content-Type": "application/json",
    "MOE-APPKEY":   req.headers["moe-appkey"]     || req.headers["moe-appid"] || "",
  };
}

function legacyDc(req) {
  return req.headers["x-moe-dc"] || "101";
}

function legacyMissingAuth(req, res) {
  if (!req.headers["authorization"]) {
    res.status(400).json({ error: "Authorization header is required." });
    return true;
  }
  return false;
}

app.post("/cb-search", apiLimiter, async (req, res) => {
  if (legacyMissingAuth(req, res)) return;
  const dc = legacyDc(req);
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks/search`,
      req.body,
      { headers: legacyCbHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) { res.status(err.response?.status || 500).json(err.response?.data || { error: err.message }); }
});

app.post("/cb-get-ids", apiLimiter, async (req, res) => {
  if (legacyMissingAuth(req, res)) return;
  const dc = legacyDc(req);
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks/get-by-ids`,
      req.body,
      { headers: legacyCbHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) { res.status(err.response?.status || 500).json(err.response?.data || { error: err.message }); }
});

app.post("/cb-create", apiLimiter, async (req, res) => {
  if (legacyMissingAuth(req, res)) return;
  const dc = legacyDc(req);
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks`,
      req.body,
      { headers: legacyCbHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) { res.status(err.response?.status || 500).json(err.response?.data || { error: err.message }); }
});

app.post("/cb-update", apiLimiter, async (req, res) => {
  if (legacyMissingAuth(req, res)) return;
  const dc  = legacyDc(req);
  const id  = req.headers["x-block-id"] || req.body.id;
  if (!id) return res.status(400).json({ error: "Block ID required (x-block-id header or body.id)." });
  try {
    const response = await axios.put(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks/${id}`,
      req.body,
      { headers: legacyCbHeaders(req), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) { res.status(err.response?.status || 500).json(err.response?.data || { error: err.message }); }
});

// ─── Token Auth + Flow Proxy ──────────────────────────────────────────────────
app.use("/api/auth", tokenAuth.router);
app.use("/api/flow", tokenAuth.flowProxy);

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    dc: "101",
    authMode: "per-request (no server-side credentials)",
    tools: [
      { name: "Email Template Builder",        url: "/template-builder" },
      { name: "Content Block & Campaign Search", url: "/content-block-search.html" },
      { name: "Content Block Migration",        url: "/cb-migrator.html" },
      { name: "Flow Action Nodes Review",       url: "/flow-review.html" },
      { name: "Token Manager",                  url: "/token-manager.html" },
    ],
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ MoEngage Tools running on port ${PORT}`);
  console.log(`   DC fixed to         : 101`);
  console.log(`   Auth mode           : per-request (no server-side credentials)`);
  console.log(`   → Dashboard              : http://localhost:${PORT}`);
  console.log(`   → Template Builder       : http://localhost:${PORT}/template-builder`);
  console.log(`   → CB & Campaign Search   : http://localhost:${PORT}/content-block-search.html`);
  console.log(`   → CB Migration           : http://localhost:${PORT}/cb-migrator.html`);
  console.log(`   → Flow Review            : http://localhost:${PORT}/flow-review.html`);
  console.log(`   → Token Manager          : http://localhost:${PORT}/token-manager.html`);
  console.log(`   → Health                 : http://localhost:${PORT}/health`);
});
