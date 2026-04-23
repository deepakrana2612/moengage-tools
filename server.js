'use strict';

require('dotenv').config();

const express     = require('express');
const axios       = require('axios');
const cors        = require('cors');
const path        = require('path');
const crypto      = require('crypto');
const rateLimit   = require('express-rate-limit');
const tokenAuth   = require('./token-auth');
const userManager = require('./user-manager');
const toolsReg    = require('./tools-registry');

const app  = express();
const PORT = process.env.PORT || 3000;
const MOE_API_BASE = 'https://api-101.moengage.com';

userManager.loadUsers();

// ─── Session Store ────────────────────────────────────────────────────────────
const sessions    = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expiry: Date.now() + SESSION_TTL });
  return token;
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;
  const sess = sessions.get(match[1]);
  if (!sess) return null;
  if (Date.now() > sess.expiry) { sessions.delete(match[1]); return null; }
  return sess;
}

// ─── Login Page ───────────────────────────────────────────────────────────────
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign in — MoEngage Tools</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#0a0a0a;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#141414;border:1px solid #222;border-radius:16px;padding:48px 40px;width:100%;max-width:400px}
    .logo{font-size:12px;letter-spacing:3px;text-transform:uppercase;color:#e20074;font-weight:600;margin-bottom:24px}
    h1{font-size:24px;font-weight:700;color:#fff;margin-bottom:8px}
    p{font-size:14px;color:#666;margin-bottom:32px}
    label{display:block;font-size:12px;font-weight:600;color:#888;margin-bottom:6px;letter-spacing:.5px}
    input{width:100%;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;
          color:#fff;font-size:14px;padding:12px 14px;outline:none;margin-bottom:16px;transition:border-color .2s}
    input:focus{border-color:#e20074}
    button{width:100%;background:#e20074;color:#fff;border:none;border-radius:8px;
           font-size:15px;font-weight:600;padding:14px;cursor:pointer;transition:background .2s;margin-top:8px}
    button:hover{background:#c8006a}
    .err{background:rgba(220,38,38,.1);border:1px solid rgba(220,38,38,.3);
         color:#f87171;border-radius:8px;padding:12px 14px;font-size:13px;margin-bottom:20px;display:none}
    .err.show{display:block}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">T-Mobile · MoEngage</div>
    <h1>Sign in</h1>
    <p>Marketing Utility Suite — Internal Access Only</p>
    <div class="err" id="err">Incorrect username or password.</div>
    <form method="POST" action="/login">
      <label>USERNAME</label>
      <input type="text" name="username" autocomplete="username" required autofocus/>
      <label>PASSWORD</label>
      <input type="password" name="password" autocomplete="current-password" required/>
      <button type="submit">Sign in \u2192</button>
    </form>
  </div>
  <script>
    if (new URLSearchParams(location.search).get('error'))
      document.getElementById('err').classList.add('show');
  </script>
</body>
</html>`;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ─── CSP / Security Headers ───────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "connect-src 'self' https://api-101.moengage.com https://dashboard-101.moengage.com",
    "img-src 'self' data: blob: https:",
    "frame-src 'self' blob:",
    "worker-src 'self' blob:",
  ].join('; '));
  res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
  next();
});

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Rate limit reached.', retryAfter: 60 },
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const open = ['/login', '/logout', '/health'];
  if (open.some(p => req.path === p)) return next();
  if (req.path.startsWith('/reset-password') || req.path.startsWith('/api/reset-password')) return next();
  const sess = getSession(req);
  if (sess) return next();
  if (req.path.startsWith('/api/') || req.path.startsWith('/proxy')) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  res.redirect('/login');
});

// ─── Tool Access Middleware ───────────────────────────────────────────────────
app.use((req, res, next) => {
  if (!toolsReg.isGatedRoute(req.path)) return next();
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ error: 'Unauthorised' });
  const user = userManager.findUser(sess.username);
  if (!user) return res.status(401).json({ error: 'Unauthorised' });
  if (user.isAdmin) return next();
  const tool = toolsReg.getByApiRoute(req.path);
  if (!tool) return next();
  if (!user.allowedTools || !user.allowedTools.includes(tool.id)) {
    return res.status(403).json({ error: 'You do not have access to this tool.' });
  }
  next();
});

// ─── Login / Logout ───────────────────────────────────────────────────────────
app.use('/login', express.urlencoded({ extended: false }));

app.get('/login', (_req, res) => { res.setHeader('Content-Type', 'text/html'); res.send(LOGIN_PAGE); });

app.post('/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const user = await userManager.validateCredentials(username.trim(), password);
  if (user) {
    const token = createSession(user.username);
    res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}; Path=/`);
    if (user.mustReset) return res.redirect('/reset-password?required=1');
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

app.get('/logout', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (match) sessions.delete(match[1]);
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Max-Age=0; Path=/');
  res.redirect('/login');
});

// ─── API: My Tools ────────────────────────────────────────────────────────────
app.get('/api/my-tools', (req, res) => {
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ error: 'Unauthorised' });
  const user = userManager.findUser(sess.username);
  if (!user) return res.status(401).json({ error: 'Unauthorised' });
  const allTools = toolsReg.getAll();
  const tools = user.isAdmin
    ? allTools
    : allTools.filter(t => user.allowedTools && user.allowedTools.includes(t.id));
  res.json({ tools, isAdmin: user.isAdmin, displayName: user.displayName || user.username });
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ error: 'Unauthorised' });
  const user = userManager.findUser(sess.username);
  if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  req.adminUser = user;
  next();
}

app.get('/admin/users', requireAdmin, (_req, res) => {
  res.json(userManager.getUsers().map(u => ({
    username: u.username, displayName: u.displayName, email: u.email,
    isAdmin: u.isAdmin, allowedTools: u.allowedTools || [], mustReset: u.mustReset, createdAt: u.createdAt,
  })));
});

app.post('/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await userManager.createUser(req.body);
    res.json({ ok: true, user: result.user });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/admin/users/:username', requireAdmin, async (req, res) => {
  try {
    await userManager.deleteUser(req.params.username);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/admin/users/:username/tools', requireAdmin, async (req, res) => {
  try {
    await userManager.updateUserTools(req.params.username, req.body.allowedTools);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/admin/users/:username/reset-link', requireAdmin, async (req, res) => {
  try {
    const user = userManager.findUser(req.params.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const token = await userManager.createResetToken(user.username);
    await userManager.sendPasswordResetEmail(user, token);
    const link = `${process.env.APP_URL || 'http://localhost:' + PORT}/reset-password?token=${token}`;
    res.json({ ok: true, link });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Password Reset ───────────────────────────────────────────────────────────
app.use('/reset-password', express.urlencoded({ extended: false }));
app.get('/reset-password', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));

app.post('/api/reset-password', async (req, res) => {
  try {
    const username = await userManager.validateResetToken(req.body.token);
    await userManager.updatePassword(username, req.body.password);
    await userManager.consumeResetToken(req.body.token);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/change-password', async (req, res) => {
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ error: 'Unauthorised' });
  try {
    const user = await userManager.validateCredentials(sess.username, req.body.currentPassword);
    if (!user) return res.status(400).json({ error: 'Current password is incorrect' });
    await userManager.updatePassword(sess.username, req.body.newPassword);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// ─── Static Files ─────────────────────────────────────────────────────────────
const reactBuildPath = path.join(__dirname, 'client', 'build');
app.use('/template-builder', express.static(reactBuildPath));
app.get('/template-builder/*', (_req, res) => res.sendFile(path.join(reactBuildPath, 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Token Auth + Flow Proxy ──────────────────────────────────────────────────
app.use('/api/auth', tokenAuth.router);
app.use('/api/flow', tokenAuth.flowProxy);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function moeHeaders(appId, apiKey) {
  return {
    'Authorization': 'Basic ' + Buffer.from(`${appId}:${apiKey}`).toString('base64'),
    'Content-Type':  'application/json',
    'MOE-APPKEY':    appId,
  };
}
function missingCreds(res) {
  return res.status(401).json({ error: 'Missing credentials. Provide x-app-id and x-api-key headers.' });
}

// ─── User Attribute Updater (inlined) ────────────────────────────────────────
function userUpdaterLog(label, method, url, body, status, response) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 23);
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`[${ts}] ${label}  ${method} ${url}`);
  console.log('  BODY:', JSON.stringify(body, null, 2));
  console.log(`[${ts}] HTTP ${status}:`, JSON.stringify(response, null, 2));
  console.log('─'.repeat(60) + '\n');
}

app.post('/api/user-updater/get-user', async (req, res) => {
  const appId  = (req.headers['x-app-id']  || '').trim();
  const apiKey = (req.headers['x-api-key'] || '').trim();
  if (!appId || !apiKey) return missingCreds(res);
  const url = `${MOE_API_BASE}/v1/customers/export?app_id=${appId}`;
  try {
    const resp = await axios.post(url, req.body, { headers: moeHeaders(appId, apiKey), validateStatus: () => true });
    userUpdaterLog('GET USER', 'POST', url, req.body, resp.status, resp.data);
    res.status(resp.status).json(resp.data);
  } catch (err) {
    const s = err.response?.status || 502, d = err.response?.data || { error: err.message };
    userUpdaterLog('GET USER', 'POST', url, req.body, s, d);
    res.status(s).json(d);
  }
});

app.post('/api/user-updater/update-user', async (req, res) => {
  const appId  = (req.headers['x-app-id']  || '').trim();
  const apiKey = (req.headers['x-api-key'] || '').trim();
  if (!appId || !apiKey) return missingCreds(res);
  const url = `${MOE_API_BASE}/v1/customer/${appId}`;
  try {
    const resp = await axios.post(url, req.body, { headers: moeHeaders(appId, apiKey), validateStatus: () => true });
    userUpdaterLog('UPDATE USER', 'POST', url, req.body, resp.status, resp.data);
    res.status(resp.status).json(resp.data);
  } catch (err) {
    const s = err.response?.status || 502, d = err.response?.data || { error: err.message };
    userUpdaterLog('UPDATE USER', 'POST', url, req.body, s, d);
    res.status(s).json(d);
  }
});

// ─── Content Block Search Utility ─────────────────────────────────────────────
function proxyMoeRequest(targetUrl, req, res) {
  axios.post(targetUrl, req.body, {
    headers: {
      'Content-Type':  'application/json',
      'Authorization': req.headers['authorization'] || '',
      'MOE-APPKEY':    req.headers['moe-appkey']    || '',
    },
    validateStatus: () => true,
  })
  .then(r => res.status(r.status).json(r.data))
  .catch(e => res.status(502).json({ error: e.message }));
}

app.post('/proxy',           apiLimiter, (req, res) => proxyMoeRequest(`${MOE_API_BASE}/v1/external/campaigns/content-blocks/search`,     req, res));
app.post('/proxy-get-ids',   apiLimiter, (req, res) => proxyMoeRequest(`${MOE_API_BASE}/v1/external/campaigns/content-blocks/get-by-ids`, req, res));
app.post('/proxy-campaigns', apiLimiter, (req, res) => proxyMoeRequest(`${MOE_API_BASE}/core-services/v1/campaigns/search`,                req, res));

// ─── Content Block Migration Utility ──────────────────────────────────────────
async function cbProxy(targetPath, req, res, method = 'POST') {
  const appId  = (req.headers['x-app-id']  || req.body?.app_id  || '').trim();
  const apiKey = (req.headers['x-api-key'] || req.body?.api_key || '').trim();
  if (!appId || !apiKey) return missingCreds(res);
  try {
    const resp = await axios({ method, url: `${MOE_API_BASE}${targetPath}`, data: req.body, headers: moeHeaders(appId, apiKey), validateStatus: () => true });
    res.status(resp.status).json(resp.data);
  } catch (err) { res.status(502).json({ error: err.message }); }
}

app.post('/api/cb/search',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks/search',     req, res));
app.post('/api/cb/get-ids', apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks/get-by-ids', req, res));
app.post('/api/cb/create',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks',             req, res));
app.post('/api/cb/update',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks',             req, res, 'PUT'));

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({
  status: 'ok', service: 'moengage-tools', dc: 'api-101.moengage.com',
  tools: toolsReg.getAll().map(t => ({ name: t.name, url: t.url })),
}));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  MoEngage Tools running on http://localhost:${PORT}\n`);
});
