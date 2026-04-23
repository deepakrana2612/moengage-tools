/**
 * MoEngage Tools — Unified Server
 * ─────────────────────────────────────────────────────────────────────────────
 * No credentials stored server-side.
 * All Basic Auth routes receive appId + apiKey per request via x- headers.
 * DC is fixed to 101.
 *
 * Route map:
 *   /proxy              → CB search        (Content Block Search utility)
 *   /proxy-get-ids      → CB get-by-ids    (Content Block Search utility)
 *   /proxy-campaigns    → Campaign search  (Content Block Search utility)
 *   /api/cb/search      → CB search        (CB Migrator utility)
 *   /api/cb/get-ids     → CB get-by-ids    (CB Migrator utility)
 *   /api/cb/create      → CB create        (CB Migrator utility)
 *   /api/cb/update      → CB update (PUT)  (CB Migrator utility)
 *   /api/user-updater/* → User Attribute Updater
 *   /api/auth/*         → Token Manager (set / status / clear)
 *   /api/flow/*         → Flow Review proxy (Bearer token)
 *   /template-builder   → Email Template Builder (React build)
 *   /                   → Static HTML tools (public/)
 */

'use strict';

require('dotenv').config();

const express   = require('express');
const axios     = require('axios');
const cors      = require('cors');
const path      = require('path');
const rateLimit = require('express-rate-limit');
const tokenAuth = require('./token-auth');

const app  = express();
const PORT = process.env.PORT || 3000;

const MOE_API_BASE = 'https://api-101.moengage.com';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function basicAuth(appId, apiKey) {
  return 'Basic ' + Buffer.from(`${appId}:${apiKey}`).toString('base64');
}

function moeHeaders(appId, apiKey) {
  return {
    'Authorization':  basicAuth(appId, apiKey),
    'Content-Type':   'application/json',
    'MOE-APPKEY':     appId,
  };
}

// Read credentials from x- headers (used by most utilities)
function credsFromHeaders(req) {
  const appId  = (req.headers['x-app-id']  || '').trim();
  const apiKey = (req.headers['x-api-key'] || '').trim();
  return (appId && apiKey) ? { appId, apiKey } : null;
}

// Read credentials from request body (used by CB migrator - dual env support)
function credsFromBody(req, prefix) {
  const appId  = (req.body[`${prefix}_app_id`]  || req.body.app_id  || '').trim();
  const apiKey = (req.body[`${prefix}_api_key`] || req.body.api_key || '').trim();
  return (appId && apiKey) ? { appId, apiKey } : null;
}

function missingCreds(res) {
  return res.status(401).json({ error: 'Missing credentials. Provide x-app-id and x-api-key headers.' });
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ─── Security Headers ─────────────────────────────────────────────────────────
// Internal tooling — relax CSP defaults so utilities can run inline scripts,
// open blob windows for CSV export, and fetch from MoEngage APIs over HTTPS.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "connect-src 'self' https://api-101.moengage.com https://dashboard-101.moengage.com",
      "img-src 'self' data: blob: https:",
      "frame-src 'self' blob:",
      "worker-src 'self' blob:",
    ].join('; ')
  );
  // Allow popup windows opened by the utilities to run scripts
  res.setHeader('Cross-Origin-Opener-Policy', 'unsafe-none');
  next();
});

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             25,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Rate limit reached. Please wait before retrying.', retryAfter: 60 },
});

// ─── Static Files ─────────────────────────────────────────────────────────────
const reactBuildPath = path.join(__dirname, 'client', 'build');
app.use('/template-builder', express.static(reactBuildPath));
app.get('/template-builder/*', (_req, res) =>
  res.sendFile(path.join(reactBuildPath, 'index.html'))
);
app.use(express.static(path.join(__dirname, 'public')));

// ─── Token Auth + Flow Proxy (Bearer token) ───────────────────────────────────
app.use('/api/auth', tokenAuth.router);
app.use('/api/flow', tokenAuth.flowProxy);

// ─── User Attribute Updater ───────────────────────────────────────────────────
const userAttrUpdater = require('./routes/user-attr-updater');
app.use('/api/user-updater', userAttrUpdater);

// ─── Content Block Search Utility ─────────────────────────────────────────────
// Used by content_block_search.html — credentials via Authorization + MOE-APPKEY headers
// forwarded directly from the browser (utility manages its own auth UI)

function proxyMoeRequest(targetUrl, req, res) {
  let rawBody = '';
  req.on('data', chunk => { rawBody += chunk; });
  req.on('end', async () => {
    try {
      const resp = await axios.post(targetUrl, rawBody, {
        headers: {
          'Content-Type':   'application/json',
          'Authorization':  req.headers['authorization'] || '',
          'MOE-APPKEY':     req.headers['moe-appkey']    || '',
        },
        validateStatus: () => true,
      });
      res.status(resp.status).json(resp.data);
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  });
}

// These routes match what content_block_search.html calls directly
app.post('/proxy',           apiLimiter, (req, res) =>
  proxyMoeRequest(`${MOE_API_BASE}/v1/external/campaigns/content-blocks/search`, req, res));

app.post('/proxy-get-ids',   apiLimiter, (req, res) =>
  proxyMoeRequest(`${MOE_API_BASE}/v1/external/campaigns/content-blocks/get-by-ids`, req, res));

app.post('/proxy-campaigns', apiLimiter, (req, res) =>
  proxyMoeRequest(`${MOE_API_BASE}/core-services/v1/campaigns/search`, req, res));

// ─── Content Block Migration Utility ──────────────────────────────────────────
// cb_migrator.html passes source/target credentials in the request body
// since it needs two separate environments simultaneously.

async function cbProxy(targetPath, req, res, method = 'POST') {
  const creds = credsFromHeaders(req) || credsFromBody(req, 'src') || credsFromBody(req, '');
  if (!creds) return missingCreds(res);

  const { appId, apiKey } = creds;
  const url = `${MOE_API_BASE}${targetPath}`;

  try {
    const resp = await axios({
      method,
      url,
      data:    req.body,
      headers: moeHeaders(appId, apiKey),
      validateStatus: () => true,
    });
    res.status(resp.status).json(resp.data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

app.post('/api/cb/search',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks/search',      req, res));
app.post('/api/cb/get-ids', apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks/get-by-ids',  req, res));
app.post('/api/cb/create',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks',             req, res));
app.post('/api/cb/update',  apiLimiter, (req, res) => cbProxy('/v1/external/campaigns/content-blocks',             req, res, 'PUT'));

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'moengage-tools',
    dc: 'api-101.moengage.com',
    tools: [
      { name: 'Email Template Builder',   url: '/template-builder' },
      { name: 'Content Block Search',     url: '/content-block-search.html' },
      { name: 'Content Block Migration',  url: '/cb-migrator.html' },
      { name: 'Flow Action Nodes Review', url: '/flow-review.html' },
      { name: 'Token Manager',            url: '/token-manager.html' },
      { name: 'User Attribute Updater',   url: '/user-attr-updater.html' },
    ],
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════╗');
  console.log('  ║        MoEngage Tools — Unified Server       ║');
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log(`  ║  http://localhost:${PORT}                        ║`);
  console.log('  ║  DC → api-101.moengage.com                   ║');
  console.log('  ╠══════════════════════════════════════════════╣');
  console.log('  ║  Tools:                                      ║');
  console.log('  ║    /template-builder      Email Builder      ║');
  console.log('  ║    /content-block-search  CB Search          ║');
  console.log('  ║    /cb-migrator           CB Migration       ║');
  console.log('  ║    /flow-review           Flow Review        ║');
  console.log('  ║    /token-manager         Token Manager      ║');
  console.log('  ║    /user-attr-updater     Attr Updater       ║');
  console.log('  ╚══════════════════════════════════════════════╝');
  console.log('');
});
