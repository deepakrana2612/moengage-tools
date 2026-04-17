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
const express   = require("express");
const axios     = require("axios");
const cors      = require("cors");
const path      = require("path");
const rateLimit = require("express-rate-limit");
const tokenAuth = require("./token-auth");

const app  = express();
const PORT = process.env.PORT || 3000;

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
      { name: "Email Template Builder",   url: "/template-builder" },
      { name: "Campaign Content Audit",   url: "/content-audit.html" },
      { name: "Content Block Search",     url: "/content-block-search.html" },
      { name: "Content Block Migration",  url: "/cb-migrator.html" },
      { name: "Flow Action Nodes Review", url: "/flow-review.html" },
      { name: "Token Manager",            url: "/token-manager.html" },
    ],
  });
});

// ─── Root ─────────────────────────────────────────────────────────────────────
app.get("/", (_req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ MoEngage Tools running on port ${PORT}`);
  console.log(`   DC fixed to         : 101`);
  console.log(`   Auth mode           : per-request (no server-side credentials)`);
  console.log(`   → Dashboard         : http://localhost:${PORT}`);
  console.log(`   → Template Builder  : http://localhost:${PORT}/template-builder`);
  console.log(`   → Content Audit     : http://localhost:${PORT}/content-audit.html`);
  console.log(`   → Content Block     : http://localhost:${PORT}/content-block-search.html`);
  console.log(`   → CB Migration      : http://localhost:${PORT}/cb-migrator.html`);
  console.log(`   → Flow Review       : http://localhost:${PORT}/flow-review.html`);
  console.log(`   → Token Manager     : http://localhost:${PORT}/token-manager.html`);
  console.log(`   → Health            : http://localhost:${PORT}/health`);
});
