/**
 * MoEngage Tools - Unified Server
 * Handles:
 *  - MoEngage API proxy (rate-limited)
 *  - Static HTML tools (Campaign Audit, Content Block Search)
 *  - React build (Email Template Builder)
 */

require("dotenv").config();
const express   = require("express");
const axios     = require("axios");
const cors      = require("cors");
const path      = require("path");
const rateLimit = require("express-rate-limit");
const tokenAuth = require("./token-auth");

const app = express();
const PORT = process.env.PORT || 3000;

// ─── MoEngage Config ────────────────────────────────────────────────────────
const MOENGAGE_BASE_URL =
  process.env.MOENGAGE_BASE_URL || "https://api-01.moengage.com";
const MOENGAGE_APP_ID = process.env.MOENGAGE_APP_ID || "";
const MOENGAGE_API_KEY = process.env.MOENGAGE_API_KEY || "";

// Basic Auth header for MoEngage
const moengageAuth = Buffer.from(
  `${MOENGAGE_APP_ID}:${MOENGAGE_API_KEY}`
).toString("base64");

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Sliding-window rate limiter (mirrors your original proxy.js logic)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute window
  max: 25,                    // max 25 requests per window (safe under MoEngage limits)
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Rate limit reached. Please wait before making more requests.",
    retryAfter: 60,
  },
});

// ─── Serve React Build (Email Template Builder) ──────────────────────────────
const reactBuildPath = path.join(__dirname, "client", "build");
app.use("/template-builder", express.static(reactBuildPath));
app.get("/template-builder/*", (req, res) => {
  res.sendFile(path.join(reactBuildPath, "index.html"));
});

// ─── Serve Static HTML Tools ─────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ─── MoEngage API Proxy Routes ───────────────────────────────────────────────

// Generic proxy handler
const moengageProxy = async (req, res) => {
  const targetPath = req.params[0];
  const targetUrl = `${MOENGAGE_BASE_URL}/${targetPath}`;

  try {
    const response = await axios({
      method: req.method,
      url: targetUrl,
      headers: {
        Authorization: `Basic ${moengageAuth}`,
        "Content-Type": "application/json",
        "MOE-APPID": MOENGAGE_APP_ID,
      },
      params: req.query,
      data: req.body,
      timeout: 30000,
    });
    res.status(response.status).json(response.data);
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: err.message };

    // 503 retry hint (mirrors original proxy.js behavior)
    if (status === 503) {
      res.status(503).json({
        error: "MoEngage service temporarily unavailable",
        retryAfter: 5,
        original: data,
      });
    } else {
      res.status(status).json(data);
    }
  }
};

// All MoEngage API calls go through /api/moengage/*
app.use("/api/moengage/*", apiLimiter);
app.all("/api/moengage/*", moengageProxy);

// ─── Campaign Audit – batch search endpoint ──────────────────────────────────
// Wraps multi-term searches so the browser tool doesn't need to call MoEngage directly
app.post("/api/audit/search", apiLimiter, async (req, res) => {
  const { terms = [], limit = 50, offset = 0 } = req.body;

  if (!Array.isArray(terms) || terms.length === 0) {
    return res.status(400).json({ error: "Provide at least one search term." });
  }

  try {
    const results = {};
    for (const term of terms) {
      const response = await axios.get(
        `${MOENGAGE_BASE_URL}/v1/${MOENGAGE_APP_ID}/campaigns`,
        {
          headers: {
            Authorization: `Basic ${moengageAuth}`,
            "MOE-APPID": MOENGAGE_APP_ID,
          },
          params: { search: term, limit, offset },
          timeout: 30000,
        }
      );
      results[term] = response.data;
    }
    res.json(results);
  } catch (err) {
    res.status(err.response?.status || 500).json({
      error: err.message,
      details: err.response?.data,
    });
  }
});

// ─── Content Block Migration Routes ──────────────────────────────────────────
// Source and target env credentials are passed per-request in the body,
// since migration needs two different app IDs / keys simultaneously.
//
// Client sends: { sourceAppId, sourceApiKey, targetAppId, targetApiKey, ...payload }
// Routes:
//   POST /api/cb/search    → search blocks in an env
//   POST /api/cb/get-ids   → fetch full block content by IDs
//   POST /api/cb/create    → create a block in target env

function cbAuth(appId, apiKey) {
  return "Basic " + Buffer.from(`${appId}:${apiKey}`).toString("base64");
}

function cbHeaders(appId, apiKey) {
  return {
    Authorization: cbAuth(appId, apiKey),
    "Content-Type": "application/json",
    "MOE-APPID": appId,
  };
}

// Search content blocks (source or target env)
app.post("/api/cb/search", apiLimiter, async (req, res) => {
  const { appId, apiKey, dc = "01", ...payload } = req.body;
  if (!appId || !apiKey) {
    return res.status(400).json({ error: "appId and apiKey are required." });
  }
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks/search`,
      payload,
      { headers: cbHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Fetch full content block details by IDs
app.post("/api/cb/get-ids", apiLimiter, async (req, res) => {
  const { appId, apiKey, dc = "01", ids = [], is_raw_content_required = true } = req.body;
  if (!appId || !apiKey) {
    return res.status(400).json({ error: "appId and apiKey are required." });
  }
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks/get-by-ids`,
      { ids, is_raw_content_required },
      { headers: cbHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// Create a content block in target env
app.post("/api/cb/create", apiLimiter, async (req, res) => {
  const { appId, apiKey, dc = "01", ...payload } = req.body;
  if (!appId || !apiKey) {
    return res.status(400).json({ error: "appId and apiKey are required." });
  }
  try {
    const response = await axios.post(
      `https://api-${dc}.moengage.com/v1/external/campaigns/content-blocks`,
      payload,
      { headers: cbHeaders(appId, apiKey), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
  }
});

// ─── Token Auth + Flow Proxy Routes ──────────────────────────────────────────
app.use("/api/auth", tokenAuth.router);
app.use("/api/flow", tokenAuth.flowProxy);

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    appId: MOENGAGE_APP_ID || "NOT SET",
    tools: [
      { name: "Email Template Builder",    url: "/template-builder" },
      { name: "Campaign Content Audit",    url: "/content-audit.html" },
      { name: "Content Block Search",      url: "/content-block-search.html" },
      { name: "Content Block Migration",   url: "/cb-migrator.html" },
      { name: "Flow Action Nodes Review",  url: "/flow-review.html" },
      { name: "Token Manager",             url: "/token-manager.html" },
    ],
  });
});

// ─── Root → Landing Page ──────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ MoEngage Tools running on port ${PORT}`);
  console.log(`   → Template Builder   : http://localhost:${PORT}/template-builder`);
  console.log(`   → Content Audit      : http://localhost:${PORT}/content-audit.html`);
  console.log(`   → Content Block      : http://localhost:${PORT}/content-block-search.html`);
  console.log(`   → CB Migration       : http://localhost:${PORT}/cb-migrator.html`);
  console.log(`   → Flow Review        : http://localhost:${PORT}/flow-review.html`);
  console.log(`   → Token Manager      : http://localhost:${PORT}/token-manager.html`);
  console.log(`   → Health             : http://localhost:${PORT}/health`);
});
