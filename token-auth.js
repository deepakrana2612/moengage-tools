/**
 * token-auth.js
 * Simple in-memory Bearer token store.
 * Token is pasted manually from browser DevTools — no refresh endpoint.
 *
 * Mount in server.js:
 *   const tokenAuth = require('./token-auth');
 *   app.use('/api/auth', tokenAuth.router);
 *   app.use('/api/flow', tokenAuth.flowProxy);
 */

const express = require("express");
const axios   = require("axios");

// ── In-memory store ───────────────────────────────────────────────────────────
const store = {
  bearerToken: null,
  setAt:       null,
  isExpired:   false,   // flipped to true on a 401 response
};

// Best-effort JWT expiry detection (no library needed)
function getJwtExpiry(token) {
  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString()
    );
    return payload.exp ? new Date(payload.exp * 1000) : null;
  } catch {
    return null;
  }
}

// ── Auth Router  /api/auth/* ──────────────────────────────────────────────────
const router = express.Router();

// POST /api/auth/set-token  { bearerToken: "eyJ..." }
router.post("/set-token", (req, res) => {
  const { bearerToken } = req.body;
  if (!bearerToken) return res.status(400).json({ error: "bearerToken is required." });

  store.bearerToken = bearerToken.trim();
  store.setAt       = new Date().toISOString();
  store.isExpired   = false;

  const expiry = getJwtExpiry(store.bearerToken);
  console.log(`[TokenAuth] Token set. JWT expiry: ${expiry?.toISOString() ?? "non-JWT or unknown"}`);
  res.json({ ok: true, expiry: expiry?.toISOString() ?? null });
});

// GET /api/auth/status
router.get("/status", (req, res) => {
  if (!store.bearerToken) return res.json({ hasToken: false });

  const expiry    = getJwtExpiry(store.bearerToken);
  const isExpired = expiry ? new Date() > expiry : store.isExpired;

  res.json({
    hasToken:  true,
    setAt:     store.setAt,
    expiry:    expiry?.toISOString() ?? null,
    isExpired,
  });
});

// POST /api/auth/clear
router.post("/clear", (req, res) => {
  store.bearerToken = null;
  store.setAt       = null;
  store.isExpired   = false;
  console.log("[TokenAuth] Token cleared.");
  res.json({ ok: true });
});

// ── Flow Proxy  /api/flow/* ───────────────────────────────────────────────────
const flowProxy = express.Router();

// POST /api/flow/proxy  { url, method, body, headers }
flowProxy.post("/proxy", async (req, res) => {
  if (!store.bearerToken) {
    return res.status(401).json({
      error: "No Bearer token set. Go to /token-manager.html and paste one.",
    });
  }

  const { url, method = "GET", body, headers: extra = {} } = req.body;
  if (!url) return res.status(400).json({ error: "url is required." });

  try {
    const response = await axios({
      method,
      url,
      headers: {
        Authorization: `Bearer ${store.bearerToken}`,
        "Content-Type": "application/json",
        ...extra,
      },
      data:    body ?? undefined,
      timeout: 30000,
    });
    res.status(response.status).json(response.data);

  } catch (err) {
    const status = err.response?.status || 500;
    if (status === 401) {
      store.isExpired = true;
      return res.status(401).json({
        error:   "Token rejected (401) — grab a fresh one from DevTools.",
        expired: true,
      });
    }
    res.status(status).json(err.response?.data ?? { error: err.message });
  }
});

module.exports = { router, flowProxy };

// ── Flow Review Routes (added to flowProxy) ───────────────────────────────────
// These use the same Bearer token from the Token Manager.
// dashboard-101 is the MoEngage app platform (not the API platform).

const FLOW_BASE = process.env.FLOW_BASE_URL || "https://dashboard-101.moengage.com";

function flowHeaders(bearerToken, flowId) {
  return {
    Authorization:  `Bearer ${bearerToken}`,
    "Content-Type": "application/json",
    Accept:         "application/json",
    page:           `flows/${flowId}`,
    moetraceid:     require("crypto").randomUUID(),
  };
}

// GET /api/flow/versions?flowId=<id>
// Lists all versions for a flow — used to map version number → version ID
flowProxy.get("/versions", async (req, res) => {
  if (!store.bearerToken) {
    return res.status(401).json({ error: "No Bearer token. Set one in /token-manager.html" });
  }
  const { flowId } = req.query;
  if (!flowId) return res.status(400).json({ error: "flowId is required." });

  try {
    const response = await axios.get(
      `${FLOW_BASE}/v1/flow/${flowId}/versions`,
      { headers: flowHeaders(store.bearerToken, flowId), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    const status = err.response?.status || 500;
    if (status === 401) store.isExpired = true;
    res.status(status).json(err.response?.data ?? { error: err.message });
  }
});

// GET /api/flow/detail?flowId=<id>&versionId=<id>
// Fetches the full flow version JSON (action nodes, segments, config)
flowProxy.get("/detail", async (req, res) => {
  if (!store.bearerToken) {
    return res.status(401).json({ error: "No Bearer token. Set one in /token-manager.html" });
  }
  const { flowId, versionId } = req.query;
  if (!flowId || !versionId) {
    return res.status(400).json({ error: "flowId and versionId are required." });
  }

  try {
    const response = await axios.get(
      `${FLOW_BASE}/v1/flows/${flowId}/versions/${versionId}/fetch`,
      { headers: flowHeaders(store.bearerToken, flowId), timeout: 30000 }
    );
    res.status(response.status).json(response.data);
  } catch (err) {
    const status = err.response?.status || 500;
    if (status === 401) store.isExpired = true;
    res.status(status).json(err.response?.data ?? { error: err.message });
  }
});
