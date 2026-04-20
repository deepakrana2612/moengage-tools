/**
 * user-manager.js
 * Handles: user CRUD, Render env var sync, Gmail email, password reset tokens
 *
 * User shape in APP_USERS JSON:
 *   { username, password, email, isAdmin, displayName }
 *
 * Required env vars:
 *   APP_USERS          JSON array of users (managed by this module)
 *   RENDER_API_KEY     From render.com → Account Settings → API Keys
 *   RENDER_SERVICE_ID  From your service URL on Render (srv-xxxxxxxx)
 *   GMAIL_USER         Your Gmail address
 *   GMAIL_APP_PASSWORD Gmail App Password (not your regular password)
 *   APP_URL            Your deployed URL e.g. https://moengage-tools.onrender.com
 */

const crypto     = require("crypto");
const nodemailer = require("nodemailer");
const axios      = require("axios");

// ─── Load / Save Users ────────────────────────────────────────────────────────

let _users = [];

function loadUsers() {
  try {
    if (process.env.APP_USERS) {
      const parsed = JSON.parse(process.env.APP_USERS);
      if (Array.isArray(parsed)) {
        _users = parsed;
        return _users;
      }
    }
  } catch {
    console.warn("[UserManager] APP_USERS parse error — starting with empty list");
  }
  _users = [];
  return _users;
}

function getUsers() { return _users; }

function findUser(username) {
  return _users.find(u => u.username.toLowerCase() === username.toLowerCase()) || null;
}

function validateCredentials(username, password) {
  const user = findUser(username);
  if (!user) return null;
  const hash = hashPassword(password);
  return hash === user.password ? user : null;
}

// ─── Password Hashing ─────────────────────────────────────────────────────────
// Uses PBKDF2 with a fixed salt derived from username (no extra dep needed)

function hashPassword(password, username = "") {
  return crypto
    .pbkdf2Sync(password, `moe-tools-${username}-salt`, 10000, 32, "sha256")
    .toString("hex");
}

function generatePassword(length = 12) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$";
  return Array.from(crypto.randomBytes(length))
    .map(b => chars[b % chars.length])
    .join("");
}

// ─── Render API — persist users to APP_USERS env var ─────────────────────────

const RENDER_API = "https://api.render.com/v1";

async function syncToRender(users) {
  const apiKey    = process.env.RENDER_API_KEY;
  const serviceId = process.env.RENDER_SERVICE_ID;

  if (!apiKey || !serviceId) {
    console.warn("[UserManager] RENDER_API_KEY or RENDER_SERVICE_ID not set — changes are in-memory only");
    return { persisted: false, reason: "Render API not configured" };
  }

  try {
    // 1. Fetch current env vars so we don't wipe anything else
    const currentRes = await axios.get(
      `${RENDER_API}/services/${serviceId}/env-vars`,
      { headers: { Authorization: `Bearer ${apiKey}`, Accept: "application/json" } }
    );

    // Render returns [{ envVar: { key, value } }]
    const currentVars = (currentRes.data || []).map(item => item.envVar || item);

    // 2. Replace APP_USERS value, keep everything else
    const updated = currentVars.map(v =>
      v.key === "APP_USERS"
        ? { key: "APP_USERS", value: JSON.stringify(users) }
        : { key: v.key, value: v.value }
    );

    // If APP_USERS wasn't in env yet, add it
    if (!updated.find(v => v.key === "APP_USERS")) {
      updated.push({ key: "APP_USERS", value: JSON.stringify(users) });
    }

    // 3. PUT back
    await axios.put(
      `${RENDER_API}/services/${serviceId}/env-vars`,
      updated,
      { headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" } }
    );

    // 4. Update in-memory
    _users = users;
    process.env.APP_USERS = JSON.stringify(users);

    console.log(`[UserManager] Synced ${users.length} users to Render`);
    return { persisted: true };

  } catch (err) {
    console.error("[UserManager] Render sync failed:", err.response?.data || err.message);
    throw new Error(`Failed to persist to Render: ${err.response?.data?.message || err.message}`);
  }
}

// ─── User CRUD ────────────────────────────────────────────────────────────────

async function createUser({ username, email, displayName, isAdmin = false }) {
  if (findUser(username)) {
    throw new Error(`Username "${username}" already exists.`);
  }

  const plainPassword = generatePassword();
  const user = {
    username:    username.trim().toLowerCase(),
    password:    hashPassword(plainPassword, username.trim().toLowerCase()),
    email:       email.trim(),
    displayName: displayName?.trim() || username,
    isAdmin:     !!isAdmin,
    mustReset:   true,   // force password reset on first login
    createdAt:   new Date().toISOString(),
  };

  const updated = [..._users, user];
  await syncToRender(updated);
  await sendWelcomeEmail(user, plainPassword);

  return { user, plainPassword };
}

async function deleteUser(username) {
  const before = _users.length;
  const updated = _users.filter(u => u.username !== username.toLowerCase());
  if (updated.length === before) throw new Error(`User "${username}" not found.`);
  await syncToRender(updated);
}

async function updatePassword(username, newPassword) {
  const updated = _users.map(u =>
    u.username === username.toLowerCase()
      ? { ...u, password: hashPassword(newPassword, username.toLowerCase()), mustReset: false }
      : u
  );
  if (!updated.find(u => u.username === username.toLowerCase())) {
    throw new Error(`User "${username}" not found.`);
  }
  await syncToRender(updated);
}

// ─── Password Reset Tokens ────────────────────────────────────────────────────

const resetTokens = new Map(); // token → { username, expiry }

function createResetToken(username) {
  const token  = crypto.randomBytes(32).toString("hex");
  const expiry = Date.now() + 60 * 60 * 1000; // 1 hour
  resetTokens.set(token, { username: username.toLowerCase(), expiry });
  return token;
}

function validateResetToken(token) {
  const entry = resetTokens.get(token);
  if (!entry) return null;
  if (Date.now() > entry.expiry) { resetTokens.delete(token); return null; }
  return entry;
}

function consumeResetToken(token) {
  const entry = resetTokens.get(token);
  resetTokens.delete(token);
  return entry;
}

// ─── Gmail SMTP ───────────────────────────────────────────────────────────────

function getTransporter() {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

async function sendWelcomeEmail(user, tempPassword) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    console.warn("[UserManager] Gmail not configured — skipping welcome email");
    return;
  }

  const appUrl      = process.env.APP_URL || "https://moengage-tools.onrender.com";
  const resetToken  = createResetToken(user.username);
  const resetLink   = `${appUrl}/reset-password?token=${resetToken}`;

  const html = `
    <div style="font-family:Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0a0a0a;color:#f5f5f5;border-radius:12px;overflow:hidden">
      <div style="background:#e20074;padding:24px 32px">
        <p style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:rgba(255,255,255,0.7);margin:0 0 4px">T-Mobile · MoEngage</p>
        <h1 style="font-size:22px;font-weight:700;color:#fff;margin:0">You've been added</h1>
      </div>
      <div style="padding:32px">
        <p style="color:#aaa;margin:0 0 24px">Hi ${user.displayName}, your account for the MoEngage Tools suite has been created.</p>
        <div style="background:#141414;border:1px solid #222;border-radius:10px;padding:20px;margin-bottom:24px">
          <p style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#666;margin:0 0 12px">Your credentials</p>
          <p style="margin:0 0 6px;font-size:14px"><span style="color:#666">Username:</span> <strong style="color:#fff">${user.username}</strong></p>
          <p style="margin:0;font-size:14px"><span style="color:#666">Temp password:</span> <strong style="color:#e20074;font-family:monospace;font-size:16px">${tempPassword}</strong></p>
        </div>
        <p style="color:#aaa;font-size:13px;margin:0 0 20px">You must set a new password before you can access the tools. Click the button below:</p>
        <a href="${resetLink}" style="display:inline-block;background:#e20074;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px">Set my password →</a>
        <p style="color:#555;font-size:12px;margin:24px 0 0">This link expires in 1 hour. If you didn't expect this email, ignore it.</p>
      </div>
    </div>
  `;

  await getTransporter().sendMail({
    from:    `"MoEngage Tools" <${process.env.GMAIL_USER}>`,
    to:      user.email,
    subject: "Your MoEngage Tools account",
    html,
  });

  console.log(`[UserManager] Welcome email sent to ${user.email}`);
}

async function sendPasswordResetEmail(username) {
  const user = findUser(username);
  if (!user) throw new Error("User not found.");

  const appUrl     = process.env.APP_URL || "https://moengage-tools.onrender.com";
  const resetToken = createResetToken(username);
  const resetLink  = `${appUrl}/reset-password?token=${resetToken}`;

  const html = `
    <div style="font-family:Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0a0a0a;color:#f5f5f5;border-radius:12px;overflow:hidden">
      <div style="background:#e20074;padding:24px 32px">
        <p style="font-size:11px;letter-spacing:3px;text-transform:uppercase;color:rgba(255,255,255,0.7);margin:0 0 4px">T-Mobile · MoEngage</p>
        <h1 style="font-size:22px;font-weight:700;color:#fff;margin:0">Reset your password</h1>
      </div>
      <div style="padding:32px">
        <p style="color:#aaa;margin:0 0 24px">Hi ${user.displayName}, click the button below to set a new password.</p>
        <a href="${resetLink}" style="display:inline-block;background:#e20074;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px">Reset password →</a>
        <p style="color:#555;font-size:12px;margin:24px 0 0">This link expires in 1 hour. If you didn't request this, ignore it.</p>
      </div>
    </div>
  `;

  await getTransporter().sendMail({
    from:    `"MoEngage Tools" <${process.env.GMAIL_USER}>`,
    to:      user.email,
    subject: "Reset your MoEngage Tools password",
    html,
  });
}

module.exports = {
  loadUsers,
  getUsers,
  findUser,
  validateCredentials,
  createUser,
  deleteUser,
  updatePassword,
  createResetToken,
  validateResetToken,
  consumeResetToken,
  sendPasswordResetEmail,
  hashPassword,
};
