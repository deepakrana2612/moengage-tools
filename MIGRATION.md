# Migration Guide — Plugging Your Existing Code In

## Folder Structure

```
moengage-tools/
├── server.js               ← NEW unified server (replaces proxy.js)
├── package.json            ← NEW root package
├── render.yaml             ← NEW Render deploy config
├── .env.example            ← NEW env template
├── .gitignore
│
├── public/                 ← Your static HTML tools go here
│   ├── index.html          ← NEW dashboard landing page
│   ├── content-audit.html          ← MOVE your audit tool here
│   └── content-block-search.html   ← MOVE your block search tool here
│
└── client/                 ← Your React Email Template Builder
    ├── package.json        ← your existing React package.json
    ├── src/                ← your existing React src/
    └── public/             ← your existing React public/
```

---

## Step 1 — Move Your Static HTML Tools

Copy your existing HTML files into `public/`:

```bash
cp path/to/content_block_search.html  public/content-block-search.html
cp path/to/campaign_audit.html        public/content-audit.html
```

---

## Step 2 — Move Your React App

Copy your existing React project into `client/`:

```bash
cp -r path/to/your-react-app/* client/
```

Make sure `client/package.json` has `"homepage": "."` so asset paths work correctly
when served from `/template-builder`:

```json
{
  "homepage": ".",
  ...
}
```

---

## Step 3 — Update API Calls in Your HTML Tools

Your HTML tools currently call `http://localhost:3000/...`

Change all proxy calls to use **relative URLs** so they work both locally and on Render:

```js
// BEFORE (localhost hardcoded)
const res = await fetch("http://localhost:3000/v1.0/custom-templates/...");

// AFTER (relative — works everywhere)
const res = await fetch("/api/moengage/v1.0/custom-templates/...");
```

The server.js proxy strips `/api/moengage` and forwards the rest to MoEngage.

---

## Step 4 — Local Dev Test

```bash
# From project root
cp .env.example .env
# Edit .env with your real MOENGAGE_APP_ID and MOENGAGE_API_KEY

npm install
npm run build        # builds React app into client/build/
npm start            # starts the server on :3000
```

Visit:
- http://localhost:3000                        → Dashboard
- http://localhost:3000/template-builder       → Email Template Builder
- http://localhost:3000/content-audit.html     → Campaign Audit
- http://localhost:3000/content-block-search.html → Content Block Search

---

## Step 5 — Deploy to Render

1. Push this folder to a **GitHub repo** (public or private — Render supports both)
2. Go to [render.com](https://render.com) → New → **Blueprint**
3. Connect the repo — Render reads `render.yaml` automatically
4. In the Render dashboard, set your secret env vars:
   - `MOENGAGE_APP_ID`
   - `MOENGAGE_API_KEY`
5. Hit **Deploy** — done. You'll get a URL like `https://moengage-tools.onrender.com`

---

## Free Tier Note

On Render's free tier, the server **spins down after 15 minutes of inactivity**.
The first request after that takes ~30 seconds to cold-start.

**Fix options:**
- Upgrade to Starter ($7/mo) → always-on
- Or use [UptimeRobot](https://uptimerobot.com) (free) to ping `/health` every 10 min
  to keep it warm at zero cost
