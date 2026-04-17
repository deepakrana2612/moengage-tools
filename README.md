# MoEngage Tools — T-Mobile Internal Suite

A unified hosted suite of MoEngage utilities for the MarTech & Campaign Operations team.

## Tools

| Tool | URL | Auth |
|------|-----|------|
| Email Template Builder | `/template-builder` | Basic Auth |
| Campaign Content Audit | `/content-audit.html` | Basic Auth |
| Content Block Search | `/content-block-search.html` | Basic Auth |
| Content Block Migration | `/cb-migrator.html` | Basic Auth (dual env) |
| Flow Action Nodes Review | `/flow-review.html` | Bearer Token |
| Token Manager | `/token-manager.html` | — |

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Copy env template and fill in credentials
cp .env.example .env

# 3. Drop your existing utility HTML files into public/
# 4. Drop your existing React app into client/

# 5. Build React + start server
npm run build
npm start
```

## Deploy to Render

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect this repo — Render reads `render.yaml` automatically
4. Add `MOENGAGE_APP_ID` and `MOENGAGE_API_KEY` in the Render dashboard
5. Deploy → get a live URL in ~3 minutes

## API Routes

```
/api/moengage/*     → MoEngage API proxy (Basic Auth)
/api/audit/search   → Campaign audit batch search
/api/cb/search      → Content block search (source or target env)
/api/cb/get-ids     → Fetch content blocks by IDs
/api/cb/create      → Create content block in target env
/api/auth/*         → Token Manager (set / status / clear)
/api/flow/proxy     → Generic Bearer-auth proxy
/api/flow/versions  → Flow version list
/api/flow/detail    → Flow version JSON fetch
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 3000) |
| `MOENGAGE_BASE_URL` | MoEngage API base URL (e.g. `https://api-01.moengage.com`) |
| `MOENGAGE_APP_ID` | MoEngage App ID |
| `MOENGAGE_API_KEY` | MoEngage API Key |
| `FLOW_BASE_URL` | Flow dashboard base URL (default: `https://dashboard-101.moengage.com`) |
