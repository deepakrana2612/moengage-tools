/**
 * tools-registry.js
 * Central registry of all utilities in the suite.
 *
 * To add a new tool in future — just add one entry to TOOLS.
 * The rest (access control, admin UI, user assignment) picks it up automatically.
 */

const TOOLS = [
  {
    id:          "template-builder",
    name:        "Email Template Builder",
    description: "Create and update MoEngage custom email templates.",
    url:         "/template-builder.html",
    icon:        "✉️",
    htmlFile:    "template-builder.html",
    apiRoutes:   ["/api/template"],
  },
  {
    id:          "content-search",
    name:        "Content Block & Campaign Search",
    description: "Search across content blocks and 2,500+ campaigns for specific text.",
    url:         "/content-block-search.html",
    icon:        "🔍",
    htmlFile:    "content-block-search.html",
    apiRoutes:   ["/proxy", "/proxy-get-ids", "/proxy-campaigns"],
  },
  {
    id:          "cb-migration",
    name:        "Content Block Migration",
    description: "Migrate content blocks between MoEngage environments.",
    url:         "/cb-migrator.html",
    icon:        "🚚",
    htmlFile:    "cb-migrator.html",
    apiRoutes:   ["/cb-search", "/cb-get-ids", "/cb-create", "/cb-update"],
  },
  {
    id:          "flow-review",
    name:        "Flow Action Nodes Review",
    description: "Fetch and inspect the full JSON of any Flow version.",
    url:         "/flow-review.html",
    icon:        "🔬",
    htmlFile:    "flow-review.html",
    apiRoutes:   ["/api/flow"],
  },
  {
  id:          "user-attr-updater",
  name:        "User Attribute Updater",
  description: "Fetch a user by ID and update any standard or custom attribute.",
  url:         "/user-attr-updater.html",
  icon:        "✏️",
  htmlFile:    "user-attr-updater.html",
  apiRoutes:   ["/api/user-updater"],
},
];

// Quick lookups
const TOOL_BY_ID       = Object.fromEntries(TOOLS.map(t => [t.id, t]));
const TOOL_BY_HTML     = Object.fromEntries(TOOLS.filter(t => t.htmlFile).map(t => [t.htmlFile, t]));

// All API route prefixes that are tool-gated (for middleware)
const ALL_GATED_ROUTES = TOOLS.flatMap(t => t.apiRoutes);

function getAll()            { return TOOLS; }
function getById(id)         { return TOOL_BY_ID[id] || null; }
function getByHtmlFile(file) { return TOOL_BY_HTML[file] || null; }
function getByApiRoute(path) {
  return TOOLS.find(t => t.apiRoutes.some(r => path.startsWith(r))) || null;
}
function isGatedRoute(path)  {
  return ALL_GATED_ROUTES.some(r => path.startsWith(r));
}

module.exports = { getAll, getById, getByHtmlFile, getByApiRoute, isGatedRoute };
