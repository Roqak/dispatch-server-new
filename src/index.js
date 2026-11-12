// dispatch-server on Cloudflare Workers.
// Plain-JS ES module implementing the same contract as the Rust binary in
// server/ (see server/README.md and server/src/{auth,proxy,admin,db}.rs).
// Default export: { fetch }. Modules format, no build step.
//
// Bindings:
//   DB      — D1 database (users, tokens, settings, Postman accounts, uid maps, audit)
//   ASSETS  — static assets binding serving ./admin (the admin panel)
//   vars    — REQUIRE_AUTH ("true"|"false"), POSTMAN_REGION ("us"|"eu"),
//             optional POSTMAN_API_BASE override, optional PBKDF2_ITERATIONS
//   secrets — SECRET_KEY (encrypts Postman keys added in the panel), optional
//             POSTMAN_API_KEY, ADMIN_PASSWORD (open mode), PBKDF2_ITERATIONS

const ROLES = ["viewer", "editor", "creator", "admin"];
const ROLE_RANK = { viewer: 0, editor: 1, creator: 2, admin: 3 };
const RATE_LIMIT_HEADER = "x-ratelimit-remaining-month";
const NO_ACCOUNT_MESSAGE = "This server has no Postman account connected and no Dispatch workspaces yet. An admin can add either in the admin panel.";
// Per-workspace list cache for granted principals; keys are scoped per grant
// set so two differently-granted principals never share stale views.
const LIST_CACHE_TTL = 60_000;
const listCache = new Map(); // cacheScope|/base|workspace -> { at, rate, value }

// The documented Postman API surface; everything else is rejected.
const PREFIXES = [
  "/workspaces", "/collections", "/environments", "/apis", "/monitors",
  "/mock-servers", "/schemas", "/integrations", "/scim",
];

// ---------------------------------------------------------------------------
// small response helpers (every API response gets CORS, per the contract)

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
  "Access-Control-Max-Age": "86400",
};

function responseWithCors(status, body, extra) {
  const headers = { ...CORS, ...(extra || {}) };
  if (body === undefined || body === null || (body === "" && (status === 204 || status === 304 || status === 101))) {
    return new Response(null, { status, headers });
  }
  if (typeof body === "string") return new Response(body, { status, headers });
  return new Response(JSON.stringify(body), {
    status, headers: { ...headers, "Content-Type": "application/json" },
  });
}

function jsonOut(status, value, rate) {
  return responseWithCors(status, value, rate ? { [RATE_LIMIT_HEADER]: rate } : {});
}

function fail(status, message) {
  return jsonOut(status, { error: message });
}

function parseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

// ---------------------------------------------------------------------------
// D1 helpers

const USER_COLS = "id, email, password_hash, role, workspace_grants, created_at";

async function dbFirst(env, sql, args = []) {
  let stmt = env.DB.prepare(sql);
  if (args.length) stmt = stmt.bind(...args);
  return stmt.first();
}
async function dbAll(env, sql, args = []) {
  let stmt = env.DB.prepare(sql);
  if (args.length) stmt = stmt.bind(...args);
  return (await stmt.all()).results;
}
async function dbRun(env, sql, args = []) {
  let stmt = env.DB.prepare(sql);
  if (args.length) stmt = stmt.bind(...args);
  return stmt.run();
}

function parseGrants(text) {
  if (text === null || text === undefined) return null;
  const parsed = parseJson(text);
  return parsed.ok && Array.isArray(parsed.value)
    ? parsed.value.filter((v) => typeof v === "string")
    : null;
}

// RFC 3339 UTC with milliseconds, like db.rs::now_iso().
function nowIso() {
  return new Date().toISOString();
}

// Best-effort audit row: (ts, user_id, email, action, method, path, status).
// D1 can't bind JS null, so nullable columns become SQL NULL literals.
async function auditInsert(env, userId, email, method, path, status, action = "proxy") {
  try {
    const slots = ["?", userId === null ? "NULL" : "?", email === null ? "NULL" : "?", "?", "?", "?", "?"];
    const args = [nowIso()];
    if (userId !== null) args.push(userId);
    if (email !== null) args.push(email);
    args.push(action, method, path, status);
    await dbRun(env,
      `INSERT INTO audit (ts, user_id, email, action, method, path, status) VALUES (${slots.join(", ")})`,
      args);
  } catch {
    // best effort, like the binary
  }
}

// ---------------------------------------------------------------------------
// crypto: passwords (PBKDF2-SHA256) and bearer tokens

function pbkdf2Iterations(env) {
  const n = typeof env.PBKDF2_ITERATIONS === "string"
    ? parseInt(env.PBKDF2_ITERATIONS, 10)
    : Number(env.PBKDF2_ITERATIONS);
  return Number.isFinite(n) && n > 0 ? n : 10000;
}

async function hashPassword(password, env) {
  const iterations = pbkdf2Iterations(env);
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return `pbkdf2$${iterations}$${b64u8(salt)}$${b64u8(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const [, iters, saltB64, hashB64] = parts;
  try {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: parseInt(iters, 10) },
      key, 256);
    return b64u8(new Uint8Array(bits)) === hashB64;
  } catch {
    return false;
  }
}

// 32 random hex chars; only the SHA-256 hex of the token is stored.
async function issueToken(env, userId) {
  const token = [...crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  await dbRun(env, "INSERT INTO tokens (token_hash, user_id, created_at) VALUES (?, ?, ?)", [
    await sha256Hex(token), userId, nowIso(),
  ]);
  return token;
}

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64u8 = (u8) => btoa(String.fromCharCode(...u8));

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// principals: { userId, email, role, grants: null | [workspaceIds] }

function principalOf(userId, email, role, grants) {
  return { userId, email, role, grants };
}

function rankOf(principal) {
  return ROLE_RANK[principal.role] ?? -1;
}

// Admins and NULL-grant principals bypass scoping entirely; a granted
// principal may only touch workspaces in its list.
function scopeOf(principal) {
  if (principal.role === "admin" || principal.grants === null) return null;
  return principal.grants;
}

// Resolves a raw token to its principal. In enforced mode user 0 (the
// open-mode admin principal) is deliberately rejected; dangling tokens
// (e.g. of a deleted user) are treated as invalid.
async function tokenPrincipal(env, token, requireAuth) {
  const row = await dbFirst(env, "SELECT user_id FROM tokens WHERE token_hash = ?", [await sha256Hex(token)]);
  if (!row) return null;
  if (row.user_id === 0) {
    if (requireAuth) return null;
    return principalOf(0, "admin", "admin", null);
  }
  const user = await dbFirst(env, `SELECT ${USER_COLS} FROM users WHERE id = ?`, [row.user_id]);
  if (!user) return null;
  return principalOf(user.id, user.email, user.role, parseGrants(user.workspace_grants));
}

async function bearerOf(request) {
  const m = /^bearer\s+(.+)$/i.exec((request.headers.get("Authorization") || "").trim());
  return m ? m[1].trim() : null;
}

// Enforced mode always requires a valid Bearer token. Open mode treats every
// request as an implicit editor with no grants, unless the caller happens to
// present a valid token (e.g. the admin principal from /auth/admin-login).
async function resolvePrincipal(env, request, requireAuth) {
  const token = await bearerOf(request);
  if (!requireAuth) {
    if (token) {
      const p = await tokenPrincipal(env, token, requireAuth);
      if (p) return p;
    }
    return principalOf(null, null, "editor", null);
  }
  if (!token) throw fail(401, "Invalid or missing token");
  const p = await tokenPrincipal(env, token, requireAuth);
  if (!p) throw fail(401, "Invalid or missing token");
  return p;
}

// Display names derived from the account email, as the desktop client's
// profile view expects: username and fullName are the email's local part.
function displayNames(email) {
  const local = email.split("@")[0];
  return [local, local];
}

// The binary accepts any non-empty string containing "@".
function emailOf(value) {
  const email = value && typeof value.email === "string" ? value.email : null;
  return email && email.includes("@") ? email : null;
}

function userJson(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    workspace_grants: parseGrants(user.workspace_grants),
    created_at: user.created_at,
  };
}

// --------------------------------------------------------------------------
// workspace-scoped resource config (sqlite map table, Postman list key,
// singular key for create responses, upstream base path)

function dialect(family) {
  return family === "collections"
    ? { table: "collections_map", listKey: "collections", thing: "collection", base: "/collections" }
    : { table: "environments_map", listKey: "environments", thing: "environment", base: "/environments" };
}

function familyOf(path) {
  for (const prefix of PREFIXES) {
    if (path.startsWith(prefix)) {
      const rest = path.slice(prefix.length);
      // "/collectionsx" must not match; "/collections" and "/collections/…" must.
      if (rest === "" || rest.startsWith("/")) {
        return { family: prefix.slice(1), rest: rest.replace(/^\/+/, "") };
      }
    }
  }
  return null;
}

// Minimum role for each proxied call, plus the message for when that exact
// tier is what was missed.
function minRole(family, method, rest) {
  const hasUid = rest !== "";
  // SCIM and integrations act on the whole Postman team behind a key.
  if (family === "scim" || family === "integrations") {
    return [ROLE_RANK.admin, "Only admins can do this"];
  }
  if (method === "GET" || method === "HEAD") return [ROLE_RANK.viewer, ""];
  if (method === "DELETE") {
    if (hasUid && (family === "collections" || family === "environments")) {
      return [ROLE_RANK.admin, "Only admins can delete collections and environments"];
    }
    if (family === "workspaces" && hasUid && !rest.includes("/")) {
      return [ROLE_RANK.admin, "Only admins can delete workspaces"];
    }
    return [ROLE_RANK.editor, ""];
  }
  // POST / PATCH / PUT and anything else: editor+, while creating a
  // collection or workspace and touching apis/monitors/mock-servers/schemas
  // needs creator+.
  const creatorOnly = (!hasUid && (family === "collections" || family === "workspaces")) ||
    ["apis", "monitors", "mock-servers", "schemas"].includes(family);
  return creatorOnly
    ? [ROLE_RANK.creator, "This action requires the creator role or above"]
    : [ROLE_RANK.editor, ""];
}

// Only uids are compared against the map; decode the percent-encoding the
// URL carried so "1%2Ddemo" matches the stored "1-demo".
function percentDecode(input) {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

// The `workspace` query parameter, if present and non-empty.
function queryWorkspace(query) {
  for (const pair of query.split("&")) {
    const idx = pair.indexOf("=");
    if (idx > 0 && pair.slice(0, idx) === "workspace" && pair.slice(idx + 1)) {
      return pair.slice(idx + 1);
    }
  }
  return null;
}

// Rewrites/inserts the `workspace` query parameter, leaving other params.
function queryWithWorkspace(query, workspace) {
  const kept = [];
  let replaced = false;
  for (const pair of query.split("&").filter(Boolean)) {
    if (pair.split("=")[0] === "workspace") {
      kept.push(`workspace=${workspace}`);
      replaced = true;
    } else {
      kept.push(pair);
    }
  }
  if (!replaced) kept.push(`workspace=${workspace}`);
  return kept.join("&");
}

// The caller's declared workspace: body["workspace"]["id"], then
// body["workspaceId"], then the `workspace` query parameter.
function findWorkspaceIn(value, query) {
  const inBody = value && (value.workspace?.id || value.workspaceId);
  if (typeof inBody === "string" && inBody) return inBody;
  return queryWorkspace(query);
}

// Forces the declared workspace into the body: an existing workspace object
// simply gets its `id` replaced; otherwise `workspace` (and any explicit
// `workspaceId`) is set to the chosen workspace.
function forceWorkspaceInBody(value, workspace) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if (value.workspace && typeof value.workspace === "object" && !Array.isArray(value.workspace)) {
      value.workspace.id = workspace;
    } else {
      value.workspace = { id: workspace };
    }
    if ("workspaceId" in value) value.workspaceId = workspace;
  }
}

// One entry (object) or a whole list (array) from a list/create response.
function listEntries(value, listKey, thing) {
  if (value && Array.isArray(value[listKey])) return value[listKey];
  const single = value ? value[thing] : null;
  return single && typeof single === "object" && !Array.isArray(single) ? [single] : null;
}

// Remembers uid → workspace rows from a per-workspace list response (an
// array) or a create response (a single object). Best effort: rows that
// can't be attributed (no uid field) are skipped.
async function rememberEntries(env, table, workspaceId, entries) {
  for (const entry of entries) {
    const uid = typeof entry.uid === "string" ? entry.uid
      : typeof entry.id === "string" ? entry.id : null;
    if (!uid) continue;
    const name = typeof entry.name === "string" ? entry.name : null;
    const updatedAt = typeof entry.updatedAt === "string" ? entry.updatedAt : null;
    // D1 can't bind JS null; use SQL NULL literals for nullable columns.
    const slots = ["?", "?", name === null ? "NULL" : "?", updatedAt === null ? "NULL" : "?"];
    const args = [uid, workspaceId];
    if (name !== null) args.push(name);
    if (updatedAt !== null) args.push(updatedAt);
    try {
      await dbRun(env,
        `INSERT INTO ${table} (uid, workspace_id, name, updated_at) VALUES (${slots.join(", ")}) ` +
        "ON CONFLICT(uid) DO UPDATE SET workspace_id = excluded.workspace_id, name = excluded.name, updated_at = excluded.updated_at",
        args);
    } catch {
      // best effort, like the binary
    }
  }
}

// Filters a GET /workspaces response down to the granted workspace IDs.
function filterWorkspaces(value, allowed) {
  if (!value || typeof value !== "object" || !Array.isArray(value.workspaces)) return null;
  value.workspaces = value.workspaces.filter((ws) => ws && allowed.includes(ws.id));
  return value;
}

// Viewer + GET on a single collection/environment ⇒ strip `currentValue`s.
function shouldRedact(principal, method, rest) {
  return principal.role === "viewer" && (method === "GET" || method === "HEAD") &&
    rest !== "" && !rest.includes("/");
}

// Drops every `currentValue` field from a JSON body, keeping `value`.
function stripCurrentValues(value) {
  const walk = (node) => {
    if (Array.isArray(node)) {
      node.forEach(walk);
    } else if (node && typeof node === "object") {
      delete node.currentValue;
      for (const child of Object.values(node)) walk(child);
    }
  };
  walk(value);
  return value;
}

// ---------------------------------------------------------------------------
// connected Postman accounts: keys added in the admin panel (encrypted with
// SECRET_KEY, never returned by any endpoint), plus POSTMAN_API_KEY if set.

const ENV_ACCOUNT_ID = 0;
const SECRET_PLACEHOLDER = "replace-with-at-least-32-random-characters";
const KEY_AAD = new TextEncoder().encode("dispatch-postman-key");
// A refused or rate-limited call did nothing upstream, so another key that can
// reach the same workspace may still serve it.
const TRY_NEXT_ACCOUNT = new Set([401, 403, 404, 429]);
const WORKSPACE_SYNC_INTERVAL = 30_000;
let lastWorkspaceSync = 0;

function secretKeyOf(env) {
  const secret = typeof env.SECRET_KEY === "string" ? env.SECRET_KEY.trim() : "";
  return secret.length >= 32 && secret !== SECRET_PLACEHOLDER ? secret : null;
}

const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));

async function aesKey(secret) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// Stored as v1.<hex iv>.<hex ciphertext+tag>; server/src/accounts.rs writes the
// same format.
async function encryptKey(secret, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const out = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: KEY_AAD },
    await aesKey(secret), new TextEncoder().encode(plain));
  return `v1.${toHex(iv)}.${toHex(new Uint8Array(out))}`;
}

async function decryptKey(secret, stored) {
  const [version, iv, data] = String(stored || "").split(".");
  if (version !== "v1" || !iv || !data) return null;
  try {
    const out = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromHex(iv), additionalData: KEY_AAD },
      await aesKey(secret), fromHex(data));
    return new TextDecoder().decode(out);
  } catch {
    return null;
  }
}

function postmanBase(env, region) {
  if (typeof env.POSTMAN_API_BASE === "string" && env.POSTMAN_API_BASE) {
    return env.POSTMAN_API_BASE.replace(/\/+$/, "");
  }
  return region === "eu" ? "https://api.eu.postman.com" : "https://api.postman.com";
}

function envAccountKey(env) {
  return typeof env.POSTMAN_API_KEY === "string" ? env.POSTMAN_API_KEY.trim() : "";
}

function envCred(env) {
  const key = envAccountKey(env);
  return key
    ? { id: ENV_ACCOUNT_ID, label: "Server environment key", key, base: postmanBase(env, env.POSTMAN_REGION) }
    : null;
}

// Every account the server can currently use. A key that can't be decrypted
// (SECRET_KEY changed or missing) is left out and reported in the admin panel.
async function connectedAccounts(env) {
  const creds = [];
  const fromEnv = envCred(env);
  if (fromEnv) creds.push(fromEnv);
  const rows = await dbAll(env, "SELECT id, label, region, key_ciphertext FROM postman_accounts ORDER BY id")
    .catch(() => []);
  const secret = secretKeyOf(env);
  if (!secret) return creds;
  for (const row of rows) {
    const key = await decryptKey(secret, row.key_ciphertext);
    if (key) creds.push({ id: row.id, label: row.label, key, base: postmanBase(env, row.region) });
  }
  return creds;
}

// ---------------------------------------------------------------------------
// the upstream (Postman) call

// Forward method + path + query + JSON body, trying each account in turn while
// the upstream refuses. Postman's status, body and rate-limit header come back
// verbatim from the last account tried.
async function forwardToPostman(creds, method, path, query, bodyJson) {
  if (creds.length === 0) {
    return { kind: "error", response: fail(404, "No connected Postman account can reach this workspace") };
  }
  let last = null;
  for (let i = 0; i < creds.length; i += 1) {
    let url = `${creds[i].base}${path}`;
    if (query) url += `?${query}`;
    const init = {
      method,
      headers: { "X-Api-Key": creds[i].key, Accept: "application/json" },
      signal: AbortSignal.timeout(60000),
    };
    if (bodyJson !== null && bodyJson !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(bodyJson);
    }
    let resp;
    try {
      resp = await fetch(url, init);
    } catch {
      last = { kind: "error",
        response: fail(502, "Couldn't reach the Postman API. Check the server's internet connection.") };
      continue;
    }
    const text = await resp.text();
    const parsed = parseJson(text);
    last = {
      kind: "upstream",
      status: resp.status,
      rate: resp.headers.get(RATE_LIMIT_HEADER),
      contentType: resp.headers.get("Content-Type") || "application/json",
      text,
      value: parsed.ok ? parsed.value : null,
      account: creds[i],
    };
    if (!TRY_NEXT_ACCOUNT.has(resp.status)) return last;
  }
  return last;
}

// A live upstream response passed through verbatim (status, body,
// content-type, rate-limit header), optionally with a rewritten JSON body.
function upstreamResponse(upstream, valueOverride) {
  if (valueOverride !== undefined) return jsonOut(upstream.status, valueOverride, upstream.rate);
  if (upstream.kind === "upstream") {
    return responseWithCors(upstream.status, upstream.text, {
      "Content-Type": upstream.contentType,
      ...(upstream.rate ? { [RATE_LIMIT_HEADER]: upstream.rate } : {}),
    });
  }
  return jsonOut(upstream.status, upstream.value, upstream.rate);
}

function upstreamIsSuccess(upstream) {
  return upstream.kind === "upstream" && upstream.status >= 200 && upstream.status < 300;
}

// ---------------------------------------------------------------------------
// workspace → account routing

// Asks every account for its workspaces. An unfiltered list replaces what's
// remembered for that account, so workspaces created in or removed from Postman
// are picked up.
async function syncWorkspaces(env, creds, query = "") {
  const results = await Promise.all(creds.map(async (cred) => ({
    cred, upstream: await forwardToPostman([cred], "GET", "/workspaces", query, null),
  })));
  if (query) return results;
  lastWorkspaceSync = Date.now();
  for (const { cred, upstream } of results) {
    if (!upstreamIsSuccess(upstream) || !Array.isArray(upstream.value?.workspaces)) continue;
    const statements = [env.DB.prepare("DELETE FROM workspace_accounts WHERE account_id = ?").bind(cred.id)];
    for (const ws of upstream.value.workspaces) {
      if (!ws || typeof ws.id !== "string") continue;
      statements.push(env.DB.prepare(
        "INSERT OR REPLACE INTO workspace_accounts (workspace_id, account_id, name, type) VALUES (?, ?, ?, ?)",
      ).bind(ws.id, cred.id, String(ws.name ?? ws.id), String(ws.type ?? "")));
    }
    await env.DB.batch(statements).catch(() => {});
  }
  return results;
}

// The accounts that can reach a workspace. An unknown id triggers one throttled
// refresh, since it may have been created in Postman moments ago.
async function workspaceCreds(env, creds, workspace) {
  const lookup = async () => {
    const rows = await dbAll(env, "SELECT account_id FROM workspace_accounts WHERE workspace_id = ?", [workspace])
      .catch(() => []);
    const ids = new Set(rows.map((row) => row.account_id));
    return creds.filter((cred) => ids.has(cred.id));
  };
  const found = await lookup();
  if (found.length || Date.now() - lastWorkspaceSync < WORKSPACE_SYNC_INTERVAL) return found;
  await syncWorkspaces(env, creds);
  return lookup();
}

// The merged workspace list. One account failing doesn't hide the others; two
// accounts seeing the same workspace show it once. Different workspaces sharing
// a name (every account has a "My Workspace") get the account's label added.
async function mergedWorkspaces(env, creds, query, allowed) {
  const results = await syncWorkspaces(env, creds, query);
  const merged = new Map();
  let failure = null;
  let rate = null;
  let first = null;
  for (const { cred, upstream } of results) {
    if (!upstreamIsSuccess(upstream) || !Array.isArray(upstream.value?.workspaces)) {
      failure = failure || upstream;
      continue;
    }
    first = first || upstream.value;
    rate = upstream.rate;
    for (const ws of upstream.value.workspaces) {
      if (!ws || (allowed && !allowed.includes(ws.id)) || merged.has(ws.id)) continue;
      merged.set(ws.id, { ws, label: cred.label });
    }
  }
  if (!first) return failure.kind === "error" ? failure.response : upstreamResponse(failure);
  const nameCounts = new Map();
  for (const { ws } of merged.values()) nameCounts.set(ws.name, (nameCounts.get(ws.name) || 0) + 1);
  const workspaces = [...merged.values()].map(({ ws, label }) =>
    nameCounts.get(ws.name) > 1 ? { ...ws, name: `${ws.name} (${label})` } : ws);
  return jsonOut(200, { ...first, workspaces }, rate);
}

// ---------------------------------------------------------------------------
// proxy internals

// Per-workspace list fetch: answers from the 60s cache when fresh; on a
// cache miss calls upstream, then populates cache and the uid map.
async function cachedWorkspaceList(env, creds, family, query, workspace, cacheScope) {
  const { base, table, listKey, thing } = dialect(family);
  const cacheKey = `${cacheScope}|${base}|${workspace}`;
  const cached = listCache.get(cacheKey);
  if (cached && Date.now() - cached.at < LIST_CACHE_TTL) {
    return { kind: "cached", status: 200, rate: cached.rate, value: cached.value };
  }
  const route = await workspaceCreds(env, creds, workspace);
  const upstream = await forwardToPostman(route, "GET", base, queryWithWorkspace(query, workspace), null);
  if (upstream.kind === "error") return upstream;
  if (upstreamIsSuccess(upstream) && upstream.value) {
    const entries = listEntries(upstream.value, listKey, thing);
    if (entries) await rememberEntries(env, table, workspace, entries);
    listCache.set(cacheKey, { at: Date.now(), rate: upstream.rate, value: upstream.value });
  }
  return upstream;
}

// Merges the per-workspace list responses of every granted workspace into one
// list. A workspace that fails is skipped while another succeeded, so one
// revoked key doesn't hide everything; failures are never cached.
async function mergedLists(env, creds, family, allowed, cacheScope) {
  const { listKey, thing } = dialect(family);
  const merged = [];
  let rate = null;
  let responseKey = listKey;
  let succeeded = false;
  let failure = null;
  for (const workspace of allowed) {
    const upstream = await cachedWorkspaceList(env, creds, family, "", workspace, cacheScope);
    if (upstream.kind === "error" || (!upstreamIsSuccess(upstream) && upstream.kind !== "cached")) {
      failure = failure || upstream;
      continue;
    }
    succeeded = true;
    if (upstream.value && typeof upstream.value === "object") {
      const hit = Object.keys(upstream.value).find((k) => k === listKey || k === thing);
      if (hit) responseKey = hit;
    }
    const entries = upstream.value ? listEntries(upstream.value, listKey, thing) : null;
    if (entries) merged.push(...entries);
    rate = upstream.rate;
  }
  if (!succeeded && failure) return failure.kind === "error" ? failure.response : upstreamResponse(failure);
  return jsonOut(200, { [responseKey]: merged }, rate);
}

// GET on the list endpoint with grants: an explicitly requested workspace is
// served from cache/upstream if granted; otherwise every granted workspace's
// lists are fetched (60s cached) and merged.
async function listScoped(env, creds, family, query, allowed, cacheScope) {
  const { listKey } = dialect(family);
  if (allowed.length === 0) return jsonOut(200, { [listKey]: [] });
  const requested = queryWorkspace(query);
  if (requested && allowed.includes(requested)) {
    const upstream = await cachedWorkspaceList(env, creds, family, query, requested, cacheScope);
    if (upstream.kind === "error") return upstream.response;
    if (upstream.kind === "cached") return jsonOut(200, upstream.value, upstream.rate);
    return upstreamResponse(upstream);
  }
  if (requested) return fail(403, "This workspace isn't in one of your workspaces");
  return mergedLists(env, creds, family, allowed, cacheScope);
}

// POST /collections or /environments with grants: force the workspace in the
// body to an allowed one (defaulting to the first), keep the query param in
// sync for clients that carry the workspace there, and cache the mapping
// from the create response.
async function createScoped(env, creds, family, query, bodyJson, allowed) {
  const { table, listKey, thing, base } = dialect(family);
  if (allowed.length === 0) return fail(403, "You have no granted workspaces");
  if (bodyJson === null || typeof bodyJson !== "object") return fail(400, "Body must be valid JSON");
  const existing = findWorkspaceIn(bodyJson, query);
  const chosen = existing !== null && allowed.includes(existing) ? existing : allowed[0];
  forceWorkspaceInBody(bodyJson, chosen);
  const route = await workspaceCreds(env, creds, chosen);
  const upstream = await forwardToPostman(route, "POST", base, queryWithWorkspace(query, chosen), bodyJson);
  if (upstream.kind === "error") return upstream.response;
  if (upstreamIsSuccess(upstream) && upstream.value) {
    const entries = listEntries(upstream.value, listKey, thing);
    if (entries) await rememberEntries(env, table, chosen, entries);
  }
  return upstreamResponse(upstream);
}

// A list with no workspace named, for a principal with no grants to scope by:
// every account's list, each collection or environment once.
async function mergedAcrossAccounts(creds, family, query) {
  const { base, listKey } = dialect(family);
  const seen = new Map();
  let failure = null;
  let succeeded = false;
  let rate = null;
  for (const cred of creds) {
    const upstream = await forwardToPostman([cred], "GET", base, query, null);
    if (!upstreamIsSuccess(upstream)) {
      failure = failure || upstream;
      continue;
    }
    succeeded = true;
    rate = upstream.rate;
    for (const entry of upstream.value?.[listKey] || []) {
      seen.set(entry.uid || entry.id, entry);
    }
  }
  if (!succeeded) return failure.kind === "error" ? failure.response : upstreamResponse(failure);
  return jsonOut(200, { [listKey]: [...seen.values()] }, rate);
}

// Which accounts to try for one collection or environment: the owning
// workspace's when known, else any account (only reachable by principals with
// no grants to scope by; granted ones must have the uid mapped).
async function credsForUid(env, creds, table, rest) {
  const uid = percentDecode(rest.split("/")[0]);
  const row = await dbFirst(env, `SELECT workspace_id FROM ${table} WHERE uid = ?`, [uid]).catch(() => null);
  if (!row) return creds;
  const route = await workspaceCreds(env, creds, row.workspace_id);
  return route.length ? route : creds;
}

// Unscoped passthrough. Maintains the uid→workspace map from per-workspace
// lists, creates and deletes; redacts viewers' single-item GETs.
async function plainForward(env, creds, family, method, rest, query, bodyJson, bodyText, principal) {
  const { table, listKey, thing, base } = dialect(family);
  const isList = rest === "";
  const isCreate = isList && method === "POST";
  const isDeleteSingle = !isList && method === "DELETE";
  const declaredWorkspace = isCreate
    ? (bodyJson ? findWorkspaceIn(bodyJson, query) : queryWorkspace(query))
    : isList ? queryWorkspace(query) : null;

  if (isList && !isCreate && !declaredWorkspace && creds.length > 1) {
    return mergedAcrossAccounts(creds, family, query);
  }
  let route;
  if (declaredWorkspace) {
    route = await workspaceCreds(env, creds, declaredWorkspace);
    if (route.length === 0) route = creds;
  } else if (isCreate) {
    route = creds.slice(0, 1);
  } else if (isList) {
    route = creds;
  } else {
    route = await credsForUid(env, creds, table, rest);
  }

  const upstream = await forwardToPostman(route, method, rest === "" ? base : `${base}/${rest}`, query,
    bodyText.trim() === "" ? null : bodyJson);
  if (upstream.kind === "error") return upstream.response;

  if (upstreamIsSuccess(upstream)) {
    if (isDeleteSingle) {
      const uid = percentDecode(rest.split("/")[0]);
      await dbRun(env, `DELETE FROM ${table} WHERE uid = ?`, [uid]).catch(() => {});
    } else if (declaredWorkspace && upstream.value) {
      const entries = listEntries(upstream.value, listKey, thing);
      if (entries) await rememberEntries(env, table, declaredWorkspace, entries);
    }
  }
  if (shouldRedact(principal, method, rest) && upstreamIsSuccess(upstream) && upstream.value !== null) {
    return upstreamResponse(upstream, stripCurrentValues(structuredClone(upstream.value)));
  }
  return upstreamResponse(upstream);
}

// Allowed single-uid call inside a granted workspace: forward verbatim, keep
// the map in sync on deletes, redact viewers.
async function forwardSingle(env, route, family, method, rest, query, bodyJson, bodyText, principal) {
  const { table, base } = dialect(family);
  const upstream = await forwardToPostman(route, method, `${base}/${rest}`, query,
    bodyText.trim() === "" ? null : bodyJson);
  if (upstream.kind === "error") return upstream.response;
  if (upstreamIsSuccess(upstream) && method === "DELETE") {
    const uid = percentDecode(rest.split("/")[0]);
    await dbRun(env, `DELETE FROM ${table} WHERE uid = ?`, [uid]).catch(() => {});
  }
  if (shouldRedact(principal, method, rest) && upstreamIsSuccess(upstream) && upstream.value !== null) {
    return upstreamResponse(upstream, stripCurrentValues(structuredClone(upstream.value)));
  }
  return upstreamResponse(upstream);
}

// /workspaces: the list is merged across accounts and filtered to the grants;
// anything aimed at one workspace goes through the accounts that can reach it.
async function workspacesRoute(env, creds, method, rest, query, bodyJson, bodyText, allowed) {
  const body = bodyText.trim() === "" ? null : bodyJson;
  if (rest === "") {
    if (method === "GET" || method === "HEAD") return mergedWorkspaces(env, creds, query, allowed);
    if (allowed !== null) return fail(403, "Only people with access to all workspaces can create one");
    return passthrough(creds.slice(0, 1), method, "/workspaces", query, body);
  }
  const uid = percentDecode(rest.split("/")[0]);
  if (allowed !== null && !allowed.includes(uid)) {
    return fail(403, "This workspace isn't in one of your workspaces");
  }
  const route = await workspaceCreds(env, creds, uid);
  if (route.length === 0 && allowed !== null) return fail(404, "No connected Postman account can reach this workspace");
  return passthrough(route.length ? route : creds, method, `/workspaces/${rest}`, query, body);
}

async function passthrough(creds, method, path, query, bodyJson) {
  const upstream = await forwardToPostman(creds, method, path, query, bodyJson);
  return upstream.kind === "error" ? upstream.response : upstreamResponse(upstream);
}

// /apis, /monitors, /mock-servers and /schemas don't belong to a workspace we
// can check, unless the caller names one. Without it, someone limited to certain
// workspaces is refused rather than shown the whole account.
async function unscopedFamilyRoute(env, creds, family, method, rest, query, bodyJson, bodyText, allowed) {
  const base = `/${family}`;
  const workspace = queryWorkspace(query);
  const body = bodyText.trim() === "" ? null : bodyJson;
  const path = rest === "" ? base : `${base}/${rest}`;
  if (allowed !== null && (!workspace || !allowed.includes(workspace))) {
    return fail(403, "This isn't available to people limited to certain workspaces");
  }
  if (!workspace) return passthrough(creds, method, path, query, body);
  const route = await workspaceCreds(env, creds, workspace);
  return passthrough(route.length ? route : creds, method, path, query, body);
}

// Cache keys are per principal grant.
function cacheScopeOf(principal) {
  const grants = scopeOf(principal) || [];
  return grants.length ? grants.join(",") : "all";
}

// The proxy fallback: every non-contract path lands here, then gets
// validated, scoped, forwarded, audited.
async function proxy(env, request, requireAuth) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;
  const query = url.search.startsWith("?") ? url.search.slice(1) : "";
  const who = { userId: null, email: null };
  const audited = async (resp) => {
    await auditInsert(env, who.userId, who.email, method, path, resp.status);
    return resp;
  };

  // 1. Principal.
  let principal;
  try {
    principal = await resolvePrincipal(env, request, requireAuth);
  } catch (resp) {
    return audited(resp); // 401, audited with no principal
  }
  who.userId = principal.userId;
  who.email = principal.email;

  // 2. Only the documented Postman API surface, and never absolute URLs.
  if (!path.startsWith("/") || path.includes("://") || path.startsWith("//")) {
    return audited(fail(404, "No such Postman endpoint"));
  }
  const found = familyOf(path);
  if (!found) return audited(fail(404, "No such Postman endpoint"));
  const { family, rest } = found;

  // 3. Role matrix.
  const [needed, neededMsg] = minRole(family, method, rest);
  if (rankOf(principal) < needed) {
    const message = rankOf(principal) === ROLE_RANK.viewer
      ? "Viewers have read-only access"
      : neededMsg || "Your role doesn't allow this action";
    return audited(fail(403, message));
  }

  const bodyText = await request.text();
  let bodyJson = null;
  if (bodyText.trim()) {
    const parsed = parseJson(bodyText);
    if (parsed.ok) bodyJson = parsed.value;
  }

  // 4. Dispatch workspaces live on this server and are answered here, with
  // Postman's lists merged in where a call spans both.
  const creds = await connectedAccounts(env);
  const stored = await dispatchRoute(env, creds, family, method, rest, query, bodyJson, bodyText, principal);
  if (stored) return audited(stored);

  // 5. Everything else needs a connected Postman account.
  if (creds.length === 0) {
    return audited(fail(503, NO_ACCOUNT_MESSAGE));
  }

  // 6. Scoping and forwarding (redaction and map upkeep happen inside).
  const allowed = scopeOf(principal);
  let response;
  if (family === "collections" || family === "environments") {
    const { table, thing } = dialect(family);
    const isList = rest === "";
    const cacheScope = cacheScopeOf(principal);
    if (allowed !== null && isList && method === "POST") {
      response = await createScoped(env, creds, family, query, bodyJson, allowed);
    } else if (allowed !== null && isList) {
      response = await listScoped(env, creds, family, query, allowed, cacheScope);
    } else if (allowed !== null) {
      // Single-uid operation: the owning workspace comes from the uid map,
      // never from the request.
      const uid = percentDecode(rest.split("/")[0]);
      const mappedRow = await dbFirst(env, `SELECT workspace_id FROM ${table} WHERE uid = ?`, [uid])
        .catch(() => null);
      if (mappedRow && allowed.includes(mappedRow.workspace_id)) {
        const route = await workspaceCreds(env, creds, mappedRow.workspace_id);
        response = await forwardSingle(env, route, family, method, rest, query, bodyJson, bodyText, principal);
      } else {
        response = fail(403,
          `This ${thing} isn't in one of your workspaces — refresh your ${thing}s list first`);
      }
    } else {
      response = await plainForward(env, creds, family, method, rest, query, bodyJson, bodyText, principal);
    }
  } else if (family === "workspaces") {
    response = await workspacesRoute(env, creds, method, rest, query, bodyJson, bodyText, allowed);
  } else if (family === "scim" || family === "integrations") {
    // Admin-only by the role matrix. These act on a whole Postman team.
    const base = `/${family}`;
    response = await passthrough(creds, method, rest === "" ? base : `${base}/${rest}`, query,
      bodyText.trim() === "" ? null : bodyJson);
  } else {
    response = await unscopedFamilyRoute(env, creds, family, method, rest, query, bodyJson, bodyText, allowed);
  }
  return audited(response);
}

// ---------------------------------------------------------------------------
// Dispatch workspaces: stored in D1 instead of Postman, served through the same
// Postman-shaped endpoints (server/src/hosted.rs is the same code in Rust).

const DW_COLLECTION = "collection";
const DW_ENVIRONMENT = "environment";
const SCHEMA_V21 = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json";
const DW_NOT_HERE = "This isn't available for workspaces stored on this Dispatch server";
// D1 rows top out at 2 MB.
const DW_MAX_BYTES = 1_900_000;
const DW_TOO_BIG = "This is too large to store on the Cloudflare version of the server (about 2 MB each). The self-hosted server has no such limit.";

const dwListKey = (kind) => (kind === DW_COLLECTION ? "collections" : "environments");
const inReach = (allowed, workspace) => allowed === null || allowed.includes(workspace);

async function dwWorkspaces(env) {
  return dbAll(env, "SELECT id, name, globals, created_by, created_at, updated_at FROM dispatch_workspaces ORDER BY name COLLATE NOCASE, id")
    .catch(() => []);
}

async function dwWorkspace(env, id) {
  return dbFirst(env, "SELECT id, name, globals, created_by, created_at, updated_at FROM dispatch_workspaces WHERE id = ?", [id])
    .catch(() => null);
}

async function dwItems(env, workspace, kind) {
  return dbAll(env, "SELECT uid, workspace_id, name, created_at, updated_at FROM dispatch_items WHERE workspace_id = ? AND kind = ? ORDER BY name COLLATE NOCASE, uid",
    [workspace, kind]).catch(() => []);
}

function dwEntry(item) {
  return { id: item.uid, uid: item.uid, name: item.name, owner: "", createdAt: item.created_at, updatedAt: item.updated_at, isPublic: false };
}

function dwWorkspaceEntry(ws) {
  return { id: ws.id, name: ws.name, type: "team", visibility: "team", dispatch: true };
}

async function dwEntriesInReach(env, kind, allowed) {
  const out = [];
  for (const ws of await dwWorkspaces(env)) {
    if (inReach(allowed, ws.id)) out.push(...(await dwItems(env, ws.id, kind)).map(dwEntry));
  }
  return out;
}

// A stamp later than `previous`, so every save changes updatedAt (the desktop
// app spots conflicts by comparing them).
function stampAfter(previous) {
  const floor = previous ? Date.parse(previous) + 1 : -Infinity;
  return new Date(Math.max(Date.now(), Number.isNaN(floor) ? -Infinity : floor)).toISOString();
}

function assignItemIds(items) {
  if (!Array.isArray(items)) return;
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    if (typeof item.id !== "string" || !item.id) item.id = crypto.randomUUID();
    if (item.item) assignItemIds(item.item);
  }
}

// Checks a create/update body and returns { name, doc } or { error }.
function dwDocument(kind, bodyJson, uid, created, updated) {
  const doc = bodyJson && typeof bodyJson === "object" ? bodyJson[kind] : null;
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { error: fail(400, `The body needs a "${kind}" object`) };
  if (kind === DW_COLLECTION) {
    const { info: rawInfo, item: rawItems, ...others } = doc;
    const info = rawInfo && typeof rawInfo === "object" && !Array.isArray(rawInfo) ? { ...rawInfo } : {};
    const name = typeof info.name === "string" ? info.name.trim() : "";
    if (!name) return { error: fail(400, "The collection needs a name (info.name)") };
    info._postman_id = uid;
    info.name = name;
    if (typeof info.schema !== "string") info.schema = SCHEMA_V21;
    info.createdAt = created;
    info.updatedAt = updated;
    info.uid = uid;
    const item = Array.isArray(rawItems) ? structuredClone(rawItems) : [];
    assignItemIds(item);
    return { name, doc: { info, item, ...others } };
  }
  const name = typeof doc.name === "string" ? doc.name.trim() : "";
  if (!name) return { error: fail(400, "The environment needs a name") };
  const values = Array.isArray(doc.values) ? doc.values : [];
  return { name, doc: { id: uid, name, owner: "", createdAt: created, updatedAt: updated, isPublic: false, values } };
}

function dwSummary(kind, uid, name) {
  return jsonOut(200, { [kind]: name === undefined ? { id: uid, uid } : { id: uid, uid, name } });
}

async function dwCreate(env, kind, workspace, bodyJson) {
  const uid = crypto.randomUUID();
  const now = nowIso();
  const made = dwDocument(kind, bodyJson, uid, now, now);
  if (made.error) return made.error;
  const text = JSON.stringify(made.doc);
  if (text.length > DW_MAX_BYTES) return fail(413, DW_TOO_BIG);
  try {
    await dbRun(env, "INSERT INTO dispatch_items (uid, kind, workspace_id, name, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [uid, kind, workspace, made.name, text, now, now]);
  } catch {
    return fail(500, `Couldn't save the ${kind}`);
  }
  return dwSummary(kind, uid, made.name);
}

// One stored collection or environment. null when the uid isn't stored here.
async function dwSingle(env, kind, method, rest, uid, bodyJson, allowed, viewer) {
  const item = await dbFirst(env, "SELECT uid, workspace_id, name, body, created_at, updated_at FROM dispatch_items WHERE uid = ? AND kind = ?",
    [uid, kind]).catch(() => null);
  if (!item) return null;
  if (!inReach(allowed, item.workspace_id)) {
    return fail(403, `This ${kind} isn't in one of your workspaces — refresh your ${kind}s list first`);
  }
  if (rest.includes("/")) return fail(400, DW_NOT_HERE);
  if (method === "GET" || method === "HEAD") {
    const parsed = parseJson(item.body);
    const doc = parsed.ok ? parsed.value : null;
    return jsonOut(200, { [kind]: viewer && doc ? stripCurrentValues(doc) : doc });
  }
  if (method === "PUT") {
    const updated = stampAfter(item.updated_at);
    const made = dwDocument(kind, bodyJson, item.uid, item.created_at, updated);
    if (made.error) return made.error;
    const text = JSON.stringify(made.doc);
    if (text.length > DW_MAX_BYTES) return fail(413, DW_TOO_BIG);
    try {
      await dbRun(env, "UPDATE dispatch_items SET name = ?, body = ?, updated_at = ? WHERE uid = ?", [made.name, text, updated, item.uid]);
    } catch {
      return fail(500, `Couldn't save the ${kind}`);
    }
    return dwSummary(kind, item.uid, made.name);
  }
  if (method === "DELETE") {
    await dbRun(env, "DELETE FROM dispatch_items WHERE uid = ?", [item.uid]).catch(() => {});
    return dwSummary(kind, item.uid);
  }
  return fail(400, DW_NOT_HERE);
}

// /workspaces/{id}…, for a Dispatch workspace. The caller has checked reach.
async function dwWorkspaceCall(env, method, ws, rest, bodyJson) {
  const slash = rest.indexOf("/");
  const sub = slash === -1 ? "" : rest.slice(slash + 1);
  const reading = method === "GET" || method === "HEAD";
  if (reading && sub === "") {
    const brief = async (kind) => (await dwItems(env, ws.id, kind)).map((item) => ({ id: item.uid, uid: item.uid, name: item.name }));
    return jsonOut(200, { workspace: {
      id: ws.id, name: ws.name, type: "team", visibility: "team", description: "",
      createdBy: ws.created_by, createdAt: ws.created_at, updatedAt: ws.updated_at, dispatch: true,
      collections: await brief(DW_COLLECTION), environments: await brief(DW_ENVIRONMENT),
    } });
  }
  if (method === "PUT" && sub === "") {
    const name = typeof bodyJson?.workspace?.name === "string" ? bodyJson.workspace.name.trim() : "";
    if (!name) return fail(400, "The workspace needs a name");
    await dbRun(env, "UPDATE dispatch_workspaces SET name = ?, updated_at = ? WHERE id = ?", [name, nowIso(), ws.id]).catch(() => {});
    return jsonOut(200, { workspace: { id: ws.id, name } });
  }
  if (method === "DELETE" && sub === "") {
    await dwDeleteWorkspace(env, ws.id);
    return jsonOut(200, { workspace: { id: ws.id } });
  }
  if (reading && sub === "global-variables") {
    const parsed = parseJson(ws.globals);
    return jsonOut(200, { values: parsed.ok && Array.isArray(parsed.value) ? parsed.value : [] });
  }
  if (method === "PUT" && sub === "global-variables") {
    if (!Array.isArray(bodyJson?.values)) return fail(400, 'The body needs a "values" array');
    const text = JSON.stringify(bodyJson.values);
    if (text.length > DW_MAX_BYTES) return fail(413, DW_TOO_BIG);
    try {
      await dbRun(env, "UPDATE dispatch_workspaces SET globals = ?, updated_at = ? WHERE id = ?", [text, nowIso(), ws.id]);
    } catch {
      return fail(500, "Couldn't save the global variables");
    }
    return jsonOut(200, { values: bodyJson.values });
  }
  return fail(400, DW_NOT_HERE);
}

async function dwDeleteWorkspace(env, id) {
  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM dispatch_items WHERE workspace_id = ?").bind(id),
    env.DB.prepare("DELETE FROM dispatch_workspaces WHERE id = ?").bind(id),
  ]);
  return (results[1]?.meta?.changes || 0) > 0;
}

// Adds Dispatch entries to a list response from Postman. If Postman failed
// outright, the stored entries are still shown on their own.
async function withExtra(response, key, extra) {
  if (!extra.length) return response;
  let value = {};
  let rate = null;
  if (response.ok) {
    const parsed = parseJson(await response.text());
    if (parsed.ok && parsed.value && typeof parsed.value === "object" && !Array.isArray(parsed.value)) value = parsed.value;
    rate = response.headers.get(RATE_LIMIT_HEADER);
  }
  const list = Array.isArray(value[key]) ? value[key] : [];
  return jsonOut(200, { ...value, [key]: [...list, ...extra] }, rate);
}

// Calls that touch a Dispatch workspace: answered from D1, or merged with
// Postman's answer when a list spans both. null sends the call on to Postman.
async function dispatchRoute(env, creds, family, method, rest, query, bodyJson, bodyText, principal) {
  const allowed = scopeOf(principal);
  const reading = method === "GET" || method === "HEAD";
  if (family === "workspaces" && rest === "") {
    if (!reading) return null;
    const all = await dwWorkspaces(env);
    if (creds.length === 0) {
      // Nothing at all to serve yet: let the 503 explain why.
      if (!all.length) return null;
      return jsonOut(200, { workspaces: all.filter((ws) => inReach(allowed, ws.id)).map(dwWorkspaceEntry) });
    }
    const extra = all.filter((ws) => inReach(allowed, ws.id)).map(dwWorkspaceEntry);
    return withExtra(await mergedWorkspaces(env, creds, query, allowed), "workspaces", extra);
  }
  if (family === "workspaces") {
    const id = percentDecode(rest.split("/")[0]);
    const ws = await dwWorkspace(env, id);
    if (!ws) return null;
    if (!inReach(allowed, id)) return fail(403, "This workspace isn't in one of your workspaces");
    return dwWorkspaceCall(env, method, ws, rest, bodyJson);
  }
  if (family !== "collections" && family !== "environments") return null;
  const kind = family === "collections" ? DW_COLLECTION : DW_ENVIRONMENT;
  if (rest !== "") {
    const uid = percentDecode(rest.split("/")[0]);
    return dwSingle(env, kind, method, rest, uid, bodyJson, allowed, principal.role === "viewer");
  }
  if (method === "POST") {
    const declared = bodyJson && typeof bodyJson === "object" ? findWorkspaceIn(bodyJson, query) : queryWorkspace(query);
    const target = allowed === null ? declared : (declared !== null && allowed.includes(declared) ? declared : allowed[0] ?? null);
    if (!target || !(await dwWorkspace(env, target))) return null;
    return dwCreate(env, kind, target, bodyJson);
  }
  if (!reading) return null;
  const requested = queryWorkspace(query);
  if (requested) {
    const ws = percentDecode(requested);
    if (!(await dwWorkspace(env, ws))) return null;
    if (!inReach(allowed, ws)) return fail(403, "This workspace isn't in one of your workspaces");
    const items = await dwItems(env, ws, kind);
    return jsonOut(200, { [dwListKey(kind)]: items.map(dwEntry) });
  }
  // No workspace named: every list in reach, from both places.
  const stored = (await dwWorkspaces(env)).map((ws) => ws.id);
  if (!stored.length) return null;
  const key = dwListKey(kind);
  const extra = await dwEntriesInReach(env, kind, allowed);
  if (creds.length === 0) return jsonOut(200, { [key]: extra });
  const response = allowed !== null
    ? await listScoped(env, creds, family, query, allowed.filter((ws) => !stored.includes(ws)), cacheScopeOf(principal))
    : await plainForward(env, creds, family, method, rest, query, bodyJson, bodyText, principal);
  return withExtra(response, key, extra);
}

// ---------------------------------------------------------------------------
// auth endpoints

async function readJsonObject(request) {
  const body = await request.json().catch(() => null);
  return body !== null && typeof body === "object" && !Array.isArray(body) ? body : null;
}

async function handleRegister(env, request, requireAuth) {
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");
  if (!requireAuth) return fail(403, "Registration is currently disabled");
  const setting = await dbFirst(env, "SELECT value FROM settings WHERE key = ?", ["allow_registration"])
    .catch(() => null);
  if (setting && setting.value !== "1") return fail(403, "Registration is currently disabled");
  const email = emailOf(parsed);
  if (!email) return fail(400, "Enter a valid email address");
  const password = typeof parsed.password === "string" ? parsed.password : null;
  if (password === null || [...password].length < 8) {
    return fail(400, "Password must be at least 8 characters");
  }
  const hash = await hashPassword(password, env);
  let role = "viewer";
  try {
    const firstUser = (await dbFirst(env, "SELECT COUNT(*) AS n FROM users")).n === 0;
    role = firstUser ? "admin" : "viewer";
    // Nobody but the first admin reaches a workspace until an admin grants it.
    const grants = firstUser ? null : [];
    const grantSlot = firstUser ? "NULL" : "'[]'";
    const result = await dbRun(env,
      `INSERT INTO users (email, password_hash, role, workspace_grants, created_at) VALUES (?, ?, ?, ${grantSlot}, ?)`,
      [email, hash, role, nowIso()]);
    const [username, fullName] = displayNames(email);
    return jsonOut(201, {
      user: { id: result.meta.last_row_id, username, fullName, email, role, workspace_grants: grants },
    });
  } catch (e) {
    const msg = String((e && e.message) || e);
    if (msg.toUpperCase().includes("UNIQUE") || msg.toUpperCase().includes("CONSTRAINT")) {
      return fail(409, "An account with this email already exists");
    }
    return fail(500, "Couldn't create the account");
  }
}

async function handleLogin(env, request) {
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");
  const email = emailOf(parsed);
  const user = email
    ? await dbFirst(env, `SELECT ${USER_COLS} FROM users WHERE email = ? COLLATE NOCASE`, [email])
      .catch(() => null)
    : null;
  const ok = user && await verifyPassword(typeof parsed.password === "string" ? parsed.password : "", user.password_hash);
  if (!ok) return fail(401, "Wrong email or password");
  const token = await issueToken(env, user.id);
  const [username, fullName] = displayNames(user.email);
  return jsonOut(200, {
    token,
    user: { id: user.id, username, fullName, email: user.email, role: user.role },
  });
}

async function handleLogout(env, request, requireAuth) {
  const token = await bearerOf(request);
  const principal = token ? await tokenPrincipal(env, token, requireAuth) : null;
  if (!principal) return fail(401, "Invalid or missing token");
  await dbRun(env, "DELETE FROM tokens WHERE token_hash = ?", [await sha256Hex(token)]).catch(() => {});
  return responseWithCors(204);
}

async function handleMe(env, request, requireAuth) {
  const token = await bearerOf(request);
  const principal = token ? await tokenPrincipal(env, token, requireAuth) : null;
  if (!principal) return fail(401, "Invalid or missing token");
  const grants = principal.grants === null ? null : principal.grants;
  if (principal.userId === 0) {
    const [username, fullName] = displayNames(principal.email);
    return jsonOut(200, { user: { id: 0, username, fullName, email: principal.email, role: principal.role, workspace_grants: grants } });
  }
  const user = await dbFirst(env, `SELECT ${USER_COLS} FROM users WHERE id = ?`, [principal.userId]);
  const [username, fullName] = displayNames(user.email);
  return jsonOut(200, {
    user: {
      id: user.id, username, fullName, email: user.email, role: user.role,
      workspace_grants: parseGrants(user.workspace_grants),
    },
  });
}

// Open-mode admin login. Only valid when REQUIRE_AUTH is false.
async function handleAdminLogin(env, request, requireAuth) {
  if (requireAuth) return fail(401, "Admin login requires REQUIRE_AUTH to be disabled");
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");
  const password = typeof parsed.password === "string" ? parsed.password : null;
  if (password === null) return fail(400, "Body must include a password");
  const expected = typeof env.ADMIN_PASSWORD === "string" ? env.ADMIN_PASSWORD : "";
  if (!expected || password !== expected) return fail(401, "Invalid admin password");
  const token = await issueToken(env, 0);
  return jsonOut(200, { token, user: { id: 0, email: "admin", role: "admin" } });
}

// ---------------------------------------------------------------------------
// admin API (role admin; other roles get 403)

async function requireAdmin(env, request, requireAuth) {
  const token = await bearerOf(request);
  const principal = token ? await tokenPrincipal(env, token, requireAuth) : null;
  if (!principal) return { principal: null, error: fail(401, "Invalid or missing token") };
  if (principal.role !== "admin") return { principal: null, error: fail(403, "Only admins can do this") };
  return { principal };
}

async function handleAdminUsersList(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const users = await dbAll(env, `SELECT ${USER_COLS} FROM users ORDER BY id`);
  return jsonOut(200, users.map(userJson));
}

// workspace_grants in admin payloads: null (all workspaces) or an array of
// workspace ID strings; stored as JSON text.
function grantsText(value) {
  if (value === undefined || value === null) return { ok: true, text: null };
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
    return { ok: true, text: JSON.stringify(value) };
  }
  return { ok: false, error: "workspace_grants must be an array of workspace IDs" };
}

async function handleAdminUsersCreate(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");
  const email = emailOf(parsed);
  if (!email) return fail(400, "Enter a valid email address");
  const password = typeof parsed.password === "string" ? parsed.password : null;
  if (password === null || [...password].length < 8) {
    return fail(400, "Password must be at least 8 characters");
  }
  const role = parsed.role === undefined || parsed.role === null ? "viewer" : parsed.role;
  if (typeof role !== "string" || !ROLES.includes(role)) {
    return fail(400, "Role must be one of viewer, editor, creator or admin");
  }
  // No access until granted, unless the request asks for all workspaces (null).
  const grants = grantsText(parsed.workspace_grants === undefined ? [] : parsed.workspace_grants);
  if (!grants.ok) return fail(400, grants.error);
  const hash = await hashPassword(password, env);
  let id;
  try {
    // D1 can't bind JS null; workspace_grants NULL becomes an SQL literal.
    const grantSlot = grants.text === null ? "NULL" : "?";
    const args = [email, hash, role];
    if (grants.text !== null) args.push(grants.text);
    args.push(nowIso());
    const result = await dbRun(env,
      `INSERT INTO users (email, password_hash, role, workspace_grants, created_at) VALUES (?, ?, ?, ${grantSlot}, ?)`,
      args);
    id = result.meta.last_row_id;
  } catch (e) {
    const msg = String((e && e.message) || e);
    if (msg.toUpperCase().includes("UNIQUE") || msg.toUpperCase().includes("CONSTRAINT")) {
      return fail(409, "An account with this email already exists");
    }
    return fail(500, "Couldn't create the account");
  }
  const created = await dbFirst(env, `SELECT ${USER_COLS} FROM users WHERE id = ?`, [id]);
  return jsonOut(201, userJson(created));
}

async function handleAdminUsersUpdate(env, request, requireAuth, idText) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const id = /^\d+$/.test(idText) ? Number(idText) : null;
  if (id === null) return fail(404, "No such user");
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");

  let roleSql = null, roleArg = null;
  if (parsed.role !== undefined && parsed.role !== null) {
    if (typeof parsed.role !== "string" || !ROLES.includes(parsed.role)) {
      return fail(400, "Role must be one of viewer, editor, creator or admin");
    }
    roleSql = "role = ?"; roleArg = parsed.role;
  }
  let grantsSql = null, grantsArg = null;
  if (parsed.workspace_grants !== undefined) {
    const grants = grantsText(parsed.workspace_grants);
    if (!grants.ok) return fail(400, grants.error);
    // D1 can't bind JS null; workspace_grants NULL becomes an SQL literal.
    grantsSql = grants.text === null ? "workspace_grants = NULL" : "workspace_grants = ?";
    grantsArg = grants.text;
  }
  let hashSql = null, hashArg = null;
  if (parsed.password !== undefined && parsed.password !== null) {
    if (typeof parsed.password !== "string") return fail(400, "Password must be a string");
    if ([...parsed.password].length < 8) return fail(400, "Password must be at least 8 characters");
    hashSql = "password_hash = ?"; hashArg = await hashPassword(parsed.password, env);
  }
  const existing = await dbFirst(env, "SELECT id FROM users WHERE id = ?", [id]);
  if (!existing) return fail(404, "No such user");
  if (roleSql || grantsSql || hashSql) {
    const sets = [roleSql, grantsSql, hashSql].filter(Boolean);
    const args = [roleArg, grantsArg, hashArg].filter((a) => a !== null);
    await dbRun(env, `UPDATE users SET ${sets.join(", ")} WHERE id = ?`, [...args, id]);
  }
  const updated = await dbFirst(env, `SELECT ${USER_COLS} FROM users WHERE id = ?`, [id]);
  return jsonOut(200, userJson(updated));
}

async function handleAdminUsersDelete(env, request, requireAuth, idText) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const id = /^\d+$/.test(idText) ? Number(idText) : null;
  if (id === null) return fail(404, "No such user");
  if (principal.userId === id) return fail(400, "You can't delete your own account");
  const existing = await dbFirst(env, "SELECT id FROM users WHERE id = ?", [id]);
  if (!existing) return fail(404, "No such user");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id),
    env.DB.prepare("DELETE FROM tokens WHERE user_id = ?").bind(id),
  ]);
  return responseWithCors(204);
}

async function handleAdminSettingsGet(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const row = await dbFirst(env, "SELECT value FROM settings WHERE key = ?", ["allow_registration"])
    .catch(() => null);
  return jsonOut(200, { allow_registration: !row || row.value === "1" });
}

async function handleAdminSettingsPatch(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const parsed = await readJsonObject(request);
  if (!parsed) return fail(400, "Body must be valid JSON");
  if (typeof parsed.allow_registration !== "boolean") {
    return fail(400, "allow_registration must be true or false");
  }
  await dbRun(env, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    ["allow_registration", parsed.allow_registration ? "1" : "0"]);
  return jsonOut(200, { allow_registration: parsed.allow_registration });
}

// Newest-first listing capped at 1000 rows (default 100).
function parseLimit(query) {
  for (const pair of query.split("&").filter(Boolean)) {
    const idx = pair.indexOf("=");
    if (idx > 0 && pair.slice(0, idx) === "limit" && pair.slice(idx + 1)) {
      const n = parseInt(pair.slice(idx + 1), 10);
      if (!Number.isFinite(n)) return { ok: false, error: "limit must be a number" };
      return { ok: true, value: Math.min(1000, Math.max(1, n)) };
    }
  }
  return { ok: true, value: 100 };
}

async function handleAdminAudit(env, request, requireAuth, query) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const limit = parseLimit(query);
  if (!limit.ok) return fail(400, limit.error);
  const rows = await dbAll(env,
    "SELECT ts, user_id, email, action, method, path, status FROM audit ORDER BY id DESC LIMIT ?",
    [limit.value]);
  return jsonOut(200, rows);
}

// ---------------------------------------------------------------------------
// admin API: connected Postman accounts and the workspaces they reach

const POSTMAN_KEY_MAX = 512;
const NO_SECRET_MESSAGE = "This server has no SECRET_KEY, so it can't store Postman keys. Set a SECRET_KEY secret of at least 32 random characters, then try again.";

function keyHint(key) {
  return `…${key.slice(-4)}`;
}

function cleanKey(value) {
  const key = typeof value === "string" ? value.trim() : "";
  return key && key.length <= POSTMAN_KEY_MAX && /^[\x21-\x7e]+$/.test(key) ? key : null;
}

function regionOf(value) {
  if (value === undefined || value === null) return "us";
  return value === "us" || value === "eu" ? value : null;
}

function cleanLabel(value) {
  return typeof value === "string" ? value.trim().slice(0, 80) : "";
}

// Who a key belongs to, from Postman's own GET /me.
async function identifyKey(cred) {
  const upstream = await forwardToPostman([cred], "GET", "/me", "", null);
  if (upstream.kind === "error") return { status: "unreachable" };
  if (upstream.status === 401 || upstream.status === 403) return { status: "invalid" };
  if (!upstreamIsSuccess(upstream)) return { status: "unreachable" };
  const user = upstream.value?.user || {};
  const usage = Array.isArray(upstream.value?.operations)
    ? upstream.value.operations.find((op) => op && op.name === "api_usage")
    : null;
  return {
    status: "ok",
    userId: user.id === undefined || user.id === null ? null : String(user.id),
    name: user.teamName || user.fullName || user.username || null,
    usage: usage && Number.isFinite(usage.usage) && Number.isFinite(usage.limit)
      ? { used: usage.usage, limit: usage.limit }
      : null,
  };
}

function storedAccountCred(env, row, key) {
  return { id: row.id, label: row.label, key, base: postmanBase(env, row.region) };
}

async function accountView(env, base, cred, workspaceCount) {
  const check = cred ? await identifyKey(cred) : { status: "undecryptable" };
  return {
    ...base,
    postman_name: check.name || base.postman_name || null,
    status: check.status,
    usage: check.usage || null,
    workspace_count: workspaceCount,
  };
}

const ACCOUNT_COLS = "id, label, region, key_hint, postman_user_id, postman_name, created_by, created_at";

function storedAccountJson(row) {
  return {
    id: row.id,
    label: row.label,
    region: row.region,
    key_hint: row.key_hint,
    source: "stored",
    postman_name: row.postman_name,
    created_by: row.created_by,
    created_at: row.created_at,
  };
}

async function workspaceCountOf(env, accountId) {
  const row = await dbFirst(env, "SELECT COUNT(*) AS n FROM workspace_accounts WHERE account_id = ?", [accountId])
    .catch(() => null);
  return row ? row.n : 0;
}

async function handleAdminAccountsList(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const creds = await connectedAccounts(env);
  await syncWorkspaces(env, creds);
  const accounts = [];
  const fromEnv = envCred(env);
  if (fromEnv) {
    accounts.push(await accountView(env, {
      id: ENV_ACCOUNT_ID, label: fromEnv.label, region: env.POSTMAN_REGION === "eu" ? "eu" : "us",
      key_hint: keyHint(fromEnv.key), source: "environment", created_by: null, created_at: null,
    }, fromEnv, await workspaceCountOf(env, ENV_ACCOUNT_ID)));
  }
  const rows = await dbAll(env, `SELECT ${ACCOUNT_COLS} FROM postman_accounts ORDER BY id`);
  for (const row of rows) {
    const cred = creds.find((c) => c.id === row.id) || null;
    accounts.push(await accountView(env, storedAccountJson(row), cred, await workspaceCountOf(env, row.id)));
  }
  return jsonOut(200, { accounts, can_store_keys: secretKeyOf(env) !== null });
}

async function handleAdminAccountsCreate(env, request, requireAuth) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "POST", "/admin/postman-accounts", resp.status, "account_add");
    return resp;
  };
  const secret = secretKeyOf(env);
  if (!secret) return finish(fail(503, NO_SECRET_MESSAGE));
  const parsed = await readJsonObject(request);
  if (!parsed) return finish(fail(400, "Body must be valid JSON"));
  const key = cleanKey(parsed.api_key);
  if (!key) return finish(fail(400, "Paste a Postman API key"));
  const region = regionOf(parsed.region);
  if (!region) return finish(fail(400, "Region must be us or eu"));
  const probe = { id: -1, label: "", key, base: postmanBase(env, region) };
  const check = await identifyKey(probe);
  if (check.status === "invalid") return finish(fail(400, "Postman didn't accept this key. Check the key and its region."));
  if (check.status !== "ok") return finish(fail(502, "Couldn't reach the Postman API to check this key. Try again."));
  if (check.userId) {
    const twin = await dbFirst(env, "SELECT label FROM postman_accounts WHERE postman_user_id = ?", [check.userId]).catch(() => null);
    if (twin) return finish(fail(409, `This Postman user is already connected as "${twin.label}"`));
  }
  const label = cleanLabel(parsed.label) || check.name || `Postman account ${keyHint(key)}`;
  const nameSlot = check.name ? "?" : "NULL";
  const userSlot = check.userId ? "?" : "NULL";
  const creatorSlot = principal.email ? "?" : "NULL";
  const args = [label, region, await encryptKey(secret, key), keyHint(key)];
  if (check.userId) args.push(check.userId);
  if (check.name) args.push(check.name);
  if (principal.email) args.push(principal.email);
  args.push(nowIso());
  const result = await dbRun(env,
    `INSERT INTO postman_accounts (label, region, key_ciphertext, key_hint, postman_user_id, postman_name, created_by, created_at) VALUES (?, ?, ?, ?, ${userSlot}, ${nameSlot}, ${creatorSlot}, ?)`,
    args);
  listCache.clear();
  const row = await dbFirst(env, `SELECT ${ACCOUNT_COLS} FROM postman_accounts WHERE id = ?`, [result.meta.last_row_id]);
  const cred = storedAccountCred(env, row, key);
  await syncWorkspaces(env, [cred]);
  return finish(jsonOut(201, {
    ...storedAccountJson(row), status: "ok", usage: check.usage || null,
    workspace_count: await workspaceCountOf(env, row.id),
  }));
}

async function handleAdminAccountsUpdate(env, request, requireAuth, idText) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const path = `/admin/postman-accounts/${idText}`;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "PATCH", path, resp.status, "account_update");
    return resp;
  };
  const id = /^\d+$/.test(idText) ? Number(idText) : null;
  if (id === null) return finish(fail(404, "No such Postman account"));
  if (id === ENV_ACCOUNT_ID) return finish(fail(400, "This key comes from the server's POSTMAN_API_KEY setting. Change it there."));
  const parsed = await readJsonObject(request);
  if (!parsed) return finish(fail(400, "Body must be valid JSON"));
  const row = await dbFirst(env, `SELECT ${ACCOUNT_COLS} FROM postman_accounts WHERE id = ?`, [id]);
  if (!row) return finish(fail(404, "No such Postman account"));
  if (parsed.label !== undefined) {
    const label = cleanLabel(parsed.label);
    if (!label) return finish(fail(400, "Give the account a name"));
    await dbRun(env, "UPDATE postman_accounts SET label = ? WHERE id = ?", [label, id]);
  }
  let replaced = null;
  if (parsed.api_key !== undefined) {
    const secret = secretKeyOf(env);
    if (!secret) return finish(fail(503, NO_SECRET_MESSAGE));
    const key = cleanKey(parsed.api_key);
    if (!key) return finish(fail(400, "Paste a Postman API key"));
    const check = await identifyKey({ id, label: row.label, key, base: postmanBase(env, row.region) });
    if (check.status === "invalid") return finish(fail(400, "Postman didn't accept this key. Check the key and its region."));
    if (check.status !== "ok") return finish(fail(502, "Couldn't reach the Postman API to check this key. Try again."));
    await dbRun(env, "UPDATE postman_accounts SET key_ciphertext = ?, key_hint = ? WHERE id = ?",
      [await encryptKey(secret, key), keyHint(key), id]);
    if (check.userId) await dbRun(env, "UPDATE postman_accounts SET postman_user_id = ? WHERE id = ?", [check.userId, id]);
    if (check.name) await dbRun(env, "UPDATE postman_accounts SET postman_name = ? WHERE id = ?", [check.name, id]);
    replaced = key;
  }
  listCache.clear();
  const updated = await dbFirst(env, `SELECT ${ACCOUNT_COLS} FROM postman_accounts WHERE id = ?`, [id]);
  if (replaced) await syncWorkspaces(env, [storedAccountCred(env, updated, replaced)]);
  const creds = await connectedAccounts(env);
  return finish(jsonOut(200, await accountView(env, storedAccountJson(updated),
    creds.find((c) => c.id === id) || null, await workspaceCountOf(env, id))));
}

async function handleAdminAccountsDelete(env, request, requireAuth, idText) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const path = `/admin/postman-accounts/${idText}`;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "DELETE", path, resp.status, "account_remove");
    return resp;
  };
  const id = /^\d+$/.test(idText) ? Number(idText) : null;
  if (id === null) return finish(fail(404, "No such Postman account"));
  if (id === ENV_ACCOUNT_ID) return finish(fail(400, "This key comes from the server's POSTMAN_API_KEY setting. Remove it there."));
  const row = await dbFirst(env, "SELECT id FROM postman_accounts WHERE id = ?", [id]);
  if (!row) return finish(fail(404, "No such Postman account"));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM postman_accounts WHERE id = ?").bind(id),
    env.DB.prepare("DELETE FROM workspace_accounts WHERE account_id = ?").bind(id),
  ]);
  listCache.clear();
  return finish(responseWithCors(204));
}

// Every workspace any connected account reaches, each once, with the accounts
// that reach it.
async function handleAdminWorkspaces(env, request, requireAuth) {
  const { error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const creds = await connectedAccounts(env);
  const results = await syncWorkspaces(env, creds);
  const failed = results.filter(({ upstream }) => !upstreamIsSuccess(upstream)).map(({ cred }) => cred.label);
  const byId = new Map();
  for (const { cred, upstream } of results) {
    if (!upstreamIsSuccess(upstream)) continue;
    for (const ws of upstream.value?.workspaces || []) {
      if (!ws || typeof ws.id !== "string") continue;
      const entry = byId.get(ws.id) || { id: ws.id, name: ws.name || ws.id, type: ws.type || "", accounts: [] };
      entry.accounts.push({ id: cred.id, label: cred.label });
      byId.set(ws.id, entry);
    }
  }
  for (const ws of await dwWorkspaces(env)) byId.set(ws.id, await dwWorkspaceJson(env, ws));
  const workspaces = [...byId.values()].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  return jsonOut(200, { workspaces, failed_accounts: failed });
}

// ---------------------------------------------------------------------------
// admin: Dispatch workspaces (stored on this server)

async function dwWorkspaceJson(env, ws) {
  const count = async (kind) => (await dbFirst(env, "SELECT COUNT(*) AS n FROM dispatch_items WHERE workspace_id = ? AND kind = ?", [ws.id, kind]).catch(() => null))?.n || 0;
  return {
    id: ws.id, name: ws.name, type: "team", accounts: [], dispatch: true,
    collections: await count(DW_COLLECTION), environments: await count(DW_ENVIRONMENT),
    created_by: ws.created_by ?? null, created_at: ws.created_at,
  };
}

function workspaceNameOf(body) {
  const name = typeof body?.name === "string" ? [...body.name.trim()].slice(0, 120).join("") : "";
  return name || null;
}

async function dwWorkspaceResponse(env, id, status) {
  const ws = await dwWorkspace(env, id);
  return ws ? jsonOut(status, await dwWorkspaceJson(env, ws)) : fail(404, "No such workspace");
}

async function handleAdminDispatchCreate(env, request, requireAuth) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "POST", "/admin/dispatch-workspaces", resp.status, "workspace_create");
    return resp;
  };
  const body = await readJsonObject(request);
  if (!body) return finish(fail(400, "Body must be valid JSON"));
  const name = workspaceNameOf(body);
  if (!name) return finish(fail(400, "Give the workspace a name"));
  const id = crypto.randomUUID();
  const now = nowIso();
  try {
    await dbRun(env, "INSERT INTO dispatch_workspaces (id, name, globals, created_by, created_at, updated_at) VALUES (?, ?, '[]', ?, ?, ?)",
      [id, name, principal.email ?? "admin", now, now]);
  } catch {
    return finish(fail(500, "Couldn't create the workspace"));
  }
  return finish(await dwWorkspaceResponse(env, id, 201));
}

async function handleAdminDispatchUpdate(env, request, requireAuth, id) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const path = `/admin/dispatch-workspaces/${id}`;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "PATCH", path, resp.status, "workspace_update");
    return resp;
  };
  const body = await readJsonObject(request);
  if (!body) return finish(fail(400, "Body must be valid JSON"));
  const name = workspaceNameOf(body);
  if (!name) return finish(fail(400, "Give the workspace a name"));
  const result = await dbRun(env, "UPDATE dispatch_workspaces SET name = ?, updated_at = ? WHERE id = ?", [name, nowIso(), id]).catch(() => null);
  if (!result) return finish(fail(500, "Couldn't rename the workspace"));
  if (!result.meta?.changes) return finish(fail(404, "No such workspace"));
  return finish(await dwWorkspaceResponse(env, id, 200));
}

async function handleAdminDispatchDelete(env, request, requireAuth, id) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const path = `/admin/dispatch-workspaces/${id}`;
  let resp;
  try {
    resp = (await dwDeleteWorkspace(env, id)) ? responseWithCors(204) : fail(404, "No such workspace");
  } catch {
    resp = fail(500, "Couldn't delete the workspace");
  }
  await auditInsert(env, principal.userId, principal.email, "DELETE", path, resp.status, "workspace_delete");
  return resp;
}

// Copies a Postman workspace onto this server as a new Dispatch workspace. The
// Postman original is left as it is.
async function handleAdminDispatchImport(env, request, requireAuth) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  if (error) return error;
  const finish = async (resp) => {
    await auditInsert(env, principal.userId, principal.email, "POST", "/admin/dispatch-workspaces/import", resp.status, "workspace_import");
    return resp;
  };
  const body = await readJsonObject(request);
  if (!body) return finish(fail(400, "Body must be valid JSON"));
  const source = typeof body.workspace_id === "string" ? body.workspace_id : "";
  if (!source) return finish(fail(400, "Choose a Postman workspace to copy"));
  if (await dwWorkspace(env, source)) return finish(fail(400, "This workspace is already stored on this server"));
  const known = await dbFirst(env, "SELECT name FROM workspace_accounts WHERE workspace_id = ? LIMIT 1", [source]).catch(() => null);
  const name = workspaceNameOf(body) || known?.name || "Imported workspace";

  const creds = await connectedAccounts(env);
  const route = await workspaceCreds(env, creds, source);
  if (!route.length) return finish(fail(404, "No connected Postman account can reach this workspace"));
  const get = async (path, query = "") => {
    const upstream = await forwardToPostman(route, "GET", path, query, null);
    if (upstream.kind === "error") throw upstream.response;
    if (!upstreamIsSuccess(upstream)) throw upstreamResponse(upstream);
    return upstream.value || {};
  };
  const id = crypto.randomUUID();
  const statements = [];
  try {
    for (const [base, key, kind] of [["/collections", "collections", DW_COLLECTION], ["/environments", "environments", DW_ENVIRONMENT]]) {
      const list = await get(base, queryWithWorkspace("", source));
      for (const entry of list[key] || []) {
        const uid = entry?.uid || entry?.id;
        if (!uid) continue;
        const doc = (await get(`${base}/${uid}`))[kind];
        if (!doc || typeof doc !== "object") continue;
        if (kind === DW_COLLECTION && doc.info) {
          for (const field of ["_postman_id", "uid", "createdAt", "updatedAt", "lastUpdatedBy", "fork", "owner"]) delete doc.info[field];
        } else {
          for (const field of ["id", "uid", "owner", "createdAt", "updatedAt"]) delete doc[field];
        }
        const newUid = crypto.randomUUID();
        const now = nowIso();
        const made = dwDocument(kind, { [kind]: doc }, newUid, now, now);
        if (made.error) return finish(fail(400, `A ${kind} in this workspace has no name`));
        const text = JSON.stringify(made.doc);
        if (text.length > DW_MAX_BYTES) return finish(fail(413, `"${made.name}" is too large to store on the Cloudflare version of the server (about 2 MB each). The self-hosted server has no such limit.`));
        statements.push(env.DB.prepare("INSERT INTO dispatch_items (uid, kind, workspace_id, name, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .bind(newUid, kind, id, made.name, text, now, now));
      }
    }
  } catch (e) {
    if (e instanceof Response) return finish(e);
    const message = String(e?.message || e);
    return finish(fail(502, /subrequest/i.test(message)
      ? "This workspace has more collections than one Cloudflare request can copy. Try a paid Workers plan, or the self-hosted server."
      : `Couldn't copy the workspace: ${message}`));
  }
  // Some workspaces don't offer globals; that's not a reason to stop.
  let globals = [];
  try {
    const value = await get(`/workspaces/${source}/global-variables`);
    if (Array.isArray(value.values)) globals = value.values;
  } catch { /* none */ }
  const now = nowIso();
  statements.unshift(env.DB.prepare("INSERT INTO dispatch_workspaces (id, name, globals, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(id, name, JSON.stringify(globals), principal.email ?? "admin", now, now));
  try {
    await env.DB.batch(statements);
  } catch (e) {
    return finish(fail(500, `Couldn't save the copy: ${e?.message || e}`));
  }
  return finish(await dwWorkspaceResponse(env, id, 201));
}

// ---------------------------------------------------------------------------
// the admin panel itself: served verbatim from ./admin via ASSETS.
// GET /admin redirects so the panel's relative assets (./styles.css, ./app.js)
// resolve against /admin/.

async function serveAdmin(env, request, rest) {
  const origin = new URL(request.url).origin;
  const clean = rest === "" || rest === "/" ? "/" : "/" + rest.replace(/^\/+/, "");
  return env.ASSETS.fetch(new Request(origin + clean, { method: "GET", headers: request.headers }));
}

// ---------------------------------------------------------------------------
// published documentation: sites built by the desktop app, served only on
// their own verified domain (same rules as server/src/docs.rs)

const DOCS_WELL_KNOWN = "/.well-known/dispatch-docs/";
const DOCS_MAX_FILE = 1024 * 1024;
const DOCS_MAX_VERSION = 20 * 1024 * 1024;
const DOCS_MAX_FILES = 1000;
const DOCS_TYPES = [
  "text/html; charset=utf-8",
  "text/css; charset=utf-8",
  "text/javascript; charset=utf-8",
  "application/json",
  "text/markdown; charset=utf-8",
  "text/plain; charset=utf-8",
  "image/svg+xml",
  "application/yaml",
  "application/xml",
];
// Fonts may be data: URLs, because published sites carry their web fonts inline.
const DOCS_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const SITE_COLS = "id, workspace_id, collection_uid, name, hostname, domain_status, verify_token, verified_at, checked_at, check_message, online, current_version, created_by, created_at, updated_at";

const docsAllowHttp = (env) => String(env.DOCS_ALLOW_HTTP ?? "").toLowerCase() === "true";
const siteLive = (s) => !!s.online && s.domain_status === "verified" && s.current_version !== null && s.current_version !== undefined;

function siteJson(s, withToken, allowHttp) {
  const out = {
    id: s.id, workspace_id: s.workspace_id, collection_uid: s.collection_uid, name: s.name,
    hostname: s.hostname ?? null, domain_status: s.domain_status, verified_at: s.verified_at ?? null,
    checked_at: s.checked_at ?? null, check_message: s.check_message ?? null, online: !!s.online, live: siteLive(s),
    current_version: s.current_version ?? null, created_by: s.created_by ?? null, created_at: s.created_at, updated_at: s.updated_at,
    url: s.hostname ? `${allowHttp ? "http" : "https"}://${s.hostname}/` : null,
  };
  if (withToken) out.verify_token = s.verify_token ?? null;
  return out;
}

// The host a request was sent to: lowercase, no trailing dot, no port unless
// DOCS_ALLOW_HTTP is on.
function requestHost(request, allowHttp) {
  const raw = (request.headers.get("Host") || new URL(request.url).host || "").trim().replace(/\.$/, "").toLowerCase();
  if (allowHttp) return raw;
  if (raw.startsWith("[")) return `[${raw.slice(1).split("]")[0]}]`;
  const m = /^(.*):(\d+)$/.exec(raw);
  return m ? m[1] : raw;
}

function normalizeHostname(raw, allowHttp) {
  let text = String(raw).trim().replace(/\/+$/, "").toLowerCase().replace(/^https?:\/\//, "").replace(/\.$/, "");
  let port = null;
  const m = /^(.*):(\d+)$/.exec(text);
  if (m && allowHttp) { text = m[1]; port = m[2]; }
  const labels = text.split(".");
  const labelOk = (l) => l.length > 0 && l.length <= 63 && !l.startsWith("-") && !l.endsWith("-") && /^[a-z0-9-]+$/.test(l);
  const dnsOk = text.length <= 253 && labels.every(labelOk) && (labels.length >= 2 || (allowHttp && text === "localhost"));
  const notIp = !labels.every((l) => /^\d+$/.test(l));
  if (!dnsOk || !notIp) throw fail(400, `"${String(raw).trim()}" isn't a domain name. Use a domain or subdomain such as docs.example.com.`);
  return port ? `${text}:${port}` : text;
}

function docsPage(status, title, message) {
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head><body style="font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:15vh auto;padding:0 1.5rem;color:#333"><h1 style="font-size:1.4rem">${title}</h1><p>${message}</p></body></html>`;
  return new Response(body, { status, headers: docsHeaders("text/html; charset=utf-8", "no-store") });
}

function docsHeaders(contentType, cache) {
  return {
    "Content-Type": contentType,
    "Content-Security-Policy": DOCS_CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": cache,
  };
}

async function findDocsFile(env, siteId, version, path) {
  const p = path.replace(/^\/+/, "");
  const candidates = p === "" || p.endsWith("/") ? [`${p}index.html`] : [p, `${p}.html`, `${p}/index.html`];
  for (const c of candidates) {
    const row = await dbFirst(env, "SELECT content_type, body FROM docs_files WHERE site_id = ? AND version = ? AND path = ?", [siteId, version, c]);
    if (row) return row;
  }
  return null;
}

function docsFileResponse(row, method) {
  if (!row) return docsPage(404, "Page not found", "There's no page at this address.");
  return new Response(method === "HEAD" ? null : row.body, { status: 200, headers: docsHeaders(row.content_type, "public, max-age=60") });
}

// Runs before routing: documentation domains get documentation and nothing else.
async function docsHost(request, env) {
  const host = requestHost(request, docsAllowHttp(env));
  if (!host) return null;
  const site = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE hostname = ?`, [host]);
  if (!site) return null;
  const path = new URL(request.url).pathname;
  if (path.startsWith(DOCS_WELL_KNOWN)) {
    const token = path.slice(DOCS_WELL_KNOWN.length);
    if (site.verify_token && token === site.verify_token) return new Response(site.verify_token, { status: 200, headers: docsHeaders("text/plain; charset=utf-8", "no-store") });
    return docsPage(404, "Page not found", "There's no page at this address.");
  }
  if (request.method !== "GET" && request.method !== "HEAD") return docsPage(405, "Not allowed", "Documentation pages can only be read.");
  if (!siteLive(site)) return docsPage(404, "Not published yet", "This documentation isn't published yet.");
  return docsFileResponse(await findDocsFile(env, site.id, site.current_version, path), request.method);
}

// Proves the domain reaches this server (the well-known URL returns the token),
// or that a TXT record _dispatch-docs.<domain> holds it. A Worker usually can't
// fetch its own custom domain, so the TXT record is the reliable route here.
async function checkDomain(allowHttp, hostname, token) {
  const url = `${allowHttp ? "http" : "https"}://${hostname}${DOCS_WELL_KNOWN}${token}`;
  let problem;
  try {
    const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000) });
    if (r.ok && (await r.text()).trim() === token) return null;
    problem = r.ok ? `${url} answered, but not with this server's token` : `${url} returned ${r.status}`;
  } catch (e) {
    problem = `couldn't reach ${url} (${e?.message || e})`;
  }
  const bare = hostname.split(":")[0];
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=_dispatch-docs.${bare}&type=TXT`, { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(10_000) });
    const v = await r.json();
    if ((v.Answer || []).some((a) => String(a.data || "").replace(/^"|"$/g, "") === token)) return null;
  } catch { /* fall through */ }
  return `Not verified: ${problem}, and there's no TXT record _dispatch-docs.${bare} with the token.`;
}

const textField = (v, k) => (typeof v?.[k] === "string" && v[k].trim() ? v[k].trim() : null);
const inScope = (p, ws) => { const s = scopeOf(p); return s === null || s.includes(ws); };

async function reachableSite(env, principal, id) {
  const site = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [id]);
  if (!site) throw fail(404, "No such documentation site");
  if (!inScope(principal, site.workspace_id)) throw fail(403, "You don't have access to this workspace");
  return site;
}

async function siteResponse(env, id, status, withToken) {
  const site = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [id]);
  if (!site) return fail(404, "No such documentation site");
  return jsonOut(status, siteJson(site, withToken, docsAllowHttp(env)));
}

async function docsAudited(env, who, action, method, path, run) {
  let resp;
  try { resp = await run(); } catch (e) { if (e instanceof Response) resp = e; else throw e; }
  await auditInsert(env, who?.userId ?? null, who?.email ?? null, method, path, resp.status, action);
  return resp;
}

async function handleDocsList(env, request, requireAuth, query) {
  let p;
  try { p = await resolvePrincipal(env, request, requireAuth); } catch (e) { return e; }
  const collection = new URLSearchParams(query).get("collection");
  const rows = await dbAll(env, `SELECT ${SITE_COLS} FROM docs_sites ORDER BY name COLLATE NOCASE`);
  const sites = rows.filter((s) => inScope(p, s.workspace_id) && (!collection || s.collection_uid === collection)).map((s) => siteJson(s, p.role === "admin", docsAllowHttp(env)));
  return jsonOut(200, { sites });
}

async function handleDocsCreate(env, request, requireAuth) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  return docsAudited(env, principal, "docs_site_create", "POST", "/admin/docs-sites", async () => {
    if (error) return error;
    const body = await readJsonObject(request);
    if (!body) return fail(400, "Body must be valid JSON");
    const ws = textField(body, "workspace_id"), col = textField(body, "collection_uid"), name = textField(body, "name");
    if (!ws || !col || !name) return fail(400, "Send workspace_id, collection_uid and name");
    if ([...name].length > 120) return fail(400, "Keep the name under 120 characters");
    const id = crypto.randomUUID();
    const now = nowIso();
    try {
      await dbRun(env, "INSERT INTO docs_sites (id, workspace_id, collection_uid, name, domain_status, online, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'none', 0, ?, ?, ?)", [id, ws, col, name, principal.email, now, now]);
    } catch (e) {
      if (/UNIQUE|constraint/i.test(String(e?.message || e))) return fail(409, "This collection already has a documentation site");
      throw e;
    }
    return siteResponse(env, id, 201, true);
  });
}

async function handleDocsUpdate(env, request, requireAuth, id) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  return docsAudited(env, principal, "docs_site_update", "PATCH", `/admin/docs-sites/${id}`, async () => {
    if (error) return error;
    const body = await readJsonObject(request);
    if (!body) return fail(400, "Body must be valid JSON");
    const allowHttp = docsAllowHttp(env);
    const site = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [id]);
    if (!site) return fail(404, "No such documentation site");
    const now = nowIso();
    if ("name" in body) {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name || [...name].length > 120) return fail(400, "The name can't be empty or longer than 120 characters");
      await dbRun(env, "UPDATE docs_sites SET name = ?, updated_at = ? WHERE id = ?", [name, now, id]);
    }
    if ("hostname" in body) {
      let host = null;
      if (body.hostname !== null && !(typeof body.hostname === "string" && !body.hostname.trim())) {
        if (typeof body.hostname !== "string") return fail(400, "hostname must be a string or null");
        host = normalizeHostname(body.hostname, allowHttp);
      }
      if (host && host === requestHost(request, allowHttp)) return fail(400, "That's this server's own address. Use a separate domain or subdomain for the documentation, such as docs.example.com.");
      if (host !== (site.hostname ?? null)) {
        try {
          if (host) await dbRun(env, "UPDATE docs_sites SET hostname = ?, domain_status = 'pending', verify_token = ?, verified_at = NULL, checked_at = NULL, check_message = NULL, online = 0, updated_at = ? WHERE id = ?", [host, toHex(crypto.getRandomValues(new Uint8Array(16))), now, id]);
          else await dbRun(env, "UPDATE docs_sites SET hostname = NULL, domain_status = 'none', verify_token = NULL, verified_at = NULL, checked_at = NULL, check_message = NULL, online = 0, updated_at = ? WHERE id = ?", [now, id]);
        } catch (e) {
          if (/UNIQUE|constraint/i.test(String(e?.message || e))) return fail(409, "Another documentation site already uses that domain");
          throw e;
        }
      }
    }
    if ("online" in body) {
      if (typeof body.online !== "boolean") return fail(400, "online must be true or false");
      const cur = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [id]);
      if (body.online && cur.domain_status !== "verified") return fail(400, "Add and verify a domain before putting the site online");
      if (body.online && (cur.current_version === null || cur.current_version === undefined)) return fail(400, "Publish a version before putting the site online");
      await dbRun(env, "UPDATE docs_sites SET online = ?, updated_at = ? WHERE id = ?", [body.online ? 1 : 0, now, id]);
    }
    return siteResponse(env, id, 200, true);
  });
}

async function handleDocsDelete(env, request, requireAuth, id) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  return docsAudited(env, principal, "docs_site_delete", "DELETE", `/admin/docs-sites/${id}`, async () => {
    if (error) return error;
    const site = await dbFirst(env, "SELECT id FROM docs_sites WHERE id = ?", [id]);
    if (!site) return fail(404, "No such documentation site");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM docs_files WHERE site_id = ?").bind(id),
      env.DB.prepare("DELETE FROM docs_versions WHERE site_id = ?").bind(id),
      env.DB.prepare("DELETE FROM docs_sites WHERE id = ?").bind(id),
    ]);
    return responseWithCors(204);
  });
}

async function handleDocsVerify(env, request, requireAuth, id) {
  const { principal, error } = await requireAdmin(env, request, requireAuth);
  return docsAudited(env, principal, "docs_domain_verify", "POST", `/admin/docs-sites/${id}/verify`, async () => {
    if (error) return error;
    const site = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [id]);
    if (!site) return fail(404, "No such documentation site");
    if (!site.hostname || !site.verify_token) return fail(400, "Add a domain first");
    const problem = await checkDomain(docsAllowHttp(env), site.hostname, site.verify_token);
    const now = nowIso();
    if (problem === null) await dbRun(env, "UPDATE docs_sites SET domain_status = 'verified', verified_at = ?, checked_at = ?, check_message = NULL, updated_at = ? WHERE id = ? AND hostname = ?", [now, now, now, id, site.hostname]);
    else await dbRun(env, "UPDATE docs_sites SET domain_status = 'failed', checked_at = ?, check_message = ?, updated_at = ? WHERE id = ? AND hostname = ?", [now, problem, now, id, site.hostname]);
    return siteResponse(env, id, 200, true);
  });
}

function validDocsPath(path) {
  return typeof path === "string" && path.length > 0 && path.length <= 200 && !path.startsWith("/")
    && !path.split("/").some((seg) => seg === "" || seg === "." || seg === "..") && /^[A-Za-z0-9._/-]+$/.test(path);
}

async function handleDocsPublish(env, request, requireAuth, id) {
  let p;
  try { p = await resolvePrincipal(env, request, requireAuth); } catch (e) { return e; }
  return docsAudited(env, p, "docs_publish", "POST", `/docs-sites/${id}/versions`, async () => {
    if (rankOf(p) < ROLE_RANK.editor) return fail(403, "Viewers can't publish documentation");
    const site = await reachableSite(env, p, id);
    const body = await readJsonObject(request);
    if (!body) return fail(400, "Body must be valid JSON");
    const files = body.files;
    if (!Array.isArray(files)) return fail(400, "Send files: [{ path, content_type, body }]");
    if (!files.length || files.length > DOCS_MAX_FILES) return fail(400, `A version needs between 1 and ${DOCS_MAX_FILES} files`);
    const enc = new TextEncoder();
    let total = 0;
    const seen = new Set();
    for (const f of files) {
      if (typeof f?.path !== "string" || typeof f?.content_type !== "string" || typeof f?.body !== "string") return fail(400, "Every file needs path, content_type and body");
      if (!validDocsPath(f.path)) return fail(400, `"${f.path}" isn't an allowed file path`);
      if (!DOCS_TYPES.includes(f.content_type)) return fail(400, `${f.path}: content type "${f.content_type}" isn't allowed`);
      const size = enc.encode(f.body).length;
      if (size > DOCS_MAX_FILE) return fail(413, `${f.path} is larger than 1 MB`);
      if (seen.has(f.path)) return fail(400, `${f.path} appears twice`);
      seen.add(f.path);
      total += size;
    }
    if (total > DOCS_MAX_VERSION) return fail(413, "A version can't be larger than 20 MB");
    if (!seen.has("index.html")) return fail(400, "A version needs an index.html");
    const changelog = typeof body.changelog === "string" ? [...body.changelog].slice(0, 20000).join("") : "";
    const row = await dbFirst(env, "SELECT COALESCE(MAX(version), 0) + 1 AS v FROM docs_versions WHERE site_id = ?", [site.id]);
    const version = row?.v || 1;
    const now = nowIso();
    const stmts = [
      env.DB.prepare("INSERT INTO docs_versions (site_id, version, published_by, published_at, changelog, file_count, total_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(site.id, version, p.email ?? "open mode", now, changelog, files.length, total),
      ...files.map((f) => env.DB.prepare("INSERT INTO docs_files (site_id, version, path, content_type, body) VALUES (?, ?, ?, ?, ?)").bind(site.id, version, f.path, f.content_type, f.body)),
      env.DB.prepare("UPDATE docs_sites SET current_version = ?, updated_at = ? WHERE id = ?").bind(version, now, site.id),
    ];
    // D1 runs a batch as one transaction.
    await env.DB.batch(stmts);
    const fresh = await dbFirst(env, `SELECT ${SITE_COLS} FROM docs_sites WHERE id = ?`, [site.id]);
    return jsonOut(201, { version, site: siteJson(fresh, p.role === "admin", docsAllowHttp(env)) });
  });
}

async function handleDocsVersions(env, request, requireAuth, id) {
  try {
    const p = await resolvePrincipal(env, request, requireAuth);
    const site = await reachableSite(env, p, id);
    const rows = await dbAll(env, "SELECT version, published_by, published_at, changelog, file_count, total_bytes FROM docs_versions WHERE site_id = ? ORDER BY version DESC", [site.id]);
    return jsonOut(200, { versions: rows.map((r) => ({ ...r, published_by: r.published_by ?? null, current: site.current_version === r.version })) });
  } catch (e) { if (e instanceof Response) return e; throw e; }
}

async function handleDocsSetCurrent(env, request, requireAuth, id) {
  let p;
  try { p = await resolvePrincipal(env, request, requireAuth); } catch (e) { return e; }
  return docsAudited(env, p, "docs_rollback", "PATCH", `/docs-sites/${id}`, async () => {
    if (rankOf(p) < ROLE_RANK.editor) return fail(403, "Viewers can't change the published version");
    const site = await reachableSite(env, p, id);
    const body = await readJsonObject(request);
    if (!body) return fail(400, "Body must be valid JSON");
    if (!Number.isInteger(body.current_version)) return fail(400, "Send current_version");
    const exists = await dbFirst(env, "SELECT 1 AS x FROM docs_versions WHERE site_id = ? AND version = ?", [site.id, body.current_version]);
    if (!exists) return fail(404, "No such version");
    await dbRun(env, "UPDATE docs_sites SET current_version = ?, updated_at = ? WHERE id = ?", [body.current_version, nowIso(), site.id]);
    return siteResponse(env, site.id, 200, p.role === "admin");
  });
}

async function handleDocsPreview(env, request, requireAuth, id, version, path) {
  try {
    const p = await resolvePrincipal(env, request, requireAuth);
    const site = await reachableSite(env, p, id);
    const row = await findDocsFile(env, site.id, version, path);
    if (!row) return fail(404, "No such file in that version");
    return docsFileResponse(row, request.method);
  } catch (e) { if (e instanceof Response) return e; throw e; }
}

async function docsRoute(request, env, path, query, requireAuth) {
  const m = request.method;
  if (path === "/admin/docs-sites" && m === "POST") return handleDocsCreate(env, request, requireAuth);
  let r = /^\/admin\/docs-sites\/([^/]+)\/verify$/.exec(path);
  if (r && m === "POST") return handleDocsVerify(env, request, requireAuth, percentDecode(r[1]));
  r = /^\/admin\/docs-sites\/([^/]+)$/.exec(path);
  if (r && m === "PATCH") return handleDocsUpdate(env, request, requireAuth, percentDecode(r[1]));
  if (r && m === "DELETE") return handleDocsDelete(env, request, requireAuth, percentDecode(r[1]));
  if (path === "/docs-sites" && m === "GET") return handleDocsList(env, request, requireAuth, query);
  r = /^\/docs-sites\/([^/]+)$/.exec(path);
  if (r && m === "PATCH") return handleDocsSetCurrent(env, request, requireAuth, percentDecode(r[1]));
  r = /^\/docs-sites\/([^/]+)\/versions$/.exec(path);
  if (r && m === "GET") return handleDocsVersions(env, request, requireAuth, percentDecode(r[1]));
  if (r && m === "POST") return handleDocsPublish(env, request, requireAuth, percentDecode(r[1]));
  r = /^\/docs-sites\/([^/]+)\/versions\/(\d+)\/files\/(.+)$/.exec(path);
  if (r && (m === "GET" || m === "HEAD")) return handleDocsPreview(env, request, requireAuth, percentDecode(r[1]), Number(r[2]), r[3]);
  return null;
}

// ---------------------------------------------------------------------------
// router

// Contract paths are their own routes; everything else falls into the proxy
// (which mirrors Postman's path space).
export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);
    } catch (e) {
      return jsonOut(500, { error: `Server database failed to initialize: ${e?.message || e}` });
    }
    // A documentation domain never reaches the API or the admin panel.
    const docs = await docsHost(request, env);
    if (docs) return docs;
    return route(request, env);
  },
};

// The binary migrates at boot; here the only boot is the first request.
// Idempotent CREATE TABLE IF NOT EXISTS, run once per isolate lifetime — this
// is what makes one-click deploy buttons work (a fresh D1 arrives empty and
// needs no `wrangler d1 execute` step before the first `/admin` or login).
let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) {
    const ddl = [
      `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL, workspace_grants TEXT, created_at TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS collections_map (uid TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, name TEXT, updated_at TEXT)`,
      `CREATE TABLE IF NOT EXISTS environments_map (uid TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, name TEXT, updated_at TEXT)`,
      `CREATE TABLE IF NOT EXISTS postman_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, region TEXT NOT NULL, key_ciphertext TEXT NOT NULL, key_hint TEXT NOT NULL, postman_user_id TEXT, postman_name TEXT, created_by TEXT, created_at TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS workspace_accounts (workspace_id TEXT NOT NULL, account_id INTEGER NOT NULL, name TEXT, type TEXT, PRIMARY KEY (workspace_id, account_id))`,
      `CREATE TABLE IF NOT EXISTS dispatch_workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, globals TEXT NOT NULL, created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS dispatch_items (uid TEXT PRIMARY KEY, kind TEXT NOT NULL, workspace_id TEXT NOT NULL, name TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
      `CREATE INDEX IF NOT EXISTS dispatch_items_workspace ON dispatch_items (workspace_id, kind)`,
      `CREATE TABLE IF NOT EXISTS docs_sites (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, collection_uid TEXT NOT NULL UNIQUE, name TEXT NOT NULL, hostname TEXT UNIQUE, domain_status TEXT NOT NULL DEFAULT 'none', verify_token TEXT, verified_at TEXT, checked_at TEXT, check_message TEXT, online INTEGER NOT NULL DEFAULT 0, current_version INTEGER, created_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS docs_versions (site_id TEXT NOT NULL, version INTEGER NOT NULL, published_by TEXT, published_at TEXT NOT NULL, changelog TEXT NOT NULL DEFAULT '', file_count INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (site_id, version))`,
      `CREATE TABLE IF NOT EXISTS docs_files (site_id TEXT NOT NULL, version INTEGER NOT NULL, path TEXT NOT NULL, content_type TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY (site_id, version, path))`,
      `CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, user_id INTEGER, email TEXT, action TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL)`,
    ];
    schemaReady = env.DB.batch(ddl.map((sql) => env.DB.prepare(sql)));
  }
  return schemaReady;
}

async function route(request, env) {
  const url = new URL(request.url);
  const requireAuth = String(env.REQUIRE_AUTH ?? "true").toLowerCase() !== "false";
  const path = url.pathname;
  const query = url.search.slice(1);

  if (request.method === "OPTIONS") return responseWithCors(204);

  if (request.method === "GET" || request.method === "HEAD") {
    if (path === "/admin") {
      return responseWithCors(303, undefined, { Location: "/admin/" });
    }
    if (path === "/admin/" || path.startsWith("/admin/")) {
    // Panel assets live at the assets root (index.html, app.js, …);
    // map /admin/ → "/" and /admin/<file> → "/<file>". The admin API paths
    // (/admin/users, /admin/postman-accounts, /admin/workspaces, /admin/settings,
    // /admin/audit) are handled below, not here.
    const isAdminApi = /^\/admin\/(users|postman-accounts|workspaces|dispatch-workspaces|settings|audit|docs-sites)/.test(path);
    if (!isAdminApi) return serveAdmin(env, request, path === "/admin/" ? "" : path.slice("/admin/".length));
    }
  }

  // Auth endpoints.
  if (request.method === "POST" && path === "/auth/register") return handleRegister(env, request, requireAuth);
  if (request.method === "POST" && path === "/auth/login") return handleLogin(env, request);
  if (request.method === "POST" && path === "/auth/logout") return handleLogout(env, request, requireAuth);
  if (request.method === "POST" && path === "/auth/admin-login") return handleAdminLogin(env, request, requireAuth);
  if (path === "/me") return handleMe(env, request, requireAuth);

  // Admin API.
  if (path === "/admin/users" && request.method === "GET") return handleAdminUsersList(env, request, requireAuth);
  if (path === "/admin/users" && request.method === "POST") return handleAdminUsersCreate(env, request, requireAuth);
  const userMatch = /^\/admin\/users\/(\d+|[^/]+)$/.exec(path);
  if (userMatch) {
    if (request.method === "PATCH") return handleAdminUsersUpdate(env, request, requireAuth, userMatch[1]);
    if (request.method === "DELETE") return handleAdminUsersDelete(env, request, requireAuth, userMatch[1]);
  }
  if (path === "/admin/postman-accounts" && request.method === "GET") return handleAdminAccountsList(env, request, requireAuth);
  if (path === "/admin/postman-accounts" && request.method === "POST") return handleAdminAccountsCreate(env, request, requireAuth);
  const accountMatch = /^\/admin\/postman-accounts\/([^/]+)$/.exec(path);
  if (accountMatch) {
    if (request.method === "PATCH") return handleAdminAccountsUpdate(env, request, requireAuth, accountMatch[1]);
    if (request.method === "DELETE") return handleAdminAccountsDelete(env, request, requireAuth, accountMatch[1]);
  }
  if (path === "/admin/workspaces" && request.method === "GET") return handleAdminWorkspaces(env, request, requireAuth);
  if (path === "/admin/dispatch-workspaces" && request.method === "POST") return handleAdminDispatchCreate(env, request, requireAuth);
  if (path === "/admin/dispatch-workspaces/import" && request.method === "POST") return handleAdminDispatchImport(env, request, requireAuth);
  const dispatchMatch = /^\/admin\/dispatch-workspaces\/([^/]+)$/.exec(path);
  if (dispatchMatch && dispatchMatch[1] !== "import") {
    const id = percentDecode(dispatchMatch[1]);
    if (request.method === "PATCH") return handleAdminDispatchUpdate(env, request, requireAuth, id);
    if (request.method === "DELETE") return handleAdminDispatchDelete(env, request, requireAuth, id);
  }
  if (path === "/admin/settings") {
    if (request.method === "GET") return handleAdminSettingsGet(env, request, requireAuth);
    if (request.method === "PATCH") return handleAdminSettingsPatch(env, request, requireAuth);
  }
  if (path === "/admin/audit" && request.method === "GET") return handleAdminAudit(env, request, requireAuth, query);

  // Published documentation.
  const docsResponse = await docsRoute(request, env, path, query, requireAuth);
  if (docsResponse) return docsResponse;

  // The proxy fallback for everything else (Postman path space).
  return proxy(env, request, requireAuth);
}