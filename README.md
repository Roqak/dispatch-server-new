# dispatch-server on Cloudflare Workers

The [Deploy to Cloudflare button](https://deploy.workers.cloudflare.com/?url=https://github.com/Ash-io/dispatch/tree/main/worker) deploys this Worker and its D1 database, and prompts for the secrets. Set `SECRET_KEY` to at least 32 random characters (`openssl rand -hex 32`): it encrypts the Postman keys you add in the panel. Leave `ADMIN_PASSWORD` as anything strong: it's only used when `REQUIRE_AUTH` is `"false"`. Manual deployment is below.

This folder must stay self-contained, because the button treats it as the root of a new repository. Nothing in it can point outside `worker/`.

The first account registered becomes admin and registration is open by default. Straight after deploying, open `/admin/`, choose **New server? Create the first account**, then add your Postman keys under **Postman accounts**. New sign-ups see nothing until you give them a workspace.

```sh
npm run deploy:server   # from the repo root: provisions D1, binds it, deploys;
                        # wrangler creates the database on first deploy
cd worker
npx wrangler secret put SECRET_KEY        # encrypts stored Postman keys: openssl rand -hex 32
# REQUIRE_AUTH=false deploys additionally need:
npx wrangler secret put ADMIN_PASSWORD
```

No schema step is required: on the first request the Worker migrates itself (the same idempotent `CREATE TABLE IF NOT EXISTS` set `server/src/db.rs` runs at boot). `worker/schema.sql` exists for manual inspection/re-apply:

```sh
(cd worker && npx wrangler d1 execute dispatch-server --remote --file schema.sql)
```

## What is configured where

- `worker/wrangler.jsonc`: Worker name, D1 binding `DB` (auto-provisioned; to bind an existing database add `database_id` yourself), the admin panel assets (`admin/`, a copy of the server's, kept identical by `npm test`), and the `REQUIRE_AUTH` / `POSTMAN_REGION` vars.
- `worker/.dev.vars.example`: the secrets this Worker uses — `SECRET_KEY`, and `ADMIN_PASSWORD` when running without auth enforcement. `POSTMAN_API_KEY` is still honoured as one more account. Never commit `.dev.vars`.

A Worker deployed before multiple accounts keeps working with its `POSTMAN_API_KEY`. To add keys in the panel, set `SECRET_KEY` on it first. Changing `SECRET_KEY` later means re-entering every stored key.
- `worker/src/index.js`: the whole Worker (same contract, roles, redaction and admin API as the Rust binary).

## Local development

```sh
cd worker && npx wrangler dev   # local D1, panel on /admin/
```

Local state lives in `.wrangler/` (gitignored). If a request answers `Server database failed to initialize`, the previous section's `d1 execute --file schema.sql --local` (from `worker/`) re-applies by hand.

## Behavior notes

- Everything from the binary contract carries over: roles `viewer < editor < creator < admin`, workspace grants, admin-only deletes, secret redaction for viewers, audit log, verbatim Postman passthrough, `/admin/` panel — including its login (the same `POST /auth/login` / `POST /auth/admin-login` endpoints).
- Workspaces stored on the server (no Postman account needed) work the same as with the binary. D1 caps a row at about 2 MB, so a single collection, environment or set of global variables larger than that is refused with a clear error; the binary has no such limit. Copying a Postman workspace makes one subrequest per collection and environment, so large workspaces need a paid Workers plan. Back up the D1 database (`npx wrangler d1 export`).
- Passwords are PBKDF2-SHA256 (native WebCrypto) instead of argon2 because Workers' CPU budget can't run argon2; `PBKDF2_ITERATIONS` raises the rounds on paid plans.
- Postman's API rate limits attach to each key, and list merges fan out per connected account and per granted workspace — the free plan's 50-subrequests-per-request cap matters if you connect many accounts or grant many workspaces. Heavy use wants a paid Workers plan.
- Register/login behave identically to the binary (first registered user becomes admin); admin user management, settings and the audit log live in the same `/admin/` panel.