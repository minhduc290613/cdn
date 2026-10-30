# AGENTS.md — ProCDN

## Product scope
ProCDN is a Cloudflare Workers CDN/proxy with GitHub asset delivery, configurable external sources, Cloudflare Cache API caching, an admin dashboard, API key management, cache settings, request counters and recent logs.

## CDN routes and features
- GitHub assets: `/gh/OWNER/REPO@VERSION/path/file.js`.
- Configured sources: `/s/SLUG/path/file.js`.
- Preserve source management, TTL settings, API key creation/revocation, statistics, logs, CORS, extension allowlist, and cache status header `X-ProCDN-Cache`.
- Do not claim a feature works unless implemented and tested. Do not fake statistics or expose secrets in logs.
- Validate all routes, source URLs, paths, and user input. Do not allow proxy access to private/internal hosts.

## Cloudflare bindings — mandatory architecture
The deployment owner configures bindings in Cloudflare Dashboard → Workers & Pages → ProCDN → Settings → Bindings.
- D1 binding name: `db`; value: any compatible D1 database selected by the owner.
- KV binding name: `kv`; value: any compatible KV namespace selected by the owner.
- Optional Workers AI binding name: `ai`, only if AI features are actually implemented.
- Application code must use `env.db` and `env.kv`.
- Do not hardcode database/namespace IDs, require D1/KV entries in `wrangler.toml`, provision databases through Cloudflare API, or require Cloudflare API tokens for database setup.
- `wrangler.toml` remains minimal. Binding names are fixed; the resource values are selected in Dashboard.

## Database and initial admin
- D1 stores the administrator account. Apply `migrations/0001_init.sql` to the D1 database selected as `db`.
- First visit shows a one-time setup page if no admin exists. The user chooses username/password; store only a secure password hash and salt.
- Once initialized, setup must be disabled and login shown. Never provide public registration after initialization.
- Validate username and password; protect initialization against duplicate/concurrent setup. Never log or return plaintext passwords or hashes.
- KV stores the existing application key/value records, including sources, settings, API-key metadata and approximate counters/logs where appropriate.
- Missing bindings or tables must produce actionable configuration errors.

## Secrets
- `.env.example` contains only `SESSION_SECRET`.
- Do not use `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `CLOUDFLARE_API_TOKEN`, or `CLOUDFLARE_ACCOUNT_ID` for this architecture.
- Ignore `.env` and `.dev.vars`; never commit secrets. Production `SESSION_SECRET` must be configured as a Cloudflare Worker secret; local `.env` is not automatically loaded by production Workers.

## Implementation rules
- Inspect the current source before changing it; preserve working features and avoid unnecessary rewrites.
- Use parameterized SQL, secure cookies, signed expiring sessions, server-side authorization, and actionable errors.
- Keep README deployment steps aligned with the actual source. Test build and key routes when possible and report unverified status honestly.

## Automatic domain detection
- Read the CDN hostname from `new URL(request.url).hostname`; Cloudflare only delivers hostnames connected by Custom Domain or Worker Route.
- Support `/proxy/DOMAIN/path/to/file.ext` as host-based origin selection.
- The proxy hostname must exactly match an enabled URL source `allowedHost` entry. Do not create an unrestricted arbitrary-URL proxy.
- Force HTTPS, reject malformed hostnames, credentials, ports and unsafe path segments, enforce the extension allowlist, and do not follow redirects on the automatic proxy route.
- Document that every CDN hostname must be connected to the Worker in Cloudflare. A DNS record by itself does not route traffic to a Worker.
