# ProCDN 

ProCDN is a Cloudflare Workers CDN and asset proxy with GitHub delivery, configurable upstream sources, Cloudflare Cache API caching, an admin dashboard, API keys, settings, counters and recent logs.

## Features
- GitHub CDN: `/gh/OWNER/REPO@VERSION/path/to/file.js`
- Configured source CDN: `/s/SLUG/path/to/file.js`
- Automatic domain detection: reads the incoming CDN hostname and serves requests on every hostname routed to this Worker.
- Host-based proxy route: `/proxy/DOMAIN/path/to/file.js` (origin domain must first be allowlisted in a URL source).
- Dashboard for source management, TTL settings, API keys, counters and logs
- One-time administrator setup; credentials stored in D1, password hashed with PBKDF2
- KV-backed source/settings/API key metadata and approximate counters/logs
- CORS and file-extension allowlist
- `X-ProCDN-Cache: HIT|MISS|BYPASS`

## 1. Create Cloudflare resources
1. Create a D1 database in Cloudflare Dashboard.
2. Create a KV namespace in Cloudflare Dashboard.
3. Open Workers & Pages → ProCDN → Settings → Bindings.
4. Add a D1 database binding named exactly `db` and select your D1 database as its Value.
5. Add a KV namespace binding named exactly `kv` and select your KV namespace as its Value.
6. No database IDs or KV IDs need to be added to `wrangler.toml`. Do not add `ADMIN_USERNAME` or `ADMIN_PASSWORD` secrets.

## 2. Initialize D1
Apply `migrations/0001_init.sql` to the D1 database selected as binding `db`. With Wrangler, from the project directory, run:

```bash
npx wrangler d1 execute YOUR_D1_DATABASE_NAME --remote --file=migrations/0001_init.sql
```

Replace `YOUR_D1_DATABASE_NAME` with the name of the D1 database you created. This command selects the database by its Wrangler resource name; it does not require editing `wrangler.toml` or creating a binding there.

## 3. Configure the session secret
Create a long random secret (at least 32 characters). For production, set it in Cloudflare Dashboard → Worker → Settings → Variables and Secrets as a **Secret** named `SESSION_SECRET`.

For local development, create `.dev.vars` (ignored by Git) containing:

```dotenv
SESSION_SECRET="replace-with-a-long-random-secret"
```

`.env.example` contains only `SESSION_SECRET`. Production Workers do not automatically load local `.env` files.

## 4. Deploy
Install Node.js, then run:

```bash
npm install
npx wrangler login
npm run deploy
```

Check that the deployed Worker has the `db` and `kv` bindings and the `SESSION_SECRET` secret. Open the Worker URL. If the database has no administrator, ProCDN displays the one-time setup form. Create the first username and password; after initialization, the setup page is disabled and login is required.

## Automatic domain detection and host-based proxy

ProCDN reads the incoming hostname from the request URL (`url.hostname`). A Worker can only receive requests for hostnames connected to it through Cloudflare Workers Routes or Custom Domains; adding a hostname in DNS alone does not attach it to this Worker. Attach each CDN hostname in Cloudflare Dashboard and route it to this Worker.

Examples:
- `https://cdn.example.com/gh/OWNER/REPO@VERSION/assets/app.js`
- `https://static.example.com/s/library/assets/app.js`
- `https://cdn.example.com/proxy/example.org/assets/app.js`

For `/proxy/DOMAIN/path`, ProCDN extracts `DOMAIN` from the path and fetches the resource over HTTPS. To prevent this feature becoming an open proxy, the exact domain must already exist as the `allowedHost` of an enabled URL source in Admin → Sources. Create a URL source with:
- Base URL: `https://example.org/`
- Allowed host: `example.org`

The proxy route intentionally does not follow upstream redirects. A redirect response is returned to the client rather than following it to an unapproved host. Only allowed file extensions are served. This is an allowlist-based automatic origin selection, not unrestricted proxying of arbitrary Internet hosts.

## URLs
- `/setup` — one-time administrator setup, only while no admin exists
- `/login` — administrator login
- `/admin` — dashboard
- `/api/health` — health check
- `/gh/OWNER/REPO@VERSION/path/to/file.js` — GitHub CDN
- `/s/SLUG/path/to/file.js` — configured source CDN

## API keys
Create keys in Admin → API keys. The key is shown only once. Use `X-API-Key: pcdn_...` or `Authorization: Bearer pcdn_...`. Read/manage scopes control API access as implemented by the application. Do not expose management keys in browser code or public repositories.

## Custom domain and multi-domain routing

In Cloudflare Dashboard, open Workers & Pages → select `procdn` → Settings/Triggers → Custom Domains and attach each hostname you want to use (or configure a Worker Route for the relevant zone). The hostname is detected automatically from each incoming request. Cloudflare must route every hostname to this Worker; ProCDN cannot intercept arbitrary domains that have not been connected.

In Cloudflare Dashboard, open Workers & Pages → select `procdn` → Settings/Triggers → Custom Domains and add a domain managed by your Cloudflare account.

## Limitations and security notes
- This starter has not been independently security-audited; review before production use.
- Use only assets you are authorized to distribute.
- Counters use KV read-modify-write and are approximate, not transactional analytics.
- The Cache API does not provide wildcard purge by prefix; use Cloudflare Dashboard purge for zone-wide purge.
- Per-key rate limiting is not implemented by this starter; consider Cloudflare rate limiting/WAF rules.
- The first-admin insert uses a unique fixed ID to prevent more than one administrator row. Protect the setup endpoint and review deployment access controls.
