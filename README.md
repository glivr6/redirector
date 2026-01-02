## URL Forwarder Manager (Flask + SQLite)

Tiny, boring-in-a-good-way redirect manager you can deploy as a single container. It includes:

- **Admin UI** at `/admin` to create/edit/delete redirect rules (HTTP Basic Auth).
- **Redirect engine** for all non-`/admin` paths.
- **SQLite persistence** stored in a single file (mount a volume to keep it across redeploys).

---

## Environment variables

- **PORT**: default `8000`
- **DB_PATH**: default `/app/data/redirects.db`
- **ADMIN_USER**: default `admin`
- **ADMIN_PASS**: default `admin`

**Important:** Change `ADMIN_USER` / `ADMIN_PASS` in production.

---

## Local quickstart (Docker)

Build:

```bash
docker build -t redirector .
```

Run (persist DB on your machine):

```bash
docker run --rm -p 8000:8000 \
  -e ADMIN_USER=admin -e ADMIN_PASS=change-me \
  -v "$(pwd)/data:/app/data" \
  redirector
```

Then open:

- `/admin` (basic auth)
- any other path will attempt to redirect

---

## Redirect behavior

- Any request to `/admin*` is handled by the admin routes only.
- All other requests attempt to match a rule and immediately redirect.
- If no rule matches, the app returns:
  `No redirect rule matched. Go to /admin to create one.`

### Matching rules

Each rule contains:

- **host**: blank = match any host  
  The app prefers `X-Forwarded-Host` (first value if comma-separated), otherwise uses the request host (port stripped).
- **path_prefix**: blank = match any path (prefix match)
- **target_base**: required (e.g. `https://target.com` or `https://target.com/base`)
- **code**: 301 / 302 / 307 / 308
- **enabled**: on/off
- **sort_order**: integer (lower wins)

Priority:

1. exact host match over blank host
2. longer `path_prefix` wins (more specific)
3. lower `sort_order` wins
4. lower `id` wins

### Redirect composition (path + query preserved)

Example:

- `target_base = https://foo.com/base`
- request `/bar?x=1`
- redirect to `https://foo.com/base/bar?x=1`

---

## Coolify deployment

### 1) Create a new service (Dockerfile)

- Point Coolify at this repo
- Build from `Dockerfile`

### 2) Set environment variables

At minimum:

- `ADMIN_USER`: strong username
- `ADMIN_PASS`: strong password

Optional:

- `PORT` (Coolify usually sets/handles this via reverse proxy; default is fine)
- `DB_PATH` (default is fine)

### 3) Mount a volume for persistence

Mount a persistent volume to:

- **Container path:** `/app/data`

This keeps `redirects.db` across redeploys.

### 4) Domains / multiple domains

In Coolify, add all desired domains to the same service (as additional domains).  
Rules can be host-specific (exact host match) or host-agnostic (blank host).

---

## Test plan

### Run locally

```bash
docker build -t redirector .
docker run --rm -p 8000:8000 -v "$(pwd)/data:/app/data" redirector
```

### Verify `/admin` basic auth

Should fail without auth:

```bash
curl -i http://localhost:8000/admin
```

Should succeed with auth:

```bash
curl -i -u admin:admin http://localhost:8000/admin
```

### Verify redirects with curl

1) Create a rule in `/admin`:

- host: (blank)
- path_prefix: `/docs`
- target_base: `https://example.com/base`
- code: `302`
- enabled: checked
- sort_order: `0`

2) Test redirect:

```bash
curl -i http://localhost:8000/docs/page?x=1
```

Expect `Location: https://example.com/base/docs/page?x=1`

### Verify host matching (reverse proxy behavior)

Create a rule with:

- host: `a.example.com`
- path_prefix: (blank)
- target_base: `https://target.example/a`

Then test using `X-Forwarded-Host`:

```bash
curl -i -H "X-Forwarded-Host: a.example.com" http://localhost:8000/anything
```

Expect a redirect to `https://target.example/a/anything`


