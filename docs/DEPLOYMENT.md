# Docker Deployment Guide

useMeter is a Bun HTTP service with SQLite persistence. It is **not** deployable by uploading `dist/client` into ReverseProxy's `my_webapp`: that app serves static/PHP files and does not run Bun, SQLite migrations, polling, or OAuth callback routes.

## Required server prerequisites

Ensure the host system provides:

- Docker Engine and Docker Compose v2
- Docker access for the deployment account, or an administrator-run deployment
- A writable deployment directory, for example `/opt/usemeter`
- A persistent Docker volume for `/app/data`
- A domain or subdomain, for example `usemeter.example.com`
- A reverse proxy route from that domain to `127.0.0.1:3100`
- A production `USAGE_MASTER_KEY` stored outside the repository

The current `murat` SSH account on `production-server` has neither Docker socket access nor Bun/Node/npm, and cannot run system administration commands without sudo.

## Install

From the deployment directory:

```sh
git clone https://github.com/muwat0/useMeter.git .
# Or fetch the desired release commit from the canonical repository.

export USAGE_MASTER_KEY='generate-a-long-random-secret'
docker compose build
docker compose up -d
```

Do not commit `.env` or the master key. For repeatable deployments, use a root-readable environment file outside the checkout and pass it with Compose's `--env-file` option.

## Verify

```sh
curl --fail http://127.0.0.1:3100/health
# Expected JSON includes: {"status":"ok","integrity":true}

docker compose ps
docker compose logs --tail=100 usemeter
```

The dashboard is served at `/`; `/assets/app.js` and `/assets/app.css` are local image assets. The SQLite database lives in the named `usemeter-data` volume at `/app/data/usage.db`.

## Reverse proxy

Configure your reverse proxy to proxy the selected HTTPS domain to `127.0.0.1:3100`. Preserve the `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers. Set `TRUST_PROXY=true` only when the proxy path is controlled and these headers cannot be spoofed by direct public access.

The application already emits security headers and uses conditional HSTS. Keep TLS termination at the reverse proxy and do not expose port 3100 publicly; the Compose file binds it to loopback by default.

## Updates and rollback

```sh
git fetch origin main
git checkout <release-commit>
docker compose build
docker compose up -d
```

The named volume must remain untouched during image updates. Before destructive database operations, make a SQLite backup from the running volume. Roll back by checking out the previous known-good commit and rebuilding the image.

## Current blocker

Deployment cannot be executed by the repository SSH account until an administrator grants Docker access or performs the reverse-proxy setup. No server files, secrets, or reverse proxy configuration should be changed without that authorization.
