# Production deployment

Copy `.env.production.example` to an environment file, replace every required
secret, then start the stack:

```sh
docker compose --env-file .env.production -f compose.production.yml up -d --build
docker compose -f compose.production.yml up -d --scale browser-worker=8
```

The API, orchestration workers, and browser workers are separate failure and
scaling domains. Do not increase browser concurrency inside a container; scale
browser-worker replicas so each Chromium process has an isolated memory budget.

Back up the PostgreSQL volume and evidence volumes together. A restore is valid
only if evidence hashes still match the restored files.
