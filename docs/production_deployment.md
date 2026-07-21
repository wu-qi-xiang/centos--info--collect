# PostgreSQL and Nginx production reference

`deploy/docker-compose.production.yml` is an opt-in override for the local
SQLite Compose workflow. It adds private PostgreSQL storage and an Nginx entry
point, while retaining the existing `web` Gunicorn and `worker` commands. It
does not start a stack, create credentials, provide TLS certificates, or
replace `deploy/docker-compose.yml`.

The override requires Docker Compose v2.24.4 or newer. It uses the
`env_file.required`, `!reset`, and `!override` Compose features to replace the
local SQLite mounts and published web port without changing the local file.
Confirm the installed version with `docker compose version` before rendering
or deploying this reference.

## Prepare an untracked environment file

Create a file outside the repository with restricted permissions. Do not put
it in version control, logs, shell history, or support tickets. It must contain
the non-placeholder Django secrets and production host names from
`.env.example`, plus the PostgreSQL settings below:

```text
DB_NAME=pylinux
DB_USER=pylinux
DB_PASSWORD=<a-secret-generated-for-this-database>
DB_CONN_MAX_AGE=60
```

Set `DJANGO_DEBUG=False`, `DJANGO_ENV=production`, a non-default
`DJANGO_SECRET_KEY`, a separate `DATA_ENCRYPTION_KEY`, and explicit
`DJANGO_ALLOWED_HOSTS`. The override sets `DB_ENGINE=postgresql`,
`DB_HOST=postgres`, and `DB_PORT=5432`; do not add a PostgreSQL `ports` entry.

For each command, provide the same file to Compose without copying it into the
checkout:

```bash
export PRODUCTION_ENV_FILE=/secure/path/pylinux.production.env
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml config
```

The production requirements include the pinned PostgreSQL Python driver used by
Django. This reference does not install dependencies or start containers; build
and image validation remain required before a live deployment.

## Initialize in order

After image and credential review, use the same two Compose files for each
command. Run database migrations before starting the Worker, then collect the
static files into the shared named volume:

```bash
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml \
  run --rm web python manage.py migrate
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml \
  run --rm web python manage.py collectstatic --noinput
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml \
  run --rm web python manage.py check --deploy
```

Start only after these checks succeed. Nginx is the sole published service on
port 80. It serves `/static/` and forwards application traffic to Gunicorn
without exposing PostgreSQL. 此参考拓扑刻意不对外提供上传文件：Nginx 不挂载
`uploads_data`，`/uploads/` 没有生产路由。这不是受控下载方案；若需对外下载，
必须另行设计并实现明确的授权流程：

```bash
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml up -d
curl --fail http://127.0.0.1/health/live/
curl --fail http://127.0.0.1/health/ready/
```

These health checks intentionally do not authenticate and return no runtime
details. TLS termination, firewall policy, backups, monitoring, and host-level
access controls remain deployment-environment responsibilities.

## Backup preflight and rollback

Before migration, confirm that PostgreSQL logical backups, the `uploads_data`
volume, and environment-file recovery are covered by the organization backup
policy. Store backup artifacts in encrypted, access-controlled storage and
perform a documented isolated restore drill. The SQLite-only helper described
in `docs/runtime_recovery.md` must not be used for PostgreSQL data.

To stop this reference topology, use the same two Compose files and retain
named volumes until recovery is confirmed:

```bash
docker compose --env-file "$PRODUCTION_ENV_FILE" \
  -f deploy/docker-compose.yml -f deploy/docker-compose.production.yml down
```

This does not alter `db.sqlite3`, local `uploads/`, or the default
`deploy/docker-compose.yml` workflow. Return to local development by running
the original SQLite Compose commands without the production override.
