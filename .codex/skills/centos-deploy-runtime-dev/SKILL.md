---
name: centos-deploy-runtime-dev
description: Work on runtime configuration, environment variables, Django settings, Docker, Compose, Gunicorn, Kubernetes manifests, static/media paths, and production checks in centos--info--collect.
---

# Centos Deploy Runtime Dev

## When To Use

Use for `PyLinux/settings.py`, runtime environment variables, production checks, dependencies, Docker/Compose/Gunicorn/Kubernetes, static/media/log/upload paths, and deployment docs.

## Execution Rule

For development work, the main agent plans and delegates after user confirmation. Subagents perform implementation within explicit file/responsibility ownership. The main agent reviews, integrates, validates, and reports.

## Fast Path

### Add or change a setting

Read:
1. `PyLinux/settings.py`
2. `PyLinux/checks.py`
3. `README.md`
4. `.env.example` if present
5. affected tests/checks

Change:
1. Use environment-driven configuration with sane local defaults.
2. Do not bake real secrets into code or docs.
3. Preserve local SQLite behavior unless explicitly changing database runtime.
4. Add or update production checks if the setting affects safety.
5. Document new environment variables.

### Change container or deployment files

Read:
1. `deploy/Dockerfile`
2. `deploy/docker-compose.yml`
3. `deploy/gunicorn.conf.py`
4. `deploy/requirements-prod.txt`
5. `k8s/k8s-dockerfile`, `k8s/k8s-django.yaml`, `k8s/requirements.txt`
6. `README.md`

Change:
1. Keep `manage.py` root-location reality in mind.
2. Preserve static/media/log/upload paths unless the deployment task changes them.
3. Avoid major dependency upgrades unless explicitly requested.
4. Keep secrets environment-driven.

## Invariants

- The app runs on the verified Python 3.11 and Django 4.2.16 baseline.
- Use the pinned dependency set; do not substitute unsupported Python or Django versions.
- Runtime code remains at repository top level to preserve old imports and migrations.
- Production checks should warn about unsafe debug/host/secret defaults.

## Validation

```bash
.venv/bin/python manage.py check
```

For Compose changes:

```bash
docker compose -f deploy/docker-compose.yml config
```

Image builds or dependency installs may require network access and may fail on modern Python.

## Shared References

- `../centos-feature-dev/references/change-recipes.md`
- `../centos-feature-dev/references/django-legacy-standards.md`
- `../centos-feature-dev/references/security-checkpoints.md`
- `../centos-feature-dev/references/documentation-rules.md`
- `../centos-feature-dev/references/runtime-env-dictionary.md`
- `../centos-feature-dev/references/test-matrix.md`
- `../centos-feature-dev/references/review-checklist.md`
