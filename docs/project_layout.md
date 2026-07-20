# Project Layout

This repository keeps Django runtime code at the top level to preserve the
legacy import paths used by `manage.py`, migrations, templates, and WSGI.
The verified runtime baseline is Python 3.11 and Django 4.2.16.

## Runtime Code

- `PyLinux/`: Django project settings, root URL configuration, and WSGI.
- `RemoteLinux/`: server inventory, SSH credentials, collection, and WebSSH.
- `linux/`: dashboard and local host information views.
- `monitor/`: threshold configuration and scheduled alert checks.
- `password/`: per-user password management.
- `userprofile/`: login, logout, and registration.
- `devops/`: DevOps automation workflows and JSON APIs.

## Presentation

- `templates/`: Django templates grouped by feature.
- `static/`: CSS, JavaScript, images, and vendored browser assets.

## Operations

- `deploy/`: Dockerfile, Compose, Gunicorn, and production dependency files.
- `k8s/`: Kubernetes manifests and legacy image build files.
- `.env.example`: environment variable reference.

## Documentation And Artifacts

- `docs/`: project notes, API docs, frontend notes, and visual audit artifacts.
- `docs/audit-screenshots/`: generated UI screenshots used during review.

## Runtime Data

- `uploads/`: user-uploaded files.
- `logs/`: application logs.
- `db.sqlite3`: local SQLite database.

Runtime data is ignored by Git and excluded from Docker build contexts.
