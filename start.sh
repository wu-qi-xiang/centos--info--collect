#!/usr/bin/env sh
set -eu

mkdir -p logs uploads

if [ "${RUN_MODE:-dev}" = "prod" ]; then
    exec gunicorn PyLinux.wsgi:application -c deploy/gunicorn.conf.py
fi

exec python manage.py runserver "${DJANGO_BIND:-0.0.0.0:8000}"
