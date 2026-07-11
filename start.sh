#!/usr/bin/env sh
set -eu

mkdir -p logs uploads

if [ -z "${PYTHON_BIN:-}" ]; then
    if [ -x ".venv/bin/python" ]; then
        PYTHON_BIN=".venv/bin/python"
    else
        PYTHON_BIN="python"
    fi
fi

"${PYTHON_BIN}" manage.py migrate --noinput

if [ "${RUN_MODE:-dev}" = "prod" ]; then
    exec gunicorn PyLinux.wsgi:application -c deploy/gunicorn.conf.py
fi

exec "${PYTHON_BIN}" manage.py runserver "${DJANGO_BIND:-0.0.0.0:8000}"
