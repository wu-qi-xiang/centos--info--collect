#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")"

mkdir -p logs uploads .cache/matplotlib

export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"

if [ -z "${PYTHON_BIN:-}" ]; then
    if [ -x ".venv/bin/python" ]; then
        PYTHON_BIN=".venv/bin/python"
    else
        PYTHON_BIN="python"
    fi
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1 && [ ! -x "$PYTHON_BIN" ]; then
    echo "Python interpreter not found or not executable: $PYTHON_BIN" >&2
    echo "Run: python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi

"$PYTHON_BIN" manage.py migrate --noinput

if [ "${RUN_MODE:-dev}" = "prod" ]; then
    exec gunicorn PyLinux.wsgi:application -c deploy/gunicorn.conf.py
fi

RUNSERVER_ARGS="${RUNSERVER_ARGS:---noreload}"

exec "$PYTHON_BIN" manage.py runserver "${DJANGO_BIND:-0.0.0.0:8000}" $RUNSERVER_ARGS
