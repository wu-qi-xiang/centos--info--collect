#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")"

mkdir -p logs uploads .cache/matplotlib

export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"

PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"

if [ ! -x "$PYTHON_BIN" ]; then
    echo "Python interpreter not found or not executable: $PYTHON_BIN" >&2
    echo "Run: python3 -m venv .venv && .venv/bin/pip install Django==2.1.7" >&2
    exit 1
fi

RUNSERVER_ARGS="${RUNSERVER_ARGS:---noreload}"

exec "$PYTHON_BIN" manage.py runserver "${DJANGO_BIND:-127.0.0.1:8000}" $RUNSERVER_ARGS
