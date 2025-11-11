#!/bin/bash
# Start script for Floaty Erlang application

# Read environment variables and set defaults
export PORT="${PORT:-8080}"
export FLOATY_USERNAME="${FLOATY_USERNAME:-admin}"
export FLOATY_PASSWORD="${FLOATY_PASSWORD:-floaty}"
export FLOATY_COOKIE_MAX_AGE="${FLOATY_COOKIE_MAX_AGE:-259200}"
export FLOATY_NO_AUTH="${FLOATY_NO_AUTH:-false}"

# Create data directory
mkdir -p data

# Start the application
cd "$(dirname "$0")"
erl -pa _build/default/lib/*/ebin \
    -eval "application:ensure_all_started(floaty_erl)" \
    -eval "io:format('Application started~n')" \
    -noshell
