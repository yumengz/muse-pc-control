#!/bin/zsh
set -euo pipefail

ROOT_DIR=${0:A:h}
cd "$ROOT_DIR"

if [[ ! -x .venv/bin/uvicorn ]]; then
    print -u2 "Missing .venv or Uvicorn. Follow the setup steps in README.md first."
    exit 1
fi
if [[ ! -f .env ]]; then
    print -u2 "Missing .env. Create it from .env.example and set PC_CONTROL_TOKEN."
    exit 1
fi

set -a
source .env
set +a

host=${PC_CONTROL_HOST:-127.0.0.1}
port=${PC_CONTROL_PORT:-5001}

if [[ "$host" != "127.0.0.1" && "$host" != "localhost" && "$host" != "::1" ]]; then
    print -u2 "Development mode refuses non-loopback host: $host"
    exit 1
fi
if [[ ! "$port" =~ '^[0-9]+$' ]] || (( port < 1 || port > 65535 )); then
    print -u2 "PC_CONTROL_PORT must be a valid TCP port."
    exit 1
fi

reload_pids=("${(@f)$(pgrep -f ".venv/bin/uvicorn app:app.*--port $port.*--reload" 2>/dev/null || true)}")
listener_pids=("${(@f)$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)}")
has_reload=false
has_listener=false
if (( ${#reload_pids[@]} > 0 )) && [[ -n "${reload_pids[1]:-}" ]]; then
    has_reload=true
fi
if (( ${#listener_pids[@]} > 0 )) && [[ -n "${listener_pids[1]:-}" ]]; then
    has_listener=true
fi
if [[ "$has_reload" == true || "$has_listener" == true ]]; then
    print "Stopping the existing development server on port $port..."
    (( ${#reload_pids[@]} > 0 )) && [[ -n "${reload_pids[1]:-}" ]] && \
        kill -TERM "${reload_pids[@]}" 2>/dev/null || true
    (( ${#listener_pids[@]} > 0 )) && [[ -n "${listener_pids[1]:-}" ]] && \
        kill -TERM "${listener_pids[@]}" 2>/dev/null || true

    for _ in {1..50}; do
        lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
        sleep 0.1
    done

    remaining_pids=("${(@f)$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)}")
    if (( ${#remaining_pids[@]} > 0 )) && [[ -n "${remaining_pids[1]:-}" ]]; then
        print "The old development server did not stop gracefully; forcing it to exit..."
        kill -KILL "${remaining_pids[@]}" 2>/dev/null || true
        for _ in {1..20}; do
            lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
            sleep 0.1
        done
    fi

    if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        print -u2 "Port $port is still occupied after stopping the old development server."
        exit 1
    fi
fi

print "Muse PC Control development server"
print "Local URL: http://$host:$port"
print "Python changes reload automatically. Refresh the browser after UI changes."
print "Press Ctrl+C to stop."

exec ./.venv/bin/uvicorn app:app \
    --host "$host" \
    --port "$port" \
    --reload \
    --reload-dir "$ROOT_DIR" \
    --reload-include '*.py'
