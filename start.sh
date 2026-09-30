#!/bin/zsh
set -euo pipefail

ROOT_DIR=${0:A:h}
cd "$ROOT_DIR"

if [[ ! -x .venv/bin/python ]]; then
    print -u2 "Missing .venv. Follow the setup steps in README.md first."
    exit 1
fi
if [[ ! -f .env ]]; then
    print -u2 "Missing .env. Create it from .env.example and set PC_CONTROL_TOKEN."
    exit 1
fi
if ! command -v cloudflared >/dev/null; then
    print -u2 "cloudflared is not installed."
    exit 1
fi

set -a
source .env
set +a

port=${PC_CONTROL_PORT:-5001}
if [[ ! "$port" =~ '^[0-9]+$' ]] || (( port < 1 || port > 65535 )); then
    print -u2 "PC_CONTROL_PORT must be a valid TCP port."
    exit 1
fi

existing_pids=("${(@f)$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)}")
if (( ${#existing_pids[@]} > 0 )) && [[ -n "${existing_pids[1]}" ]]; then
    print "Stopping the existing listener on port $port..."
    kill -TERM "${existing_pids[@]}" 2>/dev/null || true

    for _ in {1..50}; do
        remaining_pids=("${(@f)$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)}")
        if (( ${#remaining_pids[@]} == 0 )) || [[ -z "${remaining_pids[1]:-}" ]]; then
            break
        fi
        sleep 0.1
    done

    remaining_pids=("${(@f)$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)}")
    if (( ${#remaining_pids[@]} > 0 )) && [[ -n "${remaining_pids[1]:-}" ]]; then
        print "The old listener did not stop gracefully; forcing it to exit..."
        kill -KILL "${remaining_pids[@]}" 2>/dev/null || true
        for _ in {1..20}; do
            lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break
            sleep 0.1
        done
    fi

    if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        print -u2 "Port $port is still occupied after stopping the old listener."
        exit 1
    fi
fi

pkill -f "cloudflared tunnel.*127.0.0.1:$port" 2>/dev/null || true

runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/muse-pc-control.XXXXXX")
server_log="$runtime_dir/server.log"
tunnel_log="$runtime_dir/tunnel.log"
server_pid=''
tunnel_pid=''

cleanup() {
    print "\nStopping Muse PC Control..."
    [[ -n "$tunnel_pid" ]] && kill "$tunnel_pid" 2>/dev/null || true
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
    wait "$tunnel_pid" "$server_pid" 2>/dev/null || true
    rm -rf "$runtime_dir"
}
trap cleanup EXIT INT TERM

./.venv/bin/python app.py >"$server_log" 2>&1 &
server_pid=$!

for _ in {1..50}; do
    if curl -fsS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log" >&2
        exit 1
    fi
    sleep 0.1
done

if ! curl -fsS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
    print -u2 "The local service did not become ready."
    cat "$server_log" >&2
    exit 1
fi

cloudflared tunnel --no-autoupdate --protocol http2 --url "http://127.0.0.1:$port" >"$tunnel_log" 2>&1 &
tunnel_pid=$!

public_url=''
for _ in {1..150}; do
    public_url=$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$tunnel_log" | head -n 1 || true)
    [[ -n "$public_url" ]] && break
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then
        cat "$tunnel_log" >&2
        exit 1
    fi
    sleep 0.1
done

if [[ -z "$public_url" ]]; then
    print -u2 "Cloudflare Tunnel did not provide a public URL."
    cat "$tunnel_log" >&2
    exit 1
fi

notification_recipient=${MUSE_IMESSAGE_RECIPIENT:-}
if [[ -n "$notification_recipient" ]]; then
    if [[ "$notification_recipient" =~ '^\+?[0-9][0-9 ()-]{5,30}$' ]] || \
       [[ "$notification_recipient" =~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' ]]; then
        if /usr/bin/osascript "$ROOT_DIR/scripts/send_muse_url.applescript" \
            "$notification_recipient" "$public_url" >/dev/null; then
            print "URL notification sent through Messages (token omitted)."
        else
            print -u2 "Warning: Messages could not send the URL notification. The service remains available."
        fi
    else
        print -u2 "Warning: MUSE_IMESSAGE_RECIPIENT is invalid; URL notification was skipped."
    fi
fi

print ""
print "Muse PC Control is ready"
print "Local URL:  http://127.0.0.1:$port"
print "Muse URL:   $public_url"
print ""
print "Keep this terminal open. Press Ctrl+C to stop the service and tunnel."

wait "$tunnel_pid"