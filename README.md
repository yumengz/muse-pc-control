# Muse PC Control

A small macOS-only FastAPI service that gives an authorized remote Muse agent a live desktop view, bounded mouse/keyboard control, and an exact-allowlist command runner.

The default phone view is **approval focused**: macOS Accessibility watches the frontmost VS Code window for real sibling action buttons such as `Allow` + `Skip`. Only a small prompt crop is sent to the browser. A real click occurs only after an authenticated user explicitly presses the large **Approve** or **Deny** button, and the app rechecks the accessible controls first to reject stale or changed prompts. Unattended auto-approval is intentionally disabled.

## Start or restart

Run this command from any terminal. It stops the existing process listening on port `5001`, starts the local service, creates a Cloudflare HTTPS quick tunnel, and prints the current Muse URL:

```zsh
cd /path/to/muse-pc-control && ./start.sh
```

The terminal displays both the local URL and the temporary `trycloudflare.com` URL to give Muse. Keep this terminal running. Press `Ctrl+C` to stop both processes. Each new quick-tunnel session gets a new public URL. The command intentionally terminates whichever process currently owns port `5001`.

## Local development with automatic reload

For same-Mac development without a public tunnel, stop any existing launcher with `Ctrl+C`, then run:

```zsh
cd /path/to/muse-pc-control && ./start-dev.sh
```

The development launcher stops an existing reload server or listener on the configured port, binds only to the loopback host configured in `.env`, keeps bearer-token authentication enabled, and automatically restarts the FastAPI process when a Python file changes. Refresh the browser after changes to the embedded HTML, CSS, or JavaScript in `app.py`. Changes to `.env` require stopping and restarting the development launcher.

Do not run `start.sh` and `start-dev.sh` simultaneously. Development mode intentionally creates no Cloudflare tunnel; use `http://127.0.0.1:5001` locally.

## Controller functions

- **Mission-control layout:** a compact sticky header always shows connection state, pending-approval count, screenshot freshness, auto-refresh state, and a one-click screenshot refresh. Approval candidates appear in a fixed top-right overlay and never reflow the dashboard.
- **Agent mode:** add `?agent=1` to the controller URL for denser spacing and disabled UI animations. Keyboard, command, scroll, and OCR-watch panels live behind labeled toolbar buttons; their expanded state persists in browser local storage.
- **Keyboard shortcuts:** enter a validated combination such as `Cmd+A`, `Cmd+Shift+P`, or `Cmd+Option+D`. The API requires one or more recognized modifiers and exactly one recognized action key. **Clear focused field** performs `Cmd+A` followed by Backspace as one serialized operation.
- **Reliable text:** the phone UI uses an atomic clipboard paste by default, preserving newlines and Unicode for up to 16,000 characters. The legacy `/api/type` keystroke endpoint remains available. Paste, type, key, hotkey, and clear-field operations share a server-side lock; a competing request receives `429` rather than interleaving. Successful text responses report the delivered character count, while over-limit input is rejected without truncation. Text contents are never written to the audit log.
- **Allowlisted commands:** the UI loads exact entries from `allowed.txt` into a selector. It never accepts an arbitrary command string from the command panel. Output, timeout, and truncation limits remain enforced by the server.
- **Scrolling:** authenticated scroll requests are limited to 20 wheel clicks in either direction. Zero and out-of-range values are rejected.
- **Full primary display:** the optional desktop stream captures the complete primary monitor. An auto-hidden macOS Dock is not drawn into screenshots until it is revealed; use the Toggle Dock shortcut when needed.
- **Responsive polling:** desktop frames and approval scans never overlap within one browser page. Accessibility checks remain frequent, while expensive visual OCR fallback is rate-limited to prevent it from delaying the desktop stream.
- **OCR text watches:** a bounded phrase can be watched in the VS Code window. Matching changes the browser title and may issue a browser notification. Text watches are notification-only and can never click, approve, or execute a command.

## Automatic startup and URL notification

Run `./install-autostart.sh` once to install a per-user macOS LaunchAgent. It starts `start.sh` automatically after the user logs into the graphical Aqua session and restarts it if it exits. It intentionally does not run before login because Screen Recording, Accessibility, Messages, and desktop automation require a logged-in user session.

Set `MUSE_IMESSAGE_RECIPIENT` in the gitignored `.env` file to an iMessage-enabled phone number or Apple ID email. After each Cloudflare Quick Tunnel starts, Messages sends only the temporary HTTPS URL. The bearer token is never included; keep it in a password manager and provision it separately. On first use, macOS may ask for permission to let the launcher control Messages. Use `./uninstall-autostart.sh` to remove automatic startup.

LaunchAgent output is stored under `~/Library/Logs/MusePCControl`. It contains service status and the temporary URL, but never the bearer token.

## How the bearer token works

`PC_CONTROL_TOKEN` is the long-lived secret that authorizes every `/api/*` request. The server reads it from the gitignored `.env` file when the process starts. `start.sh`, `start-dev.sh`, and automatic login startup reuse the existing value; they do not generate or change it.

The browser sends the token in the `Authorization: Bearer …` header. After a successful connection, the control page stores it in that browser's local storage for the current web origin. A Cloudflare Quick Tunnel creates a different hostname after each restart, so the browser treats each URL as a new origin and may require the same token again. Store the token in Apple Passwords, 1Password, or another trusted password manager so it can be pasted securely on the phone. A named Cloudflare Tunnel with a stable hostname avoids repeated entry after the first successful connection.

The iMessage notification contains only the temporary HTTPS URL. It intentionally never contains the bearer token. Possession of both the URL and token grants powerful control of the Mac, so do not place the token in Messages, email, screenshots, logs, shell history, source control, or chat.

Generate the token once during initial setup and keep `.env` readable only by the local user. Rotate it immediately if it is exposed. After changing or rotating the value in `.env`, restart the running service because an existing process continues using the token it loaded at startup. Then update the corresponding password-manager entry. Normal service restarts do not require rotation.

## Security model

- The server binds to `127.0.0.1` only and refuses non-loopback startup through `app.py`.
- Every `/api/*` request requires `Authorization: Bearer <PC_CONTROL_TOKEN>`.
- Commands must exactly match a non-comment line in `allowed.txt`. Prefix and substring matching are deliberately unsupported.
- Commands run for at most 30 seconds, and stdout/stderr responses are capped at 64 KiB each.
- The bearer token is removed from command subprocess environments.
- API request size, rates, coordinates, mouse buttons, text length, and special keys are bounded.
- Keyboard and text requests use nonblocking backpressure: while one operation is being delivered, another receives `429` and must be retried after completion.
- Keyboard combinations and scrolling are validated against strict key and distance limits.
- OCR text watches only report a match; they have no click or command execution path.
- While an approval prompt is pending, generic clicks, movement, typing, keys, shortcuts, and scrolling are blocked by the backend; only the focused Approve or Deny decision path remains available.
- Commands and control actions are timestamped in `audit.log`; tokens and typed text contents are not logged.
- PyAutoGUI fail-safe is enabled. Move the physical pointer to a screen corner to abort automation.

This is powerful remote-control software. Use a dedicated, random token and stop the server and tunnel when they are not needed.

## Requirements

- macOS
- Python 3.11 or newer
- Screen Recording permission for the application launching the server
- Accessibility permission for the application launching the server

If launched from Terminal, grant permissions to Terminal. If launched from VS Code, grant permissions to Visual Studio Code. Configure both under **System Settings → Privacy & Security** and restart the authorized application afterward.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Generate a token with `openssl rand -hex 32` and either export it as `PC_CONTROL_TOKEN` or save it as `PC_CONTROL_TOKEN=...` in the gitignored `.env` file.
4. Review `allowed.txt` and the scripts under `allowed/`.
5. Run `python app.py`.
6. Open `http://127.0.0.1:5001`, enter the token, and connect.

Example shell session:

    python3.13 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    umask 077
    printf 'PC_CONTROL_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
    python app.py

Do not save the real token in tracked files or shell history.

## API examples

Status:

    curl -H "Authorization: Bearer $PC_CONTROL_TOKEN" http://127.0.0.1:5001/api/status

Screenshot:

    curl -H "Authorization: Bearer $PC_CONTROL_TOKEN" http://127.0.0.1:5001/api/screenshot -o screen.png

  Lightweight structured approval feed (no screenshot transfer):

    curl -H "Authorization: Bearer $PC_CONTROL_TOKEN" http://127.0.0.1:5001/api/approval/pending

  The response reports `pending`, `count`, candidate `id`, redacted OCR `action_text`, and an ISO-8601 `detected_at` timestamp. The current monitor holds at most one focused approval candidate, so `count` is currently `0` or `1`.

Run the sample script after confirming its exact entry exists in `allowed.txt`:

    curl -H "Authorization: Bearer $PC_CONTROL_TOKEN" \
      -H "Content-Type: application/json" \
    -X POST http://127.0.0.1:5001/api/command \
      -d '{"cmd":"./allowed/system_info.sh"}'

The literal safe greeting is another default allowlist entry:

    curl -H "Authorization: Bearer $PC_CONTROL_TOKEN" \
      -H "Content-Type: application/json" \
    -X POST http://127.0.0.1:5001/api/command \
      -d '{"cmd":"printf '\''hello from muse control\\n'\''"}'

## Adding allowed commands

Prefer a fixed, reviewed, non-interactive script in `allowed/`. Add only its exact invocation to `allowed.txt`. Never approve a shell, interpreter, downloader, package manager, broad prefix, or command containing user-controlled arguments.

Changing `./allowed/system_info.sh` to `./allowed/system_info.sh; another-command` is rejected because it is not an exact allowlist entry.

The phone command panel is populated by the authenticated `GET /api/commands` endpoint and submits the selected literal entry to `POST /api/command`. Editing browser markup cannot bypass the backend's exact-match check.

## VS Code approval monitor

- Keep VS Code as the frontmost application while waiting for a prompt.
- The phone page checks locally every 1.5 seconds and transfers no image when there is no candidate.
- A detected candidate sends only a focused crop containing the positive and negative buttons.
- **Approve** and **Deny** re-scan the current screen before clicking. Changed, moved, expired, or missing prompts return `409` and receive no click.
- The full desktop stream is off by default. Use **Enable desktop stream** only when general remote control is needed.
- Only actual macOS Accessibility button elements with recognized sibling approve/deny labels become candidates; explanatory text is ignored.
- Always read the focused crop before deciding. Unattended approvals remain disabled.

## Secure cloud access

Muse cannot reach `127.0.0.1` directly. Expose it only through an HTTPS tunnel such as:

- Cloudflare Tunnel, ideally protected by Cloudflare Access
- Tailscale Funnel or a private tailnet
- ngrok with its authentication/access policies enabled

Never bind publicly and never configure direct router port forwarding. The bearer token remains required even behind the tunnel. Do not share the tunnel URL or token in source control, logs, screenshots, or public chat. `start.sh` creates a temporary Cloudflare Quick Tunnel automatically; `start-dev.sh` remains local-only and creates no tunnel.

## Tests

Tests mock desktop capture and input automation, so they never click or type on the real Mac:

    pytest

## Troubleshooting

- **Black or failed screenshot:** enable Screen Recording for Terminal or VS Code, then restart it.
- **Clicks or typing do nothing:** enable Accessibility for Terminal or VS Code, then restart it.
- **Retina offset:** the UI sends displayed-image dimensions and the backend maps capture pixels to PyAutoGUI's logical display coordinates.
- **API returns 503:** set a `PC_CONTROL_TOKEN` containing at least 32 characters.
- **API returns 403 for a command:** add the exact reviewed command to `allowed.txt`; do not loosen matching.
- **Port 5000 is already used by macOS Control Center/AirPlay Receiver:** add `PC_CONTROL_PORT=5001` to `.env`, then open `http://127.0.0.1:5001`. Alternatively, disable AirPlay Receiver in macOS settings if port 5000 is required.
