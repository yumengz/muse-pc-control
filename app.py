from __future__ import annotations

import asyncio
import hmac
import logging
import os
import platform
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Annotated, Literal

import mss
import mss.tools
import pyautogui
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from approval_monitor import (
    activate_vscode_application,
    approval_pending,
    approval_scan_status,
    candidates_match,
    clear_candidate,
    current_candidate,
    scan_for_approval,
    scan_vscode_text,
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
ALLOWLIST_PATH = BASE_DIR / "allowed.txt"
MAX_COMMAND_OUTPUT = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 30
MAX_REQUEST_BYTES = 64 * 1024
MAX_TEXT_LENGTH = 16_000
TEXT_CHUNK_SIZE = 500
RATE_LIMIT_REQUESTS = 180
RATE_LIMIT_WINDOW_SECONDS = 60
ALLOWED_BUTTONS = {"left", "middle", "right"}
ALLOWED_KEYS = {
    "enter", "return", "tab", "esc", "escape", "space", "backspace", "delete",
    "up", "down", "left", "right", "home", "end", "pageup", "pagedown",
    "command", "ctrl", "control", "alt", "option", "shift",
    *(f"f{number}" for number in range(1, 13)),
}
KEY_ALIASES = {"return": "enter", "escape": "esc", "control": "ctrl", "option": "alt", "cmd": "command"}
HOTKEY_MODIFIERS = {"command", "ctrl", "alt", "shift"}
HOTKEY_KEYS = ALLOWED_KEYS | set("abcdefghijklmnopqrstuvwxyz0123456789") | {
    "`", "-", "=", "[", "]", "\\", ";", "'", ",", ".", "/",
}

pyautogui.FAILSAFE = True

logger = logging.getLogger("muse_pc_control")
logger.setLevel(logging.INFO)
if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    audit_file = RotatingFileHandler(BASE_DIR / "audit.log", maxBytes=2_000_000, backupCount=3)
    audit_file.setFormatter(formatter)
    logger.addHandler(console)
    logger.addHandler(audit_file)

app = FastAPI(title="Muse PC Control", version="1.0.0", docs_url=None, redoc_url=None)
_rate_lock = threading.Lock()
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_watch_lock = threading.Lock()
_watch_phrase = ""
_watch_last_scan_at = 0.0
_watch_last_text = ""


class CommandRequest(BaseModel):
    cmd: str = Field(min_length=1, max_length=500)


class ClickRequest(BaseModel):
    x: float = Field(ge=0)
    y: float = Field(ge=0)
    image_width: float = Field(gt=0)
    image_height: float = Field(gt=0)
    button: Literal["left", "middle", "right"] = "left"


class MoveRequest(BaseModel):
    x: float = Field(ge=0)
    y: float = Field(ge=0)
    image_width: float = Field(gt=0)
    image_height: float = Field(gt=0)
    duration: float = Field(default=0.15, ge=0, le=2)


class TypeRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT_LENGTH)
    interval: float = Field(default=0.01, ge=0, le=0.5)


class KeyRequest(BaseModel):
    key: str = Field(min_length=1, max_length=20)


class HotkeyRequest(BaseModel):
    keys: list[str] = Field(min_length=2, max_length=4)


class ScrollRequest(BaseModel):
    clicks: int = Field(ge=-20, le=20)


class TextWatchRequest(BaseModel):
    text: str = Field(min_length=2, max_length=100)
    enabled: bool = True


class ApprovalDecision(BaseModel):
    decision: Literal["approve", "deny"]


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_BYTES:
                    return Response("Request too large", status_code=413)
            except ValueError:
                return Response("Invalid Content-Length", status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    return response


def require_auth(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    expected = os.getenv("PC_CONTROL_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="PC_CONTROL_TOKEN is not configured securely")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _rate_lock:
        events = _rate_events[client]
        while events and events[0] <= now - RATE_LIMIT_WINDOW_SECONDS:
            events.popleft()
        if len(events) >= RATE_LIMIT_REQUESTS:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        events.append(now)
    return client


AuthClient = Annotated[str, Depends(require_auth)]


def capture_main_display() -> tuple[bytes, int, int]:
    with mss.mss() as capture:
        if len(capture.monitors) < 2:
            raise RuntimeError("No desktop display is available")
        monitor = capture.monitors[1]
        shot = capture.grab(monitor)
        png = mss.tools.to_png(shot.rgb, shot.size)
        return png, shot.width, shot.height


def screenshot_dimensions() -> tuple[int, int]:
    with mss.mss() as capture:
        monitor = capture.monitors[1]
        return int(monitor["width"]), int(monitor["height"])


def control_coordinates(x: float, y: float, image_width: float, image_height: float) -> tuple[int, int]:
    capture_width, capture_height = screenshot_dimensions()
    if x > image_width or y > image_height:
        raise HTTPException(status_code=422, detail="Coordinates are outside the displayed image")
    physical_x = x * capture_width / image_width
    physical_y = y * capture_height / image_height
    logical_width, logical_height = pyautogui.size()
    control_x = round(physical_x * logical_width / capture_width)
    control_y = round(physical_y * logical_height / capture_height)
    return (
        min(max(control_x, 0), max(logical_width - 1, 0)),
        min(max(control_y, 0), max(logical_height - 1, 0)),
    )


def load_allowed_commands() -> set[str]:
    if not ALLOWLIST_PATH.exists():
        return set()
    return {
        line.strip()
        for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def normalize_key(key: str) -> str:
    normalized = key.strip().lower()
    return KEY_ALIASES.get(normalized, normalized)


def validate_hotkey(keys: list[str]) -> list[str]:
    normalized = [normalize_key(key) for key in keys]
    if any(not key or len(key) > 20 or key not in HOTKEY_KEYS for key in normalized):
        raise HTTPException(status_code=422, detail="Hotkey contains an unsupported key")
    if len(set(normalized)) != len(normalized):
        raise HTTPException(status_code=422, detail="Hotkey keys must be unique")
    modifiers = [key for key in normalized if key in HOTKEY_MODIFIERS]
    action_keys = [key for key in normalized if key not in HOTKEY_MODIFIERS]
    if not modifiers or len(action_keys) != 1:
        raise HTTPException(status_code=422, detail="Hotkey requires modifiers and exactly one action key")
    return [*modifiers, action_keys[0]]


def reject_if_approval_pending() -> None:
    if approval_pending():
        raise HTTPException(status_code=409, detail="Use the focused Approve or Deny controls")


def run_allowed_command(cmd: str) -> dict[str, object]:
    allowed = load_allowed_commands()
    if cmd not in allowed:
        logger.warning("command_denied cmd=%r", cmd)
        raise HTTPException(status_code=403, detail="Command is not an exact allowlist entry")

    child_env = os.environ.copy()
    child_env.pop("PC_CONTROL_TOKEN", None)
    logger.info("command_start cmd=%r", cmd)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["/bin/zsh", "-c", cmd],
            cwd=BASE_DIR,
            env=child_env,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = (error.stdout or b"")[:MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace")
        stderr = (error.stderr or b"")[:MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace")
        logger.warning("command_timeout cmd=%r duration=%.3f", cmd, time.monotonic() - started)
        return {"ok": False, "timed_out": True, "returncode": None, "stdout": stdout, "stderr": stderr}

    stdout_bytes = completed.stdout or b""
    stderr_bytes = completed.stderr or b""
    truncated = len(stdout_bytes) > MAX_COMMAND_OUTPUT or len(stderr_bytes) > MAX_COMMAND_OUTPUT
    result = {
        "ok": completed.returncode == 0,
        "timed_out": False,
        "returncode": completed.returncode,
        "stdout": stdout_bytes[:MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace"),
        "stderr": stderr_bytes[:MAX_COMMAND_OUTPUT].decode("utf-8", errors="replace"),
        "truncated": truncated,
    }
    logger.info(
        "command_finish cmd=%r returncode=%s duration=%.3f truncated=%s",
        cmd,
        completed.returncode,
        time.monotonic() - started,
        truncated,
    )
    return result


@app.get("/", response_class=HTMLResponse)
def web_ui() -> HTMLResponse:
    return HTMLResponse(
        INDEX_HTML,
        headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
    )


@app.get("/test/approval", response_class=HTMLResponse)
def approval_test_fixture(request: Request) -> HTMLResponse:
    client = request.client.host if request.client else ""
    if client not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(APPROVAL_TEST_HTML)


@app.get("/api/status")
def api_status(_: AuthClient):
    return {
        "ok": True,
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "system": platform.system(),
    }


@app.get("/api/screenshot")
async def api_screenshot(_: AuthClient):
    try:
        png, width, height = await asyncio.to_thread(capture_main_display)
    except Exception as error:
        logger.exception("screenshot_failed")
        raise HTTPException(
            status_code=503,
            detail="Screenshot failed. Grant Screen Recording permission to the server application.",
        ) from error
    return Response(
        png,
        media_type="image/png",
        headers={"X-Screen-Width": str(width), "X-Screen-Height": str(height)},
    )


@app.post("/api/click")
async def api_click(payload: ClickRequest, client: AuthClient):
    reject_if_approval_pending()
    x, y = await asyncio.to_thread(
        control_coordinates, payload.x, payload.y, payload.image_width, payload.image_height
    )
    try:
        await asyncio.to_thread(pyautogui.click, x=x, y=y, button=payload.button)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("click client=%s x=%d y=%d button=%s", client, x, y, payload.button)
    return {"ok": True, "x": x, "y": y, "button": payload.button}


@app.post("/api/move")
async def api_move(payload: MoveRequest, client: AuthClient):
    reject_if_approval_pending()
    x, y = await asyncio.to_thread(
        control_coordinates, payload.x, payload.y, payload.image_width, payload.image_height
    )
    try:
        await asyncio.to_thread(pyautogui.moveTo, x, y, payload.duration)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("move client=%s x=%d y=%d", client, x, y)
    return {"ok": True, "x": x, "y": y}


@app.post("/api/type")
async def api_type(payload: TypeRequest, client: AuthClient):
    reject_if_approval_pending()
    try:
        for start in range(0, len(payload.text), TEXT_CHUNK_SIZE):
            chunk = payload.text[start : start + TEXT_CHUNK_SIZE]
            await asyncio.to_thread(pyautogui.write, chunk, interval=payload.interval)
            if start + TEXT_CHUNK_SIZE < len(payload.text):
                await asyncio.sleep(0.03)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("type client=%s character_count=%d", client, len(payload.text))
    return {"ok": True, "character_count": len(payload.text)}


@app.post("/api/key")
async def api_key(payload: KeyRequest, client: AuthClient):
    reject_if_approval_pending()
    key = normalize_key(payload.key)
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=422, detail="Key is not allowed")
    try:
        await asyncio.to_thread(pyautogui.press, key)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("key client=%s key=%s", client, key)
    return {"ok": True, "key": key}


@app.post("/api/hotkey")
async def api_hotkey(payload: HotkeyRequest, client: AuthClient):
    reject_if_approval_pending()
    keys = validate_hotkey(payload.keys)
    try:
        await asyncio.to_thread(pyautogui.hotkey, *keys, interval=0.05)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("hotkey client=%s keys=%s", client, "+".join(keys))
    return {"ok": True, "keys": keys}


@app.post("/api/scroll")
async def api_scroll(payload: ScrollRequest, client: AuthClient):
    reject_if_approval_pending()
    if payload.clicks == 0:
        raise HTTPException(status_code=422, detail="Scroll distance cannot be zero")
    try:
        await asyncio.to_thread(pyautogui.scroll, payload.clicks)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("scroll client=%s clicks=%d", client, payload.clicks)
    return {"ok": True, "clicks": payload.clicks}


@app.get("/api/commands")
def api_commands(_: AuthClient):
    return {"ok": True, "commands": sorted(load_allowed_commands())}


@app.post("/api/command")
async def api_command(payload: CommandRequest, _: AuthClient):
    return await asyncio.to_thread(run_allowed_command, payload.cmd)


@app.post("/api/watch/text")
def api_watch_text(payload: TextWatchRequest, client: AuthClient):
    global _watch_phrase, _watch_last_scan_at, _watch_last_text
    phrase = " ".join(payload.text.split()) if payload.enabled else ""
    if payload.enabled and len(phrase) < 2:
        raise HTTPException(status_code=422, detail="Watch text must contain at least two visible characters")
    with _watch_lock:
        _watch_phrase = phrase
        _watch_last_scan_at = 0.0
        _watch_last_text = ""
    logger.info("text_watch client=%s enabled=%s character_count=%d", client, bool(phrase), len(phrase))
    return {"ok": True, "enabled": bool(phrase), "text": phrase}


@app.get("/api/watch/text/status")
async def api_watch_text_status(_: AuthClient):
    global _watch_last_scan_at, _watch_last_text
    with _watch_lock:
        phrase = _watch_phrase
        last_scan_at = _watch_last_scan_at
        cached_text = _watch_last_text
    if not phrase:
        return {"ok": True, "enabled": False, "matched": False}
    now = time.monotonic()
    if now - last_scan_at >= 3:
        try:
            cached_text = await asyncio.to_thread(scan_vscode_text)
        except Exception as error:
            logger.warning("text_watch_scan_failed error=%s", type(error).__name__)
            return {"ok": False, "enabled": True, "matched": False, "detail": "OCR watch scan failed"}
        with _watch_lock:
            _watch_last_scan_at = now
            _watch_last_text = cached_text
    return {
        "ok": True,
        "enabled": True,
        "matched": phrase.casefold() in cached_text.casefold(),
        "text": phrase,
    }


@app.get("/api/approval/status")
async def api_approval_status(client: AuthClient):
    try:
        candidate = await asyncio.to_thread(scan_for_approval)
    except Exception as error:
        logger.warning("approval_scan_failed error=%s", type(error).__name__)
        return {"ok": False, "pending": False, "detail": "Local approval scan failed"}
    if not candidate:
        return {"ok": True, "pending": False, **approval_scan_status()}
    logger.info(
        "approval_candidate_served client=%s candidate=%s labels=%s/%s points=%s/%s",
        client,
        candidate.candidate_id,
        candidate.approve_label,
        candidate.deny_label,
        candidate.approve_point,
        candidate.deny_point,
    )
    return {
        "ok": True,
        "pending": True,
        "candidate_id": candidate.candidate_id,
        "approve_label": candidate.approve_label,
        "deny_label": candidate.deny_label,
        "ocr_text": candidate.ocr_text,
        "age_seconds": round(candidate.age_seconds, 1),
        "image_url": f"/api/approval/{candidate.candidate_id}/image",
    }


@app.get("/api/approval/{candidate_id}/image")
def api_approval_image(candidate_id: str, client: AuthClient):
    candidate = current_candidate(candidate_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="Approval candidate expired")
    logger.info(
        "approval_crop_served client=%s candidate=%s bytes=%d",
        client,
        candidate_id,
        len(candidate.crop_png),
    )
    return Response(candidate.crop_png, media_type="image/png")


@app.post("/api/approval/{candidate_id}/decision")
async def api_approval_decision(candidate_id: str, payload: ApprovalDecision, client: AuthClient):
    expected = current_candidate(candidate_id)
    if not expected:
        raise HTTPException(status_code=409, detail="Approval candidate expired; scan again")
    try:
        fresh = await asyncio.to_thread(scan_for_approval, force=True)
    except Exception as error:
        logger.warning("approval_rescan_failed error=%s", type(error).__name__)
        raise HTTPException(status_code=503, detail="Could not verify the current prompt") from error
    if not fresh or not candidates_match(expected, fresh):
        clear_candidate()
        raise HTTPException(status_code=409, detail="The prompt changed; no click was sent")
    point = fresh.approve_point if payload.decision == "approve" else fresh.deny_point
    try:
        activated = await asyncio.to_thread(activate_vscode_application)
        if not activated:
            raise HTTPException(status_code=409, detail="Could not bring VS Code to the foreground")
        await asyncio.sleep(0.2)
        if payload.decision == "deny" and fresh.deny_label == "escape":
            await asyncio.to_thread(pyautogui.press, "esc")
        else:
            await asyncio.to_thread(pyautogui.click, x=point[0], y=point[1], button="left")
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    clear_candidate()
    logger.info(
        "approval_decision client=%s decision=%s label=%s x=%d y=%d",
        client,
        payload.decision,
        fresh.approve_label if payload.decision == "approve" else fresh.deny_label,
        point[0],
        point[1],
    )
    return {"ok": True, "decision": payload.decision}


APPROVAL_TEST_HTML = r'''<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Safe Approval Action Test</title>
    <style>
        :root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#181818;color:#ddd}
        .dialog{width:min(720px,90vw);padding:28px;border:1px solid #555;border-radius:12px;background:#252526;box-shadow:0 20px 70px #0009}
        h1{margin:0 0 16px;font-size:24px;color:#fff}.command{margin:20px 0;padding:18px;border-radius:7px;background:#111;font:20px ui-monospace,monospace;color:#d7ba7d}
        p{font-size:18px;line-height:1.5}.actions{display:flex;justify-content:flex-end;gap:18px;margin-top:28px}
        button{min-width:150px;padding:15px 24px;border:1px solid #777;border-radius:7px;font-size:22px;font-weight:700;color:#fff;background:#3c3c3c;cursor:pointer}
        #approve{background:#0e639c}.result{display:none;text-align:center;font-size:28px}.hint{color:#aaa;font-size:14px}
    </style>
</head>
<body>
    <main id="prompt" class="dialog">
        <h1>Copilot wants to run a command</h1>
        <p>This is a harmless visual fixture. No command will be executed.</p>
        <div class="command">echo "OCR approval test"</div>
        <p class="hint">Keep this page visible in VS Code while Muse scans it.</p>
        <div class="actions"><button id="cancel">Cancel</button><button id="approve">Approve</button></div>
    </main>
    <div id="result" class="result"></div>
    <script>
        function finish(text){document.querySelector('#prompt').style.display='none';const result=document.querySelector('#result');result.textContent=text;result.style.display='block'}
        document.querySelector('#cancel').onclick=()=>finish('Dummy request denied safely.');
        document.querySelector('#approve').onclick=()=>finish('Dummy request approved safely. No command was run.');
    </script>
</body>
</html>'''


INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Muse PC Control</title>
  <style>
    :root{color-scheme:dark;--bg:#08111d;--panel:#111f30;--line:#294158;--text:#e7f1fb;--muted:#94a9bc;--accent:#55d6be;--danger:#ff7b7b}
    *{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at top,#18324a 0,var(--bg) 48%);font:15px system-ui;color:var(--text)}
    header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#08111dcc;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:2;backdrop-filter:blur(12px)}
    h1{font-size:18px;margin:0}.header-actions,.status{display:flex;gap:8px;align-items:center}.status{color:var(--muted)}.dot{width:9px;height:9px;border-radius:50%;background:var(--danger)}.dot.ok{background:var(--accent)}
    main{max-width:1500px;margin:auto;padding:18px}.screen{position:relative;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#02060a;box-shadow:0 24px 70px #0008}
    #desktop{display:block;width:100%;height:auto;cursor:crosshair;min-height:300px;object-fit:contain}.empty{position:absolute;inset:0;display:grid;place-items:center;color:var(--muted);pointer-events:none}
    .toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}.control-card{flex:1 1 420px;min-width:min(100%,320px);padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}.control-card h2{margin:0 0 10px;font-size:15px}.control-row{display:flex;gap:8px;flex-wrap:wrap}.control-row+ .control-row{margin-top:8px}.command-output{min-height:72px;max-height:220px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#d9e7f3;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
    input,button,select{border:1px solid var(--line);background:#0b1725;color:var(--text);border-radius:8px;padding:9px 11px}input,select{flex:1;min-width:200px}button{cursor:pointer}button:hover,select:hover{border-color:var(--accent)}
    .approval{display:none;padding:18px;border:2px solid #f6c85f;border-radius:14px;background:#271f0d;box-shadow:0 24px 100px #000}.approval.pending{display:block;position:fixed;z-index:100;top:16px;left:50%;transform:translateX(-50%);width:min(1100px,calc(100vw - 32px));max-height:calc(100vh - 32px);overflow:auto}.approval img{display:block;width:100%;height:auto;margin:12px auto;border:1px solid var(--line);border-radius:8px}.ocr-preview{padding:12px;border:1px solid #6d5a28;border-radius:10px;background:#15130d}.ocr-preview strong{display:block;margin-bottom:7px}.ocr-preview pre{margin:0;max-height:130px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#d9e7f3;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}.approval-actions{display:grid;grid-template-columns:minmax(120px,.65fr) minmax(220px,1.35fr);align-items:end;gap:12px;position:sticky;bottom:0;background:#271f0d;padding-top:10px}.approval-actions button{font-weight:700}.approve{min-height:82px;background:#175f4d;font-size:26px}.deny{min-height:58px;background:#762f39;font-size:18px}.desktop-disabled{display:none}
    .approval-heading{display:flex;align-items:center;justify-content:space-between;gap:16px}.approval-heading strong{font-size:18px}.focus-setting{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;white-space:nowrap}.focus-setting select{padding:7px 9px}@media(max-width:700px){header{align-items:flex-start}.header-actions{align-items:flex-end;flex-direction:column}.status{font-size:12px}.focus-setting{font-size:12px}}
    dialog{border:1px solid var(--line);border-radius:14px;background:var(--panel);color:var(--text);padding:24px;max-width:420px}dialog::backdrop{background:#02060add}.error{color:var(--danger);min-height:1.2em}.hint{color:var(--muted);font-size:13px}
  </style>
</head>
<body>
<header><h1>Muse · Mac Control</h1><div class="header-actions"><label class="focus-setting">Auto-focus <select class="auto-focus-duration" aria-label="Auto-focus approval cards"><option value="0">Off</option><option value="1">1 hour</option><option value="5">5 hours</option><option value="24">24 hours</option></select></label><div class="status"><span id="dot" class="dot"></span><span id="status">Locked</span><button id="logout">Lock</button></div></div></header>
<main>
    <section id="approval" class="approval" tabindex="-1"><div class="approval-heading"><strong>VS Code approval detected</strong><label class="focus-setting">Auto-focus <select class="auto-focus-duration" aria-label="Auto-focus approval cards"><option value="0">Off</option><option value="1">1 hour</option><option value="5">5 hours</option><option value="24">24 hours</option></select></label></div><p id="approvalText" class="hint"></p><img id="approvalImage" alt="Focused VS Code approval prompt"><div class="ocr-preview"><strong>OCR command/action preview</strong><pre id="approvalOcr">No readable text detected. Verify the image above.</pre></div><div class="approval-actions"><button id="denyApproval" class="deny">Deny</button><button id="approveApproval" class="approve">Approve</button></div></section>
    <div id="screen" class="screen desktop-disabled"><img id="desktop" alt="Live Mac desktop"><div id="empty" class="empty">Desktop stream is off to save bandwidth</div></div>
        <div class="toolbar">
            <section class="control-card"><h2>Keyboard and text</h2><div class="control-row"><input id="typeText" maxlength="16000" placeholder="Text to type on the Mac"><button id="typeButton">Type text</button></div><div class="control-row"><button data-key="enter">Enter</button><button data-key="tab">Tab</button><button data-key="esc">Esc</button><select id="hotkey"><option value="command,`">Cmd+` Terminal</option><option value="command,shift,p">Cmd+Shift+P Palette</option><option value="command,n">Cmd+N</option><option value="command,s">Cmd+S</option><option value="command,option,d">Toggle Dock</option><option value="command,c">Cmd+C</option><option value="command,v">Cmd+V</option></select><button id="sendHotkey">Send shortcut</button></div></section>
            <section class="control-card"><h2>Desktop</h2><div class="control-row"><button id="scrollUp">Scroll up</button><button id="scrollDown">Scroll down</button><button id="refresh">Enable full primary display</button></div><p class="hint">The capture includes the full primary display. macOS does not draw an auto-hidden Dock until it is revealed; use Toggle Dock when needed.</p></section>
            <section class="control-card"><h2>Exact allowlisted command</h2><div class="control-row"><select id="commandSelect" aria-label="Allowed command"><option value="">Loading allowlist…</option></select><button id="runCommand">Run</button></div><pre id="commandOutput" class="command-output">Select an exact reviewed entry from allowed.txt.</pre></section>
            <section class="control-card"><h2>OCR text watch (notification only)</h2><div class="control-row"><input id="watchText" maxlength="100" placeholder="Text to watch for in VS Code"><button id="startWatch">Watch</button><button id="stopWatch">Stop</button></div><p id="watchStatus" class="hint">No text watch configured. OCR watches never click automatically.</p></section>
        </div>
    <p class="hint">Approval mode sends only a small OCR-detected crop. Enable the full desktop stream only when remote control is needed.</p>
</main>
<dialog id="login"><form method="dialog"><h2>Connect securely</h2><p class="hint">Enter PC_CONTROL_TOKEN. It is stored only in this browser's local storage.</p><input id="token" type="password" minlength="32" autocomplete="current-password" placeholder="Bearer token" required><p id="loginError" class="error"></p><button id="connect" value="default">Connect</button></form></dialog>
<script>
const desktop=document.querySelector('#desktop'), empty=document.querySelector('#empty'), login=document.querySelector('#login'), approval=document.querySelector('#approval');
let desktopTimer=null, approvalTimer=null, watchTimer=null, objectUrl=null, approvalObjectUrl=null, loading=false, desktopEnabled=false, candidateId='', watchWasMatched=false;
const token=()=>localStorage.getItem('musePcToken')||'';
const autoFocusDurations=[...document.querySelectorAll('.auto-focus-duration')], autoFocusUntilKey='museApprovalAutoFocusUntil', autoFocusHoursKey='museApprovalAutoFocusHours';
function setAutoFocusSelections(value){autoFocusDurations.forEach(select=>select.value=value)}
function autoFocusEnabled(){const until=Number(localStorage.getItem(autoFocusUntilKey)||0);if(until>Date.now())return true;localStorage.removeItem(autoFocusUntilKey);localStorage.removeItem(autoFocusHoursKey);setAutoFocusSelections('0');return false}
function configureAutoFocus(event){const hours=Number(event.currentTarget.value);setAutoFocusSelections(String(hours));if(hours>0){localStorage.setItem(autoFocusHoursKey,String(hours));localStorage.setItem(autoFocusUntilKey,String(Date.now()+hours*60*60*1000))}else{localStorage.removeItem(autoFocusUntilKey);localStorage.removeItem(autoFocusHoursKey)}}
function focusApprovalCard(){if(!autoFocusEnabled())return;window.focus();approval.focus({preventScroll:true});approval.scrollTop=0;document.title='Approval pending · Muse PC Control'}
const savedAutoFocusHours=localStorage.getItem(autoFocusHoursKey)||'0';setAutoFocusSelections(autoFocusEnabled()?savedAutoFocusHours:'0');
async function api(path, options={}){const headers=new Headers(options.headers||{});headers.set('Authorization',`Bearer ${token()}`);if(options.body)headers.set('Content-Type','application/json');const response=await fetch(path,{...options,headers,cache:'no-store'});if(response.status===401||response.status===503){lock();throw new Error('Authentication required');}if(!response.ok){let detail=response.statusText;try{detail=(await response.json()).detail||detail}catch{}throw new Error(detail)}return response}
function setStatus(ok,text){document.querySelector('#dot').classList.toggle('ok',ok);document.querySelector('#status').textContent=text}
async function refresh(){if(!desktopEnabled||loading||!token())return;loading=true;try{const response=await api('/api/screenshot');const blob=await response.blob();if(objectUrl)URL.revokeObjectURL(objectUrl);objectUrl=URL.createObjectURL(blob);desktop.src=objectUrl;empty.hidden=true;setStatus(true,'Connected')}catch(error){setStatus(false,error.message)}finally{loading=false}}
async function refreshApproval(){if(!token())return;try{const response=await api('/api/approval/status'),data=await response.json();if(!data.ok){setStatus(false,data.detail||'Local approval scan failed');return}const waiting=data.state==='inactive'?`Waiting: ${data.frontmost_app||'another app'} is frontmost`:'Monitoring VS Code';setStatus(true,data.pending?'Approval pending':waiting);if(!data.pending){approval.classList.remove('pending');candidateId='';document.title=watchWasMatched?'Text watch matched · Muse PC Control':'Muse PC Control';return}if(candidateId===data.candidate_id&&approval.classList.contains('pending'))return;const isNewCandidate=candidateId!==data.candidate_id;candidateId=data.candidate_id;document.querySelector('#approvalText').textContent=`Confirm ${data.approve_label} or ${data.deny_label}. OCR is informational only; verify it against the image. The prompt is rechecked before clicking.`;document.querySelector('#approvalOcr').textContent=data.ocr_text||'No readable text detected. Verify the image above.';const imageResponse=await api(data.image_url);const blob=await imageResponse.blob();if(approvalObjectUrl)URL.revokeObjectURL(approvalObjectUrl);approvalObjectUrl=URL.createObjectURL(blob);document.querySelector('#approvalImage').src=approvalObjectUrl;approval.classList.add('pending');if(isNewCandidate)focusApprovalCard()}catch(error){candidateId='';approval.classList.remove('pending');setStatus(false,`Approval UI: ${error.message}`)}}
function startMonitoring(){clearInterval(approvalTimer);clearInterval(watchTimer);approvalTimer=setInterval(refreshApproval,1500);watchTimer=setInterval(refreshWatch,3000);refreshApproval();refreshWatch()}
async function loadCommands(){try{const response=await api('/api/commands'),data=await response.json(),select=document.querySelector('#commandSelect');select.replaceChildren();for(const command of data.commands){const option=document.createElement('option');option.value=command;option.textContent=command;select.append(option)}if(!data.commands.length){const option=document.createElement('option');option.value='';option.textContent='No allowed commands';select.append(option)}}catch(error){setStatus(false,error.message)}}
async function connect(event){event.preventDefault();const value=document.querySelector('#token').value.trim();localStorage.setItem('musePcToken',value);try{await api('/api/status');login.close();document.querySelector('#loginError').textContent='';startMonitoring();loadCommands()}catch(error){document.querySelector('#loginError').textContent=error.message}}
function lock(){localStorage.removeItem('musePcToken');clearInterval(desktopTimer);clearInterval(approvalTimer);clearInterval(watchTimer);desktopTimer=null;approvalTimer=null;watchTimer=null;desktop.removeAttribute('src');approval.classList.remove('pending');empty.hidden=false;setStatus(false,'Locked');if(!login.open)login.showModal()}
async function decide(decision){if(!candidateId)return;try{await api(`/api/approval/${candidateId}/decision`,{method:'POST',body:JSON.stringify({decision})});approval.classList.remove('pending');candidateId='';document.title='Muse PC Control';setTimeout(refreshApproval,500)}catch(error){setStatus(false,error.message);candidateId='';setTimeout(refreshApproval,500)}}
async function sendHotkey(){const keys=document.querySelector('#hotkey').value.split(',');try{await api('/api/hotkey',{method:'POST',body:JSON.stringify({keys})});setStatus(true,`Sent ${keys.join('+')}`);setTimeout(refresh,180)}catch(error){setStatus(false,error.message)}}
async function runCommand(){const cmd=document.querySelector('#commandSelect').value,output=document.querySelector('#commandOutput');if(!cmd)return;output.textContent='Running exact allowlist entry…';try{const response=await api('/api/command',{method:'POST',body:JSON.stringify({cmd})}),data=await response.json();output.textContent=`Exit: ${data.returncode??'timeout'}${data.truncated?' · output truncated':''}\n${data.stdout||''}${data.stderr?`\nSTDERR:\n${data.stderr}`:''}`;setStatus(data.ok,data.ok?'Command completed':'Command failed')}catch(error){output.textContent=error.message;setStatus(false,error.message)}}
async function refreshWatch(){try{const response=await api('/api/watch/text/status'),data=await response.json(),statusText=document.querySelector('#watchStatus');if(!data.ok){statusText.textContent=data.detail||'OCR watch scan failed';return}if(!data.enabled){statusText.textContent='No text watch configured. OCR watches never click automatically.';watchWasMatched=false;return}statusText.textContent=data.matched?`Matched: ${data.text}`:`Watching for: ${data.text}`;if(data.matched&&!watchWasMatched){document.title='Text watch matched · Muse PC Control';if('Notification'in window&&Notification.permission==='granted')new Notification('Muse text watch matched',{body:data.text})}watchWasMatched=data.matched}catch(error){document.querySelector('#watchStatus').textContent=error.message}}
async function configureWatch(enabled){const text=document.querySelector('#watchText').value.trim();if(enabled&&text.length<2){setStatus(false,'Enter at least two characters to watch for');return}try{await api('/api/watch/text',{method:'POST',body:JSON.stringify({text:enabled?text:'off',enabled})});clearInterval(watchTimer);watchWasMatched=false;if(enabled){if('Notification'in window&&Notification.permission==='default')Notification.requestPermission();watchTimer=setInterval(refreshWatch,3000);refreshWatch()}else{watchTimer=null;document.querySelector('#watchStatus').textContent='No text watch configured. OCR watches never click automatically.';document.title='Muse PC Control'}}catch(error){setStatus(false,error.message)}}
desktop.addEventListener('click',async event=>{if(candidateId){setStatus(false,'Use the focused Approve or Deny controls');return}const rect=desktop.getBoundingClientRect();try{await api('/api/click',{method:'POST',body:JSON.stringify({x:event.clientX-rect.left,y:event.clientY-rect.top,image_width:rect.width,image_height:rect.height,button:'left'})});setTimeout(refresh,180)}catch(error){setStatus(false,error.message)}});
document.querySelector('#typeButton').onclick=async()=>{const field=document.querySelector('#typeText');try{await api('/api/type',{method:'POST',body:JSON.stringify({text:field.value})});field.value=''}catch(error){setStatus(false,error.message)}};
document.querySelectorAll('[data-key]').forEach(button=>button.onclick=()=>api('/api/key',{method:'POST',body:JSON.stringify({key:button.dataset.key})}).catch(error=>setStatus(false,error.message)));
document.querySelector('#sendHotkey').onclick=sendHotkey;document.querySelector('#scrollUp').onclick=()=>api('/api/scroll',{method:'POST',body:JSON.stringify({clicks:6})}).then(()=>setTimeout(refresh,180)).catch(error=>setStatus(false,error.message));document.querySelector('#scrollDown').onclick=()=>api('/api/scroll',{method:'POST',body:JSON.stringify({clicks:-6})}).then(()=>setTimeout(refresh,180)).catch(error=>setStatus(false,error.message));document.querySelector('#runCommand').onclick=runCommand;document.querySelector('#startWatch').onclick=()=>configureWatch(true);document.querySelector('#stopWatch').onclick=()=>configureWatch(false);
document.querySelector('#refresh').onclick=()=>{desktopEnabled=!desktopEnabled;document.querySelector('#screen').classList.toggle('desktop-disabled',!desktopEnabled);document.querySelector('#refresh').textContent=desktopEnabled?'Stop desktop stream':'Enable full primary display';clearInterval(desktopTimer);desktopTimer=desktopEnabled?setInterval(refresh,1500):null;if(desktopEnabled)refresh()};autoFocusDurations.forEach(select=>select.onchange=configureAutoFocus);document.querySelector('#approveApproval').onclick=()=>decide('approve');document.querySelector('#denyApproval').onclick=()=>decide('deny');document.querySelector('#logout').onclick=lock;document.querySelector('#connect').onclick=connect;
if(token()){api('/api/status').then(()=>{login.close();startMonitoring();loadCommands()}).catch(lock)}else login.showModal();
</script>
</body></html>'''


if __name__ == "__main__":
    host = os.getenv("PC_CONTROL_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing non-loopback bind. Use a secure tunnel to 127.0.0.1 instead.")
    port = int(os.getenv("PC_CONTROL_PORT", "5000"))
    if len(os.getenv("PC_CONTROL_TOKEN", "")) < 32:
        logger.warning("Set PC_CONTROL_TOKEN to a random value of at least 32 characters before using the API.")
    uvicorn.run(app, host=host, port=port)
