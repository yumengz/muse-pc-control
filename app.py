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
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
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
MAX_REQUEST_BYTES = 256 * 1024
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
_keyboard_operation_lock = threading.Lock()
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


class PasteRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)


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


def run_keyboard_operation(operation: Callable[..., None], *args: object) -> None:
    if not _keyboard_operation_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Another keyboard or text operation is still being delivered; retry after it completes",
            headers={"Retry-After": "1"},
        )
    try:
        operation(*args)
    finally:
        _keyboard_operation_lock.release()


def type_text(text: str, interval: float) -> None:
    for start in range(0, len(text), TEXT_CHUNK_SIZE):
        chunk = text[start : start + TEXT_CHUNK_SIZE]
        pyautogui.write(chunk, interval=interval)
        if start + TEXT_CHUNK_SIZE < len(text):
            time.sleep(0.03)


def paste_text(text: str) -> None:
    try:
        subprocess.run(
            ["/usr/bin/pbcopy"],
            input=text.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HTTPException(status_code=503, detail="Could not copy text to the macOS clipboard") from error
    pyautogui.hotkey("command", "v", interval=0.05)


def clear_focused_field() -> None:
    pyautogui.hotkey("command", "a", interval=0.05)
    pyautogui.press("backspace")


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
        await asyncio.to_thread(run_keyboard_operation, type_text, payload.text, payload.interval)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("type client=%s character_count=%d", client, len(payload.text))
    return {"ok": True, "method": "keystrokes", "character_count": len(payload.text)}


@app.post("/api/paste")
async def api_paste(payload: PasteRequest, client: AuthClient):
    reject_if_approval_pending()
    try:
        await asyncio.to_thread(run_keyboard_operation, paste_text, payload.text)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("paste client=%s character_count=%d", client, len(payload.text))
    return {"ok": True, "method": "clipboard_paste", "character_count": len(payload.text)}


@app.post("/api/clear-field")
async def api_clear_field(client: AuthClient):
    reject_if_approval_pending()
    try:
        await asyncio.to_thread(run_keyboard_operation, clear_focused_field)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("clear_field client=%s", client)
    return {"ok": True, "keys": ["command", "a", "backspace"]}


@app.post("/api/key")
async def api_key(payload: KeyRequest, client: AuthClient):
    reject_if_approval_pending()
    key = normalize_key(payload.key)
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=422, detail="Key is not allowed")
    try:
        await asyncio.to_thread(run_keyboard_operation, pyautogui.press, key)
    except pyautogui.FailSafeException as error:
        raise HTTPException(status_code=409, detail="PyAutoGUI fail-safe activated") from error
    logger.info("key client=%s key=%s", client, key)
    return {"ok": True, "key": key}


@app.post("/api/hotkey")
async def api_hotkey(payload: HotkeyRequest, client: AuthClient):
    reject_if_approval_pending()
    keys = validate_hotkey(payload.keys)
    try:
        await asyncio.to_thread(run_keyboard_operation, lambda: pyautogui.hotkey(*keys, interval=0.05))
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


@app.get("/api/approval/pending")
async def api_approval_pending(_: AuthClient):
    try:
        candidate = await asyncio.to_thread(scan_for_approval)
    except Exception as error:
        logger.warning("approval_pending_scan_failed error=%s", type(error).__name__)
        return {"ok": False, "pending": False, "count": 0, "detail": "Local approval scan failed"}
    if not candidate:
        return {
            "ok": True,
            "pending": False,
            "count": 0,
            "id": None,
            "action_text": "",
            "detected_at": None,
        }
    detected_at = datetime.now(timezone.utc) - timedelta(seconds=candidate.age_seconds)
    return {
        "ok": True,
        "pending": True,
        "count": 1,
        "id": candidate.candidate_id,
        "action_text": candidate.ocr_text,
        "detected_at": detected_at.isoformat().replace("+00:00", "Z"),
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
    header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 12px;background:#08111df2;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:80;backdrop-filter:blur(12px)}
    h1{font-size:16px;margin:0;white-space:nowrap}.header-actions,.status,.screenshot-state{display:flex;gap:8px;align-items:center}.status{color:var(--muted);flex-wrap:wrap;justify-content:flex-end}.dot{width:9px;height:9px;border-radius:50%;background:var(--danger)}.dot.ok{background:var(--accent)}.pending-badge{display:inline-flex;align-items:center;gap:5px;border:1px solid #6d5a28;border-radius:999px;padding:4px 8px;background:#271f0d;color:#f6c85f;font-weight:700}.pending-badge.active{background:#5b410b;color:#fff}.badge-count{min-width:18px;text-align:center;border-radius:999px;background:#0006}.mini-button{padding:6px 9px}.screenshot-state{font-size:12px;color:var(--muted);white-space:nowrap}
    main{max-width:1500px;margin:auto;padding:10px}.screen{position:relative;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#02060a;box-shadow:0 16px 50px #0008}
    #desktop{display:block;width:100%;height:auto;cursor:crosshair;min-height:300px;object-fit:contain}.empty{position:absolute;inset:0;display:grid;place-items:center;color:var(--muted);pointer-events:none}
    .screen-meta{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 9px;background:#07111dcc;color:var(--muted);font-size:12px}.toolbar{margin-top:8px;border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}.toolbar-icons{display:flex;gap:5px;padding:6px;flex-wrap:wrap}.tool-toggle{padding:7px 10px;font-weight:650}.tool-toggle[aria-expanded="true"]{border-color:var(--accent);background:#173044}.control-section{max-height:0;opacity:0;overflow:hidden;padding:0 10px;transition:max-height .18s ease,opacity .18s ease,padding .18s ease}.control-section.expanded{max-height:650px;opacity:1;padding:10px;border-top:1px solid var(--line)}.control-section h2{margin:0 0 8px;font-size:14px}.control-row{display:flex;gap:8px;flex-wrap:wrap}.control-row+ .control-row{margin-top:8px}.command-output{min-height:72px;max-height:220px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#d9e7f3;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
    input,textarea,button,select{border:1px solid var(--line);background:#0b1725;color:var(--text);border-radius:8px;padding:9px 11px}input,textarea,select{flex:1;min-width:200px}textarea{min-height:120px;resize:vertical;white-space:pre-wrap}button{cursor:pointer}button:hover,select:hover,textarea:hover,input:hover{border-color:var(--accent)}
    .approval{display:none;padding:12px;border:2px solid #f6c85f;border-radius:12px;background:#271f0df7;box-shadow:0 24px 100px #000}.approval.pending{display:block;position:fixed;z-index:120;top:58px;right:10px;width:min(540px,calc(100vw - 20px));max-height:calc(100vh - 68px);overflow:auto}.approval img{display:block;width:100%;max-height:250px;object-fit:contain;margin:8px auto;border:1px solid var(--line);border-radius:7px}.ocr-preview{padding:9px;border:1px solid #6d5a28;border-radius:8px;background:#15130d}.ocr-preview strong{display:block;margin-bottom:5px}.ocr-preview pre{margin:0;max-height:110px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#d9e7f3;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}.approval-actions{display:grid;grid-template-columns:1fr 1.4fr;align-items:end;gap:8px;position:sticky;bottom:0;background:#271f0d;padding-top:8px}.approval-actions button{font-weight:700}.approve{min-height:58px;background:#175f4d;font-size:20px}.deny{min-height:48px;background:#762f39;font-size:16px}.desktop-disabled{display:none}
    .approval-heading{display:flex;align-items:center;justify-content:space-between;gap:10px}.approval-heading strong{font-size:16px}.focus-setting{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px;white-space:nowrap}.focus-setting select{padding:6px 8px}.agent-mode *{animation:none!important;transition:none!important}.agent-mode main{padding:4px}.agent-mode header{padding:4px 7px}.agent-mode h1{display:none}.agent-mode #desktop{max-height:46vh}.agent-mode .toolbar{margin-top:4px}.agent-mode .toolbar-icons{padding:4px}.agent-mode .tool-toggle{padding:5px 7px}.agent-mode .control-section.expanded{padding:6px;max-height:45vh;overflow:auto}@media(max-width:700px){header{align-items:flex-start}.header-actions{align-items:flex-end}.status{font-size:11px}.screenshot-state{font-size:11px}.approval.pending{top:52px}.focus-setting{font-size:11px}}
    dialog{border:1px solid var(--line);border-radius:14px;background:var(--panel);color:var(--text);padding:24px;max-width:420px}dialog::backdrop{background:#02060add}.error{color:var(--danger);min-height:1.2em}.hint{color:var(--muted);font-size:13px}
  </style>
</head>
<body>
<header data-testid="mission-header"><h1>Muse · Mission Control</h1><div class="header-actions"><div class="status"><span id="dot" class="dot" data-testid="connection-dot"></span><span id="status" data-testid="connection-status">Locked</span><span id="pendingBadge" class="pending-badge" data-testid="pending-approval-badge" title="Pending approvals">Approval <span id="pendingCount" class="badge-count" data-testid="pending-approval-count">0</span></span><span id="screenshotState" class="screenshot-state" data-testid="screenshot-state">Auto 1.5s · never updated</span><button id="headerRefresh" class="mini-button" data-testid="screenshot-refresh" title="Refresh screenshot">↻ Refresh</button><button id="logout" class="mini-button" data-testid="logout">Lock</button></div></div></header>
<main>
    <section id="approval" class="approval" tabindex="-1" data-testid="approval-overlay"><div class="approval-heading"><strong data-testid="approval-title">VS Code approval detected</strong><label class="focus-setting">Auto-focus <select class="auto-focus-duration" data-testid="approval-auto-focus" aria-label="Auto-focus approval cards"><option value="0">Off</option><option value="1">1 hour</option><option value="5">5 hours</option><option value="24">24 hours</option></select></label></div><p id="approvalText" class="hint" data-testid="approval-summary"></p><img id="approvalImage" data-testid="approval-image" alt="Focused VS Code approval prompt"><div class="ocr-preview"><strong>OCR command/action</strong><pre id="approvalOcr" data-testid="approval-action-text">No readable text detected. Verify the image above.</pre></div><div class="approval-actions"><button id="denyApproval" class="deny" data-testid="deny-approval">Deny</button><button id="approveApproval" class="approve" data-testid="approve-approval">Approve</button></div></section>
    <section id="screen" class="screen" data-testid="screenshot-feed"><div class="screen-meta"><span>Primary display</span><button id="refresh" class="mini-button" data-testid="screenshot-auto-toggle">Pause auto-refresh</button></div><img id="desktop" data-testid="desktop-image" alt="Live Mac desktop"><div id="empty" class="empty">Loading desktop…</div></section>
    <div id="toolbar" class="toolbar" data-testid="control-toolbar"><div class="toolbar-icons"><button class="tool-toggle" data-panel="keyboardSection" aria-expanded="false" data-testid="toggle-keyboard">⌨ Keyboard</button><button class="tool-toggle" data-panel="commandSection" aria-expanded="false" data-testid="toggle-command">⌘ Command</button><button class="tool-toggle" data-panel="scrollSection" aria-expanded="false" data-testid="toggle-scroll">↕ Scroll</button><button class="tool-toggle" data-panel="watchSection" aria-expanded="false" data-testid="toggle-ocr-watch">◎ OCR watch</button></div>
        <section id="keyboardSection" class="control-section" data-testid="keyboard-panel"><h2>Keyboard and text</h2><div class="control-row"><textarea id="typeText" data-testid="paste-text" placeholder="Paste multiline or Unicode text on the Mac (maximum 16,000 characters)"></textarea><button id="typeButton" data-testid="paste-text-submit">Paste text</button></div><p id="textDelivery" class="hint" data-testid="text-delivery">Clipboard paste is atomic and preserves newlines and Unicode.</p><div class="control-row"><button data-key="enter" data-testid="key-enter">Enter</button><button data-key="tab" data-testid="key-tab">Tab</button><button data-key="esc" data-testid="key-escape">Esc</button><button id="clearField" data-testid="clear-field">Clear focused field</button></div><div class="control-row"><input id="hotkey" data-testid="hotkey-input" value="Cmd+A" placeholder="Shortcut, for example Cmd+Shift+P" aria-label="Keyboard shortcut"><button id="sendHotkey" data-testid="hotkey-submit">Send shortcut</button></div></section>
        <section id="commandSection" class="control-section" data-testid="command-panel"><h2>Exact allowlisted command</h2><div class="control-row"><select id="commandSelect" data-testid="command-select" aria-label="Allowed command"><option value="">Loading allowlist…</option></select><button id="runCommand" data-testid="command-run">Run</button></div><pre id="commandOutput" class="command-output" data-testid="command-output">Select an exact reviewed entry from allowed.txt.</pre></section>
        <section id="scrollSection" class="control-section" data-testid="scroll-panel"><h2>Scroll</h2><div class="control-row"><button id="scrollUp" data-testid="scroll-up">Scroll up</button><button id="scrollDown" data-testid="scroll-down">Scroll down</button></div></section>
        <section id="watchSection" class="control-section" data-testid="ocr-watch-panel"><h2>OCR text watch (notification only)</h2><div class="control-row"><input id="watchText" data-testid="ocr-watch-input" maxlength="100" placeholder="Text to watch for in VS Code"><button id="startWatch" data-testid="ocr-watch-start">Watch</button><button id="stopWatch" data-testid="ocr-watch-stop">Stop</button></div><p id="watchStatus" class="hint" data-testid="ocr-watch-status">No text watch configured. OCR watches never click automatically.</p></section>
    </div>
</main>
<dialog id="login" data-testid="login-dialog"><form method="dialog"><h2>Connect securely</h2><p class="hint">Enter PC_CONTROL_TOKEN. It is stored only in this browser's local storage.</p><input id="token" data-testid="token-input" type="password" minlength="32" autocomplete="current-password" placeholder="Bearer token" required><p id="loginError" class="error" data-testid="login-error"></p><button id="connect" data-testid="connect" value="default">Connect</button></form></dialog>
<script>
const desktop=document.querySelector('#desktop'), empty=document.querySelector('#empty'), login=document.querySelector('#login'), approval=document.querySelector('#approval');
let desktopTimer=null, approvalTimer=null, watchTimer=null, objectUrl=null, approvalObjectUrl=null, loading=false, approvalLoading=false, desktopEnabled=true, candidateId='', watchWasMatched=false, lastScreenshotAt=0;
const token=()=>localStorage.getItem('musePcToken')||'';
const agentMode=new URLSearchParams(location.search).get('agent')==='1',panelStateKey='museControlPanels';
document.body.classList.toggle('agent-mode',agentMode);
const autoFocusDurations=[...document.querySelectorAll('.auto-focus-duration')], autoFocusUntilKey='museApprovalAutoFocusUntil', autoFocusHoursKey='museApprovalAutoFocusHours';
function setAutoFocusSelections(value){autoFocusDurations.forEach(select=>select.value=value)}
function autoFocusEnabled(){const until=Number(localStorage.getItem(autoFocusUntilKey)||0);if(until>Date.now())return true;localStorage.removeItem(autoFocusUntilKey);localStorage.removeItem(autoFocusHoursKey);setAutoFocusSelections('0');return false}
function configureAutoFocus(event){const hours=Number(event.currentTarget.value);setAutoFocusSelections(String(hours));if(hours>0){localStorage.setItem(autoFocusHoursKey,String(hours));localStorage.setItem(autoFocusUntilKey,String(Date.now()+hours*60*60*1000))}else{localStorage.removeItem(autoFocusUntilKey);localStorage.removeItem(autoFocusHoursKey)}}
function focusApprovalCard(){if(!autoFocusEnabled())return;window.focus();approval.focus({preventScroll:true});approval.scrollTop=0;document.title='Approval pending · Muse PC Control'}
const savedAutoFocusHours=localStorage.getItem(autoFocusHoursKey)||'0';setAutoFocusSelections(autoFocusEnabled()?savedAutoFocusHours:'0');
async function api(path, options={}){const headers=new Headers(options.headers||{});headers.set('Authorization',`Bearer ${token()}`);if(options.body)headers.set('Content-Type','application/json');const response=await fetch(path,{...options,headers,cache:'no-store'});if(response.status===401||response.status===503){lock();throw new Error('Authentication required');}if(!response.ok){let detail=response.statusText;try{detail=(await response.json()).detail||detail}catch{}throw new Error(detail)}return response}
function setStatus(ok,text){document.querySelector('#dot').classList.toggle('ok',ok);document.querySelector('#status').textContent=text}
function renderScreenshotState(){const age=lastScreenshotAt?`${Math.max(0,Math.floor((Date.now()-lastScreenshotAt)/1000))}s ago`:'never updated';document.querySelector('#screenshotState').textContent=`${desktopEnabled?'Auto 1.5s':'Auto paused'} · ${age}`}
function setPendingCount(count){const badge=document.querySelector('#pendingBadge');document.querySelector('#pendingCount').textContent=String(count);badge.classList.toggle('active',count>0)}
async function refresh(force=false){if((!desktopEnabled&&!force)||loading||!token())return;loading=true;try{const response=await api('/api/screenshot');const blob=await response.blob();if(objectUrl)URL.revokeObjectURL(objectUrl);objectUrl=URL.createObjectURL(blob);desktop.src=objectUrl;empty.hidden=true;lastScreenshotAt=Date.now();renderScreenshotState();setStatus(true,'Connected')}catch(error){setStatus(false,error.message)}finally{loading=false}}
async function refreshApproval(){if(!token()||approvalLoading)return;approvalLoading=true;try{const response=await api('/api/approval/status'),data=await response.json();if(!data.ok){setStatus(false,data.detail||'Local approval scan failed');return}const waiting=data.state==='inactive'?`Waiting: ${data.frontmost_app||'another app'} is frontmost`:'Monitoring VS Code';setStatus(true,data.pending?'Approval pending':waiting);setPendingCount(data.pending?1:0);if(!data.pending){approval.classList.remove('pending');candidateId='';document.title=watchWasMatched?'Text watch matched · Muse PC Control':'Muse PC Control';return}if(candidateId===data.candidate_id&&approval.classList.contains('pending'))return;const isNewCandidate=candidateId!==data.candidate_id;candidateId=data.candidate_id;document.querySelector('#approvalText').textContent=`Detected ${data.age_seconds.toFixed(1)}s ago · confirm ${data.approve_label} or ${data.deny_label}. The prompt is rechecked before clicking.`;document.querySelector('#approvalOcr').textContent=data.ocr_text||'No readable text detected. Verify the image above.';const imageResponse=await api(data.image_url);const blob=await imageResponse.blob();if(approvalObjectUrl)URL.revokeObjectURL(approvalObjectUrl);approvalObjectUrl=URL.createObjectURL(blob);document.querySelector('#approvalImage').src=approvalObjectUrl;approval.classList.add('pending');if(isNewCandidate)focusApprovalCard()}catch(error){candidateId='';setPendingCount(0);approval.classList.remove('pending');setStatus(false,`Approval UI: ${error.message}`)}finally{approvalLoading=false}}
function startMonitoring(){clearInterval(desktopTimer);clearInterval(approvalTimer);clearInterval(watchTimer);desktopTimer=desktopEnabled?setInterval(refresh,1500):null;approvalTimer=setInterval(refreshApproval,1500);watchTimer=setInterval(refreshWatch,3000);refresh();refreshApproval();refreshWatch();renderScreenshotState()}
async function loadCommands(){try{const response=await api('/api/commands'),data=await response.json(),select=document.querySelector('#commandSelect');select.replaceChildren();for(const command of data.commands){const option=document.createElement('option');option.value=command;option.textContent=command;select.append(option)}if(!data.commands.length){const option=document.createElement('option');option.value='';option.textContent='No allowed commands';select.append(option)}}catch(error){setStatus(false,error.message)}}
async function connect(event){event.preventDefault();const value=document.querySelector('#token').value.trim();localStorage.setItem('musePcToken',value);try{await api('/api/status');login.close();document.querySelector('#loginError').textContent='';startMonitoring();loadCommands()}catch(error){document.querySelector('#loginError').textContent=error.message}}
function lock(){localStorage.removeItem('musePcToken');clearInterval(desktopTimer);clearInterval(approvalTimer);clearInterval(watchTimer);desktopTimer=null;approvalTimer=null;watchTimer=null;desktop.removeAttribute('src');approval.classList.remove('pending');setPendingCount(0);empty.hidden=false;setStatus(false,'Locked');if(!login.open)login.showModal()}
async function decide(decision){if(!candidateId)return;try{await api(`/api/approval/${candidateId}/decision`,{method:'POST',body:JSON.stringify({decision})});approval.classList.remove('pending');candidateId='';document.title='Muse PC Control';setTimeout(refreshApproval,500)}catch(error){setStatus(false,error.message);candidateId='';setTimeout(refreshApproval,500)}}
function parseHotkey(value){return value.split(/[+,]/).map(key=>key.trim()).filter(Boolean)}
async function sendHotkey(){const keys=parseHotkey(document.querySelector('#hotkey').value);try{const response=await api('/api/hotkey',{method:'POST',body:JSON.stringify({keys})}),data=await response.json();setStatus(true,`Sent ${data.keys.join('+')}`);setTimeout(refresh,180)}catch(error){setStatus(false,error.message)}}
async function runCommand(){const cmd=document.querySelector('#commandSelect').value,output=document.querySelector('#commandOutput');if(!cmd)return;output.textContent='Running exact allowlist entry…';try{const response=await api('/api/command',{method:'POST',body:JSON.stringify({cmd})}),data=await response.json();output.textContent=`Exit: ${data.returncode??'timeout'}${data.truncated?' · output truncated':''}\n${data.stdout||''}${data.stderr?`\nSTDERR:\n${data.stderr}`:''}`;setStatus(data.ok,data.ok?'Command completed':'Command failed')}catch(error){output.textContent=error.message;setStatus(false,error.message)}}
async function refreshWatch(){try{const response=await api('/api/watch/text/status'),data=await response.json(),statusText=document.querySelector('#watchStatus');if(!data.ok){statusText.textContent=data.detail||'OCR watch scan failed';return}if(!data.enabled){statusText.textContent='No text watch configured. OCR watches never click automatically.';watchWasMatched=false;return}statusText.textContent=data.matched?`Matched: ${data.text}`:`Watching for: ${data.text}`;if(data.matched&&!watchWasMatched){document.title='Text watch matched · Muse PC Control';if('Notification'in window&&Notification.permission==='granted')new Notification('Muse text watch matched',{body:data.text})}watchWasMatched=data.matched}catch(error){document.querySelector('#watchStatus').textContent=error.message}}
async function configureWatch(enabled){const text=document.querySelector('#watchText').value.trim();if(enabled&&text.length<2){setStatus(false,'Enter at least two characters to watch for');return}try{await api('/api/watch/text',{method:'POST',body:JSON.stringify({text:enabled?text:'off',enabled})});clearInterval(watchTimer);watchWasMatched=false;if(enabled){if('Notification'in window&&Notification.permission==='default')Notification.requestPermission();watchTimer=setInterval(refreshWatch,3000);refreshWatch()}else{watchTimer=null;document.querySelector('#watchStatus').textContent='No text watch configured. OCR watches never click automatically.';document.title='Muse PC Control'}}catch(error){setStatus(false,error.message)}}
desktop.addEventListener('click',async event=>{if(candidateId){setStatus(false,'Use the focused Approve or Deny controls');return}const rect=desktop.getBoundingClientRect();try{await api('/api/click',{method:'POST',body:JSON.stringify({x:event.clientX-rect.left,y:event.clientY-rect.top,image_width:rect.width,image_height:rect.height,button:'left'})});setTimeout(refresh,180)}catch(error){setStatus(false,error.message)}});
document.querySelector('#typeButton').onclick=async()=>{const field=document.querySelector('#typeText'),delivery=document.querySelector('#textDelivery'),text=field.value;if(!text.length){setStatus(false,'Enter text to paste');return}if(text.length>16000){setStatus(false,`Text is ${text.length} characters; the limit is 16000`);return}try{const response=await api('/api/paste',{method:'POST',body:JSON.stringify({text})}),data=await response.json();delivery.textContent=`Delivered ${data.character_count} characters by atomic clipboard paste.`;setStatus(true,`Pasted ${data.character_count} characters`);field.value='';setTimeout(refresh,180)}catch(error){delivery.textContent=error.message;setStatus(false,error.message)}};
document.querySelectorAll('[data-key]').forEach(button=>button.onclick=()=>api('/api/key',{method:'POST',body:JSON.stringify({key:button.dataset.key})}).catch(error=>setStatus(false,error.message)));
document.querySelector('#clearField').onclick=async()=>{try{await api('/api/clear-field',{method:'POST'});setStatus(true,'Cleared focused field');setTimeout(refresh,180)}catch(error){setStatus(false,error.message)}};document.querySelector('#sendHotkey').onclick=sendHotkey;document.querySelector('#scrollUp').onclick=()=>api('/api/scroll',{method:'POST',body:JSON.stringify({clicks:6})}).then(()=>setTimeout(refresh,180)).catch(error=>setStatus(false,error.message));document.querySelector('#scrollDown').onclick=()=>api('/api/scroll',{method:'POST',body:JSON.stringify({clicks:-6})}).then(()=>setTimeout(refresh,180)).catch(error=>setStatus(false,error.message));document.querySelector('#runCommand').onclick=runCommand;document.querySelector('#startWatch').onclick=()=>configureWatch(true);document.querySelector('#stopWatch').onclick=()=>configureWatch(false);
function panelPreferences(){try{return JSON.parse(localStorage.getItem(panelStateKey)||'{}')}catch{return {}}}
function setPanel(panelId,expanded,persist=true){const panel=document.querySelector(`#${panelId}`),toggle=document.querySelector(`[data-panel="${panelId}"]`);panel.classList.toggle('expanded',expanded);toggle.setAttribute('aria-expanded',String(expanded));if(persist){const preferences=panelPreferences();preferences[panelId]=expanded;localStorage.setItem(panelStateKey,JSON.stringify(preferences))}}
document.querySelectorAll('[data-panel]').forEach(toggle=>{const panelId=toggle.dataset.panel;setPanel(panelId,Boolean(panelPreferences()[panelId]),false);toggle.onclick=()=>setPanel(panelId,toggle.getAttribute('aria-expanded')!=='true')});
document.querySelector('#headerRefresh').onclick=()=>refresh(true);document.querySelector('#refresh').onclick=()=>{desktopEnabled=!desktopEnabled;document.querySelector('#refresh').textContent=desktopEnabled?'Pause auto-refresh':'Resume auto-refresh';clearInterval(desktopTimer);desktopTimer=desktopEnabled?setInterval(refresh,1500):null;if(desktopEnabled)refresh();renderScreenshotState()};autoFocusDurations.forEach(select=>select.onchange=configureAutoFocus);document.querySelector('#approveApproval').onclick=()=>decide('approve');document.querySelector('#denyApproval').onclick=()=>decide('deny');document.querySelector('#logout').onclick=lock;document.querySelector('#connect').onclick=connect;setInterval(renderScreenshotState,1000);
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
