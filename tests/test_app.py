import subprocess
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

import app as control
import approval_monitor as monitor
from approval_monitor import (
    AccessibilityButton,
    ApprovalCandidate,
    OCRWord,
    find_accessibility_approval_pair,
    find_approval_pair,
    find_single_accessibility_allow,
    find_visual_approval_pair,
    redact_ocr_text,
)

TOKEN = "test-token-that-is-definitely-at-least-32-characters"


@pytest.fixture(autouse=True)
def configured_token(monkeypatch):
    monkeypatch.setenv("PC_CONTROL_TOKEN", TOKEN)
    control._rate_events.clear()
    monkeypatch.setattr(control, "_watch_phrase", "")
    monkeypatch.setattr(control, "_watch_last_scan_at", 0.0)
    monkeypatch.setattr(control, "_watch_last_text", "")
    monkeypatch.setattr(control, "approval_pending", lambda: False)
    monkeypatch.setattr(control, "_keyboard_operation_lock", threading.Lock())


@pytest.fixture
def client():
    return TestClient(control.app)


def auth():
    return {"Authorization": f"Bearer {TOKEN}"}


def approval_candidate(
    candidate_id="candidate-1",
    approve_point=(700, 500),
    deny_point=(580, 500),
    deny_label="cancel",
    ocr_text="Create and remove a temporary file",
):
    return ApprovalCandidate(
        candidate_id=candidate_id,
        created_at=control.time.monotonic(),
        approve_label="allow",
        deny_label=deny_label,
        approve_point=approve_point,
        deny_point=deny_point,
        crop_png=b"focused-png",
        ocr_text=ocr_text,
    )


def test_api_requires_bearer_token(client):
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/status", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_new_control_apis_require_bearer_token(client):
    assert client.post("/api/paste", json={"text": "private"}).status_code == 401
    assert client.post("/api/clear-field").status_code == 401
    assert client.post("/api/hotkey", json={"keys": ["command", "n"]}).status_code == 401
    assert client.post("/api/scroll", json={"clicks": 1}).status_code == 401
    assert client.get("/api/commands").status_code == 401
    assert client.post("/api/watch/text", json={"text": "done", "enabled": True}).status_code == 401
    assert client.get("/api/watch/text/status").status_code == 401


def test_status_reports_local_machine(client):
    response = client.get("/api/status", headers=auth())
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["hostname"]
    assert response.json()["system"]


def test_screenshot_returns_png_without_using_real_screen(client, monkeypatch):
    monkeypatch.setattr(control, "capture_main_display", lambda: (b"png-data", 3024, 1964))
    response = client.get("/api/screenshot", headers=auth())
    assert response.status_code == 200
    assert response.content == b"png-data"
    assert response.headers["content-type"] == "image/png"
    assert response.headers["x-screen-width"] == "3024"


def test_click_scales_browser_image_and_retina_coordinates(client, monkeypatch):
    monkeypatch.setattr(control, "screenshot_dimensions", lambda: (3024, 1964))
    monkeypatch.setattr(control.pyautogui, "size", lambda: (1512, 982))
    click = Mock()
    monkeypatch.setattr(control.pyautogui, "click", click)
    response = client.post(
        "/api/click",
        headers=auth(),
        json={"x": 756, "y": 491, "image_width": 1512, "image_height": 982, "button": "left"},
    )
    assert response.status_code == 200
    assert response.json()["x"] == 756
    assert response.json()["y"] == 491
    click.assert_called_once_with(x=756, y=491, button="left")


def test_click_rejects_coordinates_outside_image(client, monkeypatch):
    monkeypatch.setattr(control, "screenshot_dimensions", lambda: (3024, 1964))
    response = client.post(
        "/api/click",
        headers=auth(),
        json={"x": 900, "y": 10, "image_width": 800, "image_height": 600, "button": "left"},
    )
    assert response.status_code == 422


def test_command_requires_exact_allowlist_match(client, monkeypatch, tmp_path: Path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("printf 'safe\\n'\n", encoding="utf-8")
    monkeypatch.setattr(control, "ALLOWLIST_PATH", allowed)
    safe = client.post("/api/command", headers=auth(), json={"cmd": "printf 'safe\\n'"})
    assert safe.status_code == 200
    assert safe.json()["stdout"] == "safe\n"

    for command in ("printf 'safe\\n'; uname -a", "printf 'safe\\n' && whoami", "/bin/zsh"):
        denied = client.post("/api/command", headers=auth(), json={"cmd": command})
        assert denied.status_code == 403


def test_command_output_is_bounded(client, monkeypatch, tmp_path: Path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("large-output\n", encoding="utf-8")
    monkeypatch.setattr(control, "ALLOWLIST_PATH", allowed)
    completed = subprocess.CompletedProcess([], 0, stdout=b"x" * (control.MAX_COMMAND_OUTPUT + 10), stderr=b"")
    monkeypatch.setattr(control.subprocess, "run", lambda *args, **kwargs: completed)
    response = client.post("/api/command", headers=auth(), json={"cmd": "large-output"})
    assert response.status_code == 200
    assert len(response.json()["stdout"]) == control.MAX_COMMAND_OUTPUT
    assert response.json()["truncated"] is True


def test_command_timeout_is_reported(client, monkeypatch, tmp_path: Path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("slow-command\n", encoding="utf-8")
    monkeypatch.setattr(control, "ALLOWLIST_PATH", allowed)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="slow-command", timeout=30, output=b"partial", stderr=b"")

    monkeypatch.setattr(control.subprocess, "run", timeout)
    response = client.post("/api/command", headers=auth(), json={"cmd": "slow-command"})
    assert response.status_code == 200
    assert response.json()["timed_out"] is True
    assert response.json()["stdout"] == "partial"


def test_type_log_does_not_echo_text(client, monkeypatch, caplog):
    writer = Mock()
    monkeypatch.setattr(control.pyautogui, "write", writer)
    secret_text = "do-not-log-this-text"
    response = client.post("/api/type", headers=auth(), json={"text": secret_text})
    assert response.status_code == 200
    assert secret_text not in caplog.text
    writer.assert_called_once_with(secret_text, interval=0.01)


def test_long_text_is_sent_in_bounded_chunks(client, monkeypatch):
    writer = Mock()
    monkeypatch.setattr(control.pyautogui, "write", writer)
    text = "x" * (control.TEXT_CHUNK_SIZE * 2 + 17)
    response = client.post("/api/type", headers=auth(), json={"text": text, "interval": 0})
    assert response.status_code == 200
    assert [call.args[0] for call in writer.call_args_list] == [
        "x" * control.TEXT_CHUNK_SIZE,
        "x" * control.TEXT_CHUNK_SIZE,
        "x" * 17,
    ]
    assert response.json() == {
        "ok": True,
        "method": "keystrokes",
        "character_count": len(text),
    }


def test_paste_preserves_unicode_and_newlines_atomically(client, monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    hotkey = Mock()
    monkeypatch.setattr(control.subprocess, "run", run)
    monkeypatch.setattr(control.pyautogui, "hotkey", hotkey)
    text = "第一行\nemoji: 🧭\nthird line"
    response = client.post("/api/paste", headers=auth(), json={"text": text})
    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "method": "clipboard_paste",
        "character_count": len(text),
    }
    assert calls[0][0] == ["/usr/bin/pbcopy"]
    assert calls[0][1]["input"] == text.encode("utf-8")
    hotkey.assert_called_once_with("command", "v", interval=0.05)


def test_paste_log_does_not_echo_text(client, monkeypatch, caplog):
    monkeypatch.setattr(
        control.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )
    monkeypatch.setattr(control.pyautogui, "hotkey", Mock())
    secret_text = "do-not-log-this-pasted-text"
    response = client.post("/api/paste", headers=auth(), json={"text": secret_text})
    assert response.status_code == 200
    assert secret_text not in caplog.text


def test_keyboard_operation_backpressure_prevents_interleaving(client, monkeypatch):
    started = threading.Event()
    finish = threading.Event()
    first_response = []

    def blocking_write(text, interval):
        started.set()
        assert finish.wait(timeout=2)

    monkeypatch.setattr(control.pyautogui, "write", blocking_write)

    def send_first():
        first_response.append(client.post("/api/type", headers=auth(), json={"text": "first"}))

    worker = threading.Thread(target=send_first)
    worker.start()
    assert started.wait(timeout=2)
    busy = client.post("/api/paste", headers=auth(), json={"text": "second"})
    assert busy.status_code == 429
    assert "still being delivered" in busy.json()["detail"]
    assert busy.headers["retry-after"] == "1"
    assert not first_response
    finish.set()
    worker.join(timeout=2)
    assert first_response[0].status_code == 200


def test_clear_field_is_one_serialized_operation(client, monkeypatch):
    actions = []
    monkeypatch.setattr(
        control.pyautogui,
        "hotkey",
        lambda *keys, **kwargs: actions.append(("hotkey", keys, kwargs)),
    )
    monkeypatch.setattr(control.pyautogui, "press", lambda key: actions.append(("press", key)))
    response = client.post("/api/clear-field", headers=auth())
    assert response.status_code == 200
    assert actions == [
        ("hotkey", ("command", "a"), {"interval": 0.05}),
        ("press", "backspace"),
    ]


def test_text_over_limit_is_rejected_without_delivery(client, monkeypatch):
    write = Mock()
    hotkey = Mock()
    monkeypatch.setattr(control.pyautogui, "write", write)
    monkeypatch.setattr(control.pyautogui, "hotkey", hotkey)
    text = "x" * (control.MAX_TEXT_LENGTH + 1)
    typed = client.post("/api/type", headers=auth(), json={"text": text})
    pasted = client.post("/api/paste", headers=auth(), json={"text": text})
    assert typed.status_code == 422
    assert pasted.status_code == 422
    assert str(control.MAX_TEXT_LENGTH) in str(typed.json())
    assert str(control.MAX_TEXT_LENGTH) in str(pasted.json())
    write.assert_not_called()
    hotkey.assert_not_called()


def test_hotkey_requires_modifier_and_one_supported_action(client, monkeypatch):
    hotkey = Mock()
    monkeypatch.setattr(control.pyautogui, "hotkey", hotkey)
    response = client.post(
        "/api/hotkey", headers=auth(), json={"keys": ["cmd", "shift", "p"]}
    )
    assert response.status_code == 200
    assert response.json()["keys"] == ["command", "shift", "p"]
    hotkey.assert_called_once_with("command", "shift", "p", interval=0.05)

    assert client.post("/api/hotkey", headers=auth(), json={"keys": ["p", "n"]}).status_code == 422
    assert client.post("/api/hotkey", headers=auth(), json={"keys": ["cmd", "p", "n"]}).status_code == 422
    assert client.post("/api/hotkey", headers=auth(), json={"keys": ["cmd", "unsupported"]}).status_code == 422


def test_hotkey_supports_cmd_a(client, monkeypatch):
    hotkey = Mock()
    monkeypatch.setattr(control.pyautogui, "hotkey", hotkey)
    response = client.post("/api/hotkey", headers=auth(), json={"keys": ["Cmd", "A"]})
    assert response.status_code == 200
    assert response.json()["keys"] == ["command", "a"]
    hotkey.assert_called_once_with("command", "a", interval=0.05)


def test_scroll_is_bounded_and_zero_is_rejected(client, monkeypatch):
    scroll = Mock()
    monkeypatch.setattr(control.pyautogui, "scroll", scroll)
    response = client.post("/api/scroll", headers=auth(), json={"clicks": -6})
    assert response.status_code == 200
    scroll.assert_called_once_with(-6)
    assert client.post("/api/scroll", headers=auth(), json={"clicks": 0}).status_code == 422
    assert client.post("/api/scroll", headers=auth(), json={"clicks": 21}).status_code == 422


def test_pending_approval_blocks_generic_input(client, monkeypatch):
    hotkey = Mock()
    run = Mock()
    monkeypatch.setattr(control, "approval_pending", lambda: True)
    monkeypatch.setattr(control.pyautogui, "hotkey", hotkey)
    monkeypatch.setattr(control.subprocess, "run", run)
    response = client.post(
        "/api/hotkey", headers=auth(), json={"keys": ["command", "n"]}
    )
    assert response.status_code == 409
    assert client.post("/api/paste", headers=auth(), json={"text": "blocked"}).status_code == 409
    assert client.post("/api/clear-field", headers=auth()).status_code == 409
    hotkey.assert_not_called()
    run.assert_not_called()


def test_invalid_special_key_is_rejected(client):
    response = client.post("/api/key", headers=auth(), json={"key": "not-a-real-key"})
    assert response.status_code == 422


def test_command_list_contains_only_exact_allowlist_entries(client, monkeypatch, tmp_path: Path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("# comment\nprintf 'safe\\n'\n./allowed/system_info.sh\n", encoding="utf-8")
    monkeypatch.setattr(control, "ALLOWLIST_PATH", allowed)
    response = client.get("/api/commands", headers=auth())
    assert response.status_code == 200
    assert response.json()["commands"] == ["./allowed/system_info.sh", "printf 'safe\\n'"]


def test_text_watch_notifies_without_clicking(client, monkeypatch):
    click = Mock()
    monkeypatch.setattr(control.pyautogui, "click", click)
    monkeypatch.setattr(control, "scan_vscode_text", lambda: "Build completed successfully")
    configured = client.post(
        "/api/watch/text",
        headers=auth(),
        json={"text": "build completed", "enabled": True},
    )
    assert configured.status_code == 200
    status_response = client.get("/api/watch/text/status", headers=auth())
    assert status_response.status_code == 200
    assert status_response.json()["matched"] is True
    click.assert_not_called()


def test_control_page_contains_new_bounded_controls(client):
    html = client.get("/").text
    for control_id in (
        "typeText",
        "textDelivery",
        "clearField",
        "hotkey",
        "scrollUp",
        "scrollDown",
        "commandSelect",
        "watchText",
    ):
        assert f'id="{control_id}"' in html
    assert '<textarea id="typeText"' in html
    assert "api('/api/paste'" in html
    assert 'maxlength="16000"' not in html


def test_ocr_requires_positive_and_negative_buttons_on_same_row():
    words = [
        OCRWord("cancel", 95, 500, 400, 80, 30),
        OCRWord("allow", 96, 620, 402, 70, 30),
        OCRWord("run", 99, 100, 100, 50, 25),
    ]
    pair = find_approval_pair(words)
    assert pair is not None
    assert pair[0].text == "allow"
    assert pair[1].text == "cancel"
    assert find_approval_pair([OCRWord("allow", 99, 620, 402, 70, 30)]) is None


def test_ocr_recognizes_copilot_allow_and_skip_button_order():
    words = [
        OCRWord("allow", 96, 500, 400, 70, 30),
        OCRWord("skip", 95, 620, 402, 55, 30),
    ]
    pair = find_approval_pair(words)
    assert pair is not None
    assert pair[0].text == "allow"
    assert pair[1].text == "skip"


def test_ocr_preview_redacts_sensitive_values():
    text = "PC_CONTROL_TOKEN=private-value\nAuthorization: Bearer secret-token\nrm temporary.txt"
    redacted = redact_ocr_text(text)
    assert "private-value" not in redacted
    assert "secret-token" not in redacted
    assert "rm temporary.txt" in redacted


def test_visual_ocr_requires_positive_label_on_blue_button():
    words = [
        OCRWord("allow", 96, 100, 100, 50, 20),
        OCRWord("skip", 95, 180, 100, 40, 20),
    ]
    plain = Image.new("RGB", (320, 220), "#252526")
    assert find_visual_approval_pair(plain, words) is None

    button_image = plain.copy()
    ImageDraw.Draw(button_image).rectangle((88, 92, 162, 128), fill="#0e639c")
    assert find_visual_approval_pair(button_image, words) == (words[0], words[1])


def test_background_window_candidate_uses_global_coordinates():
    image = Image.new("RGB", (1000, 700), "#252526")
    allow = OCRWord("allow", 96, 600, 400, 70, 30)
    cancel = OCRWord("cancel", 95, 500, 400, 80, 30)
    candidate = monitor.build_candidate(
        image,
        (allow, cancel),
        logical_width=1000,
        logical_height=700,
        origin_x=120,
        origin_y=40,
    )
    assert candidate.approve_point == (755, 455)
    assert candidate.deny_point == (660, 455)


def test_accessibility_requires_sibling_action_buttons():
    allow = AccessibilityButton("allow", 500, 400, 180, 40, group_id=1)
    skip = AccessibilityButton("skip", 700, 400, 90, 40, group_id=1)
    pair = find_accessibility_approval_pair([allow, skip])
    assert pair == (allow, skip)
    unrelated_skip = AccessibilityButton("skip", 700, 400, 90, 40, group_id=2)
    assert find_accessibility_approval_pair([allow, unrelated_skip]) is None


def test_single_accessibility_allow_is_limited_to_chat_region():
    chat_allow = AccessibilityButton("allow", 1279, 472, 90, 30, group_id=1)
    pair = find_single_accessibility_allow([chat_allow], 0, 38, 1728, 1079)
    assert pair is not None
    assert pair[0] == chat_allow
    assert pair[1].label == "escape"

    editor_allow = AccessibilityButton("allow", 400, 472, 90, 30, group_id=2)
    assert find_single_accessibility_allow([editor_allow], 0, 38, 1728, 1079) is None


def test_approval_status_and_crop_require_auth(client, monkeypatch):
    candidate = approval_candidate()
    monkeypatch.setattr(control, "scan_for_approval", lambda: candidate)
    monkeypatch.setattr(control, "current_candidate", lambda candidate_id: candidate if candidate_id == candidate.candidate_id else None)
    assert client.get("/api/approval/status").status_code == 401
    status_response = client.get("/api/approval/status", headers=auth())
    assert status_response.status_code == 200
    assert status_response.json()["ocr_text"] == "Create and remove a temporary file"
    assert status_response.json()["pending"] is True
    image_response = client.get(f"/api/approval/{candidate.candidate_id}/image", headers=auth())
    assert image_response.status_code == 200
    assert image_response.content == b"focused-png"


def test_approval_decision_rechecks_prompt_before_clicking(client, monkeypatch):
    expected = approval_candidate()
    fresh = approval_candidate(candidate_id="fresh-candidate")
    click = Mock()
    monkeypatch.setattr(control, "current_candidate", lambda candidate_id: expected)
    monkeypatch.setattr(control, "scan_for_approval", lambda force=False: fresh)
    monkeypatch.setattr(control, "clear_candidate", Mock())
    monkeypatch.setattr(control, "activate_vscode_application", lambda: True)
    monkeypatch.setattr(control.pyautogui, "click", click)
    response = client.post(
        f"/api/approval/{expected.candidate_id}/decision",
        headers=auth(),
        json={"decision": "approve"},
    )
    assert response.status_code == 200
    click.assert_called_once_with(x=700, y=500, button="left")


def test_single_button_deny_uses_escape_instead_of_click(client, monkeypatch):
    expected = approval_candidate(deny_label="escape")
    fresh = approval_candidate(candidate_id="fresh-candidate", deny_label="escape")
    click = Mock()
    press = Mock()
    monkeypatch.setattr(control, "current_candidate", lambda candidate_id: expected)
    monkeypatch.setattr(control, "scan_for_approval", lambda force=False: fresh)
    monkeypatch.setattr(control, "clear_candidate", Mock())
    monkeypatch.setattr(control, "activate_vscode_application", lambda: True)
    monkeypatch.setattr(control.pyautogui, "click", click)
    monkeypatch.setattr(control.pyautogui, "press", press)
    response = client.post(
        f"/api/approval/{expected.candidate_id}/decision",
        headers=auth(),
        json={"decision": "deny"},
    )
    assert response.status_code == 200
    press.assert_called_once_with("esc")
    click.assert_not_called()


def test_changed_approval_prompt_is_never_clicked(client, monkeypatch):
    expected = approval_candidate()
    moved = approval_candidate(candidate_id="moved", approve_point=(900, 600))
    click = Mock()
    monkeypatch.setattr(control, "current_candidate", lambda candidate_id: expected)
    monkeypatch.setattr(control, "scan_for_approval", lambda force=False: moved)
    monkeypatch.setattr(control, "clear_candidate", Mock())
    monkeypatch.setattr(control.pyautogui, "click", click)
    response = client.post(
        f"/api/approval/{expected.candidate_id}/decision",
        headers=auth(),
        json={"decision": "approve"},
    )
    assert response.status_code == 409
    click.assert_not_called()


def test_unchanged_prompt_keeps_stable_candidate(monkeypatch):
    original = approval_candidate(candidate_id="stable")
    detected = approval_candidate(candidate_id="new-scan")
    monkeypatch.setattr(monitor, "_candidate", original)
    monkeypatch.setattr(monitor, "_last_scan_at", 0.0)
    monkeypatch.setattr(monitor, "_last_ocr_at", 0.0)
    monkeypatch.setattr(monitor, "frontmost_application_name", lambda: "Visual Studio Code")
    monkeypatch.setattr(
        monitor,
        "capture_ocr_image",
        lambda: (Mock(size=(1000, 700)), 1.0, 1728, 1117, 0, 0),
    )
    allow = AccessibilityButton("allow", 620, 400, 70, 30, group_id=1)
    cancel = AccessibilityButton("cancel", 500, 400, 80, 30, group_id=1)
    monkeypatch.setattr(monitor, "accessibility_buttons", lambda: [allow, cancel])
    monkeypatch.setattr(monitor, "find_accessibility_approval_pair", lambda buttons: (allow, cancel))
    monkeypatch.setattr(monitor, "build_accessibility_candidate", lambda *args: detected)
    assert monitor.scan_for_approval(force=False).candidate_id == "stable"


def test_busy_approval_scan_returns_without_waiting(monkeypatch):
    candidate = approval_candidate(candidate_id="cached")
    monkeypatch.setattr(monitor, "_candidate", candidate)
    monitor._lock.acquire()
    try:
        assert monitor.scan_for_approval(force=False) is candidate
    finally:
        monitor._lock.release()


def test_visual_ocr_fallback_is_rate_limited(monkeypatch):
    monkeypatch.setattr(monitor, "_candidate", None)
    monkeypatch.setattr(monitor, "_last_scan_at", 0.0)
    monkeypatch.setattr(monitor, "_last_ocr_at", monitor.time.monotonic())
    monkeypatch.setattr(monitor, "frontmost_application_name", lambda: "Visual Studio Code")
    monkeypatch.setattr(
        monitor,
        "capture_ocr_image",
        lambda: (Mock(size=(1000, 700)), 1.0, 1000, 700, 0, 0),
    )
    monkeypatch.setattr(monitor, "accessibility_buttons", lambda: [])
    run_ocr = Mock()
    monkeypatch.setattr(monitor, "run_ocr", run_ocr)
    assert monitor.scan_for_approval(force=False) is None
    run_ocr.assert_not_called()
