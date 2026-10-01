from __future__ import annotations

import io
import logging
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass

import Quartz
from ApplicationServices import (
    AXUIElementCopyAttributeValue,
    AXUIElementCreateApplication,
    AXValueGetValue,
    kAXValueCGPointType,
    kAXValueCGSizeType,
)
from AppKit import NSWorkspace
from PIL import Image

OCR_INTERVAL_SECONDS = 1.5
OCR_FALLBACK_INTERVAL_SECONDS = 6
CANDIDATE_MAX_AGE_SECONDS = 30
OCR_TIMEOUT_SECONDS = 8
MAX_OCR_WIDTH = 1600
APPROVAL_CROP_LEFT_CONTEXT = 60
APPROVAL_CROP_TOP_CONTEXT = 500
APPROVAL_CROP_RIGHT_CONTEXT = 650
APPROVAL_CROP_BOTTOM_CONTEXT = 150
VSCODE_APP_NAMES = {"Visual Studio Code", "Code", "Code - Insiders"}
POSITIVE_LABELS = {"allow", "approve", "continue", "confirm", "run", "yes"}
NEGATIVE_LABELS = {"cancel", "deny", "reject", "skip", "stop", "no"}
MAX_ACCESSIBILITY_ELEMENTS = 10_000

logger = logging.getLogger("muse_pc_control.approval")


@dataclass(frozen=True)
class OCRWord:
    text: str
    confidence: float
    left: int
    top: int
    width: int
    height: int

    @property
    def center(self) -> tuple[float, float]:
        return self.left + self.width / 2, self.top + self.height / 2


@dataclass(frozen=True)
class AccessibilityButton:
    label: str
    left: float
    top: float
    width: float
    height: float
    group_id: int

    @property
    def center(self) -> tuple[float, float]:
        return self.left + self.width / 2, self.top + self.height / 2


@dataclass(frozen=True)
class ApprovalCandidate:
    candidate_id: str
    created_at: float
    approve_label: str
    deny_label: str
    approve_point: tuple[int, int]
    deny_point: tuple[int, int]
    crop_png: bytes
    ocr_text: str = ""

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.created_at)


_lock = threading.Lock()
_last_scan_at = 0.0
_last_ocr_at = 0.0
_candidate: ApprovalCandidate | None = None
_last_diagnostic_signature: tuple[object, ...] | None = None
_scan_status: dict[str, str] = {"state": "starting", "frontmost_app": ""}


def frontmost_application_name() -> str:
    application = NSWorkspace.sharedWorkspace().frontmostApplication()
    return str(application.localizedName() or "") if application else ""


def vscode_application() -> object | None:
    applications = NSWorkspace.sharedWorkspace().runningApplications()
    matches = [
        application
        for application in applications
        if str(application.localizedName() or "") in VSCODE_APP_NAMES
    ]
    return next((application for application in matches if application.isActive()), matches[0] if matches else None)


def activate_vscode_application() -> bool:
    application = vscode_application()
    return bool(application and application.activateWithOptions_(1 << 1))


def accessibility_attribute(element: object, name: str) -> object | None:
    try:
        error, value = AXUIElementCopyAttributeValue(element, name, None)
    except Exception:
        return None
    return value if error == 0 else None


def accessibility_value(value: object, value_type: int) -> object | None:
    if value is None:
        return None
    try:
        success, converted = AXValueGetValue(value, value_type, None)
    except Exception:
        return None
    return converted if success else None


def button_label(element: object) -> str | None:
    values = (
        accessibility_attribute(element, "AXTitle"),
        accessibility_attribute(element, "AXDescription"),
        accessibility_attribute(element, "AXValue"),
    )
    for value in values:
        normalized = " ".join(re.findall(r"[a-z]+", str(value or "").lower()))
        for label in POSITIVE_LABELS | NEGATIVE_LABELS:
            if normalized == label or normalized.startswith(f"{label} "):
                return label
    return None


def accessibility_buttons() -> list[AccessibilityButton]:
    application = vscode_application()
    if not application:
        return []
    root = AXUIElementCreateApplication(application.processIdentifier())
    queue: list[tuple[object, int]] = [(root, 0)]
    buttons: list[AccessibilityButton] = []
    visited = 0
    while queue and visited < MAX_ACCESSIBILITY_ELEMENTS:
        element, group_id = queue.pop(0)
        visited += 1
        role = accessibility_attribute(element, "AXRole")
        if role == "AXButton":
            label = button_label(element)
            position = accessibility_value(
                accessibility_attribute(element, "AXPosition"), kAXValueCGPointType
            )
            size = accessibility_value(accessibility_attribute(element, "AXSize"), kAXValueCGSizeType)
            if label and position is not None and size is not None and size.width >= 24 and size.height >= 16:
                buttons.append(
                    AccessibilityButton(
                        label=label,
                        left=float(position.x),
                        top=float(position.y),
                        width=float(size.width),
                        height=float(size.height),
                        group_id=group_id,
                    )
                )
        children = accessibility_attribute(element, "AXChildren") or []
        queue.extend((child, id(element)) for child in children)
    return buttons


def find_accessibility_approval_pair(
    buttons: list[AccessibilityButton],
) -> tuple[AccessibilityButton, AccessibilityButton] | None:
    positives = [button for button in buttons if button.label in POSITIVE_LABELS]
    negatives = [button for button in buttons if button.label in NEGATIVE_LABELS]
    pairs: list[tuple[float, AccessibilityButton, AccessibilityButton]] = []
    for positive in positives:
        positive_x, positive_y = positive.center
        for negative in negatives:
            negative_x, negative_y = negative.center
            vertical_limit = max(positive.height, negative.height) * 1.5
            horizontal_gap = abs(positive_x - negative_x)
            if (
                positive.group_id == negative.group_id
                and abs(positive_y - negative_y) <= vertical_limit
                and 8 <= horizontal_gap <= 700
            ):
                pairs.append((positive.top, positive, negative))
    if not pairs:
        return None
    _, positive, negative = max(pairs, key=lambda pair: pair[0])
    return positive, negative


def find_single_accessibility_allow(
    buttons: list[AccessibilityButton],
    origin_x: int,
    origin_y: int,
    window_width: int,
    window_height: int,
) -> tuple[AccessibilityButton, AccessibilityButton] | None:
    candidates = [
        button
        for button in buttons
        if button.label == "allow"
        and button.left >= origin_x + window_width * 0.55
        and origin_y <= button.top <= origin_y + window_height
        and 35 <= button.width <= 300
        and 16 <= button.height <= 90
    ]
    if not candidates:
        return None
    positive = max(candidates, key=lambda button: button.top)
    escape = AccessibilityButton(
        label="escape",
        left=positive.left + positive.width + 12,
        top=positive.top,
        width=max(positive.width, 60),
        height=positive.height,
        group_id=positive.group_id,
    )
    return positive, escape


def parse_tesseract_tsv(tsv: str) -> list[OCRWord]:
    words: list[OCRWord] = []
    lines = tsv.splitlines()
    for line in lines[1:]:
        fields = line.split("\t", 11)
        if len(fields) != 12:
            continue
        text = re.sub(r"[^a-z]", "", fields[11].strip().lower())
        if not text:
            continue
        try:
            confidence = float(fields[10])
            left, top, width, height = map(int, fields[6:10])
        except ValueError:
            continue
        if confidence >= 45 and width > 0 and height > 0:
            words.append(OCRWord(text, confidence, left, top, width, height))
    return words


def find_approval_pair(words: list[OCRWord]) -> tuple[OCRWord, OCRWord] | None:
    positives = [word for word in words if word.text in POSITIVE_LABELS]
    negatives = [word for word in words if word.text in NEGATIVE_LABELS]
    pairs: list[tuple[float, OCRWord, OCRWord]] = []
    for positive in positives:
        positive_x, positive_y = positive.center
        for negative in negatives:
            negative_x, negative_y = negative.center
            vertical_limit = max(positive.height, negative.height) * 1.8
            horizontal_gap = abs(positive_x - negative_x)
            if abs(positive_y - negative_y) <= vertical_limit and 8 <= horizontal_gap <= 650:
                score = positive.confidence + negative.confidence - abs(positive_y - negative_y)
                pairs.append((score, positive, negative))
    if not pairs:
        return None
    _, positive, negative = max(pairs, key=lambda pair: pair[0])
    return positive, negative


def blue_button_background_ratio(image: Image.Image, word: OCRWord) -> float:
    left = max(0, word.left - 12)
    top = max(0, word.top - 8)
    right = min(image.width, word.left + word.width + 12)
    bottom = min(image.height, word.top + word.height + 8)
    if right <= left or bottom <= top:
        return 0.0
    pixels = list(image.crop((left, top, right, bottom)).convert("RGB").getdata())
    blue_pixels = sum(
        1
        for red, green, blue in pixels
        if blue >= 100 and blue - red >= 45 and blue - green >= 20
    )
    return blue_pixels / len(pixels)


def word_has_blue_button_background(image: Image.Image, word: OCRWord) -> bool:
    return blue_button_background_ratio(image, word) >= 0.18


def find_visual_approval_pair(
    image: Image.Image, words: list[OCRWord]
) -> tuple[OCRWord, OCRWord] | None:
    positives = [word for word in words if word.text in POSITIVE_LABELS]
    negatives = [word for word in words if word.text in NEGATIVE_LABELS]
    pairs: list[tuple[float, OCRWord, OCRWord]] = []
    for positive in positives:
        if not word_has_blue_button_background(image, positive):
            continue
        positive_x, positive_y = positive.center
        for negative in negatives:
            negative_x, negative_y = negative.center
            vertical_gap = abs(positive_y - negative_y)
            horizontal_gap = abs(positive_x - negative_x)
            if vertical_gap <= max(positive.height, negative.height) * 1.2 and 8 <= horizontal_gap <= 250:
                score = positive.confidence + negative.confidence - vertical_gap
                pairs.append((score, positive, negative))
    if not pairs:
        return None
    _, positive, negative = max(pairs, key=lambda pair: pair[0])
    return positive, negative


def run_ocr(png: bytes) -> list[OCRWord]:
    executable = shutil.which("tesseract")
    if not executable:
        raise RuntimeError("Tesseract is not installed")
    completed = subprocess.run(
        [executable, "stdin", "stdout", "--psm", "11", "tsv"],
        input=png,
        capture_output=True,
        timeout=OCR_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Tesseract failed: {detail}")
    return parse_tesseract_tsv(completed.stdout.decode("utf-8", errors="replace"))


def redact_ocr_text(text: str) -> str:
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", text)
    return re.sub(
        r"(?i)\b(PC_CONTROL_TOKEN|token|secret|password|api[_ -]?key)\b(\s*[:=]\s*)\S+",
        r"\1\2[redacted]",
        text,
    )


def extract_action_text(png: bytes) -> str:
    executable = shutil.which("tesseract")
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            [executable, "stdin", "stdout", "--psm", "6"],
            input=png,
            capture_output=True,
            timeout=OCR_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    raw_text = completed.stdout.decode("utf-8", errors="replace")
    lines = [" ".join(line.split()) for line in raw_text.splitlines()]
    normalized = "\n".join(line for line in lines if line)
    return redact_ocr_text(normalized)[:1000]


def scan_vscode_text() -> str:
    image, _, _, _, _, _ = capture_ocr_image()
    return extract_action_text(encode_png(image))


def vscode_window_info() -> dict[object, object]:
    application = vscode_application()
    if not application:
        raise RuntimeError("Visual Studio Code is not running")
    options = Quartz.kCGWindowListOptionAll | Quartz.kCGWindowListExcludeDesktopElements
    windows = Quartz.CGWindowListCopyWindowInfo(options, Quartz.kCGNullWindowID)
    candidates = [
        window
        for window in windows
        if window.get(Quartz.kCGWindowOwnerPID) == application.processIdentifier()
        and window.get(Quartz.kCGWindowLayer) == 0
        and float(window.get(Quartz.kCGWindowAlpha, 0)) > 0
        and float(window.get(Quartz.kCGWindowBounds, {}).get("Width", 0)) >= 400
        and float(window.get(Quartz.kCGWindowBounds, {}).get("Height", 0)) >= 300
    ]
    if not candidates:
        raise RuntimeError("No capturable Visual Studio Code window is available")
    return max(
        candidates,
        key=lambda window: float(window[Quartz.kCGWindowBounds]["Width"])
        * float(window[Quartz.kCGWindowBounds]["Height"]),
    )


def capture_ocr_image() -> tuple[Image.Image, float, int, int, int, int]:
    window = vscode_window_info()
    window_id = int(window[Quartz.kCGWindowNumber])
    bounds = window[Quartz.kCGWindowBounds]
    logical_width = round(float(bounds["Width"]))
    logical_height = round(float(bounds["Height"]))
    origin_x = round(float(bounds["X"]))
    origin_y = round(float(bounds["Y"]))
    image_options = Quartz.kCGWindowImageBoundsIgnoreFraming | Quartz.kCGWindowImageBestResolution
    cg_image = Quartz.CGWindowListCreateImage(
        Quartz.CGRectNull,
        Quartz.kCGWindowListOptionIncludingWindow,
        window_id,
        image_options,
    )
    if cg_image is None:
        raise RuntimeError("Visual Studio Code window capture failed")
    width = Quartz.CGImageGetWidth(cg_image)
    height = Quartz.CGImageGetHeight(cg_image)
    bytes_per_row = Quartz.CGImageGetBytesPerRow(cg_image)
    provider = Quartz.CGImageGetDataProvider(cg_image)
    data = bytes(Quartz.CGDataProviderCopyData(provider))
    image = Image.frombuffer(
        "RGBA", (width, height), data, "raw", "BGRA", bytes_per_row, 1
    ).convert("RGB")
    scale = min(1.0, MAX_OCR_WIDTH / image.width)
    if scale < 1:
        image = image.resize((round(image.width * scale), round(image.height * scale)), Image.Resampling.LANCZOS)
    return image, scale, logical_width, logical_height, origin_x, origin_y


def encode_png(image: Image.Image) -> bytes:
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def build_candidate(
    image: Image.Image,
    pair: tuple[OCRWord, OCRWord],
    logical_width: int,
    logical_height: int,
    origin_x: int = 0,
    origin_y: int = 0,
) -> ApprovalCandidate:
    positive, negative = pair
    image_width, image_height = image.size

    def logical_point(word: OCRWord) -> tuple[int, int]:
        x, y = word.center
        return (
            origin_x + min(max(round(x * logical_width / image_width), 0), logical_width - 1),
            origin_y + min(max(round(y * logical_height / image_height), 0), logical_height - 1),
        )

    left = max(0, min(positive.left, negative.left) - APPROVAL_CROP_LEFT_CONTEXT)
    top = max(0, min(positive.top, negative.top) - APPROVAL_CROP_TOP_CONTEXT)
    right = min(
        image_width,
        max(positive.left + positive.width, negative.left + negative.width)
        + APPROVAL_CROP_RIGHT_CONTEXT,
    )
    bottom = min(
        image_height,
        max(positive.top + positive.height, negative.top + negative.height)
        + APPROVAL_CROP_BOTTOM_CONTEXT,
    )
    return ApprovalCandidate(
        candidate_id=uuid.uuid4().hex,
        created_at=time.monotonic(),
        approve_label=positive.text,
        deny_label=negative.text,
        approve_point=logical_point(positive),
        deny_point=logical_point(negative),
        crop_png=encode_png(image.crop((left, top, right, bottom))),
    )


def build_accessibility_candidate(
    image: Image.Image,
    pair: tuple[AccessibilityButton, AccessibilityButton],
    logical_width: int,
    logical_height: int,
    origin_x: int = 0,
    origin_y: int = 0,
) -> ApprovalCandidate:
    positive, negative = pair
    image_width, image_height = image.size
    scale_x = image_width / logical_width
    scale_y = image_height / logical_height
    left = max(
        0,
        round((min(positive.left, negative.left) - origin_x) * scale_x)
        - APPROVAL_CROP_LEFT_CONTEXT,
    )
    top = max(
        0,
        round((min(positive.top, negative.top) - origin_y) * scale_y)
        - APPROVAL_CROP_TOP_CONTEXT,
    )
    right = min(
        image_width,
        round((max(positive.left + positive.width, negative.left + negative.width) - origin_x) * scale_x)
        + APPROVAL_CROP_RIGHT_CONTEXT,
    )
    bottom = min(
        image_height,
        round((max(positive.top + positive.height, negative.top + negative.height) - origin_y) * scale_y)
        + APPROVAL_CROP_BOTTOM_CONTEXT,
    )
    return ApprovalCandidate(
        candidate_id=uuid.uuid4().hex,
        created_at=time.monotonic(),
        approve_label=positive.label,
        deny_label=negative.label,
        approve_point=(round(positive.center[0]), round(positive.center[1])),
        deny_point=(round(negative.center[0]), round(negative.center[1])),
        crop_png=encode_png(image.crop((left, top, right, bottom))),
    )


def scan_for_approval(*, force: bool = False) -> ApprovalCandidate | None:
    global _candidate, _last_diagnostic_signature, _last_ocr_at, _last_scan_at, _scan_status
    acquired = _lock.acquire(blocking=force)
    if not acquired:
        return _candidate if _candidate and _candidate.age_seconds <= CANDIDATE_MAX_AGE_SECONDS else None
    try:
        now = time.monotonic()
        if not force and now - _last_scan_at < OCR_INTERVAL_SECONDS:
            if _candidate and _candidate.age_seconds <= CANDIDATE_MAX_AGE_SECONDS:
                return _candidate
            return None
        _last_scan_at = now
        frontmost = frontmost_application_name()
        image, _, logical_width, logical_height, origin_x, origin_y = capture_ocr_image()
        buttons = accessibility_buttons()
        accessibility_pair = find_accessibility_approval_pair(buttons)
        accessibility_single = None
        if not accessibility_pair:
            accessibility_single = find_single_accessibility_allow(
                buttons, origin_x, origin_y, logical_width, logical_height
            )
            accessibility_pair = accessibility_single
        relevant_words: list[OCRWord] = []
        blue_ratios: list[tuple[str, int, int, float]] = []
        visual_pair: tuple[OCRWord, OCRWord] | None = None
        ocr_skipped = False
        if accessibility_pair:
            detected = build_accessibility_candidate(
                image, accessibility_pair, logical_width, logical_height, origin_x, origin_y
            )
        elif not force and now - _last_ocr_at < OCR_FALLBACK_INTERVAL_SECONDS:
            detected = None
            ocr_skipped = True
        else:
            _last_ocr_at = now
            words = run_ocr(encode_png(image))
            relevant_words = [
                word for word in words if word.text in POSITIVE_LABELS | NEGATIVE_LABELS
            ]
            blue_ratios = [
                (word.text, word.left, word.top, round(blue_button_background_ratio(image, word), 3))
                for word in relevant_words
                if word.text in POSITIVE_LABELS
            ]
            visual_pair = find_visual_approval_pair(image, words)
            detected = (
                build_candidate(
                    image, visual_pair, logical_width, logical_height, origin_x, origin_y
                )
                if visual_pair
                else None
            )
        _scan_status = {
            "state": "pending" if detected else "no_candidate",
            "frontmost_app": frontmost,
            "monitoring_app": "Visual Studio Code",
            "source": "accessibility" if accessibility_pair else "visual_ocr",
        }
        signature = (
            tuple((button.label, round(button.left), round(button.top)) for button in buttons),
            tuple((word.text, word.left, word.top) for word in relevant_words),
            tuple(blue_ratios),
            detected.approve_label if detected else None,
            detected.deny_label if detected else None,
            detected.approve_point if detected else None,
            detected.deny_point if detected else None,
        )
        if force or signature != _last_diagnostic_signature:
            logger.info(
                "approval_scan frontmost=%r accessibility=%s ocr_words=%s blue_ratios=%s "
                "source=%s pair=%s points=%s",
                frontmost,
                [(button.label, round(button.left), round(button.top)) for button in buttons],
                [(word.text, word.left, word.top, round(word.confidence, 1)) for word in relevant_words],
                blue_ratios,
                "accessibility_single" if accessibility_single else (
                    "accessibility" if accessibility_pair else "visual_ocr"
                ),
                (detected.approve_label, detected.deny_label) if detected else None,
                (detected.approve_point, detected.deny_point) if detected else None,
            )
            _last_diagnostic_signature = signature
        if (
            not force
            and _candidate
            and _candidate.age_seconds <= CANDIDATE_MAX_AGE_SECONDS
            and detected
            and candidates_match(_candidate, detected)
        ):
            return _candidate
        if detected and not force:
            detected = ApprovalCandidate(
                candidate_id=detected.candidate_id,
                created_at=detected.created_at,
                approve_label=detected.approve_label,
                deny_label=detected.deny_label,
                approve_point=detected.approve_point,
                deny_point=detected.deny_point,
                crop_png=detected.crop_png,
                ocr_text=extract_action_text(detected.crop_png),
            )
        if (
            not force
            and ocr_skipped
            and detected is None
            and _candidate
            and _candidate.age_seconds <= CANDIDATE_MAX_AGE_SECONDS
        ):
            return _candidate
        _candidate = detected
        return _candidate
    finally:
        _lock.release()


def current_candidate(candidate_id: str) -> ApprovalCandidate | None:
    with _lock:
        if not _candidate or _candidate.candidate_id != candidate_id:
            return None
        if _candidate.age_seconds > CANDIDATE_MAX_AGE_SECONDS:
            return None
        return _candidate


def approval_pending() -> bool:
    with _lock:
        return bool(_candidate and _candidate.age_seconds <= CANDIDATE_MAX_AGE_SECONDS)


def approval_scan_status() -> dict[str, str]:
    with _lock:
        return dict(_scan_status)


def candidates_match(expected: ApprovalCandidate, current: ApprovalCandidate) -> bool:
    if expected.approve_label != current.approve_label or expected.deny_label != current.deny_label:
        return False
    return all(
        abs(first - second) <= 50
        for expected_point, current_point in (
            (expected.approve_point, current.approve_point),
            (expected.deny_point, current.deny_point),
        )
        for first, second in zip(expected_point, current_point)
    )


def clear_candidate() -> None:
    global _candidate
    with _lock:
        _candidate = None
