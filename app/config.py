from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WatcherConfig:
    target_chat: str = "æ–‡ä»¶ä¼ è¾“åŠ©æ‰‹"
    backend_mode: str = "db"
    poll_ms: int = 300
    rebind_ms: int = 5000
    copy_only_incoming: bool = True
    text_only: bool = True
    log_file: str = r".\runtime\logs\listener.log"

    # OCR tuning for WeChat desktop's two-pane layout.
    ocr_chat_left_offset_px: int = 220
    ocr_chat_right_margin_px: int = 8
    ocr_message_top_ratio: float = 0.52
    ocr_message_bottom_ratio: float = 0.86
    ocr_message_side_padding_px: int = 10
    ocr_message_left_ratio: float = 0.30
    ocr_message_right_ratio: float = 0.98
    ocr_header_top_ratio: float = 0.00
    ocr_header_bottom_ratio: float = 0.24
    ocr_target_check_interval_ms: int = 3000
    ocr_scale: float = 0.65


def _as_positive_int(value: Any, field_name: str, default_value: int) -> int:
    if value is None:
        return default_value
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{field_name} must be > 0")
    return parsed


def _as_non_negative_int(value: Any, field_name: str, default_value: int) -> int:
    if value is None:
        return default_value
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{field_name} must be >= 0")
    return parsed


def _as_bool(value: Any, field_name: str, default_value: bool) -> bool:
    if value is None:
        return default_value
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"1", "true", "yes", "y"}:
            return True
        if low in {"0", "false", "no", "n"}:
            return False
    raise ValueError(f"{field_name} must be boolean")


def _as_choice(
    value: Any,
    field_name: str,
    default_value: str,
    allowed: set[str],
) -> str:
    if value is None:
        return default_value
    parsed = str(value).strip().lower()
    if parsed not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(f"{field_name} must be one of: {choices}")
    return parsed


def _as_ratio(value: Any, field_name: str, default_value: float) -> float:
    if value is None:
        return default_value
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a number") from exc
    if parsed < 0.0 or parsed > 1.0:
        raise ValueError(f"{field_name} must be in [0, 1]")
    return parsed


def _as_scale(value: Any, field_name: str, default_value: float) -> float:
    if value is None:
        return default_value
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a number") from exc
    if parsed <= 0.0 or parsed > 1.0:
        raise ValueError(f"{field_name} must be in (0, 1]")
    return parsed


def load_config(config_path: Path) -> WatcherConfig:
    base = WatcherConfig()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Config must be a JSON object")

    target_chat = str(data.get("target_chat", base.target_chat)).strip()
    if not target_chat:
        raise ValueError("target_chat must not be empty")
    backend_mode = _as_choice(
        data.get("backend_mode"),
        "backend_mode",
        base.backend_mode,
        {"db", "auto", "ocr", "uia"},
    )

    poll_ms = _as_positive_int(data.get("poll_ms"), "poll_ms", base.poll_ms)
    rebind_ms = _as_positive_int(data.get("rebind_ms"), "rebind_ms", base.rebind_ms)
    copy_only_incoming = _as_bool(
        data.get("copy_only_incoming"),
        "copy_only_incoming",
        base.copy_only_incoming,
    )
    text_only = _as_bool(data.get("text_only"), "text_only", base.text_only)
    log_file = str(data.get("log_file", base.log_file)).strip() or base.log_file

    ocr_chat_left_offset_px = _as_non_negative_int(
        data.get("ocr_chat_left_offset_px"),
        "ocr_chat_left_offset_px",
        base.ocr_chat_left_offset_px,
    )
    ocr_chat_right_margin_px = _as_non_negative_int(
        data.get("ocr_chat_right_margin_px"),
        "ocr_chat_right_margin_px",
        base.ocr_chat_right_margin_px,
    )
    ocr_message_top_ratio = _as_ratio(
        data.get("ocr_message_top_ratio"),
        "ocr_message_top_ratio",
        base.ocr_message_top_ratio,
    )
    ocr_message_bottom_ratio = _as_ratio(
        data.get("ocr_message_bottom_ratio"),
        "ocr_message_bottom_ratio",
        base.ocr_message_bottom_ratio,
    )
    if ocr_message_bottom_ratio <= ocr_message_top_ratio:
        raise ValueError("ocr_message_bottom_ratio must be greater than ocr_message_top_ratio")

    ocr_message_side_padding_px = _as_non_negative_int(
        data.get("ocr_message_side_padding_px"),
        "ocr_message_side_padding_px",
        base.ocr_message_side_padding_px,
    )
    ocr_message_left_ratio = _as_ratio(
        data.get("ocr_message_left_ratio"),
        "ocr_message_left_ratio",
        base.ocr_message_left_ratio,
    )
    ocr_message_right_ratio = _as_ratio(
        data.get("ocr_message_right_ratio"),
        "ocr_message_right_ratio",
        base.ocr_message_right_ratio,
    )
    if ocr_message_right_ratio <= ocr_message_left_ratio:
        raise ValueError("ocr_message_right_ratio must be greater than ocr_message_left_ratio")
    ocr_header_top_ratio = _as_ratio(
        data.get("ocr_header_top_ratio"),
        "ocr_header_top_ratio",
        base.ocr_header_top_ratio,
    )
    ocr_header_bottom_ratio = _as_ratio(
        data.get("ocr_header_bottom_ratio"),
        "ocr_header_bottom_ratio",
        base.ocr_header_bottom_ratio,
    )
    if ocr_header_bottom_ratio <= ocr_header_top_ratio:
        raise ValueError("ocr_header_bottom_ratio must be greater than ocr_header_top_ratio")

    ocr_target_check_interval_ms = _as_positive_int(
        data.get("ocr_target_check_interval_ms"),
        "ocr_target_check_interval_ms",
        base.ocr_target_check_interval_ms,
    )
    ocr_scale = _as_scale(
        data.get("ocr_scale"),
        "ocr_scale",
        base.ocr_scale,
    )

    return replace(
        base,
        target_chat=target_chat,
        backend_mode=backend_mode,
        poll_ms=poll_ms,
        rebind_ms=rebind_ms,
        copy_only_incoming=copy_only_incoming,
        text_only=text_only,
        log_file=log_file,
        ocr_chat_left_offset_px=ocr_chat_left_offset_px,
        ocr_chat_right_margin_px=ocr_chat_right_margin_px,
        ocr_message_top_ratio=ocr_message_top_ratio,
        ocr_message_bottom_ratio=ocr_message_bottom_ratio,
        ocr_message_side_padding_px=ocr_message_side_padding_px,
        ocr_message_left_ratio=ocr_message_left_ratio,
        ocr_message_right_ratio=ocr_message_right_ratio,
        ocr_header_top_ratio=ocr_header_top_ratio,
        ocr_header_bottom_ratio=ocr_header_bottom_ratio,
        ocr_target_check_interval_ms=ocr_target_check_interval_ms,
        ocr_scale=ocr_scale,
    )



