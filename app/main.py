from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import time
from typing import Any, Protocol

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.clipboard_win import ClipboardError, copy_text
from app.config import WatcherConfig, load_config
from app.dedupe import MessageDeduper
from app.logger import JsonlLogger
from app.wechat_db import DBUnavailable, WeChatDBAutomation
from app.wechat_ocr import OCRUnavailable, WeChatOCRAutomation
from app.wechat_ui import UIAutomationUnavailable, WeChatUIAutomation


class ChatBackend(Protocol):
    def bind_window(self) -> bool: ...
    def is_bound(self) -> bool: ...
    def unbind(self) -> None: ...
    def get_window_title(self) -> str: ...
    def is_target_chat_active(self) -> bool: ...
    def fetch_visible_text_messages(self) -> list[Any]: ...
    def doctor(self) -> dict[str, Any]: ...


def _short_text(text: str, limit: int = 90) -> str:
    one_line = text.replace("\r", " ").replace("\n", " ").strip()
    if len(one_line) <= limit:
        return one_line
    return one_line[: limit - 3] + "..."


def choose_backend(config: WatcherConfig) -> tuple[ChatBackend, str, dict[str, Any]]:
    probes: dict[str, Any] = {}
    mode = str(getattr(config, "backend_mode", "db")).strip().lower()

    if mode in {"db", "auto"}:
        try:
            db = WeChatDBAutomation(target_chat=config.target_chat, config=config)
            if db.bind_window():
                probes["db"] = {"ready": True}
                return db, "db", probes
            probes["db"] = {
                "ready": False,
                "reason": db.last_error or "bind_failed",
            }
        except DBUnavailable as exc:
            probes["db"] = {"ready": False, "reason": str(exc)}
        except Exception as exc:  # pragma: no cover
            probes["db"] = {"ready": False, "reason": f"db_error: {exc}"}

    if mode == "db":
        raise RuntimeError(f"DB backend unavailable. probes={probes}")

    if mode not in {"ocr", "uia", "auto"}:
        raise RuntimeError(f"Unsupported backend_mode: {mode}")

    weak_uia: WeChatUIAutomation | None = None

    try:
        ui = WeChatUIAutomation(target_chat=config.target_chat)
        if ui.bind_window():
            ui_probe = ui.doctor()
            probes["uia"] = ui_probe
            node_count = int(ui_probe.get("accessible_node_count", 0))
            # On some WeChat builds, UIA sees only the root window and no controls.
            if node_count > 1:
                ui.unbind()
                return ui, "uia", probes
            weak_uia = ui
        else:
            probes["uia"] = {"window_found": False, "reason": "bind_failed"}
    except UIAutomationUnavailable as exc:
        probes["uia"] = {"window_found": False, "reason": str(exc)}
    except Exception as exc:  # pragma: no cover
        probes["uia"] = {"window_found": False, "reason": f"uia_error: {exc}"}

    try:
        ocr = WeChatOCRAutomation(target_chat=config.target_chat, config=config)
        probes["ocr"] = {"window_found": None, "reason": "fallback"}
        return ocr, "ocr", probes
    except OCRUnavailable as exc:
        probes["ocr"] = {"window_found": False, "reason": str(exc)}
    except Exception as exc:  # pragma: no cover
        probes["ocr"] = {"window_found": False, "reason": f"ocr_error: {exc}"}

    if weak_uia is not None:
        weak_uia.unbind()
        probes["fallback"] = {"reason": "use_weak_uia"}
        return weak_uia, "uia-weak", probes

    raise RuntimeError(f"No usable backend. probes={probes}")


class Listener:
    def __init__(self, config: WatcherConfig, logger: JsonlLogger) -> None:
        self.config = config
        self.logger = logger
        self.ui, self.backend_name, self.backend_probes = choose_backend(config)
        self.is_ocr_backend = self.backend_name.startswith("ocr")
        self.deduper = MessageDeduper(max_size=6000)
        self.seeded = False
        self.last_rebind_try_at = 0.0
        self.last_wait_log_at = 0.0
        self.target_check_interval_s = max(
            0.3, self.config.ocr_target_check_interval_ms / 1000.0
        )
        self.last_target_check_at = 0.0
        self.target_active_cache = False

    def run_forever(self) -> None:
        poll_s = self.config.poll_ms / 1000.0
        rebind_s = self.config.rebind_ms / 1000.0

        print(f"Listener started. backend={self.backend_name}. Ctrl+C to stop.")
        self.logger.log(
            "start",
            target_chat=self.config.target_chat,
            poll_ms=self.config.poll_ms,
            rebind_ms=self.config.rebind_ms,
            backend=self.backend_name,
            probes=self.backend_probes,
        )

        while True:
            now = time.monotonic()
            if not self.ui.is_bound():
                if now - self.last_rebind_try_at >= rebind_s:
                    self.last_rebind_try_at = now
                    if self.ui.bind_window():
                        self.deduper.clear()
                        self.seeded = False
                        self.target_active_cache = False
                        self.last_target_check_at = 0.0
                        title = self.ui.get_window_title()
                        print(f"Bound to WeChat window: {title or '(untitled)'}")
                        self.logger.log(
                            "rebind",
                            status="ok",
                            window_title=title,
                            backend=self.backend_name,
                        )
                    else:
                        reason = str(getattr(self.ui, "last_error", "") or "")
                        if reason:
                            print(f"Backend not ready: {reason}")
                        else:
                            print("WeChat window not found. Retrying...")
                        self.logger.log(
                            "rebind",
                            status="failed",
                            reason=reason,
                            backend=self.backend_name,
                        )
                time.sleep(poll_s)
                continue

            if self.is_ocr_backend:
                need_check = (
                    now - self.last_target_check_at >= self.target_check_interval_s
                    or not self.target_active_cache
                )
                if need_check:
                    self.target_active_cache = self.ui.is_target_chat_active()
                    self.last_target_check_at = now
                target_active = self.target_active_cache
            else:
                target_active = self.ui.is_target_chat_active()

            if not target_active:
                if now - self.last_wait_log_at >= 8:
                    print(f"Please keep active chat on: {self.config.target_chat}")
                    self.logger.log(
                        "waiting_target_chat",
                        target_chat=self.config.target_chat,
                        backend=self.backend_name,
                    )
                    self.last_wait_log_at = now
                time.sleep(poll_s)
                continue

            messages = self.ui.fetch_visible_text_messages()
            if not self.seeded:
                self.deduper.seed(msg.fingerprint for msg in messages)
                self.seeded = True
                print(f"Warmup done. Seeded {len(messages)} visible messages.")
                self.logger.log(
                    "warmup",
                    seed_count=len(messages),
                    backend=self.backend_name,
                )
                time.sleep(poll_s)
                continue

            for msg in messages:
                if not self.deduper.add(msg.fingerprint):
                    continue

                if self.config.copy_only_incoming and msg.direction != "incoming":
                    self.logger.log(
                        "ignored",
                        reason="outgoing",
                        direction=msg.direction,
                        text=_short_text(msg.text),
                        backend=self.backend_name,
                    )
                    continue

                try:
                    copy_text(msg.text, retries=3, retry_delay_s=0.1)
                except ClipboardError as exc:
                    print(f"Copy failed: {exc}")
                    self.logger.log(
                        "error",
                        stage="copy",
                        error=str(exc),
                        backend=self.backend_name,
                    )
                else:
                    print(f"Copied: {_short_text(msg.text)}")
                    self.logger.log(
                        "copied",
                        source="filehelper",
                        direction=msg.direction,
                        text=msg.text,
                        backend=self.backend_name,
                    )
            time.sleep(poll_s)


def _config_with_overrides(config: WatcherConfig, args: argparse.Namespace) -> WatcherConfig:
    out = config
    if args.poll_ms is not None:
        out = replace(out, poll_ms=args.poll_ms)
    if args.rebind_ms is not None:
        out = replace(out, rebind_ms=args.rebind_ms)
    if args.log_file:
        out = replace(out, log_file=args.log_file)
    return out


def _resolve_log_path(config: WatcherConfig, project_root: Path) -> Path:
    log_path = Path(config.log_file)
    if not log_path.is_absolute():
        log_path = project_root / log_path
    return log_path.resolve()


def run_doctor(config: WatcherConfig, logger: JsonlLogger) -> int:
    try:
        backend, backend_name, probes = choose_backend(config)
    except Exception as exc:
        payload = {
            "window_found": False,
            "target_active": False,
            "visible_message_count": 0,
            "backend": "none",
            "error": str(exc),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        logger.log("doctor", **payload)
        return 2

    if not backend.bind_window():
        payload = {
            "window_found": False,
            "target_active": False,
            "visible_message_count": 0,
            "backend": backend_name,
            "probes": probes,
        }
    else:
        payload = backend.doctor()
        payload["backend"] = payload.get("backend", backend_name)
        payload["probes"] = probes

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    logger.log("doctor", **payload)
    return 0 if payload.get("window_found") else 1


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parent.parent
    default_config = project_root / "config" / "settings.json"
    parser = argparse.ArgumentParser(description="Listen WeChat File Transfer Assistant and copy new messages.")
    parser.add_argument("--config", default=str(default_config), help="Config file path")
    parser.add_argument("--poll-ms", type=int, help="Polling interval in milliseconds")
    parser.add_argument("--rebind-ms", type=int, help="Rebind interval in milliseconds")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--doctor", action="store_true", help="Doctor mode only")
    return parser.parse_args()


def _configure_stdio_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            continue


def main() -> int:
    _configure_stdio_utf8()
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    config = load_config(Path(args.config))
    config = _config_with_overrides(config, args)

    if config.poll_ms <= 0:
        raise ValueError("poll_ms must be > 0")
    if config.rebind_ms <= 0:
        raise ValueError("rebind_ms must be > 0")

    log_path = _resolve_log_path(config, project_root)
    logger = JsonlLogger(log_path)

    if args.doctor:
        return run_doctor(config, logger)

    try:
        listener = Listener(config, logger)
        listener.run_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        logger.log("stop", reason="keyboard_interrupt")
        return 0
    except (UIAutomationUnavailable, OCRUnavailable, DBUnavailable) as exc:
        print(str(exc))
        logger.log("stop", reason="dependency_missing", error=str(exc))
        return 2
    except Exception as exc:  # pragma: no cover - runtime safety net
        print(f"Fatal exit: {exc}")
        logger.log("stop", reason="fatal_error", error=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
