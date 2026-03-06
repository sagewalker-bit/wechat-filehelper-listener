from __future__ import annotations

from dataclasses import dataclass
from collections import deque
import hashlib
import re
from typing import Any, Optional


try:
    import uiautomation as auto
except Exception:  # pragma: no cover - runtime dependency
    auto = None


@dataclass(frozen=True)
class Rect:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        return max(0, self.bottom - self.top)

    @property
    def center_x(self) -> float:
        return (self.left + self.right) / 2.0


@dataclass(frozen=True)
class MessageSnapshot:
    text: str
    direction: str
    runtime_id: str
    rect: Rect
    fingerprint: str


class UIAutomationUnavailable(RuntimeError):
    pass


class WeChatUIAutomation:
    _NOISE_TEXTS = {
        "以下为新消息",
        "以上是打招呼的内容",
        "正在输入...",
        "对方正在输入...",
    }
    _TIME_PAT = re.compile(
        r"^(\d{1,2}:\d{2}|昨天\s*\d{1,2}:\d{2}|星期[一二三四五六日天]\s*\d{1,2}:\d{2}|"
        r"\d{4}[/-]\d{1,2}[/-]\d{1,2})$"
    )

    def __init__(self, target_chat: str) -> None:
        if auto is None:
            raise UIAutomationUnavailable(
                "缺少 uiautomation 依赖，请先运行 scripts/install.ps1 安装。"
            )
        self.target_chat = target_chat
        self.window: Any = None

    def is_bound(self) -> bool:
        if self.window is None:
            return False
        return self._control_rect(self.window) is not None

    def unbind(self) -> None:
        self.window = None

    def bind_window(self) -> bool:
        self.window = self._find_wechat_window()
        if self.window is None:
            return False
        try:
            self.window.SetActive()
        except Exception:
            pass
        return True

    def get_window_title(self) -> str:
        if not self.window:
            return ""
        return str(self._safe_get(self.window, "Name", default="")).strip()

    def is_target_chat_active(self) -> bool:
        if not self.window:
            return False

        title = self.get_window_title()
        if self.target_chat in title:
            return True

        win_rect = self._control_rect(self.window)
        if not win_rect:
            return False

        top_band_bottom = win_rect.top + 130
        target = self.target_chat

        for ctrl in self._walk_controls(self.window, max_nodes=800, max_depth=6):
            if not self._is_text_control(ctrl):
                continue
            text = self._normalize_text(self._safe_get(ctrl, "Name", default=""))
            if not text or target not in text:
                continue
            rect = self._control_rect(ctrl)
            if not rect:
                continue
            if (
                rect.top >= win_rect.top
                and rect.bottom <= top_band_bottom
                and rect.center_x > (win_rect.left + win_rect.width * 0.22)
            ):
                return True
        return False

    def fetch_visible_text_messages(self) -> list[MessageSnapshot]:
        if not self.window:
            return []

        win_rect = self._control_rect(self.window)
        if not win_rect:
            return []

        input_top = self._infer_input_top(win_rect)
        center_x = (win_rect.left + win_rect.right) / 2.0
        left_content_limit = win_rect.left + int(win_rect.width * 0.22)
        right_content_limit = win_rect.right - 8
        top_limit = win_rect.top + 56
        bottom_limit = input_top - 3

        snapshots: list[MessageSnapshot] = []
        for ctrl in self._walk_controls(self.window, max_nodes=2600, max_depth=13):
            if not self._is_text_control(ctrl):
                continue
            text = self._normalize_text(self._safe_get(ctrl, "Name", default=""))
            if not text or self._is_noise_text(text):
                continue

            rect = self._control_rect(ctrl)
            if not rect:
                continue
            if rect.width < 8 or rect.height < 8:
                continue
            if rect.left < left_content_limit or rect.right > right_content_limit:
                continue
            if rect.top < top_limit or rect.bottom > bottom_limit:
                continue

            direction = "incoming" if rect.center_x < center_x else "outgoing"
            runtime_id = self._runtime_id(ctrl)
            fingerprint = self._fingerprint(text, direction, runtime_id, rect)
            snapshots.append(
                MessageSnapshot(
                    text=text,
                    direction=direction,
                    runtime_id=runtime_id,
                    rect=rect,
                    fingerprint=fingerprint,
                )
            )

        snapshots.sort(key=lambda x: (x.rect.top, x.rect.left, x.rect.bottom))
        deduped: list[MessageSnapshot] = []
        seen: set[str] = set()
        for msg in snapshots:
            if msg.fingerprint in seen:
                continue
            deduped.append(msg)
            seen.add(msg.fingerprint)
        return deduped

    def doctor(self) -> dict[str, Any]:
        if not self.window:
            return {
                "window_found": False,
                "target_active": False,
                "visible_message_count": 0,
                "accessible_node_count": 0,
                "backend": "uia",
            }

        node_count = len(self._walk_controls(self.window, max_nodes=3000, max_depth=12))
        messages = self.fetch_visible_text_messages()
        return {
            "window_found": True,
            "window_title": self.get_window_title(),
            "window_class": str(self._safe_get(self.window, "ClassName", default="")),
            "target_active": self.is_target_chat_active(),
            "visible_message_count": len(messages),
            "sample_texts": [m.text for m in messages[-3:]],
            "accessible_node_count": node_count,
            "backend": "uia",
        }

    def _find_wechat_window(self) -> Any:
        root = auto.GetRootControl()
        best_score = -1
        best_window = None

        # Some WeChat builds expose the main window with small bounds temporarily.
        # Use soft size scoring instead of hard filtering.
        for ctrl in self._walk_controls(root, max_nodes=1200, max_depth=2):
            ctrl_type = self._safe_get(ctrl, "ControlTypeName", default="")
            if str(ctrl_type) != "WindowControl":
                continue

            rect = self._control_rect(ctrl)
            name = str(self._safe_get(ctrl, "Name", default=""))
            class_name = str(self._safe_get(ctrl, "ClassName", default=""))
            score = 0
            lname = name.lower()
            lclass = class_name.lower()

            if "wechat" in lclass or "xwechat" in lclass:
                score += 5
            if "微信" in name:
                score += 4
            if "wechat" in lname:
                score += 3
            if rect and rect.width >= 450 and rect.height >= 350:
                score += 2
            elif rect:
                score += 1

            if score > best_score:
                best_score = score
                best_window = ctrl

        return best_window if best_score >= 3 else None

    def _infer_input_top(self, win_rect: Rect) -> int:
        default_top = win_rect.bottom - int(win_rect.height * 0.22)
        candidates: list[int] = []
        for ctrl in self._walk_controls(self.window, max_nodes=1600, max_depth=11):
            if not self._is_edit_control(ctrl):
                continue
            rect = self._control_rect(ctrl)
            if not rect:
                continue
            if rect.width < int(win_rect.width * 0.20):
                continue
            if rect.top <= (win_rect.top + int(win_rect.height * 0.50)):
                continue
            candidates.append(rect.top)
        return min(candidates) if candidates else default_top

    @staticmethod
    def _safe_get(ctrl: Any, attr: str, default: Any = None) -> Any:
        try:
            return getattr(ctrl, attr)
        except Exception:
            return default

    @staticmethod
    def _normalize_text(text: str) -> str:
        text = str(text).replace("\r", "\n")
        text = "\n".join(line.rstrip() for line in text.split("\n"))
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _is_noise_text(self, text: str) -> bool:
        if not text:
            return True
        if text in self._NOISE_TEXTS:
            return True
        if self._TIME_PAT.match(text):
            return True
        return False

    @staticmethod
    def _is_text_control(ctrl: Any) -> bool:
        try:
            return ctrl.ControlTypeName == "TextControl"
        except Exception:
            return False

    @staticmethod
    def _is_edit_control(ctrl: Any) -> bool:
        try:
            return ctrl.ControlTypeName == "EditControl"
        except Exception:
            return False

    @staticmethod
    def _control_rect(ctrl: Any) -> Optional[Rect]:
        try:
            r = ctrl.BoundingRectangle
            rect = Rect(int(r.left), int(r.top), int(r.right), int(r.bottom))
            if rect.width <= 0 or rect.height <= 0:
                return None
            return rect
        except Exception:
            return None

    def _runtime_id(self, ctrl: Any) -> str:
        try:
            if hasattr(ctrl, "GetRuntimeId"):
                rid = ctrl.GetRuntimeId()
                if rid:
                    return ",".join(str(x) for x in rid)
        except Exception:
            pass
        raw = (
            f"{self._safe_get(ctrl, 'AutomationId', '')}|"
            f"{self._safe_get(ctrl, 'ClassName', '')}|"
            f"{self._safe_get(ctrl, 'Name', '')}"
        )
        return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    @staticmethod
    def _fingerprint(text: str, direction: str, runtime_id: str, rect: Rect) -> str:
        payload = (
            f"{runtime_id}|{direction}|"
            f"{rect.left},{rect.top},{rect.right},{rect.bottom}|{text}"
        )
        return hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def _walk_controls(root: Any, max_nodes: int, max_depth: int) -> list[Any]:
        queue: deque[tuple[Any, int]] = deque([(root, 0)])
        out: list[Any] = []
        while queue and len(out) < max_nodes:
            ctrl, depth = queue.popleft()
            out.append(ctrl)
            if depth >= max_depth:
                continue
            try:
                children = ctrl.GetChildren()
            except Exception:
                children = []
            for child in children:
                queue.append((child, depth + 1))
        return out
