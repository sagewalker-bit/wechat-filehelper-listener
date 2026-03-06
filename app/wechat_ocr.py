from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import re
from typing import Any, Optional

try:
    import numpy as np
except Exception:  # pragma: no cover - runtime dependency
    np = None

try:
    from PIL import Image, ImageGrab
except Exception:  # pragma: no cover - runtime dependency
    Image = None
    ImageGrab = None

from app.config import WatcherConfig
from app.wechat_ui import MessageSnapshot, Rect

try:
    from rapidocr_onnxruntime import RapidOCR
except Exception:  # pragma: no cover - runtime dependency
    RapidOCR = None


user32 = ctypes.WinDLL("user32", use_last_error=True)
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowTextW = user32.GetWindowTextW
GetClassNameW = user32.GetClassNameW
EnumWindows = user32.EnumWindows
IsWindowVisible = user32.IsWindowVisible
IsWindow = user32.IsWindow
GetWindowRect = user32.GetWindowRect
IsIconic = user32.IsIconic


class OCRUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class OCRTextBox:
    text: str
    score: float
    rect: Rect


@dataclass(frozen=True)
class OCRLine:
    text: str
    rect: Rect


class WeChatOCRAutomation:
    _TIME_PAT = re.compile(
        r"^(\d{1,2}:\d{2}|昨天\s*\d{1,2}:\d{2}|星期[一二三四五六日天]\s*\d{1,2}:\d{2}|"
        r"\d{4}[/-]\d{1,2}[/-]\d{1,2})$"
    )
    _NOISE_TEXTS = {
        "以下为新消息",
        "以上是打招呼的内容",
        "正在输入...",
        "对方正在输入...",
        "微信",
        "聊天信息",
    }

    def __init__(self, target_chat: str, config: WatcherConfig) -> None:
        if RapidOCR is None or np is None or ImageGrab is None or Image is None:
            raise OCRUnavailable(
                "OCR dependencies are missing. Run scripts/install.cmd first."
            )
        self.target_chat = target_chat
        self.hwnd: Optional[int] = None
        self.engine = RapidOCR()

        self.chat_left_offset_px = config.ocr_chat_left_offset_px
        self.chat_right_margin_px = config.ocr_chat_right_margin_px
        self.message_top_ratio = config.ocr_message_top_ratio
        self.message_bottom_ratio = config.ocr_message_bottom_ratio
        self.message_side_padding_px = config.ocr_message_side_padding_px
        self.message_left_ratio = config.ocr_message_left_ratio
        self.message_right_ratio = config.ocr_message_right_ratio
        self.header_top_ratio = config.ocr_header_top_ratio
        self.header_bottom_ratio = config.ocr_header_bottom_ratio
        self.ocr_scale = config.ocr_scale

    def is_bound(self) -> bool:
        return bool(self.hwnd and IsWindow(self.hwnd))

    def unbind(self) -> None:
        self.hwnd = None

    def bind_window(self) -> bool:
        self.hwnd = self._find_wechat_main_window()
        return bool(self.hwnd)

    def get_window_title(self) -> str:
        if not self.hwnd:
            return ""
        return _get_window_text(self.hwnd).strip()

    def is_target_chat_active(self) -> bool:
        win_rect = self._window_rect()
        if not win_rect:
            return False
        chat_left, _, chat_right, _ = self._chat_panel_bounds(win_rect)
        header_top = win_rect.top + int(win_rect.height * self.header_top_ratio)
        header_bottom = win_rect.top + int(win_rect.height * self.header_bottom_ratio)
        top_boxes = self._ocr_region_abs(
            abs_left=chat_left,
            abs_top=header_top,
            abs_right=chat_right,
            abs_bottom=header_bottom,
            min_score=0.35,
        )
        for box in top_boxes:
            if self.target_chat in box.text:
                return True
        return False

    def fetch_visible_text_messages(self) -> list[MessageSnapshot]:
        win_rect = self._window_rect()
        if not win_rect:
            return []

        chat_left, _, chat_right, _ = self._chat_panel_bounds(win_rect)
        # Use explicit left/right ratios first; fallback to chat-pane padding.
        ratio_left = win_rect.left + int(win_rect.width * self.message_left_ratio)
        ratio_right = win_rect.left + int(win_rect.width * self.message_right_ratio)
        if ratio_right - ratio_left >= 120:
            msg_left = max(chat_left + 2, ratio_left)
            msg_right = min(chat_right - 2, ratio_right)
        else:
            msg_left = chat_left + self.message_side_padding_px
            msg_right = chat_right - self.message_side_padding_px

        # Prevent over-aggressive top clipping that causes "only last line" issue.
        effective_top_ratio = min(self.message_top_ratio, 0.30)
        effective_bottom_ratio = max(self.message_bottom_ratio, 0.93)
        msg_top = win_rect.top + int(win_rect.height * effective_top_ratio)
        msg_bottom = win_rect.top + int(win_rect.height * effective_bottom_ratio)
        boxes = self._ocr_region_abs(
            abs_left=msg_left,
            abs_top=msg_top,
            abs_right=msg_right,
            abs_bottom=msg_bottom,
            min_score=0.40,
        )
        center_x = (msg_left + msg_right) / 2.0
        filtered_boxes: list[OCRTextBox] = []
        for b in boxes:
            if self._is_noise_text(b.text):
                continue
            if b.rect.width < 8 or b.rect.height < 8:
                continue
            if b.rect.left < msg_left or b.rect.right > msg_right:
                continue
            if b.rect.top < msg_top or b.rect.bottom > msg_bottom:
                continue
            filtered_boxes.append(b)

        # OCR often splits one chat bubble into many fragments.
        # Merge fragments -> lines -> message blocks, then copy full text.
        lines = self._merge_boxes_to_lines(filtered_boxes)
        merged_blocks = self._merge_lines_to_messages(lines, msg_left, msg_right, center_x)

        out: list[MessageSnapshot] = []
        for text, rect, direction in merged_blocks:
            runtime_id = self._runtime_id_from_rect_and_text(rect, text)
            fingerprint = self._fingerprint(text, direction, runtime_id, rect)
            out.append(
                MessageSnapshot(
                    text=text,
                    direction=direction,
                    runtime_id=runtime_id,
                    rect=rect,
                    fingerprint=fingerprint,
                )
            )

        out.sort(key=lambda x: (x.rect.top, x.rect.left, x.rect.bottom))
        uniq: list[MessageSnapshot] = []
        seen: set[str] = set()
        for msg in out:
            if msg.fingerprint in seen:
                continue
            uniq.append(msg)
            seen.add(msg.fingerprint)
        return uniq

    def doctor(self) -> dict[str, Any]:
        win_rect = self._window_rect()
        if not win_rect:
            return {
                "window_found": False,
                "target_active": False,
                "visible_message_count": 0,
                "backend": "ocr",
            }
        chat_left, _, chat_right, _ = self._chat_panel_bounds(win_rect)
        messages = self.fetch_visible_text_messages()
        return {
            "window_found": True,
            "window_title": self.get_window_title(),
            "window_class": _get_class_name(self.hwnd) if self.hwnd else "",
            "target_active": self.is_target_chat_active(),
            "visible_message_count": len(messages),
            "sample_texts": [m.text for m in messages[-3:]],
            "chat_panel_left": chat_left,
            "chat_panel_right": chat_right,
            "tuning": {
                "ocr_chat_left_offset_px": self.chat_left_offset_px,
                "ocr_chat_right_margin_px": self.chat_right_margin_px,
                "ocr_message_top_ratio": self.message_top_ratio,
                "ocr_message_bottom_ratio": self.message_bottom_ratio,
                "ocr_message_side_padding_px": self.message_side_padding_px,
                "ocr_message_left_ratio": self.message_left_ratio,
                "ocr_message_right_ratio": self.message_right_ratio,
                "ocr_header_top_ratio": self.header_top_ratio,
                "ocr_header_bottom_ratio": self.header_bottom_ratio,
                "ocr_scale": self.ocr_scale,
            },
            "backend": "ocr",
        }

    def _find_wechat_main_window(self) -> Optional[int]:
        hwnds: list[int] = []
        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

        @enum_proc
        def callback(hwnd: int, _: int) -> bool:
            if not IsWindowVisible(hwnd):
                return True
            title = _get_window_text(hwnd)
            cls = _get_class_name(hwnd)
            if not title:
                return True
            ltitle = title.lower()
            lcls = cls.lower()
            if (
                "微信" in title
                or "wechat" in ltitle
                or "wechat" in lcls
                or "weixin" in lcls
            ):
                hwnds.append(hwnd)
            return True

        EnumWindows(callback, 0)
        if not hwnds:
            return None

        best = None
        best_area = -1
        for hwnd in hwnds:
            rect = _get_window_rect(hwnd)
            if not rect:
                continue
            area = rect.width * rect.height
            if area > best_area:
                best = hwnd
                best_area = area
        return best

    def _window_rect(self) -> Optional[Rect]:
        if not self.hwnd:
            return None
        if not IsWindow(self.hwnd):
            return None
        if IsIconic(self.hwnd):
            return None
        return _get_window_rect(self.hwnd)

    def _ocr_region_abs(
        self,
        abs_left: int,
        abs_top: int,
        abs_right: int,
        abs_bottom: int,
        min_score: float,
    ) -> list[OCRTextBox]:
        win_rect = self._window_rect()
        if not win_rect:
            return []

        cap_left = max(win_rect.left, abs_left)
        cap_top = max(win_rect.top, abs_top)
        cap_right = min(win_rect.right, abs_right)
        cap_bottom = min(win_rect.bottom, abs_bottom)
        if cap_right <= cap_left or cap_bottom <= cap_top:
            return []

        img = ImageGrab.grab(
            bbox=(cap_left, cap_top, cap_right, cap_bottom),
            all_screens=True,
        )
        scale_x = 1.0
        scale_y = 1.0
        if self.ocr_scale < 0.999:
            src_w, src_h = img.size
            dst_w = max(1, int(src_w * self.ocr_scale))
            dst_h = max(1, int(src_h * self.ocr_scale))
            if dst_w != src_w or dst_h != src_h:
                try:
                    resample_mode = Image.Resampling.BILINEAR
                except Exception:  # pragma: no cover
                    resample_mode = Image.BILINEAR
                img = img.resize((dst_w, dst_h), resample_mode)
                scale_x = src_w / dst_w
                scale_y = src_h / dst_h
        arr = np.asarray(img)
        if arr.size == 0:
            return []

        result, _ = self.engine(arr)
        if not result:
            return []

        out: list[OCRTextBox] = []
        for item in result:
            try:
                points = item[0]
                text = self._normalize_text(item[1])
                score = float(item[2])
            except Exception:
                continue
            if not text or score < min_score:
                continue

            xs = [int(p[0]) for p in points]
            ys = [int(p[1]) for p in points]
            r = Rect(
                left=cap_left + int(min(xs) * scale_x),
                top=cap_top + int(min(ys) * scale_y),
                right=cap_left + int(max(xs) * scale_x),
                bottom=cap_top + int(max(ys) * scale_y),
            )
            out.append(OCRTextBox(text=text, score=score, rect=r))
        return out

    def _chat_panel_bounds(self, win_rect: Rect) -> tuple[int, int, int, int]:
        chat_left = win_rect.left + self.chat_left_offset_px
        chat_right = win_rect.right - self.chat_right_margin_px
        chat_top = win_rect.top
        chat_bottom = win_rect.bottom
        if chat_right <= chat_left + 40:
            chat_left = win_rect.left + int(win_rect.width * 0.35)
            chat_right = win_rect.right - 2
        return chat_left, chat_top, chat_right, chat_bottom

    def _merge_boxes_to_lines(self, boxes: list[OCRTextBox]) -> list[OCRLine]:
        if not boxes:
            return []
        boxes_sorted = sorted(boxes, key=lambda b: (b.rect.top, b.rect.left))

        lines: list[dict[str, Any]] = []
        for box in boxes_sorted:
            box_center_y = (box.rect.top + box.rect.bottom) / 2.0
            box_h = box.rect.height
            attached = False

            for line in reversed(lines[-8:]):
                line_center_y = line["center_y"]
                line_h = line["avg_h"]
                y_thresh = max(10.0, 0.6 * max(line_h, box_h))
                if abs(box_center_y - line_center_y) <= y_thresh:
                    line["boxes"].append(box)
                    count = len(line["boxes"])
                    line["center_y"] = (line["center_y"] * (count - 1) + box_center_y) / count
                    line["avg_h"] = (line["avg_h"] * (count - 1) + box_h) / count
                    line["rect"] = self._union_rect(line["rect"], box.rect)
                    attached = True
                    break

            if not attached:
                lines.append(
                    {
                        "boxes": [box],
                        "center_y": box_center_y,
                        "avg_h": float(box_h),
                        "rect": box.rect,
                    }
                )

        out: list[OCRLine] = []
        for line in lines:
            line_boxes = sorted(line["boxes"], key=lambda b: b.rect.left)
            text = self._join_text_fragments([b.text for b in line_boxes])
            if not text:
                continue
            rect = line["rect"]
            out.append(OCRLine(text=text, rect=rect))

        out.sort(key=lambda x: (x.rect.top, x.rect.left))
        return out

    def _merge_lines_to_messages(
        self,
        lines: list[OCRLine],
        msg_left: int,
        msg_right: int,
        center_x: float,
    ) -> list[tuple[str, Rect, str]]:
        if not lines:
            return []

        blocks: list[dict[str, Any]] = []
        for line in lines:
            direction = self._infer_direction(line.rect, msg_left, msg_right, center_x)

            if not blocks:
                blocks.append(
                    {
                        "direction": direction,
                        "lines": [line],
                        "rect": line.rect,
                    }
                )
                continue

            prev = blocks[-1]
            prev_rect: Rect = prev["rect"]
            prev_last_line: OCRLine = prev["lines"][-1]

            vertical_gap = line.rect.top - prev_last_line.rect.bottom
            overlap = self._horizontal_overlap_ratio(prev_rect, line.rect)
            close_left = abs(line.rect.left - prev_rect.left) <= 70
            gap_thresh = max(30, int(2.2 * max(prev_last_line.rect.height, line.rect.height)))
            center_dx = abs(line.rect.center_x - prev_rect.center_x)
            prev_tail = prev_last_line.text.rstrip()[-1:] if prev_last_line.text.rstrip() else ""

            geo_merge = (
                vertical_gap <= gap_thresh
                and (overlap >= 0.12 or close_left or center_dx <= 120)
            )
            cross_side_merge = (
                vertical_gap <= gap_thresh
                and overlap >= 0.35
                and close_left
                and prev_tail not in {"。", "！", "？", "!", "?", "…"}
            )

            if (direction == prev["direction"] and geo_merge) or (
                direction != prev["direction"] and cross_side_merge
            ):
                prev["lines"].append(line)
                prev["rect"] = self._union_rect(prev_rect, line.rect)
            else:
                blocks.append(
                    {
                        "direction": direction,
                        "lines": [line],
                        "rect": line.rect,
                    }
                )

        merged: list[tuple[str, Rect, str]] = []
        for block in blocks:
            lines_in_block: list[OCRLine] = block["lines"]
            text = "\n".join(l.text for l in lines_in_block if l.text)
            text = self._normalize_text(text)
            if not text:
                continue
            if len(text) == 1:
                # Reduce false positives from isolated OCR noise such as stray date chars.
                continue
            merged.append((text, block["rect"], block["direction"]))
        return self._soft_merge_message_blocks(merged)

    def _soft_merge_message_blocks(
        self,
        blocks: list[tuple[str, Rect, str]],
    ) -> list[tuple[str, Rect, str]]:
        if not blocks:
            return []
        out: list[tuple[str, Rect, str]] = [blocks[0]]
        for curr_text, curr_rect, curr_dir in blocks[1:]:
            prev_text, prev_rect, prev_dir = out[-1]
            if self._should_soft_merge(prev_text, prev_rect, prev_dir, curr_text, curr_rect, curr_dir):
                merged_text = self._concat_block_text(prev_text, curr_text)
                merged_rect = self._union_rect(prev_rect, curr_rect)
                out[-1] = (merged_text, merged_rect, prev_dir)
            else:
                out.append((curr_text, curr_rect, curr_dir))
        return out

    @staticmethod
    def _infer_direction(rect: Rect, msg_left: int, msg_right: int, center_x: float) -> str:
        dist_left = max(0, rect.left - msg_left)
        dist_right = max(0, msg_right - rect.right)
        if abs(dist_right - dist_left) <= 16:
            return "incoming" if rect.center_x < center_x else "outgoing"
        return "outgoing" if dist_right < dist_left else "incoming"

    def _should_soft_merge(
        self,
        prev_text: str,
        prev_rect: Rect,
        prev_dir: str,
        curr_text: str,
        curr_rect: Rect,
        curr_dir: str,
    ) -> bool:
        if prev_dir != curr_dir:
            return False
        vertical_gap = curr_rect.top - prev_rect.bottom
        if vertical_gap < -4:
            return False
        gap_thresh = max(32, int(3.0 * max(prev_rect.height, curr_rect.height)))
        if vertical_gap > gap_thresh:
            return False
        overlap = self._horizontal_overlap_ratio(prev_rect, curr_rect)
        left_diff = abs(prev_rect.left - curr_rect.left)
        if overlap < 0.08 and left_diff > 180:
            return False
        prev_last = prev_text.strip()[-1:] if prev_text.strip() else ""
        # If previous block already ends in hard punctuation, usually this is a new message.
        if prev_last in {"。", "！", "？", "!", "?", "…"}:
            return False
        return True

    @staticmethod
    def _concat_block_text(prev_text: str, curr_text: str) -> str:
        prev = prev_text.rstrip()
        curr = curr_text.lstrip()
        if not prev:
            return curr
        if not curr:
            return prev
        if prev.endswith("\n"):
            return prev + curr
        if WeChatOCRAutomation._need_space(prev[-1], curr[0]):
            return prev + " " + curr
        return prev + curr

    @staticmethod
    def _union_rect(a: Rect, b: Rect) -> Rect:
        return Rect(
            left=min(a.left, b.left),
            top=min(a.top, b.top),
            right=max(a.right, b.right),
            bottom=max(a.bottom, b.bottom),
        )

    @staticmethod
    def _horizontal_overlap_ratio(a: Rect, b: Rect) -> float:
        overlap = max(0, min(a.right, b.right) - max(a.left, b.left))
        base = max(1, min(a.width, b.width))
        return overlap / base

    @staticmethod
    def _join_text_fragments(parts: list[str]) -> str:
        if not parts:
            return ""
        out = parts[0]
        for p in parts[1:]:
            if not p:
                continue
            if out and WeChatOCRAutomation._need_space(out[-1], p[0]):
                out += " " + p
            else:
                out += p
        return out

    @staticmethod
    def _need_space(prev_char: str, next_char: str) -> bool:
        return prev_char.isascii() and next_char.isascii() and prev_char.isalnum() and next_char.isalnum()

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
        if len(text) == 1 and text in {"+", "-", "."}:
            return True
        return False

    @staticmethod
    def _runtime_id_from_rect_and_text(rect: Rect, text: str) -> str:
        payload = f"{rect.left},{rect.top},{rect.right},{rect.bottom}|{text}"
        return hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]

    @staticmethod
    def _fingerprint(text: str, direction: str, runtime_id: str, rect: Rect) -> str:
        payload = (
            f"{runtime_id}|{direction}|"
            f"{rect.left},{rect.top},{rect.right},{rect.bottom}|{text}"
        )
        return hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()


def _get_window_text(hwnd: int) -> str:
    length = GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def _get_class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, buf, 256)
    return buf.value


def _get_window_rect(hwnd: int) -> Optional[Rect]:
    rc = wintypes.RECT()
    if not GetWindowRect(hwnd, ctypes.byref(rc)):
        return None
    rect = Rect(left=int(rc.left), top=int(rc.top), right=int(rc.right), bottom=int(rc.bottom))
    if rect.width <= 0 or rect.height <= 0:
        return None
    return rect
