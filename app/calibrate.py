from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
from typing import Optional

from app.config import WatcherConfig, load_config

try:
    import tkinter as tk
    from tkinter import messagebox
except Exception:  # pragma: no cover - runtime dependency
    tk = None
    messagebox = None

try:
    from PIL import ImageGrab, ImageTk
except Exception:  # pragma: no cover - runtime dependency
    ImageGrab = None
    ImageTk = None


user32 = ctypes.WinDLL("user32", use_last_error=True)
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowTextW = user32.GetWindowTextW
GetClassNameW = user32.GetClassNameW
EnumWindows = user32.EnumWindows
IsWindowVisible = user32.IsWindowVisible
IsWindow = user32.IsWindow
GetWindowRect = user32.GetWindowRect
IsIconic = user32.IsIconic


def _window_text(hwnd: int) -> str:
    length = GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def _window_class(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, buf, 256)
    return buf.value


def _window_rect(hwnd: int) -> Optional[tuple[int, int, int, int]]:
    rc = wintypes.RECT()
    if not GetWindowRect(hwnd, ctypes.byref(rc)):
        return None
    left, top, right, bottom = int(rc.left), int(rc.top), int(rc.right), int(rc.bottom)
    if right <= left or bottom <= top:
        return None
    return left, top, right, bottom


def _find_wechat_window() -> Optional[int]:
    hwnds: list[int] = []
    enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    @enum_proc
    def callback(hwnd: int, _: int) -> bool:
        if not IsWindowVisible(hwnd):
            return True
        title = _window_text(hwnd)
        cls = _window_class(hwnd)
        if not title:
            return True
        ltitle = title.lower()
        lcls = cls.lower()
        if "微信" in title or "wechat" in ltitle or "wechat" in lcls or "weixin" in lcls:
            hwnds.append(hwnd)
        return True

    EnumWindows(callback, 0)
    if not hwnds:
        return None

    best_hwnd = None
    best_area = -1
    for hwnd in hwnds:
        rect = _window_rect(hwnd)
        if not rect:
            continue
        left, top, right, bottom = rect
        area = (right - left) * (bottom - top)
        if area > best_area:
            best_area = area
            best_hwnd = hwnd
    return best_hwnd


def _clip_rect(rect: tuple[int, int, int, int], w: int, h: int) -> tuple[int, int, int, int]:
    x1, y1, x2, y2 = rect
    x1 = max(0, min(w - 1, x1))
    y1 = max(0, min(h - 1, y1))
    x2 = max(1, min(w, x2))
    y2 = max(1, min(h, y2))
    if x2 <= x1:
        x2 = min(w, x1 + 1)
    if y2 <= y1:
        y2 = min(h, y1 + 1)
    return x1, y1, x2, y2


def _normalize_rect(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int, int, int]:
    x1, y1 = a
    x2, y2 = b
    return min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)


def _clip_to_bounds(
    rect: tuple[int, int, int, int],
    bounds: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, x2, y2 = rect
    bx1, by1, bx2, by2 = bounds
    x1 = max(bx1, min(bx2 - 1, x1))
    y1 = max(by1, min(by2 - 1, y1))
    x2 = max(bx1 + 1, min(bx2, x2))
    y2 = max(by1 + 1, min(by2, y2))
    if x2 <= x1:
        x2 = min(bx2, x1 + 1)
    if y2 <= y1:
        y2 = min(by2, y1 + 1)
    return x1, y1, x2, y2


class CalibrationUI:
    def __init__(
        self,
        root: "tk.Tk",
        image,
        initial_chat_rect: tuple[int, int, int, int],
        initial_msg_rect: tuple[int, int, int, int],
    ) -> None:
        self.root = root
        self.original_image = image
        self.img_w, self.img_h = image.size

        screen_w = max(100, root.winfo_screenwidth() - 120)
        screen_h = max(100, root.winfo_screenheight() - 180)
        self.scale = min(1.0, screen_w / self.img_w, screen_h / self.img_h)
        if self.scale < 1.0:
            show_w = max(1, int(self.img_w * self.scale))
            show_h = max(1, int(self.img_h * self.scale))
            self.show_image = image.resize((show_w, show_h))
        else:
            show_w = self.img_w
            show_h = self.img_h
            self.show_image = image

        self.tk_image = ImageTk.PhotoImage(self.show_image)
        self.canvas = tk.Canvas(root, width=show_w, height=show_h, cursor="crosshair", highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.tk_image)

        self.info_var = tk.StringVar()
        self.info_label = tk.Label(root, textvariable=self.info_var, anchor="w", justify="left")
        self.info_label.pack(fill=tk.X, padx=8, pady=6)

        self.step = 1
        self.cancelled = False
        self.done = False
        self.drag_start: Optional[tuple[int, int]] = None
        self.drag_now: Optional[tuple[int, int]] = None

        self.chat_rect = _clip_rect(initial_chat_rect, self.img_w, self.img_h)
        self.msg_rect = _clip_to_bounds(
            _clip_rect(initial_msg_rect, self.img_w, self.img_h),
            self.chat_rect,
        )

        self.canvas.bind("<ButtonPress-1>", self._on_mouse_down)
        self.canvas.bind("<B1-Motion>", self._on_mouse_move)
        self.canvas.bind("<ButtonRelease-1>", self._on_mouse_up)
        self.root.bind("<Return>", self._on_enter)
        self.root.bind("<Escape>", self._on_escape)
        self.root.bind("<Key-r>", self._on_reset)
        self.root.bind("<Key-R>", self._on_reset)

        self._refresh()

    def _to_img(self, event_x: int, event_y: int) -> tuple[int, int]:
        x = int(event_x / self.scale)
        y = int(event_y / self.scale)
        return max(0, min(self.img_w - 1, x)), max(0, min(self.img_h - 1, y))

    def _to_canvas_rect(self, rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        x1, y1, x2, y2 = rect
        return (
            int(x1 * self.scale),
            int(y1 * self.scale),
            int(x2 * self.scale),
            int(y2 * self.scale),
        )

    def _on_mouse_down(self, event) -> None:
        self.drag_start = self._to_img(event.x, event.y)
        self.drag_now = self.drag_start
        self._refresh()

    def _on_mouse_move(self, event) -> None:
        if self.drag_start is None:
            return
        self.drag_now = self._to_img(event.x, event.y)
        self._refresh()

    def _on_mouse_up(self, event) -> None:
        if self.drag_start is None:
            return
        self.drag_now = self._to_img(event.x, event.y)
        rect = _normalize_rect(self.drag_start, self.drag_now)
        rect = _clip_rect(rect, self.img_w, self.img_h)
        if self.step == 2:
            rect = _clip_to_bounds(rect, self.chat_rect)
        if rect[2] - rect[0] >= 20 and rect[3] - rect[1] >= 20:
            if self.step == 1:
                self.chat_rect = rect
                self.msg_rect = _clip_to_bounds(self.msg_rect, self.chat_rect)
            else:
                self.msg_rect = rect
        self.drag_start = None
        self.drag_now = None
        self._refresh()

    def _on_enter(self, _event) -> None:
        if self.step == 1:
            self.step = 2
            self._refresh()
            return
        self.done = True
        self.root.destroy()

    def _on_escape(self, _event) -> None:
        self.cancelled = True
        self.root.destroy()

    def _on_reset(self, _event) -> None:
        if self.step == 2:
            self.msg_rect = _clip_to_bounds(
                (
                    self.chat_rect[0] + 10,
                    self.chat_rect[1] + int(self.img_h * 0.52),
                    self.chat_rect[2] - 10,
                    self.chat_rect[1] + int(self.img_h * 0.86),
                ),
                self.chat_rect,
            )
        self.drag_start = None
        self.drag_now = None
        self._refresh()

    def _refresh(self) -> None:
        self.canvas.delete("overlay")

        # Draw step rectangles
        if self.step == 1:
            rect = self.chat_rect
            color = "#33c1ff"
            self.info_var.set(
                "Step 1/2: Drag to select RIGHT chat pane only (exclude left contacts). "
                "Press Enter to continue."
            )
        else:
            # show chat rect fixed
            cx1, cy1, cx2, cy2 = self._to_canvas_rect(self.chat_rect)
            self.canvas.create_rectangle(
                cx1, cy1, cx2, cy2, outline="#33c1ff", width=2, tags="overlay"
            )
            rect = self.msg_rect
            color = "#2ecc71"
            self.info_var.set(
                "Step 2/2: Drag to select MESSAGE area in chat pane (usually lower area). "
                "Press Enter to save."
            )

        rx1, ry1, rx2, ry2 = self._to_canvas_rect(rect)
        self.canvas.create_rectangle(rx1, ry1, rx2, ry2, outline=color, width=2, tags="overlay")

        if self.drag_start and self.drag_now:
            drag_rect = _normalize_rect(self.drag_start, self.drag_now)
            if self.step == 2:
                drag_rect = _clip_to_bounds(drag_rect, self.chat_rect)
            dx1, dy1, dx2, dy2 = self._to_canvas_rect(drag_rect)
            self.canvas.create_rectangle(
                dx1, dy1, dx2, dy2, outline="#ffcc00", width=2, dash=(5, 3), tags="overlay"
            )

    def get_result(self) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
        return self.chat_rect, self.msg_rect


def _load_raw_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Config JSON root must be object")
    return data


def _save_raw_json(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def run_calibration(config_path: Path) -> int:
    if tk is None or ImageGrab is None or ImageTk is None:
        print("GUI dependencies missing. Please ensure tkinter and Pillow are available.")
        return 2

    cfg: WatcherConfig = load_config(config_path)
    data = _load_raw_json(config_path)

    hwnd = _find_wechat_window()
    if hwnd is None or not IsWindow(hwnd):
        print("WeChat window not found. Open WeChat first.")
        return 1
    if IsIconic(hwnd):
        print("WeChat is minimized. Restore the window and try again.")
        return 1

    rect = _window_rect(hwnd)
    if not rect:
        print("Cannot read WeChat window bounds.")
        return 1
    left, top, right, bottom = rect
    width = right - left
    height = bottom - top

    screenshot = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)

    init_chat = (
        cfg.ocr_chat_left_offset_px,
        0,
        width - cfg.ocr_chat_right_margin_px,
        height,
    )
    init_chat = _clip_rect(init_chat, width, height)

    init_msg = (
        int(width * cfg.ocr_message_left_ratio),
        int(height * cfg.ocr_message_top_ratio),
        int(width * cfg.ocr_message_right_ratio),
        int(height * cfg.ocr_message_bottom_ratio),
    )
    init_msg = _clip_to_bounds(_clip_rect(init_msg, width, height), init_chat)

    root = tk.Tk()
    root.title("WeChat OCR Calibration")
    ui = CalibrationUI(root, screenshot, init_chat, init_msg)
    root.mainloop()

    if ui.cancelled or not ui.done:
        print("Calibration cancelled.")
        return 1

    chat_rect, msg_rect = ui.get_result()
    chat_left = chat_rect[0]
    chat_right_margin = max(0, width - chat_rect[2])
    msg_top_ratio = max(0.0, min(1.0, msg_rect[1] / float(height)))
    msg_bottom_ratio = max(0.0, min(1.0, msg_rect[3] / float(height)))
    if msg_bottom_ratio <= msg_top_ratio:
        msg_bottom_ratio = min(0.99, msg_top_ratio + 0.01)

    left_pad = max(0, msg_rect[0] - chat_rect[0])
    right_pad = max(0, chat_rect[2] - msg_rect[2])
    side_padding = max(0, int(round((left_pad + right_pad) / 2)))

    data["ocr_chat_left_offset_px"] = int(chat_left)
    data["ocr_chat_right_margin_px"] = int(chat_right_margin)
    # Keep a practical vertical range so long multi-line bubbles are not clipped.
    data["ocr_message_top_ratio"] = round(float(min(msg_top_ratio, 0.35)), 4)
    data["ocr_message_bottom_ratio"] = round(float(max(msg_bottom_ratio, 0.90)), 4)
    data["ocr_message_side_padding_px"] = int(side_padding)
    data["ocr_message_left_ratio"] = round(float(msg_rect[0] / float(width)), 4)
    data["ocr_message_right_ratio"] = round(float(msg_rect[2] / float(width)), 4)
    _save_raw_json(config_path, data)

    print("Calibration saved:")
    print(f"  ocr_chat_left_offset_px = {data['ocr_chat_left_offset_px']}")
    print(f"  ocr_chat_right_margin_px = {data['ocr_chat_right_margin_px']}")
    print(f"  ocr_message_top_ratio = {data['ocr_message_top_ratio']}")
    print(f"  ocr_message_bottom_ratio = {data['ocr_message_bottom_ratio']}")
    print(f"  ocr_message_side_padding_px = {data['ocr_message_side_padding_px']}")
    print(f"  ocr_message_left_ratio = {data['ocr_message_left_ratio']}")
    print(f"  ocr_message_right_ratio = {data['ocr_message_right_ratio']}")
    print("")
    print("Next:")
    print("  1) .\\scripts\\doctor.cmd")
    print("  2) .\\scripts\\run.cmd")
    return 0


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parent.parent
    default_config = project_root / "config" / "settings.json"
    parser = argparse.ArgumentParser(description="Interactive OCR region calibration for WeChat.")
    parser.add_argument("--config", default=str(default_config), help="Config file path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_calibration(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
