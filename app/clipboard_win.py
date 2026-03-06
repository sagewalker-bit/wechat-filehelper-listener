from __future__ import annotations

import ctypes
from ctypes import wintypes
import time


CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.OpenClipboard.restype = wintypes.BOOL
user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = wintypes.BOOL
user32.EmptyClipboard.argtypes = []
user32.EmptyClipboard.restype = wintypes.BOOL
user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
user32.SetClipboardData.restype = wintypes.HANDLE

kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalLock.restype = wintypes.LPVOID
kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalUnlock.restype = wintypes.BOOL
kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalFree.restype = wintypes.HGLOBAL


class ClipboardError(RuntimeError):
    pass


def _win_error(message: str) -> ClipboardError:
    return ClipboardError(f"{message}, code={ctypes.get_last_error()}")


def copy_text(text: str, retries: int = 3, retry_delay_s: float = 0.10) -> None:
    if text is None:
        raise ClipboardError("text 不能为空")

    payload = (text + "\x00").encode("utf-16-le")

    for _ in range(retries):
        if not user32.OpenClipboard(None):
            time.sleep(retry_delay_s)
            continue

        try:
            if not user32.EmptyClipboard():
                raise _win_error("EmptyClipboard 失败")

            h_global = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(payload))
            if not h_global:
                raise _win_error("GlobalAlloc 失败")

            locked = kernel32.GlobalLock(h_global)
            if not locked:
                kernel32.GlobalFree(h_global)
                raise _win_error("GlobalLock 失败")

            try:
                ctypes.memmove(locked, payload, len(payload))
            finally:
                kernel32.GlobalUnlock(h_global)

            if not user32.SetClipboardData(CF_UNICODETEXT, h_global):
                kernel32.GlobalFree(h_global)
                raise _win_error("SetClipboardData 失败")
            return
        finally:
            user32.CloseClipboard()

    raise ClipboardError("打开剪贴板失败，可能被其他程序占用")

