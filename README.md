# 微信文件传输助手监听器（Windows）

这个工具会持续监听微信 PC 端「文件传输助手」会话，收到新文本时自动复制到剪贴板。

## 最简单用法（推荐）

1. 首次安装：

```powershell
.\scripts\install.cmd
```

2. 打开可视化校准（会弹窗，可鼠标框选）：

```powershell
.\scripts\calibrate.cmd
```

3. 校准后检查状态：

```powershell
.\scripts\doctor.cmd
```

4. 正式开始监听：

```powershell
.\scripts\run.cmd
```

## 可视化校准怎么操作

运行 `.\scripts\calibrate.cmd` 后会弹出微信截图窗口：

- 第 1 步：用鼠标拖框，选中右侧聊天面板（排除左侧联系人列表）
- 按 `Enter` 进入第 2 步
- 第 2 步：用鼠标拖框，选中消息识别区域（建议选右侧中下部）
- 再按 `Enter` 保存
- 按 `Esc` 可取消

保存后会自动写入 `config\settings.json`，你不用手改数字。

## 运行前条件

- 微信已登录
- 当前聊天切到「文件传输助手」
- 微信窗口保持可见

## 配置文件（如需手动微调）

文件：`config\settings.json`

```json
{
  "target_chat": "文件传输助手",
  "poll_ms": 180,
  "rebind_ms": 5000,
  "copy_only_incoming": true,
  "text_only": true,
  "log_file": ".\\runtime\\logs\\listener.log",

  "ocr_chat_left_offset_px": 220,
  "ocr_chat_right_margin_px": 8,
  "ocr_message_top_ratio": 0.52,
  "ocr_message_bottom_ratio": 0.86,
  "ocr_message_side_padding_px": 10,
  "ocr_header_top_ratio": 0.00,
  "ocr_header_bottom_ratio": 0.24,
  "ocr_target_check_interval_ms": 3000,
  "ocr_scale": 0.65
}
```

## 关键参数说明

- `ocr_chat_left_offset_px`：右侧聊天区左边界（像素）
- `ocr_message_top_ratio`：识别区域上边界（越大越快）
- `ocr_scale`：OCR 缩放（越小越快，越大越清晰）

## 打包给其他电脑

```powershell
.\scripts\package.cmd
```

会在 `dist\` 目录生成 zip。


## DB backend (default now)

This project now prefers local database mode (`backend_mode = "db"`).

- Scope is hard-limited to `filehelper` (文件传输助手) only.
- It does **not** OCR the chat window in DB mode.
- First run requires WeChat process to be running, so key material can be resolved.
- If doctor says `WeChat process not found`, open WeChat and retry.
- If doctor says `Access denied`, run PowerShell as Administrator once, then retry.

You can switch back via config:

```json
{
  "backend_mode": "ocr"
}
```
