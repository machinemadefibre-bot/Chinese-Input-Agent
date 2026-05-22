#ifndef CHINESE_INPUT_AGENT_APP_CLIPBOARD_MONITOR_H
#define CHINESE_INPUT_AGENT_APP_CLIPBOARD_MONITOR_H

#include <windows.h>

#define WM_APP_CLIPBOARD_PROBE_DONE (WM_APP + 30)

BOOL app_clipboard_monitor_start(HWND owner);
void app_clipboard_monitor_stop(HWND owner);
void app_clipboard_monitor_handle_update(HWND owner);
BOOL app_clipboard_monitor_complete_probe(LPARAM lparam);
BOOL app_clipboard_monitor_has_pending(void);
WCHAR *app_clipboard_monitor_take_pending_text(void);
void app_clipboard_monitor_ignore_pending(void);
void app_clipboard_monitor_mark_last_opened_done(void);
void app_clipboard_monitor_mark_last_opened_failed(void);

#endif
