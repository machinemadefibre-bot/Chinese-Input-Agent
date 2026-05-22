#ifndef CHINESE_INPUT_AGENT_UI_TRAY_H
#define CHINESE_INPUT_AGENT_UI_TRAY_H

#include <windows.h>

#define WM_APP_TRAY (WM_APP + 40)

BOOL ui_tray_init(HWND hwnd, HINSTANCE instance);
void ui_tray_shutdown(HWND hwnd);
void ui_tray_set_pending(HWND hwnd, BOOL pending);
BOOL ui_tray_handle_message(HWND hwnd, WPARAM wparam, LPARAM lparam);
BOOL ui_tray_handle_timer(HWND hwnd, WPARAM wparam);

#endif
