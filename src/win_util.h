#ifndef CHINESE_INPUT_AGENT_WIN_UTIL_H
#define CHINESE_INPUT_AGENT_WIN_UTIL_H

#include <windows.h>
#include <stddef.h>

WCHAR *win_dup_wide(const WCHAR *text);
WCHAR *win_get_window_text_alloc(HWND hwnd);
BOOL win_get_clipboard_text(HWND owner, WCHAR **out);
void win_show_error(HWND owner, const WCHAR *title, const WCHAR *message);
void win_set_control_font(HWND hwnd, HFONT font);

#endif
