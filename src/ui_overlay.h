#ifndef CHINESE_INPUT_AGENT_UI_OVERLAY_H
#define CHINESE_INPUT_AGENT_UI_OVERLAY_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "app_constants.h"

#define UI_OVERLAY_CLASS_NAME APP_OVERLAY_WINDOW_CLASS_NAME

BOOL ui_overlay_register_class(HINSTANCE instance);
HWND ui_overlay_create(HWND parent, HINSTANCE instance, int control_id);
void ui_overlay_layout(HWND overlay, HWND textbox);
void ui_overlay_set_text(HWND overlay, const WCHAR *text, BOOL show);

#endif
