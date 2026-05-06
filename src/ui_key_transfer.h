#ifndef CHINESE_INPUT_AGENT_UI_KEY_TRANSFER_H
#define CHINESE_INPUT_AGENT_UI_KEY_TRANSFER_H

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

typedef struct UI_KEY_TRANSFER_HOST {
    HINSTANCE instance;
    HFONT ui_font;
    void (*show_error)(void *user, HWND owner, const WCHAR *message);
    void (*on_name_prompt_close)(void *user);
    void *user;
} UI_KEY_TRANSFER_HOST;

BOOL ui_key_transfer_register_class(HINSTANCE instance);
void ui_key_transfer_show(HWND owner, const UI_KEY_TRANSFER_HOST *host);
void ui_key_transfer_set_busy(BOOL busy);
HWND ui_key_transfer_overlay_for_textbox(HWND textbox);
BOOL ui_key_transfer_translate_message(MSG *msg);

#endif
