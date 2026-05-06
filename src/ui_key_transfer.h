#ifndef CHINESE_INPUT_AGENT_UI_KEY_TRANSFER_H
#define CHINESE_INPUT_AGENT_UI_KEY_TRANSFER_H

#include <windows.h>

typedef struct UI_KEY_TRANSFER_HOST {
    HINSTANCE instance;
    HFONT ui_font;
    void (*show_error)(void *user, HWND owner, const WCHAR *message);
    void (*on_name_prompt_close_requested)(void *user);
    /* Copied by ui_key_transfer_show; user must remain valid while the key-transfer window is open. */
    void *user;
} UI_KEY_TRANSFER_HOST;

BOOL ui_key_transfer_register_class(HINSTANCE instance);
/* Copies host into module state; host->user is retained for later window and prompt callbacks. */
void ui_key_transfer_show(HWND owner, const UI_KEY_TRANSFER_HOST *host);
void ui_key_transfer_set_busy(BOOL busy);
HWND ui_key_transfer_overlay_for_textbox(HWND textbox);
BOOL ui_key_transfer_translate_message(MSG *msg);

#endif
