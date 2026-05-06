#ifndef CHINESE_INPUT_AGENT_UI_WORK_MESSAGES_H
#define CHINESE_INPUT_AGENT_UI_WORK_MESSAGES_H

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
#include <stddef.h>

typedef struct UI_WORK_MESSAGE_HOST {
    void (*set_textbox_overlay)(void *user, HWND textbox, const WCHAR *text, BOOL show);
    void (*show_error)(void *user, HWND owner, const WCHAR *message);
    BOOL (*reload_active_crypto)(void *user, WCHAR *err, size_t err_cch);
    void (*refresh_key_combo)(void *user);
    void *user;
} UI_WORK_MESSAGE_HOST;

LRESULT ui_work_handle_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                               const UI_WORK_MESSAGE_HOST *host);

#endif
