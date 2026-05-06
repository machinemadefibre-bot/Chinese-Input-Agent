#ifndef CHINESE_INPUT_AGENT_UI_WORK_MESSAGES_H
#define CHINESE_INPUT_AGENT_UI_WORK_MESSAGES_H

#include <windows.h>
#include <stddef.h>

typedef struct UI_WORK_MESSAGE_HOST {
    void (*set_textbox_overlay)(void *user, HWND textbox, const WCHAR *text, BOOL show);
    void (*clear_textbox_overlay_later)(void *user, HWND textbox);
    void (*show_error)(void *user, HWND owner, const WCHAR *message);
    /* Import-key completion changes app session state; keep those side effects explicit at the boundary. */
    BOOL (*reload_crypto_after_key_import)(void *user, WCHAR *err, size_t err_cch);
    void (*refresh_key_list_after_key_import)(void *user);
    BOOL (*save_decrypted_plaintext)(void *user, int profile_index, const WCHAR *plain,
                                     WCHAR *err, size_t err_cch);
    void *user;
} UI_WORK_MESSAGE_HOST;

LRESULT ui_work_handle_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                               const UI_WORK_MESSAGE_HOST *host);

#endif
