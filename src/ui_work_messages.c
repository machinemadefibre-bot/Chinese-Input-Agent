#include "ui_work_messages.h"
#include "app_shared.h"
#include "app_work.h"
#include "ui_strings.h"

static void host_set_overlay(const UI_WORK_MESSAGE_HOST *host, HWND textbox, const WCHAR *text, BOOL show) {
    if (host && host->set_textbox_overlay) host->set_textbox_overlay(host->user, textbox, text, show);
}

static void host_clear_overlay_later(const UI_WORK_MESSAGE_HOST *host, HWND textbox) {
    if (host && host->clear_textbox_overlay_later) host->clear_textbox_overlay_later(host->user, textbox);
}

static void host_show_error(const UI_WORK_MESSAGE_HOST *host, HWND owner, const WCHAR *message) {
    if (host && host->show_error) host->show_error(host->user, owner, message);
}

static WCHAR *build_group_display_text(const APP_WORK_MESSAGE *message) {
    if (!message || message->kind != APP_WORK_KIND_DECRYPT || message->group_index < 0 ||
        !message->sender || !message->sender[0]) {
        return NULL;
    }
    WSTRB builder = {0};
    if (!wstrb_append(&builder, message->sender) ||
        !wstrb_append(&builder, L"\r\n") ||
        !wstrb_append(&builder, message->text ? message->text : L"")) {
        wstrb_secure_free(&builder);
        return NULL;
    }
    WCHAR *display_text = builder.data;
    builder.data = NULL;
    return display_text;
}

LRESULT ui_work_handle_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                               const UI_WORK_MESSAGE_HOST *host) {
    (void)wparam;
    /* lparam owns an APP_WORK_MESSAGE allocated by app_work; this handler consumes and frees it. */
    APP_WORK_MESSAGE *message = (APP_WORK_MESSAGE *)lparam;
    if (message) {
        if (msg == WM_APP_WORK_ERROR) {
            if (message->target_textbox && IsWindow(message->target_textbox)) {
                SetWindowTextW(message->target_textbox, L"");
                host_set_overlay(host, message->target_textbox, UI_TEXT_WORK_FAILED_UNFINISHED, TRUE);
                host_clear_overlay_later(host, message->target_textbox);
            }
            host_show_error(host, hwnd, message->text ? message->text : UI_TEXT_BACKGROUND_WORK_FAILED);
        } else if (msg == WM_APP_WORK_CANCELLED) {
            if (message->target_textbox && IsWindow(message->target_textbox)) {
                SetWindowTextW(message->target_textbox, L"");
                host_set_overlay(host, message->target_textbox, NULL, FALSE);
            }
        } else if (message->target_textbox && IsWindow(message->target_textbox)) {
            if (msg == WM_APP_WORK_UPDATE) {
                SetWindowTextW(message->target_textbox, L"");
                host_set_overlay(host, message->target_textbox, message->text ? message->text : L"", TRUE);
            } else if (msg == WM_APP_WORK_DONE) {
                host_set_overlay(host, message->target_textbox, NULL, FALSE);
                if (message->kind == APP_WORK_KIND_GROUP_ENCRYPT && message->sent_plaintext &&
                    host && host->save_sent_group_plaintext) {
                    WCHAR err[256] = L"";
                    if (!host->save_sent_group_plaintext(host->user, message->sent_group_index,
                                                         message->sent_sender, message->sent_plaintext,
                                                         err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
                    }
                } else if (message->kind == APP_WORK_KIND_ENCRYPT && message->sent_plaintext &&
                           host && host->save_sent_plaintext) {
                    WCHAR err[256] = L"";
                    if (!host->save_sent_plaintext(host->user, message->sent_profile_index,
                                                   message->sent_sender, message->sent_plaintext,
                                                   err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
                    }
                }
                if (message->kind == APP_WORK_KIND_DECRYPT && message->text && message->text[0] &&
                    message->group_index >= 0 && host && host->save_decrypted_group_plaintext) {
                    WCHAR err[256] = L"";
                    if (!host->save_decrypted_group_plaintext(host->user, message->group_index,
                                                              message->sender, message->text,
                                                              err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
                    }
                } else if (message->kind == APP_WORK_KIND_DECRYPT && message->text && message->text[0] &&
                           host && host->save_decrypted_plaintext) {
                    WCHAR err[256] = L"";
                    if (!host->save_decrypted_plaintext(host->user, message->profile_index,
                                                        message->text, err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
                    }
                }
                WCHAR *group_display_text = build_group_display_text(message);
                SetWindowTextW(message->target_textbox,
                               group_display_text ? group_display_text : (message->text ? message->text : L""));
                secure_free_wide(group_display_text);
                if (message->kind == APP_WORK_KIND_IMPORT_KEY) {
                    WCHAR err[256] = L"";
                    if (message->profile_index >= 0 && host && host->reload_crypto_after_key_import &&
                        !host->reload_crypto_after_key_import(host->user, err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_IMPORT_REFRESH_FAILED);
                    }
                    if (host && host->refresh_key_list_after_key_import) host->refresh_key_list_after_key_import(host->user);
                } else if ((message->kind == APP_WORK_KIND_CREATE_GROUP ||
                            message->kind == APP_WORK_KIND_REKEY_GROUP) &&
                           host && host->refresh_key_list_after_key_import) {
                    host->refresh_key_list_after_key_import(host->user);
                }
            }
        }
        app_work_free_message(message);
    } else if (msg == WM_APP_WORK_ERROR || msg == WM_APP_WORK_DONE) {
        host_show_error(host, hwnd, UI_TEXT_BACKGROUND_WORK_FAILED);
    }
    if (msg == WM_APP_WORK_DONE || msg == WM_APP_WORK_ERROR || msg == WM_APP_WORK_CANCELLED) {
        app_work_complete_message_handled();
    }
    return 0;
}
