#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _CRT_SECURE_NO_WARNINGS

#include "ui_work_messages.h"
#include "app_work.h"
#include "ui_strings.h"

static void host_set_overlay(const UI_WORK_MESSAGE_HOST *host, HWND textbox, const WCHAR *text, BOOL show) {
    if (host && host->set_textbox_overlay) host->set_textbox_overlay(host->user, textbox, text, show);
}

static void host_show_error(const UI_WORK_MESSAGE_HOST *host, HWND owner, const WCHAR *message) {
    if (host && host->show_error) host->show_error(host->user, owner, message);
}

LRESULT ui_work_handle_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                               const UI_WORK_MESSAGE_HOST *host) {
    (void)wparam;
    APP_WORK_MESSAGE *message = (APP_WORK_MESSAGE *)lparam;
    if (message) {
        if (msg == WM_APP_WORK_ERROR) {
            if (message->target_textbox && IsWindow(message->target_textbox)) {
                SetWindowTextW(message->target_textbox, UI_TEXT_EMPTY);
                host_set_overlay(host, message->target_textbox, UI_TEXT_WORK_FAILED_UNFINISHED, TRUE);
            }
            host_show_error(host, hwnd, message->text ? message->text : UI_TEXT_BACKGROUND_WORK_FAILED);
        } else if (msg == WM_APP_WORK_CANCELLED) {
            if (message->target_textbox && IsWindow(message->target_textbox)) {
                SetWindowTextW(message->target_textbox, UI_TEXT_EMPTY);
                host_set_overlay(host, message->target_textbox, NULL, FALSE);
            }
        } else if (message->target_textbox && IsWindow(message->target_textbox)) {
            if (msg == WM_APP_WORK_UPDATE) {
                SetWindowTextW(message->target_textbox, UI_TEXT_EMPTY);
                host_set_overlay(host, message->target_textbox, message->text ? message->text : UI_TEXT_EMPTY, TRUE);
            } else if (msg == WM_APP_WORK_DONE) {
                host_set_overlay(host, message->target_textbox, NULL, FALSE);
                SetWindowTextW(message->target_textbox, message->text ? message->text : UI_TEXT_EMPTY);
                if (message->kind == APP_WORK_KIND_IMPORT_KEY) {
                    WCHAR err[256] = L"";
                    if (host && host->reload_active_crypto && !host->reload_active_crypto(host->user, err, ARRAYSIZE(err))) {
                        host_show_error(host, hwnd, err[0] ? err : UI_TEXT_IMPORT_REFRESH_FAILED);
                    }
                    if (host && host->refresh_key_combo) host->refresh_key_combo(host->user);
                    if (message->text && message->text[0]) {
                        MessageBoxW(hwnd, message->text, UI_TEXT_CONTACT_FINGERPRINT_TITLE, MB_OK | MB_ICONINFORMATION);
                    }
                }
            }
        }
        app_work_free_message(message);
    }
    if (msg == WM_APP_WORK_DONE || msg == WM_APP_WORK_ERROR || msg == WM_APP_WORK_CANCELLED) {
        app_work_complete_message_handled();
    }
    return 0;
}
