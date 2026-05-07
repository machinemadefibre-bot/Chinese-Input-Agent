#include "ui_key_transfer.h"
#include "app_constants.h"
#include "app_flow.h"
#include "app_limits.h"
#include "app_profiles.h"
#include "app_shared.h"
#include "app_work.h"
#include "ui_ids.h"
#include "ui_layout.h"
#include "ui_name_prompt.h"
#include "ui_overlay.h"
#include "ui_strings.h"
#include "win_util.h"

#include <strsafe.h>

#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif

/* Owns the key-transfer window and the UI-side import/export orchestration around app_work. */
static HWND g_key_window;
static HWND g_key_overlay;
static UI_KEY_TRANSFER_HOST g_host;

static void show_key_transfer_error(HWND owner, const WCHAR *message) {
    if (g_host.show_error) g_host.show_error(g_host.user, owner, message);
}

static void set_key_overlay(HWND textbox, const WCHAR *text, BOOL show) {
    ui_overlay_set_text(ui_key_transfer_overlay_for_textbox(textbox), text, show);
}

static void do_export_key(HWND hwnd, HWND target_textbox) {
    int group_index = g_host.get_selected_group_index ? g_host.get_selected_group_index(g_host.user) : -1;
    APP_WORK_CTX *ctx = app_work_alloc(group_index >= 0 ? APP_WORK_KIND_EXPORT_GROUP : APP_WORK_KIND_EXPORT_KEY,
                                       hwnd, target_textbox);
    if (!ctx) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->group_index = group_index;
    set_key_overlay(target_textbox, group_index >= 0 ? UI_TEXT_GROUP_EXPORT_OVERLAY : UI_TEXT_KEY_EXPORT_OVERLAY, TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!app_work_start(ctx)) {
        set_key_overlay(target_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_create_group(HWND hwnd, HWND name_edit, HWND self_name_edit, HWND target_textbox) {
    WCHAR *group_name = win_get_window_text_alloc(name_edit);
    WCHAR *self_name = win_get_window_text_alloc(self_name_edit);
    if (!group_name || !self_name) {
        secure_free_wide(group_name);
        secure_free_wide(self_name);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_CREATE_GROUP, hwnd, target_textbox);
    if (!ctx) {
        secure_free_wide(group_name);
        secure_free_wide(self_name);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->input = group_name;
    ctx->name = self_name;
    set_key_overlay(target_textbox, UI_TEXT_GROUP_CREATE_OVERLAY, TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!app_work_start(ctx)) {
        set_key_overlay(target_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_rekey_group(HWND hwnd, HWND target_textbox) {
    int group_index = g_host.get_selected_group_index ? g_host.get_selected_group_index(g_host.user) : -1;
    if (group_index < 0) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_REKEY_GROUP, hwnd, target_textbox);
    if (!ctx) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->group_index = group_index;
    set_key_overlay(target_textbox, UI_TEXT_GROUP_REKEY_OVERLAY, TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!app_work_start(ctx)) {
        set_key_overlay(target_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_set_group_alias(HWND hwnd, HWND member_id_edit, HWND alias_edit, HWND target_textbox) {
    int group_index = g_host.get_selected_group_index ? g_host.get_selected_group_index(g_host.user) : -1;
    if (group_index < 0) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    WCHAR *member_id = win_get_window_text_alloc(member_id_edit);
    WCHAR *alias = win_get_window_text_alloc(alias_edit);
    if (!member_id || !alias) {
        secure_free_wide(member_id);
        secure_free_wide(alias);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_SET_GROUP_ALIAS, hwnd, target_textbox);
    if (!ctx) {
        secure_free_wide(member_id);
        secure_free_wide(alias);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->group_index = group_index;
    ctx->input = member_id;
    ctx->name = alias;
    set_key_overlay(target_textbox, UI_TEXT_GROUP_ALIAS_OVERLAY, TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!app_work_start(ctx)) {
        set_key_overlay(target_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_import_key(HWND hwnd, HWND source_textbox) {
    WCHAR *text = win_get_window_text_alloc(source_textbox);
    if (!text) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    WCHAR *body = NULL;
    WCHAR fingerprint[32] = L"";
    APP_FLOW_EXCHANGE_KIND exchange_kind = APP_FLOW_EXCHANGE_CONTACT;
    WCHAR err[256] = L"";
    if (!app_flow_extract_exchange_body(text, &exchange_kind, &body, fingerprint, ARRAYSIZE(fingerprint), err, ARRAYSIZE(err))) {
        xfree(text);
        show_key_transfer_error(hwnd, err[0] ? err : UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    if (exchange_kind == APP_FLOW_EXCHANGE_CONTACT && profiles_count() >= APP_PROFILE_MAX_PROFILES) {
        secure_free_wide(body);
        xfree(text);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    WCHAR name[128] = L"";
    if (exchange_kind == APP_FLOW_EXCHANGE_CONTACT) {
        UI_NAME_PROMPT_HOST prompt_host;
        ZeroMemory(&prompt_host, sizeof(prompt_host));
        prompt_host.on_window_close_requested = g_host.on_name_prompt_close_requested;
        prompt_host.user = g_host.user;
        if (!ui_prompt_key_name(g_host.instance, hwnd, g_host.ui_font, &prompt_host, name, ARRAYSIZE(name))) {
            secure_free_wide(body);
            xfree(text);
            return;
        }
    } else {
        WCHAR *self_name = win_get_window_text_alloc(GetDlgItem(hwnd, IDC_GROUP_SELF_NAME));
        if (!self_name) {
            secure_free_wide(body);
            xfree(text);
            show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
            return;
        }
        if (FAILED(StringCchCopyW(name, ARRAYSIZE(name), self_name))) {
            secure_free_wide(self_name);
            secure_free_wide(body);
            xfree(text);
            show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
            return;
        }
        secure_free_wide(self_name);
    }

    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_IMPORT_KEY, hwnd, source_textbox);
    if (!ctx) {
        secure_free_wide(body);
        xfree(text);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    ctx->input = body;
    ctx->name = win_dup_wide(name);
    ctx->expected_fingerprint = win_dup_wide(fingerprint);
    if (!ctx->name || !ctx->expected_fingerprint) {
        app_work_free_ctx(ctx);
        xfree(text);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }

    set_key_overlay(source_textbox, UI_TEXT_KEY_IMPORT_OVERLAY, TRUE);
    SetWindowTextW(source_textbox, L"");
    if (!app_work_start(ctx)) {
        set_key_overlay(source_textbox, NULL, FALSE);
        SetWindowTextW(source_textbox, text);
        app_work_free_ctx(ctx);
    }
    xfree(text);
}

static LRESULT CALLBACK KeyTransferWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lparam;
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TEXT, cs->hInstance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, APP_MAX_EDIT_TEXT_CHARS, 0);
        g_key_overlay = ui_overlay_create(edit, cs->hInstance, IDC_KEY_OVERLAY);
        HWND import_btn = CreateWindowExW(0, L"BUTTON", UI_TEXT_IMPORT,
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_IMPORT, cs->hInstance, NULL);
        HWND export_btn = CreateWindowExW(0, L"BUTTON", UI_TEXT_EXPORT,
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_EXPORT, cs->hInstance, NULL);
        HWND group_name = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_NAME, cs->hInstance, NULL);
        SendMessageW(group_name, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_GROUP_NAME_CUE);
        HWND group_self_name = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                               0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_SELF_NAME, cs->hInstance, NULL);
        SendMessageW(group_self_name, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_GROUP_SELF_NAME_CUE);
        HWND group_create = CreateWindowExW(0, L"BUTTON", UI_TEXT_CREATE_GROUP,
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                            0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_CREATE, cs->hInstance, NULL);
        HWND group_rekey = CreateWindowExW(0, L"BUTTON", UI_TEXT_REKEY_GROUP,
                                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_REKEY, cs->hInstance, NULL);
        HWND member_id = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_MEMBER_ID, cs->hInstance, NULL);
        SendMessageW(member_id, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_GROUP_MEMBER_ID_CUE);
        HWND member_alias = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                            0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_MEMBER_ALIAS, cs->hInstance, NULL);
        SendMessageW(member_alias, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_GROUP_MEMBER_ALIAS_CUE);
        HWND set_alias = CreateWindowExW(0, L"BUTTON", UI_TEXT_SET_GROUP_ALIAS,
                                         WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_GROUP_SET_ALIAS, cs->hInstance, NULL);
        HWND controls[] = { edit, g_key_overlay, import_btn, export_btn, group_name, group_self_name,
                            group_create, group_rekey, member_id, member_alias, set_alias };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) win_set_control_font(controls[i], g_host.ui_font);
        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lparam);
        int h = HIWORD(lparam);
        int margin = UI_KEY_TRANSFER_MARGIN;
        int gap = UI_KEY_TRANSFER_GAP;
        int button_h = UI_KEY_TRANSFER_BUTTON_HEIGHT;
        int button_w = UI_KEY_TRANSFER_BUTTON_WIDTH;
        int button_y = h - margin - button_h;
        int alias_y = button_y - gap - button_h;
        int group_y = alias_y - gap - button_h;
        int edit_y = margin;
        int edit_h = group_y - gap - edit_y;
        if (edit_h < UI_KEY_TRANSFER_MIN_EDIT_HEIGHT) edit_h = UI_KEY_TRANSFER_MIN_EDIT_HEIGHT;
        HWND key_edit = GetDlgItem(hwnd, IDC_KEY_TEXT);
        MoveWindow(key_edit, margin, edit_y, w - margin * 2, edit_h, TRUE);
        ui_overlay_layout(g_key_overlay, key_edit);
        int edit_pair_w = (w - margin * 2 - button_w * 2 - gap * 3) / 2;
        if (edit_pair_w < 80) edit_pair_w = 80;
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_NAME), margin, group_y,
                   edit_pair_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_SELF_NAME), margin + edit_pair_w + gap, group_y,
                   edit_pair_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_CREATE), w - margin - button_w * 2 - gap, group_y,
                   button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_REKEY), w - margin - button_w, group_y,
                   button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_MEMBER_ID), margin, alias_y,
                   edit_pair_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_MEMBER_ALIAS), margin + edit_pair_w + gap, alias_y,
                   w - margin * 2 - edit_pair_w - button_w - gap * 2, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_GROUP_SET_ALIAS), w - margin - button_w, alias_y,
                   button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_IMPORT), w - margin - button_w * 2 - gap, button_y, button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_EXPORT), w - margin - button_w, button_y, button_w, button_h, TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = UI_KEY_TRANSFER_MIN_TRACK_WIDTH;
        mmi->ptMinTrackSize.y = UI_KEY_TRANSFER_MIN_TRACK_HEIGHT;
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_KEY_IMPORT:
            do_import_key(hwnd, GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        case IDC_KEY_EXPORT:
            do_export_key(hwnd, GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        case IDC_GROUP_CREATE:
            do_create_group(hwnd, GetDlgItem(hwnd, IDC_GROUP_NAME),
                            GetDlgItem(hwnd, IDC_GROUP_SELF_NAME), GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        case IDC_GROUP_REKEY:
            do_rekey_group(hwnd, GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        case IDC_GROUP_SET_ALIAS:
            do_set_group_alias(hwnd, GetDlgItem(hwnd, IDC_GROUP_MEMBER_ID),
                               GetDlgItem(hwnd, IDC_GROUP_MEMBER_ALIAS), GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        }
        break;
    case WM_CLOSE:
        /* Key transfer uses the single global work slot, so closing the window cancels any in-flight transfer. */
        if (app_work_is_active()) app_work_cancel();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_key_window == hwnd) {
            g_key_window = NULL;
            g_key_overlay = NULL;
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

BOOL ui_key_transfer_register_class(HINSTANCE instance) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = KeyTransferWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = APP_KEY_TRANSFER_WINDOW_CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

void ui_key_transfer_show(HWND owner, const UI_KEY_TRANSFER_HOST *host) {
    if (g_key_window && IsWindow(g_key_window)) {
        SetForegroundWindow(g_key_window);
        return;
    }
    if (host) g_host = *host;
    g_key_window = CreateWindowExW(WS_EX_TOOLWINDOW, APP_KEY_TRANSFER_WINDOW_CLASS_NAME,
                                   UI_TEXT_IMPORT_EXPORT_KEY, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                                   CW_USEDEFAULT, CW_USEDEFAULT, UI_KEY_TRANSFER_INITIAL_WIDTH, UI_KEY_TRANSFER_INITIAL_HEIGHT,
                                   owner, NULL, g_host.instance, NULL);
    if (!g_key_window) {
        show_key_transfer_error(owner, UI_TEXT_WINDOW_INIT_FAILED);
        return;
    }
    ShowWindow(g_key_window, SW_SHOW);
    UpdateWindow(g_key_window);
}

void ui_key_transfer_set_busy(BOOL busy) {
    BOOL enable = !busy;
    if (!g_key_window || !IsWindow(g_key_window)) return;
    EnableWindow(GetDlgItem(g_key_window, IDC_KEY_IMPORT), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_KEY_EXPORT), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_NAME), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_SELF_NAME), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_CREATE), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_REKEY), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_MEMBER_ID), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_MEMBER_ALIAS), enable);
    EnableWindow(GetDlgItem(g_key_window, IDC_GROUP_SET_ALIAS), enable);
}

HWND ui_key_transfer_overlay_for_textbox(HWND textbox) {
    if (g_key_window && IsWindow(g_key_window) &&
        textbox == GetDlgItem(g_key_window, IDC_KEY_TEXT)) {
        return g_key_overlay;
    }
    return NULL;
}

BOOL ui_key_transfer_translate_message(MSG *msg) {
    return g_key_window && IsDialogMessageW(g_key_window, msg);
}
