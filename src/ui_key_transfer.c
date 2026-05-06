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
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_EXPORT_KEY, hwnd, target_textbox);
    if (!ctx) {
        show_key_transfer_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    set_key_overlay(target_textbox, UI_TEXT_KEY_EXPORT_OVERLAY, TRUE);
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
    WCHAR err[256] = L"";
    if (!app_flow_extract_key_package_body(text, &body, fingerprint, ARRAYSIZE(fingerprint), err, ARRAYSIZE(err))) {
        xfree(text);
        show_key_transfer_error(hwnd, err[0] ? err : UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    if (profiles_count() >= APP_PROFILE_MAX_PROFILES) {
        secure_free_wide(body);
        xfree(text);
        show_key_transfer_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    WCHAR name[128];
    UI_NAME_PROMPT_HOST prompt_host;
    ZeroMemory(&prompt_host, sizeof(prompt_host));
    prompt_host.on_window_close_requested = g_host.on_name_prompt_close_requested;
    prompt_host.user = g_host.user;
    if (!ui_prompt_key_name(g_host.instance, hwnd, g_host.ui_font, &prompt_host, name, ARRAYSIZE(name))) {
        secure_free_wide(body);
        xfree(text);
        return;
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
        HWND controls[] = { edit, g_key_overlay, import_btn, export_btn };
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
        int edit_y = margin;
        int edit_h = button_y - gap - edit_y;
        if (edit_h < UI_KEY_TRANSFER_MIN_EDIT_HEIGHT) edit_h = UI_KEY_TRANSFER_MIN_EDIT_HEIGHT;
        HWND key_edit = GetDlgItem(hwnd, IDC_KEY_TEXT);
        MoveWindow(key_edit, margin, edit_y, w - margin * 2, edit_h, TRUE);
        ui_overlay_layout(g_key_overlay, key_edit);
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
        show_key_transfer_error(owner, L"");
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
