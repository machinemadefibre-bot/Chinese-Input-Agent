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

#include <windows.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <strsafe.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#include "app_flow.h"
#include "app_shared.h"
#include "app_llm.h"
#include "app_storage.h"
#include "app_profiles.h"
#include "app_archive.h"
#include "app_work.h"
#include "ui_overlay.h"
#include "win_util.h"

#define APP_TITLE L"ChineseInputAgent"
#define APP_DIR_NAME L"ChineseInputAgent"

#define IDC_TEXTBOX 1001
#define IDC_ENCRYPT 1002
#define IDC_DECRYPT 1003
#define IDC_CLEAR 1004
#define IDC_KEY_SELECT 1006
#define IDC_KEY_TRANSFER 1007
#define IDC_TOPIC 1008
#define IDC_TEXT_OVERLAY 1009

#define IDC_NAME_EDIT 3001
#define IDC_KEY_TEXT 3002
#define IDC_KEY_IMPORT 3003
#define IDC_KEY_EXPORT 3004
#define IDC_KEY_OVERLAY 3005

#define MASTER_KEY_BYTES APP_PROFILE_MASTER_KEY_BYTES
#define MAX_PROFILES APP_PROFILE_MAX_PROFILES

#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif

static HINSTANCE g_instance;
static HWND g_main_window;
static HWND g_textbox;
static HWND g_text_overlay;
static HWND g_key_select;
static HWND g_topic_edit;
static HWND g_key_window;
static HWND g_key_overlay;
static HFONT g_ui_font;
static BOOL g_archive_mode;
static CRYPTO_BOX *g_active_box;

static void set_control_font(HWND hwnd);
static void show_error(HWND owner, const WCHAR *message);
static void do_key_transfer(HWND owner);
static void do_archive(HWND hwnd);
static void show_archive_for_active_profile(void);
static void leave_archive_mode(void);
static void refresh_main_mode_controls(void);
static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show);
static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit);
static CRYPTO_BOX *get_active_box_for_work(void *user);
static void set_work_busy(void *user, BOOL busy);
static void show_work_error(void *user, HWND owner, const WCHAR *message);
static void configure_app_work(HWND main_window);

static void refresh_key_combo(void) {
    if (!g_key_select) return;
    SendMessageW(g_key_select, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < profiles_count(); ++i) {
        KEY_PROFILE *profile = profiles_get(i);
        SendMessageW(g_key_select, CB_ADDSTRING, 0, (LPARAM)(profile ? profile->name : L""));
    }
    if (profiles_active_index() >= 0) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)profiles_active_index(), 0);
}

static void close_active_crypto(void) {
    crypto_box_close(g_active_box);
    g_active_box = NULL;
}

static BOOL reload_active_crypto(WCHAR *err, size_t err_cch) {
    int index = profiles_active_index();
    if (index < 0) {
        set_error(err, err_cch, L"No active profile is selected.");
        return FALSE;
    }
    CRYPTO_BOX *new_box = NULL;
    if (!profiles_open_crypto(index, &new_box, err, err_cch)) return FALSE;
    close_active_crypto();
    g_active_box = new_box;
    if (g_key_select) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)index, 0);
    return TRUE;
}

static BOOL activate_profile(int index, HWND owner, WCHAR *err, size_t err_cch) {
    (void)owner;
    CRYPTO_BOX *new_box = NULL;
    if (!profiles_open_crypto(index, &new_box, err, err_cch)) return FALSE;
    if (!profiles_activate(index, err, err_cch)) {
        crypto_box_close(new_box);
        return FALSE;
    }
    close_active_crypto();
    g_active_box = new_box;
    if (g_key_select) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)index, 0);
    return TRUE;
}

static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit) {
    WCHAR *topic = win_get_window_text_alloc(topic_edit);
    if (!topic) {
        show_error(owner, L"");
        return NULL;
    }
    if (topic[0] == L'\0') {
        xfree(topic);
        show_error(owner, L"");
        return NULL;
    }
    return topic;
}

static void show_archive_for_active_profile(void) {
    if (!g_textbox || !IsWindow(g_textbox)) return;
    KEY_PROFILE *profile = profiles_active();
    if (!profile) {
        SetWindowTextW(g_textbox, L"");
        return;
    }
    WCHAR err[256] = L"";
    WCHAR *archive = NULL;
    if (!archive_load_text(profile, &archive, err, ARRAYSIZE(err))) {
        show_error(g_main_window, err[0] ? err : L"");
        return;
    }
    set_textbox_overlay(g_textbox, NULL, FALSE);
    SetWindowTextW(g_textbox, archive ? archive : L"");
    SendMessageW(g_textbox, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_textbox, EM_SCROLLCARET, 0, 0);
    secure_free_wide(archive);
}

static void refresh_main_mode_controls(void) {
    if (!g_main_window || !IsWindow(g_main_window)) return;
    BOOL busy = app_work_is_active();
    HWND encrypt = GetDlgItem(g_main_window, IDC_ENCRYPT);
    HWND decrypt = GetDlgItem(g_main_window, IDC_DECRYPT);
    HWND archive = GetDlgItem(g_main_window, IDC_CLEAR);
    HWND key_transfer = GetDlgItem(g_main_window, IDC_KEY_TRANSFER);
    if (archive) SetWindowTextW(archive, g_archive_mode ? L"\u8fd4\u56de" : L"\u5f52\u6863");
    if (g_textbox) SendMessageW(g_textbox, EM_SETREADONLY, g_archive_mode ? TRUE : FALSE, 0);
    if (g_topic_edit) EnableWindow(g_topic_edit, !busy && !g_archive_mode);
    if (encrypt) {
        EnableWindow(encrypt, !g_archive_mode);
        SetWindowTextW(encrypt, busy && !g_archive_mode ? L"\u505c\u6b62" : L"\u52a0\u5bc6");
    }
    if (decrypt) EnableWindow(decrypt, !busy && !g_archive_mode);
    if (archive) EnableWindow(archive, !busy);
    if (g_key_select) EnableWindow(g_key_select, !busy);
    if (key_transfer) EnableWindow(key_transfer, !busy && !g_archive_mode);
}

static void enter_archive_mode(void) {
    g_archive_mode = TRUE;
    refresh_main_mode_controls();
    show_archive_for_active_profile();
}

static void leave_archive_mode(void) {
    g_archive_mode = FALSE;
    set_textbox_overlay(g_textbox, NULL, FALSE);
    if (g_textbox) SetWindowTextW(g_textbox, L"");
    refresh_main_mode_controls();
}

static void do_archive(HWND hwnd) {
    if (g_archive_mode) {
        leave_archive_mode();
        return;
    }
    KEY_PROFILE *profile = profiles_active();
    if (!profile) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR *plain = win_get_window_text_alloc(g_textbox);
    if (!plain) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (plain[0] == L'\0') {
        secure_free_wide(plain);
        enter_archive_mode();
        return;
    }
    WCHAR err[256] = L"";
    if (!archive_append_text(profile, plain, err, ARRAYSIZE(err))) {
        secure_free_wide(plain);
        show_error(hwnd, err[0] ? err : L"");
        return;
    }
    secure_free_wide(plain);
    enter_archive_mode();
}

static void set_busy_controls(BOOL busy) {
    BOOL enable = !busy;
    if (g_main_window && IsWindow(g_main_window)) {
        refresh_main_mode_controls();
    }
    if (g_key_window && IsWindow(g_key_window)) {
        EnableWindow(GetDlgItem(g_key_window, IDC_KEY_IMPORT), enable);
        EnableWindow(GetDlgItem(g_key_window, IDC_KEY_EXPORT), enable);
    }
}

static HWND overlay_for_textbox(HWND textbox) {
    if (textbox && textbox == g_textbox) return g_text_overlay;
    if (g_key_window && IsWindow(g_key_window) &&
        textbox == GetDlgItem(g_key_window, IDC_KEY_TEXT)) {
        return g_key_overlay;
    }
    return NULL;
}

static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show) {
    HWND overlay = overlay_for_textbox(textbox);
    ui_overlay_set_text(overlay, text, show);
}

static void do_export_key(HWND hwnd, HWND target_textbox) {
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_EXPORT_KEY, hwnd, target_textbox);
    if (!ctx) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    set_textbox_overlay(target_textbox, L"\u6b63\u5728\u751f\u6210\u8054\u7cfb\u4eba\u516c\u94a5\u5305\u8f7d\u4f53\u6587\u672c\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(target_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

typedef struct NAME_PROMPT_STATE {
    BOOL is_done;
    BOOL is_accepted;
    WCHAR name[128];
} NAME_PROMPT_STATE;

static LRESULT CALLBACK NamePromptWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    NAME_PROMPT_STATE *state = (NAME_PROMPT_STATE *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lparam;
        state = (NAME_PROMPT_STATE *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);
        HWND label = CreateWindowExW(0, L"STATIC", L"\u7ed9\u5bfc\u5165\u7684\u5bc6\u94a5\u547d\u540d", WS_CHILD | WS_VISIBLE,
                                     14, 16, 260, 24, hwnd, NULL, g_instance, NULL);
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", state->name,
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                    14, 46, 300, 28, hwnd, (HMENU)IDC_NAME_EDIT, g_instance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, ARRAYSIZE(state->name) - 1, 0);
        HWND ok_button = CreateWindowExW(0, L"BUTTON", L"\u786e\u5b9a", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         146, 88, 80, 32, hwnd, (HMENU)IDOK, g_instance, NULL);
        HWND cancel = CreateWindowExW(0, L"BUTTON", L"\u53d6\u6d88", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      234, 88, 80, 32, hwnd, (HMENU)IDCANCEL, g_instance, NULL);
        HWND controls[] = { label, edit, ok_button, cancel };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        SetFocus(edit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == IDOK) {
            GetWindowTextW(GetDlgItem(hwnd, IDC_NAME_EDIT), state->name, ARRAYSIZE(state->name));
            if (state->name[0] == L'\0') StringCchCopyW(state->name, ARRAYSIZE(state->name), L"\u5bfc\u5165\u5bc6\u94a5");
            state->is_accepted = TRUE;
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wparam) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        app_work_cancel();
        shutdown_local_llm_worker();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (state) state->is_done = TRUE;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL prompt_key_name(HWND owner, WCHAR *name, size_t cch) {
    NAME_PROMPT_STATE state;
    ZeroMemory(&state, sizeof(state));
    StringCchCopyW(state.name, ARRAYSIZE(state.name), L"\u5bfc\u5165\u5bc6\u94a5");
    HWND win = CreateWindowExW(WS_EX_TOOLWINDOW, L"ChineseInputAgentNamePrompt",
                               L"\u5bfc\u5165\u5bc6\u94a5", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                               CW_USEDEFAULT, CW_USEDEFAULT, 350, 170,
                               owner, NULL, g_instance, &state);
    if (!win) return FALSE;
    EnableWindow(owner, FALSE);
    ShowWindow(win, SW_SHOW);
    MSG msg;
    while (!state.is_done && GetMessageW(&msg, NULL, 0, 0)) {
        if (IsDialogMessageW(win, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
    if (!state.is_accepted) return FALSE;
    StringCchCopyW(name, cch, state.name);
    return TRUE;
}

static void do_import_key(HWND hwnd, HWND source_textbox) {
    WCHAR *text = win_get_window_text_alloc(source_textbox);
    if (!text) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR *body = NULL;
    WCHAR err[256] = L"";
    if (!app_flow_extract_key_package_body(text, &body, err, ARRAYSIZE(err))) {
        xfree(text);
        show_error(hwnd, err[0] ? err : L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (profiles_count() >= MAX_PROFILES) {
        secure_free_wide(body);
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR name[128];
    if (!prompt_key_name(hwnd, name, ARRAYSIZE(name))) {
        secure_free_wide(body);
        xfree(text);
        return;
    }

    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_IMPORT_KEY, hwnd, source_textbox);
    if (!ctx) {
        secure_free_wide(body);
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->input = body;
    ctx->name = win_dup_wide(name);
    if (!ctx->name) {
        app_work_free_ctx(ctx);
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }

    set_textbox_overlay(source_textbox, L"\u6b63\u5728\u89e3\u6790\u8054\u7cfb\u4eba\u516c\u94a5\u5305\u8f7d\u4f53\u6587\u672c\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(source_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(source_textbox, NULL, FALSE);
        SetWindowTextW(source_textbox, text);
        app_work_free_ctx(ctx);
    }
    xfree(text);
}

static void show_error(HWND owner, const WCHAR *message) {
    win_show_error(owner, APP_TITLE, message);
}

static CRYPTO_BOX *get_active_box_for_work(void *user) {
    (void)user;
    return g_active_box;
}

static void set_work_busy(void *user, BOOL busy) {
    (void)user;
    set_busy_controls(busy);
}

static void show_work_error(void *user, HWND owner, const WCHAR *message) {
    (void)user;
    show_error(owner, message);
}

static void configure_app_work(HWND main_window) {
    APP_WORK_HOST host;
    ZeroMemory(&host, sizeof(host));
    host.main_window = main_window;
    host.get_active_box = get_active_box_for_work;
    host.set_busy = set_work_busy;
    host.show_error = show_work_error;
    app_work_configure(&host);
}

static void do_encrypt(HWND hwnd) {
    WCHAR *plain_w = win_get_window_text_alloc(g_textbox);
    if (!plain_w) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (plain_w[0] == L'\0') {
        secure_free_wide(plain_w);
        return;
    }
    WCHAR *topic = get_required_topic_text(hwnd, g_topic_edit);
    if (!topic) {
        secure_free_wide(plain_w);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_ENCRYPT, hwnd, g_textbox);
    if (!ctx) {
        secure_free_wide(plain_w);
        xfree(topic);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->input = plain_w;
    ctx->topic = topic;
    set_textbox_overlay(g_textbox, L"\u6b63\u5728\u52a0\u5bc6\u5e76\u6df7\u6dc6\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        SetWindowTextW(g_textbox, plain_w);
        app_work_free_ctx(ctx);
    }
}

static void do_decrypt(HWND hwnd) {
    WCHAR *clip = NULL;
    if (!win_get_clipboard_text(hwnd, &clip)) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (clip[0] == L'\0') {
        xfree(clip);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_DECRYPT, hwnd, g_textbox);
    if (!ctx) {
        xfree(clip);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->input = clip;
    set_textbox_overlay(g_textbox, L"\u6b63\u5728\u4ece\u526a\u8d34\u677f\u89e3\u5bc6\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void layout_main(HWND hwnd, int width, int height) {
    int margin = 12;
    int gap = 8;
    int combo_h = 30;
    int topic_h = 30;
    int button_h = 38;
    int topic_y = margin + combo_h + gap;
    int edit_y = topic_y + topic_h + gap;
    int edit_h = height - edit_y - gap - button_h - margin;
    if (edit_h < 80) edit_h = 80;
    int button_y = edit_y + edit_h + gap;
    int button_w = (width - margin * 2 - gap * 3) / 4;
    if (button_w < 58) button_w = 58;

    MoveWindow(g_key_select, margin, margin, width - margin * 2, 220, TRUE);
    MoveWindow(g_topic_edit, margin, topic_y, width - margin * 2, topic_h, TRUE);
    MoveWindow(g_textbox, margin, edit_y, width - margin * 2, edit_h, TRUE);
    ui_overlay_layout(g_text_overlay, g_textbox);
    MoveWindow(GetDlgItem(hwnd, IDC_ENCRYPT), margin, button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_DECRYPT), margin + (button_w + gap), button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_CLEAR), margin + (button_w + gap) * 2, button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_KEY_TRANSFER), margin + (button_w + gap) * 3, button_y, button_w, button_h, TRUE);
}

static void set_control_font(HWND hwnd) {
    win_set_control_font(hwnd, g_ui_font);
}

static LRESULT CALLBACK KeyTransferWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE: {
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TEXT, g_instance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
        g_key_overlay = ui_overlay_create(edit, g_instance, IDC_KEY_OVERLAY);
        HWND import_btn = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u5165",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_IMPORT, g_instance, NULL);
        HWND export_btn = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u51fa",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_EXPORT, g_instance, NULL);
        HWND controls[] = { edit, g_key_overlay, import_btn, export_btn };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lparam);
        int h = HIWORD(lparam);
        int margin = 12;
        int gap = 8;
        int button_h = 36;
        int button_w = 110;
        int button_y = h - margin - button_h;
        int edit_y = margin;
        int edit_h = button_y - gap - edit_y;
        if (edit_h < 80) edit_h = 80;
        HWND key_edit = GetDlgItem(hwnd, IDC_KEY_TEXT);
        MoveWindow(key_edit, margin, edit_y, w - margin * 2, edit_h, TRUE);
        ui_overlay_layout(g_key_overlay, key_edit);
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_IMPORT), w - margin - button_w * 2 - gap, button_y, button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_EXPORT), w - margin - button_w, button_y, button_w, button_h, TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = 480;
        mmi->ptMinTrackSize.y = 300;
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

static void do_key_transfer(HWND owner) {
    if (g_key_window && IsWindow(g_key_window)) {
        SetForegroundWindow(g_key_window);
        return;
    }
    g_key_window = CreateWindowExW(WS_EX_TOOLWINDOW, L"ChineseInputAgentKeyWindow",
                                   L"\u5bfc\u5165/\u5bfc\u51fa\u5bc6\u94a5", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                                   CW_USEDEFAULT, CW_USEDEFAULT, 620, 420,
                                   owner, NULL, g_instance, NULL);
    if (!g_key_window) {
        show_error(owner, L"");
        return;
    }
    ShowWindow(g_key_window, SW_SHOW);
    UpdateWindow(g_key_window);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_APP_WORK_UPDATE:
    case WM_APP_WORK_DONE:
    case WM_APP_WORK_ERROR:
    case WM_APP_WORK_CANCELLED: {
        APP_WORK_MESSAGE *m = (APP_WORK_MESSAGE *)lparam;
        if (m) {
            if (msg == WM_APP_WORK_ERROR) {
                if (m->target_textbox && IsWindow(m->target_textbox)) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, L"\u4efb\u52a1\u5931\u8d25\uff0c\u672a\u5199\u5165\u672a\u5b8c\u6210\u5185\u5bb9", TRUE);
                }
                show_error(hwnd, m->text ? m->text : L"\u540e\u53f0\u4efb\u52a1\u5931\u8d25\u3002");
            } else if (msg == WM_APP_WORK_CANCELLED) {
                if (m->target_textbox && IsWindow(m->target_textbox)) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, NULL, FALSE);
                }
            } else if (m->target_textbox && IsWindow(m->target_textbox)) {
                if (msg == WM_APP_WORK_UPDATE) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, m->text ? m->text : L"", TRUE);
                } else if (msg == WM_APP_WORK_DONE) {
                    set_textbox_overlay(m->target_textbox, NULL, FALSE);
                    SetWindowTextW(m->target_textbox, m->text ? m->text : L"");
                    if (m->kind == APP_WORK_KIND_IMPORT_KEY) {
                        WCHAR err[256] = L"";
                        if (!reload_active_crypto(err, ARRAYSIZE(err))) {
                            show_error(hwnd, err[0] ? err : L"\u5bc6\u94a5\u5bfc\u5165\u540e\u5237\u65b0\u52a0\u5bc6\u72b6\u6001\u5931\u8d25\u3002");
                        }
                        refresh_key_combo();
                        if (m->text && m->text[0]) {
                            MessageBoxW(hwnd, m->text, L"\u8054\u7cfb\u4eba\u6307\u7eb9\u786e\u8ba4", MB_OK | MB_ICONINFORMATION);
                        }
                    }
                }
            }
            app_work_free_message(m);
        }
        if (msg == WM_APP_WORK_DONE || msg == WM_APP_WORK_ERROR || msg == WM_APP_WORK_CANCELLED) {
            app_work_complete_message_handled();
        }
        return 0;
    }
    case WM_CREATE: {
        g_key_select = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_SELECT, g_instance, NULL);
        g_topic_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_TOPIC, g_instance, NULL);
        SendMessageW(g_topic_edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"\u8bf7\u5148\u8f93\u5165\u8ba8\u8bba\u7684\u4e3b\u9898");
        g_textbox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_TEXTBOX, g_instance, NULL);
        SendMessageW(g_textbox, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
        g_text_overlay = ui_overlay_create(g_textbox, g_instance, IDC_TEXT_OVERLAY);

        HWND encrypt = CreateWindowExW(0, L"BUTTON", L"\u52a0\u5bc6", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_ENCRYPT, g_instance, NULL);
        HWND decrypt = CreateWindowExW(0, L"BUTTON", L"\u89e3\u5bc6", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_DECRYPT, g_instance, NULL);
        HWND clear = CreateWindowExW(0, L"BUTTON", L"\u5f52\u6863", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_CLEAR, g_instance, NULL);
        HWND key_transfer = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u5165/\u5bfc\u51fa\u5bc6\u94a5",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                            0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TRANSFER, g_instance, NULL);
        HWND controls[] = { g_key_select, g_topic_edit, g_textbox, g_text_overlay, encrypt, decrypt, clear, key_transfer };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        refresh_key_combo();
        refresh_main_mode_controls();
        break;
    }
    case WM_SIZE:
        layout_main(hwnd, LOWORD(lparam), HIWORD(lparam));
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = 620;
        mmi->ptMinTrackSize.y = 360;
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_KEY_SELECT:
            if (HIWORD(wparam) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_key_select, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel != profiles_active_index()) {
                    WCHAR err[256] = L"";
                    if (!activate_profile(sel, hwnd, err, ARRAYSIZE(err))) {
                        show_error(hwnd, err[0] ? err : L"\u5207\u6362\u5bc6\u94a5\u5931\u8d25\u3002");
                        refresh_key_combo();
                    } else if (g_archive_mode) {
                        show_archive_for_active_profile();
                    }
                }
            }
            break;
        case IDC_ENCRYPT:
            if (app_work_is_active()) {
                app_work_cancel();
                break;
            }
            do_encrypt(hwnd);
            break;
        case IDC_DECRYPT:
            do_decrypt(hwnd);
            break;
        case IDC_CLEAR:
            do_archive(hwnd);
            break;
        case IDC_KEY_TRANSFER:
            do_key_transfer(hwnd);
            break;
        }
        break;
    case WM_CLOSE:
        if (app_work_is_active()) app_work_cancel();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL register_windows(void) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentMainWindow";
    if (!RegisterClassExW(&wc)) return FALSE;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = NamePromptWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentNamePrompt";
    if (!RegisterClassExW(&wc)) return FALSE;

    if (!ui_overlay_register_class(g_instance)) return FALSE;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = KeyTransferWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentKeyWindow";
    return RegisterClassExW(&wc) != 0;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev;
    (void)cmd;
    g_instance = instance;
    configure_app_work(NULL);
    app_llm_init(app_work_cancelled, app_work_post_llm_stream_progress);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm;
    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        g_ui_font = CreateFontIndirectW(&ncm.lfMessageFont);
    }
    if (!g_ui_font) {
        g_ui_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    WCHAR err[256] = L"";
    if (!profiles_load(err, ARRAYSIZE(err))) {
        MessageBoxW(NULL, err, APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!activate_profile(profiles_active_index(), NULL, err, ARRAYSIZE(err))) {
        profiles_shutdown();
        MessageBoxW(NULL, err, APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!register_windows()) {
        close_active_crypto();
        profiles_shutdown();
        MessageBoxW(NULL, L"Window initialization failed.", APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }

    g_main_window = CreateWindowExW(0, L"ChineseInputAgentMainWindow", APP_TITLE,
                                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                    CW_USEDEFAULT, CW_USEDEFAULT, 760, 520,
                                    NULL, NULL, instance, NULL);
    if (!g_main_window) {
        close_active_crypto();
        profiles_shutdown();
        MessageBoxW(NULL, L"Window initialization failed.", APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    configure_app_work(g_main_window);

    ShowWindow(g_main_window, show);
    UpdateWindow(g_main_window);
    start_local_llm_background();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (g_key_window && IsDialogMessageW(g_key_window, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_llm_cleanup();
    close_active_crypto();
    profiles_shutdown();
    if (g_ui_font) DeleteObject(g_ui_font);
    return (int)msg.wParam;
}
