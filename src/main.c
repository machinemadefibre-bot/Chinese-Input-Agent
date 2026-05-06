#include <windows.h>
#include <commctrl.h>

#include "app_constants.h"
#include "app_limits.h"
#include "app_shared.h"
#include "app_llm.h"
#include "app_profiles.h"
#include "app_archive.h"
#include "app_work.h"
#include "ui_overlay.h"
#include "ui_key_transfer.h"
#include "ui_ids.h"
#include "ui_layout.h"
#include "ui_work_messages.h"
#include "ui_strings.h"
#include "win_util.h"

#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif

static HINSTANCE g_instance;
static HWND g_main_window;
static HWND g_textbox;
static HWND g_text_overlay;
static HWND g_key_select;
static HWND g_topic_edit;
static HFONT g_ui_font;
static BOOL g_archive_mode;
static CRYPTO_BOX *g_active_box;

static void set_control_font(HWND hwnd);
static void show_error(HWND owner, const WCHAR *message);
static void show_key_transfer(HWND owner);
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
        set_error(err, err_cch, UI_TEXT_NO_ACTIVE_PROFILE);
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
        show_error(owner, UI_TEXT_TOPIC_REQUIRED);
        return NULL;
    }
    if (topic[0] == L'\0') {
        xfree(topic);
        show_error(owner, UI_TEXT_TOPIC_REQUIRED);
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
        show_error(g_main_window, err[0] ? err : UI_TEXT_ARCHIVE_FAILED);
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
    if (archive) SetWindowTextW(archive, g_archive_mode ? UI_TEXT_BACK : UI_TEXT_ARCHIVE);
    if (g_textbox) SendMessageW(g_textbox, EM_SETREADONLY, g_archive_mode ? TRUE : FALSE, 0);
    if (g_topic_edit) EnableWindow(g_topic_edit, !busy && !g_archive_mode);
    if (encrypt) {
        EnableWindow(encrypt, !g_archive_mode);
        SetWindowTextW(encrypt, busy && !g_archive_mode ? UI_TEXT_STOP : UI_TEXT_ENCRYPT);
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
        show_error(hwnd, UI_TEXT_ARCHIVE_FAILED);
        return;
    }
    WCHAR *plain = win_get_window_text_alloc(g_textbox);
    if (!plain) {
        show_error(hwnd, UI_TEXT_ARCHIVE_FAILED);
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
    if (g_main_window && IsWindow(g_main_window)) {
        refresh_main_mode_controls();
    }
    ui_key_transfer_set_busy(busy);
}

static HWND overlay_for_textbox(HWND textbox) {
    if (textbox && textbox == g_textbox) return g_text_overlay;
    return ui_key_transfer_overlay_for_textbox(textbox);
}

static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show) {
    HWND overlay = overlay_for_textbox(textbox);
    ui_overlay_set_text(overlay, text, show);
}

static void cancel_transfer_on_name_prompt_close(void *user) {
    (void)user;
    /* Preserved behavior: closing the modal import-name prompt cancels the active transfer and stops the local worker. */
    app_work_cancel();
    shutdown_local_llm_worker();
}

static void show_error(HWND owner, const WCHAR *message) {
    win_show_error(owner, CIA_APP_TITLE, message);
}

static void key_transfer_show_error(void *user, HWND owner, const WCHAR *message) {
    (void)user;
    show_error(owner, message);
}

static void show_key_transfer(HWND owner) {
    UI_KEY_TRANSFER_HOST host;
    ZeroMemory(&host, sizeof(host));
    host.instance = g_instance;
    host.ui_font = g_ui_font;
    host.show_error = key_transfer_show_error;
    host.on_name_prompt_close_requested = cancel_transfer_on_name_prompt_close;
    ui_key_transfer_show(owner, &host);
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

static void work_messages_set_overlay(void *user, HWND textbox, const WCHAR *text, BOOL show) {
    (void)user;
    set_textbox_overlay(textbox, text, show);
}

static void work_messages_show_error(void *user, HWND owner, const WCHAR *message) {
    (void)user;
    show_error(owner, message);
}

static BOOL work_messages_reload_crypto_after_key_import(void *user, WCHAR *err, size_t err_cch) {
    (void)user;
    return reload_active_crypto(err, err_cch);
}

static void work_messages_refresh_key_list_after_key_import(void *user) {
    (void)user;
    refresh_key_combo();
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
        show_error(hwnd, UI_TEXT_ENCRYPT_FAILED);
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
        show_error(hwnd, UI_TEXT_ENCRYPT_FAILED);
        return;
    }
    ctx->input = plain_w;
    ctx->topic = topic;
    set_textbox_overlay(g_textbox, UI_TEXT_ENCRYPT_OVERLAY, TRUE);
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
        show_error(hwnd, UI_TEXT_DECRYPT_FAILED);
        return;
    }
    if (clip[0] == L'\0') {
        xfree(clip);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_DECRYPT, hwnd, g_textbox);
    if (!ctx) {
        xfree(clip);
        show_error(hwnd, UI_TEXT_DECRYPT_FAILED);
        return;
    }
    ctx->input = clip;
    set_textbox_overlay(g_textbox, UI_TEXT_DECRYPT_OVERLAY, TRUE);
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void layout_main(HWND hwnd, int width, int height) {
    int margin = UI_MAIN_MARGIN;
    int gap = UI_MAIN_GAP;
    int combo_h = UI_MAIN_COMBO_HEIGHT;
    int topic_h = UI_MAIN_TOPIC_HEIGHT;
    int button_h = UI_MAIN_BUTTON_HEIGHT;
    int topic_y = margin + combo_h + gap;
    int edit_y = topic_y + topic_h + gap;
    int edit_h = height - edit_y - gap - button_h - margin;
    if (edit_h < UI_MAIN_MIN_EDIT_HEIGHT) edit_h = UI_MAIN_MIN_EDIT_HEIGHT;
    int button_y = edit_y + edit_h + gap;
    int button_w = (width - margin * 2 - gap * 3) / 4;
    if (button_w < UI_MAIN_MIN_BUTTON_WIDTH) button_w = UI_MAIN_MIN_BUTTON_WIDTH;

    MoveWindow(g_key_select, margin, margin, width - margin * 2, UI_MAIN_COMBO_DROPDOWN_HEIGHT, TRUE);
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

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_APP_WORK_UPDATE:
    case WM_APP_WORK_DONE:
    case WM_APP_WORK_ERROR:
    case WM_APP_WORK_CANCELLED: {
        UI_WORK_MESSAGE_HOST host;
        ZeroMemory(&host, sizeof(host));
        host.set_textbox_overlay = work_messages_set_overlay;
        host.show_error = work_messages_show_error;
        host.reload_crypto_after_key_import = work_messages_reload_crypto_after_key_import;
        host.refresh_key_list_after_key_import = work_messages_refresh_key_list_after_key_import;
        return ui_work_handle_message(hwnd, msg, wparam, lparam, &host);
    }
    case WM_CREATE: {
        g_key_select = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_SELECT, g_instance, NULL);
        g_topic_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_TOPIC, g_instance, NULL);
        SendMessageW(g_topic_edit, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_TOPIC_CUE);
        g_textbox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_TEXTBOX, g_instance, NULL);
        SendMessageW(g_textbox, EM_SETLIMITTEXT, APP_MAX_EDIT_TEXT_CHARS, 0);
        g_text_overlay = ui_overlay_create(g_textbox, g_instance, IDC_TEXT_OVERLAY);

        HWND encrypt = CreateWindowExW(0, L"BUTTON", UI_TEXT_ENCRYPT, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_ENCRYPT, g_instance, NULL);
        HWND decrypt = CreateWindowExW(0, L"BUTTON", UI_TEXT_DECRYPT, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_DECRYPT, g_instance, NULL);
        HWND clear = CreateWindowExW(0, L"BUTTON", UI_TEXT_ARCHIVE, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_CLEAR, g_instance, NULL);
        HWND key_transfer = CreateWindowExW(0, L"BUTTON", UI_TEXT_IMPORT_EXPORT_KEY,
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
        mmi->ptMinTrackSize.x = UI_MAIN_MIN_TRACK_WIDTH;
        mmi->ptMinTrackSize.y = UI_MAIN_MIN_TRACK_HEIGHT;
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
                        show_error(hwnd, err[0] ? err : UI_TEXT_SWITCH_KEY_FAILED);
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
            show_key_transfer(hwnd);
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
    wc.lpszClassName = APP_MAIN_WINDOW_CLASS_NAME;
    if (!RegisterClassExW(&wc)) return FALSE;

    if (!ui_overlay_register_class(g_instance)) return FALSE;
    return ui_key_transfer_register_class(g_instance);
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
        g_ui_font = CreateFontW(UI_FONT_FALLBACK_HEIGHT, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    WCHAR err[256] = L"";
    if (!profiles_load(err, ARRAYSIZE(err))) {
        MessageBoxW(NULL, err, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!activate_profile(profiles_active_index(), NULL, err, ARRAYSIZE(err))) {
        profiles_shutdown();
        MessageBoxW(NULL, err, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!register_windows()) {
        close_active_crypto();
        profiles_shutdown();
        MessageBoxW(NULL, UI_TEXT_WINDOW_INIT_FAILED, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }

    g_main_window = CreateWindowExW(0, APP_MAIN_WINDOW_CLASS_NAME, CIA_APP_TITLE,
                                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                    CW_USEDEFAULT, CW_USEDEFAULT, UI_MAIN_INITIAL_WIDTH, UI_MAIN_INITIAL_HEIGHT,
                                    NULL, NULL, instance, NULL);
    if (!g_main_window) {
        close_active_crypto();
        profiles_shutdown();
        MessageBoxW(NULL, UI_TEXT_WINDOW_INIT_FAILED, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    configure_app_work(g_main_window);

    ShowWindow(g_main_window, show);
    UpdateWindow(g_main_window);
    start_local_llm_background();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (ui_key_transfer_translate_message(&msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_llm_cleanup();
    close_active_crypto();
    profiles_shutdown();
    if (g_ui_font) DeleteObject(g_ui_font);
    return (int)msg.wParam;
}
