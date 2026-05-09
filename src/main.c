#include <windows.h>
#include <commctrl.h>

#include "app_constants.h"
#include "app_limits.h"
#include "app_shared.h"
#include "app_llm.h"
#include "app_profiles.h"
#include "app_groups.h"
#include "app_archive.h"
#include "app_flow.h"
#include "app_tokenizer_prefs.h"
#include "app_work.h"
#include "ui_overlay.h"
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
static HWND g_key_aux_edit;
static HFONT g_ui_font;
static BOOL g_archive_mode;
static CRYPTO_BOX *g_active_box;
static HWND g_overlay_clear_textbox;
static BOOL g_selected_group;
static int g_selected_group_index = -1;

typedef enum MAIN_VIEW_MODE {
    MAIN_VIEW_CHAT = 0,
    MAIN_VIEW_KEY_CHOOSER,
    MAIN_VIEW_PRIVATE_KEY_EXCHANGE,
    MAIN_VIEW_GROUP_KEY_EXCHANGE
} MAIN_VIEW_MODE;

typedef enum GROUP_KEY_MODE {
    GROUP_KEY_JOIN_CREATE = 0,
    GROUP_KEY_ALIAS
} GROUP_KEY_MODE;

static MAIN_VIEW_MODE g_main_view_mode = MAIN_VIEW_CHAT;
static GROUP_KEY_MODE g_group_key_mode = GROUP_KEY_JOIN_CREATE;

static const UINT_PTR TEXTBOX_OVERLAY_CLEAR_TIMER_ID = 1;
static const LPARAM KEY_COMBO_GROUP_FLAG = 0x10000;

static void set_control_font(HWND hwnd);
static void show_error(HWND owner, const WCHAR *message);
static void do_archive(HWND hwnd);
static void do_key_exchange_import(HWND hwnd);
static void do_key_exchange_export(HWND hwnd);
static void do_key_exchange_create_group(HWND hwnd);
static void do_group_alias_update(HWND hwnd, BOOL restore_default);
static void enter_key_chooser_mode(void);
static void enter_private_key_exchange_mode(HWND owner);
static void enter_group_key_exchange_mode(void);
static void leave_key_exchange_mode(void);
static void show_archive_for_active_profile(void);
static void leave_archive_mode(void);
static void refresh_main_mode_controls(void);
static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show);
static void clear_textbox_overlay_later(HWND textbox);
static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit);
static CRYPTO_BOX *get_active_box_for_work(void *user);
static void set_work_busy(void *user, BOOL busy);
static void show_work_error(void *user, HWND owner, const WCHAR *message);
static void configure_app_work(HWND main_window);
static BOOL save_chat_plaintext(int profile_index, const WCHAR *sender, const WCHAR *plain,
                                WCHAR *err, size_t err_cch);
static BOOL save_group_chat_plaintext(int group_index, const WCHAR *sender, const WCHAR *plain,
                                      WCHAR *err, size_t err_cch);
static void layout_main(HWND hwnd, int width, int height);

static LPARAM make_profile_item_data(int profile_index) {
    return (LPARAM)profile_index;
}

static LPARAM make_group_item_data(int group_index) {
    return KEY_COMBO_GROUP_FLAG | (LPARAM)group_index;
}

static BOOL combo_item_is_group(LPARAM item_data) {
    return (item_data & KEY_COMBO_GROUP_FLAG) != 0;
}

static int combo_item_index(LPARAM item_data) {
    return (int)(item_data & ~KEY_COMBO_GROUP_FLAG);
}

static void refresh_key_combo(void) {
    if (!g_key_select) return;
    BOOL want_group = g_selected_group;
    int wanted_group = g_selected_group_index;
    int wanted_profile = profiles_active_index();
    SendMessageW(g_key_select, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < profiles_count(); ++i) {
        WCHAR profile_name[128] = L"";
        profiles_get_name_copy(i, profile_name, ARRAYSIZE(profile_name));
        LRESULT item = SendMessageW(g_key_select, CB_ADDSTRING, 0, (LPARAM)profile_name);
        if (item >= 0) SendMessageW(g_key_select, CB_SETITEMDATA, (WPARAM)item, make_profile_item_data(i));
    }
    for (int i = 0; i < app_groups_count(); ++i) {
        WCHAR display_name[160] = L"";
        if (!app_groups_get_display_name(i, display_name, ARRAYSIZE(display_name))) continue;
        LRESULT item = SendMessageW(g_key_select, CB_ADDSTRING, 0, (LPARAM)display_name);
        if (item >= 0) SendMessageW(g_key_select, CB_SETITEMDATA, (WPARAM)item, make_group_item_data(i));
    }
    int combo_count = (int)SendMessageW(g_key_select, CB_GETCOUNT, 0, 0);
    int selection = -1;
    for (int item_idx = 0; item_idx < combo_count; ++item_idx) {
        LPARAM item_data = SendMessageW(g_key_select, CB_GETITEMDATA, (WPARAM)item_idx, 0);
        if (want_group && combo_item_is_group(item_data) && combo_item_index(item_data) == wanted_group) {
            selection = item_idx;
            break;
        }
        if (!want_group && !combo_item_is_group(item_data) && combo_item_index(item_data) == wanted_profile) {
            selection = item_idx;
            break;
        }
    }
    if (selection >= 0) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)selection, 0);
}

static void close_active_crypto(void) {
    app_work_clear_key_export_cache();
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
    g_selected_group = FALSE;
    g_selected_group_index = -1;
    profiles_lock_inactive_masters();
    refresh_key_combo();
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
    g_selected_group = FALSE;
    g_selected_group_index = -1;
    profiles_lock_inactive_masters();
    refresh_key_combo();
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
    if (g_selected_group) {
        WCHAR err[256] = L"";
        WCHAR *archive = NULL;
        if (!app_groups_archive_load_text(g_selected_group_index, &archive, err, ARRAYSIZE(err))) {
            show_error(g_main_window, err[0] ? err : UI_TEXT_ARCHIVE_FAILED);
            return;
        }
        set_textbox_overlay(g_textbox, NULL, FALSE);
        SetWindowTextW(g_textbox, archive ? archive : L"");
        SendMessageW(g_textbox, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
        SendMessageW(g_textbox, EM_SCROLLCARET, 0, 0);
        secure_free_wide(archive);
        return;
    }
    int profile_index = profiles_active_index();
    if (profile_index < 0) {
        SetWindowTextW(g_textbox, L"");
        return;
    }
    WCHAR err[256] = L"";
    WCHAR *archive = NULL;
    if (!archive_load_text(profile_index, &archive, err, ARRAYSIZE(err))) {
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
    BOOL private_exchange = g_main_view_mode == MAIN_VIEW_PRIVATE_KEY_EXCHANGE;
    BOOL group_exchange = g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE;
    BOOL exchange_mode = private_exchange || group_exchange;
    BOOL chooser_mode = g_main_view_mode == MAIN_VIEW_KEY_CHOOSER;
    HWND encrypt = GetDlgItem(g_main_window, IDC_ENCRYPT);
    HWND decrypt = GetDlgItem(g_main_window, IDC_DECRYPT);
    HWND archive = GetDlgItem(g_main_window, IDC_CLEAR);
    HWND key_transfer = GetDlgItem(g_main_window, IDC_KEY_TRANSFER);
    HWND group_choice = GetDlgItem(g_main_window, IDC_KEY_TRANSFER_GROUP);
    HWND private_choice = GetDlgItem(g_main_window, IDC_KEY_TRANSFER_PRIVATE);
    if (archive) {
        if (group_exchange) SetWindowTextW(archive, UI_TEXT_SET_GROUP_ALIAS);
        else if (private_exchange) SetWindowTextW(archive, UI_TEXT_ARCHIVE);
        else SetWindowTextW(archive, g_archive_mode ? UI_TEXT_BACK : UI_TEXT_ARCHIVE);
    }
    if (g_textbox) SendMessageW(g_textbox, EM_SETREADONLY, g_archive_mode ? TRUE : FALSE, 0);
    if (g_topic_edit) {
        const WCHAR *cue = UI_TEXT_TOPIC_CUE;
        if (private_exchange) cue = UI_TEXT_CONTACT_NAME_CUE;
        else if (group_exchange) {
            cue = g_group_key_mode == GROUP_KEY_ALIAS ?
                  UI_TEXT_GROUP_MEMBER_LOOKUP_CUE : UI_TEXT_GROUP_LOCAL_NAME_CUE;
        }
        SendMessageW(g_topic_edit, EM_SETCUEBANNER, TRUE, (LPARAM)cue);
        EnableWindow(g_topic_edit, !busy && !g_archive_mode && !chooser_mode);
    }
    if (g_key_aux_edit) {
        SendMessageW(g_key_aux_edit, EM_SETCUEBANNER, TRUE,
                     (LPARAM)(g_group_key_mode == GROUP_KEY_ALIAS ?
                              UI_TEXT_GROUP_MEMBER_ALIAS_CUE : UI_TEXT_GROUP_NICKNAME_CUE));
        ShowWindow(g_key_aux_edit, group_exchange ? SW_SHOW : SW_HIDE);
        EnableWindow(g_key_aux_edit, !busy && group_exchange);
    }
    if (encrypt) {
        EnableWindow(encrypt, !g_archive_mode);
        if (busy && !g_archive_mode) SetWindowTextW(encrypt, UI_TEXT_STOP);
        else if (group_exchange) {
            SetWindowTextW(encrypt, g_group_key_mode == GROUP_KEY_ALIAS ?
                           UI_TEXT_CONFIRM_CHANGE : UI_TEXT_JOIN_GROUP);
        } else {
            SetWindowTextW(encrypt, private_exchange ? UI_TEXT_IMPORT : UI_TEXT_ENCRYPT);
        }
    }
    if (decrypt) {
        if (group_exchange) {
            SetWindowTextW(decrypt, g_group_key_mode == GROUP_KEY_ALIAS ?
                           UI_TEXT_RESTORE_DEFAULT : UI_TEXT_CREATE_GROUP);
        } else {
            SetWindowTextW(decrypt, private_exchange ? UI_TEXT_EXPORT : UI_TEXT_DECRYPT);
        }
        EnableWindow(decrypt, !busy && !g_archive_mode && !chooser_mode);
    }
    if (archive) EnableWindow(archive, !busy && !chooser_mode && (!exchange_mode || group_exchange));
    if (g_key_select) EnableWindow(g_key_select, !busy && !chooser_mode && (!exchange_mode || group_exchange));
    if (key_transfer) {
        ShowWindow(key_transfer, chooser_mode ? SW_HIDE : SW_SHOW);
        SetWindowTextW(key_transfer, exchange_mode ? UI_TEXT_RETURN : UI_TEXT_IMPORT_EXPORT_KEY);
        EnableWindow(key_transfer, !busy && !g_archive_mode);
    }
    if (group_choice) {
        ShowWindow(group_choice, chooser_mode ? SW_SHOW : SW_HIDE);
        EnableWindow(group_choice, !busy && chooser_mode);
    }
    if (private_choice) {
        ShowWindow(private_choice, chooser_mode ? SW_SHOW : SW_HIDE);
        EnableWindow(private_choice, !busy && chooser_mode);
    }
    if (g_main_window) {
        RECT rc;
        if (GetClientRect(g_main_window, &rc)) layout_main(g_main_window, rc.right - rc.left, rc.bottom - rc.top);
    }
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
    (void)hwnd;
    if (g_archive_mode) {
        leave_archive_mode();
        return;
    }
    enter_archive_mode();
}

static void set_busy_controls(BOOL busy) {
    if (g_main_window && IsWindow(g_main_window)) {
        refresh_main_mode_controls();
    }
}

static HWND overlay_for_textbox(HWND textbox) {
    if (textbox && textbox == g_textbox) return g_text_overlay;
    return NULL;
}

static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show) {
    HWND overlay = overlay_for_textbox(textbox);
    ui_overlay_set_text(overlay, text, show);
}

static void clear_textbox_overlay_later(HWND textbox) {
    if (!g_main_window || !IsWindow(g_main_window) || !textbox || !IsWindow(textbox)) return;
    g_overlay_clear_textbox = textbox;
    SetTimer(g_main_window, TEXTBOX_OVERLAY_CLEAR_TIMER_ID, UI_OVERLAY_TRANSIENT_CLEAR_MS, NULL);
}

static void show_error(HWND owner, const WCHAR *message) {
    win_show_error(owner, CIA_APP_TITLE, message);
}

static void enter_key_chooser_mode(void) {
    if (g_archive_mode) return;
    g_main_view_mode = MAIN_VIEW_KEY_CHOOSER;
    refresh_main_mode_controls();
}

static void enter_private_key_exchange_mode(HWND owner) {
    if (g_archive_mode) return;
    if (!g_active_box) {
        WCHAR err[256] = L"";
        if (!reload_active_crypto(err, ARRAYSIZE(err))) {
            show_error(owner, err[0] ? err : UI_TEXT_SWITCH_KEY_FAILED);
            return;
        }
    }
    g_main_view_mode = MAIN_VIEW_PRIVATE_KEY_EXCHANGE;
    refresh_main_mode_controls();
}

static void enter_group_key_exchange_mode(void) {
    if (g_archive_mode) return;
    g_main_view_mode = MAIN_VIEW_GROUP_KEY_EXCHANGE;
    g_group_key_mode = GROUP_KEY_JOIN_CREATE;
    refresh_main_mode_controls();
}

static void leave_key_exchange_mode(void) {
    g_main_view_mode = MAIN_VIEW_CHAT;
    g_group_key_mode = GROUP_KEY_JOIN_CREATE;
    refresh_main_mode_controls();
}

static BOOL read_exchange_name(HWND edit, WCHAR **out) {
    *out = win_get_window_text_alloc(edit);
    return *out != NULL;
}

static BOOL exchange_kind_matches_current_mode(APP_FLOW_EXCHANGE_KIND exchange_kind) {
    return (g_main_view_mode == MAIN_VIEW_PRIVATE_KEY_EXCHANGE && exchange_kind == APP_FLOW_EXCHANGE_CONTACT) ||
           (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE && exchange_kind == APP_FLOW_EXCHANGE_GROUP);
}

static void do_key_exchange_import(HWND hwnd) {
    WCHAR *text = win_get_window_text_alloc(g_textbox);
    if (!text) {
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    WCHAR *body = NULL;
    WCHAR fingerprint[32] = L"";
    APP_FLOW_EXCHANGE_KIND exchange_kind = APP_FLOW_EXCHANGE_CONTACT;
    WCHAR err[256] = L"";
    if (!app_flow_extract_exchange_body(text, &exchange_kind, &body, fingerprint, ARRAYSIZE(fingerprint),
                                        err, ARRAYSIZE(err)) ||
        !exchange_kind_matches_current_mode(exchange_kind)) {
        secure_free_wide(text);
        secure_free_wide(body);
        show_error(hwnd, err[0] ? err : UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    if (exchange_kind == APP_FLOW_EXCHANGE_CONTACT && profiles_count() >= APP_PROFILE_MAX_PROFILES) {
        secure_free_wide(text);
        secure_free_wide(body);
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    WCHAR *name = NULL;
    WCHAR *group_name = NULL;
    HWND name_edit = exchange_kind == APP_FLOW_EXCHANGE_CONTACT ? g_topic_edit : g_key_aux_edit;
    if (!read_exchange_name(name_edit, &name)) {
        secure_free_wide(text);
        secure_free_wide(body);
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    if (exchange_kind == APP_FLOW_EXCHANGE_GROUP && !read_exchange_name(g_topic_edit, &group_name)) {
        secure_free_wide(name);
        secure_free_wide(text);
        secure_free_wide(body);
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }

    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_IMPORT_KEY, hwnd, g_textbox);
    if (!ctx) {
        secure_free_wide(group_name);
        secure_free_wide(name);
        secure_free_wide(text);
        secure_free_wide(body);
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }
    ctx->input = body;
    ctx->name = win_dup_wide(name);
    ctx->topic = group_name;
    ctx->expected_fingerprint = win_dup_wide(fingerprint);
    if (!ctx->name || !ctx->expected_fingerprint) {
        app_work_free_ctx(ctx);
        secure_free_wide(name);
        secure_free_wide(text);
        show_error(hwnd, UI_TEXT_KEY_IMPORT_FAILED);
        return;
    }

    set_textbox_overlay(g_textbox,
                        exchange_kind == APP_FLOW_EXCHANGE_GROUP ?
                        UI_TEXT_GROUP_IMPORT_OVERLAY : UI_TEXT_KEY_IMPORT_OVERLAY,
                        TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        SetWindowTextW(g_textbox, text);
        app_work_free_ctx(ctx);
    }
    secure_free_wide(name);
    secure_free_wide(text);
}

static void do_key_exchange_export(HWND hwnd) {
    APP_WORK_KIND kind = APP_WORK_KIND_EXPORT_KEY;
    int group_index = -1;
    const WCHAR *overlay_text = UI_TEXT_KEY_EXPORT_OVERLAY;
    if (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
        group_index = g_selected_group ? g_selected_group_index : -1;
        if (group_index < 0) {
            show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
            return;
        }
        kind = APP_WORK_KIND_EXPORT_GROUP;
        overlay_text = UI_TEXT_GROUP_EXPORT_OVERLAY;
    } else if (!g_active_box) {
        WCHAR err[256] = L"";
        if (!reload_active_crypto(err, ARRAYSIZE(err))) {
            show_error(hwnd, err[0] ? err : UI_TEXT_KEY_EXPORT_FAILED);
            return;
        }
    }

    APP_WORK_CTX *ctx = app_work_alloc(kind, hwnd, g_textbox);
    if (!ctx) {
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->group_index = group_index;
    set_textbox_overlay(g_textbox, overlay_text, TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_key_exchange_create_group(HWND hwnd) {
    if (g_main_view_mode != MAIN_VIEW_GROUP_KEY_EXCHANGE) return;
    WCHAR *group_name = NULL;
    WCHAR *self_name = NULL;
    if (!read_exchange_name(g_topic_edit, &group_name) ||
        !read_exchange_name(g_key_aux_edit, &self_name)) {
        secure_free_wide(group_name);
        secure_free_wide(self_name);
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_CREATE_GROUP, hwnd, g_textbox);
    if (!ctx) {
        secure_free_wide(group_name);
        secure_free_wide(self_name);
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->input = group_name;
    ctx->name = self_name;
    set_textbox_overlay(g_textbox, UI_TEXT_GROUP_CREATE_OVERLAY, TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
}

static void do_group_alias_update(HWND hwnd, BOOL restore_default) {
    if (g_main_view_mode != MAIN_VIEW_GROUP_KEY_EXCHANGE) return;
    int group_index = g_selected_group ? g_selected_group_index : -1;
    if (group_index < 0) {
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    WCHAR *lookup = NULL;
    WCHAR *alias = NULL;
    if (!read_exchange_name(g_topic_edit, &lookup) ||
        (!restore_default && !read_exchange_name(g_key_aux_edit, &alias))) {
        secure_free_wide(lookup);
        secure_free_wide(alias);
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    if (restore_default) {
        alias = win_dup_wide(L"");
        if (!alias) {
            secure_free_wide(lookup);
            show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
            return;
        }
    }
    APP_WORK_CTX *ctx = app_work_alloc(APP_WORK_KIND_SET_GROUP_ALIAS, hwnd, g_textbox);
    if (!ctx) {
        secure_free_wide(lookup);
        secure_free_wide(alias);
        show_error(hwnd, UI_TEXT_KEY_EXPORT_FAILED);
        return;
    }
    ctx->group_index = group_index;
    ctx->input = lookup;
    ctx->name = alias;
    set_textbox_overlay(g_textbox, UI_TEXT_GROUP_ALIAS_OVERLAY, TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!app_work_start(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        app_work_free_ctx(ctx);
    }
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

static void work_messages_clear_overlay_later(void *user, HWND textbox) {
    (void)user;
    clear_textbox_overlay_later(textbox);
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

static BOOL save_chat_plaintext(int profile_index, const WCHAR *sender, const WCHAR *plain,
                                WCHAR *err, size_t err_cch) {
    if (profile_index < 0 || profile_index >= profiles_count()) {
        set_error(err, err_cch, UI_TEXT_NO_ACTIVE_PROFILE);
        return FALSE;
    }
    return archive_append_text(profile_index, sender, plain, err, err_cch);
}

static BOOL save_group_chat_plaintext(int group_index, const WCHAR *sender, const WCHAR *plain,
                                      WCHAR *err, size_t err_cch) {
    return app_groups_archive_append_text(group_index, sender, plain, err, err_cch);
}

static BOOL work_messages_save_decrypted_plaintext(void *user, int profile_index, const WCHAR *plain,
                                                   WCHAR *err, size_t err_cch) {
    (void)user;
    WCHAR sender_name[128] = L"";
    const WCHAR *sender = NULL;
    if (profiles_get_name_copy(profile_index, sender_name, ARRAYSIZE(sender_name)) && sender_name[0]) {
        sender = sender_name;
    }
    return save_chat_plaintext(profile_index, sender, plain, err, err_cch);
}

static BOOL work_messages_save_decrypted_group_plaintext(void *user, int group_index,
                                                         const WCHAR *sender, const WCHAR *plain,
                                                         WCHAR *err, size_t err_cch) {
    (void)user;
    return save_group_chat_plaintext(group_index, sender, plain, err, err_cch);
}

static BOOL work_messages_save_sent_plaintext(void *user, int profile_index, const WCHAR *sender,
                                              const WCHAR *plain, WCHAR *err, size_t err_cch) {
    (void)user;
    return save_chat_plaintext(profile_index, sender, plain, err, err_cch);
}

static BOOL work_messages_save_sent_group_plaintext(void *user, int group_index,
                                                    const WCHAR *sender, const WCHAR *plain,
                                                    WCHAR *err, size_t err_cch) {
    (void)user;
    return save_group_chat_plaintext(group_index, sender, plain, err, err_cch);
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
    WCHAR *plain_for_history = win_dup_wide(plain_w);
    if (!plain_for_history) {
        secure_free_wide(plain_w);
        xfree(topic);
        show_error(hwnd, UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
        return;
    }
    APP_WORK_CTX *ctx = app_work_alloc(g_selected_group ? APP_WORK_KIND_GROUP_ENCRYPT : APP_WORK_KIND_ENCRYPT,
                                       hwnd, g_textbox);
    if (!ctx) {
        secure_free_wide(plain_for_history);
        secure_free_wide(plain_w);
        xfree(topic);
        show_error(hwnd, UI_TEXT_ENCRYPT_FAILED);
        return;
    }
    ctx->input = plain_w;
    ctx->topic = topic;
    ctx->group_index = g_selected_group ? g_selected_group_index : -1;
    ctx->sent_plaintext = plain_for_history;
    ctx->sent_profile_index = g_selected_group ? -1 : profiles_active_index();
    ctx->sent_group_index = g_selected_group ? g_selected_group_index : -1;
    if (!g_selected_group) {
        ctx->sent_sender = win_dup_wide(UI_TEXT_SENDER_SELF);
        if (!ctx->sent_sender) {
            app_work_free_ctx(ctx);
            show_error(hwnd, UI_TEXT_CHAT_HISTORY_SAVE_FAILED);
            return;
        }
    }
    plain_for_history = NULL;
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
    if (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE && g_key_aux_edit) {
        int input_w = (width - margin * 2 - gap) / 2;
        if (input_w < UI_MAIN_MIN_BUTTON_WIDTH) input_w = UI_MAIN_MIN_BUTTON_WIDTH;
        MoveWindow(g_topic_edit, margin, topic_y, input_w, topic_h, TRUE);
        MoveWindow(g_key_aux_edit, margin + input_w + gap, topic_y,
                   width - margin * 2 - input_w - gap, topic_h, TRUE);
    } else {
        MoveWindow(g_topic_edit, margin, topic_y, width - margin * 2, topic_h, TRUE);
        if (g_key_aux_edit) MoveWindow(g_key_aux_edit, margin, topic_y, width - margin * 2, topic_h, TRUE);
    }
    MoveWindow(g_textbox, margin, edit_y, width - margin * 2, edit_h, TRUE);
    ui_overlay_layout(g_text_overlay, g_textbox);
    MoveWindow(GetDlgItem(hwnd, IDC_ENCRYPT), margin, button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_DECRYPT), margin + (button_w + gap), button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_CLEAR), margin + (button_w + gap) * 2, button_y, button_w, button_h, TRUE);
    int key_x = margin + (button_w + gap) * 3;
    MoveWindow(GetDlgItem(hwnd, IDC_KEY_TRANSFER), key_x, button_y, button_w, button_h, TRUE);
    int split_gap = 4;
    int split_w = (button_w - split_gap) / 2;
    MoveWindow(GetDlgItem(hwnd, IDC_KEY_TRANSFER_GROUP), key_x, button_y, split_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_KEY_TRANSFER_PRIVATE), key_x + split_w + split_gap, button_y,
               button_w - split_w - split_gap, button_h, TRUE);
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
        host.clear_textbox_overlay_later = work_messages_clear_overlay_later;
        host.show_error = work_messages_show_error;
        host.reload_crypto_after_key_import = work_messages_reload_crypto_after_key_import;
        host.refresh_key_list_after_key_import = work_messages_refresh_key_list_after_key_import;
        host.save_decrypted_plaintext = work_messages_save_decrypted_plaintext;
        host.save_decrypted_group_plaintext = work_messages_save_decrypted_group_plaintext;
        host.save_sent_plaintext = work_messages_save_sent_plaintext;
        host.save_sent_group_plaintext = work_messages_save_sent_group_plaintext;
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
        g_key_aux_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                         WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_AUX, g_instance, NULL);
        SendMessageW(g_key_aux_edit, EM_SETCUEBANNER, TRUE, (LPARAM)UI_TEXT_GROUP_SELF_NAME_CUE);
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
        HWND key_group = CreateWindowExW(0, L"BUTTON", UI_TEXT_GROUP_CHAT,
                                         WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                                         0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TRANSFER_GROUP, g_instance, NULL);
        HWND key_private = CreateWindowExW(0, L"BUTTON", UI_TEXT_PRIVATE_CHAT,
                                           WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TRANSFER_PRIVATE, g_instance, NULL);
        HWND controls[] = { g_key_select, g_topic_edit, g_key_aux_edit, g_textbox, g_text_overlay,
                            encrypt, decrypt, clear, key_transfer, key_group, key_private };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        refresh_key_combo();
        refresh_main_mode_controls();
        break;
    }
    case WM_SIZE:
        layout_main(hwnd, LOWORD(lparam), HIWORD(lparam));
        return 0;
    case WM_TIMER:
        if (wparam == TEXTBOX_OVERLAY_CLEAR_TIMER_ID) {
            KillTimer(hwnd, TEXTBOX_OVERLAY_CLEAR_TIMER_ID);
            if (g_overlay_clear_textbox && IsWindow(g_overlay_clear_textbox) && !app_work_is_active()) {
                set_textbox_overlay(g_overlay_clear_textbox, NULL, FALSE);
            }
            g_overlay_clear_textbox = NULL;
            return 0;
        }
        break;
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
                LPARAM item_data = sel >= 0 ? SendMessageW(g_key_select, CB_GETITEMDATA, (WPARAM)sel, 0) : -1;
                if (sel >= 0 && combo_item_is_group(item_data)) {
                    g_selected_group = TRUE;
                    g_selected_group_index = combo_item_index(item_data);
                    close_active_crypto();
                    if (g_archive_mode) show_archive_for_active_profile();
                } else if (sel >= 0 && (g_selected_group || combo_item_index(item_data) != profiles_active_index())) {
                    int profile_index = combo_item_index(item_data);
                    WCHAR err[256] = L"";
                    if (!activate_profile(profile_index, hwnd, err, ARRAYSIZE(err))) {
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
            if (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE &&
                g_group_key_mode == GROUP_KEY_ALIAS) {
                do_group_alias_update(hwnd, FALSE);
                break;
            }
            if (g_main_view_mode == MAIN_VIEW_PRIVATE_KEY_EXCHANGE ||
                g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
                do_key_exchange_import(hwnd);
                break;
            }
            do_encrypt(hwnd);
            break;
        case IDC_DECRYPT:
            if (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
                if (g_group_key_mode == GROUP_KEY_ALIAS) {
                    do_group_alias_update(hwnd, TRUE);
                } else {
                    do_key_exchange_create_group(hwnd);
                }
                break;
            }
            if (g_main_view_mode == MAIN_VIEW_PRIVATE_KEY_EXCHANGE ||
                g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
                do_key_exchange_export(hwnd);
                break;
            }
            do_decrypt(hwnd);
            break;
        case IDC_CLEAR:
            if (g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
                g_group_key_mode = GROUP_KEY_ALIAS;
                SetWindowTextW(g_topic_edit, L"");
                SetWindowTextW(g_key_aux_edit, L"");
                refresh_main_mode_controls();
                break;
            }
            do_archive(hwnd);
            break;
        case IDC_KEY_TRANSFER:
            if (g_main_view_mode == MAIN_VIEW_PRIVATE_KEY_EXCHANGE ||
                g_main_view_mode == MAIN_VIEW_GROUP_KEY_EXCHANGE) {
                leave_key_exchange_mode();
            } else {
                enter_key_chooser_mode();
            }
            break;
        case IDC_KEY_TRANSFER_GROUP:
            enter_group_key_exchange_mode();
            break;
        case IDC_KEY_TRANSFER_PRIVATE:
            enter_private_key_exchange_mode(hwnd);
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

    return ui_overlay_register_class(g_instance);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev;
    (void)cmd;
    g_instance = instance;
    configure_app_work(NULL);
    app_llm_init(app_work_cancelled);

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
    if (!app_groups_load(err, ARRAYSIZE(err))) {
        profiles_shutdown();
        MessageBoxW(NULL, err, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!app_tokenizer_prefs_load(err, ARRAYSIZE(err))) {
        app_groups_shutdown();
        profiles_shutdown();
        MessageBoxW(NULL, err, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!activate_profile(profiles_active_index(), NULL, err, ARRAYSIZE(err))) {
        app_tokenizer_prefs_shutdown();
        app_groups_shutdown();
        profiles_shutdown();
        MessageBoxW(NULL, err, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!register_windows()) {
        close_active_crypto();
        app_tokenizer_prefs_shutdown();
        app_groups_shutdown();
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
        app_tokenizer_prefs_shutdown();
        app_groups_shutdown();
        profiles_shutdown();
        MessageBoxW(NULL, UI_TEXT_WINDOW_INIT_FAILED, CIA_APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    configure_app_work(g_main_window);
    refresh_main_mode_controls();

    ShowWindow(g_main_window, show);
    UpdateWindow(g_main_window);
    start_local_llm_background();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_llm_cleanup();
    close_active_crypto();
    app_tokenizer_prefs_shutdown();
    app_groups_shutdown();
    profiles_shutdown();
    if (g_ui_font) DeleteObject(g_ui_font);
    return (int)msg.wParam;
}
