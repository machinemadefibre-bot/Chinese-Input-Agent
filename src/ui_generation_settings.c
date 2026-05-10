#include "ui_generation_settings.h"

#include "app_paths.h"
#include "app_shared.h"
#include "ui_ids.h"
#include "ui_layout.h"
#include "ui_strings.h"
#include "win_util.h"

#include <commctrl.h>
#include <stdlib.h>
#include <strsafe.h>

typedef struct GENERATION_DIALOG_STATE {
    UI_GENERATION_SETTINGS *settings;
    HFONT ui_font;
    BOOL done;
    BOOL accepted;
} GENERATION_DIALOG_STATE;

static const WCHAR GENERATION_SETTINGS_CLASS_NAME[] = L"ChineseInputAgentGenerationSettings";

static int clamp_slider_value(int value, int min_value, int max_value) {
    if (value < min_value) return min_value;
    if (value > max_value) return max_value;
    return value;
}

static APP_CARRIER_REDUNDANCY_LEVEL clamp_redundancy(APP_CARRIER_REDUNDANCY_LEVEL level) {
    if (level < APP_CARRIER_REDUNDANCY_NONE || level > APP_CARRIER_REDUNDANCY_HIGH) {
        return APP_CARRIER_REDUNDANCY_NONE;
    }
    return level;
}

static WCHAR *dup_wide_or_null(const WCHAR *text) {
    if (!text || !text[0]) return NULL;
    size_t len = wcslen(text);
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, text, (len + 1) * sizeof(WCHAR));
    return copy;
}

void ui_generation_settings_init_defaults(UI_GENERATION_SETTINGS *settings) {
    if (!settings) return;
    ZeroMemory(settings, sizeof(*settings));
    settings->temperature = 0.70;
    settings->top_p = 0.80;
    settings->redundancy_level = APP_CARRIER_REDUNDANCY_NONE;
}

void ui_generation_settings_free(UI_GENERATION_SETTINGS *settings) {
    if (!settings) return;
    xfree(settings->custom_prompt);
    ZeroMemory(settings, sizeof(*settings));
}

static BOOL get_settings_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, APP_GENERATION_SETTINGS_FILE_NAME);
}

static BOOL get_prompt_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, APP_GENERATION_PROMPT_FILE_NAME);
}

static BOOL get_default_prompt_path(WCHAR *path, size_t cch) {
    WCHAR exe[MAX_PATH];
    WCHAR base[MAX_PATH];
    WCHAR tools[MAX_PATH];
    WCHAR prompts[MAX_PATH];
    if (!path || cch == 0 || !GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) return FALSE;
    strip_last_path_component_early(exe);
    if (join_path(tools, ARRAYSIZE(tools), exe, APP_WORKER_TOOLS_DIR) &&
        join_path(prompts, ARRAYSIZE(prompts), tools, L"prompts") &&
        join_path(path, cch, prompts, L"default.txt") &&
        file_exists_w(path)) {
        return TRUE;
    }
    if (join_path(base, ARRAYSIZE(base), exe, L"..\\tools\\payload_watermark\\prompts") &&
        join_path(path, cch, base, L"default.txt") &&
        file_exists_w(path)) {
        return TRUE;
    }
    if (join_path(base, ARRAYSIZE(base), exe, L"..\\..\\tools\\payload_watermark\\prompts") &&
        join_path(path, cch, base, L"default.txt") &&
        file_exists_w(path)) {
        return TRUE;
    }
    return FALSE;
}

static BOOL parse_double_line(const WCHAR *text, const WCHAR *key, double *out) {
    WCHAR pattern[64];
    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"%s=", key))) return FALSE;
    const WCHAR *p = wcsstr(text ? text : L"", pattern);
    if (!p) return FALSE;
    p += wcslen(pattern);
    WCHAR *end = NULL;
    double value = wcstod(p, &end);
    if (end == p) return FALSE;
    *out = value;
    return TRUE;
}

static BOOL parse_int_line(const WCHAR *text, const WCHAR *key, int *out) {
    WCHAR pattern[64];
    if (FAILED(StringCchPrintfW(pattern, ARRAYSIZE(pattern), L"%s=", key))) return FALSE;
    const WCHAR *p = wcsstr(text ? text : L"", pattern);
    if (!p) return FALSE;
    p += wcslen(pattern);
    WCHAR *end = NULL;
    long value = wcstol(p, &end, 10);
    if (end == p) return FALSE;
    *out = (int)value;
    return TRUE;
}

void ui_generation_settings_load(UI_GENERATION_SETTINGS *settings) {
    if (!settings) return;
    WCHAR path[MAX_PATH] = L"";
    WCHAR prompt_path[MAX_PATH] = L"";
    WCHAR default_prompt_path[MAX_PATH] = L"";
    WCHAR *config = NULL;
    WCHAR *prompt = NULL;
    ui_generation_settings_init_defaults(settings);
    if (get_settings_path(path, ARRAYSIZE(path)) && file_exists_w(path) &&
        read_utf8_text_file(path, &config)) {
        double value = 0.0;
        int int_value = 0;
        if (parse_double_line(config, L"temperature", &value) && value >= 0.10 && value <= 1.20) {
            settings->temperature = value;
        }
        if (parse_double_line(config, L"top_p", &value) && value >= 0.10 && value <= 1.00) {
            settings->top_p = value;
        }
        if (parse_int_line(config, L"redundancy", &int_value)) {
            settings->redundancy_level = clamp_redundancy((APP_CARRIER_REDUNDANCY_LEVEL)int_value);
        }
        settings->save_config = TRUE;
    }
    if (get_prompt_path(prompt_path, ARRAYSIZE(prompt_path)) && file_exists_w(prompt_path) &&
        read_utf8_text_file(prompt_path, &prompt)) {
        if (prompt[0]) {
            settings->custom_prompt = prompt;
            prompt = NULL;
        }
    }
    if (!settings->custom_prompt &&
        get_default_prompt_path(default_prompt_path, ARRAYSIZE(default_prompt_path)) &&
        read_utf8_text_file(default_prompt_path, &prompt)) {
        if (prompt[0]) {
            settings->custom_prompt = prompt;
            prompt = NULL;
        }
    }
    secure_free_wide(config);
    secure_free_wide(prompt);
}

static BOOL write_text_utf8_file_atomic(const WCHAR *path, const WCHAR *text) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(text ? text : L"", &utf8, &len)) return FALSE;
    BOOL write_succeeded = write_file_bytes_atomic(path, (const BYTE *)utf8, (DWORD)len);
    secure_free(utf8, (SIZE_T)len + 1);
    return write_succeeded;
}

static BOOL save_generation_settings(const UI_GENERATION_SETTINGS *settings) {
    WCHAR path[MAX_PATH] = L"";
    WCHAR prompt_path[MAX_PATH] = L"";
    WSTRB config = {0};
    if (!get_settings_path(path, ARRAYSIZE(path)) || !get_prompt_path(prompt_path, ARRAYSIZE(prompt_path))) {
        return FALSE;
    }
    if (!settings->save_config) {
        DeleteFileW(path);
        DeleteFileW(prompt_path);
        return TRUE;
    }
    if (!wstrb_appendf(&config, L"temperature=%.2f\r\ntop_p=%.2f\r\nredundancy=%d\r\n",
                       settings->temperature, settings->top_p, (int)settings->redundancy_level)) {
        wstrb_free(&config);
        return FALSE;
    }
    if (!write_text_utf8_file_atomic(path, config.data ? config.data : L"")) {
        wstrb_free(&config);
        return FALSE;
    }
    wstrb_free(&config);
    if (settings->custom_prompt && settings->custom_prompt[0]) {
        return write_text_utf8_file_atomic(prompt_path, settings->custom_prompt);
    }
    DeleteFileW(prompt_path);
    return TRUE;
}

static void set_dialog_font(HWND hwnd, HFONT font) {
    if (hwnd && font) SendMessageW(hwnd, WM_SETFONT, (WPARAM)font, TRUE);
}

static void update_slider_value_label(HWND hwnd, int slider_id, int label_id) {
    HWND slider = GetDlgItem(hwnd, slider_id);
    HWND label = GetDlgItem(hwnd, label_id);
    int value = (int)SendMessageW(slider, TBM_GETPOS, 0, 0);
    WCHAR text[32];
    if (SUCCEEDED(StringCchPrintfW(text, ARRAYSIZE(text), L"%.2f", (double)value / 100.0))) {
        SetWindowTextW(label, text);
    }
}

static void layout_generation_dialog(HWND hwnd, int width, int height) {
    int margin = UI_GEN_MARGIN;
    int gap = UI_GEN_GAP;
    int label_h = UI_GEN_LABEL_HEIGHT;
    int button_h = UI_GEN_BUTTON_HEIGHT;
    int y = margin;
    int content_w = width - margin * 2;
    int button_y = height - margin - button_h;
    int edit_h = button_y - margin - (label_h + gap) * 4 - UI_GEN_SLIDER_HEIGHT * 2 - UI_MAIN_TOPIC_HEIGHT - gap * 6;
    if (edit_h < UI_GEN_EDIT_HEIGHT / 2) edit_h = UI_GEN_EDIT_HEIGHT / 2;

    MoveWindow(GetDlgItem(hwnd, -1), margin, y, content_w, label_h, TRUE);
    y += label_h;
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_PROMPT_EDIT), margin, y, content_w, edit_h, TRUE);
    y += edit_h + gap;

    MoveWindow(GetDlgItem(hwnd, -2), margin, y, 90, label_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_TEMP_VALUE), width - margin - 60, y, 60, label_h, TRUE);
    y += label_h;
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_TEMP_SLIDER), margin, y, content_w, UI_GEN_SLIDER_HEIGHT, TRUE);
    y += UI_GEN_SLIDER_HEIGHT + gap;

    MoveWindow(GetDlgItem(hwnd, -3), margin, y, 90, label_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_TOPP_VALUE), width - margin - 60, y, 60, label_h, TRUE);
    y += label_h;
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_TOPP_SLIDER), margin, y, content_w, UI_GEN_SLIDER_HEIGHT, TRUE);
    y += UI_GEN_SLIDER_HEIGHT + gap;

    MoveWindow(GetDlgItem(hwnd, -4), margin, y, 90, label_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_REDUNDANCY), margin + 100, y - 2, 180, UI_MAIN_TOPIC_HEIGHT, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_GEN_SAVE_CONFIG), margin + 300, y, 160, label_h, TRUE);

    MoveWindow(GetDlgItem(hwnd, IDOK), width - margin - UI_GEN_BUTTON_WIDTH * 2 - gap, button_y,
               UI_GEN_BUTTON_WIDTH, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDCANCEL), width - margin - UI_GEN_BUTTON_WIDTH, button_y,
               UI_GEN_BUTTON_WIDTH, button_h, TRUE);
}

static WCHAR *read_prompt_edit(HWND hwnd) {
    HWND edit = GetDlgItem(hwnd, IDC_GEN_PROMPT_EDIT);
    int len = GetWindowTextLengthW(edit);
    if (len <= 0) return NULL;
    WCHAR *text = (WCHAR *)xalloc(((SIZE_T)len + 1) * sizeof(WCHAR));
    if (!text) return NULL;
    GetWindowTextW(edit, text, len + 1);
    return text;
}

static BOOL apply_dialog_values(HWND hwnd, GENERATION_DIALOG_STATE *state) {
    WCHAR *prompt = read_prompt_edit(hwnd);
    int temp_value = (int)SendMessageW(GetDlgItem(hwnd, IDC_GEN_TEMP_SLIDER), TBM_GETPOS, 0, 0);
    int top_p_value = (int)SendMessageW(GetDlgItem(hwnd, IDC_GEN_TOPP_SLIDER), TBM_GETPOS, 0, 0);
    int redundancy = (int)SendMessageW(GetDlgItem(hwnd, IDC_GEN_REDUNDANCY), CB_GETCURSEL, 0, 0);
    BOOL save_config = SendMessageW(GetDlgItem(hwnd, IDC_GEN_SAVE_CONFIG), BM_GETCHECK, 0, 0) == BST_CHECKED;
    xfree(state->settings->custom_prompt);
    state->settings->custom_prompt = prompt && prompt[0] ? prompt : NULL;
    if (prompt && !prompt[0]) xfree(prompt);
    state->settings->temperature = (double)clamp_slider_value(temp_value, 10, 120) / 100.0;
    state->settings->top_p = (double)clamp_slider_value(top_p_value, 10, 100) / 100.0;
    state->settings->redundancy_level = clamp_redundancy((APP_CARRIER_REDUNDANCY_LEVEL)redundancy);
    state->settings->save_config = save_config;
    return TRUE;
}

static LRESULT CALLBACK GenerationSettingsWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    GENERATION_DIALOG_STATE *state = (GENERATION_DIALOG_STATE *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lparam;
        state = (GENERATION_DIALOG_STATE *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);
        HWND prompt_label = CreateWindowExW(0, L"STATIC", UI_TEXT_GEN_PROMPT_LABEL, WS_CHILD | WS_VISIBLE,
                                            0, 0, 0, 0, hwnd, (HMENU)-1, cs->hInstance, NULL);
        HWND prompt_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
                                           state->settings->custom_prompt ? state->settings->custom_prompt : L"",
                                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL |
                                           ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_PROMPT_EDIT, cs->hInstance, NULL);
        HWND temp_label = CreateWindowExW(0, L"STATIC", UI_TEXT_GEN_TEMP_LABEL, WS_CHILD | WS_VISIBLE,
                                          0, 0, 0, 0, hwnd, (HMENU)-2, cs->hInstance, NULL);
        HWND temp_slider = CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBS_AUTOTICKS,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_TEMP_SLIDER, cs->hInstance, NULL);
        HWND temp_value = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_TEMP_VALUE, cs->hInstance, NULL);
        HWND top_p_label = CreateWindowExW(0, L"STATIC", UI_TEXT_GEN_TOPP_LABEL, WS_CHILD | WS_VISIBLE,
                                           0, 0, 0, 0, hwnd, (HMENU)-3, cs->hInstance, NULL);
        HWND top_p_slider = CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBS_AUTOTICKS,
                                            0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_TOPP_SLIDER, cs->hInstance, NULL);
        HWND top_p_value = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_RIGHT,
                                           0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_TOPP_VALUE, cs->hInstance, NULL);
        HWND redundancy_label = CreateWindowExW(0, L"STATIC", UI_TEXT_GEN_REDUNDANCY_LABEL, WS_CHILD | WS_VISIBLE,
                                                0, 0, 0, 0, hwnd, (HMENU)-4, cs->hInstance, NULL);
        HWND redundancy_combo = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                                                0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_REDUNDANCY, cs->hInstance, NULL);
        HWND save_check = CreateWindowExW(0, L"BUTTON", UI_TEXT_GEN_SAVE_CONFIG,
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_GEN_SAVE_CONFIG, cs->hInstance, NULL);
        HWND ok = CreateWindowExW(0, L"BUTTON", UI_TEXT_OK, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                  0, 0, 0, 0, hwnd, (HMENU)IDOK, cs->hInstance, NULL);
        HWND cancel = CreateWindowExW(0, L"BUTTON", UI_TEXT_CANCEL, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                      0, 0, 0, 0, hwnd, (HMENU)IDCANCEL, cs->hInstance, NULL);
        HWND controls[] = { prompt_label, prompt_edit, temp_label, temp_slider, temp_value,
                            top_p_label, top_p_slider, top_p_value, redundancy_label,
                            redundancy_combo, save_check, ok, cancel };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_dialog_font(controls[i], state->ui_font);
        SendMessageW(temp_slider, TBM_SETRANGE, TRUE, MAKELPARAM(10, 120));
        SendMessageW(temp_slider, TBM_SETPOS, TRUE, clamp_slider_value((int)(state->settings->temperature * 100.0 + 0.5), 10, 120));
        SendMessageW(top_p_slider, TBM_SETRANGE, TRUE, MAKELPARAM(10, 100));
        SendMessageW(top_p_slider, TBM_SETPOS, TRUE, clamp_slider_value((int)(state->settings->top_p * 100.0 + 0.5), 10, 100));
        SendMessageW(redundancy_combo, CB_ADDSTRING, 0, (LPARAM)UI_TEXT_REDUNDANCY_NONE);
        SendMessageW(redundancy_combo, CB_ADDSTRING, 0, (LPARAM)UI_TEXT_REDUNDANCY_LOW);
        SendMessageW(redundancy_combo, CB_ADDSTRING, 0, (LPARAM)UI_TEXT_REDUNDANCY_MEDIUM);
        SendMessageW(redundancy_combo, CB_ADDSTRING, 0, (LPARAM)UI_TEXT_REDUNDANCY_HIGH);
        SendMessageW(redundancy_combo, CB_SETCURSEL, (WPARAM)clamp_redundancy(state->settings->redundancy_level), 0);
        SendMessageW(save_check, BM_SETCHECK, state->settings->save_config ? BST_CHECKED : BST_UNCHECKED, 0);
        update_slider_value_label(hwnd, IDC_GEN_TEMP_SLIDER, IDC_GEN_TEMP_VALUE);
        update_slider_value_label(hwnd, IDC_GEN_TOPP_SLIDER, IDC_GEN_TOPP_VALUE);
        RECT rc;
        GetClientRect(hwnd, &rc);
        layout_generation_dialog(hwnd, rc.right - rc.left, rc.bottom - rc.top);
        break;
    }
    case WM_SIZE:
        layout_generation_dialog(hwnd, LOWORD(lparam), HIWORD(lparam));
        return 0;
    case WM_HSCROLL:
        update_slider_value_label(hwnd, IDC_GEN_TEMP_SLIDER, IDC_GEN_TEMP_VALUE);
        update_slider_value_label(hwnd, IDC_GEN_TOPP_SLIDER, IDC_GEN_TOPP_VALUE);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == IDOK) {
            if (state && apply_dialog_values(hwnd, state)) {
                state->accepted = TRUE;
                state->done = TRUE;
                DestroyWindow(hwnd);
            }
            return 0;
        }
        if (LOWORD(wparam) == IDCANCEL) {
            if (state) state->done = TRUE;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        if (state) state->done = TRUE;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL ensure_generation_settings_class(HINSTANCE instance) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = GenerationSettingsWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = GENERATION_SETTINGS_CLASS_NAME;
    return RegisterClassExW(&wc) || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

BOOL ui_generation_settings_show(HINSTANCE instance, HWND owner, HFONT ui_font,
                                 UI_GENERATION_SETTINGS *settings,
                                 WCHAR *err, size_t err_cch) {
    if (!instance || !settings || !ensure_generation_settings_class(instance)) {
        set_error(err, err_cch, UI_TEXT_GEN_SETTINGS_FAILED);
        return FALSE;
    }
    GENERATION_DIALOG_STATE state;
    ZeroMemory(&state, sizeof(state));
    state.settings = settings;
    state.ui_font = ui_font;
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, GENERATION_SETTINGS_CLASS_NAME,
                                UI_TEXT_GEN_SETTINGS_TITLE,
                                WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                UI_GEN_WINDOW_WIDTH, UI_GEN_WINDOW_HEIGHT,
                                owner, NULL, instance, &state);
    if (!hwnd) {
        set_error(err, err_cch, UI_TEXT_GEN_SETTINGS_FAILED);
        return FALSE;
    }
    if (owner) EnableWindow(owner, FALSE);
    MSG msg;
    while (!state.done) {
        BOOL got = GetMessageW(&msg, NULL, 0, 0);
        if (got == -1) {
            if (owner) EnableWindow(owner, TRUE);
            set_error(err, err_cch, UI_TEXT_GEN_SETTINGS_FAILED);
            return FALSE;
        }
        if (got == 0) {
            if (owner) EnableWindow(owner, TRUE);
            PostQuitMessage((int)msg.wParam);
            return FALSE;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (owner) {
        EnableWindow(owner, TRUE);
        SetForegroundWindow(owner);
    }
    if (!state.accepted) return TRUE;
    if (!save_generation_settings(settings)) {
        set_error(err, err_cch, UI_TEXT_GEN_SETTINGS_FAILED);
        return FALSE;
    }
    return TRUE;
}
