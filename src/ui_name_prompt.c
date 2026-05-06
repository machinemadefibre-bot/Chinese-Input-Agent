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

#include "ui_name_prompt.h"
#include "app_constants.h"
#include "ui_layout.h"
#include "ui_strings.h"
#include "win_util.h"

#include <strsafe.h>

#define IDC_NAME_EDIT 3001

typedef struct NAME_PROMPT_STATE {
    BOOL is_done;
    BOOL is_accepted;
    HFONT ui_font;
    UI_NAME_PROMPT_HOST host;
    WCHAR name[128];
} NAME_PROMPT_STATE;

static LRESULT CALLBACK NamePromptWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    NAME_PROMPT_STATE *state = (NAME_PROMPT_STATE *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lparam;
        state = (NAME_PROMPT_STATE *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);
        HWND label = CreateWindowExW(0, L"STATIC", UI_TEXT_NAME_PROMPT_LABEL, WS_CHILD | WS_VISIBLE,
                                     UI_NAME_LABEL_X, UI_NAME_LABEL_Y, UI_NAME_LABEL_WIDTH, UI_NAME_LABEL_HEIGHT,
                                     hwnd, NULL, cs->hInstance, NULL);
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", state->name,
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                    UI_NAME_EDIT_X, UI_NAME_EDIT_Y, UI_NAME_EDIT_WIDTH, UI_NAME_EDIT_HEIGHT,
                                    hwnd, (HMENU)IDC_NAME_EDIT, cs->hInstance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, ARRAYSIZE(state->name) - 1, 0);
        HWND ok_button = CreateWindowExW(0, L"BUTTON", UI_TEXT_OK, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                         UI_NAME_OK_X, UI_NAME_BUTTON_Y, UI_NAME_BUTTON_WIDTH, UI_NAME_BUTTON_HEIGHT,
                                         hwnd, (HMENU)IDOK, cs->hInstance, NULL);
        HWND cancel = CreateWindowExW(0, L"BUTTON", UI_TEXT_CANCEL, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      UI_NAME_CANCEL_X, UI_NAME_BUTTON_Y, UI_NAME_BUTTON_WIDTH, UI_NAME_BUTTON_HEIGHT,
                                      hwnd, (HMENU)IDCANCEL, cs->hInstance, NULL);
        HWND controls[] = { label, edit, ok_button, cancel };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) win_set_control_font(controls[i], state->ui_font);
        SetFocus(edit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == IDOK) {
            GetWindowTextW(GetDlgItem(hwnd, IDC_NAME_EDIT), state->name, ARRAYSIZE(state->name));
            if (state->name[0] == L'\0') StringCchCopyW(state->name, ARRAYSIZE(state->name), UI_TEXT_DEFAULT_IMPORT_KEY_NAME);
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
        if (state && state->host.on_close) state->host.on_close(state->host.user);
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (state) state->is_done = TRUE;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL ensure_name_prompt_class(HINSTANCE instance) {
    static BOOL registered;
    if (registered) return TRUE;
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = NamePromptWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = APP_NAME_PROMPT_WINDOW_CLASS_NAME;
    if (!RegisterClassExW(&wc)) return FALSE;
    registered = TRUE;
    return TRUE;
}

BOOL ui_prompt_key_name(HINSTANCE instance, HWND owner, HFONT ui_font,
                        const UI_NAME_PROMPT_HOST *host, WCHAR *name, size_t name_cch) {
    if (!ensure_name_prompt_class(instance)) return FALSE;
    NAME_PROMPT_STATE state;
    ZeroMemory(&state, sizeof(state));
    state.ui_font = ui_font;
    if (host) state.host = *host;
    StringCchCopyW(state.name, ARRAYSIZE(state.name), UI_TEXT_DEFAULT_IMPORT_KEY_NAME);
    HWND win = CreateWindowExW(WS_EX_TOOLWINDOW, APP_NAME_PROMPT_WINDOW_CLASS_NAME,
                               UI_TEXT_DEFAULT_IMPORT_KEY_NAME, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                               CW_USEDEFAULT, CW_USEDEFAULT, UI_NAME_WINDOW_WIDTH, UI_NAME_WINDOW_HEIGHT,
                               owner, NULL, instance, &state);
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
    StringCchCopyW(name, name_cch, state.name);
    return TRUE;
}
