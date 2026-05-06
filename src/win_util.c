#include "win_util.h"
#include "app_shared.h"

#include <strsafe.h>

WCHAR *win_dup_wide(const WCHAR *text) {
    size_t len = wcslen(text ? text : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, text ? text : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

WCHAR *win_get_window_text_alloc(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    WCHAR *window_text = (WCHAR *)xalloc(((SIZE_T)len + 1) * sizeof(WCHAR));
    if (!window_text) return NULL;
    GetWindowTextW(hwnd, window_text, len + 1);
    return window_text;
}

BOOL win_get_clipboard_text(HWND owner, WCHAR **out) {
    *out = NULL;
    if (!OpenClipboard(owner)) return FALSE;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) {
        CloseClipboard();
        return FALSE;
    }
    WCHAR *src = (WCHAR *)GlobalLock(h);
    if (!src) {
        CloseClipboard();
        return FALSE;
    }
    size_t len = wcslen(src);
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) {
        GlobalUnlock(h);
        CloseClipboard();
        return FALSE;
    }
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, src, (len + 1) * sizeof(WCHAR));
    GlobalUnlock(h);
    CloseClipboard();
    *out = copy;
    return copy != NULL;
}

void win_show_error(HWND owner, const WCHAR *title, const WCHAR *message) {
    MessageBoxW(owner, message, title, MB_ICONERROR | MB_OK);
}

void win_set_control_font(HWND hwnd, HFONT font) {
    if (!hwnd) return;
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)font, TRUE);
}
