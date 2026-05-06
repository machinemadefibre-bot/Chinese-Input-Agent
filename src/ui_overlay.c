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

#include "ui_overlay.h"
#include "app_shared.h"
#include "win_util.h"

#include <strsafe.h>

typedef struct OVERLAY_STATE {
    WCHAR *text;
    HFONT font;
} OVERLAY_STATE;

static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    OVERLAY_STATE *state = (OVERLAY_STATE *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_NCCREATE:
        state = (OVERLAY_STATE *)xalloc(sizeof(*state));
        if (!state) return FALSE;
        state->text = win_dup_wide(L"");
        if (!state->text) {
            xfree(state);
            return FALSE;
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);
        return TRUE;
    case WM_SETFONT:
        if (state) state->font = (HFONT)wparam;
        if (LOWORD(lparam)) RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
        return 0;
    case WM_SETTEXT: {
        if (!state) return FALSE;
        WCHAR *new_text = win_dup_wide((const WCHAR *)lparam);
        if (!new_text) return FALSE;
        secure_free_wide(state->text);
        state->text = new_text;
        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
        return TRUE;
    }
    case WM_GETTEXTLENGTH:
        return state && state->text ? (LRESULT)wcslen(state->text) : 0;
    case WM_GETTEXT: {
        WCHAR *out = (WCHAR *)lparam;
        int cch = (int)wparam;
        if (!out || cch <= 0) return 0;
        out[0] = L'\0';
        if (!state || !state->text) return 0;
        StringCchCopyW(out, (size_t)cch, state->text);
        return (LRESULT)wcslen(out);
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;
        if (w > 0 && h > 0) {
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
            HGDIOBJ old_bmp = SelectObject(mem, bmp);
            RECT local_rc = { 0, 0, w, h };
            HRGN clip = CreateRectRgn(0, 0, w, h);
            if (clip) {
                SelectClipRgn(mem, clip);
                DeleteObject(clip);
            }
            HBRUSH bg = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
            FillRect(mem, &local_rc, bg);
            DeleteObject(bg);
            HFONT old_font = NULL;
            if (state && state->font) old_font = (HFONT)SelectObject(mem, state->font);
            SetBkMode(mem, TRANSPARENT);
            SetTextColor(mem, RGB(128, 128, 128));
            RECT text_rc = local_rc;
            DrawTextW(mem, state && state->text ? state->text : L"", -1, &text_rc,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            if (old_font) SelectObject(mem, old_font);
            BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old_bmp);
            DeleteObject(bmp);
            DeleteDC(mem);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_NCDESTROY:
        if (state) {
            secure_free_wide(state->text);
            xfree(state);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

BOOL ui_overlay_register_class(HINSTANCE instance) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = UI_OVERLAY_CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND ui_overlay_create(HWND parent, HINSTANCE instance, int control_id) {
    return CreateWindowExW(0, UI_OVERLAY_CLASS_NAME, L"",
                           WS_CHILD | WS_CLIPSIBLINGS,
                           0, 0, 0, 0, parent, (HMENU)(INT_PTR)control_id, instance, NULL);
}

void ui_overlay_layout(HWND overlay, HWND textbox) {
    if (!overlay || !textbox || !IsWindow(overlay) || !IsWindow(textbox)) return;
    RECT edit_rc;
    GetClientRect(textbox, &edit_rc);
    int overlay_w = edit_rc.right - edit_rc.left - 16;
    int overlay_h = edit_rc.bottom - edit_rc.top - 16;
    if (overlay_w < 1) overlay_w = 1;
    if (overlay_h < 1) overlay_h = 1;
    MoveWindow(overlay, 8, 8, overlay_w, overlay_h, TRUE);
    SetWindowPos(overlay, HWND_TOP, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

void ui_overlay_set_text(HWND overlay, const WCHAR *text, BOOL show) {
    if (!overlay || !IsWindow(overlay)) return;
    BOOL want_visible = show && text && text[0];
    SetWindowTextW(overlay, text ? text : L"");
    if (want_visible) {
        if (!IsWindowVisible(overlay)) ShowWindow(overlay, SW_SHOWNOACTIVATE);
        SetWindowPos(overlay, HWND_TOP, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        RedrawWindow(overlay, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
    } else if (IsWindowVisible(overlay)) {
        ShowWindow(overlay, SW_HIDE);
    }
}
