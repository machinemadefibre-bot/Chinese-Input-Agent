#include "app_attachments.h"

#include "app_shared.h"

#include <commctrl.h>
#include <shellapi.h>
#include <strsafe.h>

#define ATTACHMENT_MAX 4
#define ATTACHMENT_SUBCLASS_ID 0x43494150u

static WCHAR *g_attachment_paths[ATTACHMENT_MAX];
static size_t g_attachment_count;

static BOOL is_image_path(const WCHAR *path) {
    const WCHAR *dot = path ? wcsrchr(path, L'.') : NULL;
    if (!dot) return FALSE;
    return _wcsicmp(dot, L".jpg") == 0 ||
           _wcsicmp(dot, L".jpeg") == 0 ||
           _wcsicmp(dot, L".png") == 0 ||
           _wcsicmp(dot, L".bmp") == 0 ||
           _wcsicmp(dot, L".gif") == 0 ||
           _wcsicmp(dot, L".tif") == 0 ||
           _wcsicmp(dot, L".tiff") == 0 ||
           _wcsicmp(dot, L".avif") == 0;
}

static const WCHAR *file_name_part(const WCHAR *path) {
    const WCHAR *slash1 = path ? wcsrchr(path, L'\\') : NULL;
    const WCHAR *slash2 = path ? wcsrchr(path, L'/') : NULL;
    const WCHAR *slash = slash1 > slash2 ? slash1 : slash2;
    return slash ? slash + 1 : (path ? path : L"");
}

static BOOL add_attachment_path(HWND edit, const WCHAR *path) {
    if (!edit || !path || !path[0] || !is_image_path(path) || g_attachment_count >= ATTACHMENT_MAX) return FALSE;
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;
    size_t len = wcslen(path);
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (!copy) return FALSE;
    CopyMemory(copy, path, (len + 1) * sizeof(WCHAR));
    g_attachment_paths[g_attachment_count++] = copy;

    WCHAR placeholder[MAX_PATH + 32];
    if (SUCCEEDED(StringCchPrintfW(placeholder, ARRAYSIZE(placeholder),
                                   L"\r\n[\u56fe\u7247: %s]\r\n", file_name_part(path)))) {
        SendMessageW(edit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
        SendMessageW(edit, EM_REPLACESEL, TRUE, (LPARAM)placeholder);
    }
    return TRUE;
}

static BOOL handle_hdrop(HWND edit, HDROP drop) {
    UINT count = DragQueryFileW(drop, 0xffffffffu, NULL, 0);
    BOOL handled = FALSE;
    for (UINT idx = 0; idx < count && g_attachment_count < ATTACHMENT_MAX; ++idx) {
        WCHAR path[MAX_PATH];
        if (DragQueryFileW(drop, idx, path, ARRAYSIZE(path)) &&
            add_attachment_path(edit, path)) {
            handled = TRUE;
        }
    }
    return handled;
}

static BOOL handle_clipboard_files(HWND edit) {
    BOOL handled = FALSE;
    if (!OpenClipboard(edit)) return FALSE;
    HANDLE hdrop = GetClipboardData(CF_HDROP);
    if (hdrop) handled = handle_hdrop(edit, (HDROP)hdrop);
    if (!handled) {
        HANDLE text_handle = GetClipboardData(CF_UNICODETEXT);
        if (text_handle) {
            const WCHAR *text = (const WCHAR *)GlobalLock(text_handle);
            if (text && is_image_path(text)) handled = add_attachment_path(edit, text);
            if (text) GlobalUnlock(text_handle);
        }
    }
    CloseClipboard();
    return handled;
}

static LRESULT CALLBACK attachment_subclass_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                                                 UINT_PTR subclass_id, DWORD_PTR ref_data) {
    (void)subclass_id;
    (void)ref_data;
    if (msg == WM_PASTE && handle_clipboard_files(hwnd)) return 0;
    if (msg == WM_DROPFILES) {
        BOOL handled = handle_hdrop(hwnd, (HDROP)wparam);
        DragFinish((HDROP)wparam);
        if (handled) return 0;
    }
    return DefSubclassProc(hwnd, msg, wparam, lparam);
}

BOOL app_attachments_install(HWND rich_edit) {
    if (!rich_edit) return FALSE;
    DragAcceptFiles(rich_edit, TRUE);
    return SetWindowSubclass(rich_edit, attachment_subclass_proc, ATTACHMENT_SUBCLASS_ID, 0);
}

void app_attachments_clear(void) {
    for (size_t idx = 0; idx < g_attachment_count; ++idx) {
        secure_free_wide(g_attachment_paths[idx]);
        g_attachment_paths[idx] = NULL;
    }
    g_attachment_count = 0;
}

BOOL app_attachments_has_pending(void) {
    return g_attachment_count > 0;
}

BOOL app_attachments_first_path(WCHAR *out, size_t cch) {
    if (!out || cch == 0) return FALSE;
    out[0] = L'\0';
    if (g_attachment_count == 0 || !g_attachment_paths[0]) return FALSE;
    return SUCCEEDED(StringCchCopyW(out, cch, g_attachment_paths[0]));
}

BOOL app_attachments_clipboard_image_path(HWND owner, WCHAR *out, size_t cch) {
    if (!out || cch == 0) return FALSE;
    out[0] = L'\0';
    BOOL found = FALSE;
    if (!OpenClipboard(owner)) return FALSE;
    HANDLE hdrop = GetClipboardData(CF_HDROP);
    if (hdrop) {
        UINT count = DragQueryFileW((HDROP)hdrop, 0xffffffffu, NULL, 0);
        for (UINT idx = 0; idx < count; ++idx) {
            WCHAR path[MAX_PATH];
            if (DragQueryFileW((HDROP)hdrop, idx, path, ARRAYSIZE(path)) && is_image_path(path)) {
                found = SUCCEEDED(StringCchCopyW(out, cch, path));
                break;
            }
        }
    }
    if (!found) {
        HANDLE text_handle = GetClipboardData(CF_UNICODETEXT);
        if (text_handle) {
            const WCHAR *text = (const WCHAR *)GlobalLock(text_handle);
            if (text && is_image_path(text)) found = SUCCEEDED(StringCchCopyW(out, cch, text));
            if (text) GlobalUnlock(text_handle);
        }
    }
    CloseClipboard();
    return found;
}
