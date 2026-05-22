#include "ui_tray.h"

#include "app_constants.h"
#include "ui_ids.h"
#include "ui_strings.h"

#include <shellapi.h>
#include <strsafe.h>

#define UI_TRAY_UID 1
#define UI_TRAY_FLASH_TIMER_ID 41
#define UI_TRAY_FLASH_INTERVAL_MS 500

static BOOL g_tray_added;
static BOOL g_tray_pending;
static BOOL g_tray_flash_on;
static HICON g_tray_icon_normal;
static HICON g_tray_icon_pending;

static void fill_tray_data(HWND hwnd, NOTIFYICONDATAW *nid) {
    ZeroMemory(nid, sizeof(*nid));
    nid->cbSize = sizeof(*nid);
    nid->hWnd = hwnd;
    nid->uID = UI_TRAY_UID;
    nid->uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid->uCallbackMessage = WM_APP_TRAY;
    nid->hIcon = g_tray_pending && g_tray_flash_on ? g_tray_icon_pending : g_tray_icon_normal;
    StringCchCopyW(nid->szTip, ARRAYSIZE(nid->szTip),
                   g_tray_pending ? UI_TEXT_TRAY_PENDING : UI_TEXT_TRAY_READY);
}

static void update_tray(HWND hwnd) {
    if (!g_tray_added) return;
    NOTIFYICONDATAW nid;
    fill_tray_data(hwnd, &nid);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void show_tray_menu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    if (g_tray_pending) {
        AppendMenuW(menu, MF_STRING, IDC_TRAY_DECRYPT_OPEN, UI_TEXT_TRAY_DECRYPT_OPEN);
        AppendMenuW(menu, MF_STRING, IDC_TRAY_IGNORE, UI_TEXT_TRAY_IGNORE);
        AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
    }
    AppendMenuW(menu, MF_STRING, IDC_TRAY_OPEN, UI_TEXT_TRAY_OPEN);
    AppendMenuW(menu, MF_STRING, IDC_TRAY_EXIT, UI_TEXT_TRAY_EXIT);

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(menu);
}

BOOL ui_tray_init(HWND hwnd, HINSTANCE instance) {
    (void)instance;
    g_tray_icon_normal = LoadIconW(NULL, IDI_APPLICATION);
    g_tray_icon_pending = LoadIconW(NULL, IDI_INFORMATION);
    NOTIFYICONDATAW nid;
    fill_tray_data(hwnd, &nid);
    g_tray_added = Shell_NotifyIconW(NIM_ADD, &nid);
    if (g_tray_added) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
    return g_tray_added;
}

void ui_tray_shutdown(HWND hwnd) {
    KillTimer(hwnd, UI_TRAY_FLASH_TIMER_ID);
    if (g_tray_added) {
        NOTIFYICONDATAW nid;
        fill_tray_data(hwnd, &nid);
        Shell_NotifyIconW(NIM_DELETE, &nid);
    }
    g_tray_added = FALSE;
    g_tray_pending = FALSE;
    g_tray_flash_on = FALSE;
}

void ui_tray_set_pending(HWND hwnd, BOOL pending) {
    g_tray_pending = pending;
    g_tray_flash_on = pending;
    if (pending) {
        SetTimer(hwnd, UI_TRAY_FLASH_TIMER_ID, UI_TRAY_FLASH_INTERVAL_MS, NULL);
    } else {
        KillTimer(hwnd, UI_TRAY_FLASH_TIMER_ID);
    }
    update_tray(hwnd);
}

BOOL ui_tray_handle_message(HWND hwnd, WPARAM wparam, LPARAM lparam) {
    if ((UINT)wparam != UI_TRAY_UID) return FALSE;
    switch (LOWORD(lparam)) {
    case WM_LBUTTONUP:
    case NIN_SELECT:
        PostMessageW(hwnd, WM_COMMAND,
                     MAKEWPARAM(g_tray_pending ? IDC_TRAY_DECRYPT_OPEN : IDC_TRAY_OPEN, 0), 0);
        return TRUE;
    case WM_RBUTTONUP:
    case WM_CONTEXTMENU:
        show_tray_menu(hwnd);
        return TRUE;
    default:
        return TRUE;
    }
}

BOOL ui_tray_handle_timer(HWND hwnd, WPARAM wparam) {
    if (wparam != UI_TRAY_FLASH_TIMER_ID) return FALSE;
    if (!g_tray_pending) {
        KillTimer(hwnd, UI_TRAY_FLASH_TIMER_ID);
        return TRUE;
    }
    g_tray_flash_on = !g_tray_flash_on;
    update_tray(hwnd);
    return TRUE;
}
