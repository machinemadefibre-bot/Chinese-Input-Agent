#ifndef CHINESE_INPUT_AGENT_APP_ATTACHMENTS_H
#define CHINESE_INPUT_AGENT_APP_ATTACHMENTS_H

#include <windows.h>
#include <stddef.h>

BOOL app_attachments_install(HWND rich_edit);
void app_attachments_clear(void);
BOOL app_attachments_has_pending(void);
BOOL app_attachments_first_path(WCHAR *out, size_t cch);
BOOL app_attachments_clipboard_image_path(HWND owner, WCHAR *out, size_t cch);

#endif
