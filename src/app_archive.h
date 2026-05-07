#ifndef CHINESE_INPUT_AGENT_APP_ARCHIVE_H
#define CHINESE_INPUT_AGENT_APP_ARCHIVE_H

#include <windows.h>
#include <stddef.h>

BOOL archive_append_text(int profile_index, const WCHAR *sender, const WCHAR *plain,
                         WCHAR *err, size_t err_cch);
BOOL archive_load_text(int profile_index, WCHAR **out, WCHAR *err, size_t err_cch);

#endif
