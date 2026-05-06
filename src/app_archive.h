#ifndef CHINESE_INPUT_AGENT_APP_ARCHIVE_H
#define CHINESE_INPUT_AGENT_APP_ARCHIVE_H

#include <windows.h>
#include <stddef.h>
#include "app_profiles.h"

BOOL archive_append_text(const KEY_PROFILE *profile, const WCHAR *sender, const WCHAR *plain,
                         WCHAR *err, size_t err_cch);
BOOL archive_load_text(const KEY_PROFILE *profile, WCHAR **out, WCHAR *err, size_t err_cch);

#endif
