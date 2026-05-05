#ifndef CHINESE_INPUT_AGENT_APP_ARCHIVE_H
#define CHINESE_INPUT_AGENT_APP_ARCHIVE_H

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

#include <windows.h>
#include <stddef.h>
#include "app_profiles.h"

BOOL archive_append_text(const KEY_PROFILE *profile, const WCHAR *plain, WCHAR *err, size_t err_cch);
BOOL archive_load_text(const KEY_PROFILE *profile, WCHAR **out, WCHAR *err, size_t err_cch);

#endif
