#ifndef APP_CHAT_HISTORY_H
#define APP_CHAT_HISTORY_H

#include <windows.h>
#include <stdint.h>

#define CHAT_HISTORY_KEY_BYTES 32

BOOL chat_history_append_private(const WCHAR *profile_id,
                                 const BYTE private_history_key[CHAT_HISTORY_KEY_BYTES],
                                 const WCHAR *sender,
                                 const WCHAR *plain,
                                 WCHAR *err,
                                 size_t err_cch);

BOOL chat_history_load_private(const WCHAR *profile_id,
                               const BYTE private_history_key[CHAT_HISTORY_KEY_BYTES],
                               WCHAR **out,
                               WCHAR *err,
                               size_t err_cch);

BOOL chat_history_append_group(uint64_t group_id,
                               const WCHAR *sender,
                               const WCHAR *plain,
                               WCHAR *err,
                               size_t err_cch);

BOOL chat_history_load_group(uint64_t group_id,
                             WCHAR **out,
                             WCHAR *err,
                             size_t err_cch);

#endif
