#ifndef CHINESE_INPUT_AGENT_APP_TOKENIZER_PREFS_H
#define CHINESE_INPUT_AGENT_APP_TOKENIZER_PREFS_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#define APP_TOKENIZER_ID_CCH 64

BOOL app_tokenizer_prefs_load(WCHAR *err, size_t err_cch);
void app_tokenizer_prefs_shutdown(void);

BOOL app_tokenizer_prefs_get_profile(int profile_index, WCHAR *out, size_t cch);
BOOL app_tokenizer_prefs_set_profile(int profile_index, const WCHAR *tokenizer_id);

BOOL app_tokenizer_prefs_get_group_recent(int group_index, WCHAR *out, size_t cch);
BOOL app_tokenizer_prefs_set_group_recent(int group_index, const WCHAR *tokenizer_id);

BOOL app_tokenizer_prefs_get_group_sender(int group_index, uint32_t sender_id, WCHAR *out, size_t cch);
BOOL app_tokenizer_prefs_set_group_sender(int group_index, uint32_t sender_id, const WCHAR *tokenizer_id);

#endif
