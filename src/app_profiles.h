#ifndef CHINESE_INPUT_AGENT_APP_PROFILES_H
#define CHINESE_INPUT_AGENT_APP_PROFILES_H

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

#define APP_PROFILE_MASTER_KEY_BYTES 32
#define APP_PROFILE_MAX_PROFILES 64

typedef struct KEY_PROFILE {
    WCHAR id[33];
    WCHAR name[128];
    BYTE *wrapped_key;
    DWORD wrapped_key_len;
    BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES];
    BOOL master_loaded;
} KEY_PROFILE;

BOOL profiles_load(WCHAR *err, size_t err_cch);
BOOL profiles_save(void);
BOOL profiles_activate(int index, WCHAR *err, size_t err_cch);
void profiles_clear_all(void);
void profiles_shutdown(void);
int profiles_count(void);
int profiles_active_index(void);
KEY_PROFILE *profiles_get(int index);
KEY_PROFILE *profiles_active(void);
BOOL profiles_get_state_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch);
BOOL profiles_get_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch);
BOOL profiles_get_legacy_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch);
void profiles_clear_profile(KEY_PROFILE *profile);
BOOL profiles_create_from_master(const WCHAR *name, const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES],
                                 KEY_PROFILE *out, WCHAR *err, size_t err_cch);
BOOL profiles_append_imported(KEY_PROFILE *profile, int *index_out, WCHAR *err, size_t err_cch);
void profiles_remove_at(int index);
BOOL profiles_build_key_package(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);

#endif
