#ifndef CHINESE_INPUT_AGENT_APP_PROFILES_H
#define CHINESE_INPUT_AGENT_APP_PROFILES_H

#include <windows.h>
#include <stddef.h>
#include "crypto_box.h"

#define APP_PROFILE_MASTER_KEY_BYTES 32
#define APP_PROFILE_MAX_PROFILES 64

typedef struct KEY_PROFILE KEY_PROFILE;
typedef BOOL (*PROFILE_MASTER_KEY_FN)(const BYTE profile_master[APP_PROFILE_MASTER_KEY_BYTES],
                                      void *user, WCHAR *err, size_t err_cch);

BOOL profiles_load(WCHAR *err, size_t err_cch);
BOOL profiles_save(void);
BOOL profiles_activate(int index, WCHAR *err, size_t err_cch);
void profiles_lock_inactive_masters(void);
void profiles_clear_all(void);
void profiles_shutdown(void);
int profiles_count(void);
int profiles_active_index(void);
BOOL profiles_get_name_copy(int index, WCHAR *out, size_t cch);
BOOL profiles_set_name(int index, const WCHAR *name, WCHAR *err, size_t err_cch);
BOOL profiles_get_state_path_by_index(int index, WCHAR *path, size_t cch);
BOOL profiles_get_archive_path_by_index(int index, WCHAR *path, size_t cch);
BOOL profiles_get_legacy_archive_path_by_index(int index, WCHAR *path, size_t cch);
BOOL profiles_append_from_master(const WCHAR *name, const BYTE profile_master[APP_PROFILE_MASTER_KEY_BYTES],
                                 int *index_out, WCHAR *err, size_t err_cch);
void profiles_remove_at(int index);
BOOL profiles_open_crypto(int index, CRYPTO_BOX **out, WCHAR *err, size_t err_cch);
BOOL profiles_with_master_key(int index, PROFILE_MASTER_KEY_FN callback, void *user,
                              WCHAR *err, size_t err_cch);

#endif
