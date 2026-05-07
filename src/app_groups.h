#ifndef CHINESE_INPUT_AGENT_APP_GROUPS_H
#define CHINESE_INPUT_AGENT_APP_GROUPS_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#define APP_GROUP_MAX_GROUPS 64
#define APP_GROUP_MAX_MEMBERS 128
#define APP_GROUP_ID_BYTES 8
#define APP_GROUP_EPOCH_SEED_BYTES 32
#define APP_GROUP_MESSAGE_OVERHEAD_BYTES 31

BOOL app_groups_load(WCHAR *err, size_t err_cch);
BOOL app_groups_save(void);
void app_groups_shutdown(void);

int app_groups_count(void);
const WCHAR *app_groups_name(int index);
BOOL app_groups_get_display_name(int index, WCHAR *out, size_t cch);
BOOL app_groups_get_message_seed(int index, WCHAR *out, size_t cch);
BOOL app_groups_get_local_sender_label(int index, WCHAR *out, size_t cch);

BOOL app_groups_create(const WCHAR *name, const WCHAR *local_sender_name,
                       int *index_out, WCHAR *err, size_t err_cch);
BOOL app_groups_rekey(int index, WCHAR *err, size_t err_cch);
BOOL app_groups_set_member_alias(int index, const WCHAR *sender_id_hex, const WCHAR *alias,
                                 WCHAR **out_message, WCHAR *err, size_t err_cch);
BOOL app_groups_export_package(int index, BYTE **out, DWORD *out_len,
                               WCHAR *err, size_t err_cch);
BOOL app_groups_is_package(const BYTE *pkg, DWORD pkg_len);
BOOL app_groups_package_fingerprint(const BYTE *pkg, DWORD pkg_len,
                                    WCHAR *out, size_t cch,
                                    WCHAR *err, size_t err_cch);
BOOL app_groups_import_package(const BYTE *pkg, DWORD pkg_len,
                               const WCHAR *local_group_name,
                               const WCHAR *local_sender_name,
                               int *index_out, WCHAR **out_message,
                               WCHAR *err, size_t err_cch);

BOOL app_groups_encrypt_message(int index, const WCHAR *plain,
                                BYTE **out, DWORD *out_len,
                                WCHAR *err, size_t err_cch);
BOOL app_groups_decrypt_message(const BYTE *message, DWORD message_len,
                                WCHAR **plain_out, WCHAR **sender_out,
                                int *group_index_out,
                                WCHAR *err, size_t err_cch);

BOOL app_groups_archive_append_text(int index, const WCHAR *sender, const WCHAR *plain,
                                    WCHAR *err, size_t err_cch);
BOOL app_groups_archive_load_text(int index, WCHAR **out,
                                  WCHAR *err, size_t err_cch);

#endif
