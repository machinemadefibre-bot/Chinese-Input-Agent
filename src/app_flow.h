#ifndef CHINESE_INPUT_AGENT_APP_FLOW_H
#define CHINESE_INPUT_AGENT_APP_FLOW_H

#include <windows.h>
#include <stddef.h>

#include "app_progress.h"
#include "crypto_box.h"

typedef BOOL (*APP_FLOW_CANCEL_FN)(void);

typedef enum APP_FLOW_EXCHANGE_KIND {
    APP_FLOW_EXCHANGE_CONTACT = 1,
    APP_FLOW_EXCHANGE_GROUP = 2
} APP_FLOW_EXCHANGE_KIND;

typedef struct APP_FLOW_DECRYPT_RESULT {
    WCHAR *plain;
    WCHAR *sender;
    int profile_index;
    int group_index;
    BOOL is_group;
} APP_FLOW_DECRYPT_RESULT;

void app_flow_free_decrypt_result(APP_FLOW_DECRYPT_RESULT *result);
BOOL app_flow_extract_exchange_body(const WCHAR *text, APP_FLOW_EXCHANGE_KIND *kind_out,
                                    WCHAR **out, WCHAR *fingerprint, size_t fingerprint_cch,
                                    WCHAR *err, size_t err_cch);
BOOL app_flow_extract_key_package_body(const WCHAR *text, WCHAR **out,
                                       WCHAR *fingerprint, size_t fingerprint_cch,
                                       WCHAR *err, size_t err_cch);
BOOL app_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
                              const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                    const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_export_key(CRYPTO_BOX *box, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_export_group_key(int group_index, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_rekey_group_key(int group_index, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                           const CIA_PROGRESS_SINK *progress,
                           int *group_index_out, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_set_group_member_alias(int group_index, const WCHAR *sender_id_hex, const WCHAR *alias,
                                     WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_import_key(const WCHAR *carrier, const WCHAR *expected_fingerprint, const WCHAR *name,
                         const WCHAR *group_name,
                         int *active_index_out, int *group_index_out,
                         WCHAR **out_message, WCHAR *err, size_t err_cch);
BOOL app_flow_decrypt_clip_auto(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                APP_FLOW_DECRYPT_RESULT *result,
                                WCHAR *err, size_t err_cch);
BOOL app_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        WCHAR **plain_w_out, int *profile_index_out,
                                        WCHAR *err, size_t err_cch);

#endif
