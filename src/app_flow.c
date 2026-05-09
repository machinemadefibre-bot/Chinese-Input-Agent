#include "app_flow.h"

#include "app_carrier_flow.h"
#include "app_contact_flow.h"
#include "app_message_flow.h"

void app_flow_free_decrypt_result(APP_FLOW_DECRYPT_RESULT *result) {
    app_message_flow_free_decrypt_result(result);
}

BOOL app_flow_extract_exchange_body(const WCHAR *text, APP_FLOW_EXCHANGE_KIND *kind_out,
                                    WCHAR **out, WCHAR *fingerprint, size_t fingerprint_cch,
                                    WCHAR *err, size_t err_cch) {
    return app_carrier_extract_exchange_body(text, kind_out, out, fingerprint, fingerprint_cch, err, err_cch);
}

BOOL app_flow_extract_key_package_body(const WCHAR *text, WCHAR **out,
                                       WCHAR *fingerprint, size_t fingerprint_cch,
                                       WCHAR *err, size_t err_cch) {
    return app_carrier_extract_contact_package_body(text, out, fingerprint, fingerprint_cch, err, err_cch);
}

BOOL app_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
                              const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_message_flow_encrypt_message(box, plain, topic, progress, out, err, err_cch);
}

BOOL app_flow_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                    const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_message_flow_encrypt_group_message(group_index, plain, topic, progress, out, err, err_cch);
}

BOOL app_flow_export_key(CRYPTO_BOX *box, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_contact_flow_export_key(box, progress, out, err, err_cch);
}

BOOL app_flow_export_group_key(int group_index, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_contact_flow_export_group_key(group_index, progress, out, err, err_cch);
}

BOOL app_flow_rekey_group_key(int group_index, const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_contact_flow_rekey_group_key(group_index, progress, out, err, err_cch);
}

BOOL app_flow_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                           const CIA_PROGRESS_SINK *progress,
                           int *group_index_out, WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_contact_flow_create_group(group_name, local_sender_name, progress,
                                         group_index_out, out, err, err_cch);
}

BOOL app_flow_set_group_member_alias(int group_index, const WCHAR *sender_id_hex, const WCHAR *alias,
                                     WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_contact_flow_set_group_member_alias(group_index, sender_id_hex, alias, out, err, err_cch);
}

BOOL app_flow_import_key(const WCHAR *carrier, const WCHAR *expected_fingerprint, const WCHAR *name,
                         const WCHAR *group_name,
                         int *active_index_out, int *group_index_out,
                         WCHAR **out_message, WCHAR *err, size_t err_cch) {
    return app_contact_flow_import_key(carrier, expected_fingerprint, name, group_name,
                                       active_index_out, group_index_out, out_message, err, err_cch);
}

BOOL app_flow_decrypt_clip_auto(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                APP_FLOW_DECRYPT_RESULT *result,
                                WCHAR *err, size_t err_cch) {
    return app_message_flow_decrypt_clip_auto(clip, cancel_fn, result, err, err_cch);
}

BOOL app_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        WCHAR **plain_w_out, int *profile_index_out,
                                        WCHAR *err, size_t err_cch) {
    return app_message_flow_decrypt_clip_auto_profile(clip, cancel_fn, plain_w_out, profile_index_out,
                                                      err, err_cch);
}
