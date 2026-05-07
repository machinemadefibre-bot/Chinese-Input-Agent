#ifndef CHINESE_INPUT_AGENT_APP_CONTACT_FLOW_H
#define CHINESE_INPUT_AGENT_APP_CONTACT_FLOW_H

#include <windows.h>
#include <stddef.h>

#include "crypto_box.h"

BOOL app_contact_flow_export_key(CRYPTO_BOX *box, HWND progress_target,
                                 WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_contact_flow_export_group_key(int group_index, HWND progress_target,
                                       WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_contact_flow_rekey_group_key(int group_index, HWND progress_target,
                                      WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_contact_flow_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                                   HWND progress_target,
                                   int *group_index_out, WCHAR **out,
                                   WCHAR *err, size_t err_cch);
BOOL app_contact_flow_set_group_member_alias(int group_index, const WCHAR *sender_id_hex,
                                             const WCHAR *alias, WCHAR **out,
                                             WCHAR *err, size_t err_cch);
BOOL app_contact_flow_import_key(const WCHAR *carrier, const WCHAR *expected_fingerprint,
                                 const WCHAR *name, const WCHAR *group_name,
                                 int *active_index_out, int *group_index_out,
                                 WCHAR **out_message, WCHAR *err, size_t err_cch);

#endif
