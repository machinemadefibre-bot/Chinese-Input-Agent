#ifndef CHINESE_INPUT_AGENT_APP_FLOW_H
#define CHINESE_INPUT_AGENT_APP_FLOW_H

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

#include "crypto_box.h"

typedef BOOL (*APP_FLOW_CANCEL_FN)(void);

BOOL app_flow_extract_key_package_body(const WCHAR *text, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
                              HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_export_key(CRYPTO_BOX *box, HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_flow_import_key(const WCHAR *carrier, const WCHAR *name, int *active_index_out,
                         WCHAR **out_message, WCHAR *err, size_t err_cch);
BOOL app_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        WCHAR **plain_w_out, WCHAR *err, size_t err_cch);

#endif
