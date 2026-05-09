#ifndef CHINESE_INPUT_AGENT_APP_MESSAGE_FLOW_H
#define CHINESE_INPUT_AGENT_APP_MESSAGE_FLOW_H

#include <windows.h>
#include <stddef.h>

#include "app_flow.h"
#include "crypto_box.h"

void app_message_flow_free_decrypt_result(APP_FLOW_DECRYPT_RESULT *result);
BOOL app_message_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
                                      const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_message_flow_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                            const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_message_flow_decrypt_clip_auto(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        APP_FLOW_DECRYPT_RESULT *result,
                                        WCHAR *err, size_t err_cch);
BOOL app_message_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                                WCHAR **plain_w_out, int *profile_index_out,
                                                WCHAR *err, size_t err_cch);

#endif
