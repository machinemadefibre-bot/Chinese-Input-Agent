#ifndef CHINESE_INPUT_AGENT_CIA_CORE_H
#define CHINESE_INPUT_AGENT_CIA_CORE_H

#include <windows.h>
#include <stddef.h>

#include "app_progress.h"

/*
 * Headless facade for the current Windows Unicode build.
 * This public API intentionally uses WCHAR/BOOL and avoids UI handles,
 * dialogs, control handles, and windowing callbacks.
 */

typedef BOOL (*CIA_CORE_CANCEL_FN)(void *user);

typedef struct CIA_CORE_OPTIONS {
    CIA_CORE_CANCEL_FN cancel;
    void *cancel_user;
    BOOL start_worker_background;
} CIA_CORE_OPTIONS;

typedef enum CIA_CORE_CONVERSATION_KIND {
    CIA_CORE_CONVERSATION_PRIVATE = 1,
    CIA_CORE_CONVERSATION_GROUP = 2
} CIA_CORE_CONVERSATION_KIND;

typedef struct CIA_CORE_DECRYPT_RESULT {
    WCHAR *plain;
    WCHAR *sender;
    int profile_index;
    int group_index;
    BOOL is_group;
} CIA_CORE_DECRYPT_RESULT;

BOOL cia_core_init(const CIA_CORE_OPTIONS *options, WCHAR *err, size_t err_cch);
void cia_core_cleanup(void);

void cia_core_free_string(WCHAR *text);
void cia_core_free_decrypt_result(CIA_CORE_DECRYPT_RESULT *result);

BOOL cia_core_encrypt_message(const WCHAR *plain, const WCHAR *topic,
                              const CIA_PROGRESS_SINK *progress,
                              WCHAR **out, WCHAR *err, size_t err_cch);
BOOL cia_core_decrypt_text(const WCHAR *text, CIA_CORE_DECRYPT_RESULT *result,
                           WCHAR *err, size_t err_cch);

BOOL cia_core_export_contact(const CIA_PROGRESS_SINK *progress,
                             WCHAR **out, WCHAR *err, size_t err_cch);
BOOL cia_core_import_contact(const WCHAR *carrier, const WCHAR *expected_fingerprint,
                             const WCHAR *name, int *active_profile_index_out,
                             WCHAR **out_message, WCHAR *err, size_t err_cch);

BOOL cia_core_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                           const CIA_PROGRESS_SINK *progress,
                           int *group_index_out, WCHAR **out,
                           WCHAR *err, size_t err_cch);
BOOL cia_core_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                    const CIA_PROGRESS_SINK *progress,
                                    WCHAR **out, WCHAR *err, size_t err_cch);

BOOL cia_core_load_chat_history(CIA_CORE_CONVERSATION_KIND kind, int conversation_index,
                                WCHAR **out, WCHAR *err, size_t err_cch);
BOOL cia_core_append_chat_history(CIA_CORE_CONVERSATION_KIND kind, int conversation_index,
                                  const WCHAR *sender, const WCHAR *plain,
                                  WCHAR *err, size_t err_cch);

#endif
