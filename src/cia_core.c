#include "cia_core.h"

#include "app_archive.h"
#include "app_flow.h"
#include "app_groups.h"
#include "app_llm.h"
#include "app_profiles.h"
#include "app_shared.h"
#include "app_tokenizer_prefs.h"

static CRYPTO_BOX *g_core_active_box;
static CIA_CORE_CANCEL_FN g_core_cancel;
static void *g_core_cancel_user;
static BOOL g_core_initialized;
static BOOL g_core_profiles_loaded;

static BOOL cia_core_cancelled(void) {
    return g_core_cancel ? g_core_cancel(g_core_cancel_user) : FALSE;
}

static void cia_core_close_active_crypto(void) {
    crypto_box_close(g_core_active_box);
    g_core_active_box = NULL;
}

static BOOL cia_core_reload_active_crypto(WCHAR *err, size_t err_cch) {
    if (!g_core_profiles_loaded) {
        set_error(err, err_cch, L"Profiles are not loaded in this cia_core session.");
        return FALSE;
    }
    int profile_index = profiles_active_index();
    if (profile_index < 0) {
        set_error(err, err_cch, L"No active profile is available.");
        return FALSE;
    }
    CRYPTO_BOX *new_box = NULL;
    if (!profiles_open_crypto(profile_index, &new_box, err, err_cch)) return FALSE;
    cia_core_close_active_crypto();
    g_core_active_box = new_box;
    profiles_lock_inactive_masters();
    return TRUE;
}

static BOOL cia_core_ensure_active_crypto(WCHAR *err, size_t err_cch) {
    if (g_core_active_box) return TRUE;
    return cia_core_reload_active_crypto(err, err_cch);
}

BOOL cia_core_init(const CIA_CORE_OPTIONS *options, WCHAR *err, size_t err_cch) {
    if (g_core_initialized) return TRUE;
    g_core_cancel = options ? options->cancel : NULL;
    g_core_cancel_user = options ? options->cancel_user : NULL;

    app_llm_init(cia_core_cancelled);
    if (!options || !options->skip_profiles) {
        if (!profiles_load(err, err_cch)) goto fail;
        g_core_profiles_loaded = TRUE;
    }
    if (!app_groups_load(err, err_cch)) goto fail_profiles;
    if (!app_tokenizer_prefs_load(err, err_cch)) goto fail_groups;

    g_core_initialized = TRUE;
    if (options && options->start_worker_background) {
        start_local_llm_background();
    }
    return TRUE;

fail_groups:
    app_groups_shutdown();
fail_profiles:
    if (g_core_profiles_loaded) profiles_shutdown();
fail:
    app_llm_cleanup();
    g_core_cancel = NULL;
    g_core_cancel_user = NULL;
    g_core_profiles_loaded = FALSE;
    return FALSE;
}

void cia_core_cleanup(void) {
    if (!g_core_initialized) return;
    app_llm_cleanup();
    cia_core_close_active_crypto();
    app_tokenizer_prefs_shutdown();
    app_groups_shutdown();
    if (g_core_profiles_loaded) profiles_shutdown();
    g_core_cancel = NULL;
    g_core_cancel_user = NULL;
    g_core_profiles_loaded = FALSE;
    g_core_initialized = FALSE;
}

void cia_core_free_string(WCHAR *text) {
    secure_free_wide(text);
}

void cia_core_free_decrypt_result(CIA_CORE_DECRYPT_RESULT *result) {
    if (!result) return;
    secure_free_wide(result->plain);
    secure_free_wide(result->sender);
    ZeroMemory(result, sizeof(*result));
}

BOOL cia_core_encrypt_message(const WCHAR *plain, const WCHAR *topic,
                              const CIA_PROGRESS_SINK *progress,
                              WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!cia_core_ensure_active_crypto(err, err_cch)) {
        return FALSE;
    }
    return app_flow_encrypt_message(g_core_active_box, plain, topic, progress, out, err, err_cch);
}

BOOL cia_core_decrypt_text(const WCHAR *text, CIA_CORE_DECRYPT_RESULT *result,
                           WCHAR *err, size_t err_cch) {
    if (!result) {
        set_error(err, err_cch, L"Invalid decrypt result buffer.");
        return FALSE;
    }
    ZeroMemory(result, sizeof(*result));
    APP_FLOW_DECRYPT_RESULT flow_result;
    ZeroMemory(&flow_result, sizeof(flow_result));
    if (!app_flow_decrypt_clip_auto(text, cia_core_cancelled, &flow_result, err, err_cch)) {
        return FALSE;
    }
    result->plain = flow_result.plain;
    result->sender = flow_result.sender;
    result->profile_index = flow_result.profile_index;
    result->group_index = flow_result.group_index;
    result->is_group = flow_result.is_group;
    ZeroMemory(&flow_result, sizeof(flow_result));
    return TRUE;
}

BOOL cia_core_export_contact(const CIA_PROGRESS_SINK *progress,
                             WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!cia_core_ensure_active_crypto(err, err_cch)) {
        return FALSE;
    }
    return app_flow_export_key(g_core_active_box, progress, out, err, err_cch);
}

BOOL cia_core_import_contact(const WCHAR *carrier, const WCHAR *expected_fingerprint,
                             const WCHAR *name, int *active_profile_index_out,
                             WCHAR **out_message, WCHAR *err, size_t err_cch) {
    if (active_profile_index_out) *active_profile_index_out = -1;
    *out_message = NULL;

    APP_FLOW_EXCHANGE_KIND kind = APP_FLOW_EXCHANGE_CONTACT;
    WCHAR fingerprint[32] = L"";
    WCHAR *body = NULL;
    if (!app_flow_extract_exchange_body(carrier, &kind, &body, fingerprint, ARRAYSIZE(fingerprint),
                                        err, err_cch)) {
        return FALSE;
    }
    secure_free_wide(body);
    if (kind != APP_FLOW_EXCHANGE_CONTACT) {
        set_error(err, err_cch, L"The provided exchange text is a group package, not a contact package.");
        return FALSE;
    }

    int active_index = -1;
    int group_index = -1;
    const WCHAR *fingerprint_to_verify =
        expected_fingerprint && expected_fingerprint[0] ? expected_fingerprint : fingerprint;
    if (!app_flow_import_key(carrier, fingerprint_to_verify, name, NULL,
                             &active_index, &group_index, out_message, err, err_cch)) {
        return FALSE;
    }
    (void)group_index;
    if (!cia_core_reload_active_crypto(err, err_cch)) {
        secure_free_wide(*out_message);
        *out_message = NULL;
        return FALSE;
    }
    if (active_profile_index_out) *active_profile_index_out = active_index;
    return TRUE;
}

BOOL cia_core_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                           const CIA_PROGRESS_SINK *progress,
                           int *group_index_out, WCHAR **out,
                           WCHAR *err, size_t err_cch) {
    return app_flow_create_group(group_name, local_sender_name, progress,
                                 group_index_out, out, err, err_cch);
}

BOOL cia_core_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                    const CIA_PROGRESS_SINK *progress,
                                    WCHAR **out, WCHAR *err, size_t err_cch) {
    return app_flow_encrypt_group_message(group_index, plain, topic, progress, out, err, err_cch);
}

BOOL cia_core_load_chat_history(CIA_CORE_CONVERSATION_KIND kind, int conversation_index,
                                WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (kind == CIA_CORE_CONVERSATION_PRIVATE) {
        return archive_load_text(conversation_index, out, err, err_cch);
    }
    if (kind == CIA_CORE_CONVERSATION_GROUP) {
        return app_groups_archive_load_text(conversation_index, out, err, err_cch);
    }
    set_error(err, err_cch, L"Invalid chat history conversation kind.");
    return FALSE;
}

BOOL cia_core_append_chat_history(CIA_CORE_CONVERSATION_KIND kind, int conversation_index,
                                  const WCHAR *sender, const WCHAR *plain,
                                  WCHAR *err, size_t err_cch) {
    if (kind == CIA_CORE_CONVERSATION_PRIVATE) {
        return archive_append_text(conversation_index, sender, plain, err, err_cch);
    }
    if (kind == CIA_CORE_CONVERSATION_GROUP) {
        return app_groups_archive_append_text(conversation_index, sender, plain, err, err_cch);
    }
    set_error(err, err_cch, L"Invalid chat history conversation kind.");
    return FALSE;
}
