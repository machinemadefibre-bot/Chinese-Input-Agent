#include "app_work.h"
#include "app_flow.h"
#include "app_shared.h"
#include "win_util.h"

static const WCHAR WORK_START_FAILED_TEXT[] = L"\u64cd\u4f5c\u5931\u8d25\u3002";
static const WCHAR WORK_BACKGROUND_FAILED_TEXT[] = L"\u540e\u53f0\u4efb\u52a1\u5931\u8d25\u3002";
static const WCHAR WORK_PROGRESS_PREFIX[] = L"\u751f\u6210\u8fdb\u5ea6 [";
static const size_t WORK_PROGRESS_BAR_WIDTH = 24;

static volatile LONG g_work_active;
static volatile LONG g_cancel_work;
static APP_WORK_HOST g_host;

#define WORK_GROUP_EXPORT_CACHE_SLOTS 16

typedef struct WORK_GROUP_EXPORT_CACHE_ENTRY {
    BOOL used;
    int group_index;
    WCHAR *text;
} WORK_GROUP_EXPORT_CACHE_ENTRY;

static CRYPTO_BOX *g_cached_contact_export_box;
static WCHAR *g_cached_contact_export_text;
static WORK_GROUP_EXPORT_CACHE_ENTRY g_cached_group_exports[WORK_GROUP_EXPORT_CACHE_SLOTS];
static DWORD WINAPI work_thread_proc(LPVOID param);
static void reset_work_state_flags(void);
static void app_work_post_llm_stream_progress(void *user, const WCHAR *partial,
                                              size_t tokens_done, size_t tokens_total, double tps);
static void cache_contact_export(CRYPTO_BOX *box, const WCHAR *text);
static BOOL copy_cached_contact_export(CRYPTO_BOX *box, WCHAR **out,
                                       BOOL *cache_hit, WCHAR *err, size_t err_cch);
static void cache_group_export(int group_index, const WCHAR *text);
static BOOL copy_cached_group_export(int group_index, WCHAR **out,
                                     BOOL *cache_hit, WCHAR *err, size_t err_cch);
void app_work_configure(const APP_WORK_HOST *host) {
    if (host) {
        g_host = *host;
    } else {
        ZeroMemory(&g_host, sizeof(g_host));
    }
}

APP_WORK_CTX *app_work_alloc(APP_WORK_KIND kind, HWND owner, HWND target_textbox) {
    APP_WORK_CTX *ctx = (APP_WORK_CTX *)xalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->kind = kind;
    ctx->owner = owner;
    ctx->target_textbox = target_textbox;
    ctx->group_index = -1;
    ctx->sent_profile_index = -1;
    ctx->sent_group_index = -1;
    return ctx;
}

void app_work_free_ctx(APP_WORK_CTX *ctx) {
    if (!ctx) return;
    secure_free_wide(ctx->input);
    xfree(ctx->topic);
    xfree(ctx->name);
    xfree((WCHAR *)ctx->carrier_options.custom_prompt_text);
    secure_free_wide(ctx->expected_fingerprint);
    secure_free_wide(ctx->sent_plaintext);
    secure_free_wide(ctx->sent_sender);
    xfree(ctx);
}

void app_work_free_message(APP_WORK_MESSAGE *message) {
    if (!message) return;
    secure_free_wide(message->text);
    secure_free_wide(message->sender);
    secure_free_wide(message->sent_plaintext);
    secure_free_wide(message->sent_sender);
    xfree(message);
}

BOOL app_work_is_active(void) {
    return InterlockedCompareExchange(&g_work_active, 0, 0) != 0;
}

void app_work_cancel(void) {
    InterlockedExchange(&g_cancel_work, 1);
}

BOOL app_work_cancelled(void) {
    return InterlockedCompareExchange(&g_cancel_work, 0, 0) != 0;
}

static void clear_cached_contact_export(void) {
    secure_free_wide(g_cached_contact_export_text);
    g_cached_contact_export_text = NULL;
    g_cached_contact_export_box = NULL;
}

static void clear_cached_group_exports(void) {
    for (size_t slot = 0; slot < WORK_GROUP_EXPORT_CACHE_SLOTS; ++slot) {
        secure_free_wide(g_cached_group_exports[slot].text);
        g_cached_group_exports[slot].text = NULL;
        g_cached_group_exports[slot].group_index = -1;
        g_cached_group_exports[slot].used = FALSE;
    }
}

void app_work_clear_key_export_cache(void) {
    clear_cached_contact_export();
    clear_cached_group_exports();
}

static void cache_contact_export(CRYPTO_BOX *box, const WCHAR *text) {
    clear_cached_contact_export();
    if (!box || !text) return;
    WCHAR *copy = win_dup_wide(text);
    if (!copy) return;
    g_cached_contact_export_box = box;
    g_cached_contact_export_text = copy;
}

static BOOL copy_cached_contact_export(CRYPTO_BOX *box, WCHAR **out,
                                       BOOL *cache_hit, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (cache_hit) *cache_hit = FALSE;
    if (!box || box != g_cached_contact_export_box || !g_cached_contact_export_text) return TRUE;
    if (cache_hit) *cache_hit = TRUE;
    *out = win_dup_wide(g_cached_contact_export_text);
    if (!*out) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    return TRUE;
}

static void cache_group_export(int group_index, const WCHAR *text) {
    if (group_index < 0 || !text) return;
    size_t target_slot = WORK_GROUP_EXPORT_CACHE_SLOTS;
    for (size_t slot = 0; slot < WORK_GROUP_EXPORT_CACHE_SLOTS; ++slot) {
        if (g_cached_group_exports[slot].used && g_cached_group_exports[slot].group_index == group_index) {
            target_slot = slot;
            break;
        }
        if (!g_cached_group_exports[slot].used && target_slot == WORK_GROUP_EXPORT_CACHE_SLOTS) {
            target_slot = slot;
        }
    }
    if (target_slot == WORK_GROUP_EXPORT_CACHE_SLOTS) target_slot = 0;
    secure_free_wide(g_cached_group_exports[target_slot].text);
    g_cached_group_exports[target_slot].text = win_dup_wide(text);
    if (!g_cached_group_exports[target_slot].text) {
        g_cached_group_exports[target_slot].used = FALSE;
        g_cached_group_exports[target_slot].group_index = -1;
        return;
    }
    g_cached_group_exports[target_slot].used = TRUE;
    g_cached_group_exports[target_slot].group_index = group_index;
}

static BOOL copy_cached_group_export(int group_index, WCHAR **out,
                                     BOOL *cache_hit, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (cache_hit) *cache_hit = FALSE;
    if (group_index < 0) return TRUE;
    for (size_t slot = 0; slot < WORK_GROUP_EXPORT_CACHE_SLOTS; ++slot) {
        if (!g_cached_group_exports[slot].used || g_cached_group_exports[slot].group_index != group_index) continue;
        if (cache_hit) *cache_hit = TRUE;
        *out = win_dup_wide(g_cached_group_exports[slot].text);
        if (!*out) {
            set_error(err, err_cch, L"Out of memory.");
            return FALSE;
        }
        return TRUE;
    }
    return TRUE;
}

void app_work_complete_message_handled(void) {
    reset_work_state_flags();
    if (g_host.set_busy) g_host.set_busy(g_host.user, FALSE);
}

static void reset_work_state_flags(void) {
    InterlockedExchange(&g_work_active, 0);
    InterlockedExchange(&g_cancel_work, 0);
}

static void show_work_start_error(HWND owner) {
    if (g_host.show_error) {
        g_host.show_error(g_host.user, owner, WORK_START_FAILED_TEXT);
    }
}

BOOL app_work_start(APP_WORK_CTX *ctx) {
    if (!ctx) {
        show_work_start_error(NULL);
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_work_active, 1, 0) != 0) {
        show_work_start_error(ctx->owner);
        return FALSE;
    }
    InterlockedExchange(&g_cancel_work, 0);
    if (g_host.set_busy) g_host.set_busy(g_host.user, TRUE);
    HANDLE thread = CreateThread(NULL, 0, work_thread_proc, ctx, 0, NULL);
    if (!thread) {
        reset_work_state_flags();
        if (g_host.set_busy) g_host.set_busy(g_host.user, FALSE);
        show_work_start_error(ctx->owner);
        return FALSE;
    }
    CloseHandle(thread);
    return TRUE;
}

static BOOL post_work_text_kind(UINT msg, HWND target_textbox, const WCHAR *text,
                                APP_WORK_KIND kind, int profile_index,
                                int group_index, const WCHAR *sender,
                                const WCHAR *sent_plaintext, const WCHAR *sent_sender,
                                int sent_profile_index, int sent_group_index) {
    APP_WORK_MESSAGE *message = (APP_WORK_MESSAGE *)xalloc(sizeof(*message));
    if (!message) return FALSE;
    message->kind = kind;
    message->target_textbox = target_textbox;
    message->profile_index = profile_index;
    message->group_index = group_index;
    message->sent_profile_index = sent_profile_index;
    message->sent_group_index = sent_group_index;
    message->text = win_dup_wide(text ? text : L"");
    message->sender = win_dup_wide(sender ? sender : L"");
    if (sent_plaintext) message->sent_plaintext = win_dup_wide(sent_plaintext);
    if (sent_sender) message->sent_sender = win_dup_wide(sent_sender);
    if (!message->text || !message->sender ||
        (sent_plaintext && !message->sent_plaintext) ||
        (sent_sender && !message->sent_sender)) goto fail;
    if (!g_host.main_window || !PostMessageW(g_host.main_window, msg, 0, (LPARAM)message)) {
        goto fail;
    }
    return TRUE;
fail:
    app_work_free_message(message);
    return FALSE;
}

static BOOL post_work_text(UINT msg, HWND target_textbox, const WCHAR *text) {
    return post_work_text_kind(msg, target_textbox, text, 0, -1, -1, NULL, NULL, NULL, -1, -1);
}

static void finish_unposted_terminal_work(UINT msg) {
    /* Without a terminal UI message, no handler will clear the active/cancel flags. */
    if (g_host.main_window && PostMessageW(g_host.main_window, msg, 0, 0)) return;
    reset_work_state_flags();
}

static CIA_PROGRESS_SINK progress_sink_for_ctx(APP_WORK_CTX *ctx) {
    CIA_PROGRESS_SINK progress = { app_work_post_llm_stream_progress, ctx ? ctx->target_textbox : NULL };
    return progress;
}

static void app_work_post_llm_stream_progress(void *user, const WCHAR *partial,
                                              size_t tokens_done, size_t tokens_total, double tps) {
    HWND target_textbox = (HWND)user;
    if (!target_textbox || !IsWindow(target_textbox)) return;
    const size_t bar_width = WORK_PROGRESS_BAR_WIDTH;
    if (tokens_total == 0) tokens_total = 1;
    if (tokens_done > tokens_total) tokens_done = tokens_total;
    size_t filled = (tokens_done * bar_width) / tokens_total;
    WSTRB progress_builder = {0};
    if (!wstrb_append(&progress_builder, WORK_PROGRESS_PREFIX)) goto cleanup;
    for (size_t i = 0; i < bar_width; ++i) {
        if (!wstrb_append_char(&progress_builder, i < filled ? L'#' : L'-')) goto cleanup;
    }
    if (tps > 0.0) {
        if (!wstrb_appendf(&progress_builder, L"] %zu/%zu  %.1f token/s\r\n\r\n", tokens_done, tokens_total, tps)) goto cleanup;
    } else {
        if (!wstrb_appendf(&progress_builder, L"] %zu/%zu  -- token/s\r\n\r\n", tokens_done, tokens_total)) goto cleanup;
    }
    if (!wstrb_append(&progress_builder, partial ? partial : L"")) goto cleanup;
    post_work_text(WM_APP_WORK_UPDATE, target_textbox, progress_builder.data ? progress_builder.data : L"");
cleanup:
    wstrb_free(&progress_builder);
}

static CRYPTO_BOX *active_box(void) {
    return g_host.get_active_box ? g_host.get_active_box(g_host.user) : NULL;
}

static BOOL worker_encrypt(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    CRYPTO_BOX *box = active_box();
    if (!box) {
        set_error(err, err_cch, L"No active crypto context is open.");
        return FALSE;
    }
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    return app_flow_encrypt_message(box, ctx ? ctx->input : NULL, ctx ? ctx->topic : NULL,
                                    ctx ? &ctx->carrier_options : NULL,
                                    &progress, out, err, err_cch);
}

static BOOL worker_group_encrypt(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    return app_flow_encrypt_group_message(ctx ? ctx->group_index : -1, ctx ? ctx->input : NULL,
                                          ctx ? ctx->topic : NULL,
                                          ctx ? &ctx->carrier_options : NULL,
                                          &progress, out, err, err_cch);
}

static BOOL worker_export_key(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    CRYPTO_BOX *box = active_box();
    if (!box) {
        set_error(err, err_cch, L"No active crypto context is open.");
        return FALSE;
    }
    BOOL cache_hit = FALSE;
    if (!copy_cached_contact_export(box, out, &cache_hit, err, err_cch) || cache_hit) {
        return cache_hit && *out;
    }
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    BOOL exported = app_flow_export_key(box, &progress, out, err, err_cch);
    if (exported) cache_contact_export(box, *out);
    return exported;
}

static BOOL worker_export_group(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    int group_index = ctx ? ctx->group_index : -1;
    BOOL cache_hit = FALSE;
    if (!copy_cached_group_export(group_index, out, &cache_hit, err, err_cch) || cache_hit) {
        return cache_hit && *out;
    }
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    BOOL exported = app_flow_export_group_key(group_index, &progress, out, err, err_cch);
    if (exported) cache_group_export(group_index, *out);
    return exported;
}

static BOOL worker_create_group(APP_WORK_CTX *ctx, WCHAR **out, int *group_index_out,
                                WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (group_index_out) *group_index_out = -1;
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    return app_flow_create_group(ctx ? ctx->input : NULL, ctx ? ctx->name : NULL,
                                 &progress,
                                 group_index_out, out, err, err_cch);
}

static BOOL worker_rekey_group(APP_WORK_CTX *ctx, WCHAR **out, int *group_index_out,
                               WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (group_index_out) *group_index_out = ctx ? ctx->group_index : -1;
    CIA_PROGRESS_SINK progress = progress_sink_for_ctx(ctx);
    return app_flow_rekey_group_key(ctx ? ctx->group_index : -1,
                                    &progress, out, err, err_cch);
}

static BOOL worker_set_group_alias(APP_WORK_CTX *ctx, WCHAR **out, int *group_index_out,
                                   WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (group_index_out) *group_index_out = ctx ? ctx->group_index : -1;
    return app_flow_set_group_member_alias(ctx ? ctx->group_index : -1,
                                           ctx ? ctx->input : NULL,
                                           ctx ? ctx->name : NULL,
                                           out, err, err_cch);
}

static BOOL worker_import_key(APP_WORK_CTX *ctx, WCHAR **out, int *profile_index_out,
                              int *group_index_out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (profile_index_out) *profile_index_out = -1;
    if (group_index_out) *group_index_out = -1;
    return app_flow_import_key(ctx ? ctx->input : NULL, ctx ? ctx->expected_fingerprint : NULL,
                               ctx ? ctx->name : NULL,
                               ctx ? ctx->topic : NULL,
                               profile_index_out, group_index_out, out, err, err_cch);
}

static BOOL worker_decrypt(APP_WORK_CTX *ctx, APP_FLOW_DECRYPT_RESULT *result,
                           WCHAR *err, size_t err_cch) {
    ZeroMemory(result, sizeof(*result));
    result->profile_index = -1;
    result->group_index = -1;
    if (!ctx || !ctx->input || !ctx->input[0]) {
        set_error(err, err_cch, L"Clipboard text is empty.");
        return FALSE;
    }
    return app_flow_decrypt_clip_auto(ctx->input, app_work_cancelled, result, err, err_cch);
}

static DWORD WINAPI work_thread_proc(LPVOID param) {
    APP_WORK_CTX *ctx = (APP_WORK_CTX *)param;
    if (!ctx) {
        reset_work_state_flags();
        return 0;
    }
    WCHAR *result = NULL;
    WCHAR err[256] = L"";
    BOOL work_succeeded = FALSE;
    UINT terminal_msg = WM_APP_WORK_ERROR;
    const WCHAR *terminal_text = WORK_BACKGROUND_FAILED_TEXT;
    int result_profile_index = -1;
    int result_group_index = -1;
    APP_FLOW_DECRYPT_RESULT decrypt_result;
    ZeroMemory(&decrypt_result, sizeof(decrypt_result));

    if (ctx->kind == APP_WORK_KIND_ENCRYPT) {
        work_succeeded = worker_encrypt(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_GROUP_ENCRYPT) {
        work_succeeded = worker_group_encrypt(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_EXPORT_KEY) {
        work_succeeded = worker_export_key(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_EXPORT_GROUP) {
        work_succeeded = worker_export_group(ctx, &result, err, ARRAYSIZE(err));
        result_group_index = ctx->group_index;
    } else if (ctx->kind == APP_WORK_KIND_CREATE_GROUP) {
        work_succeeded = worker_create_group(ctx, &result, &result_group_index, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_REKEY_GROUP) {
        work_succeeded = worker_rekey_group(ctx, &result, &result_group_index, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_SET_GROUP_ALIAS) {
        work_succeeded = worker_set_group_alias(ctx, &result, &result_group_index, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_IMPORT_KEY) {
        work_succeeded = worker_import_key(ctx, &result, &result_profile_index,
                                           &result_group_index, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_DECRYPT) {
        work_succeeded = worker_decrypt(ctx, &decrypt_result, err, ARRAYSIZE(err));
        if (work_succeeded) {
            result = decrypt_result.plain;
            decrypt_result.plain = NULL;
            result_profile_index = decrypt_result.profile_index;
            result_group_index = decrypt_result.group_index;
        }
    } else {
        set_error(err, ARRAYSIZE(err), L"Unknown background work kind.");
    }

    if (work_succeeded && !app_work_cancelled()) {
        terminal_msg = WM_APP_WORK_DONE;
        terminal_text = result ? result : L"";
        if (ctx->kind == APP_WORK_KIND_IMPORT_KEY) {
            app_work_clear_key_export_cache();
        } else if (ctx->kind == APP_WORK_KIND_CREATE_GROUP || ctx->kind == APP_WORK_KIND_REKEY_GROUP) {
            clear_cached_group_exports();
            cache_group_export(result_group_index, result);
        }
    } else if (app_work_cancelled()) {
        terminal_msg = WM_APP_WORK_CANCELLED;
        terminal_text = L"";
    } else {
        terminal_msg = WM_APP_WORK_ERROR;
        terminal_text = err[0] ? err : WORK_BACKGROUND_FAILED_TEXT;
    }
    BOOL should_save_sent_plaintext = terminal_msg == WM_APP_WORK_DONE &&
        (ctx->kind == APP_WORK_KIND_ENCRYPT || ctx->kind == APP_WORK_KIND_GROUP_ENCRYPT);
    if (!post_work_text_kind(terminal_msg, ctx->target_textbox, terminal_text,
                             ctx->kind, result_profile_index, result_group_index,
                             decrypt_result.sender,
                             should_save_sent_plaintext ? ctx->sent_plaintext : NULL,
                             should_save_sent_plaintext ? ctx->sent_sender : NULL,
                             should_save_sent_plaintext ? ctx->sent_profile_index : -1,
                             should_save_sent_plaintext ? ctx->sent_group_index : -1)) {
        finish_unposted_terminal_work(terminal_msg);
    }
    app_flow_free_decrypt_result(&decrypt_result);
    secure_free_wide(result);
    app_work_free_ctx(ctx);
    return 0;
}
