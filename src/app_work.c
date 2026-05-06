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

static DWORD WINAPI work_thread_proc(LPVOID param);
static void reset_work_state_flags(void);

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
    return ctx;
}

void app_work_free_ctx(APP_WORK_CTX *ctx) {
    if (!ctx) return;
    secure_free_wide(ctx->input);
    xfree(ctx->topic);
    xfree(ctx->name);
    xfree(ctx);
}

void app_work_free_message(APP_WORK_MESSAGE *message) {
    if (!message) return;
    secure_free_wide(message->text);
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

static BOOL post_work_text_kind(UINT msg, HWND target_textbox, const WCHAR *text, APP_WORK_KIND kind) {
    APP_WORK_MESSAGE *message = (APP_WORK_MESSAGE *)xalloc(sizeof(*message));
    if (!message) return FALSE;
    message->kind = kind;
    message->target_textbox = target_textbox;
    message->text = win_dup_wide(text ? text : L"");
    if (!message->text) {
        xfree(message);
        return FALSE;
    }
    if (!g_host.main_window || !PostMessageW(g_host.main_window, msg, 0, (LPARAM)message)) {
        secure_free_wide(message->text);
        xfree(message);
        return FALSE;
    }
    return TRUE;
}

static BOOL post_work_text(UINT msg, HWND target_textbox, const WCHAR *text) {
    return post_work_text_kind(msg, target_textbox, text, 0);
}

static void finish_unposted_terminal_work(UINT msg) {
    /* Without a terminal UI message, no handler will clear the active/cancel flags. */
    if (g_host.main_window && PostMessageW(g_host.main_window, msg, 0, 0)) return;
    reset_work_state_flags();
}

void app_work_post_llm_stream_progress(HWND target_textbox, const WCHAR *partial,
                                       size_t tokens_done, size_t tokens_total, double tps) {
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
    return app_flow_encrypt_message(box, ctx ? ctx->input : NULL, ctx ? ctx->topic : NULL,
                                    ctx ? ctx->target_textbox : NULL, out, err, err_cch);
}

static BOOL worker_export_key(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    CRYPTO_BOX *box = active_box();
    if (!box) {
        set_error(err, err_cch, L"No active crypto context is open.");
        return FALSE;
    }
    return app_flow_export_key(box, ctx ? ctx->target_textbox : NULL, out, err, err_cch);
}

static BOOL worker_import_key(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    int imported_index = -1;
    return app_flow_import_key(ctx ? ctx->input : NULL, ctx ? ctx->name : NULL,
                               &imported_index, out, err, err_cch);
}

static BOOL worker_decrypt(APP_WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!ctx || !ctx->input || !ctx->input[0]) {
        set_error(err, err_cch, L"Clipboard text is empty.");
        return FALSE;
    }
    return app_flow_decrypt_clip_auto_profile(ctx->input, app_work_cancelled, out, err, err_cch);
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

    if (ctx->kind == APP_WORK_KIND_ENCRYPT) {
        work_succeeded = worker_encrypt(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_EXPORT_KEY) {
        work_succeeded = worker_export_key(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_IMPORT_KEY) {
        work_succeeded = worker_import_key(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == APP_WORK_KIND_DECRYPT) {
        work_succeeded = worker_decrypt(ctx, &result, err, ARRAYSIZE(err));
    } else {
        set_error(err, ARRAYSIZE(err), L"Unknown background work kind.");
    }

    if (work_succeeded && !app_work_cancelled()) {
        terminal_msg = WM_APP_WORK_DONE;
        terminal_text = result ? result : L"";
    } else if (app_work_cancelled()) {
        terminal_msg = WM_APP_WORK_CANCELLED;
        terminal_text = L"";
    } else {
        terminal_msg = WM_APP_WORK_ERROR;
        terminal_text = err[0] ? err : WORK_BACKGROUND_FAILED_TEXT;
    }
    if (!post_work_text_kind(terminal_msg, ctx->target_textbox, terminal_text, ctx->kind)) {
        finish_unposted_terminal_work(terminal_msg);
    }
    secure_free_wide(result);
    app_work_free_ctx(ctx);
    return 0;
}
