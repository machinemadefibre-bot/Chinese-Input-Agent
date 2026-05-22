#include "app_clipboard_monitor.h"

#include "app_flow.h"
#include "app_shared.h"
#include "win_util.h"

#include <bcrypt.h>
#include <stdint.h>
#include <strsafe.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define CLIPBOARD_MIN_PROBE_CHARS 100
#define CLIPBOARD_HASH_CACHE_SIZE 64
#define CLIPBOARD_IGNORE_MS 60000ull

typedef struct HASH_SLOT {
    BOOL used;
    BYTE hash[32];
} HASH_SLOT;

typedef struct PROBE_THREAD_CTX {
    HWND owner;
    DWORD generation;
    WCHAR *text;
    BYTE hash[32];
} PROBE_THREAD_CTX;

typedef struct CLIPBOARD_PROBE_MESSAGE {
    BOOL matched;
    DWORD generation;
    WCHAR *text;
    BYTE hash[32];
    APP_FLOW_PROBE_RESULT result;
} CLIPBOARD_PROBE_MESSAGE;

static CRITICAL_SECTION g_clipboard_lock;
static BOOL g_clipboard_lock_ready;
static BOOL g_clipboard_stopping;
static BOOL g_probe_active;
static DWORD g_probe_generation;
static WCHAR *g_pending_text;
static BYTE g_pending_hash[32];
static BOOL g_pending_valid;
static BYTE g_last_opened_hash[32];
static BOOL g_last_opened_valid;
static HASH_SLOT g_failed_hashes[CLIPBOARD_HASH_CACHE_SIZE];
static HASH_SLOT g_ignored_hashes[CLIPBOARD_HASH_CACHE_SIZE];
static size_t g_failed_next;
static size_t g_ignored_next;
static ULONGLONG g_ignore_until_ms;

static BOOL hash_equal(const BYTE a[32], const BYTE b[32]) {
    return memcmp(a, b, 32) == 0;
}

static void remember_hash(HASH_SLOT *slots, size_t *next, const BYTE hash[32]) {
    if (!slots || !next || !hash) return;
    for (size_t idx = 0; idx < CLIPBOARD_HASH_CACHE_SIZE; ++idx) {
        if (slots[idx].used && hash_equal(slots[idx].hash, hash)) return;
    }
    HASH_SLOT *slot = &slots[*next % CLIPBOARD_HASH_CACHE_SIZE];
    slot->used = TRUE;
    CopyMemory(slot->hash, hash, 32);
    *next = (*next + 1) % CLIPBOARD_HASH_CACHE_SIZE;
}

static BOOL hash_in_cache(const HASH_SLOT *slots, const BYTE hash[32]) {
    if (!slots || !hash) return FALSE;
    for (size_t idx = 0; idx < CLIPBOARD_HASH_CACHE_SIZE; ++idx) {
        if (slots[idx].used && hash_equal(slots[idx].hash, hash)) return TRUE;
    }
    return FALSE;
}

static BOOL sha256_bytes(const BYTE *bytes, DWORD len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD obj_len = 0, hash_len = 0, cb = 0;
    BOOL ok = FALSE;
    if (!bytes || !out) return FALSE;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) < 0 ||
        hash_len != 32) goto cleanup;
    object = (BYTE *)xalloc(obj_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(alg, &hash, object, obj_len, NULL, 0, 0) < 0) goto cleanup;
    if (len && BCryptHashData(hash, (PUCHAR)bytes, len, 0) < 0) goto cleanup;
    if (BCryptFinishHash(hash, out, 32, 0) < 0) goto cleanup;
    ok = TRUE;
cleanup:
    if (!ok) SecureZeroMemory(out, 32);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(object, obj_len);
    return ok;
}

static size_t trimmed_char_count(const WCHAR *text) {
    const WCHAR *start = text ? text : L"";
    while (*start && iswspace(*start)) ++start;
    const WCHAR *end = start + wcslen(start);
    while (end > start && iswspace(end[-1])) --end;
    return (size_t)(end - start);
}

static void free_probe_message(CLIPBOARD_PROBE_MESSAGE *message) {
    if (!message) return;
    secure_free_wide(message->text);
    secure_free(message, sizeof(*message));
}

static BOOL probe_cancelled(void) {
    BOOL stopping = FALSE;
    if (!g_clipboard_lock_ready) return FALSE;
    EnterCriticalSection(&g_clipboard_lock);
    stopping = g_clipboard_stopping;
    LeaveCriticalSection(&g_clipboard_lock);
    return stopping;
}

static DWORD WINAPI probe_thread_proc_with_owner(LPVOID param) {
    PROBE_THREAD_CTX *ctx = (PROBE_THREAD_CTX *)param;
    HWND owner = ctx ? ctx->owner : NULL;
    DWORD generation = ctx ? ctx->generation : 0;
    CLIPBOARD_PROBE_MESSAGE *message = NULL;
    WCHAR err[256] = L"";
    if (!ctx) return 0;
    message = (CLIPBOARD_PROBE_MESSAGE *)xalloc(sizeof(*message));
    if (message) {
        message->generation = generation;
        CopyMemory(message->hash, ctx->hash, sizeof(message->hash));
        message->matched = app_flow_probe_clip_short(ctx->text, probe_cancelled,
                                                     &message->result, err, ARRAYSIZE(err));
        if (message->matched) {
            message->text = ctx->text;
            ctx->text = NULL;
        }
    }
    secure_free_wide(ctx->text);
    secure_free(ctx, sizeof(*ctx));

    BOOL should_post = FALSE;
    if (message && g_clipboard_lock_ready) {
        EnterCriticalSection(&g_clipboard_lock);
        should_post = !g_clipboard_stopping && generation == g_probe_generation;
        LeaveCriticalSection(&g_clipboard_lock);
    }
    if (!message || !should_post || !PostMessageW(owner, WM_APP_CLIPBOARD_PROBE_DONE, 0, (LPARAM)message)) {
        if (g_clipboard_lock_ready) {
            EnterCriticalSection(&g_clipboard_lock);
            g_probe_active = FALSE;
            LeaveCriticalSection(&g_clipboard_lock);
        }
        free_probe_message(message);
    }
    return 0;
}

BOOL app_clipboard_monitor_start(HWND owner) {
    if (!g_clipboard_lock_ready) {
        InitializeCriticalSection(&g_clipboard_lock);
        g_clipboard_lock_ready = TRUE;
    }
    EnterCriticalSection(&g_clipboard_lock);
    g_clipboard_stopping = FALSE;
    ++g_probe_generation;
    g_probe_active = FALSE;
    LeaveCriticalSection(&g_clipboard_lock);
    return AddClipboardFormatListener(owner);
}

void app_clipboard_monitor_stop(HWND owner) {
    if (owner) RemoveClipboardFormatListener(owner);
    if (!g_clipboard_lock_ready) return;
    EnterCriticalSection(&g_clipboard_lock);
    g_clipboard_stopping = TRUE;
    ++g_probe_generation;
    g_probe_active = FALSE;
    secure_free_wide(g_pending_text);
    g_pending_text = NULL;
    g_pending_valid = FALSE;
    LeaveCriticalSection(&g_clipboard_lock);
}

void app_clipboard_monitor_handle_update(HWND owner) {
    WCHAR *text = NULL;
    BYTE hash[32];
    ZeroMemory(hash, sizeof(hash));
    if (!win_get_clipboard_text(owner, &text)) return;
    size_t chars = wcslen(text);
    if (trimmed_char_count(text) <= CLIPBOARD_MIN_PROBE_CHARS ||
        chars > ((size_t)0xffffffffu / sizeof(WCHAR))) {
        xfree(text);
        return;
    }
    if (!sha256_bytes((const BYTE *)text, (DWORD)(chars * sizeof(WCHAR)), hash)) {
        xfree(text);
        return;
    }

    EnterCriticalSection(&g_clipboard_lock);
    BOOL should_skip = g_clipboard_stopping ||
                       g_probe_active ||
                       GetTickCount64() < g_ignore_until_ms ||
                       hash_in_cache(g_failed_hashes, hash) ||
                       hash_in_cache(g_ignored_hashes, hash) ||
                       (g_pending_valid && hash_equal(g_pending_hash, hash));
    DWORD generation = g_probe_generation;
    if (!should_skip) g_probe_active = TRUE;
    LeaveCriticalSection(&g_clipboard_lock);
    if (should_skip) {
        xfree(text);
        return;
    }

    PROBE_THREAD_CTX *ctx = (PROBE_THREAD_CTX *)xalloc(sizeof(*ctx));
    if (!ctx) {
        EnterCriticalSection(&g_clipboard_lock);
        g_probe_active = FALSE;
        LeaveCriticalSection(&g_clipboard_lock);
        xfree(text);
        return;
    }
    ctx->owner = owner;
    ctx->generation = generation;
    ctx->text = text;
    CopyMemory(ctx->hash, hash, sizeof(ctx->hash));
    HANDLE thread = CreateThread(NULL, 0, probe_thread_proc_with_owner, ctx, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    } else {
        EnterCriticalSection(&g_clipboard_lock);
        g_probe_active = FALSE;
        LeaveCriticalSection(&g_clipboard_lock);
        secure_free_wide(ctx->text);
        secure_free(ctx, sizeof(*ctx));
    }
}

BOOL app_clipboard_monitor_complete_probe(LPARAM lparam) {
    CLIPBOARD_PROBE_MESSAGE *message = (CLIPBOARD_PROBE_MESSAGE *)lparam;
    BOOL has_pending = FALSE;
    if (!message) return FALSE;
    EnterCriticalSection(&g_clipboard_lock);
    g_probe_active = FALSE;
    if (message->generation != g_probe_generation || g_clipboard_stopping) {
        has_pending = FALSE;
    } else if (message->matched && !hash_in_cache(g_ignored_hashes, message->hash)) {
        secure_free_wide(g_pending_text);
        g_pending_text = message->text;
        message->text = NULL;
        CopyMemory(g_pending_hash, message->hash, sizeof(g_pending_hash));
        g_pending_valid = TRUE;
        has_pending = TRUE;
    } else {
        remember_hash(g_failed_hashes, &g_failed_next, message->hash);
    }
    LeaveCriticalSection(&g_clipboard_lock);
    free_probe_message(message);
    return has_pending;
}

BOOL app_clipboard_monitor_has_pending(void) {
    BOOL has_pending;
    EnterCriticalSection(&g_clipboard_lock);
    has_pending = g_pending_valid && g_pending_text && g_pending_text[0];
    LeaveCriticalSection(&g_clipboard_lock);
    return has_pending;
}

WCHAR *app_clipboard_monitor_take_pending_text(void) {
    WCHAR *text = NULL;
    EnterCriticalSection(&g_clipboard_lock);
    if (g_pending_valid && g_pending_text) {
        text = g_pending_text;
        g_pending_text = NULL;
        CopyMemory(g_last_opened_hash, g_pending_hash, sizeof(g_last_opened_hash));
        g_last_opened_valid = TRUE;
        g_pending_valid = FALSE;
    }
    LeaveCriticalSection(&g_clipboard_lock);
    return text;
}

void app_clipboard_monitor_ignore_pending(void) {
    EnterCriticalSection(&g_clipboard_lock);
    if (g_pending_valid) remember_hash(g_ignored_hashes, &g_ignored_next, g_pending_hash);
    g_ignore_until_ms = GetTickCount64() + CLIPBOARD_IGNORE_MS;
    secure_free_wide(g_pending_text);
    g_pending_text = NULL;
    g_pending_valid = FALSE;
    LeaveCriticalSection(&g_clipboard_lock);
}

void app_clipboard_monitor_mark_last_opened_done(void) {
    EnterCriticalSection(&g_clipboard_lock);
    if (g_last_opened_valid) remember_hash(g_ignored_hashes, &g_ignored_next, g_last_opened_hash);
    g_last_opened_valid = FALSE;
    LeaveCriticalSection(&g_clipboard_lock);
}

void app_clipboard_monitor_mark_last_opened_failed(void) {
    EnterCriticalSection(&g_clipboard_lock);
    if (g_last_opened_valid) remember_hash(g_failed_hashes, &g_failed_next, g_last_opened_hash);
    g_last_opened_valid = FALSE;
    LeaveCriticalSection(&g_clipboard_lock);
}
