#include "app_archive.h"
#include "app_chat_history.h"
#include "app_profiles.h"
#include "app_shared.h"

typedef struct ARCHIVE_APPEND_CTX {
    WCHAR profile_id[64];
    const WCHAR *sender;
    const WCHAR *plain;
} ARCHIVE_APPEND_CTX;

static BOOL archive_append_with_master(const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES],
                                       void *user,
                                       WCHAR *err,
                                       size_t err_cch)
{
    ARCHIVE_APPEND_CTX *ctx = (ARCHIVE_APPEND_CTX *)user;
    return chat_history_append_private(ctx->profile_id,
                                       master_key,
                                       ctx->sender,
                                       ctx->plain,
                                       err,
                                       err_cch);
}

BOOL archive_append_text(int profile_index, const WCHAR *sender, const WCHAR *plain,
                         WCHAR *err, size_t err_cch)
{
    ARCHIVE_APPEND_CTX append_ctx;
    WCHAR profile_name[128] = L"";
    ZeroMemory(&append_ctx, sizeof(append_ctx));
    if (!profiles_get_id_copy(profile_index, append_ctx.profile_id, ARRAYSIZE(append_ctx.profile_id))) {
        set_error(err, err_cch, L"Archive profile id is not available.");
        return FALSE;
    }
    if (sender && sender[0]) {
        append_ctx.sender = sender;
    } else {
        profiles_get_name_copy(profile_index, profile_name, ARRAYSIZE(profile_name));
        append_ctx.sender = profile_name[0] ? profile_name : L"\u672a\u547d\u540d";
    }
    append_ctx.plain = plain ? plain : L"";
    return profiles_with_master_key(profile_index,
                                    archive_append_with_master,
                                    &append_ctx,
                                    err,
                                    err_cch);
}

typedef struct ARCHIVE_LOAD_CTX {
    WCHAR profile_id[64];
    WCHAR **out;
} ARCHIVE_LOAD_CTX;

static BOOL archive_load_with_master(const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES],
                                     void *user,
                                     WCHAR *err,
                                     size_t err_cch)
{
    ARCHIVE_LOAD_CTX *ctx = (ARCHIVE_LOAD_CTX *)user;
    return chat_history_load_private(ctx->profile_id, master_key, ctx->out, err, err_cch);
}

BOOL archive_load_text(int profile_index, WCHAR **out, WCHAR *err, size_t err_cch)
{
    ARCHIVE_LOAD_CTX load_ctx;
    ZeroMemory(&load_ctx, sizeof(load_ctx));
    if (out) {
        *out = NULL;
    }
    if (!out) {
        set_error(err, err_cch, L"Archive output is not available.");
        return FALSE;
    }
    if (!profiles_get_id_copy(profile_index, load_ctx.profile_id, ARRAYSIZE(load_ctx.profile_id))) {
        set_error(err, err_cch, L"Archive profile id is not available.");
        return FALSE;
    }
    load_ctx.out = out;
    return profiles_with_master_key(profile_index,
                                    archive_load_with_master,
                                    &load_ctx,
                                    err,
                                    err_cch);
}

