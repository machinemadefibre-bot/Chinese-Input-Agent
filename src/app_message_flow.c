#include "app_message_flow.h"

#include "app_carrier_flow.h"
#include "app_groups.h"
#include "app_profiles.h"
#include "app_shared.h"

#include <strsafe.h>

void app_message_flow_free_decrypt_result(APP_FLOW_DECRYPT_RESULT *result) {
    if (!result) return;
    secure_free_wide(result->plain);
    secure_free_wide(result->sender);
    ZeroMemory(result, sizeof(*result));
}

static BOOL decrypt_sealed_with_box(CRYPTO_BOX *box, const BYTE *sealed, DWORD sealed_len,
                                    WCHAR **plain_w_out, WCHAR *err, size_t err_cch) {
    *plain_w_out = NULL;
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    if (!crypto_box_decrypt(box, sealed, sealed_len, &plain, &plain_len, err, err_cch)) {
        return FALSE;
    }

    if ((plain_len % sizeof(WCHAR)) != 0) {
        secure_free(plain, plain_len);
        set_error(err, err_cch, L"Decrypted plaintext has an invalid UTF-16 length.");
        return FALSE;
    }
    size_t plain_chars = plain_len / sizeof(WCHAR);
    WCHAR *plain_w = (WCHAR *)xalloc((plain_chars + 1) * sizeof(WCHAR));
    if (!plain_w) {
        secure_free(plain, plain_len);
        set_error(err, err_cch, L"Out of memory while decoding plaintext.");
        return FALSE;
    }
    CopyMemory(plain_w, plain, plain_len);
    plain_w[plain_chars] = L'\0';
    secure_free(plain, plain_len);
    *plain_w_out = plain_w;
    return TRUE;
}

BOOL app_message_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
                                      HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!box || !plain) {
        set_error(err, err_cch, L"Invalid encryption request.");
        return FALSE;
    }
    size_t plain_chars = wcslen(plain);
    if (plain_chars > (((DWORD)0xffffffffu) / sizeof(WCHAR))) {
        set_error(err, err_cch, L"Plaintext is too large to encrypt.");
        return FALSE;
    }
    DWORD plain_len = (DWORD)(plain_chars * sizeof(WCHAR));

    BYTE *sealed = NULL;
    DWORD sealed_len = 0;
    if (!crypto_box_encrypt(box, (const BYTE *)plain, plain_len, &sealed, &sealed_len, err, err_cch)) {
        return FALSE;
    }

    WCHAR seed[256] = L"";
    if (!app_carrier_get_message_seed(box, seed, ARRAYSIZE(seed), TRUE, err, err_cch)) {
        secure_free(sealed, sealed_len);
        return FALSE;
    }

    BOOL carrier_encoded = app_carrier_encode_message_payload(sealed, sealed_len, seed, topic,
                                                              progress_target, out, err, err_cch);
    secure_free(sealed, sealed_len);
    return carrier_encoded;
}

BOOL app_message_flow_encrypt_group_message(int group_index, const WCHAR *plain, const WCHAR *topic,
                                            HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!plain) {
        set_error(err, err_cch, L"Invalid group encryption request.");
        return FALSE;
    }
    BYTE *sealed = NULL;
    DWORD sealed_len = 0;
    if (!app_groups_encrypt_message(group_index, plain, &sealed, &sealed_len, err, err_cch)) {
        return FALSE;
    }
    WCHAR seed[256] = L"";
    if (!app_groups_get_message_seed(group_index, seed, ARRAYSIZE(seed))) {
        secure_free(sealed, sealed_len);
        set_error(err, err_cch, L"Failed to build group message seed.");
        return FALSE;
    }
    BOOL carrier_encoded = app_carrier_encode_message_payload(sealed, sealed_len, seed, topic,
                                                              progress_target, out, err, err_cch);
    secure_free(sealed, sealed_len);
    return carrier_encoded;
}

BOOL app_message_flow_decrypt_clip_auto(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        APP_FLOW_DECRYPT_RESULT *result,
                                        WCHAR *err, size_t err_cch) {
    if (!result) {
        set_error(err, err_cch, L"Invalid decrypt result buffer.");
        return FALSE;
    }
    ZeroMemory(result, sizeof(*result));
    result->profile_index = -1;
    result->group_index = -1;

    WCHAR group_last_err[768] = L"";
    for (int group_index = 0; group_index < app_groups_count(); ++group_index) {
        if (cancel_fn && cancel_fn()) {
            set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            return FALSE;
        }
        WCHAR seed[256] = L"";
        if (!app_groups_get_message_seed(group_index, seed, ARRAYSIZE(seed))) continue;
        BYTE *group_sealed = NULL;
        DWORD group_sealed_len = 0;
        WCHAR local_err[768] = L"";
        if (!app_carrier_decode_message_payload(clip, seed, &group_sealed, &group_sealed_len,
                                                local_err, ARRAYSIZE(local_err))) {
            if (local_err[0]) StringCchCopyW(group_last_err, ARRAYSIZE(group_last_err), local_err);
            continue;
        }
        WCHAR *plain_w = NULL;
        WCHAR *sender_w = NULL;
        int decrypted_group_index = -1;
        BOOL group_decrypted = app_groups_decrypt_message(group_sealed, group_sealed_len,
                                                          &plain_w, &sender_w, &decrypted_group_index,
                                                          local_err, ARRAYSIZE(local_err));
        secure_free(group_sealed, group_sealed_len);
        if (group_decrypted) {
            result->plain = plain_w;
            result->sender = sender_w;
            result->group_index = decrypted_group_index;
            result->is_group = TRUE;
            return TRUE;
        }
        secure_free_wide(plain_w);
        secure_free_wide(sender_w);
        if (local_err[0]) StringCchCopyW(group_last_err, ARRAYSIZE(group_last_err), local_err);
    }

    int original = profiles_active_index();
    WCHAR last_err[768] = L"";
    WCHAR local_decode_err[768] = L"";
    BOOL saw_local_decode_error = FALSE;
    BOOL saw_local_payload = FALSE;

    int count = profiles_count();
    for (int pass = 0; pass < count; ++pass) {
        if (cancel_fn && cancel_fn()) {
            set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            return FALSE;
        }
        int index;
        if (original >= 0 && original < count && pass == count - 1) {
            index = original;
        } else {
            index = pass;
            if (original >= 0 && original < count && index >= original) index++;
        }
        if (index < 0 || index >= count) continue;

        WCHAR local_err[768] = L"";
        CRYPTO_BOX *box = NULL;
        if (!profiles_open_crypto(index, &box, local_err, ARRAYSIZE(local_err))) {
            StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err[0] ? local_err : L"");
            continue;
        }

        WCHAR *plain_w = NULL;
        WCHAR seed[256] = L"";
        BYTE *local_sealed = NULL;
        DWORD local_sealed_len = 0;
        BOOL have_local_payload = FALSE;
        if (app_carrier_get_message_seed(box, seed, ARRAYSIZE(seed), FALSE, local_err, ARRAYSIZE(local_err))) {
            have_local_payload = app_carrier_decode_message_payload(clip, seed, &local_sealed, &local_sealed_len,
                                                                    local_decode_err, ARRAYSIZE(local_decode_err));
            if (!have_local_payload) {
                if (local_decode_err[0]) {
                    saw_local_decode_error = TRUE;
                    StringCchCopyW(local_err, ARRAYSIZE(local_err), local_decode_err);
                } else {
                    StringCchCopyW(local_err, ARRAYSIZE(local_err), L"Local top-k decode failed without a diagnostic message.");
                }
            }
        }
        if (have_local_payload) saw_local_payload = TRUE;
        BOOL decrypt_succeeded = have_local_payload &&
            decrypt_sealed_with_box(box, local_sealed, local_sealed_len, &plain_w, local_err, ARRAYSIZE(local_err));
        crypto_box_close(box);
        secure_free(local_sealed, local_sealed_len);
        if (decrypt_succeeded) {
            result->plain = plain_w;
            result->profile_index = index;
            result->is_group = FALSE;
            profiles_lock_inactive_masters();
            return TRUE;
        }
        StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err[0] ? local_err : L"");
    }
    profiles_lock_inactive_masters();

    if (saw_local_decode_error && !saw_local_payload && local_decode_err[0]) {
        set_error(err, err_cch,
                  L"Local top-k decode failed before decryption: %s",
                  local_decode_err);
    } else if (last_err[0]) {
        set_error(err, err_cch, L"\u6ca1\u6709\u627e\u5230\u80fd\u89e3\u5bc6\u8fd9\u6bb5\u6587\u5b57\u7684\u5bc6\u94a5\u3002\u6700\u540e\u9519\u8bef\uff1a%s", last_err);
    } else if (group_last_err[0]) {
        set_error(err, err_cch, L"No group was able to decode or decrypt the clipboard text. Last error: %s", group_last_err);
    } else {
        set_error(err, err_cch, L"No profile was able to decode or decrypt the clipboard text.");
    }
    return FALSE;
}

BOOL app_message_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                                WCHAR **plain_w_out, int *profile_index_out,
                                                WCHAR *err, size_t err_cch) {
    APP_FLOW_DECRYPT_RESULT result;
    *plain_w_out = NULL;
    if (profile_index_out) *profile_index_out = -1;
    if (!app_message_flow_decrypt_clip_auto(clip, cancel_fn, &result, err, err_cch)) {
        return FALSE;
    }
    *plain_w_out = result.plain;
    result.plain = NULL;
    if (profile_index_out) *profile_index_out = result.profile_index;
    app_message_flow_free_decrypt_result(&result);
    return TRUE;
}
