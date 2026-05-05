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

#include "app_flow.h"

#include "app_llm.h"
#include "app_profiles.h"
#include "app_shared.h"

#include <bcrypt.h>
#include <strsafe.h>
#include <stdint.h>

#define MASTER_KEY_BYTES APP_PROFILE_MASTER_KEY_BYTES
#define MAX_PROFILES APP_PROFILE_MAX_PROFILES

static const WCHAR KEY_PACKAGE_PREFIX_START[] = L"\u4f60\u597d\uff0c\u6211\u662f\u7f16\u53f7";
static const WCHAR KEY_PACKAGE_PREFIX_END[] = L"\uff0c\u8fd9\u662f\u6211\u7684\u81ea\u6211\u4ecb\u7ecd\u3002";
static const WCHAR KEY_PACKAGE_TOPK_SEED[] = L"ChineseInputAgent key-exchange top-k payload v1";
static const WCHAR KEY_PACKAGE_TOPIC[] = L"\u81ea\u6211\u4ecb\u7ecd";

static WCHAR *flow_dup_wide(const WCHAR *s) {
    size_t len = wcslen(s ? s : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, s ? s : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

static BOOL append_hex_bytes(WCHAR *dst, size_t dst_cch, size_t offset, const BYTE *data, DWORD len) {
    static const WCHAR hex[] = L"0123456789abcdef";
    if (!dst || !data || dst_cch <= offset || (dst_cch - offset) < (size_t)len * 2 + 1) return FALSE;
    WCHAR *p = dst + offset;
    for (DWORD i = 0; i < len; ++i) {
        p[i * 2] = hex[(data[i] >> 4) & 0xf];
        p[i * 2 + 1] = hex[data[i] & 0xf];
    }
    p[(size_t)len * 2] = L'\0';
    return TRUE;
}

static BOOL format_topk_seed_from_public_key(WCHAR *seed, size_t seed_cch, const BYTE *public_key,
                                             DWORD public_key_len, WCHAR *err, size_t err_cch) {
    const WCHAR prefix[] = L"ChineseInputAgent top-k payload seed v1:";
    size_t prefix_len = wcslen(prefix);
    BOOL ok = SUCCEEDED(StringCchCopyW(seed, seed_cch, prefix)) &&
              append_hex_bytes(seed, seed_cch, prefix_len, public_key, public_key_len);
    if (!ok) {
        set_error(err, err_cch, L"Failed to build top-k seed from contact public key.");
        return FALSE;
    }
    return TRUE;
}

static BOOL get_message_topk_seed(CRYPTO_BOX *box, WCHAR *seed, size_t seed_cch,
                                  BOOL prefer_remote, WCHAR *err, size_t err_cch) {
    BYTE *public_key = NULL;
    DWORD public_key_len = 0;
    WCHAR local_err[256] = L"";
    if (prefer_remote &&
        crypto_box_get_remote_public_key(box, &public_key, &public_key_len, local_err, ARRAYSIZE(local_err))) {
        BOOL ok = format_topk_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
        xfree(public_key);
        return ok;
    }
    if (!crypto_box_get_public_key(box, &public_key, &public_key_len, err, err_cch)) {
        return FALSE;
    }
    BOOL ok = format_topk_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
    xfree(public_key);
    return ok;
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

BOOL app_flow_extract_key_package_body(const WCHAR *text, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    WCHAR *start = wcsstr(text ? text : L"", KEY_PACKAGE_PREFIX_START);
    if (!start) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    WCHAR *body = wcsstr(start, KEY_PACKAGE_PREFIX_END);
    if (!body) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    body += wcslen(KEY_PACKAGE_PREFIX_END);
    *out = flow_dup_wide(body);
    if (!*out) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    return TRUE;
}

BOOL app_flow_encrypt_message(CRYPTO_BOX *box, const WCHAR *plain, const WCHAR *topic,
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
    if (!get_message_topk_seed(box, seed, ARRAYSIZE(seed), TRUE, err, err_cch)) {
        secure_free(sealed, sealed_len);
        return FALSE;
    }

    BOOL ok = local_topk_encode_payload(sealed, sealed_len, seed, topic, NULL, -1,
                                        progress_target, out, err, err_cch);
    secure_free(sealed, sealed_len);
    return ok;
}

BOOL app_flow_export_key(CRYPTO_BOX *box, HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    if (!crypto_box_prepare_key_export(box, err, err_cch) ||
        !crypto_box_export_contact_package(box, &pkg, &pkg_len, err, err_cch)) {
        return FALSE;
    }

    WCHAR fingerprint[32] = L"";
    if (!crypto_box_get_public_fingerprint(box, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    WSTRB prefix = {0};
    if (!wstrb_append(&prefix, KEY_PACKAGE_PREFIX_START) ||
        !wstrb_append(&prefix, fingerprint) ||
        !wstrb_append(&prefix, KEY_PACKAGE_PREFIX_END)) {
        secure_free(pkg, pkg_len);
        wstrb_free(&prefix);
        set_error(err, err_cch, L"Failed to build key package prefix.");
        return FALSE;
    }
    BOOL ok = local_topk_encode_payload(pkg, pkg_len, KEY_PACKAGE_TOPK_SEED, KEY_PACKAGE_TOPIC,
                                        prefix.data, 0, progress_target, out, err, err_cch);
    wstrb_free(&prefix);
    secure_free(pkg, pkg_len);
    return ok;
}

BOOL app_flow_import_key(const WCHAR *carrier, const WCHAR *name, int *active_index_out,
                         WCHAR **out_message, WCHAR *err, size_t err_cch) {
    if (active_index_out) *active_index_out = -1;
    *out_message = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    if (!local_topk_decode_payload(carrier, KEY_PACKAGE_TOPK_SEED, &pkg, &pkg_len, err, err_cch)) {
        return FALSE;
    }
    WCHAR fingerprint[32] = L"";
    if (!crypto_box_contact_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    if (profiles_count() >= MAX_PROFILES) {
        secure_free(pkg, pkg_len);
        set_error(err, err_cch, L"\u5bc6\u94a5\u6570\u91cf\u5df2\u8fbe\u5230\u4e0a\u9650\u3002");
        return FALSE;
    }

    BYTE master[MASTER_KEY_BYTES];
    if (BCryptGenRandom(NULL, master, sizeof(master), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        secure_free(pkg, pkg_len);
        set_error(err, err_cch, L"\u65e0\u6cd5\u751f\u6210\u672c\u5730\u968f\u673a\u5bc6\u94a5\u3002");
        return FALSE;
    }
    KEY_PROFILE imported;
    if (!profiles_create_from_master(name, master, &imported, err, err_cch)) {
        SecureZeroMemory(master, sizeof(master));
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    SecureZeroMemory(master, sizeof(master));

    int original = profiles_active_index();
    int imported_index = -1;
    if (!profiles_append_imported(&imported, &imported_index, err, err_cch)) {
        profiles_clear_profile(&imported);
        secure_free(pkg, pkg_len);
        return FALSE;
    }

    CRYPTO_BOX *box = NULL;
    BOOL ok = profiles_save() &&
              profiles_open_crypto(imported_index, &box, err, err_cch) &&
              crypto_box_import_contact_package(box, pkg, pkg_len, err, err_cch) &&
              profiles_activate(imported_index, err, err_cch);
    crypto_box_close(box);
    secure_free(pkg, pkg_len);

    if (!ok) {
        WCHAR state_path[MAX_PATH];
        KEY_PROFILE *failed_profile = profiles_get(imported_index);
        if (failed_profile && profiles_get_state_path(failed_profile, state_path, ARRAYSIZE(state_path))) {
            secure_delete_file(state_path);
        }
        profiles_remove_at(imported_index);
        if (original >= 0 && original < profiles_count()) {
            WCHAR restore_err[256] = L"";
            profiles_activate(original, restore_err, ARRAYSIZE(restore_err));
        } else {
            profiles_save();
        }
        return FALSE;
    }
    if (active_index_out) *active_index_out = imported_index;

    WSTRB msg = {0};
    if (!wstrb_appendf(&msg, L"\u8054\u7cfb\u4eba\u516c\u94a5\u5df2\u5bfc\u5165\u3002\r\n\r\n\u8bf7\u81ea\u884c\u786e\u8ba4\u6307\u7eb9\u662f\u5426\u4e0e\u660e\u6587\u76f8\u540c\uff1a%s", fingerprint)) {
        set_error(err, err_cch, L"\u5bfc\u5165\u7ed3\u679c\u6d88\u606f\u6784\u9020\u5931\u8d25\u3002");
        return FALSE;
    }
    *out_message = msg.data;
    return TRUE;
}

BOOL app_flow_decrypt_clip_auto_profile(const WCHAR *clip, APP_FLOW_CANCEL_FN cancel_fn,
                                        WCHAR **plain_w_out, WCHAR *err, size_t err_cch) {
    *plain_w_out = NULL;
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
        if (get_message_topk_seed(box, seed, ARRAYSIZE(seed), FALSE, local_err, ARRAYSIZE(local_err))) {
            have_local_payload = local_topk_decode_payload(clip, seed, &local_sealed, &local_sealed_len,
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
        BOOL ok = have_local_payload &&
            decrypt_sealed_with_box(box, local_sealed, local_sealed_len, &plain_w, local_err, ARRAYSIZE(local_err));
        crypto_box_close(box);
        secure_free(local_sealed, local_sealed_len);
        if (ok) {
            *plain_w_out = plain_w;
            return TRUE;
        }
        StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err[0] ? local_err : L"");
    }

    if (saw_local_decode_error && !saw_local_payload && local_decode_err[0]) {
        set_error(err, err_cch,
                  L"Local top-k decode failed before decryption: %s",
                  local_decode_err);
    } else if (last_err[0]) {
        set_error(err, err_cch, L"\u6ca1\u6709\u627e\u5230\u80fd\u89e3\u5bc6\u8fd9\u6bb5\u6587\u5b57\u7684\u5bc6\u94a5\u3002\u6700\u540e\u9519\u8bef\uff1a%s", last_err);
    } else {
        set_error(err, err_cch, L"No profile was able to decode or decrypt the clipboard text.");
    }
    return FALSE;
}
