#include "app_carrier_flow.h"

#include "app_llm.h"
#include "app_shared.h"

#include <strsafe.h>

/* Carrier protocol text and seeds. Keep stable for existing encoded key/message payloads. */
static const WCHAR KEY_PACKAGE_PREFIX_START[] = L"\u4f60\u597d\uff0c\u6211\u662f\u7f16\u53f7";
static const WCHAR KEY_PACKAGE_PREFIX_END[] = L"\uff0c\u8fd9\u662f\u6211\u7684\u81ea\u6211\u4ecb\u7ecd\u3002";
static const WCHAR GROUP_PACKAGE_PREFIX_START[] = L"\u4f60\u597d\uff01\u6211\u4eec\u7684\u793e\u56e2\u7f16\u53f7\u662f";
static const WCHAR GROUP_PACKAGE_PREFIX_END[] = L"\u3002\u8fd9\u662f\u6211\u4eec\u793e\u56e2\u7684\u4ecb\u7ecd\u3002";
static const WCHAR KEY_PACKAGE_TOPK_SEED[] = L"ChineseInputAgent key-exchange top-k payload v1";
static const WCHAR CONTACT_KEY_PACKAGE_TOPIC[] = L"\u6c42\u804c\u81ea\u6211\u4ecb\u7ecd";
static const WCHAR GROUP_KEY_PACKAGE_TOPIC[] = L"\u793e\u56e2\u62db\u65b0\u7b80\u4ecb\u3001\u793e\u56e2\u4ecb\u7ecd";
static const WCHAR CONTACT_KEY_PROMPT_TEMPLATE[] = L"self_intro";
static const WCHAR GROUP_KEY_PROMPT_TEMPLATE[] = L"group_key";
static const size_t KEY_PACKAGE_FINGERPRINT_CHARS = 8;

static WCHAR *carrier_dup_wide(const WCHAR *s) {
    size_t len = wcslen(s ? s : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, s ? s : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

static BOOL is_base32_fingerprint(const WCHAR *fingerprint, size_t fingerprint_len) {
    static const WCHAR alphabet[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    if (!fingerprint || fingerprint_len != KEY_PACKAGE_FINGERPRINT_CHARS) return FALSE;
    for (size_t char_idx = 0; char_idx < fingerprint_len; ++char_idx) {
        if (!wcschr(alphabet, fingerprint[char_idx])) return FALSE;
    }
    return TRUE;
}

static BOOL extract_prefixed_exchange_body(const WCHAR *text,
                                           const WCHAR *prefix_start,
                                           const WCHAR *prefix_end,
                                           WCHAR **out,
                                           WCHAR *fingerprint,
                                           size_t fingerprint_cch,
                                           WCHAR *err,
                                           size_t err_cch) {
    *out = NULL;
    if (fingerprint && fingerprint_cch) fingerprint[0] = L'\0';
    WCHAR *start = wcsstr(text ? text : L"", prefix_start);
    if (!start) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    WCHAR *fingerprint_start = start + wcslen(prefix_start);
    WCHAR *body = wcsstr(fingerprint_start, prefix_end);
    if (!body) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    size_t fingerprint_len = (size_t)(body - fingerprint_start);
    if (!fingerprint || fingerprint_cch == 0 || fingerprint_len >= fingerprint_cch ||
        !is_base32_fingerprint(fingerprint_start, fingerprint_len)) {
        set_error(err, err_cch, L"\u5bc6\u94a5\u6307\u7eb9\u7f3a\u5931\u6216\u683c\u5f0f\u65e0\u6548\u3002");
        return FALSE;
    }
    CopyMemory(fingerprint, fingerprint_start, fingerprint_len * sizeof(WCHAR));
    fingerprint[fingerprint_len] = L'\0';
    body += wcslen(prefix_end);
    *out = carrier_dup_wide(body);
    if (!*out) {
        set_error(err, err_cch, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    return TRUE;
}

BOOL app_carrier_extract_exchange_body(const WCHAR *text, APP_FLOW_EXCHANGE_KIND *kind_out,
                                       WCHAR **out, WCHAR *fingerprint, size_t fingerprint_cch,
                                       WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (kind_out) *kind_out = APP_FLOW_EXCHANGE_CONTACT;
    WCHAR local_err[256] = L"";
    if (extract_prefixed_exchange_body(text, GROUP_PACKAGE_PREFIX_START, GROUP_PACKAGE_PREFIX_END,
                                       out, fingerprint, fingerprint_cch, local_err, ARRAYSIZE(local_err))) {
        if (kind_out) *kind_out = APP_FLOW_EXCHANGE_GROUP;
        return TRUE;
    }
    if (extract_prefixed_exchange_body(text, KEY_PACKAGE_PREFIX_START, KEY_PACKAGE_PREFIX_END,
                                       out, fingerprint, fingerprint_cch, err, err_cch)) {
        if (kind_out) *kind_out = APP_FLOW_EXCHANGE_CONTACT;
        return TRUE;
    }
    if (local_err[0]) set_error(err, err_cch, L"%s", local_err);
    return FALSE;
}

BOOL app_carrier_extract_contact_package_body(const WCHAR *text, WCHAR **out,
                                              WCHAR *fingerprint, size_t fingerprint_cch,
                                              WCHAR *err, size_t err_cch) {
    return extract_prefixed_exchange_body(text, KEY_PACKAGE_PREFIX_START, KEY_PACKAGE_PREFIX_END,
                                          out, fingerprint, fingerprint_cch, err, err_cch);
}

static BOOL encode_exchange_package(const BYTE *pkg, DWORD pkg_len,
                                    const WCHAR *fingerprint,
                                    const WCHAR *prefix_start,
                                    const WCHAR *prefix_end,
                                    const WCHAR *topic,
                                    const WCHAR *prompt_template,
                                    const CIA_PROGRESS_SINK *progress,
                                    WCHAR **out,
                                    WCHAR *err,
                                    size_t err_cch) {
    WSTRB prefix = {0};
    if (!wstrb_append(&prefix, prefix_start) ||
        !wstrb_append(&prefix, fingerprint ? fingerprint : L"") ||
        !wstrb_append(&prefix, prefix_end)) {
        wstrb_free(&prefix);
        set_error(err, err_cch, L"Failed to build exchange package prefix.");
        return FALSE;
    }
    BOOL package_encoded = local_topk_encode_payload(pkg, pkg_len, KEY_PACKAGE_TOPK_SEED, topic, prompt_template,
                                                     prefix.data, -1, NULL, progress, out, err, err_cch);
    wstrb_free(&prefix);
    return package_encoded;
}

BOOL app_carrier_encode_contact_package(const BYTE *pkg, DWORD pkg_len, const WCHAR *fingerprint,
                                        const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return encode_exchange_package(pkg, pkg_len, fingerprint,
                                   KEY_PACKAGE_PREFIX_START, KEY_PACKAGE_PREFIX_END,
                                   CONTACT_KEY_PACKAGE_TOPIC, CONTACT_KEY_PROMPT_TEMPLATE,
                                   progress, out, err, err_cch);
}

BOOL app_carrier_encode_group_package(const BYTE *pkg, DWORD pkg_len, const WCHAR *fingerprint,
                                      const CIA_PROGRESS_SINK *progress, WCHAR **out, WCHAR *err, size_t err_cch) {
    return encode_exchange_package(pkg, pkg_len, fingerprint,
                                   GROUP_PACKAGE_PREFIX_START, GROUP_PACKAGE_PREFIX_END,
                                   GROUP_KEY_PACKAGE_TOPIC, GROUP_KEY_PROMPT_TEMPLATE,
                                   progress, out, err, err_cch);
}

BOOL app_carrier_decode_exchange_package(const WCHAR *carrier, BYTE **out, DWORD *out_len,
                                         WCHAR *err, size_t err_cch) {
    return local_topk_decode_payload(carrier, KEY_PACKAGE_TOPK_SEED, out, out_len, err, err_cch);
}

BOOL app_carrier_decode_exchange_package_multi(const WCHAR *carrier,
                                               APP_LLM_DECODE_CANDIDATE **out, DWORD *out_count,
                                               WCHAR *err, size_t err_cch) {
    return local_topk_decode_payload_multi(carrier, KEY_PACKAGE_TOPK_SEED, NULL, out, out_count, err, err_cch);
}

static BOOL append_hex_bytes(WCHAR *dst, size_t dst_cch, size_t offset, const BYTE *bytes, DWORD len) {
    static const WCHAR hex[] = L"0123456789abcdef";
    if (!dst || !bytes || dst_cch <= offset || (dst_cch - offset) < (size_t)len * 2 + 1) return FALSE;
    WCHAR *p = dst + offset;
    for (DWORD i = 0; i < len; ++i) {
        p[i * 2] = hex[(bytes[i] >> 4) & 0xf];
        p[i * 2 + 1] = hex[bytes[i] & 0xf];
    }
    p[(size_t)len * 2] = L'\0';
    return TRUE;
}

static BOOL format_message_seed_from_public_key(WCHAR *seed, size_t seed_cch, const BYTE *public_key,
                                                DWORD public_key_len, WCHAR *err, size_t err_cch) {
    /* Message carrier seed prefix is part of the decode contract. */
    const WCHAR prefix[] = L"ChineseInputAgent top-k payload seed v1:";
    size_t prefix_len = wcslen(prefix);
    BOOL seed_built = SUCCEEDED(StringCchCopyW(seed, seed_cch, prefix)) &&
                      append_hex_bytes(seed, seed_cch, prefix_len, public_key, public_key_len);
    if (!seed_built) {
        set_error(err, err_cch, L"Failed to build top-k seed from contact public key.");
        return FALSE;
    }
    return TRUE;
}

BOOL app_carrier_get_message_seed(CRYPTO_BOX *box, WCHAR *seed, size_t seed_cch,
                                  BOOL prefer_remote, WCHAR *err, size_t err_cch) {
    BYTE *public_key = NULL;
    DWORD public_key_len = 0;
    WCHAR local_err[256] = L"";
    if (prefer_remote &&
        crypto_box_get_remote_public_key(box, &public_key, &public_key_len, local_err, ARRAYSIZE(local_err))) {
        BOOL remote_seed_built = format_message_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
        xfree(public_key);
        return remote_seed_built;
    }
    if (!crypto_box_get_public_key(box, &public_key, &public_key_len, err, err_cch)) {
        return FALSE;
    }
    BOOL local_seed_built = format_message_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
    xfree(public_key);
    return local_seed_built;
}

BOOL app_carrier_encode_message_payload(const BYTE *payload, DWORD payload_len,
                                        const WCHAR *seed, const WCHAR *topic,
                                        const APP_CARRIER_OPTIONS *carrier_options,
                                        const CIA_PROGRESS_SINK *progress, WCHAR **out,
                                        WCHAR *err, size_t err_cch) {
    return local_topk_encode_payload(payload, payload_len, seed, topic, NULL, NULL, -1,
                                     carrier_options, progress, out, err, err_cch);
}

BOOL app_carrier_decode_message_payload(const WCHAR *carrier, const WCHAR *seed,
                                        BYTE **out, DWORD *out_len,
                                        WCHAR *err, size_t err_cch) {
    return local_topk_decode_payload(carrier, seed, out, out_len, err, err_cch);
}

BOOL app_carrier_decode_message_payload_multi(const WCHAR *carrier, const WCHAR *seed,
                                              const WCHAR *preferred_tokenizer_id,
                                              APP_LLM_DECODE_CANDIDATE **out, DWORD *out_count,
                                              WCHAR *err, size_t err_cch) {
    return local_topk_decode_payload_multi(carrier, seed, preferred_tokenizer_id, out, out_count, err, err_cch);
}
