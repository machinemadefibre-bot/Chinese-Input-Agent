#include "app_groups.h"

#include "app_paths.h"
#include "app_shared.h"
#include "app_storage.h"

#include <bcrypt.h>
#include <strsafe.h>
#include <stdint.h>
#include <string.h>
#include <wctype.h>

/* Group storage and message constants define the new v2 group format. */
#define GROUPS_MAGIC 0x52474943u
#define GROUPS_VERSION 2u
#define GROUP_PACKAGE_FORMAT 0x51u
#define GROUP_MESSAGE_FORMAT 0x31u
#define GROUP_HEADER_BYTES 19
#define GROUP_TAG_BYTES 12
#define GROUP_SKIPPED_KEYS 64u
#define GROUP_FINGERPRINT_CHARS 8
#define GROUP_NAME_CCH 128
#define GROUP_LOCAL_NAME_CCH 128
#define GROUP_MEMBER_NAME_CCH 128
#define GROUP_DEFAULT_LOCAL_SENDER_NAME L"\u7fa4\u6210\u5458"

typedef struct GROUP_SKIPPED_KEY {
    BOOL used;
    uint32_t counter;
    BYTE key[32];
} GROUP_SKIPPED_KEY;

typedef struct GROUP_RECV_CHAIN {
    uint32_t sender_id;
    uint32_t next_counter;
    BYTE chain_key[32];
    WCHAR reported_name[GROUP_MEMBER_NAME_CCH];
    WCHAR alias_name[GROUP_MEMBER_NAME_CCH];
    GROUP_SKIPPED_KEY skipped[GROUP_SKIPPED_KEYS];
} GROUP_RECV_CHAIN;

typedef struct APP_GROUP {
    uint64_t group_id;
    uint16_t epoch;
    uint32_t local_sender_id;
    uint32_t send_counter;
    BYTE epoch_seed[APP_GROUP_EPOCH_SEED_BYTES];
    BYTE send_chain_key[32];
    WCHAR name[GROUP_NAME_CCH];
    WCHAR local_sender_name[GROUP_LOCAL_NAME_CCH];
    GROUP_RECV_CHAIN *recv_chains;
    size_t recv_count;
    size_t recv_cap;
} APP_GROUP;

typedef struct BYTE_BUILDER {
    BYTE *data;
    size_t len;
    size_t cap;
} BYTE_BUILDER;

typedef struct READ_CURSOR {
    const BYTE *data;
    size_t len;
    size_t pos;
} READ_CURSOR;

static APP_GROUP *g_groups;
static int g_group_count;

static BOOL ensure_recv_capacity(APP_GROUP *group);

static BOOL builder_reserve(BYTE_BUILDER *builder, size_t extra) {
    if (!builder || extra > SIZE_MAX - builder->len) return FALSE;
    size_t need = builder->len + extra;
    if (need <= builder->cap) return TRUE;
    size_t cap = builder->cap ? builder->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    BYTE *p = (BYTE *)xrealloc(builder->data, (SIZE_T)cap);
    if (!p) return FALSE;
    builder->data = p;
    builder->cap = cap;
    return TRUE;
}

static BOOL builder_append(BYTE_BUILDER *builder, const void *bytes, size_t len) {
    if (!builder || (!bytes && len) || !builder_reserve(builder, len)) return FALSE;
    if (len) CopyMemory(builder->data + builder->len, bytes, len);
    builder->len += len;
    return TRUE;
}

static BOOL builder_u8(BYTE_BUILDER *builder, uint8_t value) {
    return builder_append(builder, &value, 1);
}

static BOOL builder_u16(BYTE_BUILDER *builder, uint16_t value) {
    BYTE encoded[2];
    encoded[0] = (BYTE)(value & 0xffu);
    encoded[1] = (BYTE)((value >> 8) & 0xffu);
    return builder_append(builder, encoded, sizeof(encoded));
}

static BOOL builder_u32(BYTE_BUILDER *builder, uint32_t value) {
    BYTE encoded[4];
    encoded[0] = (BYTE)(value & 0xffu);
    encoded[1] = (BYTE)((value >> 8) & 0xffu);
    encoded[2] = (BYTE)((value >> 16) & 0xffu);
    encoded[3] = (BYTE)((value >> 24) & 0xffu);
    return builder_append(builder, encoded, sizeof(encoded));
}

static BOOL builder_u64(BYTE_BUILDER *builder, uint64_t value) {
    BYTE encoded[8];
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        encoded[byte_idx] = (BYTE)((value >> (byte_idx * 8)) & 0xffu);
    }
    return builder_append(builder, encoded, sizeof(encoded));
}

static BOOL builder_wide_blob(BYTE_BUILDER *builder, const WCHAR *text) {
    size_t chars = wcslen(text ? text : L"");
    if (chars > 0xffffffffu / sizeof(WCHAR)) return FALSE;
    return builder_u32(builder, (uint32_t)(chars * sizeof(WCHAR))) &&
           builder_append(builder, text ? text : L"", chars * sizeof(WCHAR));
}

static void builder_secure_free(BYTE_BUILDER *builder) {
    if (!builder) return;
    secure_free(builder->data, builder->cap);
    ZeroMemory(builder, sizeof(*builder));
}

static BOOL read_bytes(READ_CURSOR *cursor, void *out, size_t len) {
    if (!cursor || (!out && len) || cursor->pos > cursor->len || len > cursor->len - cursor->pos) return FALSE;
    if (len) CopyMemory(out, cursor->data + cursor->pos, len);
    cursor->pos += len;
    return TRUE;
}

static BOOL read_ref(READ_CURSOR *cursor, const BYTE **out, size_t len) {
    if (!cursor || !out || cursor->pos > cursor->len || len > cursor->len - cursor->pos) return FALSE;
    *out = cursor->data + cursor->pos;
    cursor->pos += len;
    return TRUE;
}

static BOOL read_u8(READ_CURSOR *cursor, uint8_t *out) {
    return read_bytes(cursor, out, 1);
}

static BOOL read_u16(READ_CURSOR *cursor, uint16_t *out) {
    BYTE encoded[2];
    if (!read_bytes(cursor, encoded, sizeof(encoded))) return FALSE;
    *out = (uint16_t)encoded[0] | ((uint16_t)encoded[1] << 8);
    return TRUE;
}

static BOOL read_u32(READ_CURSOR *cursor, uint32_t *out) {
    BYTE encoded[4];
    if (!read_bytes(cursor, encoded, sizeof(encoded))) return FALSE;
    *out = (uint32_t)encoded[0] |
           ((uint32_t)encoded[1] << 8) |
           ((uint32_t)encoded[2] << 16) |
           ((uint32_t)encoded[3] << 24);
    return TRUE;
}

static BOOL read_u64(READ_CURSOR *cursor, uint64_t *out) {
    BYTE encoded[8];
    uint64_t value = 0;
    if (!read_bytes(cursor, encoded, sizeof(encoded))) return FALSE;
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        value |= ((uint64_t)encoded[byte_idx]) << (byte_idx * 8);
    }
    *out = value;
    return TRUE;
}

static uint16_t read_u16_le(const BYTE bytes[2]) {
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t read_u32_le(const BYTE bytes[4]) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64_le(const BYTE bytes[8]) {
    uint64_t value = 0;
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        value |= ((uint64_t)bytes[byte_idx]) << (byte_idx * 8);
    }
    return value;
}

static void write_u16_le(BYTE bytes[2], uint16_t value) {
    bytes[0] = (BYTE)(value & 0xffu);
    bytes[1] = (BYTE)((value >> 8) & 0xffu);
}

static void write_u32_le(BYTE bytes[4], uint32_t value) {
    bytes[0] = (BYTE)(value & 0xffu);
    bytes[1] = (BYTE)((value >> 8) & 0xffu);
    bytes[2] = (BYTE)((value >> 16) & 0xffu);
    bytes[3] = (BYTE)((value >> 24) & 0xffu);
}

static void write_u64_le(BYTE bytes[8], uint64_t value) {
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        bytes[byte_idx] = (BYTE)((value >> (byte_idx * 8)) & 0xffu);
    }
}

static BOOL read_wide_blob(READ_CURSOR *cursor, WCHAR *out, size_t out_cch) {
    uint32_t bytes = 0;
    const BYTE *blob = NULL;
    if (!out || out_cch == 0 || !read_u32(cursor, &bytes) ||
        (bytes % sizeof(WCHAR)) != 0 ||
        (bytes / sizeof(WCHAR)) >= out_cch ||
        !read_ref(cursor, &blob, bytes)) return FALSE;
    if (bytes) CopyMemory(out, blob, bytes);
    out[bytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static void clear_recv_chain(GROUP_RECV_CHAIN *chain) {
    if (chain) SecureZeroMemory(chain, sizeof(*chain));
}

static void clear_group(APP_GROUP *group) {
    if (!group) return;
    for (size_t chain_idx = 0; chain_idx < group->recv_count; ++chain_idx) {
        clear_recv_chain(&group->recv_chains[chain_idx]);
    }
    secure_free(group->recv_chains, group->recv_cap * sizeof(GROUP_RECV_CHAIN));
    SecureZeroMemory(group, sizeof(*group));
}

static void clear_all_groups(void) {
    if (g_groups) {
        for (int group_idx = 0; group_idx < g_group_count; ++group_idx) {
            clear_group(&g_groups[group_idx]);
        }
    }
    secure_free(g_groups, APP_GROUP_MAX_GROUPS * sizeof(APP_GROUP));
    g_groups = NULL;
    g_group_count = 0;
}

static BOOL ensure_group_array(void) {
    if (g_groups) return TRUE;
    g_groups = (APP_GROUP *)xalloc(APP_GROUP_MAX_GROUPS * sizeof(APP_GROUP));
    return g_groups != NULL;
}

static APP_GROUP *group_at(int index) {
    if (!g_groups || index < 0 || index >= g_group_count) return NULL;
    return &g_groups[index];
}

static int find_group_by_id(uint64_t group_id) {
    if (!g_groups) return -1;
    for (int group_idx = 0; group_idx < g_group_count; ++group_idx) {
        if (g_groups[group_idx].group_id == group_id) return group_idx;
    }
    return -1;
}

static BOOL group_file_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, APP_GROUPS_FILE_NAME);
}

static BOOL group_archive_path(uint64_t group_id, WCHAR *path, size_t cch) {
    WCHAR name[64];
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), APP_GROUP_ARCHIVE_FILE_FORMAT,
                                (unsigned long long)group_id))) return FALSE;
    return get_app_file(path, cch, name);
}

static BOOL random_bytes(BYTE *out, DWORD len) {
    return out && BCryptGenRandom(NULL, out, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

static BOOL random_u64_nonzero(uint64_t *out) {
    if (!out || !random_bytes((BYTE *)out, sizeof(*out))) return FALSE;
    if (*out == 0) *out = 1;
    return TRUE;
}

static BOOL random_u32_nonzero(uint32_t *out) {
    if (!out || !random_bytes((BYTE *)out, sizeof(*out))) return FALSE;
    if (*out == 0) *out = 1;
    return TRUE;
}

static BOOL hmac_sha256_segments(const BYTE *key, DWORD key_len,
                                 const BYTE **parts, const DWORD *lens, DWORD count,
                                 BYTE out[32]) {
    BOOL hmac_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD obj_len = 0, hash_len = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) < 0 ||
        hash_len != 32) goto cleanup;
    object = (BYTE *)xalloc(obj_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(alg, &hash, object, obj_len, (PUCHAR)key, key_len, 0) < 0) goto cleanup;
    for (DWORD part_idx = 0; part_idx < count; ++part_idx) {
        if (lens[part_idx] && BCryptHashData(hash, (PUCHAR)parts[part_idx], lens[part_idx], 0) < 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, out, 32, 0) < 0) goto cleanup;
    hmac_succeeded = TRUE;
cleanup:
    if (!hmac_succeeded) SecureZeroMemory(out, 32);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(object, obj_len);
    return hmac_succeeded;
}

static BOOL sha256_segments(const BYTE **parts, const DWORD *lens, DWORD count, BYTE out[32]) {
    BOOL hash_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD obj_len = 0, hash_len = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) < 0 ||
        hash_len != 32) goto cleanup;
    object = (BYTE *)xalloc(obj_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(alg, &hash, object, obj_len, NULL, 0, 0) < 0) goto cleanup;
    for (DWORD part_idx = 0; part_idx < count; ++part_idx) {
        if (lens[part_idx] && BCryptHashData(hash, (PUCHAR)parts[part_idx], lens[part_idx], 0) < 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, out, 32, 0) < 0) goto cleanup;
    hash_succeeded = TRUE;
cleanup:
    if (!hash_succeeded) SecureZeroMemory(out, 32);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(object, obj_len);
    return hash_succeeded;
}

static BOOL aes_gcm_encrypt_raw(const BYTE key_bytes[32], const BYTE *aad, DWORD aad_len,
                                const BYTE nonce[12], const BYTE *plain, DWORD plain_len,
                                BYTE *tag, DWORD tag_len, BYTE *cipher) {
    BOOL encrypt_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BYTE *key_object = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (BYTE *)xalloc(obj_len);
    if (!key_object) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &key, key_object, obj_len, (PUCHAR)key_bytes, 32, 0) < 0) goto cleanup;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = 12;
    auth.pbAuthData = (PUCHAR)aad;
    auth.cbAuthData = aad_len;
    auth.pbTag = tag;
    auth.cbTag = tag_len;
    if (BCryptEncrypt(key, (PUCHAR)plain, plain_len, &auth, NULL, 0, cipher, plain_len, &result, 0) < 0 ||
        result != plain_len) goto cleanup;
    encrypt_succeeded = TRUE;
cleanup:
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(key_object, obj_len);
    return encrypt_succeeded;
}

static BOOL aes_gcm_decrypt_raw(const BYTE key_bytes[32], const BYTE *aad, DWORD aad_len,
                                const BYTE nonce[12], const BYTE *cipher, DWORD cipher_len,
                                const BYTE *tag, DWORD tag_len, BYTE *plain) {
    BOOL decrypt_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BYTE *key_object = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (BYTE *)xalloc(obj_len);
    if (!key_object) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &key, key_object, obj_len, (PUCHAR)key_bytes, 32, 0) < 0) goto cleanup;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = 12;
    auth.pbAuthData = (PUCHAR)aad;
    auth.cbAuthData = aad_len;
    auth.pbTag = (PUCHAR)tag;
    auth.cbTag = tag_len;
    if (BCryptDecrypt(key, (PUCHAR)cipher, cipher_len, &auth, NULL, 0, plain, cipher_len, &result, 0) < 0 ||
        result != cipher_len) goto cleanup;
    decrypt_succeeded = TRUE;
cleanup:
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(key_object, obj_len);
    return decrypt_succeeded;
}

static BOOL derive_sender_chain_key(const BYTE epoch_seed[32], uint32_t sender_id, BYTE out[32]) {
    static const BYTE label[] = "ChineseInputAgent group sender chain v1";
    BYTE sender_bytes[4];
    write_u32_le(sender_bytes, sender_id);
    const BYTE *parts[2] = { label, sender_bytes };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), sizeof(sender_bytes) };
    return hmac_sha256_segments(epoch_seed, 32, parts, lens, 2, out);
}

static BOOL derive_chain_step(const BYTE chain_key[32], BYTE message_key[32], BYTE next_chain_key[32]) {
    static const BYTE msg_label[] = "ChineseInputAgent group message key v1";
    static const BYTE next_label[] = "ChineseInputAgent group next chain v1";
    const BYTE *msg_parts[1] = { msg_label };
    DWORD msg_lens[1] = { (DWORD)(sizeof(msg_label) - 1) };
    const BYTE *next_parts[1] = { next_label };
    DWORD next_lens[1] = { (DWORD)(sizeof(next_label) - 1) };
    return hmac_sha256_segments(chain_key, 32, msg_parts, msg_lens, 1, message_key) &&
           hmac_sha256_segments(chain_key, 32, next_parts, next_lens, 1, next_chain_key);
}

static BOOL derive_group_nonce(const BYTE message_key[32], const BYTE header[GROUP_HEADER_BYTES], BYTE nonce[12]) {
    static const BYTE label[] = "ChineseInputAgent group nonce v1";
    BYTE digest[32];
    const BYTE *parts[2] = { label, header };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), GROUP_HEADER_BYTES };
    BOOL nonce_derived = hmac_sha256_segments(message_key, 32, parts, lens, 2, digest);
    if (nonce_derived) CopyMemory(nonce, digest, 12);
    SecureZeroMemory(digest, sizeof(digest));
    return nonce_derived;
}

static void write_group_header(BYTE header[GROUP_HEADER_BYTES], uint64_t group_id,
                               uint16_t epoch, uint32_t sender_id, uint32_t counter) {
    header[0] = GROUP_MESSAGE_FORMAT;
    write_u64_le(header + 1, group_id);
    write_u16_le(header + 9, epoch);
    write_u32_le(header + 11, sender_id);
    write_u32_le(header + 15, counter);
}

static uint16_t current_local_minute_of_day(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return (uint16_t)((st.wHour * 60u + st.wMinute) % (24u * 60u));
}

static BOOL parse_sender_id_hex(const WCHAR *text, uint32_t *sender_id_out) {
    uint32_t value = 0;
    int digits = 0;
    if (!text || !sender_id_out) return FALSE;
    const WCHAR *hash = wcsrchr(text, L'#');
    if (hash && hash[1]) text = hash + 1;
    while (*text && iswspace(*text)) ++text;
    if (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) text += 2;
    while (*text) {
        WCHAR ch = *text++;
        uint32_t nibble = 0;
        if (iswspace(ch) || ch == L'#') break;
        if (digits == 8) break;
        if (ch >= L'0' && ch <= L'9') nibble = (uint32_t)(ch - L'0');
        else if (ch >= L'a' && ch <= L'f') nibble = (uint32_t)(ch - L'a' + 10);
        else if (ch >= L'A' && ch <= L'F') nibble = (uint32_t)(ch - L'A' + 10);
        else return FALSE;
        value = (value << 4) | nibble;
        ++digits;
    }
    if (digits != 8 || value == 0) return FALSE;
    *sender_id_out = value;
    return TRUE;
}

static void trim_wide_span(const WCHAR **start, const WCHAR **end) {
    while (*start < *end && iswspace(**start)) ++*start;
    while (*end > *start && iswspace((*end)[-1])) --*end;
}

static BOOL normalize_member_lookup(const WCHAR *text, WCHAR *out, size_t out_cch) {
    if (!text || !out || out_cch == 0) return FALSE;
    const WCHAR *start = text;
    const WCHAR *end = text + wcslen(text);
    trim_wide_span(&start, &end);
    if (end - start >= 5 &&
        start[0] >= L'0' && start[0] <= L'9' &&
        start[1] >= L'0' && start[1] <= L'9' &&
        start[2] == L':' &&
        start[3] >= L'0' && start[3] <= L'9' &&
        start[4] >= L'0' && start[4] <= L'9') {
        start += 5;
        trim_wide_span(&start, &end);
    }
    const WCHAR *hash = wcsrchr(start, L'#');
    if (hash && hash < end) end = hash;
    trim_wide_span(&start, &end);
    size_t len = (size_t)(end - start);
    if (len == 0 || len >= out_cch) return FALSE;
    CopyMemory(out, start, len * sizeof(WCHAR));
    out[len] = L'\0';
    return TRUE;
}

static BOOL member_name_matches_lookup(const WCHAR *member_name, const WCHAR *lookup) {
    WCHAR normalized_member[GROUP_MEMBER_NAME_CCH];
    WCHAR normalized_lookup[GROUP_MEMBER_NAME_CCH];
    if (!normalize_member_lookup(member_name, normalized_member, ARRAYSIZE(normalized_member)) ||
        !normalize_member_lookup(lookup, normalized_lookup, ARRAYSIZE(normalized_lookup))) {
        return FALSE;
    }
    return CompareStringOrdinal(normalized_member, -1, normalized_lookup, -1, TRUE) == CSTR_EQUAL;
}

static BOOL resolve_member_lookup(APP_GROUP *group, const WCHAR *lookup,
                                  uint32_t *sender_id_out, WCHAR *err, size_t err_cch) {
    if (!group || !lookup || !sender_id_out) {
        set_error(err, err_cch, L"Invalid group member lookup.");
        return FALSE;
    }
    if (parse_sender_id_hex(lookup, sender_id_out)) return TRUE;
    uint32_t matched_sender_id = 0;
    unsigned matches = 0;
    for (size_t chain_idx = 0; chain_idx < group->recv_count; ++chain_idx) {
        GROUP_RECV_CHAIN *chain = &group->recv_chains[chain_idx];
        if (member_name_matches_lookup(chain->alias_name, lookup) ||
            member_name_matches_lookup(chain->reported_name, lookup)) {
            matched_sender_id = chain->sender_id;
            ++matches;
        }
    }
    if (matches == 1) {
        *sender_id_out = matched_sender_id;
        return TRUE;
    }
    set_error(err, err_cch,
              matches ? L"Multiple group members match that name." :
                        L"No group member matches that id or name.");
    return FALSE;
}

static BOOL format_sender_label(uint16_t minute_of_day, const WCHAR *display_name,
                                uint32_t sender_id, WCHAR **out) {
    WCHAR label[GROUP_MEMBER_NAME_CCH + 32];
    unsigned hour = minute_of_day / 60u;
    unsigned minute = minute_of_day % 60u;
    if (FAILED(StringCchPrintfW(label, ARRAYSIZE(label), L"%02u:%02u %s#%08lx",
                                hour, minute,
                                display_name && display_name[0] ? display_name : L"\u7fa4\u6210\u5458",
                                (unsigned long)sender_id))) {
        return FALSE;
    }
    size_t label_cch = wcslen(label) + 1;
    WCHAR *copy = (WCHAR *)xalloc(label_cch * sizeof(WCHAR));
    if (!copy) return FALSE;
    CopyMemory(copy, label, label_cch * sizeof(WCHAR));
    *out = copy;
    return TRUE;
}

static int find_skipped_key(GROUP_RECV_CHAIN *chain, uint32_t counter) {
    if (!chain) return -1;
    for (int key_idx = 0; key_idx < (int)GROUP_SKIPPED_KEYS; ++key_idx) {
        if (chain->skipped[key_idx].used && chain->skipped[key_idx].counter == counter) return key_idx;
    }
    return -1;
}

static unsigned count_free_skipped_keys(GROUP_RECV_CHAIN *chain) {
    unsigned free_count = 0;
    if (!chain) return 0;
    for (int key_idx = 0; key_idx < (int)GROUP_SKIPPED_KEYS; ++key_idx) {
        if (!chain->skipped[key_idx].used) ++free_count;
    }
    return free_count;
}

static GROUP_RECV_CHAIN *find_recv_chain(APP_GROUP *group, uint32_t sender_id) {
    if (!group) return NULL;
    for (size_t chain_idx = 0; chain_idx < group->recv_count; ++chain_idx) {
        if (group->recv_chains[chain_idx].sender_id == sender_id) return &group->recv_chains[chain_idx];
    }
    return NULL;
}

static GROUP_RECV_CHAIN *ensure_recv_chain(APP_GROUP *group, uint32_t sender_id,
                                           WCHAR *err, size_t err_cch) {
    GROUP_RECV_CHAIN *chain = find_recv_chain(group, sender_id);
    if (chain) return chain;
    if (!ensure_recv_capacity(group)) {
        set_error(err, err_cch, L"Group member limit reached.");
        return NULL;
    }
    chain = &group->recv_chains[group->recv_count];
    ZeroMemory(chain, sizeof(*chain));
    chain->sender_id = sender_id;
    if (!derive_sender_chain_key(group->epoch_seed, sender_id, chain->chain_key)) {
        SecureZeroMemory(chain, sizeof(*chain));
        set_error(err, err_cch, L"Group sender chain derivation failed.");
        return NULL;
    }
    ++group->recv_count;
    return chain;
}

static BOOL ensure_recv_capacity(APP_GROUP *group) {
    if (!group || group->recv_count >= APP_GROUP_MAX_MEMBERS) return FALSE;
    if (group->recv_count < group->recv_cap) return TRUE;
    size_t new_cap = group->recv_cap ? group->recv_cap * 2 : 8;
    if (new_cap > APP_GROUP_MAX_MEMBERS) new_cap = APP_GROUP_MAX_MEMBERS;
    GROUP_RECV_CHAIN *new_chains = (GROUP_RECV_CHAIN *)xrealloc(group->recv_chains,
                                                                new_cap * sizeof(GROUP_RECV_CHAIN));
    if (!new_chains) return FALSE;
    ZeroMemory(new_chains + group->recv_cap, (new_cap - group->recv_cap) * sizeof(GROUP_RECV_CHAIN));
    group->recv_chains = new_chains;
    group->recv_cap = new_cap;
    return TRUE;
}

static BOOL build_message_payload(APP_GROUP *group, const WCHAR *plain, BYTE **out, DWORD *out_len,
                                  WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    size_t plain_chars = wcslen(plain ? plain : L"");
    size_t name_chars = wcslen(group && group->local_sender_name[0] ?
                               group->local_sender_name : GROUP_DEFAULT_LOCAL_SENDER_NAME);
    if (!group ||
        plain_chars > 0xffffffffu / sizeof(WCHAR) ||
        name_chars > 0xffffu / sizeof(WCHAR)) {
        set_error(err, err_cch, L"Group plaintext is too large.");
        return FALSE;
    }
    DWORD plain_bytes = (DWORD)(plain_chars * sizeof(WCHAR));
    uint16_t name_bytes = (uint16_t)(name_chars * sizeof(WCHAR));
    BYTE_BUILDER builder = {0};
    if (!builder_u16(&builder, current_local_minute_of_day()) ||
        !builder_u16(&builder, name_bytes) ||
        !builder_append(&builder,
                        group->local_sender_name[0] ?
                        group->local_sender_name : GROUP_DEFAULT_LOCAL_SENDER_NAME,
                        name_bytes) ||
        !builder_append(&builder, plain ? plain : L"", plain_bytes) ||
        builder.len > 0xffffffffu) {
        builder_secure_free(&builder);
        set_error(err, err_cch, L"Failed to build group plaintext payload.");
        return FALSE;
    }
    *out = builder.data;
    *out_len = (DWORD)builder.len;
    builder.data = NULL;
    builder_secure_free(&builder);
    return TRUE;
}

static BOOL parse_message_payload(const BYTE *payload, DWORD payload_len,
                                  GROUP_RECV_CHAIN *chain, uint32_t sender_id,
                                  WCHAR **plain_out, WCHAR **sender_out,
                                  WCHAR *err, size_t err_cch) {
    *plain_out = NULL;
    *sender_out = NULL;
    READ_CURSOR cursor;
    uint16_t minute_of_day = 0;
    uint16_t name_bytes = 0;
    const BYTE *name_blob = NULL;
    const BYTE *plain_blob = NULL;
    WCHAR reported_name[GROUP_MEMBER_NAME_CCH];
    ZeroMemory(reported_name, sizeof(reported_name));
    cursor.data = payload;
    cursor.len = payload_len;
    cursor.pos = 0;
    if (!payload ||
        !read_u16(&cursor, &minute_of_day) ||
        !read_u16(&cursor, &name_bytes) ||
        minute_of_day >= 24u * 60u ||
        (name_bytes % sizeof(WCHAR)) != 0 ||
        (name_bytes / sizeof(WCHAR)) >= ARRAYSIZE(reported_name) ||
        !read_ref(&cursor, &name_blob, name_bytes) ||
        ((cursor.len - cursor.pos) % sizeof(WCHAR)) != 0) {
        set_error(err, err_cch, L"Invalid group plaintext payload.");
        return FALSE;
    }
    if (name_bytes) CopyMemory(reported_name, name_blob, name_bytes);
    reported_name[name_bytes / sizeof(WCHAR)] = L'\0';
    plain_blob = cursor.data + cursor.pos;
    DWORD plain_bytes = (DWORD)(cursor.len - cursor.pos);
    WCHAR *sender = NULL;
    WCHAR *plain = (WCHAR *)xalloc((plain_bytes / sizeof(WCHAR) + 1) * sizeof(WCHAR));
    if (!plain) {
        secure_free_wide(plain);
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    if (chain && reported_name[0]) {
        if (FAILED(StringCchCopyW(chain->reported_name, ARRAYSIZE(chain->reported_name), reported_name))) {
            secure_free_wide(plain);
            set_error(err, err_cch, L"Group sender name is too long.");
            return FALSE;
        }
    }
    if (!format_sender_label(minute_of_day,
                             chain && chain->alias_name[0] ? chain->alias_name :
                             (reported_name[0] ? reported_name : (chain ? chain->reported_name : L"")),
                             sender_id, &sender)) {
        secure_free_wide(plain);
        set_error(err, err_cch, L"Failed to build group sender label.");
        return FALSE;
    }
    if (plain_bytes) CopyMemory(plain, plain_blob, plain_bytes);
    plain[plain_bytes / sizeof(WCHAR)] = L'\0';
    *sender_out = sender;
    *plain_out = plain;
    return TRUE;
}

static BOOL serialize_groups(BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    BYTE_BUILDER builder = {0};
    if (!builder_u32(&builder, GROUPS_MAGIC) ||
        !builder_u32(&builder, GROUPS_VERSION) ||
        !builder_u32(&builder, (uint32_t)g_group_count)) goto cleanup;
    for (int group_idx = 0; group_idx < g_group_count; ++group_idx) {
        APP_GROUP *group = &g_groups[group_idx];
        if (!builder_u64(&builder, group->group_id) ||
            !builder_u32(&builder, group->epoch) ||
            !builder_u32(&builder, group->local_sender_id) ||
            !builder_u32(&builder, group->send_counter) ||
            !builder_append(&builder, group->epoch_seed, sizeof(group->epoch_seed)) ||
            !builder_append(&builder, group->send_chain_key, sizeof(group->send_chain_key)) ||
            !builder_wide_blob(&builder, group->name) ||
            !builder_wide_blob(&builder, group->local_sender_name) ||
            !builder_u32(&builder, (uint32_t)group->recv_count)) goto cleanup;
        for (size_t chain_idx = 0; chain_idx < group->recv_count; ++chain_idx) {
            GROUP_RECV_CHAIN *chain = &group->recv_chains[chain_idx];
            uint32_t skipped_count = 0;
            for (int skipped_idx = 0; skipped_idx < (int)GROUP_SKIPPED_KEYS; ++skipped_idx) {
                if (chain->skipped[skipped_idx].used) ++skipped_count;
            }
            if (!builder_u32(&builder, chain->sender_id) ||
                !builder_u32(&builder, chain->next_counter) ||
                !builder_append(&builder, chain->chain_key, sizeof(chain->chain_key)) ||
                !builder_u32(&builder, skipped_count)) goto cleanup;
            for (int skipped_idx = 0; skipped_idx < (int)GROUP_SKIPPED_KEYS; ++skipped_idx) {
                GROUP_SKIPPED_KEY *skipped = &chain->skipped[skipped_idx];
                if (!skipped->used) continue;
                if (!builder_u32(&builder, skipped->counter) ||
                    !builder_append(&builder, skipped->key, sizeof(skipped->key))) goto cleanup;
            }
            if (!builder_wide_blob(&builder, chain->reported_name) ||
                !builder_wide_blob(&builder, chain->alias_name)) goto cleanup;
        }
    }
    if (builder.len > 0xffffffffu) goto cleanup;
    *out = builder.data;
    *out_len = (DWORD)builder.len;
    builder.data = NULL;
    builder_secure_free(&builder);
    return TRUE;
cleanup:
    builder_secure_free(&builder);
    return FALSE;
}

static BOOL parse_groups(const BYTE *plain, DWORD plain_len, WCHAR *err, size_t err_cch) {
    READ_CURSOR cursor;
    uint32_t magic = 0, version = 0, count = 0;
    APP_GROUP *parsed = NULL;
    cursor.data = plain;
    cursor.len = plain_len;
    cursor.pos = 0;
    if (!read_u32(&cursor, &magic) || !read_u32(&cursor, &version) || !read_u32(&cursor, &count) ||
        magic != GROUPS_MAGIC || (version != 1u && version != GROUPS_VERSION) || count > APP_GROUP_MAX_GROUPS) {
        set_error(err, err_cch, L"Group database format is invalid.");
        return FALSE;
    }
    parsed = (APP_GROUP *)xalloc(APP_GROUP_MAX_GROUPS * sizeof(APP_GROUP));
    if (!parsed) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    for (uint32_t group_idx = 0; group_idx < count; ++group_idx) {
        APP_GROUP *group = &parsed[group_idx];
        uint32_t epoch = 0, recv_count = 0;
        if (!read_u64(&cursor, &group->group_id) ||
            !read_u32(&cursor, &epoch) ||
            !read_u32(&cursor, &group->local_sender_id) ||
            !read_u32(&cursor, &group->send_counter) ||
            !read_bytes(&cursor, group->epoch_seed, sizeof(group->epoch_seed)) ||
            !read_bytes(&cursor, group->send_chain_key, sizeof(group->send_chain_key)) ||
            !read_wide_blob(&cursor, group->name, ARRAYSIZE(group->name)) ||
            !read_wide_blob(&cursor, group->local_sender_name, ARRAYSIZE(group->local_sender_name)) ||
            !read_u32(&cursor, &recv_count) ||
            epoch > 0xffffu ||
            recv_count > APP_GROUP_MAX_MEMBERS) goto fail;
        group->epoch = (uint16_t)epoch;
        if (recv_count) {
            group->recv_chains = (GROUP_RECV_CHAIN *)xalloc(recv_count * sizeof(GROUP_RECV_CHAIN));
            if (!group->recv_chains) goto fail;
            group->recv_cap = recv_count;
            group->recv_count = recv_count;
        }
        for (uint32_t chain_idx = 0; chain_idx < recv_count; ++chain_idx) {
            GROUP_RECV_CHAIN *chain = &group->recv_chains[chain_idx];
            uint32_t skipped_count = 0;
            if (!read_u32(&cursor, &chain->sender_id) ||
                !read_u32(&cursor, &chain->next_counter) ||
                !read_bytes(&cursor, chain->chain_key, sizeof(chain->chain_key)) ||
                !read_u32(&cursor, &skipped_count) ||
                skipped_count > GROUP_SKIPPED_KEYS) goto fail;
            for (uint32_t skipped_idx = 0; skipped_idx < skipped_count; ++skipped_idx) {
                chain->skipped[skipped_idx].used = TRUE;
                if (!read_u32(&cursor, &chain->skipped[skipped_idx].counter) ||
                    !read_bytes(&cursor, chain->skipped[skipped_idx].key,
                                sizeof(chain->skipped[skipped_idx].key))) goto fail;
            }
            if (version >= 2u &&
                (!read_wide_blob(&cursor, chain->reported_name, ARRAYSIZE(chain->reported_name)) ||
                 !read_wide_blob(&cursor, chain->alias_name, ARRAYSIZE(chain->alias_name)))) goto fail;
        }
    }
    if (cursor.pos != cursor.len) goto fail;
    clear_all_groups();
    g_groups = parsed;
    g_group_count = (int)count;
    return TRUE;
fail:
    if (parsed) {
        for (uint32_t group_idx = 0; group_idx < count && group_idx < APP_GROUP_MAX_GROUPS; ++group_idx) {
            clear_group(&parsed[group_idx]);
        }
        secure_free(parsed, APP_GROUP_MAX_GROUPS * sizeof(APP_GROUP));
    }
    set_error(err, err_cch, L"Group database format is invalid.");
    return FALSE;
}

BOOL app_groups_save(void) {
    WCHAR path[MAX_PATH];
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL save_succeeded = FALSE;
    if (!group_file_path(path, ARRAYSIZE(path))) return FALSE;
    if (!serialize_groups(&plain, &plain_len)) goto cleanup;
    if (!dpapi_protect(plain, plain_len, &protected_blob, &protected_len)) goto cleanup;
    save_succeeded = write_file_bytes_atomic(path, protected_blob, protected_len);
cleanup:
    secure_free(plain, plain_len);
    secure_free(protected_blob, protected_len);
    return save_succeeded;
}

BOOL app_groups_load(WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BOOL load_succeeded = FALSE;
    clear_all_groups();
    if (!ensure_group_array()) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    if (!group_file_path(path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Group database path is not available.");
        return FALSE;
    }
    if (!read_file_bytes(path, &file, &file_len)) {
        if (file_exists_w(path)) {
            set_error(err, err_cch, L"Group database exists but could not be read.");
            return FALSE;
        }
        return TRUE;
    }
    if (!dpapi_unprotect(file, file_len, &plain, &plain_len)) {
        set_error(err, err_cch, L"Group database could not be decrypted.");
        goto cleanup;
    }
    load_succeeded = parse_groups(plain, plain_len, err, err_cch);
cleanup:
    secure_free(file, file_len);
    secure_free(plain, plain_len);
    return load_succeeded;
}

void app_groups_shutdown(void) {
    clear_all_groups();
}

int app_groups_count(void) {
    return g_group_count;
}

const WCHAR *app_groups_name(int index) {
    APP_GROUP *group = group_at(index);
    return group ? group->name : NULL;
}

BOOL app_groups_get_display_name(int index, WCHAR *out, size_t cch) {
    APP_GROUP *group = group_at(index);
    if (!group || !out || cch == 0) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"\u7fa4\uff1a%s", group->name));
}

BOOL app_groups_get_message_seed(int index, WCHAR *out, size_t cch) {
    APP_GROUP *group = group_at(index);
    if (!group || !out || cch == 0) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"ChineseInputAgent group top-k payload seed v1:%016llx",
                                     (unsigned long long)group->group_id));
}

BOOL app_groups_get_local_sender_label(int index, WCHAR *out, size_t cch) {
    APP_GROUP *group = group_at(index);
    WCHAR *label = NULL;
    BOOL label_built = FALSE;
    if (!group || !out || cch == 0) return FALSE;
    if (format_sender_label(current_local_minute_of_day(),
                            group->local_sender_name[0] ?
                            group->local_sender_name : GROUP_DEFAULT_LOCAL_SENDER_NAME,
                            group->local_sender_id, &label)) {
        label_built = SUCCEEDED(StringCchCopyW(out, cch, label));
    }
    secure_free_wide(label);
    return label_built;
}

BOOL app_groups_create(const WCHAR *name, const WCHAR *local_sender_name,
                       int *index_out, WCHAR *err, size_t err_cch) {
    if (index_out) *index_out = -1;
    if (!ensure_group_array()) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    if (g_group_count >= APP_GROUP_MAX_GROUPS) {
        set_error(err, err_cch, L"Group limit reached.");
        return FALSE;
    }
    APP_GROUP *group = &g_groups[g_group_count];
    ZeroMemory(group, sizeof(*group));
    if (!random_u64_nonzero(&group->group_id) ||
        !random_u32_nonzero(&group->local_sender_id) ||
        !random_bytes(group->epoch_seed, sizeof(group->epoch_seed))) {
        clear_group(group);
        set_error(err, err_cch, L"Failed to generate group key material.");
        return FALSE;
    }
    group->epoch = 1;
    group->send_counter = 0;
    if (!derive_sender_chain_key(group->epoch_seed, group->local_sender_id, group->send_chain_key)) {
        clear_group(group);
        set_error(err, err_cch, L"Group sender chain derivation failed.");
        return FALSE;
    }
    if (FAILED(StringCchCopyW(group->name, ARRAYSIZE(group->name),
                              name && name[0] ? name : L"\u7fa4\u804a")) ||
        FAILED(StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name),
                              local_sender_name && local_sender_name[0] ?
                              local_sender_name : GROUP_DEFAULT_LOCAL_SENDER_NAME))) {
        clear_group(group);
        set_error(err, err_cch, L"Group name is too long.");
        return FALSE;
    }
    ++g_group_count;
    if (!app_groups_save()) {
        --g_group_count;
        clear_group(group);
        set_error(err, err_cch, L"Group database save failed.");
        return FALSE;
    }
    if (index_out) *index_out = g_group_count - 1;
    return TRUE;
}

BOOL app_groups_rekey(int index, WCHAR *err, size_t err_cch) {
    APP_GROUP *group = group_at(index);
    if (!group) {
        set_error(err, err_cch, L"Group is not available.");
        return FALSE;
    }
    if (group->epoch == 0xffffu) {
        set_error(err, err_cch, L"Group epoch is exhausted. Create a new group.");
        return FALSE;
    }

    uint16_t old_epoch = group->epoch;
    uint32_t old_send_counter = group->send_counter;
    size_t old_recv_count = group->recv_count;
    BYTE old_epoch_seed[APP_GROUP_EPOCH_SEED_BYTES];
    BYTE old_send_chain_key[32];
    BYTE new_epoch_seed[APP_GROUP_EPOCH_SEED_BYTES];
    BYTE new_send_chain_key[32];
    BOOL rekey_succeeded = FALSE;
    CopyMemory(old_epoch_seed, group->epoch_seed, sizeof(old_epoch_seed));
    CopyMemory(old_send_chain_key, group->send_chain_key, sizeof(old_send_chain_key));
    ZeroMemory(new_epoch_seed, sizeof(new_epoch_seed));
    ZeroMemory(new_send_chain_key, sizeof(new_send_chain_key));

    if (!random_bytes(new_epoch_seed, sizeof(new_epoch_seed)) ||
        !derive_sender_chain_key(new_epoch_seed, group->local_sender_id, new_send_chain_key)) {
        set_error(err, err_cch, L"Failed to generate group key material.");
        goto cleanup;
    }

    group->epoch = (uint16_t)(group->epoch + 1);
    group->send_counter = 0;
    group->recv_count = 0;
    CopyMemory(group->epoch_seed, new_epoch_seed, sizeof(group->epoch_seed));
    CopyMemory(group->send_chain_key, new_send_chain_key, sizeof(group->send_chain_key));
    if (!app_groups_save()) {
        group->epoch = old_epoch;
        group->send_counter = old_send_counter;
        group->recv_count = old_recv_count;
        CopyMemory(group->epoch_seed, old_epoch_seed, sizeof(group->epoch_seed));
        CopyMemory(group->send_chain_key, old_send_chain_key, sizeof(group->send_chain_key));
        set_error(err, err_cch, L"Group database save failed.");
        goto cleanup;
    }
    for (size_t chain_idx = 0; chain_idx < old_recv_count; ++chain_idx) {
        clear_recv_chain(&group->recv_chains[chain_idx]);
    }
    rekey_succeeded = TRUE;
cleanup:
    SecureZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
    SecureZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
    SecureZeroMemory(new_epoch_seed, sizeof(new_epoch_seed));
    SecureZeroMemory(new_send_chain_key, sizeof(new_send_chain_key));
    return rekey_succeeded;
}

BOOL app_groups_set_member_alias(int index, const WCHAR *sender_id_hex, const WCHAR *alias,
                                 WCHAR **out_message, WCHAR *err, size_t err_cch) {
    if (out_message) *out_message = NULL;
    APP_GROUP *group = group_at(index);
    uint32_t sender_id = 0;
    if (!group || !resolve_member_lookup(group, sender_id_hex, &sender_id, err, err_cch)) {
        return FALSE;
    }
    if (sender_id == group->local_sender_id) {
        set_error(err, err_cch, L"\u8fd9\u662f\u4f60\u81ea\u5df1\u5728\u5f53\u524d\u7fa4\u91cc\u7684\u7f16\u53f7\u3002\u8981\u6539\u522b\u4eba\u7684\u5907\u6ce8\uff0c\u8bf7\u7528\u5bf9\u65b9\u6d88\u606f\u7b2c\u4e00\u884c # \u540e\u9762\u7684 8 \u4f4d\u7f16\u53f7\uff0c\u6216\u7528\u5df2\u6536\u5230\u7684\u5bf9\u65b9\u6635\u79f0\u3002");
        return FALSE;
    }
    GROUP_RECV_CHAIN *chain = ensure_recv_chain(group, sender_id, err, err_cch);
    if (!chain) return FALSE;
    WCHAR old_alias[GROUP_MEMBER_NAME_CCH];
    StringCchCopyW(old_alias, ARRAYSIZE(old_alias), chain->alias_name);
    if (alias && alias[0]) {
        if (FAILED(StringCchCopyW(chain->alias_name, ARRAYSIZE(chain->alias_name), alias))) {
            set_error(err, err_cch, L"Group member alias is too long.");
            return FALSE;
        }
    } else {
        chain->alias_name[0] = L'\0';
    }
    if (!app_groups_save()) {
        StringCchCopyW(chain->alias_name, ARRAYSIZE(chain->alias_name), old_alias);
        set_error(err, err_cch, L"Group database save failed.");
        return FALSE;
    }
    if (out_message) {
        WSTRB msg = {0};
        if (!wstrb_appendf(&msg, L"\u5df2\u8bbe\u7f6e\u7fa4\u6210\u5458\u79f0\u547c\uff1a%08lx -> %s",
                           (unsigned long)sender_id,
                           chain->alias_name[0] ? chain->alias_name : L"\u672a\u8bbe\u7f6e")) {
            wstrb_free(&msg);
            set_error(err, err_cch, L"Failed to build group alias message.");
            return FALSE;
        }
        *out_message = msg.data;
        msg.data = NULL;
    }
    return TRUE;
}

BOOL app_groups_export_package(int index, BYTE **out, DWORD *out_len,
                               WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    APP_GROUP *group = group_at(index);
    if (!group) {
        set_error(err, err_cch, L"Group is not available.");
        return FALSE;
    }
    BYTE_BUILDER builder = {0};
    size_t name_chars = wcslen(group->name);
    if (name_chars > 0xffffu / sizeof(WCHAR)) {
        set_error(err, err_cch, L"Group name is too long.");
        return FALSE;
    }
    if (!builder_u8(&builder, GROUP_PACKAGE_FORMAT) ||
        !builder_u64(&builder, group->group_id) ||
        !builder_u16(&builder, group->epoch) ||
        !builder_append(&builder, group->epoch_seed, sizeof(group->epoch_seed)) ||
        !builder_u16(&builder, (uint16_t)(name_chars * sizeof(WCHAR))) ||
        !builder_append(&builder, group->name, name_chars * sizeof(WCHAR))) {
        builder_secure_free(&builder);
        set_error(err, err_cch, L"Failed to build group package.");
        return FALSE;
    }
    if (builder.len > 0xffffffffu) {
        builder_secure_free(&builder);
        set_error(err, err_cch, L"Group package is too large.");
        return FALSE;
    }
    *out = builder.data;
    *out_len = (DWORD)builder.len;
    builder.data = NULL;
    builder_secure_free(&builder);
    return TRUE;
}

BOOL app_groups_is_package(const BYTE *pkg, DWORD pkg_len) {
    return pkg && pkg_len >= 1 + 8 + 2 + APP_GROUP_EPOCH_SEED_BYTES + 2 && pkg[0] == GROUP_PACKAGE_FORMAT;
}

BOOL app_groups_package_fingerprint(const BYTE *pkg, DWORD pkg_len,
                                    WCHAR *out, size_t cch,
                                    WCHAR *err, size_t err_cch) {
    static const BYTE label[] = "ChineseInputAgent group package fingerprint v1";
    static const WCHAR alphabet[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    BYTE digest[32];
    const BYTE *parts[2] = { label, pkg };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), pkg_len };
    if (!out || cch < GROUP_FINGERPRINT_CHARS + 1 || !app_groups_is_package(pkg, pkg_len) ||
        !sha256_segments(parts, lens, 2, digest)) {
        set_error(err, err_cch, L"Group package fingerprint failed.");
        return FALSE;
    }
    uint64_t bits = ((uint64_t)digest[0] << 32) |
                    ((uint64_t)digest[1] << 24) |
                    ((uint64_t)digest[2] << 16) |
                    ((uint64_t)digest[3] << 8) |
                    (uint64_t)digest[4];
    for (size_t char_idx = 0; char_idx < GROUP_FINGERPRINT_CHARS; ++char_idx) {
        unsigned shift = (unsigned)(35u - char_idx * 5u);
        out[char_idx] = alphabet[(bits >> shift) & 0x1fu];
    }
    out[GROUP_FINGERPRINT_CHARS] = L'\0';
    SecureZeroMemory(digest, sizeof(digest));
    return TRUE;
}

static BOOL build_group_import_success_message(const WCHAR *group_name,
                                               const BYTE *pkg, DWORD pkg_len,
                                               WCHAR **out_message,
                                               WCHAR *err, size_t err_cch) {
    if (!out_message) return TRUE;
    WCHAR fingerprint[32] = L"";
    if (!app_groups_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        return FALSE;
    }
    WSTRB msg = {0};
    if (!wstrb_appendf(&msg, L"\u5df2\u5bfc\u5165\u7fa4\u804a\uff1a%s\r\n\r\n\u6307\u7eb9\uff1a%s\r\n\r\n\u8bf7\u901a\u8fc7\u53ef\u4fe1\u6e20\u9053\u5bf9\u6bd4\u6307\u7eb9\u3002",
                       group_name && group_name[0] ? group_name : L"\u7fa4\u804a",
                       fingerprint)) {
        wstrb_free(&msg);
        set_error(err, err_cch, L"Failed to build group import message.");
        return FALSE;
    }
    *out_message = msg.data;
    msg.data = NULL;
    return TRUE;
}

BOOL app_groups_import_package(const BYTE *pkg, DWORD pkg_len,
                               const WCHAR *local_group_name,
                               const WCHAR *local_sender_name,
                               int *index_out, WCHAR **out_message,
                               WCHAR *err, size_t err_cch) {
    if (index_out) *index_out = -1;
    if (out_message) *out_message = NULL;
    if (!ensure_group_array()) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    READ_CURSOR cursor;
    uint8_t format = 0;
    uint64_t group_id = 0;
    uint16_t epoch = 0;
    BYTE epoch_seed[APP_GROUP_EPOCH_SEED_BYTES];
    uint16_t name_bytes = 0;
    const BYTE *name_blob = NULL;
    WCHAR name[GROUP_NAME_CCH];
    cursor.data = pkg;
    cursor.len = pkg_len;
    cursor.pos = 0;
    ZeroMemory(epoch_seed, sizeof(epoch_seed));
    ZeroMemory(name, sizeof(name));
    if (!read_u8(&cursor, &format) ||
        !read_u64(&cursor, &group_id) ||
        !read_u16(&cursor, &epoch) ||
        !read_bytes(&cursor, epoch_seed, sizeof(epoch_seed)) ||
        !read_u16(&cursor, &name_bytes) ||
        format != GROUP_PACKAGE_FORMAT ||
        group_id == 0 ||
        epoch == 0 ||
        (name_bytes % sizeof(WCHAR)) != 0 ||
        (name_bytes / sizeof(WCHAR)) >= ARRAYSIZE(name) ||
        !read_ref(&cursor, &name_blob, name_bytes) ||
        cursor.pos != cursor.len) {
        SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
        set_error(err, err_cch, L"Invalid group package.");
        return FALSE;
    }
    if (name_bytes) CopyMemory(name, name_blob, name_bytes);
    name[name_bytes / sizeof(WCHAR)] = L'\0';

    int index = find_group_by_id(group_id);
    APP_GROUP *group = NULL;
    BOOL group_was_new = FALSE;
    if (index < 0) {
        if (g_group_count >= APP_GROUP_MAX_GROUPS) {
            SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
            set_error(err, err_cch, L"Group limit reached.");
            return FALSE;
        }
        index = g_group_count++;
        group_was_new = TRUE;
        group = &g_groups[index];
        ZeroMemory(group, sizeof(*group));
        group->group_id = group_id;
        if (!random_u32_nonzero(&group->local_sender_id)) {
            --g_group_count;
            clear_group(group);
            SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
            set_error(err, err_cch, L"Failed to generate local group sender id.");
            return FALSE;
        }
    } else {
        group = &g_groups[index];
        if (epoch < group->epoch) {
            SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
            set_error(err, err_cch, L"Group package is older than the local group state.");
            return FALSE;
        }
        if (epoch == group->epoch) {
            if (memcmp(epoch_seed, group->epoch_seed, sizeof(epoch_seed)) != 0) {
                SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
                set_error(err, err_cch, L"Group package does not match the local group state.");
                return FALSE;
            }
            SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
            if ((local_group_name && local_group_name[0]) ||
                (local_sender_name && local_sender_name[0])) {
                WCHAR old_name[GROUP_NAME_CCH];
                WCHAR old_local_sender_name[GROUP_LOCAL_NAME_CCH];
                StringCchCopyW(old_name, ARRAYSIZE(old_name), group->name);
                StringCchCopyW(old_local_sender_name, ARRAYSIZE(old_local_sender_name), group->local_sender_name);
                if ((local_group_name && local_group_name[0] &&
                     FAILED(StringCchCopyW(group->name, ARRAYSIZE(group->name), local_group_name))) ||
                    (local_sender_name && local_sender_name[0] &&
                     FAILED(StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name), local_sender_name)))) {
                    StringCchCopyW(group->name, ARRAYSIZE(group->name), old_name);
                    StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name), old_local_sender_name);
                    set_error(err, err_cch, L"Group name is too long.");
                    return FALSE;
                }
                if (!app_groups_save()) {
                    StringCchCopyW(group->name, ARRAYSIZE(group->name), old_name);
                    StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name), old_local_sender_name);
                    set_error(err, err_cch, L"Group database save failed.");
                    return FALSE;
                }
            }
            if (index_out) *index_out = index;
            return build_group_import_success_message(group->name, pkg, pkg_len,
                                                      out_message, err, err_cch);
        }
    }

    uint16_t old_epoch = group->epoch;
    uint32_t old_send_counter = group->send_counter;
    size_t old_recv_count = group->recv_count;
    BYTE old_epoch_seed[APP_GROUP_EPOCH_SEED_BYTES];
    BYTE old_send_chain_key[32];
    BYTE imported_send_chain_key[32];
    WCHAR old_name[GROUP_NAME_CCH];
    WCHAR old_local_sender_name[GROUP_LOCAL_NAME_CCH];
    WCHAR imported_name[GROUP_NAME_CCH];
    WCHAR imported_local_sender_name[GROUP_LOCAL_NAME_CCH];
    ZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
    ZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
    ZeroMemory(imported_send_chain_key, sizeof(imported_send_chain_key));
    ZeroMemory(old_name, sizeof(old_name));
    ZeroMemory(old_local_sender_name, sizeof(old_local_sender_name));
    ZeroMemory(imported_name, sizeof(imported_name));
    ZeroMemory(imported_local_sender_name, sizeof(imported_local_sender_name));
    if (!group_was_new) {
        CopyMemory(old_epoch_seed, group->epoch_seed, sizeof(old_epoch_seed));
        CopyMemory(old_send_chain_key, group->send_chain_key, sizeof(old_send_chain_key));
        StringCchCopyW(old_name, ARRAYSIZE(old_name), group->name);
        StringCchCopyW(old_local_sender_name, ARRAYSIZE(old_local_sender_name), group->local_sender_name);
    }
    if (!derive_sender_chain_key(epoch_seed, group->local_sender_id, imported_send_chain_key)) {
        if (group_was_new) {
            --g_group_count;
            clear_group(group);
        }
        SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
        SecureZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
        SecureZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
        SecureZeroMemory(imported_send_chain_key, sizeof(imported_send_chain_key));
        set_error(err, err_cch, L"Group sender chain derivation failed.");
        return FALSE;
    }
    if (FAILED(StringCchCopyW(imported_name, ARRAYSIZE(imported_name),
                              local_group_name && local_group_name[0] ? local_group_name :
                              (name[0] ? name : L"\u7fa4\u804a"))) ||
        FAILED(StringCchCopyW(imported_local_sender_name, ARRAYSIZE(imported_local_sender_name),
                              local_sender_name && local_sender_name[0] ?
                              local_sender_name : GROUP_DEFAULT_LOCAL_SENDER_NAME))) {
        if (group_was_new) {
            --g_group_count;
            clear_group(group);
        }
        SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
        SecureZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
        SecureZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
        SecureZeroMemory(imported_send_chain_key, sizeof(imported_send_chain_key));
        set_error(err, err_cch, L"Group name is too long.");
        return FALSE;
    }
    group->recv_count = 0;
    group->epoch = epoch;
    group->send_counter = 0;
    CopyMemory(group->epoch_seed, epoch_seed, sizeof(group->epoch_seed));
    CopyMemory(group->send_chain_key, imported_send_chain_key, sizeof(group->send_chain_key));
    StringCchCopyW(group->name, ARRAYSIZE(group->name), imported_name);
    StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name), imported_local_sender_name);
    SecureZeroMemory(epoch_seed, sizeof(epoch_seed));
    SecureZeroMemory(imported_send_chain_key, sizeof(imported_send_chain_key));
    if (!app_groups_save()) {
        if (group_was_new) {
            --g_group_count;
            clear_group(group);
        } else {
            group->epoch = old_epoch;
            group->send_counter = old_send_counter;
            group->recv_count = old_recv_count;
            CopyMemory(group->epoch_seed, old_epoch_seed, sizeof(group->epoch_seed));
            CopyMemory(group->send_chain_key, old_send_chain_key, sizeof(group->send_chain_key));
            StringCchCopyW(group->name, ARRAYSIZE(group->name), old_name);
            StringCchCopyW(group->local_sender_name, ARRAYSIZE(group->local_sender_name), old_local_sender_name);
        }
        SecureZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
        SecureZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
        set_error(err, err_cch, L"Group database save failed.");
        return FALSE;
    }
    for (size_t chain_idx = 0; chain_idx < old_recv_count; ++chain_idx) {
        clear_recv_chain(&group->recv_chains[chain_idx]);
    }
    SecureZeroMemory(old_epoch_seed, sizeof(old_epoch_seed));
    SecureZeroMemory(old_send_chain_key, sizeof(old_send_chain_key));
    if (index_out) *index_out = index;
    return build_group_import_success_message(group->name, pkg, pkg_len,
                                              out_message, err, err_cch);
}

BOOL app_groups_encrypt_message(int index, const WCHAR *plain,
                                BYTE **out, DWORD *out_len,
                                WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    APP_GROUP *group = group_at(index);
    if (!group || !plain) {
        set_error(err, err_cch, L"Invalid group encryption request.");
        return FALSE;
    }
    if (group->send_counter == 0xffffffffu) {
        set_error(err, err_cch, L"Group send counter is exhausted. Create a new group invite.");
        return FALSE;
    }
    BYTE *payload = NULL;
    DWORD payload_len = 0;
    if (!build_message_payload(group, plain, &payload, &payload_len, err, err_cch)) return FALSE;
    if (payload_len > 0xffffffffu - APP_GROUP_MESSAGE_OVERHEAD_BYTES) {
        secure_free(payload, payload_len);
        set_error(err, err_cch, L"Group plaintext is too large.");
        return FALSE;
    }

    BYTE header[GROUP_HEADER_BYTES];
    BYTE old_chain_key[32];
    BYTE message_key[32];
    BYTE next_chain_key[32];
    BYTE nonce[12];
    BYTE *message = NULL;
    DWORD message_len = APP_GROUP_MESSAGE_OVERHEAD_BYTES + payload_len;
    uint32_t old_counter = group->send_counter;
    BOOL encrypted = FALSE;
    ZeroMemory(header, sizeof(header));
    ZeroMemory(old_chain_key, sizeof(old_chain_key));
    ZeroMemory(message_key, sizeof(message_key));
    ZeroMemory(next_chain_key, sizeof(next_chain_key));
    ZeroMemory(nonce, sizeof(nonce));

    write_group_header(header, group->group_id, group->epoch, group->local_sender_id, group->send_counter);
    CopyMemory(old_chain_key, group->send_chain_key, sizeof(old_chain_key));
    if (!derive_chain_step(group->send_chain_key, message_key, next_chain_key) ||
        !derive_group_nonce(message_key, header, nonce)) {
        set_error(err, err_cch, L"Group message key derivation failed.");
        goto cleanup;
    }
    message = (BYTE *)xalloc(message_len ? message_len : 1);
    if (!message) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    CopyMemory(message, header, GROUP_HEADER_BYTES);
    if (!aes_gcm_encrypt_raw(message_key, message, GROUP_HEADER_BYTES, nonce,
                             payload, payload_len,
                             message + GROUP_HEADER_BYTES, GROUP_TAG_BYTES,
                             message + APP_GROUP_MESSAGE_OVERHEAD_BYTES)) {
        set_error(err, err_cch, L"Group AES-GCM encryption failed.");
        goto cleanup;
    }
    CopyMemory(group->send_chain_key, next_chain_key, sizeof(group->send_chain_key));
    ++group->send_counter;
    if (!app_groups_save()) {
        CopyMemory(group->send_chain_key, old_chain_key, sizeof(group->send_chain_key));
        group->send_counter = old_counter;
        set_error(err, err_cch, L"Group state save failed.");
        goto cleanup;
    }
    *out = message;
    *out_len = message_len;
    message = NULL;
    encrypted = TRUE;
cleanup:
    secure_free(payload, payload_len);
    secure_free(message, message_len);
    SecureZeroMemory(header, sizeof(header));
    SecureZeroMemory(old_chain_key, sizeof(old_chain_key));
    SecureZeroMemory(message_key, sizeof(message_key));
    SecureZeroMemory(next_chain_key, sizeof(next_chain_key));
    SecureZeroMemory(nonce, sizeof(nonce));
    return encrypted;
}

BOOL app_groups_decrypt_message(const BYTE *message, DWORD message_len,
                                WCHAR **plain_out, WCHAR **sender_out,
                                int *group_index_out,
                                WCHAR *err, size_t err_cch) {
    *plain_out = NULL;
    *sender_out = NULL;
    if (group_index_out) *group_index_out = -1;
    if (!message || message_len < APP_GROUP_MESSAGE_OVERHEAD_BYTES || message[0] != GROUP_MESSAGE_FORMAT) {
        set_error(err, err_cch, L"Invalid group message format.");
        return FALSE;
    }
    uint64_t group_id = read_u64_le(message + 1);
    uint16_t epoch = read_u16_le(message + 9);
    uint32_t sender_id = read_u32_le(message + 11);
    uint32_t counter = read_u32_le(message + 15);
    if (counter == 0xffffffffu) {
        set_error(err, err_cch, L"Group receive counter is exhausted. Create a new group invite.");
        return FALSE;
    }
    int group_index = find_group_by_id(group_id);
    if (group_index < 0) {
        set_error(err, err_cch, L"No matching group was found.");
        return FALSE;
    }
    APP_GROUP *group = &g_groups[group_index];
    if (epoch != group->epoch || sender_id == 0) {
        set_error(err, err_cch, L"Group message does not match the active group epoch.");
        return FALSE;
    }

    GROUP_RECV_CHAIN *chain = find_recv_chain(group, sender_id);
    BOOL chain_was_new = FALSE;
    GROUP_RECV_CHAIN backup_chain;
    ZeroMemory(&backup_chain, sizeof(backup_chain));
    if (!chain) {
        chain_was_new = TRUE;
        if (!ensure_recv_capacity(group)) {
            set_error(err, err_cch, L"Group member limit reached.");
            return FALSE;
        }
        chain = &group->recv_chains[group->recv_count];
        ZeroMemory(chain, sizeof(*chain));
        chain->sender_id = sender_id;
        if (!derive_sender_chain_key(group->epoch_seed, sender_id, chain->chain_key)) {
            SecureZeroMemory(chain, sizeof(*chain));
            set_error(err, err_cch, L"Group sender chain derivation failed.");
            return FALSE;
        }
    } else {
        backup_chain = *chain;
    }

    DWORD cipher_len = message_len - APP_GROUP_MESSAGE_OVERHEAD_BYTES;
    BYTE *payload = NULL;
    BYTE message_key[32];
    BYTE next_chain_key[32];
    BYTE working_chain_key[32];
    BYTE nonce[12];
    GROUP_SKIPPED_KEY temp_skipped[GROUP_SKIPPED_KEYS];
    int skipped_slot = -1;
    BOOL decrypted = FALSE;
    ZeroMemory(message_key, sizeof(message_key));
    ZeroMemory(next_chain_key, sizeof(next_chain_key));
    ZeroMemory(working_chain_key, sizeof(working_chain_key));
    ZeroMemory(nonce, sizeof(nonce));
    ZeroMemory(temp_skipped, sizeof(temp_skipped));

    skipped_slot = find_skipped_key(chain, counter);
    if (skipped_slot >= 0) {
        CopyMemory(message_key, chain->skipped[skipped_slot].key, sizeof(message_key));
    } else {
        if (counter < chain->next_counter) {
            set_error(err, err_cch, L"Group message counter is too old.");
            goto cleanup;
        }
        uint32_t gap = counter - chain->next_counter;
        if (gap > GROUP_SKIPPED_KEYS || gap > count_free_skipped_keys(chain)) {
            set_error(err, err_cch, L"Group message is outside the out-of-order window.");
            goto cleanup;
        }
        CopyMemory(working_chain_key, chain->chain_key, sizeof(working_chain_key));
        for (uint32_t skipped_idx = 0; skipped_idx < gap; ++skipped_idx) {
            BYTE skipped_next_chain[32];
            ZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
            temp_skipped[skipped_idx].used = TRUE;
            temp_skipped[skipped_idx].counter = chain->next_counter + skipped_idx;
            if (!derive_chain_step(working_chain_key, temp_skipped[skipped_idx].key, skipped_next_chain)) {
                SecureZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
                set_error(err, err_cch, L"Group skipped-key derivation failed.");
                goto cleanup;
            }
            SecureZeroMemory(working_chain_key, sizeof(working_chain_key));
            CopyMemory(working_chain_key, skipped_next_chain, sizeof(working_chain_key));
            SecureZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
        }
        if (!derive_chain_step(working_chain_key, message_key, next_chain_key)) {
            set_error(err, err_cch, L"Group message key derivation failed.");
            goto cleanup;
        }
    }
    if (!derive_group_nonce(message_key, message, nonce)) {
        set_error(err, err_cch, L"Group nonce derivation failed.");
        goto cleanup;
    }
    payload = (BYTE *)xalloc(cipher_len ? cipher_len : 1);
    if (!payload) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (!aes_gcm_decrypt_raw(message_key, message, GROUP_HEADER_BYTES, nonce,
                             message + APP_GROUP_MESSAGE_OVERHEAD_BYTES, cipher_len,
                             message + GROUP_HEADER_BYTES, GROUP_TAG_BYTES, payload)) {
        set_error(err, err_cch, L"Group message authentication failed.");
        goto cleanup;
    }
    if (!parse_message_payload(payload, cipher_len, chain, sender_id, plain_out, sender_out, err, err_cch)) {
        goto cleanup;
    }

    if (chain_was_new) ++group->recv_count;
    if (skipped_slot >= 0) {
        SecureZeroMemory(&chain->skipped[skipped_slot], sizeof(chain->skipped[skipped_slot]));
    } else {
        uint32_t gap = counter - chain->next_counter;
        for (uint32_t skipped_idx = 0; skipped_idx < gap; ++skipped_idx) {
            int free_idx = -1;
            for (int slot_idx = 0; slot_idx < (int)GROUP_SKIPPED_KEYS; ++slot_idx) {
                if (!chain->skipped[slot_idx].used) {
                    free_idx = slot_idx;
                    break;
                }
            }
            if (free_idx < 0) {
                set_error(err, err_cch, L"Group skipped-key cache is full.");
                goto rollback;
            }
            chain->skipped[free_idx] = temp_skipped[skipped_idx];
            SecureZeroMemory(&temp_skipped[skipped_idx], sizeof(temp_skipped[skipped_idx]));
        }
        CopyMemory(chain->chain_key, next_chain_key, sizeof(chain->chain_key));
        chain->next_counter = counter + 1;
    }
    if (!app_groups_save()) {
        set_error(err, err_cch, L"Group state save failed.");
        goto rollback;
    }
    if (group_index_out) *group_index_out = group_index;
    decrypted = TRUE;
    goto cleanup;

rollback:
    secure_free_wide(*plain_out);
    secure_free_wide(*sender_out);
    *plain_out = NULL;
    *sender_out = NULL;
    if (chain_was_new) {
        if (group->recv_count > 0 && &group->recv_chains[group->recv_count - 1] == chain) {
            --group->recv_count;
        }
        clear_recv_chain(chain);
    } else {
        *chain = backup_chain;
    }
cleanup:
    secure_free(payload, cipher_len);
    SecureZeroMemory(message_key, sizeof(message_key));
    SecureZeroMemory(next_chain_key, sizeof(next_chain_key));
    SecureZeroMemory(working_chain_key, sizeof(working_chain_key));
    SecureZeroMemory(nonce, sizeof(nonce));
    SecureZeroMemory(temp_skipped, sizeof(temp_skipped));
    SecureZeroMemory(&backup_chain, sizeof(backup_chain));
    return decrypted;
}

static WCHAR *dup_wide(const WCHAR *text) {
    size_t len = wcslen(text ? text : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, text ? text : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

static BOOL build_archive_record(const WCHAR *sender, const WCHAR *plain, WCHAR **out) {
    *out = NULL;
    SYSTEMTIME st;
    GetLocalTime(&st);
    WSTRB record_builder = {0};
    if (!wstrb_appendf(&record_builder, L"[%04u-%02u-%02u %02u:%02u:%02u] \u53d1\u9001\u4eba\uff1a%s\r\n",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                       sender && sender[0] ? sender : L"\u672a\u547d\u540d") ||
        !wstrb_append(&record_builder, plain ? plain : L"")) {
        wstrb_secure_free(&record_builder);
        return FALSE;
    }
    size_t len = wcslen(plain ? plain : L"");
    if (len == 0 || (plain[len - 1] != L'\n' && plain[len - 1] != L'\r')) {
        if (!wstrb_append(&record_builder, L"\r\n")) {
            wstrb_secure_free(&record_builder);
            return FALSE;
        }
    }
    if (!wstrb_append(&record_builder, L"\r\n")) {
        wstrb_secure_free(&record_builder);
        return FALSE;
    }
    *out = record_builder.data;
    record_builder.data = NULL;
    return TRUE;
}

BOOL app_groups_archive_append_text(int index, const WCHAR *sender, const WCHAR *plain,
                                    WCHAR *err, size_t err_cch) {
    APP_GROUP *group = group_at(index);
    WCHAR path[MAX_PATH];
    WCHAR *record = NULL;
    char *record_utf8 = NULL;
    int record_len = 0;
    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *old = NULL;
    DWORD old_len = 0;
    BYTE *merged = NULL;
    DWORD merged_len = 0;
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL archive_saved = FALSE;
    WCHAR local_sender_label[GROUP_MEMBER_NAME_CCH + 32] = L"";
    if (!group || !group_archive_path(group->group_id, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Group archive path is not available.");
        return FALSE;
    }
    if ((!sender || !sender[0]) &&
        !app_groups_get_local_sender_label(index, local_sender_label, ARRAYSIZE(local_sender_label))) {
        set_error(err, err_cch, L"Failed to build group sender label.");
        goto cleanup;
    }
    if (!build_archive_record(sender && sender[0] ? sender : local_sender_label, plain, &record) ||
        !wide_to_utf8(record, &record_utf8, &record_len)) {
        set_error(err, err_cch, L"Failed to build group archive record.");
        goto cleanup;
    }
    if (read_file_bytes(path, &file, &file_len)) {
        if (!dpapi_unprotect(file, file_len, &old, &old_len)) {
            set_error(err, err_cch, L"Group archive file exists but could not be decrypted.");
            goto cleanup;
        }
    } else if (file_exists_w(path)) {
        set_error(err, err_cch, L"Group archive file exists but could not be read.");
        goto cleanup;
    }
    if (record_len < 0 || (DWORD)record_len > 0xffffffffu - old_len) {
        set_error(err, err_cch, L"Group archive data is too large.");
        goto cleanup;
    }
    merged_len = old_len + (DWORD)record_len;
    merged = (BYTE *)xalloc(merged_len ? merged_len : 1);
    if (!merged) {
        set_error(err, err_cch, L"Out of memory while updating group archive.");
        goto cleanup;
    }
    if (old && old_len) CopyMemory(merged, old, old_len);
    CopyMemory(merged + old_len, record_utf8, (DWORD)record_len);
    archive_saved = dpapi_protect(merged, merged_len, &protected_blob, &protected_len) &&
                    write_file_bytes_atomic(path, protected_blob, protected_len);
    if (!archive_saved) set_error(err, err_cch, L"Failed to write group archive.");
cleanup:
    secure_free_wide(record);
    secure_free_str(record_utf8);
    secure_free(file, file_len);
    secure_free(old, old_len);
    secure_free(merged, merged_len);
    secure_free(protected_blob, protected_len);
    return archive_saved;
}

BOOL app_groups_archive_load_text(int index, WCHAR **out,
                                  WCHAR *err, size_t err_cch) {
    *out = NULL;
    APP_GROUP *group = group_at(index);
    WCHAR path[MAX_PATH];
    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BOOL loaded = FALSE;
    if (!group || !group_archive_path(group->group_id, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Group archive path is not available.");
        return FALSE;
    }
    if (!read_file_bytes(path, &file, &file_len)) {
        if (file_exists_w(path)) {
            set_error(err, err_cch, L"Group archive file exists but could not be read.");
            return FALSE;
        }
        *out = dup_wide(L"");
        return *out != NULL;
    }
    loaded = dpapi_unprotect(file, file_len, &plain, &plain_len) &&
             utf8_to_wide_n((const char *)plain, (int)plain_len, out);
    secure_free(file, file_len);
    secure_free(plain, plain_len);
    if (!loaded) {
        set_error(err, err_cch, L"Group archive file could not be decrypted or decoded.");
        return FALSE;
    }
    return TRUE;
}
