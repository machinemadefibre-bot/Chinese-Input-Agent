#include "crypto_box.h"
#include "app_shared.h"

#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

int curve25519_donna(uint8_t *out, const uint8_t *secret, const uint8_t *basepoint);

/* Crypto state and message wire-format constants. Do not change without a migration. */
#define STATE_MAGIC 0x31454943u
#define STATE_VERSION 5u
#define STATE_VERSION_PRE_SESSION 4u
#define STATE_KEY_BYTES 32
#define X25519_KEY_BYTES 32
#define CONTACT_CHECKSUM_BYTES 8
#define CONTACT_PACKAGE_FORMAT_BASE 0x20u
#define CONTACT_PACKAGE_RECIPIENT_FLAG 0x01u
#define CONTACT_PACKAGE_FORMAT_MASK 0xfeu
#define CONTACT_PACKAGE_BASE_BYTES (1 + X25519_KEY_BYTES + X25519_KEY_BYTES + CONTACT_CHECKSUM_BYTES)
#define CONTACT_PACKAGE_WITH_RECIPIENT_BYTES (CONTACT_PACKAGE_BASE_BYTES + X25519_KEY_BYTES)
#define CONTACT_FINGERPRINT_CHARS 8
#define STATE_NONCE_BYTES 12
#define STATE_TAG_BYTES 16
#define STATE_HEADER_BYTES 16

#define MESSAGE_NONCE_BYTES 12
#define MESSAGE_TAG_BYTES 12
#define SESSION_PACKET_FORMAT 0x21u
#define SESSION_ID_BYTES 8
#define SESSION_COUNTER_BYTES 4
#define SESSION_HEADER_BYTES (1 + SESSION_ID_BYTES + SESSION_COUNTER_BYTES)
#define SESSION_MAX_SKIPPED_KEYS 64u

typedef struct BOX_BUF {
    uint8_t *data;
    size_t len;
} BOX_BUF;

typedef struct BYTE_BUILDER {
    uint8_t *data;
    size_t len;
    size_t cap;
} BYTE_BUILDER;

typedef struct READ_CURSOR {
    const uint8_t *data;
    size_t len;
    size_t pos;
} READ_CURSOR;

typedef struct CONTACT_PACKAGE_VIEW {
    const uint8_t *static_public;
    const uint8_t *handshake_public;
    const uint8_t *recipient_public;
    BOOL has_recipient;
    DWORD body_len;
} CONTACT_PACKAGE_VIEW;

typedef struct SKIPPED_MESSAGE_KEY {
    BOOL used;
    uint64_t session_id;
    uint32_t counter;
    uint8_t key[32];
} SKIPPED_MESSAGE_KEY;

struct CRYPTO_BOX {
    BYTE state_key[STATE_KEY_BYTES];
    WCHAR state_path[MAX_PATH];
    BOX_BUF public_key;
    BOX_BUF private_key;
    BOX_BUF remote_public_key;
    BOOL local_handshake_ready;
    uint8_t local_handshake_private[X25519_KEY_BYTES];
    uint8_t local_handshake_public[X25519_KEY_BYTES];
    BOOL remote_handshake_ready;
    uint8_t remote_handshake_public[X25519_KEY_BYTES];
    BOOL send_chain_ready;
    BOOL recv_chain_ready;
    uint64_t send_session_id;
    uint64_t recv_session_id;
    uint32_t send_counter;
    uint32_t recv_counter;
    uint8_t send_chain_key[32];
    uint8_t recv_chain_key[32];
    SKIPPED_MESSAGE_KEY skipped_keys[SESSION_MAX_SKIPPED_KEYS];
};

static void set_box_error(WCHAR *error_buffer, size_t cch, const WCHAR *fmt, ...) {
    if (!error_buffer || cch == 0) return;
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(error_buffer, cch, fmt, args);
    va_end(args);
}

static void *box_alloc(size_t bytes) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes ? bytes : 1);
}

static void box_secure_free(void *p, size_t bytes) {
    if (p) {
        SecureZeroMemory(p, bytes);
        HeapFree(GetProcessHeap(), 0, p);
    }
}

static BOOL bytes_all_zero(const uint8_t *bytes, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= bytes[i];
    return acc == 0;
}

static void x25519_clamp_private(uint8_t priv[X25519_KEY_BYTES]) {
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

static BOOL validate_public_key_blob(const uint8_t *blob, size_t len) {
    return blob && len == X25519_KEY_BYTES && !bytes_all_zero(blob, X25519_KEY_BYTES);
}

static BOOL validate_private_key_blob(const uint8_t *blob, size_t len) {
    if (!blob || len != X25519_KEY_BYTES || bytes_all_zero(blob, X25519_KEY_BYTES)) return FALSE;
    uint8_t clamped[X25519_KEY_BYTES];
    memcpy(clamped, blob, sizeof(clamped));
    x25519_clamp_private(clamped);
    BOOL is_clamped = memcmp(clamped, blob, sizeof(clamped)) == 0;
    SecureZeroMemory(clamped, sizeof(clamped));
    return is_clamped;
}

static BOOL buf_set(BOX_BUF *dst, const uint8_t *bytes, size_t len) {
    uint8_t *copy = NULL;
    if (len) {
        copy = (uint8_t *)box_alloc(len);
        if (!copy) return FALSE;
        memcpy(copy, bytes, len);
    }
    box_secure_free(dst->data, dst->len);
    dst->data = copy;
    dst->len = len;
    return TRUE;
}

static void buf_clear(BOX_BUF *box_buffer) {
    box_secure_free(box_buffer->data, box_buffer->len);
    box_buffer->data = NULL;
    box_buffer->len = 0;
}

static BOOL builder_reserve(BYTE_BUILDER *builder, size_t extra) {
    if (!builder) return FALSE;
    if (extra > SIZE_MAX - builder->len) return FALSE;
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
    uint8_t *p = builder->data ?
        (uint8_t *)HeapReAlloc(GetProcessHeap(), 0, builder->data, cap) :
        (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
    if (!p) return FALSE;
    builder->data = p;
    builder->cap = cap;
    return TRUE;
}

static BOOL builder_append(BYTE_BUILDER *builder, const void *bytes, size_t len) {
    if (!builder || (!bytes && len)) return FALSE;
    if (!builder_reserve(builder, len)) return FALSE;
    if (len) memcpy(builder->data + builder->len, bytes, len);
    builder->len += len;
    return TRUE;
}

static BOOL builder_u32(BYTE_BUILDER *builder, uint32_t v) {
    uint8_t encoded[4];
    encoded[0] = (uint8_t)(v & 0xff);
    encoded[1] = (uint8_t)((v >> 8) & 0xff);
    encoded[2] = (uint8_t)((v >> 16) & 0xff);
    encoded[3] = (uint8_t)((v >> 24) & 0xff);
    return builder_append(builder, encoded, sizeof(encoded));
}

static BOOL builder_u64(BYTE_BUILDER *builder, uint64_t v) {
    uint8_t encoded[8];
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        encoded[byte_idx] = (uint8_t)((v >> (byte_idx * 8)) & 0xffu);
    }
    return builder_append(builder, encoded, sizeof(encoded));
}

static BOOL builder_blob(BYTE_BUILDER *builder, const uint8_t *bytes, size_t len) {
    if (len > 0xffffffffu) return FALSE;
    return builder_u32(builder, (uint32_t)len) && builder_append(builder, bytes, len);
}

static void builder_free(BYTE_BUILDER *builder) {
    box_secure_free(builder->data, builder->cap);
    ZeroMemory(builder, sizeof(*builder));
}

static BOOL read_u32(READ_CURSOR *c, uint32_t *out) {
    if (!c || !out || c->pos > c->len || c->len - c->pos < 4) return FALSE;
    const uint8_t *p = c->data + c->pos;
    *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    c->pos += 4;
    return TRUE;
}

static BOOL read_u64(READ_CURSOR *c, uint64_t *out) {
    if (!c || !out || c->pos > c->len || c->len - c->pos < 8) return FALSE;
    const uint8_t *p = c->data + c->pos;
    uint64_t v = 0;
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        v |= ((uint64_t)p[byte_idx]) << (byte_idx * 8);
    }
    *out = v;
    c->pos += 8;
    return TRUE;
}

static BOOL read_fixed_ref(READ_CURSOR *c, const uint8_t **bytes, size_t len) {
    if (!c || !bytes || c->pos > c->len || len > c->len - c->pos) return FALSE;
    *bytes = c->data + c->pos;
    c->pos += len;
    return TRUE;
}

static BOOL read_blob_ref(READ_CURSOR *c, const uint8_t **bytes, size_t *len) {
    uint32_t n = 0;
    if (!bytes || !len || !read_u32(c, &n) || c->pos > c->len || (size_t)n > c->len - c->pos) return FALSE;
    *bytes = c->data + c->pos;
    *len = n;
    c->pos += n;
    return TRUE;
}

static uint64_t read_u64_le(const uint8_t bytes[8]) {
    uint64_t v = 0;
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        v |= ((uint64_t)bytes[byte_idx]) << (byte_idx * 8);
    }
    return v;
}

static uint32_t read_u32_le(const uint8_t bytes[4]) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void write_u64_le(uint8_t bytes[8], uint64_t v) {
    for (int byte_idx = 0; byte_idx < 8; ++byte_idx) {
        bytes[byte_idx] = (uint8_t)((v >> (byte_idx * 8)) & 0xffu);
    }
}

static void write_u32_le(uint8_t bytes[4], uint32_t v) {
    bytes[0] = (uint8_t)(v & 0xffu);
    bytes[1] = (uint8_t)((v >> 8) & 0xffu);
    bytes[2] = (uint8_t)((v >> 16) & 0xffu);
    bytes[3] = (uint8_t)((v >> 24) & 0xffu);
}

static BOOL read_file_all(const WCHAR *path, uint8_t **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > 0x7fffffffu) {
        CloseHandle(h);
        return FALSE;
    }
    DWORD len = (DWORD)sz.QuadPart;
    uint8_t *file_buffer = (uint8_t *)box_alloc(len ? len : 1);
    if (!file_buffer) {
        CloseHandle(h);
        return FALSE;
    }
    DWORD bytes_read = 0;
    BOOL read_succeeded = ReadFile(h, file_buffer, len, &bytes_read, NULL) && bytes_read == len;
    CloseHandle(h);
    if (!read_succeeded) {
        box_secure_free(file_buffer, len);
        return FALSE;
    }
    *out = file_buffer;
    *out_len = len;
    return TRUE;
}

static BOOL write_file_all(const WCHAR *path, const uint8_t *bytes, DWORD len) {
    return write_file_bytes_atomic(path, bytes, len);
}

static BOOL box_file_exists(const WCHAR *path) {
    if (!path || !path[0]) return FALSE;
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL hmac_sha256_segments(const uint8_t *key, DWORD key_len,
                                 const uint8_t **parts, const DWORD *lens, int count,
                                 uint8_t out[32]) {
    BOOL hmac_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t *object = NULL;
    DWORD obj_len = 0, hash_len = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) < 0 ||
        hash_len != 32) goto cleanup;
    object = (uint8_t *)box_alloc(obj_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(alg, &hash, object, obj_len, (PUCHAR)key, key_len, 0) < 0) goto cleanup;
    for (int i = 0; i < count; ++i) {
        if (lens[i] && BCryptHashData(hash, (PUCHAR)parts[i], lens[i], 0) < 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, out, 32, 0) < 0) goto cleanup;
    hmac_succeeded = TRUE;
cleanup:
    if (!hmac_succeeded) SecureZeroMemory(out, 32);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    box_secure_free(object, obj_len);
    return hmac_succeeded;
}

static BOOL sha256_segments(const uint8_t **parts, const DWORD *lens, int count, uint8_t out[32]) {
    BOOL hash_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    uint8_t *object = NULL;
    DWORD obj_len = 0, hash_len = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) < 0 ||
        hash_len != 32) goto cleanup;
    object = (uint8_t *)box_alloc(obj_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(alg, &hash, object, obj_len, NULL, 0, 0) < 0) goto cleanup;
    for (int i = 0; i < count; ++i) {
        if (lens[i] && BCryptHashData(hash, (PUCHAR)parts[i], lens[i], 0) < 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, out, 32, 0) < 0) goto cleanup;
    hash_succeeded = TRUE;
cleanup:
    if (!hash_succeeded) SecureZeroMemory(out, 32);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    box_secure_free(object, obj_len);
    return hash_succeeded;
}

static BOOL aes_gcm_encrypt_raw(const uint8_t key_bytes[32],
                                const uint8_t *aad, DWORD aad_len,
                                const uint8_t *nonce, DWORD nonce_len,
                                const uint8_t *plain, DWORD plain_len,
                                uint8_t *tag, DWORD tag_len,
                                uint8_t *cipher) {
    BOOL encrypt_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    uint8_t *key_object = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (uint8_t *)box_alloc(obj_len);
    if (!key_object) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &key, key_object, obj_len, (PUCHAR)key_bytes, 32, 0) < 0) goto cleanup;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = nonce_len;
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
    box_secure_free(key_object, obj_len);
    return encrypt_succeeded;
}

static BOOL aes_gcm_decrypt_raw(const uint8_t key_bytes[32],
                                const uint8_t *aad, DWORD aad_len,
                                const uint8_t *nonce, DWORD nonce_len,
                                const uint8_t *tag, DWORD tag_len,
                                const uint8_t *cipher, DWORD cipher_len,
                                uint8_t *plain) {
    BOOL decrypt_succeeded = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    uint8_t *key_object = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (uint8_t *)box_alloc(obj_len);
    if (!key_object) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &key, key_object, obj_len, (PUCHAR)key_bytes, 32, 0) < 0) goto cleanup;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = nonce_len;
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
    box_secure_free(key_object, obj_len);
    return decrypt_succeeded;
}

static BOOL x25519_public_from_private(const uint8_t priv[X25519_KEY_BYTES], uint8_t pub[X25519_KEY_BYTES]) {
    static const uint8_t basepoint[X25519_KEY_BYTES] = { 9 };
    if (curve25519_donna(pub, priv, basepoint) != 0) return FALSE;
    return !bytes_all_zero(pub, X25519_KEY_BYTES);
}

static BOOL x25519_shared_secret(const uint8_t priv[X25519_KEY_BYTES],
                                 const uint8_t pub[X25519_KEY_BYTES],
                                 uint8_t shared[X25519_KEY_BYTES]) {
    if (!validate_private_key_blob(priv, X25519_KEY_BYTES) ||
        !validate_public_key_blob(pub, X25519_KEY_BYTES)) return FALSE;
    if (curve25519_donna(shared, priv, pub) != 0) return FALSE;
    return !bytes_all_zero(shared, X25519_KEY_BYTES);
}

static BOOL contact_package_checksum(const uint8_t *body, DWORD body_len, uint8_t out[CONTACT_CHECKSUM_BYTES]) {
    static const uint8_t label[] = "ChineseInputAgent contact package checksum v2";
    uint8_t digest[32];
    const uint8_t *parts[2] = { label, body };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), body_len };
    BOOL checksum_built = sha256_segments(parts, lens, 2, digest);
    if (checksum_built) memcpy(out, digest, CONTACT_CHECKSUM_BYTES);
    SecureZeroMemory(digest, sizeof(digest));
    return checksum_built;
}

static BOOL parse_contact_package(const uint8_t *pkg, DWORD pkg_len, CONTACT_PACKAGE_VIEW *view) {
    if (!pkg || !view || pkg_len < 1) return FALSE;
    ZeroMemory(view, sizeof(*view));
    uint8_t format = pkg[0];
    BOOL has_recipient = (format & CONTACT_PACKAGE_RECIPIENT_FLAG) != 0;
    if ((format & CONTACT_PACKAGE_FORMAT_MASK) != CONTACT_PACKAGE_FORMAT_BASE) return FALSE;
    DWORD expected_len = has_recipient ? CONTACT_PACKAGE_WITH_RECIPIENT_BYTES : CONTACT_PACKAGE_BASE_BYTES;
    if (pkg_len != expected_len) return FALSE;

    DWORD pos = 1;
    view->static_public = pkg + pos;
    pos += X25519_KEY_BYTES;
    view->handshake_public = pkg + pos;
    pos += X25519_KEY_BYTES;
    if (has_recipient) {
        view->recipient_public = pkg + pos;
        pos += X25519_KEY_BYTES;
    }
    view->has_recipient = has_recipient;
    view->body_len = pos;

    if (!validate_public_key_blob(view->static_public, X25519_KEY_BYTES) ||
        !validate_public_key_blob(view->handshake_public, X25519_KEY_BYTES) ||
        (has_recipient && !validate_public_key_blob(view->recipient_public, X25519_KEY_BYTES))) {
        return FALSE;
    }

    uint8_t expected[CONTACT_CHECKSUM_BYTES];
    BOOL checksum_matches = contact_package_checksum(pkg, pos, expected) &&
                            memcmp(expected, pkg + pos, CONTACT_CHECKSUM_BYTES) == 0;
    SecureZeroMemory(expected, sizeof(expected));
    return checksum_matches;
}

static BOOL contact_fingerprint_from_public(const uint8_t pub[X25519_KEY_BYTES], WCHAR *out, size_t cch) {
    static const uint8_t label[] = "ChineseInputAgent contact fingerprint";
    static const WCHAR alphabet[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    uint8_t digest[32];
    const uint8_t *parts[2] = { label, pub };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), X25519_KEY_BYTES };
    if (!out || cch < CONTACT_FINGERPRINT_CHARS + 1) return FALSE;
    if (!validate_public_key_blob(pub, X25519_KEY_BYTES) || !sha256_segments(parts, lens, 2, digest)) return FALSE;
    uint64_t bits = ((uint64_t)digest[0] << 32) |
                    ((uint64_t)digest[1] << 24) |
                    ((uint64_t)digest[2] << 16) |
                    ((uint64_t)digest[3] << 8) |
                    (uint64_t)digest[4];
    for (size_t char_idx = 0; char_idx < CONTACT_FINGERPRINT_CHARS; ++char_idx) {
        unsigned shift = (unsigned)(35u - char_idx * 5u);
        out[char_idx] = alphabet[(bits >> shift) & 0x1fu];
    }
    out[CONTACT_FINGERPRINT_CHARS] = L'\0';
    SecureZeroMemory(digest, sizeof(digest));
    return TRUE;
}

static void clear_skipped_message_keys(CRYPTO_BOX *box) {
    if (!box) return;
    SecureZeroMemory(box->skipped_keys, sizeof(box->skipped_keys));
}

static void clear_session_chains(CRYPTO_BOX *box) {
    if (!box) return;
    box->send_chain_ready = FALSE;
    box->recv_chain_ready = FALSE;
    box->send_session_id = 0;
    box->recv_session_id = 0;
    box->send_counter = 0;
    box->recv_counter = 0;
    SecureZeroMemory(box->send_chain_key, sizeof(box->send_chain_key));
    SecureZeroMemory(box->recv_chain_key, sizeof(box->recv_chain_key));
    clear_skipped_message_keys(box);
}

static void clear_handshake_state(CRYPTO_BOX *box) {
    if (!box) return;
    box->local_handshake_ready = FALSE;
    box->remote_handshake_ready = FALSE;
    SecureZeroMemory(box->local_handshake_private, sizeof(box->local_handshake_private));
    SecureZeroMemory(box->local_handshake_public, sizeof(box->local_handshake_public));
    SecureZeroMemory(box->remote_handshake_public, sizeof(box->remote_handshake_public));
}

static BOOL generate_handshake_key(CRYPTO_BOX *box) {
    if (!box) return FALSE;
    if (box->local_handshake_ready &&
        validate_private_key_blob(box->local_handshake_private, sizeof(box->local_handshake_private)) &&
        validate_public_key_blob(box->local_handshake_public, sizeof(box->local_handshake_public))) {
        return TRUE;
    }
    SecureZeroMemory(box->local_handshake_private, sizeof(box->local_handshake_private));
    SecureZeroMemory(box->local_handshake_public, sizeof(box->local_handshake_public));
    if (BCryptGenRandom(NULL, box->local_handshake_private, sizeof(box->local_handshake_private),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return FALSE;
    }
    x25519_clamp_private(box->local_handshake_private);
    if (!x25519_public_from_private(box->local_handshake_private, box->local_handshake_public)) {
        SecureZeroMemory(box->local_handshake_private, sizeof(box->local_handshake_private));
        SecureZeroMemory(box->local_handshake_public, sizeof(box->local_handshake_public));
        return FALSE;
    }
    box->local_handshake_ready = TRUE;
    return TRUE;
}

static BOOL derive_labeled_secret(const uint8_t key[32], const char *label, uint8_t out[32]) {
    const uint8_t *parts[1] = { (const uint8_t *)label };
    DWORD lens[1] = { (DWORD)strlen(label) };
    return hmac_sha256_segments(key, 32, parts, lens, 1, out);
}

static BOOL derive_labeled_session_id(const uint8_t key[32], const char *label, uint64_t *out) {
    uint8_t digest[32];
    BOOL id_derived = derive_labeled_secret(key, label, digest);
    if (id_derived) {
        *out = read_u64_le(digest);
        if (*out == 0) *out = 1;
    }
    SecureZeroMemory(digest, sizeof(digest));
    return id_derived;
}

static BOOL derive_handshake_session(CRYPTO_BOX *box, WCHAR *err, size_t err_cch) {
    static const uint8_t salt_key[] = "ChineseInputAgent CIM2 handshake salt v1";
    uint8_t dh_ss[X25519_KEY_BYTES];
    uint8_t dh_se[X25519_KEY_BYTES];
    uint8_t dh_es[X25519_KEY_BYTES];
    uint8_t dh_ee[X25519_KEY_BYTES];
    uint8_t salt[32];
    uint8_t root[32];
    uint8_t chain_0_to_1[32];
    uint8_t chain_1_to_0[32];
    uint64_t session_0_to_1 = 0;
    uint64_t session_1_to_0 = 0;
    BOOL session_derived = FALSE;

    ZeroMemory(dh_ss, sizeof(dh_ss));
    ZeroMemory(dh_se, sizeof(dh_se));
    ZeroMemory(dh_es, sizeof(dh_es));
    ZeroMemory(dh_ee, sizeof(dh_ee));
    ZeroMemory(salt, sizeof(salt));
    ZeroMemory(root, sizeof(root));
    ZeroMemory(chain_0_to_1, sizeof(chain_0_to_1));
    ZeroMemory(chain_1_to_0, sizeof(chain_1_to_0));

    if (!box ||
        !validate_private_key_blob(box->private_key.data, box->private_key.len) ||
        !validate_public_key_blob(box->public_key.data, box->public_key.len) ||
        !validate_public_key_blob(box->remote_public_key.data, box->remote_public_key.len) ||
        !box->local_handshake_ready ||
        !box->remote_handshake_ready ||
        !validate_private_key_blob(box->local_handshake_private, sizeof(box->local_handshake_private)) ||
        !validate_public_key_blob(box->local_handshake_public, sizeof(box->local_handshake_public)) ||
        !validate_public_key_blob(box->remote_handshake_public, sizeof(box->remote_handshake_public))) {
        set_box_error(err, err_cch, L"Session handshake material is incomplete.");
        goto cleanup;
    }

    int role_cmp = memcmp(box->public_key.data, box->remote_public_key.data, X25519_KEY_BYTES);
    if (role_cmp == 0) {
        set_box_error(err, err_cch, L"Session handshake cannot use identical static keys.");
        goto cleanup;
    }
    BOOL local_is_role0 = role_cmp < 0;

    if (!x25519_shared_secret(box->private_key.data, box->remote_public_key.data, dh_ss)) {
        set_box_error(err, err_cch, L"Session static-static key agreement failed.");
        goto cleanup;
    }
    if (local_is_role0) {
        if (!x25519_shared_secret(box->private_key.data, box->remote_handshake_public, dh_se) ||
            !x25519_shared_secret(box->local_handshake_private, box->remote_public_key.data, dh_es)) {
            set_box_error(err, err_cch, L"Session static-ephemeral key agreement failed.");
            goto cleanup;
        }
    } else {
        if (!x25519_shared_secret(box->local_handshake_private, box->remote_public_key.data, dh_se) ||
            !x25519_shared_secret(box->private_key.data, box->remote_handshake_public, dh_es)) {
            set_box_error(err, err_cch, L"Session static-ephemeral key agreement failed.");
            goto cleanup;
        }
    }
    if (!x25519_shared_secret(box->local_handshake_private, box->remote_handshake_public, dh_ee)) {
        set_box_error(err, err_cch, L"Session ephemeral key agreement failed.");
        goto cleanup;
    }

    const uint8_t *role0_static = local_is_role0 ? box->public_key.data : box->remote_public_key.data;
    const uint8_t *role1_static = local_is_role0 ? box->remote_public_key.data : box->public_key.data;
    const uint8_t *role0_eph = local_is_role0 ? box->local_handshake_public : box->remote_handshake_public;
    const uint8_t *role1_eph = local_is_role0 ? box->remote_handshake_public : box->local_handshake_public;
    const uint8_t *salt_parts[4] = { role0_static, role1_static, role0_eph, role1_eph };
    DWORD salt_lens[4] = { X25519_KEY_BYTES, X25519_KEY_BYTES, X25519_KEY_BYTES, X25519_KEY_BYTES };
    const uint8_t *root_parts[4] = { dh_ss, dh_se, dh_es, dh_ee };
    DWORD root_lens[4] = { X25519_KEY_BYTES, X25519_KEY_BYTES, X25519_KEY_BYTES, X25519_KEY_BYTES };
    if (!hmac_sha256_segments(salt_key, (DWORD)(sizeof(salt_key) - 1), salt_parts, salt_lens, 4, salt) ||
        !hmac_sha256_segments(salt, sizeof(salt), root_parts, root_lens, 4, root) ||
        !derive_labeled_secret(root, "ChineseInputAgent CIM2 chain 0->1 v1", chain_0_to_1) ||
        !derive_labeled_secret(root, "ChineseInputAgent CIM2 chain 1->0 v1", chain_1_to_0) ||
        !derive_labeled_session_id(root, "ChineseInputAgent CIM2 session id 0->1 v1", &session_0_to_1) ||
        !derive_labeled_session_id(root, "ChineseInputAgent CIM2 session id 1->0 v1", &session_1_to_0)) {
        set_box_error(err, err_cch, L"Session key derivation failed.");
        goto cleanup;
    }

    clear_session_chains(box);
    if (local_is_role0) {
        memcpy(box->send_chain_key, chain_0_to_1, sizeof(box->send_chain_key));
        memcpy(box->recv_chain_key, chain_1_to_0, sizeof(box->recv_chain_key));
        box->send_session_id = session_0_to_1;
        box->recv_session_id = session_1_to_0;
    } else {
        memcpy(box->send_chain_key, chain_1_to_0, sizeof(box->send_chain_key));
        memcpy(box->recv_chain_key, chain_0_to_1, sizeof(box->recv_chain_key));
        box->send_session_id = session_1_to_0;
        box->recv_session_id = session_0_to_1;
    }
    box->send_counter = 0;
    box->recv_counter = 0;
    box->send_chain_ready = TRUE;
    box->recv_chain_ready = TRUE;
    clear_handshake_state(box);
    session_derived = TRUE;

cleanup:
    SecureZeroMemory(dh_ss, sizeof(dh_ss));
    SecureZeroMemory(dh_se, sizeof(dh_se));
    SecureZeroMemory(dh_es, sizeof(dh_es));
    SecureZeroMemory(dh_ee, sizeof(dh_ee));
    SecureZeroMemory(salt, sizeof(salt));
    SecureZeroMemory(root, sizeof(root));
    SecureZeroMemory(chain_0_to_1, sizeof(chain_0_to_1));
    SecureZeroMemory(chain_1_to_0, sizeof(chain_1_to_0));
    return session_derived;
}

static BOOL establish_session_if_ready(CRYPTO_BOX *box, WCHAR *err, size_t err_cch) {
    if (!box || !box->local_handshake_ready || !box->remote_handshake_ready) return TRUE;
    return derive_handshake_session(box, err, err_cch);
}

static BOOL derive_chain_step(const uint8_t chain_key[32], uint8_t message_key[32], uint8_t next_chain_key[32]) {
    return derive_labeled_secret(chain_key, "ChineseInputAgent CIM2 message key v1", message_key) &&
           derive_labeled_secret(chain_key, "ChineseInputAgent CIM2 next chain v1", next_chain_key);
}

static BOOL derive_session_nonce(const uint8_t message_key[32],
                                 const uint8_t header[SESSION_HEADER_BYTES],
                                 uint8_t nonce[MESSAGE_NONCE_BYTES]) {
    static const uint8_t label[] = "ChineseInputAgent CIM2 nonce v1";
    uint8_t digest[32];
    const uint8_t *parts[2] = { label, header };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), SESSION_HEADER_BYTES };
    BOOL nonce_derived = hmac_sha256_segments(message_key, 32, parts, lens, 2, digest);
    if (nonce_derived) memcpy(nonce, digest, MESSAGE_NONCE_BYTES);
    SecureZeroMemory(digest, sizeof(digest));
    return nonce_derived;
}

static void write_session_header(uint8_t header[SESSION_HEADER_BYTES], uint64_t session_id, uint32_t counter) {
    header[0] = SESSION_PACKET_FORMAT;
    write_u64_le(header + 1, session_id);
    write_u32_le(header + 1 + SESSION_ID_BYTES, counter);
}

static int find_skipped_key_index(CRYPTO_BOX *box, uint64_t session_id, uint32_t counter) {
    if (!box) return -1;
    for (int key_idx = 0; key_idx < (int)SESSION_MAX_SKIPPED_KEYS; ++key_idx) {
        SKIPPED_MESSAGE_KEY *skipped = &box->skipped_keys[key_idx];
        if (skipped->used && skipped->session_id == session_id && skipped->counter == counter) return key_idx;
    }
    return -1;
}

static int find_free_skipped_key_index(CRYPTO_BOX *box) {
    if (!box) return -1;
    for (int key_idx = 0; key_idx < (int)SESSION_MAX_SKIPPED_KEYS; ++key_idx) {
        if (!box->skipped_keys[key_idx].used) return key_idx;
    }
    return -1;
}

static unsigned count_free_skipped_keys(CRYPTO_BOX *box) {
    unsigned free_count = 0;
    if (!box) return 0;
    for (int key_idx = 0; key_idx < (int)SESSION_MAX_SKIPPED_KEYS; ++key_idx) {
        if (!box->skipped_keys[key_idx].used) ++free_count;
    }
    return free_count;
}

static BOOL protect_state_with_key(const BYTE state_key[STATE_KEY_BYTES], const uint8_t *plain, DWORD plain_len, uint8_t **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES;
    if (!state_key || (!plain && plain_len) || plain_len > 0xffffffffu - overhead) return FALSE;
    uint8_t nonce[STATE_NONCE_BYTES];
    uint8_t *state_envelope = NULL;
    DWORD total = overhead + plain_len;
    BOOL state_protected = FALSE;

    if (BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return FALSE;
    state_envelope = (uint8_t *)box_alloc(total ? total : 1);
    if (!state_envelope) goto cleanup;
    memcpy(state_envelope, "CIST", 4);
    state_envelope[4] = STATE_VERSION;
    state_envelope[5] = STATE_NONCE_BYTES;
    state_envelope[6] = STATE_TAG_BYTES;
    state_envelope[7] = 0;
    state_envelope[8] = (uint8_t)(plain_len & 0xff);
    state_envelope[9] = (uint8_t)((plain_len >> 8) & 0xff);
    state_envelope[10] = (uint8_t)((plain_len >> 16) & 0xff);
    state_envelope[11] = (uint8_t)((plain_len >> 24) & 0xff);
    memcpy(state_envelope + STATE_HEADER_BYTES, nonce, sizeof(nonce));
    if (!aes_gcm_encrypt_raw(state_key, state_envelope, STATE_HEADER_BYTES,
                             nonce, sizeof(nonce),
                             plain, plain_len,
                             state_envelope + STATE_HEADER_BYTES + STATE_NONCE_BYTES,
                             STATE_TAG_BYTES,
                             state_envelope + STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES)) goto cleanup;
    *out = state_envelope;
    *out_len = total;
    state_envelope = NULL;
    state_protected = TRUE;
cleanup:
    box_secure_free(state_envelope, total);
    SecureZeroMemory(nonce, sizeof(nonce));
    return state_protected;
}

static BOOL protect_state(CRYPTO_BOX *box, const uint8_t *plain, DWORD plain_len, uint8_t **out, DWORD *out_len) {
    if (!box) return FALSE;
    return protect_state_with_key(box->state_key, plain, plain_len, out, out_len);
}

static BOOL unprotect_state_with_key(const BYTE state_key[STATE_KEY_BYTES], const uint8_t *state_envelope, DWORD state_envelope_len, uint8_t **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES;
    if (!state_key ||
        !state_envelope ||
        state_envelope_len < overhead ||
        memcmp(state_envelope, "CIST", 4) != 0 ||
        (state_envelope[4] != STATE_VERSION && state_envelope[4] != STATE_VERSION_PRE_SESSION) ||
        state_envelope[5] != STATE_NONCE_BYTES ||
        state_envelope[6] != STATE_TAG_BYTES) return FALSE;
    DWORD plain_len = (DWORD)state_envelope[8] | ((DWORD)state_envelope[9] << 8) | ((DWORD)state_envelope[10] << 16) | ((DWORD)state_envelope[11] << 24);
    if (plain_len > state_envelope_len - overhead || overhead + plain_len != state_envelope_len) return FALSE;
    uint8_t *plain = (uint8_t *)box_alloc(plain_len ? plain_len : 1);
    if (!plain) return FALSE;
    if (!aes_gcm_decrypt_raw(state_key, state_envelope, STATE_HEADER_BYTES,
                             state_envelope + STATE_HEADER_BYTES, STATE_NONCE_BYTES,
                             state_envelope + STATE_HEADER_BYTES + STATE_NONCE_BYTES, STATE_TAG_BYTES,
                             state_envelope + STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES,
                             plain_len, plain)) {
        box_secure_free(plain, plain_len);
        return FALSE;
    }
    *out = plain;
    *out_len = plain_len;
    return TRUE;
}

static BOOL save_state(CRYPTO_BOX *box) {
    if (!box || !box->state_path[0]) return TRUE;
    BYTE_BUILDER state_builder = {0};
    uint8_t *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL state_saved = FALSE;
    if (!builder_u32(&state_builder, STATE_MAGIC) ||
        !builder_u32(&state_builder, STATE_VERSION) ||
        !builder_blob(&state_builder, box->public_key.data, box->public_key.len) ||
        !builder_blob(&state_builder, box->private_key.data, box->private_key.len) ||
        !builder_blob(&state_builder, box->remote_public_key.data, box->remote_public_key.len) ||
        !builder_u32(&state_builder, box->local_handshake_ready ? 1u : 0u) ||
        !builder_append(&state_builder, box->local_handshake_private, sizeof(box->local_handshake_private)) ||
        !builder_append(&state_builder, box->local_handshake_public, sizeof(box->local_handshake_public)) ||
        !builder_u32(&state_builder, box->remote_handshake_ready ? 1u : 0u) ||
        !builder_append(&state_builder, box->remote_handshake_public, sizeof(box->remote_handshake_public)) ||
        !builder_u32(&state_builder, box->send_chain_ready ? 1u : 0u) ||
        !builder_u64(&state_builder, box->send_session_id) ||
        !builder_u32(&state_builder, box->send_counter) ||
        !builder_append(&state_builder, box->send_chain_key, sizeof(box->send_chain_key)) ||
        !builder_u32(&state_builder, box->recv_chain_ready ? 1u : 0u) ||
        !builder_u64(&state_builder, box->recv_session_id) ||
        !builder_u32(&state_builder, box->recv_counter) ||
        !builder_append(&state_builder, box->recv_chain_key, sizeof(box->recv_chain_key)) ||
        !builder_u32(&state_builder, SESSION_MAX_SKIPPED_KEYS)) goto cleanup;
    for (int key_idx = 0; key_idx < (int)SESSION_MAX_SKIPPED_KEYS; ++key_idx) {
        SKIPPED_MESSAGE_KEY *skipped = &box->skipped_keys[key_idx];
        if (!builder_u32(&state_builder, skipped->used ? 1u : 0u) ||
            !builder_u64(&state_builder, skipped->session_id) ||
            !builder_u32(&state_builder, skipped->counter) ||
            !builder_append(&state_builder, skipped->key, sizeof(skipped->key))) goto cleanup;
    }
    if (!protect_state(box, state_builder.data, (DWORD)state_builder.len, &protected_blob, &protected_len)) goto cleanup;
    state_saved = write_file_all(box->state_path, protected_blob, protected_len);
cleanup:
    builder_free(&state_builder);
    box_secure_free(protected_blob, protected_len);
    return state_saved;
}

static BOOL load_state_with_key(CRYPTO_BOX *box, const BYTE state_key[STATE_KEY_BYTES]) {
    uint8_t *file = NULL;
    DWORD file_len = 0;
    uint8_t *plain = NULL;
    DWORD plain_len = 0;
    BOOL state_loaded = FALSE;
    if (!box || !state_key || !box->state_path[0] || !read_file_all(box->state_path, &file, &file_len)) return FALSE;
    if (!unprotect_state_with_key(state_key, file, file_len, &plain, &plain_len)) goto cleanup;
    READ_CURSOR c = { plain, plain_len, 0 };
    uint32_t magic = 0, version = 0;
    const uint8_t *pub = NULL, *priv = NULL, *remote = NULL;
    size_t pub_len = 0, priv_len = 0, remote_len = 0;
    if (!read_u32(&c, &magic) ||
        !read_u32(&c, &version) ||
        magic != STATE_MAGIC ||
        (version != STATE_VERSION && version != STATE_VERSION_PRE_SESSION) ||
        !read_blob_ref(&c, &pub, &pub_len) ||
        !read_blob_ref(&c, &priv, &priv_len) ||
        !read_blob_ref(&c, &remote, &remote_len) ||
        !validate_public_key_blob(pub, pub_len) ||
        !validate_private_key_blob(priv, priv_len)) goto cleanup;
    if (remote_len && !validate_public_key_blob(remote, remote_len)) goto cleanup;
    if (!buf_set(&box->public_key, pub, pub_len) ||
        !buf_set(&box->private_key, priv, priv_len) ||
        !buf_set(&box->remote_public_key, remote, remote_len)) goto cleanup;
    clear_handshake_state(box);
    clear_session_chains(box);
    if (version == STATE_VERSION) {
        uint32_t local_ready = 0, remote_ready = 0, send_ready = 0, recv_ready = 0, skipped_count = 0;
        const uint8_t *local_priv = NULL, *local_pub = NULL, *remote_hs = NULL, *send_chain = NULL, *recv_chain = NULL;
        if (!read_u32(&c, &local_ready) ||
            !read_fixed_ref(&c, &local_priv, X25519_KEY_BYTES) ||
            !read_fixed_ref(&c, &local_pub, X25519_KEY_BYTES) ||
            !read_u32(&c, &remote_ready) ||
            !read_fixed_ref(&c, &remote_hs, X25519_KEY_BYTES) ||
            !read_u32(&c, &send_ready) ||
            !read_u64(&c, &box->send_session_id) ||
            !read_u32(&c, &box->send_counter) ||
            !read_fixed_ref(&c, &send_chain, 32) ||
            !read_u32(&c, &recv_ready) ||
            !read_u64(&c, &box->recv_session_id) ||
            !read_u32(&c, &box->recv_counter) ||
            !read_fixed_ref(&c, &recv_chain, 32) ||
            !read_u32(&c, &skipped_count) ||
            skipped_count != SESSION_MAX_SKIPPED_KEYS) goto cleanup;
        if (local_ready > 1 || remote_ready > 1 || send_ready > 1 || recv_ready > 1) goto cleanup;
        if (local_ready) {
            if (!validate_private_key_blob(local_priv, X25519_KEY_BYTES) ||
                !validate_public_key_blob(local_pub, X25519_KEY_BYTES)) goto cleanup;
            memcpy(box->local_handshake_private, local_priv, X25519_KEY_BYTES);
            memcpy(box->local_handshake_public, local_pub, X25519_KEY_BYTES);
            box->local_handshake_ready = TRUE;
        }
        if (remote_ready) {
            if (!validate_public_key_blob(remote_hs, X25519_KEY_BYTES)) goto cleanup;
            memcpy(box->remote_handshake_public, remote_hs, X25519_KEY_BYTES);
            box->remote_handshake_ready = TRUE;
        }
        if (send_ready) {
            if (bytes_all_zero(send_chain, 32) || box->send_session_id == 0) goto cleanup;
            memcpy(box->send_chain_key, send_chain, 32);
            box->send_chain_ready = TRUE;
        }
        if (recv_ready) {
            if (bytes_all_zero(recv_chain, 32) || box->recv_session_id == 0) goto cleanup;
            memcpy(box->recv_chain_key, recv_chain, 32);
            box->recv_chain_ready = TRUE;
        }
        for (uint32_t key_idx = 0; key_idx < skipped_count; ++key_idx) {
            uint32_t used = 0;
            const uint8_t *key = NULL;
            if (!read_u32(&c, &used) ||
                !read_u64(&c, &box->skipped_keys[key_idx].session_id) ||
                !read_u32(&c, &box->skipped_keys[key_idx].counter) ||
                !read_fixed_ref(&c, &key, 32) ||
                used > 1) goto cleanup;
            if (used) {
                if (bytes_all_zero(key, 32) || box->skipped_keys[key_idx].session_id == 0) goto cleanup;
                box->skipped_keys[key_idx].used = TRUE;
                memcpy(box->skipped_keys[key_idx].key, key, 32);
            }
        }
    }
    if (c.pos != c.len) goto cleanup;
    state_loaded = TRUE;
cleanup:
    box_secure_free(file, file_len);
    box_secure_free(plain, plain_len);
    return state_loaded;
}

static BOOL load_state(CRYPTO_BOX *box) {
    if (!box) return FALSE;
    return load_state_with_key(box, box->state_key);
}

static BOOL generate_identity(CRYPTO_BOX *box) {
    uint8_t priv[X25519_KEY_BYTES];
    uint8_t pub[X25519_KEY_BYTES];
    BOOL identity_generated = FALSE;
    ZeroMemory(priv, sizeof(priv));
    ZeroMemory(pub, sizeof(pub));
    if (BCryptGenRandom(NULL, priv, sizeof(priv), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) goto cleanup;
    x25519_clamp_private(priv);
    if (!x25519_public_from_private(priv, pub)) goto cleanup;
    identity_generated = box &&
                         buf_set(&box->public_key, pub, sizeof(pub)) &&
                         buf_set(&box->private_key, priv, sizeof(priv));
cleanup:
    SecureZeroMemory(priv, sizeof(priv));
    SecureZeroMemory(pub, sizeof(pub));
    return identity_generated;
}

static BOOL crypto_box_open_internal(const BYTE state_encryption_key[32],
                                     const BYTE legacy_state_encryption_key[32],
                                     const WCHAR *state_path,
                                     CRYPTO_BOX **out,
                                     WCHAR *err,
                                     size_t err_cch) {
    if (out) *out = NULL;
    if (!out) return FALSE;
    if (!state_encryption_key) {
        set_box_error(err, err_cch, L"State encryption key is not ready.");
        return FALSE;
    }
    CRYPTO_BOX *box = (CRYPTO_BOX *)box_alloc(sizeof(CRYPTO_BOX));
    if (!box) {
        set_box_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    memcpy(box->state_key, state_encryption_key, STATE_KEY_BYTES);
    if (state_path && state_path[0]) StringCchCopyW(box->state_path, ARRAYSIZE(box->state_path), state_path);
    else box->state_path[0] = L'\0';
    BOOL state_exists = box_file_exists(box->state_path);
    if (state_exists && !load_state(box)) {
        BOOL migrated_legacy_state = FALSE;
        if (legacy_state_encryption_key && load_state_with_key(box, legacy_state_encryption_key)) {
            migrated_legacy_state = save_state(box);
        }
        if (!migrated_legacy_state) {
            set_box_error(err, err_cch, L"Key state file exists but could not be decrypted or parsed.");
            crypto_box_close(box);
            return FALSE;
        }
    }
    if (!box->public_key.data || !box->private_key.data) {
        if (!generate_identity(box) || !save_state(box)) {
            set_box_error(err, err_cch, L"X25519 key init failed.");
            crypto_box_close(box);
            return FALSE;
        }
    }
    *out = box;
    return TRUE;
}

BOOL crypto_box_open(const BYTE state_encryption_key[32], const WCHAR *state_path, CRYPTO_BOX **out,
                     WCHAR *err, size_t err_cch) {
    return crypto_box_open_internal(state_encryption_key, NULL, state_path, out, err, err_cch);
}

BOOL crypto_box_open_with_legacy_state_key(const BYTE state_encryption_key[32],
                                           const BYTE legacy_state_encryption_key[32],
                                           const WCHAR *state_path,
                                           CRYPTO_BOX **out,
                                           WCHAR *err,
                                           size_t err_cch) {
    return crypto_box_open_internal(state_encryption_key,
                                    legacy_state_encryption_key,
                                    state_path,
                                    out,
                                    err,
                                    err_cch);
}

void crypto_box_close(CRYPTO_BOX *box) {
    if (!box) return;
    buf_clear(&box->public_key);
    buf_clear(&box->private_key);
    buf_clear(&box->remote_public_key);
    SecureZeroMemory(box->state_key, sizeof(box->state_key));
    SecureZeroMemory(box->state_path, sizeof(box->state_path));
    box_secure_free(box, sizeof(*box));
}

BOOL crypto_box_get_public_key(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (!box || !validate_public_key_blob(box->public_key.data, box->public_key.len)) {
        set_box_error(err, err_cch, L"Local public key is not ready.");
        return FALSE;
    }
    BYTE *copy = (BYTE *)box_alloc(box->public_key.len);
    if (!copy) {
        set_box_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    memcpy(copy, box->public_key.data, box->public_key.len);
    *out = copy;
    *out_len = (DWORD)box->public_key.len;
    return TRUE;
}

BOOL crypto_box_get_remote_public_key(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (!box || !validate_public_key_blob(box->remote_public_key.data, box->remote_public_key.len)) {
        set_box_error(err, err_cch, L"No imported contact public key.");
        return FALSE;
    }
    BYTE *copy = (BYTE *)box_alloc(box->remote_public_key.len);
    if (!copy) {
        set_box_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    memcpy(copy, box->remote_public_key.data, box->remote_public_key.len);
    *out = copy;
    *out_len = (DWORD)box->remote_public_key.len;
    return TRUE;
}

BOOL crypto_box_get_public_fingerprint(CRYPTO_BOX *box, WCHAR *out, size_t cch, WCHAR *err, size_t err_cch) {
    if (!box || !validate_public_key_blob(box->public_key.data, box->public_key.len)) {
        set_box_error(err, err_cch, L"Local public key is not ready.");
        return FALSE;
    }
    if (!contact_fingerprint_from_public(box->public_key.data, out, cch)) {
        set_box_error(err, err_cch, L"Contact fingerprint generation failed.");
        return FALSE;
    }
    return TRUE;
}

BOOL crypto_box_contact_package_fingerprint(const BYTE *pkg, DWORD pkg_len, WCHAR *out, size_t cch,
                                            WCHAR *err, size_t err_cch) {
    CONTACT_PACKAGE_VIEW view;
    if (!parse_contact_package(pkg, pkg_len, &view)) {
        set_box_error(err, err_cch, L"Invalid session contact package.");
        return FALSE;
    }
    if (!contact_fingerprint_from_public(view.static_public, out, cch)) {
        set_box_error(err, err_cch, L"Contact fingerprint generation failed.");
        return FALSE;
    }
    return TRUE;
}

BOOL crypto_box_contact_package_recipient_public(const BYTE *pkg, DWORD pkg_len, BYTE recipient[32],
                                                 BOOL *has_recipient, WCHAR *err, size_t err_cch) {
    if (has_recipient) *has_recipient = FALSE;
    if (recipient) SecureZeroMemory(recipient, X25519_KEY_BYTES);
    if (!has_recipient || !recipient) {
        set_box_error(err, err_cch, L"Invalid contact package recipient output.");
        return FALSE;
    }
    CONTACT_PACKAGE_VIEW view;
    if (!parse_contact_package(pkg, pkg_len, &view)) {
        set_box_error(err, err_cch, L"Invalid session contact package.");
        return FALSE;
    }
    *has_recipient = view.has_recipient;
    if (view.has_recipient) memcpy(recipient, view.recipient_public, X25519_KEY_BYTES);
    return TRUE;
}

BOOL crypto_box_prepare_key_export(CRYPTO_BOX *box, WCHAR *err, size_t err_cch) {
    if (!save_state(box)) {
        set_box_error(err, err_cch, L"Key state save failed.");
        return FALSE;
    }
    return TRUE;
}

BOOL crypto_box_export_contact_package(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    uint8_t checksum[CONTACT_CHECKSUM_BYTES];
    uint8_t *pkg = NULL;
    DWORD pkg_alloc_len = 0;
    BOOL package_exported = FALSE;
    ZeroMemory(checksum, sizeof(checksum));
    if (!box || !validate_public_key_blob(box->public_key.data, box->public_key.len)) {
        set_box_error(err, err_cch, L"Local public key is not ready.");
        goto cleanup;
    }
    if (!box->state_path[0]) {
        set_box_error(err, err_cch, L"Session state path is not available.");
        goto cleanup;
    }
    if (!generate_handshake_key(box)) {
        set_box_error(err, err_cch, L"Session handshake key generation failed.");
        goto cleanup;
    }

    BOOL include_recipient = validate_public_key_blob(box->remote_public_key.data, box->remote_public_key.len);
    DWORD body_len = include_recipient ?
        (DWORD)(CONTACT_PACKAGE_WITH_RECIPIENT_BYTES - CONTACT_CHECKSUM_BYTES) :
        (DWORD)(CONTACT_PACKAGE_BASE_BYTES - CONTACT_CHECKSUM_BYTES);
    DWORD pkg_len = body_len + CONTACT_CHECKSUM_BYTES;
    pkg_alloc_len = pkg_len;
    pkg = (uint8_t *)box_alloc(pkg_alloc_len);
    if (!pkg) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    uint8_t *p = pkg;
    *p++ = (uint8_t)(CONTACT_PACKAGE_FORMAT_BASE | (include_recipient ? CONTACT_PACKAGE_RECIPIENT_FLAG : 0u));
    memcpy(p, box->public_key.data, X25519_KEY_BYTES);
    p += X25519_KEY_BYTES;
    memcpy(p, box->local_handshake_public, X25519_KEY_BYTES);
    p += X25519_KEY_BYTES;
    if (include_recipient) {
        memcpy(p, box->remote_public_key.data, X25519_KEY_BYTES);
        p += X25519_KEY_BYTES;
    }
    if (!contact_package_checksum(pkg, body_len, checksum)) {
        set_box_error(err, err_cch, L"Contact package checksum failed.");
        goto cleanup;
    }
    memcpy(p, checksum, CONTACT_CHECKSUM_BYTES);
    if (!establish_session_if_ready(box, err, err_cch) || !save_state(box)) {
        if (!err || !err[0]) set_box_error(err, err_cch, L"Session contact package save failed.");
        goto cleanup;
    }
    *out = pkg;
    *out_len = pkg_len;
    pkg = NULL;
    package_exported = TRUE;
cleanup:
    if (!package_exported) {
        box_secure_free(*out, *out_len);
        *out = NULL;
        *out_len = 0;
    }
    box_secure_free(pkg, pkg_alloc_len);
    SecureZeroMemory(checksum, sizeof(checksum));
    return package_exported;
}

BOOL crypto_box_import_contact_package(CRYPTO_BOX *box, const BYTE *pkg, DWORD pkg_len, WCHAR *err, size_t err_cch) {
    if (!box || !pkg) {
        set_box_error(err, err_cch, L"Invalid session contact package.");
        return FALSE;
    }
    if (!box->state_path[0]) {
        set_box_error(err, err_cch, L"Session state path is not available.");
        return FALSE;
    }
    CONTACT_PACKAGE_VIEW view;
    if (!parse_contact_package(pkg, pkg_len, &view)) {
        set_box_error(err, err_cch, L"Invalid session contact package.");
        return FALSE;
    }
    if (view.has_recipient &&
        (!validate_public_key_blob(box->public_key.data, box->public_key.len) ||
         memcmp(view.recipient_public, box->public_key.data, X25519_KEY_BYTES) != 0)) {
        set_box_error(err, err_cch, L"This session contact package is addressed to a different local key.");
        return FALSE;
    }

    BOOL remote_changed = box->remote_public_key.data &&
                          memcmp(box->remote_public_key.data, view.static_public, X25519_KEY_BYTES) != 0;
    if (remote_changed) {
        clear_handshake_state(box);
        clear_session_chains(box);
    }
    if (!buf_set(&box->remote_public_key, view.static_public, X25519_KEY_BYTES)) {
        set_box_error(err, err_cch, L"Contact package save failed.");
        return FALSE;
    }
    memcpy(box->remote_handshake_public, view.handshake_public, X25519_KEY_BYTES);
    box->remote_handshake_ready = TRUE;
    if (!establish_session_if_ready(box, err, err_cch) || !save_state(box)) {
        if (!err || !err[0]) set_box_error(err, err_cch, L"Contact package save failed.");
        return FALSE;
    }
    return TRUE;
}

BOOL crypto_box_encrypt(CRYPTO_BOX *box, const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (!box || (!plain && plain_len)) {
        set_box_error(err, err_cch, L"Invalid plaintext buffer.");
        return FALSE;
    }
    if (!box->state_path[0]) {
        set_box_error(err, err_cch, L"Session state path is not available.");
        return FALSE;
    }
    if (!box->send_chain_ready || box->send_session_id == 0) {
        set_box_error(err, err_cch, L"Session is not ready. Exchange key packages first.");
        return FALSE;
    }
    if (box->send_counter == 0xffffffffu) {
        set_box_error(err, err_cch, L"Session send counter is exhausted. Exchange key packages again.");
        return FALSE;
    }
    if (plain_len > 0xffffffffu - SESSION_HEADER_BYTES - MESSAGE_TAG_BYTES) {
        set_box_error(err, err_cch, L"Plaintext is too large.");
        return FALSE;
    }

    uint8_t header[SESSION_HEADER_BYTES];
    uint8_t old_chain_key[32];
    uint8_t message_key[32];
    uint8_t next_chain_key[32];
    uint8_t nonce[MESSAGE_NONCE_BYTES];
    uint8_t *message = NULL;
    DWORD message_len = SESSION_HEADER_BYTES + MESSAGE_TAG_BYTES + plain_len;
    uint32_t old_counter = box->send_counter;
    BOOL message_encrypted = FALSE;

    ZeroMemory(header, sizeof(header));
    ZeroMemory(old_chain_key, sizeof(old_chain_key));
    ZeroMemory(message_key, sizeof(message_key));
    ZeroMemory(next_chain_key, sizeof(next_chain_key));
    ZeroMemory(nonce, sizeof(nonce));

    write_session_header(header, box->send_session_id, box->send_counter);
    memcpy(old_chain_key, box->send_chain_key, sizeof(old_chain_key));
    if (!derive_chain_step(box->send_chain_key, message_key, next_chain_key) ||
        !derive_session_nonce(message_key, header, nonce)) {
        set_box_error(err, err_cch, L"Session message key derivation failed.");
        goto cleanup;
    }

    message = (uint8_t *)box_alloc(message_len ? message_len : 1);
    if (!message) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    memcpy(message, header, SESSION_HEADER_BYTES);
    if (!aes_gcm_encrypt_raw(message_key, message, SESSION_HEADER_BYTES, nonce, MESSAGE_NONCE_BYTES,
                             plain, plain_len,
                             message + SESSION_HEADER_BYTES, MESSAGE_TAG_BYTES,
                             message + SESSION_HEADER_BYTES + MESSAGE_TAG_BYTES)) {
        set_box_error(err, err_cch, L"AES-GCM encryption failed.");
        goto cleanup;
    }

    memcpy(box->send_chain_key, next_chain_key, sizeof(box->send_chain_key));
    box->send_counter++;
    if (!save_state(box)) {
        memcpy(box->send_chain_key, old_chain_key, sizeof(box->send_chain_key));
        box->send_counter = old_counter;
        set_box_error(err, err_cch, L"Session state save failed.");
        goto cleanup;
    }

    *out = message;
    *out_len = message_len;
    message = NULL;
    message_encrypted = TRUE;
cleanup:
    box_secure_free(message, message_len);
    SecureZeroMemory(header, sizeof(header));
    SecureZeroMemory(old_chain_key, sizeof(old_chain_key));
    SecureZeroMemory(message_key, sizeof(message_key));
    SecureZeroMemory(next_chain_key, sizeof(next_chain_key));
    SecureZeroMemory(nonce, sizeof(nonce));
    return message_encrypted;
}

BOOL crypto_box_decrypt(CRYPTO_BOX *box, const BYTE *message, DWORD message_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (!box || (!message && message_len)) {
        set_box_error(err, err_cch, L"Invalid encrypted message buffer.");
        return FALSE;
    }
    if (!box->state_path[0]) {
        set_box_error(err, err_cch, L"Session state path is not available.");
        return FALSE;
    }
    if (message_len < SESSION_HEADER_BYTES + MESSAGE_TAG_BYTES || message[0] != SESSION_PACKET_FORMAT) {
        set_box_error(err, err_cch, L"Invalid session message format.");
        return FALSE;
    }

    uint64_t session_id = read_u64_le(message + 1);
    uint32_t counter = read_u32_le(message + 1 + SESSION_ID_BYTES);
    DWORD cipher_len = message_len - SESSION_HEADER_BYTES - MESSAGE_TAG_BYTES;
    uint8_t *plain = NULL;
    uint8_t message_key[32];
    uint8_t next_chain_key[32];
    uint8_t working_chain_key[32];
    uint8_t old_recv_chain_key[32];
    uint8_t nonce[MESSAGE_NONCE_BYTES];
    SKIPPED_MESSAGE_KEY old_skipped_keys[SESSION_MAX_SKIPPED_KEYS];
    SKIPPED_MESSAGE_KEY temp_skipped_keys[SESSION_MAX_SKIPPED_KEYS];
    SKIPPED_MESSAGE_KEY old_skipped_slot;
    uint32_t old_recv_counter = box->recv_counter;
    int skipped_slot = -1;
    BOOL message_decrypted = FALSE;

    ZeroMemory(message_key, sizeof(message_key));
    ZeroMemory(next_chain_key, sizeof(next_chain_key));
    ZeroMemory(working_chain_key, sizeof(working_chain_key));
    ZeroMemory(old_recv_chain_key, sizeof(old_recv_chain_key));
    ZeroMemory(nonce, sizeof(nonce));
    ZeroMemory(old_skipped_keys, sizeof(old_skipped_keys));
    ZeroMemory(temp_skipped_keys, sizeof(temp_skipped_keys));
    ZeroMemory(&old_skipped_slot, sizeof(old_skipped_slot));

    if (session_id == 0) {
        set_box_error(err, err_cch, L"Invalid session id.");
        goto cleanup;
    }

    skipped_slot = find_skipped_key_index(box, session_id, counter);
    if (skipped_slot >= 0) {
        old_skipped_slot = box->skipped_keys[skipped_slot];
        memcpy(message_key, box->skipped_keys[skipped_slot].key, sizeof(message_key));
    } else {
        if (!box->recv_chain_ready || session_id != box->recv_session_id) {
            set_box_error(err, err_cch, L"Session message does not match the active receive session.");
            goto cleanup;
        }
        if (counter < box->recv_counter) {
            set_box_error(err, err_cch, L"Session message counter is too old.");
            goto cleanup;
        }
        if (counter == 0xffffffffu) {
            set_box_error(err, err_cch, L"Session receive counter is exhausted. Exchange key packages again.");
            goto cleanup;
        }
        uint32_t gap = counter - box->recv_counter;
        if (gap > SESSION_MAX_SKIPPED_KEYS || gap > count_free_skipped_keys(box)) {
            set_box_error(err, err_cch, L"Session message is outside the out-of-order window.");
            goto cleanup;
        }
        memcpy(working_chain_key, box->recv_chain_key, sizeof(working_chain_key));
        for (uint32_t skipped_idx = 0; skipped_idx < gap; ++skipped_idx) {
            uint8_t skipped_next_chain[32];
            ZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
            temp_skipped_keys[skipped_idx].used = TRUE;
            temp_skipped_keys[skipped_idx].session_id = session_id;
            temp_skipped_keys[skipped_idx].counter = box->recv_counter + skipped_idx;
            if (!derive_chain_step(working_chain_key, temp_skipped_keys[skipped_idx].key, skipped_next_chain)) {
                SecureZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
                set_box_error(err, err_cch, L"Session skipped-key derivation failed.");
                goto cleanup;
            }
            SecureZeroMemory(working_chain_key, sizeof(working_chain_key));
            memcpy(working_chain_key, skipped_next_chain, sizeof(working_chain_key));
            SecureZeroMemory(skipped_next_chain, sizeof(skipped_next_chain));
        }
        if (!derive_chain_step(working_chain_key, message_key, next_chain_key)) {
            set_box_error(err, err_cch, L"Session message key derivation failed.");
            goto cleanup;
        }
    }

    if (!derive_session_nonce(message_key, message, nonce)) {
        set_box_error(err, err_cch, L"Session nonce derivation failed.");
        goto cleanup;
    }
    plain = (uint8_t *)box_alloc(cipher_len ? cipher_len : 1);
    if (!plain) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (!aes_gcm_decrypt_raw(message_key, message, SESSION_HEADER_BYTES,
                             nonce, MESSAGE_NONCE_BYTES,
                             message + SESSION_HEADER_BYTES, MESSAGE_TAG_BYTES,
                             message + SESSION_HEADER_BYTES + MESSAGE_TAG_BYTES, cipher_len,
                             plain)) {
        set_box_error(err, err_cch, L"AES-GCM authentication failed.");
        goto cleanup;
    }

    if (skipped_slot >= 0) {
        ZeroMemory(&box->skipped_keys[skipped_slot], sizeof(box->skipped_keys[skipped_slot]));
        if (!save_state(box)) {
            box->skipped_keys[skipped_slot] = old_skipped_slot;
            set_box_error(err, err_cch, L"Session state save failed.");
            goto cleanup;
        }
    } else {
        memcpy(old_recv_chain_key, box->recv_chain_key, sizeof(old_recv_chain_key));
        memcpy(old_skipped_keys, box->skipped_keys, sizeof(old_skipped_keys));
        for (int skipped_idx = 0; skipped_idx < (int)SESSION_MAX_SKIPPED_KEYS; ++skipped_idx) {
            if (!temp_skipped_keys[skipped_idx].used) continue;
            int free_idx = find_free_skipped_key_index(box);
            if (free_idx < 0) {
                memcpy(box->skipped_keys, old_skipped_keys, sizeof(box->skipped_keys));
                set_box_error(err, err_cch, L"Session skipped-key cache is full.");
                goto cleanup;
            }
            box->skipped_keys[free_idx] = temp_skipped_keys[skipped_idx];
        }
        memcpy(box->recv_chain_key, next_chain_key, sizeof(box->recv_chain_key));
        box->recv_counter = counter + 1;
        if (!save_state(box)) {
            memcpy(box->recv_chain_key, old_recv_chain_key, sizeof(box->recv_chain_key));
            box->recv_counter = old_recv_counter;
            memcpy(box->skipped_keys, old_skipped_keys, sizeof(box->skipped_keys));
            set_box_error(err, err_cch, L"Session state save failed.");
            goto cleanup;
        }
    }

    *out = plain;
    *out_len = cipher_len;
    plain = NULL;
    message_decrypted = TRUE;
cleanup:
    box_secure_free(plain, cipher_len);
    SecureZeroMemory(message_key, sizeof(message_key));
    SecureZeroMemory(next_chain_key, sizeof(next_chain_key));
    SecureZeroMemory(working_chain_key, sizeof(working_chain_key));
    SecureZeroMemory(old_recv_chain_key, sizeof(old_recv_chain_key));
    SecureZeroMemory(nonce, sizeof(nonce));
    SecureZeroMemory(old_skipped_keys, sizeof(old_skipped_keys));
    SecureZeroMemory(temp_skipped_keys, sizeof(temp_skipped_keys));
    SecureZeroMemory(&old_skipped_slot, sizeof(old_skipped_slot));
    return message_decrypted;
}
