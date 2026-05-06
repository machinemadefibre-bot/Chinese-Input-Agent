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
#define STATE_VERSION 4u
#define MASTER_KEY_BYTES 32
#define X25519_KEY_BYTES 32
#define CONTACT_CHECKSUM_BYTES 8
#define CONTACT_COMPACT_PACKAGE_BYTES (X25519_KEY_BYTES + CONTACT_CHECKSUM_BYTES)
#define CONTACT_FINGERPRINT_DIGITS 16
#define STATE_NONCE_BYTES 12
#define STATE_TAG_BYTES 16
#define STATE_HEADER_BYTES 16

#define MESSAGE_NONCE_BYTES 12
#define MESSAGE_TAG_BYTES 16

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

struct CRYPTO_BOX {
    BYTE master_key[MASTER_KEY_BYTES];
    WCHAR state_path[MAX_PATH];
    BOX_BUF public_key;
    BOX_BUF private_key;
    BOX_BUF remote_public_key;
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

static BOOL read_blob_ref(READ_CURSOR *c, const uint8_t **bytes, size_t *len) {
    uint32_t n = 0;
    if (!bytes || !len || !read_u32(c, &n) || c->pos > c->len || (size_t)n > c->len - c->pos) return FALSE;
    *bytes = c->data + c->pos;
    *len = n;
    c->pos += n;
    return TRUE;
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

static BOOL derive_message_key(const uint8_t *shared, DWORD shared_len,
                               const uint8_t *ephemeral_public, DWORD ephemeral_public_len,
                               const uint8_t *recipient_public, DWORD recipient_public_len,
                               uint8_t key_out[32]) {
    static const uint8_t salt_key[] = "ChineseInputAgent X25519 ECIES salt v1";
    static const uint8_t info[] = "ChineseInputAgent X25519 ECIES key v1";
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t one = 1;
    const uint8_t *salt_parts[2] = { ephemeral_public, recipient_public };
    DWORD salt_lens[2] = { ephemeral_public_len, recipient_public_len };
    const uint8_t *ikm_parts[1] = { shared };
    DWORD ikm_lens[1] = { shared_len };
    const uint8_t *info_parts[2] = { info, &one };
    DWORD info_lens[2] = { (DWORD)(sizeof(info) - 1), 1 };
    BOOL key_derived = FALSE;

    if (!hmac_sha256_segments(salt_key, (DWORD)(sizeof(salt_key) - 1), salt_parts, salt_lens, 2, salt)) goto cleanup;
    if (!hmac_sha256_segments(salt, sizeof(salt), ikm_parts, ikm_lens, 1, prk)) goto cleanup;
    if (!hmac_sha256_segments(prk, sizeof(prk), info_parts, info_lens, 2, key_out)) goto cleanup;
    key_derived = TRUE;
cleanup:
    SecureZeroMemory(salt, sizeof(salt));
    SecureZeroMemory(prk, sizeof(prk));
    if (!key_derived) SecureZeroMemory(key_out, 32);
    return key_derived;
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

static BOOL contact_checksum(const uint8_t pub[X25519_KEY_BYTES], uint8_t out[CONTACT_CHECKSUM_BYTES]) {
    static const uint8_t label[] = "ChineseInputAgent contact checksum";
    uint8_t digest[32];
    const uint8_t *parts[2] = { label, pub };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), X25519_KEY_BYTES };
    BOOL checksum_built = sha256_segments(parts, lens, 2, digest);
    if (checksum_built) memcpy(out, digest, CONTACT_CHECKSUM_BYTES);
    SecureZeroMemory(digest, sizeof(digest));
    return checksum_built;
}

static BOOL contact_fingerprint_from_public(const uint8_t pub[X25519_KEY_BYTES], WCHAR *out, size_t cch) {
    static const uint8_t label[] = "ChineseInputAgent contact fingerprint";
    static const WCHAR alphabet[] = L"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    uint8_t digest[32];
    const uint8_t *parts[2] = { label, pub };
    DWORD lens[2] = { (DWORD)(sizeof(label) - 1), X25519_KEY_BYTES };
    if (!out || cch < CONTACT_FINGERPRINT_DIGITS + 4) return FALSE;
    if (!validate_public_key_blob(pub, X25519_KEY_BYTES) || !sha256_segments(parts, lens, 2, digest)) return FALSE;
    size_t bit = 0, pos = 0;
    for (size_t i = 0; i < CONTACT_FINGERPRINT_DIGITS; ++i) {
        uint32_t v = 0;
        for (int j = 0; j < 5; ++j) {
            size_t byte_i = bit / 8;
            size_t bit_i = 7 - (bit % 8);
            v = (v << 1) | ((digest[byte_i] >> bit_i) & 1u);
            ++bit;
        }
        if (i && (i % 4) == 0) out[pos++] = L'-';
        out[pos++] = alphabet[v & 31u];
    }
    out[pos] = L'\0';
    SecureZeroMemory(digest, sizeof(digest));
    return TRUE;
}

static BOOL protect_state(CRYPTO_BOX *box, const uint8_t *plain, DWORD plain_len, uint8_t **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES;
    if (!box || (!plain && plain_len) || plain_len > 0xffffffffu - overhead) return FALSE;
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
    if (!aes_gcm_encrypt_raw(box->master_key, state_envelope, STATE_HEADER_BYTES,
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

static BOOL unprotect_state(CRYPTO_BOX *box, const uint8_t *state_envelope, DWORD state_envelope_len, uint8_t **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = STATE_HEADER_BYTES + STATE_NONCE_BYTES + STATE_TAG_BYTES;
    if (!box ||
        !state_envelope ||
        state_envelope_len < overhead ||
        memcmp(state_envelope, "CIST", 4) != 0 ||
        state_envelope[4] != STATE_VERSION ||
        state_envelope[5] != STATE_NONCE_BYTES ||
        state_envelope[6] != STATE_TAG_BYTES) return FALSE;
    DWORD plain_len = (DWORD)state_envelope[8] | ((DWORD)state_envelope[9] << 8) | ((DWORD)state_envelope[10] << 16) | ((DWORD)state_envelope[11] << 24);
    if (plain_len > state_envelope_len - overhead || overhead + plain_len != state_envelope_len) return FALSE;
    uint8_t *plain = (uint8_t *)box_alloc(plain_len ? plain_len : 1);
    if (!plain) return FALSE;
    if (!aes_gcm_decrypt_raw(box->master_key, state_envelope, STATE_HEADER_BYTES,
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
        !builder_blob(&state_builder, box->remote_public_key.data, box->remote_public_key.len)) goto cleanup;
    if (!protect_state(box, state_builder.data, (DWORD)state_builder.len, &protected_blob, &protected_len)) goto cleanup;
    state_saved = write_file_all(box->state_path, protected_blob, protected_len);
cleanup:
    builder_free(&state_builder);
    box_secure_free(protected_blob, protected_len);
    return state_saved;
}

static BOOL load_state(CRYPTO_BOX *box) {
    uint8_t *file = NULL;
    DWORD file_len = 0;
    uint8_t *plain = NULL;
    DWORD plain_len = 0;
    BOOL state_loaded = FALSE;
    if (!box || !box->state_path[0] || !read_file_all(box->state_path, &file, &file_len)) return FALSE;
    if (!unprotect_state(box, file, file_len, &plain, &plain_len)) goto cleanup;
    READ_CURSOR c = { plain, plain_len, 0 };
    uint32_t magic = 0, version = 0;
    const uint8_t *pub = NULL, *priv = NULL, *remote = NULL;
    size_t pub_len = 0, priv_len = 0, remote_len = 0;
    if (!read_u32(&c, &magic) ||
        !read_u32(&c, &version) ||
        magic != STATE_MAGIC ||
        version != STATE_VERSION ||
        !read_blob_ref(&c, &pub, &pub_len) ||
        !read_blob_ref(&c, &priv, &priv_len) ||
        !read_blob_ref(&c, &remote, &remote_len) ||
        !validate_public_key_blob(pub, pub_len) ||
        !validate_private_key_blob(priv, priv_len)) goto cleanup;
    if (c.pos != c.len || (remote_len && !validate_public_key_blob(remote, remote_len))) goto cleanup;
    if (!buf_set(&box->public_key, pub, pub_len) ||
        !buf_set(&box->private_key, priv, priv_len) ||
        !buf_set(&box->remote_public_key, remote, remote_len)) goto cleanup;
    state_loaded = TRUE;
cleanup:
    box_secure_free(file, file_len);
    box_secure_free(plain, plain_len);
    return state_loaded;
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

BOOL crypto_box_open(const BYTE master_key[32], const WCHAR *state_path, CRYPTO_BOX **out,
                     WCHAR *err, size_t err_cch) {
    if (out) *out = NULL;
    if (!out) return FALSE;
    if (!master_key) {
        set_box_error(err, err_cch, L"Master key is not ready.");
        return FALSE;
    }
    CRYPTO_BOX *box = (CRYPTO_BOX *)box_alloc(sizeof(CRYPTO_BOX));
    if (!box) {
        set_box_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    memcpy(box->master_key, master_key, MASTER_KEY_BYTES);
    if (state_path && state_path[0]) StringCchCopyW(box->state_path, ARRAYSIZE(box->state_path), state_path);
    else box->state_path[0] = L'\0';
    BOOL state_exists = box_file_exists(box->state_path);
    if (state_exists && !load_state(box)) {
        set_box_error(err, err_cch, L"Key state file exists but could not be decrypted or parsed.");
        crypto_box_close(box);
        return FALSE;
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

void crypto_box_close(CRYPTO_BOX *box) {
    if (!box) return;
    buf_clear(&box->public_key);
    buf_clear(&box->private_key);
    buf_clear(&box->remote_public_key);
    SecureZeroMemory(box->master_key, sizeof(box->master_key));
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
    if (!pkg || pkg_len != CONTACT_COMPACT_PACKAGE_BYTES ||
        !validate_public_key_blob(pkg, X25519_KEY_BYTES)) {
        set_box_error(err, err_cch, L"Invalid compact contact package.");
        return FALSE;
    }
    uint8_t expected[CONTACT_CHECKSUM_BYTES];
    BOOL package_verified = contact_checksum(pkg, expected) &&
                            memcmp(expected, pkg + X25519_KEY_BYTES, CONTACT_CHECKSUM_BYTES) == 0 &&
                            contact_fingerprint_from_public(pkg, out, cch);
    SecureZeroMemory(expected, sizeof(expected));
    if (!package_verified) {
        set_box_error(err, err_cch, L"Invalid compact contact package checksum.");
        return FALSE;
    }
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
    BOOL package_exported = FALSE;
    ZeroMemory(checksum, sizeof(checksum));
    if (!box || !validate_public_key_blob(box->public_key.data, box->public_key.len)) {
        set_box_error(err, err_cch, L"Local public key is not ready.");
        goto cleanup;
    }
    if (!contact_checksum(box->public_key.data, checksum)) {
        set_box_error(err, err_cch, L"Contact package checksum failed.");
        goto cleanup;
    }
    pkg = (uint8_t *)box_alloc(CONTACT_COMPACT_PACKAGE_BYTES);
    if (!pkg) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    uint8_t *p = pkg;
    memcpy(p, box->public_key.data, X25519_KEY_BYTES); p += X25519_KEY_BYTES;
    memcpy(p, checksum, CONTACT_CHECKSUM_BYTES);
    *out = pkg;
    *out_len = CONTACT_COMPACT_PACKAGE_BYTES;
    pkg = NULL;
    package_exported = TRUE;
cleanup:
    if (!package_exported) {
        box_secure_free(*out, *out_len);
        *out = NULL;
        *out_len = 0;
    }
    box_secure_free(pkg, CONTACT_COMPACT_PACKAGE_BYTES);
    SecureZeroMemory(checksum, sizeof(checksum));
    return package_exported;
}

BOOL crypto_box_import_contact_package(CRYPTO_BOX *box, const BYTE *pkg, DWORD pkg_len, WCHAR *err, size_t err_cch) {
    if (!box || !pkg || pkg_len != CONTACT_COMPACT_PACKAGE_BYTES) {
        set_box_error(err, err_cch, L"Invalid compact contact package length.");
        return FALSE;
    }
    const uint8_t *pub = pkg;
    const uint8_t *checksum = pub + X25519_KEY_BYTES;
    uint8_t expected[CONTACT_CHECKSUM_BYTES];
    BOOL verified = FALSE;
    ZeroMemory(expected, sizeof(expected));
    verified =
        validate_public_key_blob(pub, X25519_KEY_BYTES) &&
        contact_checksum(pub, expected) &&
        memcmp(expected, checksum, CONTACT_CHECKSUM_BYTES) == 0;
    SecureZeroMemory(expected, sizeof(expected));
    if (!verified) {
        set_box_error(err, err_cch, L"Invalid compact contact package checksum.");
        return FALSE;
    }
    if (!buf_set(&box->remote_public_key, pub, X25519_KEY_BYTES) || !save_state(box)) {
        set_box_error(err, err_cch, L"Contact package save failed.");
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
    const uint8_t *recipient_pub = box->remote_public_key.data ? box->remote_public_key.data : box->public_key.data;
    size_t recipient_len = box->remote_public_key.data ? box->remote_public_key.len : box->public_key.len;
    uint8_t eph_priv[X25519_KEY_BYTES];
    uint8_t eph_pub[X25519_KEY_BYTES];
    uint8_t shared[X25519_KEY_BYTES];
    uint8_t key[32];
    uint8_t nonce[MESSAGE_NONCE_BYTES];
    uint8_t *message = NULL;
    DWORD message_len = 0;
    BOOL message_encrypted = FALSE;

    ZeroMemory(eph_priv, sizeof(eph_priv));
    ZeroMemory(eph_pub, sizeof(eph_pub));
    ZeroMemory(shared, sizeof(shared));
    ZeroMemory(key, sizeof(key));
    ZeroMemory(nonce, sizeof(nonce));

    if (!validate_public_key_blob(recipient_pub, recipient_len)) {
        set_box_error(err, err_cch, L"Recipient public key is not ready.");
        goto cleanup;
    }
    if (BCryptGenRandom(NULL, eph_priv, sizeof(eph_priv), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        set_box_error(err, err_cch, L"Random generation failed.");
        goto cleanup;
    }
    x25519_clamp_private(eph_priv);
    if (!x25519_public_from_private(eph_priv, eph_pub) ||
        !x25519_shared_secret(eph_priv, recipient_pub, shared)) {
        set_box_error(err, err_cch, L"X25519 key agreement failed.");
        goto cleanup;
    }
    if (!derive_message_key(shared, sizeof(shared),
                            eph_pub, sizeof(eph_pub),
                            recipient_pub, (DWORD)recipient_len, key)) {
        set_box_error(err, err_cch, L"Message key derivation failed.");
        goto cleanup;
    }
    if (BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        set_box_error(err, err_cch, L"Random generation failed.");
        goto cleanup;
    }
    DWORD aad_len = X25519_KEY_BYTES + MESSAGE_NONCE_BYTES;
    if (plain_len > 0xffffffffu - aad_len - MESSAGE_TAG_BYTES) {
        set_box_error(err, err_cch, L"Plaintext is too large.");
        goto cleanup;
    }
    message_len = aad_len + MESSAGE_TAG_BYTES + plain_len;
    message = (uint8_t *)box_alloc(message_len ? message_len : 1);
    if (!message) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    memcpy(message, eph_pub, X25519_KEY_BYTES);
    memcpy(message + X25519_KEY_BYTES, nonce, MESSAGE_NONCE_BYTES);
    if (!aes_gcm_encrypt_raw(key, message, aad_len, nonce, MESSAGE_NONCE_BYTES,
                             plain, plain_len,
                             message + aad_len, MESSAGE_TAG_BYTES,
                             message + aad_len + MESSAGE_TAG_BYTES)) {
        set_box_error(err, err_cch, L"AES-GCM encryption failed.");
        goto cleanup;
    }
    *out = message;
    *out_len = message_len;
    message = NULL;
    message_encrypted = TRUE;
cleanup:
    box_secure_free(message, message_len);
    SecureZeroMemory(eph_priv, sizeof(eph_priv));
    SecureZeroMemory(eph_pub, sizeof(eph_pub));
    SecureZeroMemory(shared, sizeof(shared));
    SecureZeroMemory(key, sizeof(key));
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
    uint8_t shared[X25519_KEY_BYTES];
    uint8_t key[32];
    uint8_t *plain = NULL;
    DWORD cipher_len = 0;
    BOOL message_decrypted = FALSE;

    ZeroMemory(shared, sizeof(shared));
    ZeroMemory(key, sizeof(key));

    DWORD aad_len = X25519_KEY_BYTES + MESSAGE_NONCE_BYTES;
    if (message_len < aad_len + MESSAGE_TAG_BYTES) {
        set_box_error(err, err_cch, L"Invalid encrypted message length.");
        goto cleanup;
    }
    cipher_len = message_len - aad_len - MESSAGE_TAG_BYTES;
    if (!validate_private_key_blob(box->private_key.data, box->private_key.len) ||
        !validate_public_key_blob(box->public_key.data, box->public_key.len)) {
        set_box_error(err, err_cch, L"Local private key is not ready.");
        goto cleanup;
    }
    const uint8_t *eph_pub = message;
    if (!validate_public_key_blob(eph_pub, X25519_KEY_BYTES) ||
        !x25519_shared_secret(box->private_key.data, eph_pub, shared)) {
        set_box_error(err, err_cch, L"X25519 key agreement failed.");
        goto cleanup;
    }
    if (!derive_message_key(shared, sizeof(shared),
                            eph_pub, X25519_KEY_BYTES,
                            box->public_key.data, (DWORD)box->public_key.len, key)) {
        set_box_error(err, err_cch, L"Message key derivation failed.");
        goto cleanup;
    }
    plain = (uint8_t *)box_alloc(cipher_len ? cipher_len : 1);
    if (!plain) {
        set_box_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (!aes_gcm_decrypt_raw(key, message, aad_len,
                             message + X25519_KEY_BYTES, MESSAGE_NONCE_BYTES,
                             message + aad_len, MESSAGE_TAG_BYTES,
                             message + aad_len + MESSAGE_TAG_BYTES, cipher_len,
                             plain)) {
        set_box_error(err, err_cch, L"AES-GCM authentication failed.");
        goto cleanup;
    }
    *out = plain;
    *out_len = cipher_len;
    plain = NULL;
    message_decrypted = TRUE;
cleanup:
    box_secure_free(plain, cipher_len);
    SecureZeroMemory(shared, sizeof(shared));
    SecureZeroMemory(key, sizeof(key));
    return message_decrypted;
}
