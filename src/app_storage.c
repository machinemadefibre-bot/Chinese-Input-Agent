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

#include "app_storage.h"
#include "app_shared.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <string.h>

#define MASTER_KEY_BYTES APP_STORAGE_MASTER_KEY_BYTES
#define LOCAL_BLOB_HEADER_BYTES APP_STORAGE_LOCAL_BLOB_HEADER_BYTES
#define LOCAL_BLOB_NONCE_BYTES APP_STORAGE_LOCAL_BLOB_NONCE_BYTES
#define LOCAL_BLOB_TAG_BYTES APP_STORAGE_LOCAL_BLOB_TAG_BYTES
BOOL dpapi_protect(const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len) {
    DATA_BLOB in_blob, out_blob;
    in_blob.pbData = (BYTE *)plain;
    in_blob.cbData = plain_len;
    ZeroMemory(&out_blob, sizeof(out_blob));
    if (!CryptProtectData(&in_blob, L"ChineseInputAgent local secret", NULL, NULL, NULL, 0, &out_blob)) {
        return FALSE;
    }
    BYTE *copy = (BYTE *)xalloc(out_blob.cbData);
    if (!copy) {
        LocalFree(out_blob.pbData);
        return FALSE;
    }
    CopyMemory(copy, out_blob.pbData, out_blob.cbData);
    *out = copy;
    *out_len = out_blob.cbData;
    LocalFree(out_blob.pbData);
    return TRUE;
}

BOOL dpapi_unprotect(const BYTE *blob, DWORD blob_len, BYTE **out, DWORD *out_len) {
    DATA_BLOB in_blob, out_blob;
    in_blob.pbData = (BYTE *)blob;
    in_blob.cbData = blob_len;
    ZeroMemory(&out_blob, sizeof(out_blob));
    if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        return FALSE;
    }
    BYTE *copy = (BYTE *)xalloc(out_blob.cbData);
    if (!copy) {
        LocalFree(out_blob.pbData);
        return FALSE;
    }
    CopyMemory(copy, out_blob.pbData, out_blob.cbData);
    *out = copy;
    *out_len = out_blob.cbData;
    LocalFree(out_blob.pbData);
    return TRUE;
}

BOOL local_aes_gcm_encrypt(const BYTE key[MASTER_KEY_BYTES], const BYTE *plain, DWORD plain_len,
                                  BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES;
    if (!key || (!plain && plain_len) || plain_len > 0xffffffffu - overhead) return FALSE;
    BOOL ok = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    BYTE *key_object = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;
    BYTE nonce[LOCAL_BLOB_NONCE_BYTES];
    BYTE *envelope = NULL;

    if (BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return FALSE;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (BYTE *)xalloc(obj_len);
    if (!key_object) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &hkey, key_object, obj_len, (PUCHAR)key, MASTER_KEY_BYTES, 0) < 0) goto cleanup;

    DWORD total = overhead + plain_len;
    envelope = (BYTE *)xalloc(total ? total : 1);
    if (!envelope) goto cleanup;
    CopyMemory(envelope, "CIA1", 4);
    envelope[4] = 1;
    envelope[5] = LOCAL_BLOB_NONCE_BYTES;
    envelope[6] = LOCAL_BLOB_TAG_BYTES;
    envelope[7] = 0;
    envelope[8] = (BYTE)(plain_len & 0xff);
    envelope[9] = (BYTE)((plain_len >> 8) & 0xff);
    envelope[10] = (BYTE)((plain_len >> 16) & 0xff);
    envelope[11] = (BYTE)((plain_len >> 24) & 0xff);
    CopyMemory(envelope + LOCAL_BLOB_HEADER_BYTES, nonce, LOCAL_BLOB_NONCE_BYTES);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = nonce;
    auth.cbNonce = LOCAL_BLOB_NONCE_BYTES;
    auth.pbAuthData = envelope;
    auth.cbAuthData = LOCAL_BLOB_HEADER_BYTES;
    auth.pbTag = envelope + LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES;
    auth.cbTag = LOCAL_BLOB_TAG_BYTES;

    if (BCryptEncrypt(hkey, (PUCHAR)plain, plain_len, &auth, NULL, 0,
                      envelope + LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES,
                      plain_len, &result, 0) < 0 || result != plain_len) goto cleanup;

    *out = envelope;
    *out_len = total;
    envelope = NULL;
    ok = TRUE;
cleanup:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(key_object, obj_len);
    secure_free(envelope, envelope ? total : 0);
    SecureZeroMemory(nonce, sizeof(nonce));
    return ok;
}

BOOL local_aes_gcm_decrypt(const BYTE key[MASTER_KEY_BYTES], const BYTE *envelope, DWORD envelope_len,
                                  BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    const DWORD overhead = LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES;
    if (!key || !envelope ||
        envelope_len < overhead ||
        memcmp(envelope, "CIA1", 4) != 0 ||
        envelope[4] != 1 ||
        envelope[5] != LOCAL_BLOB_NONCE_BYTES ||
        envelope[6] != LOCAL_BLOB_TAG_BYTES) return FALSE;
    DWORD cipher_len = (DWORD)envelope[8] |
                       ((DWORD)envelope[9] << 8) |
                       ((DWORD)envelope[10] << 16) |
                       ((DWORD)envelope[11] << 24);
    if (cipher_len > envelope_len - overhead || overhead + cipher_len != envelope_len) return FALSE;

    BOOL ok = FALSE;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    BYTE *key_object = NULL;
    BYTE *plain = NULL;
    DWORD obj_len = 0, cb = 0, result = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto cleanup;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto cleanup;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0) < 0) goto cleanup;
    key_object = (BYTE *)xalloc(obj_len);
    plain = (BYTE *)xalloc(cipher_len ? cipher_len : 1);
    if (!key_object || !plain) goto cleanup;
    if (BCryptGenerateSymmetricKey(alg, &hkey, key_object, obj_len, (PUCHAR)key, MASTER_KEY_BYTES, 0) < 0) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)(envelope + LOCAL_BLOB_HEADER_BYTES);
    auth.cbNonce = LOCAL_BLOB_NONCE_BYTES;
    auth.pbAuthData = (PUCHAR)envelope;
    auth.cbAuthData = LOCAL_BLOB_HEADER_BYTES;
    auth.pbTag = (PUCHAR)(envelope + LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES);
    auth.cbTag = LOCAL_BLOB_TAG_BYTES;

    if (BCryptDecrypt(hkey, (PUCHAR)(envelope + LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES),
                      cipher_len, &auth, NULL, 0, plain, cipher_len, &result, 0) < 0 || result != cipher_len) goto cleanup;
    *out = plain;
    *out_len = cipher_len;
    plain = NULL;
    ok = TRUE;
cleanup:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    secure_free(key_object, obj_len);
    secure_free(plain, cipher_len);
    return ok;
}

BOOL read_u32_mem(const BYTE **p, const BYTE *end, DWORD *out) {
    if (!p || !*p || !end || !out || *p > end) return FALSE;
    if ((size_t)(end - *p) < sizeof(DWORD)) return FALSE;
    CopyMemory(out, *p, sizeof(DWORD));
    *p += sizeof(DWORD);
    return TRUE;
}

BOOL read_bytes_mem(const BYTE **p, const BYTE *end, void *out, DWORD len) {
    if (!p || !*p || !end || (!out && len) || *p > end) return FALSE;
    if ((size_t)(end - *p) < len) return FALSE;
    CopyMemory(out, *p, len);
    *p += len;
    return TRUE;
}


