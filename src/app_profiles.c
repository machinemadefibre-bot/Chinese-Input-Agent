#include "app_profiles.h"
#include "app_paths.h"
#include "app_shared.h"
#include "app_storage.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <strsafe.h>
#include <string.h>

/* Persisted profile database format. Keep these values stable unless a migration is added. */
#define PROFILES_MAGIC 0x31505348u
#define PROFILES_VERSION 1u

struct KEY_PROFILE {
    WCHAR id[33];
    WCHAR name[128];
    BYTE *wrapped_key;
    DWORD wrapped_key_len;
    BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES];
    BOOL master_loaded;
};

static KEY_PROFILE g_profiles[APP_PROFILE_MAX_PROFILES];
static int g_profile_count;
static int g_active_profile = -1;

static const char PROFILE_KEY_LABEL_CRYPTO_STATE[] =
    "ChineseInputAgent crypto state protection v1";
static const char PROFILE_KEY_LABEL_PRIVATE_HISTORY[] =
    "ChineseInputAgent private chat history v1";

static BOOL get_profiles_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, APP_PROFILES_FILE_NAME);
}

static BOOL profile_get_state_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[80];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), APP_PROFILE_STATE_FILE_FORMAT, profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static BOOL profile_get_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), APP_PROFILE_ARCHIVE_FILE_FORMAT, profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static BOOL profile_get_legacy_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), APP_PROFILE_LEGACY_ARCHIVE_FILE_FORMAT, profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static void profiles_clear_profile(KEY_PROFILE *profile) {
    secure_free(profile->wrapped_key, profile->wrapped_key_len);
    SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
    ZeroMemory(profile, sizeof(*profile));
}

static void lock_profile_master(KEY_PROFILE *profile) {
    if (!profile) return;
    SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
    profile->master_loaded = FALSE;
}

static void lock_profile_master_if_inactive(int index) {
    if (index < 0 || index >= g_profile_count || index == g_active_profile) return;
    lock_profile_master(&g_profiles[index]);
}

void profiles_clear_all(void) {
    for (int i = 0; i < g_profile_count; ++i) profiles_clear_profile(&g_profiles[i]);
    g_profile_count = 0;
    g_active_profile = -1;
}

static BOOL generate_profile_id(WCHAR id[33]) {
    BYTE bytes[16];
    static const WCHAR hex[] = L"0123456789abcdef";
    if (BCryptGenRandom(NULL, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return FALSE;
    for (int i = 0; i < 16; ++i) {
        id[i * 2] = hex[(bytes[i] >> 4) & 0xf];
        id[i * 2 + 1] = hex[bytes[i] & 0xf];
    }
    id[32] = L'\0';
    SecureZeroMemory(bytes, sizeof(bytes));
    return TRUE;
}


static BOOL open_or_create_profile_wrap_key(NCRYPT_PROV_HANDLE *out_provider, NCRYPT_KEY_HANDLE *out_key, WCHAR *err, size_t err_cch) {
    *out_provider = 0;
    *out_key = 0;
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    WCHAR key_name[128];
    /* This label identifies the persisted Windows Hello wrapping key. Changing it would orphan existing profiles. */
    if (!get_scoped_wrap_key_name(L"Profile Wrap Key Hello v2", key_name, ARRAYSIZE(key_name))) {
        set_error(err, err_cch, L"\u65e0\u6cd5\u521b\u5efa Windows Hello \u5bc6\u94a5\u540d\u79f0\u3002");
        return FALSE;
    }
    SECURITY_STATUS ss = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0);
    if (ss != ERROR_SUCCESS) {
        set_error(err, err_cch, L"\u65e0\u6cd5\u6253\u5f00 Windows \u5bc6\u94a5\u5b58\u50a8\u63d0\u4f9b\u7a0b\u5e8f\u3002");
        return FALSE;
    }
    ss = NCryptOpenKey(provider, &key, key_name, 0, 0);
    if (ss != ERROR_SUCCESS) {
        ss = NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, key_name, 0, 0);
        if (ss != ERROR_SUCCESS) {
            NCryptFreeObject(provider);
            set_error(err, err_cch, L"\u65e0\u6cd5\u521b\u5efa Windows Hello \u4fdd\u62a4\u5bc6\u94a5\u3002");
            return FALSE;
        }
        DWORD key_bits = 2048;
        ss = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&key_bits, sizeof(key_bits), 0);
        if (ss != ERROR_SUCCESS) {
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            set_error(err, err_cch, L"\u65e0\u6cd5\u914d\u7f6e Windows Hello \u4fdd\u62a4\u5bc6\u94a5\u3002");
            return FALSE;
        }
        NCRYPT_UI_POLICY policy;
        ZeroMemory(&policy, sizeof(policy));
        policy.dwVersion = 1;
        policy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG | NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
        ss = NCryptSetProperty(key, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), 0);
        if (ss != ERROR_SUCCESS) {
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            set_error(err, err_cch, L"\u65e0\u6cd5\u542f\u7528 Windows Hello \u4fdd\u62a4\u3002");
            return FALSE;
        }
        ss = NCryptFinalizeKey(key, 0);
        if (ss != ERROR_SUCCESS) {
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            set_error(err, err_cch, L"Windows Hello \u4fdd\u62a4\u5bc6\u94a5\u521b\u5efa\u5931\u8d25\u3002");
            return FALSE;
        }
    }
    *out_provider = provider;
    *out_key = key;
    return TRUE;
}

static BOOL wrap_profile_master_key(const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES], BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!open_or_create_profile_wrap_key(&provider, &key, err, err_cch)) return FALSE;
    BCRYPT_OAEP_PADDING_INFO padding;
    ZeroMemory(&padding, sizeof(padding));
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD cb = 0;
    SECURITY_STATUS ss = NCryptEncrypt(key, (PBYTE)master_key, APP_PROFILE_MASTER_KEY_BYTES, &padding, NULL, 0, &cb, NCRYPT_PAD_OAEP_FLAG);
    if (ss != ERROR_SUCCESS || cb == 0) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        set_error(err, err_cch, L"\u4e3b\u5bc6\u94a5\u4fdd\u62a4\u5931\u8d25\u3002");
        return FALSE;
    }
    BYTE *wrapped_key = (BYTE *)xalloc(cb);
    if (!wrapped_key) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        set_error(err, err_cch, L"\u5185\u5b58\u4e0d\u8db3\u3002");
        return FALSE;
    }
    ss = NCryptEncrypt(key, (PBYTE)master_key, APP_PROFILE_MASTER_KEY_BYTES, &padding, wrapped_key, cb, &cb, NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (ss != ERROR_SUCCESS) {
        secure_free(wrapped_key, cb);
        set_error(err, err_cch, L"\u4e3b\u5bc6\u94a5\u4fdd\u62a4\u5931\u8d25\u3002");
        return FALSE;
    }
    *out = wrapped_key;
    *out_len = cb;
    return TRUE;
}

static BOOL unwrap_profile_master_key(KEY_PROFILE *profile, WCHAR *err, size_t err_cch) {
    if (profile->master_loaded) return TRUE;
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!open_or_create_profile_wrap_key(&provider, &key, err, err_cch)) return FALSE;
    BCRYPT_OAEP_PADDING_INFO padding;
    ZeroMemory(&padding, sizeof(padding));
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD cb = APP_PROFILE_MASTER_KEY_BYTES;
    SECURITY_STATUS ss = NCryptDecrypt(key, profile->wrapped_key, profile->wrapped_key_len, &padding,
                                       profile->master_key, APP_PROFILE_MASTER_KEY_BYTES, &cb, NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (ss != ERROR_SUCCESS || cb != APP_PROFILE_MASTER_KEY_BYTES) {
        SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
        set_error(err, err_cch, L"Windows Hello \u89e3\u9501\u5931\u8d25\u6216\u5df2\u53d6\u6d88\u3002");
        return FALSE;
    }
    profile->master_loaded = TRUE;
    return TRUE;
}

static BOOL hmac_sha256_segments(const BYTE *key, DWORD key_len,
                                 const BYTE **segments, const DWORD *segment_lens,
                                 size_t segment_count,
                                 BYTE out[APP_PROFILE_MASTER_KEY_BYTES]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD object_len = 0;
    DWORD result_len = 0;
    BOOL hmac_succeeded = FALSE;

    if (BCryptOpenAlgorithmProvider(&algorithm,
                                    BCRYPT_SHA256_ALGORITHM,
                                    NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) goto cleanup;
    if (BCryptGetProperty(algorithm,
                          BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&object_len,
                          sizeof(object_len),
                          &result_len,
                          0) != 0) goto cleanup;
    object = (BYTE *)xalloc(object_len);
    if (!object) goto cleanup;
    if (BCryptCreateHash(algorithm,
                         &hash,
                         object,
                         object_len,
                         (PUCHAR)key,
                         key_len,
                         0) != 0) goto cleanup;
    for (size_t idx = 0; idx < segment_count; ++idx) {
        if (segment_lens[idx] &&
            BCryptHashData(hash, (PUCHAR)segments[idx], segment_lens[idx], 0) != 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, out, APP_PROFILE_MASTER_KEY_BYTES, 0) != 0) goto cleanup;
    hmac_succeeded = TRUE;

cleanup:
    if (!hmac_succeeded) SecureZeroMemory(out, APP_PROFILE_MASTER_KEY_BYTES);
    if (hash) BCryptDestroyHash(hash);
    if (object) secure_free(object, object_len);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return hmac_succeeded;
}

static BOOL derive_profile_local_key(KEY_PROFILE *profile,
                                     const BYTE profile_root_key[APP_PROFILE_MASTER_KEY_BYTES],
                                     const char *label,
                                     BYTE out_key[APP_PROFILE_MASTER_KEY_BYTES],
                                     WCHAR *err,
                                     size_t err_cch) {
    char *profile_id_utf8 = NULL;
    if (!profile || !profile_root_key || !label || !out_key) {
        set_error(err, err_cch, L"Invalid profile key derivation request.");
        return FALSE;
    }
    if (!wide_to_utf8(profile->id, &profile_id_utf8, NULL)) {
        set_error(err, err_cch, L"Unable to encode profile id for key derivation.");
        return FALSE;
    }
    const BYTE *segments[2] = {
        (const BYTE *)label,
        (const BYTE *)profile_id_utf8
    };
    DWORD segment_lens[2] = {
        (DWORD)strlen(label),
        (DWORD)strlen(profile_id_utf8)
    };
    BOOL derived = hmac_sha256_segments(profile_root_key,
                                        APP_PROFILE_MASTER_KEY_BYTES,
                                        segments,
                                        segment_lens,
                                        ARRAYSIZE(segments),
                                        out_key);
    secure_free_str(profile_id_utf8);
    if (!derived) {
        set_error(err, err_cch, L"Profile key derivation failed.");
    }
    return derived;
}

BOOL profiles_save(void) {
    WCHAR path[MAX_PATH];
    if (!get_profiles_path(path, ARRAYSIZE(path))) return FALSE;
    STRB profile_db_plain = {0};
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL profile_db_written = FALSE;
    DWORD v = PROFILES_MAGIC;
    if (!strb_append_n(&profile_db_plain, (const char *)&v, sizeof(v))) goto cleanup;
    v = PROFILES_VERSION;
    if (!strb_append_n(&profile_db_plain, (const char *)&v, sizeof(v))) goto cleanup;
    v = (DWORD)g_profile_count;
    if (!strb_append_n(&profile_db_plain, (const char *)&v, sizeof(v))) goto cleanup;
    WCHAR active_id[33] = L"";
    if (g_active_profile >= 0 && g_active_profile < g_profile_count) {
        StringCchCopyW(active_id, ARRAYSIZE(active_id), g_profiles[g_active_profile].id);
    }
    if (!strb_append_n(&profile_db_plain, (const char *)active_id, sizeof(active_id))) goto cleanup;
    for (int profile_idx = 0; profile_idx < g_profile_count; ++profile_idx) {
        KEY_PROFILE *profile = &g_profiles[profile_idx];
        if (!strb_append_n(&profile_db_plain, (const char *)profile->id, sizeof(profile->id))) goto cleanup;
        if (!strb_append_n(&profile_db_plain, (const char *)profile->name, sizeof(profile->name))) goto cleanup;
        v = profile->wrapped_key_len;
        if (!strb_append_n(&profile_db_plain, (const char *)&v, sizeof(v))) goto cleanup;
        if (!strb_append_n(&profile_db_plain, (const char *)profile->wrapped_key, profile->wrapped_key_len)) goto cleanup;
    }
    profile_db_written = dpapi_protect((const BYTE *)profile_db_plain.data, (DWORD)profile_db_plain.len, &protected_blob, &protected_len) &&
                         write_file_bytes_atomic(path, protected_blob, protected_len);
cleanup:
    secure_free(protected_blob, protected_len);
    strb_secure_free(&profile_db_plain);
    return profile_db_written;
}

static BOOL profiles_create_from_master(const WCHAR *name, const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES],
                                        KEY_PROFILE *out, WCHAR *err, size_t err_cch) {
    if (!out || !master_key) {
        set_error(err, err_cch, L"Invalid profile creation request.");
        return FALSE;
    }
    ZeroMemory(out, sizeof(*out));
    if (!generate_profile_id(out->id)) {
        set_error(err, err_cch, L"Random generation failed while creating profile id.");
        return FALSE;
    }
    StringCchCopyW(out->name, ARRAYSIZE(out->name), name && name[0] ? name : L"");
    CopyMemory(out->master_key, master_key, APP_PROFILE_MASTER_KEY_BYTES);
    out->master_loaded = TRUE;
    if (!wrap_profile_master_key(master_key, &out->wrapped_key, &out->wrapped_key_len, err, err_cch)) {
        profiles_clear_profile(out);
        return FALSE;
    }
    return TRUE;
}

static BOOL create_default_profile(WCHAR *err, size_t err_cch) {
    if (g_profile_count >= APP_PROFILE_MAX_PROFILES) {
        set_error(err, err_cch, L"Profile limit reached.");
        return FALSE;
    }
    BYTE master[APP_PROFILE_MASTER_KEY_BYTES];
    if (BCryptGenRandom(NULL, master, sizeof(master), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        set_error(err, err_cch, L"Random generation failed while creating the default profile.");
        return FALSE;
    }
    BOOL default_profile_created = profiles_create_from_master(L"\u9ed8\u8ba4\u5bc6\u94a5", master, &g_profiles[0], err, err_cch);
    SecureZeroMemory(master, sizeof(master));
    if (!default_profile_created) return FALSE;
    g_profile_count = 1;
    g_active_profile = 0;
    BOOL profile_db_saved = profiles_save();
    SecureZeroMemory(g_profiles[0].master_key, sizeof(g_profiles[0].master_key));
    g_profiles[0].master_loaded = FALSE;
    return profile_db_saved;
}

BOOL profiles_load(WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!get_profiles_path(path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Profile data directory is not available.");
        return FALSE;
    }
    BOOL profile_file_exists = file_exists_w(path);
    BYTE *profile_blob = NULL;
    DWORD profile_blob_len = 0;
    if (!read_file_bytes(path, &profile_blob, &profile_blob_len)) {
        if (profile_file_exists) {
            set_error(err, err_cch, L"Profile database exists but could not be read.");
            return FALSE;
        }
        return create_default_profile(err, err_cch);
    }
    BYTE *profile_plain = NULL;
    DWORD profile_plain_len = 0;
    if (!dpapi_unprotect(profile_blob, profile_blob_len, &profile_plain, &profile_plain_len)) {
        secure_free(profile_blob, profile_blob_len);
        set_error(err, err_cch, L"Profile database could not be decrypted. The file may belong to another Windows account or be corrupted.");
        return FALSE;
    }
    const BYTE *cursor = profile_plain;
    const BYTE *plain_end = profile_plain + profile_plain_len;
    DWORD magic = 0, version = 0, count = 0;
    WCHAR active_id[33] = L"";
    BOOL header_parsed = read_u32_mem(&cursor, plain_end, &magic) &&
                         read_u32_mem(&cursor, plain_end, &version) &&
                         read_u32_mem(&cursor, plain_end, &count) &&
                         read_bytes_mem(&cursor, plain_end, active_id, sizeof(active_id)) &&
                         magic == PROFILES_MAGIC &&
                         version == PROFILES_VERSION &&
                         count <= APP_PROFILE_MAX_PROFILES;
    if (!header_parsed) {
        secure_free(profile_blob, profile_blob_len);
        secure_free(profile_plain, profile_plain_len);
        set_error(err, err_cch, L"Profile database header is invalid or unsupported.");
        return FALSE;
    }
    profiles_clear_all();
    BOOL records_parsed = TRUE;
    for (DWORD profile_idx = 0; profile_idx < count; ++profile_idx) {
        DWORD wrapped_len = 0;
        KEY_PROFILE *profile = &g_profiles[profile_idx];
        records_parsed = read_bytes_mem(&cursor, plain_end, profile->id, sizeof(profile->id)) &&
                         read_bytes_mem(&cursor, plain_end, profile->name, sizeof(profile->name)) &&
                         read_u32_mem(&cursor, plain_end, &wrapped_len) &&
                         wrapped_len > 0 && (size_t)(plain_end - cursor) >= wrapped_len;
        if (!records_parsed) break;
        profile->id[32] = L'\0';
        profile->name[ARRAYSIZE(profile->name) - 1] = L'\0';
        profile->wrapped_key = (BYTE *)xalloc(wrapped_len);
        if (!profile->wrapped_key) {
            records_parsed = FALSE;
            break;
        }
        profile->wrapped_key_len = wrapped_len;
        CopyMemory(profile->wrapped_key, cursor, wrapped_len);
        cursor += wrapped_len;
    }
    BOOL consumed_all_records = (cursor == plain_end);
    secure_free(profile_blob, profile_blob_len);
    secure_free(profile_plain, profile_plain_len);
    if (!records_parsed || !consumed_all_records) {
        profiles_clear_all();
        set_error(err, err_cch, L"Profile database is truncated or contains invalid records.");
        return FALSE;
    }
    g_profile_count = (int)count;
    g_active_profile = 0;
    for (int i = 0; i < g_profile_count; ++i) {
        if (wcscmp(g_profiles[i].id, active_id) == 0) {
            g_active_profile = i;
            break;
        }
    }
    if (g_profile_count == 0) return create_default_profile(err, err_cch);
    return TRUE;
}

BOOL profiles_activate(int index, WCHAR *err, size_t err_cch) {
    if (index < 0 || index >= g_profile_count) {
        set_error(err, err_cch, L"Requested profile index is out of range.");
        return FALSE;
    }
    if (!unwrap_profile_master_key(&g_profiles[index], err, err_cch)) return FALSE;
    g_active_profile = index;
    BOOL profile_saved = profiles_save();
    if (profile_saved) profiles_lock_inactive_masters();
    return profile_saved;
}

void profiles_lock_inactive_masters(void) {
    for (int profile_idx = 0; profile_idx < g_profile_count; ++profile_idx) {
        if (profile_idx == g_active_profile) continue;
        lock_profile_master(&g_profiles[profile_idx]);
    }
}


int profiles_count(void) {
    return g_profile_count;
}

int profiles_active_index(void) {
    return g_active_profile;
}

static KEY_PROFILE *profile_at(int index) {
    if (index < 0 || index >= g_profile_count) return NULL;
    return &g_profiles[index];
}

BOOL profiles_get_name_copy(int index, WCHAR *out, size_t cch) {
    KEY_PROFILE *profile = profile_at(index);
    if (!profile || !out || cch == 0) return FALSE;
    return SUCCEEDED(StringCchCopyW(out, cch, profile->name));
}

BOOL profiles_get_id_copy(int index, WCHAR *out, size_t cch) {
    KEY_PROFILE *profile = profile_at(index);
    if (!profile || !out || cch == 0) return FALSE;
    return SUCCEEDED(StringCchCopyW(out, cch, profile->id));
}

BOOL profiles_set_name(int index, const WCHAR *name, WCHAR *err, size_t err_cch) {
    KEY_PROFILE *profile = profile_at(index);
    if (!profile) {
        set_error(err, err_cch, L"Requested profile index is out of range.");
        return FALSE;
    }
    if (FAILED(StringCchCopyW(profile->name, ARRAYSIZE(profile->name), name ? name : L""))) {
        set_error(err, err_cch, L"Profile name is too long.");
        return FALSE;
    }
    return TRUE;
}

BOOL profiles_get_state_path_by_index(int index, WCHAR *path, size_t cch) {
    return profile_get_state_path(profile_at(index), path, cch);
}

BOOL profiles_get_archive_path_by_index(int index, WCHAR *path, size_t cch) {
    return profile_get_archive_path(profile_at(index), path, cch);
}

BOOL profiles_get_legacy_archive_path_by_index(int index, WCHAR *path, size_t cch) {
    return profile_get_legacy_archive_path(profile_at(index), path, cch);
}

BOOL profiles_open_crypto(int index, CRYPTO_BOX **out, WCHAR *err, size_t err_cch) {
    if (!out) {
        set_error(err, err_cch, L"Invalid crypto context output.");
        return FALSE;
    }
    *out = NULL;
    if (index < 0 || index >= g_profile_count) {
        set_error(err, err_cch, L"Requested profile index is out of range.");
        return FALSE;
    }
    KEY_PROFILE *profile = &g_profiles[index];
    BYTE state_key[APP_PROFILE_MASTER_KEY_BYTES];
    BOOL opened = FALSE;
    SecureZeroMemory(state_key, sizeof(state_key));
    if (!profile->master_loaded && !unwrap_profile_master_key(profile, err, err_cch)) return FALSE;
    WCHAR state_path[MAX_PATH];
    if (!profile_get_state_path(profile, state_path, ARRAYSIZE(state_path))) {
        set_error(err, err_cch, L"Profile state path is not available.");
        goto cleanup;
    }
    if (!derive_profile_local_key(profile,
                                  profile->master_key,
                                  PROFILE_KEY_LABEL_CRYPTO_STATE,
                                  state_key,
                                  err,
                                  err_cch)) {
        goto cleanup;
    }
    opened = crypto_box_open(state_key, state_path, out, err, err_cch);
    if (!opened && file_exists_w(state_path)) {
        opened = crypto_box_open_with_legacy_state_key(state_key,
                                                       profile->master_key,
                                                       state_path,
                                                       out,
                                                       err,
                                                       err_cch);
    }
cleanup:
    SecureZeroMemory(state_key, sizeof(state_key));
    lock_profile_master_if_inactive(index);
    return opened;
}

static BOOL profiles_with_derived_key(int index,
                                      const char *label,
                                      PROFILE_DERIVED_KEY_FN callback,
                                      void *user,
                                      WCHAR *err,
                                      size_t err_cch) {
    KEY_PROFILE *profile = profile_at(index);
    BYTE derived_key[APP_PROFILE_MASTER_KEY_BYTES];
    BOOL callback_succeeded = FALSE;
    SecureZeroMemory(derived_key, sizeof(derived_key));
    if (!profile || !label || !callback) {
        set_error(err, err_cch, L"Invalid profile derived-key request.");
        return FALSE;
    }
    if (!profile->master_loaded && !unwrap_profile_master_key(profile, err, err_cch)) return FALSE;
    if (derive_profile_local_key(profile, profile->master_key, label, derived_key, err, err_cch)) {
        callback_succeeded = callback(derived_key, user, err, err_cch);
    }
    SecureZeroMemory(derived_key, sizeof(derived_key));
    lock_profile_master_if_inactive(index);
    return callback_succeeded;
}

BOOL profiles_with_private_history_key(int index, PROFILE_DERIVED_KEY_FN callback, void *user,
                                       WCHAR *err, size_t err_cch) {
    return profiles_with_derived_key(index,
                                     PROFILE_KEY_LABEL_PRIVATE_HISTORY,
                                     callback,
                                     user,
                                     err,
                                     err_cch);
}

static BOOL profiles_append_imported(KEY_PROFILE *profile, int *index_out, WCHAR *err, size_t err_cch) {
    if (!profile || g_profile_count >= APP_PROFILE_MAX_PROFILES) {
        set_error(err, err_cch, L"\u5bc6\u94a5\u6570\u91cf\u5df2\u8fbe\u5230\u4e0a\u9650\u3002");
        return FALSE;
    }
    int index = g_profile_count++;
    g_profiles[index] = *profile;
    ZeroMemory(profile, sizeof(*profile));
    g_active_profile = index;
    if (index_out) *index_out = index;
    return TRUE;
}

BOOL profiles_append_from_master(const WCHAR *name, const BYTE master_key[APP_PROFILE_MASTER_KEY_BYTES],
                                 int *index_out, WCHAR *err, size_t err_cch) {
    KEY_PROFILE imported;
    if (!profiles_create_from_master(name, master_key, &imported, err, err_cch)) return FALSE;
    if (!profiles_append_imported(&imported, index_out, err, err_cch)) {
        profiles_clear_profile(&imported);
        return FALSE;
    }
    return TRUE;
}

void profiles_remove_at(int index) {
    if (index < 0 || index >= g_profile_count) return;
    profiles_clear_profile(&g_profiles[index]);
    for (int i = index; i < g_profile_count - 1; ++i) {
        g_profiles[i] = g_profiles[i + 1];
    }
    ZeroMemory(&g_profiles[g_profile_count - 1], sizeof(g_profiles[g_profile_count - 1]));
    --g_profile_count;
    if (g_active_profile == index) g_active_profile = -1;
    else if (g_active_profile > index) --g_active_profile;
}

void profiles_shutdown(void) {
    profiles_clear_all();
}
