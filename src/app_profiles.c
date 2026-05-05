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

#include "app_profiles.h"
#include "app_shared.h"
#include "app_storage.h"
#include "crypto_box.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <strsafe.h>

#define PROFILES_MAGIC 0x31505348u
#define PROFILES_VERSION 1u

static BYTE g_active_master_key[APP_PROFILE_MASTER_KEY_BYTES];
static KEY_PROFILE g_profiles[APP_PROFILE_MAX_PROFILES];
static int g_profile_count;
static int g_active_profile = -1;
static BOOL g_crypto_ready;

#define MASTER_KEY_BYTES APP_PROFILE_MASTER_KEY_BYTES
#define MAX_PROFILES APP_PROFILE_MAX_PROFILES
static BOOL get_profiles_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, L"profiles.dat");
}

BOOL profiles_get_state_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[80];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"state_%s.dat", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

BOOL profiles_get_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"archive_%s.dat", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

BOOL profiles_get_legacy_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"archive_%s.txt", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

void profiles_clear_profile(KEY_PROFILE *profile) {
    secure_free(profile->wrapped_key, profile->wrapped_key_len);
    SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
    ZeroMemory(profile, sizeof(*profile));
}

void profiles_clear_all(void) {
    for (int i = 0; i < g_profile_count; ++i) profiles_clear_profile(&g_profiles[i]);
    g_profile_count = 0;
    g_active_profile = -1;
    SecureZeroMemory(g_active_master_key, sizeof(g_active_master_key));
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

static BOOL wrap_profile_master_key(const BYTE master_key[MASTER_KEY_BYTES], BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!open_or_create_profile_wrap_key(&provider, &key, err, err_cch)) return FALSE;
    BCRYPT_OAEP_PADDING_INFO padding;
    ZeroMemory(&padding, sizeof(padding));
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD cb = 0;
    SECURITY_STATUS ss = NCryptEncrypt(key, (PBYTE)master_key, MASTER_KEY_BYTES, &padding, NULL, 0, &cb, NCRYPT_PAD_OAEP_FLAG);
    if (ss != ERROR_SUCCESS || cb == 0) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        set_error(err, err_cch, L"\u4e3b\u5bc6\u94a5\u4fdd\u62a4\u5931\u8d25\u3002");
        return FALSE;
    }
    BYTE *buf = (BYTE *)xalloc(cb);
    if (!buf) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        set_error(err, err_cch, L"\u5185\u5b58\u4e0d\u8db3\u3002");
        return FALSE;
    }
    ss = NCryptEncrypt(key, (PBYTE)master_key, MASTER_KEY_BYTES, &padding, buf, cb, &cb, NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (ss != ERROR_SUCCESS) {
        secure_free(buf, cb);
        set_error(err, err_cch, L"\u4e3b\u5bc6\u94a5\u4fdd\u62a4\u5931\u8d25\u3002");
        return FALSE;
    }
    *out = buf;
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
    DWORD cb = MASTER_KEY_BYTES;
    SECURITY_STATUS ss = NCryptDecrypt(key, profile->wrapped_key, profile->wrapped_key_len, &padding,
                                       profile->master_key, MASTER_KEY_BYTES, &cb, NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (ss != ERROR_SUCCESS || cb != MASTER_KEY_BYTES) {
        SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
        set_error(err, err_cch, L"Windows Hello \u89e3\u9501\u5931\u8d25\u6216\u5df2\u53d6\u6d88\u3002");
        return FALSE;
    }
    profile->master_loaded = TRUE;
    return TRUE;
}

BOOL profiles_save(void) {
    WCHAR path[MAX_PATH];
    if (!get_profiles_path(path, ARRAYSIZE(path))) return FALSE;
    STRB plain = {0};
    BOOL ok = TRUE;
    DWORD v = PROFILES_MAGIC;
    ok = ok && strb_append_n(&plain, (const char *)&v, sizeof(v));
    v = PROFILES_VERSION;
    ok = ok && strb_append_n(&plain, (const char *)&v, sizeof(v));
    v = (DWORD)g_profile_count;
    ok = ok && strb_append_n(&plain, (const char *)&v, sizeof(v));
    WCHAR active_id[33] = L"";
    if (g_active_profile >= 0 && g_active_profile < g_profile_count) {
        StringCchCopyW(active_id, ARRAYSIZE(active_id), g_profiles[g_active_profile].id);
    }
    ok = ok && strb_append_n(&plain, (const char *)active_id, sizeof(active_id));
    for (int i = 0; i < g_profile_count && ok; ++i) {
        ok = ok && strb_append_n(&plain, (const char *)g_profiles[i].id, sizeof(g_profiles[i].id));
        ok = ok && strb_append_n(&plain, (const char *)g_profiles[i].name, sizeof(g_profiles[i].name));
        v = g_profiles[i].wrapped_key_len;
        ok = ok && strb_append_n(&plain, (const char *)&v, sizeof(v));
        ok = ok && strb_append_n(&plain, (const char *)g_profiles[i].wrapped_key, g_profiles[i].wrapped_key_len);
    }
    if (ok) {
        BYTE *protected_blob = NULL;
        DWORD protected_len = 0;
        ok = dpapi_protect((const BYTE *)plain.data, (DWORD)plain.len, &protected_blob, &protected_len) &&
             write_file_bytes(path, protected_blob, protected_len);
        secure_free(protected_blob, protected_len);
    }
    strb_secure_free(&plain);
    return ok;
}

BOOL profiles_create_from_master(const WCHAR *name, const BYTE master_key[MASTER_KEY_BYTES], KEY_PROFILE *out, WCHAR *err, size_t err_cch) {
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
    CopyMemory(out->master_key, master_key, MASTER_KEY_BYTES);
    out->master_loaded = TRUE;
    if (!wrap_profile_master_key(master_key, &out->wrapped_key, &out->wrapped_key_len, err, err_cch)) {
        profiles_clear_profile(out);
        return FALSE;
    }
    return TRUE;
}

static BOOL create_default_profile(WCHAR *err, size_t err_cch) {
    if (g_profile_count >= MAX_PROFILES) {
        set_error(err, err_cch, L"Profile limit reached.");
        return FALSE;
    }
    BYTE master[MASTER_KEY_BYTES];
    if (BCryptGenRandom(NULL, master, sizeof(master), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        set_error(err, err_cch, L"Random generation failed while creating the default profile.");
        return FALSE;
    }
    BOOL ok = profiles_create_from_master(L"\u9ed8\u8ba4\u5bc6\u94a5", master, &g_profiles[0], err, err_cch);
    SecureZeroMemory(master, sizeof(master));
    if (!ok) return FALSE;
    g_profile_count = 1;
    g_active_profile = 0;
    ok = profiles_save();
    SecureZeroMemory(g_profiles[0].master_key, sizeof(g_profiles[0].master_key));
    g_profiles[0].master_loaded = FALSE;
    return ok;
}

BOOL profiles_load(WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!get_profiles_path(path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Profile data directory is not available.");
        return FALSE;
    }
    BOOL profile_file_exists = file_exists_w(path);
    BYTE *data = NULL;
    DWORD data_len = 0;
    if (!read_file_bytes(path, &data, &data_len)) {
        if (profile_file_exists) {
            set_error(err, err_cch, L"Profile database exists but could not be read.");
            return FALSE;
        }
        return create_default_profile(err, err_cch);
    }
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    if (!dpapi_unprotect(data, data_len, &plain, &plain_len)) {
        secure_free(data, data_len);
        set_error(err, err_cch, L"Profile database could not be decrypted. The file may belong to another Windows account or be corrupted.");
        return FALSE;
    }
    const BYTE *p = plain;
    const BYTE *end = plain + plain_len;
    DWORD magic = 0, version = 0, count = 0;
    WCHAR active_id[33] = L"";
    BOOL ok = read_u32_mem(&p, end, &magic) &&
              read_u32_mem(&p, end, &version) &&
              read_u32_mem(&p, end, &count) &&
              read_bytes_mem(&p, end, active_id, sizeof(active_id)) &&
              magic == PROFILES_MAGIC &&
              version == PROFILES_VERSION &&
              count <= MAX_PROFILES;
    if (!ok) {
        secure_free(data, data_len);
        secure_free(plain, plain_len);
        set_error(err, err_cch, L"Profile database header is invalid or unsupported.");
        return FALSE;
    }
    profiles_clear_all();
    for (DWORD i = 0; i < count; ++i) {
        DWORD wrapped_len = 0;
        ok = read_bytes_mem(&p, end, g_profiles[i].id, sizeof(g_profiles[i].id)) &&
             read_bytes_mem(&p, end, g_profiles[i].name, sizeof(g_profiles[i].name)) &&
             read_u32_mem(&p, end, &wrapped_len) &&
             wrapped_len > 0 && (size_t)(end - p) >= wrapped_len;
        if (!ok) break;
        g_profiles[i].id[32] = L'\0';
        g_profiles[i].name[ARRAYSIZE(g_profiles[i].name) - 1] = L'\0';
        g_profiles[i].wrapped_key = (BYTE *)xalloc(wrapped_len);
        if (!g_profiles[i].wrapped_key) {
            ok = FALSE;
            break;
        }
        g_profiles[i].wrapped_key_len = wrapped_len;
        CopyMemory(g_profiles[i].wrapped_key, p, wrapped_len);
        p += wrapped_len;
    }
    BOOL consumed_all = (p == end);
    secure_free(data, data_len);
    secure_free(plain, plain_len);
    if (!ok || !consumed_all) {
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
    if (g_crypto_ready) {
        crypto_box_shutdown();
        g_crypto_ready = FALSE;
    }
    WCHAR state_path[MAX_PATH];
    if (!profiles_get_state_path(&g_profiles[index], state_path, ARRAYSIZE(state_path))) {
        set_error(err, err_cch, L"Profile state path is not available.");
        return FALSE;
    }
    if (!crypto_box_init(g_profiles[index].master_key, state_path, err, err_cch)) return FALSE;
    g_crypto_ready = TRUE;
    g_active_profile = index;
    CopyMemory(g_active_master_key, g_profiles[index].master_key, MASTER_KEY_BYTES);
    profiles_save();
    return TRUE;
}


int profiles_count(void) {
    return g_profile_count;
}

int profiles_active_index(void) {
    return g_active_profile;
}

KEY_PROFILE *profiles_get(int index) {
    if (index < 0 || index >= g_profile_count) return NULL;
    return &g_profiles[index];
}

KEY_PROFILE *profiles_active(void) {
    return profiles_get(g_active_profile);
}

BOOL profiles_build_key_package(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (g_active_profile < 0 || g_active_profile >= g_profile_count) {
        set_error(err, err_cch, L"No active profile is selected.");
        return FALSE;
    }
    KEY_PROFILE *profile = &g_profiles[g_active_profile];
    if (!profile->master_loaded && !unwrap_profile_master_key(profile, err, err_cch)) return FALSE;
    return crypto_box_export_contact_package(out, out_len, err, err_cch);
}

BOOL profiles_append_imported(KEY_PROFILE *profile, int *index_out, WCHAR *err, size_t err_cch) {
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
    if (g_crypto_ready) {
        crypto_box_shutdown();
        g_crypto_ready = FALSE;
    }
    profiles_clear_all();
}
