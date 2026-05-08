#include "app_tokenizer_prefs.h"

#include "app_groups.h"
#include "app_paths.h"
#include "app_profiles.h"
#include "app_shared.h"
#include "app_storage.h"

#include <strsafe.h>
#include <string.h>

#define TOKENIZER_PREFS_MAGIC 0x31504b54u
#define TOKENIZER_PREFS_VERSION 1u
#define TOKENIZER_PREFS_MAX_ENTRIES 512u
#define TOKENIZER_PREF_KEY_CCH 128

typedef struct TOKENIZER_PREF_ENTRY {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    WCHAR tokenizer_id[APP_TOKENIZER_ID_CCH];
} TOKENIZER_PREF_ENTRY;

static TOKENIZER_PREF_ENTRY g_tokenizer_prefs[TOKENIZER_PREFS_MAX_ENTRIES];
static DWORD g_tokenizer_pref_count;

static BOOL tokenizer_prefs_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, APP_TOKENIZER_PREFS_FILE_NAME);
}

static BOOL copy_tokenizer_id(WCHAR *dst, size_t dst_cch, const WCHAR *tokenizer_id) {
    if (!dst || dst_cch == 0 || !tokenizer_id || !tokenizer_id[0]) return FALSE;
    return SUCCEEDED(StringCchCopyW(dst, dst_cch, tokenizer_id));
}

static int find_pref_key(const WCHAR *key) {
    if (!key || !key[0]) return -1;
    for (DWORD idx = 0; idx < g_tokenizer_pref_count; ++idx) {
        if (wcscmp(g_tokenizer_prefs[idx].key, key) == 0) return (int)idx;
    }
    return -1;
}

static BOOL build_profile_key(int profile_index, WCHAR *key, size_t cch) {
    WCHAR profile_id[64] = L"";
    if (!profiles_get_id_copy(profile_index, profile_id, ARRAYSIZE(profile_id))) return FALSE;
    return SUCCEEDED(StringCchPrintfW(key, cch, L"P:%s", profile_id));
}

static BOOL build_group_recent_key(int group_index, WCHAR *key, size_t cch) {
    uint64_t group_id = 0;
    if (!app_groups_get_id(group_index, &group_id)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(key, cch, L"GR:%016llx", (unsigned long long)group_id));
}

static BOOL build_group_sender_key(int group_index, uint32_t sender_id, WCHAR *key, size_t cch) {
    uint64_t group_id = 0;
    if (!app_groups_get_id(group_index, &group_id) || sender_id == 0) return FALSE;
    return SUCCEEDED(StringCchPrintfW(key, cch, L"G:%016llx:%08lx",
                                      (unsigned long long)group_id,
                                      (unsigned long)sender_id));
}

static BOOL save_tokenizer_prefs(void) {
    WCHAR path[MAX_PATH];
    DWORD plain_len = 12 + g_tokenizer_pref_count * sizeof(TOKENIZER_PREF_ENTRY);
    BYTE *plain = NULL;
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL saved = FALSE;
    if (!tokenizer_prefs_path(path, ARRAYSIZE(path))) return FALSE;
    plain = (BYTE *)xalloc(plain_len ? plain_len : 1);
    if (!plain) return FALSE;
    DWORD *header = (DWORD *)plain;
    header[0] = TOKENIZER_PREFS_MAGIC;
    header[1] = TOKENIZER_PREFS_VERSION;
    header[2] = g_tokenizer_pref_count;
    if (g_tokenizer_pref_count) {
        CopyMemory(plain + 12, g_tokenizer_prefs,
                   g_tokenizer_pref_count * sizeof(TOKENIZER_PREF_ENTRY));
    }
    saved = dpapi_protect(plain, plain_len, &protected_blob, &protected_len) &&
            write_file_bytes_atomic(path, protected_blob, protected_len);
    secure_free(plain, plain_len);
    secure_free(protected_blob, protected_len);
    return saved;
}

static BOOL get_pref_by_key(const WCHAR *key, WCHAR *out, size_t cch) {
    int idx = find_pref_key(key);
    if (idx < 0 || !out || cch == 0) return FALSE;
    return SUCCEEDED(StringCchCopyW(out, cch, g_tokenizer_prefs[idx].tokenizer_id));
}

static BOOL set_pref_by_key(const WCHAR *key, const WCHAR *tokenizer_id) {
    if (!key || !key[0] || !tokenizer_id || !tokenizer_id[0]) return FALSE;
    int idx = find_pref_key(key);
    if (idx < 0) {
        if (g_tokenizer_pref_count >= TOKENIZER_PREFS_MAX_ENTRIES) return FALSE;
        idx = (int)g_tokenizer_pref_count++;
        if (FAILED(StringCchCopyW(g_tokenizer_prefs[idx].key, ARRAYSIZE(g_tokenizer_prefs[idx].key), key))) {
            --g_tokenizer_pref_count;
            return FALSE;
        }
    }
    if (!copy_tokenizer_id(g_tokenizer_prefs[idx].tokenizer_id,
                           ARRAYSIZE(g_tokenizer_prefs[idx].tokenizer_id),
                           tokenizer_id)) return FALSE;
    return save_tokenizer_prefs();
}

BOOL app_tokenizer_prefs_load(WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    ZeroMemory(g_tokenizer_prefs, sizeof(g_tokenizer_prefs));
    g_tokenizer_pref_count = 0;
    if (!tokenizer_prefs_path(path, ARRAYSIZE(path))) return TRUE;
    if (!read_file_bytes(path, &file, &file_len)) return TRUE;
    if (!dpapi_unprotect(file, file_len, &plain, &plain_len) ||
        plain_len < 12 ||
        ((DWORD *)plain)[0] != TOKENIZER_PREFS_MAGIC ||
        ((DWORD *)plain)[1] != TOKENIZER_PREFS_VERSION ||
        ((DWORD *)plain)[2] > TOKENIZER_PREFS_MAX_ENTRIES ||
        plain_len != 12 + ((DWORD *)plain)[2] * sizeof(TOKENIZER_PREF_ENTRY)) {
        secure_free(file, file_len);
        secure_free(plain, plain_len);
        (void)err;
        (void)err_cch;
        return TRUE;
    }
    g_tokenizer_pref_count = ((DWORD *)plain)[2];
    if (g_tokenizer_pref_count) {
        CopyMemory(g_tokenizer_prefs, plain + 12,
                   g_tokenizer_pref_count * sizeof(TOKENIZER_PREF_ENTRY));
        for (DWORD idx = 0; idx < g_tokenizer_pref_count; ++idx) {
            g_tokenizer_prefs[idx].key[TOKENIZER_PREF_KEY_CCH - 1] = L'\0';
            g_tokenizer_prefs[idx].tokenizer_id[APP_TOKENIZER_ID_CCH - 1] = L'\0';
        }
    }
    secure_free(file, file_len);
    secure_free(plain, plain_len);
    return TRUE;
}

void app_tokenizer_prefs_shutdown(void) {
    SecureZeroMemory(g_tokenizer_prefs, sizeof(g_tokenizer_prefs));
    g_tokenizer_pref_count = 0;
}

BOOL app_tokenizer_prefs_get_profile(int profile_index, WCHAR *out, size_t cch) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_profile_key(profile_index, key, ARRAYSIZE(key)) && get_pref_by_key(key, out, cch);
}

BOOL app_tokenizer_prefs_set_profile(int profile_index, const WCHAR *tokenizer_id) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_profile_key(profile_index, key, ARRAYSIZE(key)) && set_pref_by_key(key, tokenizer_id);
}

BOOL app_tokenizer_prefs_get_group_recent(int group_index, WCHAR *out, size_t cch) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_group_recent_key(group_index, key, ARRAYSIZE(key)) && get_pref_by_key(key, out, cch);
}

BOOL app_tokenizer_prefs_set_group_recent(int group_index, const WCHAR *tokenizer_id) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_group_recent_key(group_index, key, ARRAYSIZE(key)) && set_pref_by_key(key, tokenizer_id);
}

BOOL app_tokenizer_prefs_get_group_sender(int group_index, uint32_t sender_id, WCHAR *out, size_t cch) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_group_sender_key(group_index, sender_id, key, ARRAYSIZE(key)) && get_pref_by_key(key, out, cch);
}

BOOL app_tokenizer_prefs_set_group_sender(int group_index, uint32_t sender_id, const WCHAR *tokenizer_id) {
    WCHAR key[TOKENIZER_PREF_KEY_CCH];
    return build_group_sender_key(group_index, sender_id, key, ARRAYSIZE(key)) && set_pref_by_key(key, tokenizer_id);
}
