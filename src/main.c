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

#include <windows.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <strsafe.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#include "crypto_box.h"
#include "app_shared.h"
#include "app_llm.h"
#include "app_storage.h"

#define APP_TITLE L"ChineseInputAgent"
#define APP_DIR_NAME L"ChineseInputAgent"

#define IDC_TEXTBOX 1001
#define IDC_ENCRYPT 1002
#define IDC_DECRYPT 1003
#define IDC_CLEAR 1004
#define IDC_KEY_SELECT 1006
#define IDC_KEY_TRANSFER 1007
#define IDC_TOPIC 1008
#define IDC_TEXT_OVERLAY 1009

#define IDC_NAME_EDIT 3001
#define IDC_KEY_TEXT 3002
#define IDC_KEY_IMPORT 3003
#define IDC_KEY_EXPORT 3004
#define IDC_KEY_OVERLAY 3005
#define WM_APP_WORK_UPDATE (WM_APP + 10)
#define WM_APP_WORK_DONE (WM_APP + 11)
#define WM_APP_WORK_ERROR (WM_APP + 12)
#define WM_APP_WORK_CANCELLED (WM_APP + 13)

#define MASTER_KEY_BYTES 32
#define PROFILES_MAGIC 0x31505348u
#define PROFILES_VERSION 1u
#define MAX_PROFILES 64
#define LOCAL_BLOB_HEADER_BYTES 12
#define LOCAL_BLOB_NONCE_BYTES 12
#define LOCAL_BLOB_TAG_BYTES 16
#define WORK_KIND_ENCRYPT 1
#define WORK_KIND_EXPORT_KEY 2
#define WORK_KIND_DECRYPT 3
#define WORK_KIND_IMPORT_KEY 4

#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif

static const WCHAR KEY_PACKAGE_PREFIX_START[] = L"\u4f60\u597d\uff0c\u6211\u662f\u7f16\u53f7";
static const WCHAR KEY_PACKAGE_PREFIX_END[] = L"\uff0c\u8fd9\u662f\u6211\u7684\u81ea\u6211\u4ecb\u7ecd\u3002";
static const WCHAR KEY_PACKAGE_TOPK_SEED[] = L"ChineseInputAgent key-exchange top-k payload v1";
static const WCHAR KEY_PACKAGE_TOPIC[] = L"\u81ea\u6211\u4ecb\u7ecd";

typedef struct KEY_PROFILE {
    WCHAR id[33];
    WCHAR name[128];
    BYTE *wrapped_key;
    DWORD wrapped_key_len;
    BYTE master_key[MASTER_KEY_BYTES];
    BOOL master_loaded;
} KEY_PROFILE;

typedef struct WORK_CTX {
    int kind;
    HWND owner;
    HWND target_textbox;
    WCHAR *input;
    WCHAR *topic;
    WCHAR *name;
} WORK_CTX;

typedef struct WORK_MESSAGE {
    int kind;
    HWND target_textbox;
    WCHAR *text;
} WORK_MESSAGE;

static HINSTANCE g_instance;
static HWND g_main_window;
static HWND g_textbox;
static HWND g_text_overlay;
static HWND g_key_select;
static HWND g_topic_edit;
static HWND g_key_window;
static HWND g_key_overlay;
static HFONT g_ui_font;
static BYTE g_active_master_key[MASTER_KEY_BYTES];
static KEY_PROFILE g_profiles[MAX_PROFILES];
static int g_profile_count;
static int g_active_profile = -1;
static BOOL g_crypto_ready;
static volatile LONG g_work_active;
static volatile LONG g_cancel_work;
static BOOL g_archive_mode;

static void set_control_font(HWND hwnd);
static WCHAR *get_window_text_alloc(HWND hwnd);
static WCHAR *dup_wide(const WCHAR *s);
static void show_error(HWND owner, const WCHAR *message);
static void do_key_transfer(HWND owner);
static void do_archive(HWND hwnd);
static void show_archive_for_active_profile(void);
static void leave_archive_mode(void);
static void refresh_main_mode_controls(void);
static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show);
static BOOL start_background_work(WORK_CTX *ctx);
static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit);
static DWORD WINAPI work_thread_proc(LPVOID param);
static BOOL get_message_topk_seed(WCHAR *seed, size_t seed_cch, BOOL prefer_remote, WCHAR *err, size_t err_cch);
static BOOL decrypt_clip_auto_profile(HWND hwnd, const WCHAR *clip, WCHAR **plain_w_out,
                                      WCHAR *err, size_t err_cch);
static void post_llm_stream_progress(HWND target_textbox, const WCHAR *partial, size_t done, size_t total, double tps);
static BOOL work_cancelled(void);
static void free_work_ctx(WORK_CTX *ctx);
static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

static BOOL get_profiles_path(WCHAR *path, size_t cch) {
    return get_app_file(path, cch, L"profiles.dat");
}

static BOOL get_profile_state_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[80];
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"state_%s.dat", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static BOOL get_profile_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"archive_%s.dat", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static BOOL get_profile_legacy_archive_path(const KEY_PROFILE *profile, WCHAR *path, size_t cch) {
    WCHAR name[96];
    if (!profile || !profile->id[0]) return FALSE;
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name), L"archive_%s.txt", profile->id))) return FALSE;
    return get_app_file(path, cch, name);
}

static void clear_profile(KEY_PROFILE *profile) {
    secure_free(profile->wrapped_key, profile->wrapped_key_len);
    SecureZeroMemory(profile->master_key, sizeof(profile->master_key));
    ZeroMemory(profile, sizeof(*profile));
}

static void clear_all_profiles(void) {
    for (int i = 0; i < g_profile_count; ++i) clear_profile(&g_profiles[i]);
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
        set_error(err, err_cch, L"");
        return FALSE;
    }
    return TRUE;
}

static BOOL get_message_topk_seed(WCHAR *seed, size_t seed_cch, BOOL prefer_remote, WCHAR *err, size_t err_cch) {
    BYTE *public_key = NULL;
    DWORD public_key_len = 0;
    WCHAR local_err[256] = L"";
    if (prefer_remote &&
        crypto_box_get_remote_public_key(&public_key, &public_key_len, local_err, ARRAYSIZE(local_err))) {
        BOOL ok = format_topk_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
        xfree(public_key);
        return ok;
    }
    if (!crypto_box_get_public_key(&public_key, &public_key_len, err, err_cch)) {
        return FALSE;
    }
    BOOL ok = format_topk_seed_from_public_key(seed, seed_cch, public_key, public_key_len, err, err_cch);
    xfree(public_key);
    return ok;
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

static BOOL save_profiles(void) {
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

static BOOL create_profile_from_master(const WCHAR *name, const BYTE master_key[MASTER_KEY_BYTES], KEY_PROFILE *out, WCHAR *err, size_t err_cch) {
    ZeroMemory(out, sizeof(*out));
    if (!generate_profile_id(out->id)) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    StringCchCopyW(out->name, ARRAYSIZE(out->name), name && name[0] ? name : L"");
    CopyMemory(out->master_key, master_key, MASTER_KEY_BYTES);
    out->master_loaded = TRUE;
    if (!wrap_profile_master_key(master_key, &out->wrapped_key, &out->wrapped_key_len, err, err_cch)) {
        clear_profile(out);
        return FALSE;
    }
    return TRUE;
}

static BOOL create_default_profile(WCHAR *err, size_t err_cch) {
    if (g_profile_count >= MAX_PROFILES) return FALSE;
    BYTE master[MASTER_KEY_BYTES];
    if (BCryptGenRandom(NULL, master, sizeof(master), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    BOOL ok = create_profile_from_master(L"\u9ed8\u8ba4\u5bc6\u94a5", master, &g_profiles[0], err, err_cch);
    SecureZeroMemory(master, sizeof(master));
    if (!ok) return FALSE;
    g_profile_count = 1;
    g_active_profile = 0;
    ok = save_profiles();
    SecureZeroMemory(g_profiles[0].master_key, sizeof(g_profiles[0].master_key));
    g_profiles[0].master_loaded = FALSE;
    return ok;
}

static BOOL load_profiles(WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!get_profiles_path(path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    BYTE *data = NULL;
    DWORD data_len = 0;
    if (!read_file_bytes(path, &data, &data_len)) {
        return create_default_profile(err, err_cch);
    }
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BOOL protected_file = dpapi_unprotect(data, data_len, &plain, &plain_len);
    const BYTE *source = protected_file ? plain : data;
    DWORD source_len = protected_file ? plain_len : data_len;
    const BYTE *p = source;
    const BYTE *end = source + source_len;
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
        set_error(err, err_cch, L"");
        return FALSE;
    }
    clear_all_profiles();
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
        clear_all_profiles();
        set_error(err, err_cch, L"");
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
    if (!protected_file) save_profiles();
    return TRUE;
}

static BOOL activate_profile(int index, HWND owner, WCHAR *err, size_t err_cch) {
    (void)owner;
    if (index < 0 || index >= g_profile_count) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    if (!unwrap_profile_master_key(&g_profiles[index], err, err_cch)) return FALSE;
    if (g_crypto_ready) {
        crypto_box_shutdown();
        g_crypto_ready = FALSE;
    }
    WCHAR state_path[MAX_PATH];
    if (!get_profile_state_path(&g_profiles[index], state_path, ARRAYSIZE(state_path))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    if (!crypto_box_init(g_profiles[index].master_key, state_path, err, err_cch)) return FALSE;
    g_crypto_ready = TRUE;
    g_active_profile = index;
    CopyMemory(g_active_master_key, g_profiles[index].master_key, MASTER_KEY_BYTES);
    save_profiles();
    if (g_key_select) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)index, 0);
    return TRUE;
}

static void refresh_key_combo(void) {
    if (!g_key_select) return;
    SendMessageW(g_key_select, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_profile_count; ++i) {
        SendMessageW(g_key_select, CB_ADDSTRING, 0, (LPARAM)g_profiles[i].name);
    }
    if (g_active_profile >= 0) SendMessageW(g_key_select, CB_SETCURSEL, (WPARAM)g_active_profile, 0);
}

static BOOL build_key_package(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (g_active_profile < 0 || g_active_profile >= g_profile_count) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    KEY_PROFILE *profile = &g_profiles[g_active_profile];
    if (!profile->master_loaded && !unwrap_profile_master_key(profile, err, err_cch)) return FALSE;
    return crypto_box_export_contact_package(out, out_len, err, err_cch);
}

static WCHAR *dup_wide(const WCHAR *s) {
    size_t len = wcslen(s ? s : L"");
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, s ? s : L"", (len + 1) * sizeof(WCHAR));
    return copy;
}

static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit) {
    WCHAR *topic = get_window_text_alloc(topic_edit);
    if (!topic) {
        show_error(owner, L"");
        return NULL;
    }
    if (topic[0] == L'\0') {
        xfree(topic);
        show_error(owner, L"");
        return NULL;
    }
    return topic;
}

static BOOL build_archive_record(const KEY_PROFILE *profile, const WCHAR *plain, WCHAR **out) {
    *out = NULL;
    SYSTEMTIME st;
    GetLocalTime(&st);
    WSTRB b = {0};
    if (!wstrb_appendf(&b, L"[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                       profile && profile->name[0] ? profile->name : L"\u672a\u547d\u540d") ||
        !wstrb_append(&b, plain ? plain : L"")) {
        wstrb_secure_free(&b);
        return FALSE;
    }
    size_t len = wcslen(plain ? plain : L"");
    if (len == 0 || (plain[len - 1] != L'\n' && plain[len - 1] != L'\r')) {
        if (!wstrb_append(&b, L"\r\n")) {
            wstrb_secure_free(&b);
            return FALSE;
        }
    }
    if (!wstrb_append(&b, L"\r\n")) {
        wstrb_secure_free(&b);
        return FALSE;
    }
    *out = b.data;
    return TRUE;
}

typedef struct ARCHIVE_BLOCK {
    WCHAR *text;
    WCHAR stamp[32];
    size_t index;
} ARCHIVE_BLOCK;

static const WCHAR *find_archive_record_end(const WCHAR *start, size_t *record_cch) {
    const WCHAR *crlf = wcsstr(start, L"\r\n\r\n");
    const WCHAR *lf = wcsstr(start, L"\n\n");
    const WCHAR *end = NULL;
    size_t sep = 0;
    if (crlf && (!lf || crlf < lf)) {
        end = crlf;
        sep = 4;
    } else if (lf) {
        end = lf;
        sep = 2;
    }
    if (end) {
        *record_cch = (size_t)(end - start) + sep;
        return start + *record_cch;
    }
    *record_cch = wcslen(start);
    return start + *record_cch;
}

static int compare_archive_blocks(const void *a, const void *b) {
    const ARCHIVE_BLOCK *aa = (const ARCHIVE_BLOCK *)a;
    const ARCHIVE_BLOCK *bb = (const ARCHIVE_BLOCK *)b;
    int cmp = wcscmp(aa->stamp, bb->stamp);
    if (cmp != 0) return cmp;
    if (aa->index < bb->index) return -1;
    if (aa->index > bb->index) return 1;
    return 0;
}

static BOOL archive_text_oldest_first(const WCHAR *text, WCHAR **out) {
    *out = NULL;
    if (!text || !text[0]) {
        *out = dup_wide(L"");
        return *out != NULL;
    }

    size_t count = 0;
    const WCHAR *p = text;
    while (*p) {
        size_t n = 0;
        const WCHAR *next = find_archive_record_end(p, &n);
        if (n > 0) ++count;
        p = next;
    }
    if (count == 0) {
        *out = dup_wide(L"");
        return *out != NULL;
    }

    ARCHIVE_BLOCK *blocks = (ARCHIVE_BLOCK *)xalloc(sizeof(ARCHIVE_BLOCK) * count);
    if (!blocks) return FALSE;

    BOOL ok = TRUE;
    p = text;
    size_t idx = 0;
    while (*p && idx < count) {
        size_t n = 0;
        const WCHAR *next = find_archive_record_end(p, &n);
        if (n > 0) {
            blocks[idx].text = (WCHAR *)xalloc((n + 1) * sizeof(WCHAR));
            if (!blocks[idx].text) {
                ok = FALSE;
                break;
            }
            CopyMemory(blocks[idx].text, p, n * sizeof(WCHAR));
            blocks[idx].text[n] = L'\0';
            blocks[idx].index = idx;
            if (n >= 21 && p[0] == L'[' && p[20] == L']') {
                CopyMemory(blocks[idx].stamp, p, 21 * sizeof(WCHAR));
                blocks[idx].stamp[21] = L'\0';
            } else {
                StringCchPrintfW(blocks[idx].stamp, ARRAYSIZE(blocks[idx].stamp), L"~%08zu", idx);
            }
            ++idx;
        }
        p = next;
    }

    if (ok) {
        qsort(blocks, count, sizeof(ARCHIVE_BLOCK), compare_archive_blocks);
        WSTRB b = {0};
        for (size_t i = 0; i < count && ok; ++i) {
            ok = wstrb_append(&b, blocks[i].text ? blocks[i].text : L"");
        }
        if (ok) {
            *out = b.data;
        } else {
            wstrb_secure_free(&b);
        }
    }

    for (size_t i = 0; i < count; ++i) secure_free_wide(blocks[i].text);
    xfree(blocks);
    return ok;
}

static BOOL append_archive_text(const KEY_PROFILE *profile, const WCHAR *plain, WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!get_profile_archive_path(profile, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    WCHAR legacy_path[MAX_PATH];
    get_profile_legacy_archive_path(profile, legacy_path, ARRAYSIZE(legacy_path));
    WCHAR *record = NULL;
    if (!build_archive_record(profile, plain, &record)) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    char *record_utf8 = NULL;
    int record_len = 0;
    if (!wide_to_utf8(record, &record_utf8, &record_len)) {
        secure_free_wide(record);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    secure_free_wide(record);

    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *old = NULL;
    DWORD old_len = 0;
    if (read_file_bytes(path, &file, &file_len)) {
        if (!local_aes_gcm_decrypt(profile->master_key, file, file_len, &old, &old_len)) {
            xfree(file);
            secure_free_str(record_utf8);
            set_error(err, err_cch, L"");
            return FALSE;
        }
        xfree(file);
    } else if (legacy_path[0]) {
        read_file_bytes(legacy_path, &old, &old_len);
    }

    DWORD total = old_len + (DWORD)record_len;
    BYTE *merged = (BYTE *)xalloc(total ? total : 1);
    if (!merged) {
        secure_free_str(record_utf8);
        secure_free(old, old_len);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    if (old && old_len) CopyMemory(merged, old, old_len);
    CopyMemory(merged + old_len, record_utf8, (DWORD)record_len);
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL ok = local_aes_gcm_encrypt(profile->master_key, merged, total, &protected_blob, &protected_len) &&
              write_file_bytes(path, protected_blob, protected_len);
    if (ok && legacy_path[0]) DeleteFileW(legacy_path);
    secure_free(protected_blob, protected_len);
    secure_free_str(record_utf8);
    secure_free(old, old_len);
    secure_free(merged, total);
    if (!ok) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    return TRUE;
}

static BOOL load_archive_text(const KEY_PROFILE *profile, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    WCHAR path[MAX_PATH];
    if (!get_profile_archive_path(profile, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    BYTE *data = NULL;
    DWORD data_len = 0;
    if (!read_file_bytes(path, &data, &data_len)) {
        WCHAR legacy_path[MAX_PATH];
        if (get_profile_legacy_archive_path(profile, legacy_path, ARRAYSIZE(legacy_path)) &&
            read_file_bytes(legacy_path, &data, &data_len)) {
            BOOL ok = utf8_to_wide_n((const char *)data, (int)data_len, out);
            if (ok) {
                WCHAR *ordered = NULL;
                if (archive_text_oldest_first(*out, &ordered)) {
                    secure_free_wide(*out);
                    *out = ordered;
                }
            }
            if (ok) {
                BYTE *protected_blob = NULL;
                DWORD protected_len = 0;
                if (local_aes_gcm_encrypt(profile->master_key, data, data_len, &protected_blob, &protected_len) &&
                    write_file_bytes(path, protected_blob, protected_len)) {
                    DeleteFileW(legacy_path);
                }
                secure_free(protected_blob, protected_len);
            }
            secure_free(data, data_len);
            if (!ok) set_error(err, err_cch, L"");
            return ok;
        }
        *out = dup_wide(L"");
        return *out != NULL;
    }
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BOOL ok = local_aes_gcm_decrypt(profile->master_key, data, data_len, &plain, &plain_len) &&
              utf8_to_wide_n((const char *)plain, (int)plain_len, out);
    if (ok) {
        WCHAR *ordered = NULL;
        if (archive_text_oldest_first(*out, &ordered)) {
            secure_free_wide(*out);
            *out = ordered;
        }
    }
    xfree(data);
    secure_free(plain, plain_len);
    if (!ok) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    return TRUE;
}

static void show_archive_for_active_profile(void) {
    if (!g_textbox || !IsWindow(g_textbox)) return;
    if (g_active_profile < 0 || g_active_profile >= g_profile_count) {
        SetWindowTextW(g_textbox, L"");
        return;
    }
    WCHAR err[256] = L"";
    WCHAR *archive = NULL;
    if (!load_archive_text(&g_profiles[g_active_profile], &archive, err, ARRAYSIZE(err))) {
        show_error(g_main_window, err[0] ? err : L"");
        return;
    }
    set_textbox_overlay(g_textbox, NULL, FALSE);
    SetWindowTextW(g_textbox, archive ? archive : L"");
    SendMessageW(g_textbox, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_textbox, EM_SCROLLCARET, 0, 0);
    secure_free_wide(archive);
}

static void refresh_main_mode_controls(void) {
    if (!g_main_window || !IsWindow(g_main_window)) return;
    BOOL busy = g_work_active != 0;
    HWND encrypt = GetDlgItem(g_main_window, IDC_ENCRYPT);
    HWND decrypt = GetDlgItem(g_main_window, IDC_DECRYPT);
    HWND archive = GetDlgItem(g_main_window, IDC_CLEAR);
    HWND key_transfer = GetDlgItem(g_main_window, IDC_KEY_TRANSFER);
    if (archive) SetWindowTextW(archive, g_archive_mode ? L"\u8fd4\u56de" : L"\u5f52\u6863");
    if (g_textbox) SendMessageW(g_textbox, EM_SETREADONLY, g_archive_mode ? TRUE : FALSE, 0);
    if (g_topic_edit) EnableWindow(g_topic_edit, !busy && !g_archive_mode);
    if (encrypt) {
        EnableWindow(encrypt, !g_archive_mode);
        SetWindowTextW(encrypt, busy && !g_archive_mode ? L"\u505c\u6b62" : L"\u52a0\u5bc6");
    }
    if (decrypt) EnableWindow(decrypt, !busy && !g_archive_mode);
    if (archive) EnableWindow(archive, !busy);
    if (g_key_select) EnableWindow(g_key_select, !busy);
    if (key_transfer) EnableWindow(key_transfer, !busy && !g_archive_mode);
}

static void enter_archive_mode(void) {
    g_archive_mode = TRUE;
    refresh_main_mode_controls();
    show_archive_for_active_profile();
}

static void leave_archive_mode(void) {
    g_archive_mode = FALSE;
    set_textbox_overlay(g_textbox, NULL, FALSE);
    if (g_textbox) SetWindowTextW(g_textbox, L"");
    refresh_main_mode_controls();
}

static void do_archive(HWND hwnd) {
    if (g_archive_mode) {
        leave_archive_mode();
        return;
    }
    if (g_active_profile < 0 || g_active_profile >= g_profile_count) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR *plain = get_window_text_alloc(g_textbox);
    if (!plain) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (plain[0] == L'\0') {
        secure_free_wide(plain);
        enter_archive_mode();
        return;
    }
    WCHAR err[256] = L"";
    if (!append_archive_text(&g_profiles[g_active_profile], plain, err, ARRAYSIZE(err))) {
        secure_free_wide(plain);
        show_error(hwnd, err[0] ? err : L"");
        return;
    }
    secure_free_wide(plain);
    enter_archive_mode();
}

static void set_busy_controls(BOOL busy) {
    BOOL enable = !busy;
    if (g_main_window && IsWindow(g_main_window)) {
        refresh_main_mode_controls();
    }
    if (g_key_window && IsWindow(g_key_window)) {
        EnableWindow(GetDlgItem(g_key_window, IDC_KEY_IMPORT), enable);
        EnableWindow(GetDlgItem(g_key_window, IDC_KEY_EXPORT), enable);
    }
}

static HWND overlay_for_textbox(HWND textbox) {
    if (textbox && textbox == g_textbox) return g_text_overlay;
    if (g_key_window && IsWindow(g_key_window) &&
        textbox == GetDlgItem(g_key_window, IDC_KEY_TEXT)) {
        return g_key_overlay;
    }
    return NULL;
}

static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show) {
    HWND overlay = overlay_for_textbox(textbox);
    if (!overlay || !IsWindow(overlay)) return;
    BOOL want_visible = show && text && text[0];
    SetWindowTextW(overlay, text ? text : L"");
    if (want_visible) {
        if (!IsWindowVisible(overlay)) ShowWindow(overlay, SW_SHOWNOACTIVATE);
        SetWindowPos(overlay, HWND_TOP, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        RedrawWindow(overlay, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
    } else if (IsWindowVisible(overlay)) {
        ShowWindow(overlay, SW_HIDE);
    }
}

static BOOL post_work_text_kind(UINT msg, HWND target_textbox, const WCHAR *text, int kind) {
    WORK_MESSAGE *m = (WORK_MESSAGE *)xalloc(sizeof(WORK_MESSAGE));
    if (!m) return FALSE;
    m->kind = kind;
    m->target_textbox = target_textbox;
    m->text = dup_wide(text ? text : L"");
    if (!m->text) {
        xfree(m);
        return FALSE;
    }
    if (!PostMessageW(g_main_window, msg, 0, (LPARAM)m)) {
        xfree(m->text);
        xfree(m);
        return FALSE;
    }
    return TRUE;
}

static BOOL post_work_text(UINT msg, HWND target_textbox, const WCHAR *text) {
    return post_work_text_kind(msg, target_textbox, text, 0);
}

static void post_llm_stream_progress(HWND target_textbox, const WCHAR *partial, size_t done, size_t total, double tps) {
    const size_t bar_width = 24;
    if (total == 0) total = 1;
    if (done > total) done = total;
    size_t filled = (done * bar_width) / total;
    WSTRB b = {0};
    if (!wstrb_append(&b, L"\u751f\u6210\u8fdb\u5ea6 [")) goto cleanup;
    for (size_t i = 0; i < bar_width; ++i) {
        if (!wstrb_append_char(&b, i < filled ? L'#' : L'-')) goto cleanup;
    }
    if (tps > 0.0) {
        if (!wstrb_appendf(&b, L"] %zu/%zu  %.1f token/s\r\n\r\n", done, total, tps)) goto cleanup;
    } else {
        if (!wstrb_appendf(&b, L"] %zu/%zu  -- token/s\r\n\r\n", done, total)) goto cleanup;
    }
    if (!wstrb_append(&b, partial ? partial : L"")) goto cleanup;
    post_work_text(WM_APP_WORK_UPDATE, target_textbox, b.data ? b.data : L"");
cleanup:
    wstrb_free(&b);
}

static BOOL start_background_work(WORK_CTX *ctx) {
    if (InterlockedCompareExchange(&g_work_active, 1, 0) != 0) {
        show_error(ctx->owner, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    InterlockedExchange(&g_cancel_work, 0);
    set_busy_controls(TRUE);
    HANDLE thread = CreateThread(NULL, 0, work_thread_proc, ctx, 0, NULL);
    if (!thread) {
        InterlockedExchange(&g_work_active, 0);
        InterlockedExchange(&g_cancel_work, 0);
        set_busy_controls(FALSE);
        show_error(ctx->owner, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return FALSE;
    }
    CloseHandle(thread);
    return TRUE;
}

static void do_export_key(HWND hwnd, HWND target_textbox) {
    WORK_CTX *ctx = (WORK_CTX *)xalloc(sizeof(WORK_CTX));
    if (!ctx) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->kind = WORK_KIND_EXPORT_KEY;
    ctx->owner = hwnd;
    ctx->target_textbox = target_textbox;
    ctx->topic = NULL;
    set_textbox_overlay(target_textbox, L"\u6b63\u5728\u751f\u6210\u8054\u7cfb\u4eba\u516c\u94a5\u5305\u8f7d\u4f53\u6587\u672c\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(target_textbox, L"");
    if (!start_background_work(ctx)) {
        set_textbox_overlay(target_textbox, NULL, FALSE);
        xfree(ctx);
    }
}

typedef struct NAME_PROMPT_STATE {
    BOOL done;
    BOOL ok;
    WCHAR name[128];
} NAME_PROMPT_STATE;

static LRESULT CALLBACK NamePromptWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    NAME_PROMPT_STATE *state = (NAME_PROMPT_STATE *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lparam;
        state = (NAME_PROMPT_STATE *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);
        HWND label = CreateWindowExW(0, L"STATIC", L"\u7ed9\u5bfc\u5165\u7684\u5bc6\u94a5\u547d\u540d", WS_CHILD | WS_VISIBLE,
                                     14, 16, 260, 24, hwnd, NULL, g_instance, NULL);
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", state->name,
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                    14, 46, 300, 28, hwnd, (HMENU)IDC_NAME_EDIT, g_instance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, ARRAYSIZE(state->name) - 1, 0);
        HWND ok = CreateWindowExW(0, L"BUTTON", L"\u786e\u5b9a", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                  146, 88, 80, 32, hwnd, (HMENU)IDOK, g_instance, NULL);
        HWND cancel = CreateWindowExW(0, L"BUTTON", L"\u53d6\u6d88", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      234, 88, 80, 32, hwnd, (HMENU)IDCANCEL, g_instance, NULL);
        HWND controls[] = { label, edit, ok, cancel };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        SetFocus(edit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == IDOK) {
            GetWindowTextW(GetDlgItem(hwnd, IDC_NAME_EDIT), state->name, ARRAYSIZE(state->name));
            if (state->name[0] == L'\0') StringCchCopyW(state->name, ARRAYSIZE(state->name), L"\u5bfc\u5165\u5bc6\u94a5");
            state->ok = TRUE;
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wparam) == IDCANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        InterlockedExchange(&g_cancel_work, 1);
        shutdown_local_llm_worker();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (state) state->done = TRUE;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL prompt_key_name(HWND owner, WCHAR *name, size_t cch) {
    NAME_PROMPT_STATE state;
    ZeroMemory(&state, sizeof(state));
    StringCchCopyW(state.name, ARRAYSIZE(state.name), L"\u5bfc\u5165\u5bc6\u94a5");
    HWND win = CreateWindowExW(WS_EX_TOOLWINDOW, L"ChineseInputAgentNamePrompt",
                               L"\u5bfc\u5165\u5bc6\u94a5", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                               CW_USEDEFAULT, CW_USEDEFAULT, 350, 170,
                               owner, NULL, g_instance, &state);
    if (!win) return FALSE;
    EnableWindow(owner, FALSE);
    ShowWindow(win, SW_SHOW);
    MSG msg;
    while (!state.done && GetMessageW(&msg, NULL, 0, 0)) {
        if (IsDialogMessageW(win, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
    if (!state.ok) return FALSE;
    StringCchCopyW(name, cch, state.name);
    return TRUE;
}

static void do_import_key(HWND hwnd, HWND source_textbox) {
    WCHAR *text = get_window_text_alloc(source_textbox);
    if (!text) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR *start = wcsstr(text, KEY_PACKAGE_PREFIX_START);
    if (!start) {
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR *body = wcsstr(start, KEY_PACKAGE_PREFIX_END);
    if (!body) {
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    body += wcslen(KEY_PACKAGE_PREFIX_END);
    if (g_profile_count >= MAX_PROFILES) {
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    WCHAR name[128];
    if (!prompt_key_name(hwnd, name, ARRAYSIZE(name))) {
        xfree(text);
        return;
    }

    WORK_CTX *ctx = (WORK_CTX *)xalloc(sizeof(WORK_CTX));
    if (!ctx) {
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->kind = WORK_KIND_IMPORT_KEY;
    ctx->owner = hwnd;
    ctx->target_textbox = source_textbox;
    ctx->input = dup_wide(body);
    ctx->name = dup_wide(name);
    if (!ctx->input || !ctx->name) {
        free_work_ctx(ctx);
        xfree(text);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }

    set_textbox_overlay(source_textbox, L"\u6b63\u5728\u89e3\u6790\u8054\u7cfb\u4eba\u516c\u94a5\u5305\u8f7d\u4f53\u6587\u672c\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(source_textbox, L"");
    if (!start_background_work(ctx)) {
        set_textbox_overlay(source_textbox, NULL, FALSE);
        SetWindowTextW(source_textbox, text);
        free_work_ctx(ctx);
    }
    xfree(text);
}

static WCHAR *get_window_text_alloc(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    WCHAR *buf = (WCHAR *)xalloc(((SIZE_T)len + 1) * sizeof(WCHAR));
    if (!buf) return NULL;
    GetWindowTextW(hwnd, buf, len + 1);
    return buf;
}

static BOOL get_clipboard_text(HWND owner, WCHAR **out) {
    *out = NULL;
    if (!OpenClipboard(owner)) return FALSE;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) {
        CloseClipboard();
        return FALSE;
    }
    WCHAR *src = (WCHAR *)GlobalLock(h);
    if (!src) {
        CloseClipboard();
        return FALSE;
    }
    size_t len = wcslen(src);
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, src, (len + 1) * sizeof(WCHAR));
    GlobalUnlock(h);
    CloseClipboard();
    *out = copy;
    return copy != NULL;
}

static void show_error(HWND owner, const WCHAR *message) {
    MessageBoxW(owner, message, APP_TITLE, MB_ICONERROR | MB_OK);
}

static BOOL work_cancelled(void) {
    return InterlockedCompareExchange(&g_cancel_work, 0, 0) != 0;
}

static void free_work_ctx(WORK_CTX *ctx) {
    if (!ctx) return;
    secure_free_wide(ctx->input);
    xfree(ctx->topic);
    xfree(ctx->name);
    xfree(ctx);
}

static void post_worker_error(HWND target, const WCHAR *message) {
    post_work_text(WM_APP_WORK_ERROR, target, message ? message : L"\u540e\u53f0\u4efb\u52a1\u5931\u8d25\u3002");
}

static BOOL worker_encrypt(WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    size_t plain_chars = ctx->input ? wcslen(ctx->input) : 0;
    if (plain_chars > (((DWORD)0xffffffffu) / sizeof(WCHAR))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    DWORD plain_len = (DWORD)(plain_chars * sizeof(WCHAR));

    BYTE *sealed = NULL;
    DWORD sealed_len = 0;
    if (!crypto_box_encrypt((const BYTE *)ctx->input, plain_len, &sealed, &sealed_len, err, err_cch)) {
        return FALSE;
    }

    WCHAR seed[256] = L"";
    if (!get_message_topk_seed(seed, ARRAYSIZE(seed), TRUE, err, err_cch)) {
        secure_free(sealed, sealed_len);
        return FALSE;
    }

    BOOL ok = local_topk_encode_payload(sealed, sealed_len, seed, ctx->topic, NULL, -1, ctx->target_textbox, out, err, err_cch);
    secure_free(sealed, sealed_len);
    return ok;
}

static BOOL worker_export_key(WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    if (!build_key_package(&pkg, &pkg_len, err, err_cch)) return FALSE;

    WCHAR fingerprint[32] = L"";
    if (!crypto_box_get_public_fingerprint(fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    WSTRB prefix = {0};
    if (!wstrb_append(&prefix, KEY_PACKAGE_PREFIX_START) ||
        !wstrb_append(&prefix, fingerprint) ||
        !wstrb_append(&prefix, KEY_PACKAGE_PREFIX_END)) {
        secure_free(pkg, pkg_len);
        wstrb_free(&prefix);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    BOOL ok = local_topk_encode_payload(pkg, pkg_len, KEY_PACKAGE_TOPK_SEED, KEY_PACKAGE_TOPIC,
                                        prefix.data, 0, ctx->target_textbox, out, err, err_cch);
    wstrb_free(&prefix);
    secure_free(pkg, pkg_len);
    return ok;
}

static BOOL worker_import_key(WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    if (!local_topk_decode_payload(ctx->input, KEY_PACKAGE_TOPK_SEED, &pkg, &pkg_len, err, err_cch)) {
        return FALSE;
    }
    WCHAR fingerprint[32] = L"";
    if (!crypto_box_contact_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    if (g_profile_count >= MAX_PROFILES) {
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
    if (!create_profile_from_master(ctx->name, master, &imported, err, err_cch)) {
        SecureZeroMemory(master, sizeof(master));
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    SecureZeroMemory(master, sizeof(master));

    int original = g_active_profile;
    int imported_index = g_profile_count;
    g_profiles[g_profile_count++] = imported;
    g_active_profile = imported_index;
    BOOL ok = save_profiles() &&
              activate_profile(imported_index, ctx->owner, err, err_cch) &&
              crypto_box_import_contact_package(pkg, pkg_len, err, err_cch) &&
              save_profiles();
    secure_free(pkg, pkg_len);
    if (!ok) {
        WCHAR state_path[MAX_PATH];
        if (get_profile_state_path(&g_profiles[imported_index], state_path, ARRAYSIZE(state_path))) {
            secure_delete_file(state_path);
        }
        clear_profile(&g_profiles[imported_index]);
        g_profile_count--;
        g_active_profile = -1;
        if (original >= 0 && original < g_profile_count) {
            WCHAR restore_err[256] = L"";
            activate_profile(original, ctx->owner, restore_err, ARRAYSIZE(restore_err));
        }
        return FALSE;
    }

    WSTRB msg = {0};
    if (!wstrb_appendf(&msg, L"\u8054\u7cfb\u4eba\u516c\u94a5\u5df2\u5bfc\u5165\u3002\r\n\r\n\u8bf7\u81ea\u884c\u786e\u8ba4\u6307\u7eb9\u662f\u5426\u4e0e\u660e\u6587\u76f8\u540c\uff1a%s", fingerprint)) {
        set_error(err, err_cch, L"\u5bfc\u5165\u7ed3\u679c\u6d88\u606f\u6784\u9020\u5931\u8d25\u3002");
        return FALSE;
    }
    *out = msg.data;
    return TRUE;
}
static BOOL worker_decrypt(WORK_CTX *ctx, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!ctx || !ctx->input || !ctx->input[0]) {
        set_error(err, err_cch, L"");
        return FALSE;
    }
    return decrypt_clip_auto_profile(ctx->owner, ctx->input, out, err, err_cch);
}

static DWORD WINAPI work_thread_proc(LPVOID param) {
    WORK_CTX *ctx = (WORK_CTX *)param;
    WCHAR *result = NULL;
    WCHAR err[256] = L"";
    BOOL ok = FALSE;

    if (ctx->kind == WORK_KIND_ENCRYPT) {
        ok = worker_encrypt(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == WORK_KIND_EXPORT_KEY) {
        ok = worker_export_key(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == WORK_KIND_IMPORT_KEY) {
        ok = worker_import_key(ctx, &result, err, ARRAYSIZE(err));
    } else if (ctx->kind == WORK_KIND_DECRYPT) {
        ok = worker_decrypt(ctx, &result, err, ARRAYSIZE(err));
    } else {
        set_error(err, ARRAYSIZE(err), L"");
    }

    if (ok && !work_cancelled()) {
        post_work_text_kind(WM_APP_WORK_DONE, ctx->target_textbox, result ? result : L"", ctx->kind);
    } else if (work_cancelled()) {
        post_work_text_kind(WM_APP_WORK_CANCELLED, ctx->target_textbox, L"", ctx->kind);
    } else {
        post_work_text_kind(WM_APP_WORK_ERROR, ctx->target_textbox, err[0] ? err : L"\u540e\u53f0\u4efb\u52a1\u5931\u8d25\u3002", ctx->kind);
    }
    secure_free_wide(result);
    free_work_ctx(ctx);
    return 0;
}

static void do_encrypt(HWND hwnd) {
    WCHAR *plain_w = get_window_text_alloc(g_textbox);
    if (!plain_w) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (plain_w[0] == L'\0') {
        secure_free_wide(plain_w);
        return;
    }
    WCHAR *topic = get_required_topic_text(hwnd, g_topic_edit);
    if (!topic) {
        secure_free_wide(plain_w);
        return;
    }
    WORK_CTX *ctx = (WORK_CTX *)xalloc(sizeof(WORK_CTX));
    if (!ctx) {
        secure_free_wide(plain_w);
        xfree(topic);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->kind = WORK_KIND_ENCRYPT;
    ctx->owner = hwnd;
    ctx->target_textbox = g_textbox;
    ctx->input = plain_w;
    ctx->topic = topic;
    set_textbox_overlay(g_textbox, L"\u6b63\u5728\u52a0\u5bc6\u5e76\u6df7\u6dc6\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    SetWindowTextW(g_textbox, L"");
    if (!start_background_work(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        SetWindowTextW(g_textbox, plain_w);
        secure_free_wide(plain_w);
        xfree(topic);
        xfree(ctx);
    }
}

static void do_decrypt(HWND hwnd) {
    WCHAR *clip = NULL;
    if (!get_clipboard_text(hwnd, &clip)) {
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    if (clip[0] == L'\0') {
        xfree(clip);
        return;
    }
    WORK_CTX *ctx = (WORK_CTX *)xalloc(sizeof(WORK_CTX));
    if (!ctx) {
        xfree(clip);
        show_error(hwnd, L"\u64cd\u4f5c\u5931\u8d25\u3002");
        return;
    }
    ctx->kind = WORK_KIND_DECRYPT;
    ctx->owner = hwnd;
    ctx->target_textbox = g_textbox;
    ctx->input = clip;
    ctx->topic = NULL;
    set_textbox_overlay(g_textbox, L"\u6b63\u5728\u4ece\u526a\u8d34\u677f\u89e3\u5bc6\uff0c\u8bf7\u7a0d\u5019...", TRUE);
    if (!start_background_work(ctx)) {
        set_textbox_overlay(g_textbox, NULL, FALSE);
        xfree(clip);
        xfree(ctx);
    }
}

static BOOL decrypt_sealed_with_current_profile(const BYTE *sealed, DWORD sealed_len,
                                                WCHAR **plain_w_out, WCHAR *err, size_t err_cch) {
    *plain_w_out = NULL;
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    if (!crypto_box_decrypt(sealed, sealed_len, &plain, &plain_len, err, err_cch)) {
        return FALSE;
    }

    if ((plain_len % sizeof(WCHAR)) != 0) {
        secure_free(plain, plain_len);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    size_t plain_chars = plain_len / sizeof(WCHAR);
    WCHAR *plain_w = (WCHAR *)xalloc((plain_chars + 1) * sizeof(WCHAR));
    if (!plain_w) {
        secure_free(plain, plain_len);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    CopyMemory(plain_w, plain, plain_len);
    plain_w[plain_chars] = L'\0';
    secure_free(plain, plain_len);
    *plain_w_out = plain_w;
    return TRUE;
}

static BOOL decrypt_clip_auto_profile(HWND hwnd, const WCHAR *clip, WCHAR **plain_w_out,
                                      WCHAR *err, size_t err_cch) {
    *plain_w_out = NULL;
    int original = g_active_profile;
    WCHAR last_err[768] = L"";
    WCHAR local_decode_err[768] = L"";
    BOOL saw_local_decode_error = FALSE;
    BOOL saw_local_payload = FALSE;

    for (int pass = 0; pass < g_profile_count; ++pass) {
        if (work_cancelled()) {
            set_error(err, err_cch, L"");
            return FALSE;
        }
        int index;
        if (original >= 0 && original < g_profile_count && pass == g_profile_count - 1) {
            index = original;
        } else {
            index = pass;
            if (original >= 0 && original < g_profile_count && index >= original) index++;
        }
        if (index < 0 || index >= g_profile_count) continue;

        WCHAR local_err[768] = L"";
        if (index != g_active_profile &&
            !activate_profile(index, hwnd, local_err, ARRAYSIZE(local_err))) {
            StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err[0] ? local_err : L"");
            continue;
        }

        WCHAR *plain_w = NULL;
        WCHAR seed[256] = L"";
        BYTE *local_sealed = NULL;
        DWORD local_sealed_len = 0;
        BOOL have_local_payload = FALSE;
        if (get_message_topk_seed(seed, ARRAYSIZE(seed), FALSE, local_err, ARRAYSIZE(local_err))) {
            have_local_payload = local_topk_decode_payload(clip, seed, &local_sealed, &local_sealed_len,
                                                          local_decode_err, ARRAYSIZE(local_decode_err));
            if (!have_local_payload) {
                if (local_decode_err[0]) {
                    saw_local_decode_error = TRUE;
                    StringCchCopyW(local_err, ARRAYSIZE(local_err), local_decode_err);
                } else {
                    StringCchCopyW(local_err, ARRAYSIZE(local_err), L"");
                }
            }
        }
        if (have_local_payload) saw_local_payload = TRUE;
        BOOL ok = have_local_payload &&
            decrypt_sealed_with_current_profile(local_sealed, local_sealed_len, &plain_w, local_err, ARRAYSIZE(local_err));
        secure_free(local_sealed, local_sealed_len);
        if (ok) {
            *plain_w_out = plain_w;
            return TRUE;
        }
        StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err[0] ? local_err : L"");
    }

    if (original >= 0 && original < g_profile_count) {
        WCHAR restore_err[256] = L"";
        activate_profile(original, hwnd, restore_err, ARRAYSIZE(restore_err));
    }

    if (saw_local_decode_error && !saw_local_payload && local_decode_err[0]) {
        set_error(err, err_cch,
                  L"",
                  local_decode_err);
    } else if (last_err[0]) {
        set_error(err, err_cch, L"\u6ca1\u6709\u627e\u5230\u80fd\u89e3\u5bc6\u8fd9\u6bb5\u6587\u5b57\u7684\u5bc6\u94a5\u3002\u6700\u540e\u9519\u8bef\uff1a%s", last_err);
    } else {
        set_error(err, err_cch, L"");
    }
    return FALSE;
}

static void layout_main(HWND hwnd, int width, int height) {
    int margin = 12;
    int gap = 8;
    int combo_h = 30;
    int topic_h = 30;
    int button_h = 38;
    int topic_y = margin + combo_h + gap;
    int edit_y = topic_y + topic_h + gap;
    int edit_h = height - edit_y - gap - button_h - margin;
    if (edit_h < 80) edit_h = 80;
    int button_y = edit_y + edit_h + gap;
    int button_w = (width - margin * 2 - gap * 3) / 4;
    if (button_w < 58) button_w = 58;

    MoveWindow(g_key_select, margin, margin, width - margin * 2, 220, TRUE);
    MoveWindow(g_topic_edit, margin, topic_y, width - margin * 2, topic_h, TRUE);
    MoveWindow(g_textbox, margin, edit_y, width - margin * 2, edit_h, TRUE);
    if (g_text_overlay) {
        RECT edit_rc;
        GetClientRect(g_textbox, &edit_rc);
        int overlay_w = edit_rc.right - edit_rc.left - 16;
        int overlay_h = edit_rc.bottom - edit_rc.top - 16;
        if (overlay_w < 1) overlay_w = 1;
        if (overlay_h < 1) overlay_h = 1;
        MoveWindow(g_text_overlay, 8, 8, overlay_w, overlay_h, TRUE);
        SetWindowPos(g_text_overlay, HWND_TOP, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    MoveWindow(GetDlgItem(hwnd, IDC_ENCRYPT), margin, button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_DECRYPT), margin + (button_w + gap), button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_CLEAR), margin + (button_w + gap) * 2, button_y, button_w, button_h, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_KEY_TRANSFER), margin + (button_w + gap) * 3, button_y, button_w, button_h, TRUE);
}

static void set_control_font(HWND hwnd) {
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)g_ui_font, TRUE);
}

static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_NCCREATE:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)dup_wide(L""));
        return TRUE;
    case WM_SETTEXT: {
        WCHAR *old_text = (WCHAR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        WCHAR *new_text = dup_wide((const WCHAR *)lparam);
        if (!new_text) return FALSE;
        secure_free_wide(old_text);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)new_text);
        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
        return TRUE;
    }
    case WM_GETTEXTLENGTH: {
        WCHAR *text = (WCHAR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        return text ? (LRESULT)wcslen(text) : 0;
    }
    case WM_GETTEXT: {
        WCHAR *text = (WCHAR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        WCHAR *out = (WCHAR *)lparam;
        int cch = (int)wparam;
        if (!out || cch <= 0) return 0;
        out[0] = L'\0';
        if (!text) return 0;
        StringCchCopyW(out, (size_t)cch, text);
        return (LRESULT)wcslen(out);
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;
        if (w > 0 && h > 0) {
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
            HGDIOBJ old_bmp = SelectObject(mem, bmp);
            RECT local_rc = { 0, 0, w, h };
            HRGN clip = CreateRectRgn(0, 0, w, h);
            if (clip) {
                SelectClipRgn(mem, clip);
                DeleteObject(clip);
            }
            HBRUSH bg = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
            FillRect(mem, &local_rc, bg);
            DeleteObject(bg);
            HFONT old_font = NULL;
            if (g_ui_font) old_font = (HFONT)SelectObject(mem, g_ui_font);
            SetBkMode(mem, TRANSPARENT);
            SetTextColor(mem, RGB(128, 128, 128));
            RECT text_rc = local_rc;
            WCHAR *text = (WCHAR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            DrawTextW(mem, text ? text : L"", -1, &text_rc,
                      DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
            if (old_font) SelectObject(mem, old_font);
            BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old_bmp);
            DeleteObject(bmp);
            DeleteDC(mem);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY: {
        WCHAR *text = (WCHAR *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        secure_free_wide(text);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static LRESULT CALLBACK KeyTransferWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE: {
        HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TEXT, g_instance, NULL);
        SendMessageW(edit, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
        g_key_overlay = CreateWindowExW(0, L"ChineseInputAgentOverlay", L"",
                                        WS_CHILD | WS_CLIPSIBLINGS,
                                        0, 0, 0, 0, edit, (HMENU)IDC_KEY_OVERLAY, g_instance, NULL);
        HWND import_btn = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u5165",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_IMPORT, g_instance, NULL);
        HWND export_btn = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u51fa",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                          0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_EXPORT, g_instance, NULL);
        HWND controls[] = { edit, g_key_overlay, import_btn, export_btn };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lparam);
        int h = HIWORD(lparam);
        int margin = 12;
        int gap = 8;
        int button_h = 36;
        int button_w = 110;
        int button_y = h - margin - button_h;
        int edit_y = margin;
        int edit_h = button_y - gap - edit_y;
        if (edit_h < 80) edit_h = 80;
        HWND key_edit = GetDlgItem(hwnd, IDC_KEY_TEXT);
        MoveWindow(key_edit, margin, edit_y, w - margin * 2, edit_h, TRUE);
        if (g_key_overlay) {
            RECT edit_rc;
            GetClientRect(key_edit, &edit_rc);
            int overlay_w = edit_rc.right - edit_rc.left - 16;
            int overlay_h = edit_rc.bottom - edit_rc.top - 16;
            if (overlay_w < 1) overlay_w = 1;
            if (overlay_h < 1) overlay_h = 1;
            MoveWindow(g_key_overlay, 8, 8, overlay_w, overlay_h, TRUE);
            SetWindowPos(g_key_overlay, HWND_TOP, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_IMPORT), w - margin - button_w * 2 - gap, button_y, button_w, button_h, TRUE);
        MoveWindow(GetDlgItem(hwnd, IDC_KEY_EXPORT), w - margin - button_w, button_y, button_w, button_h, TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = 480;
        mmi->ptMinTrackSize.y = 300;
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_KEY_IMPORT:
            do_import_key(hwnd, GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        case IDC_KEY_EXPORT:
            do_export_key(hwnd, GetDlgItem(hwnd, IDC_KEY_TEXT));
            break;
        }
        break;
    case WM_CLOSE:
        if (g_work_active) {
            InterlockedExchange(&g_cancel_work, 1);
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_key_window == hwnd) {
            g_key_window = NULL;
            g_key_overlay = NULL;
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void do_key_transfer(HWND owner) {
    if (g_key_window && IsWindow(g_key_window)) {
        SetForegroundWindow(g_key_window);
        return;
    }
    g_key_window = CreateWindowExW(WS_EX_TOOLWINDOW, L"ChineseInputAgentKeyWindow",
                                   L"\u5bfc\u5165/\u5bfc\u51fa\u5bc6\u94a5", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_SIZEBOX,
                                   CW_USEDEFAULT, CW_USEDEFAULT, 620, 420,
                                   owner, NULL, g_instance, NULL);
    if (!g_key_window) {
        show_error(owner, L"");
        return;
    }
    ShowWindow(g_key_window, SW_SHOW);
    UpdateWindow(g_key_window);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_APP_WORK_UPDATE:
    case WM_APP_WORK_DONE:
    case WM_APP_WORK_ERROR:
    case WM_APP_WORK_CANCELLED: {
        WORK_MESSAGE *m = (WORK_MESSAGE *)lparam;
        if (m) {
            if (msg == WM_APP_WORK_ERROR) {
                if (m->target_textbox && IsWindow(m->target_textbox)) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, L"\u4efb\u52a1\u5931\u8d25\uff0c\u672a\u5199\u5165\u672a\u5b8c\u6210\u5185\u5bb9", TRUE);
                }
                show_error(hwnd, m->text ? m->text : L"\u540e\u53f0\u4efb\u52a1\u5931\u8d25\u3002");
            } else if (msg == WM_APP_WORK_CANCELLED) {
                if (m->target_textbox && IsWindow(m->target_textbox)) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, NULL, FALSE);
                }
            } else if (m->target_textbox && IsWindow(m->target_textbox)) {
                if (msg == WM_APP_WORK_UPDATE) {
                    SetWindowTextW(m->target_textbox, L"");
                    set_textbox_overlay(m->target_textbox, m->text ? m->text : L"", TRUE);
                } else if (msg == WM_APP_WORK_DONE) {
                    set_textbox_overlay(m->target_textbox, NULL, FALSE);
                    SetWindowTextW(m->target_textbox, m->text ? m->text : L"");
                    if (m->kind == WORK_KIND_IMPORT_KEY) {
                        refresh_key_combo();
                        if (m->text && m->text[0]) {
                            MessageBoxW(hwnd, m->text, L"\u8054\u7cfb\u4eba\u6307\u7eb9\u786e\u8ba4", MB_OK | MB_ICONINFORMATION);
                        }
                    }
                }
            }
            xfree(m->text);
            xfree(m);
        }
        if (msg == WM_APP_WORK_DONE || msg == WM_APP_WORK_ERROR || msg == WM_APP_WORK_CANCELLED) {
            InterlockedExchange(&g_work_active, 0);
            InterlockedExchange(&g_cancel_work, 0);
            set_busy_controls(FALSE);
        }
        return 0;
    }
    case WM_CREATE: {
        g_key_select = CreateWindowExW(0, WC_COMBOBOXW, L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_SELECT, g_instance, NULL);
        g_topic_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_TOPIC, g_instance, NULL);
        SendMessageW(g_topic_edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"\u8bf7\u5148\u8f93\u5165\u8ba8\u8bba\u7684\u4e3b\u9898");
        g_textbox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | ES_MULTILINE |
                                    ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
                                    0, 0, 0, 0, hwnd, (HMENU)IDC_TEXTBOX, g_instance, NULL);
        SendMessageW(g_textbox, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
        g_text_overlay = CreateWindowExW(0, L"ChineseInputAgentOverlay", L"",
                                         WS_CHILD | WS_CLIPSIBLINGS,
                                         0, 0, 0, 0, g_textbox, (HMENU)IDC_TEXT_OVERLAY, g_instance, NULL);

        HWND encrypt = CreateWindowExW(0, L"BUTTON", L"\u52a0\u5bc6", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_ENCRYPT, g_instance, NULL);
        HWND decrypt = CreateWindowExW(0, L"BUTTON", L"\u89e3\u5bc6", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, hwnd, (HMENU)IDC_DECRYPT, g_instance, NULL);
        HWND clear = CreateWindowExW(0, L"BUTTON", L"\u5f52\u6863", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_CLEAR, g_instance, NULL);
        HWND key_transfer = CreateWindowExW(0, L"BUTTON", L"\u5bfc\u5165/\u5bfc\u51fa\u5bc6\u94a5",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                            0, 0, 0, 0, hwnd, (HMENU)IDC_KEY_TRANSFER, g_instance, NULL);
        HWND controls[] = { g_key_select, g_topic_edit, g_textbox, g_text_overlay, encrypt, decrypt, clear, key_transfer };
        for (size_t i = 0; i < ARRAYSIZE(controls); ++i) set_control_font(controls[i]);
        refresh_key_combo();
        refresh_main_mode_controls();
        break;
    }
    case WM_SIZE:
        layout_main(hwnd, LOWORD(lparam), HIWORD(lparam));
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = 620;
        mmi->ptMinTrackSize.y = 360;
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_KEY_SELECT:
            if (HIWORD(wparam) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_key_select, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel != g_active_profile) {
                    WCHAR err[256] = L"";
                    if (!activate_profile(sel, hwnd, err, ARRAYSIZE(err))) {
                        show_error(hwnd, err[0] ? err : L"\u5207\u6362\u5bc6\u94a5\u5931\u8d25\u3002");
                        refresh_key_combo();
                    } else if (g_archive_mode) {
                        show_archive_for_active_profile();
                    }
                }
            }
            break;
        case IDC_ENCRYPT:
            if (g_work_active) {
                InterlockedExchange(&g_cancel_work, 1);
                break;
            }
            do_encrypt(hwnd);
            break;
        case IDC_DECRYPT:
            do_decrypt(hwnd);
            break;
        case IDC_CLEAR:
            do_archive(hwnd);
            break;
        case IDC_KEY_TRANSFER:
            do_key_transfer(hwnd);
            break;
        }
        break;
    case WM_CLOSE:
        if (g_work_active) {
            InterlockedExchange(&g_cancel_work, 1);
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static BOOL register_windows(void) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentMainWindow";
    if (!RegisterClassExW(&wc)) return FALSE;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = NamePromptWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentNamePrompt";
    if (!RegisterClassExW(&wc)) return FALSE;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"ChineseInputAgentOverlay";
    if (!RegisterClassExW(&wc)) return FALSE;

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = KeyTransferWndProc;
    wc.hInstance = g_instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ChineseInputAgentKeyWindow";
    return RegisterClassExW(&wc) != 0;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev;
    (void)cmd;
    g_instance = instance;
    app_llm_init(work_cancelled, post_llm_stream_progress);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm;
    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        g_ui_font = CreateFontIndirectW(&ncm.lfMessageFont);
    }
    if (!g_ui_font) {
        g_ui_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    WCHAR err[256] = L"";
    if (!load_profiles(err, ARRAYSIZE(err))) {
        MessageBoxW(NULL, err, APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!activate_profile(g_active_profile, NULL, err, ARRAYSIZE(err))) {
        clear_all_profiles();
        MessageBoxW(NULL, err, APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }
    if (!register_windows()) {
        if (g_crypto_ready) crypto_box_shutdown();
        clear_all_profiles();
        MessageBoxW(NULL, L"Window initialization failed.", APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }

    g_main_window = CreateWindowExW(0, L"ChineseInputAgentMainWindow", APP_TITLE,
                                    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                    CW_USEDEFAULT, CW_USEDEFAULT, 760, 520,
                                    NULL, NULL, instance, NULL);
    if (!g_main_window) {
        if (g_crypto_ready) crypto_box_shutdown();
        clear_all_profiles();
        MessageBoxW(NULL, L"Window initialization failed.", APP_TITLE, MB_ICONERROR | MB_OK);
        app_llm_cleanup();
        return 1;
    }

    ShowWindow(g_main_window, show);
    UpdateWindow(g_main_window);
    start_local_llm_background();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (g_key_window && IsDialogMessageW(g_key_window, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    app_llm_cleanup();
    if (g_crypto_ready) crypto_box_shutdown();
    clear_all_profiles();
    SecureZeroMemory(g_active_master_key, sizeof(g_active_master_key));
    if (g_ui_font) DeleteObject(g_ui_font);
    return (int)msg.wParam;
}
