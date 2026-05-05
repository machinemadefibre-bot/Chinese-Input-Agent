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

typedef struct STRB {
    char *data;
    size_t len;
    size_t cap;
} STRB;

typedef struct WSTRB {
    WCHAR *data;
    size_t len;
    size_t cap;
} WSTRB;

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

typedef struct LOCAL_LLM_WORKER {
    CRITICAL_SECTION lock;
    BOOL lock_ready;
    BOOL process_ready;
    PROCESS_INFORMATION process;
    HANDLE stdin_write;
    HANDLE stdout_read;
    WCHAR stderr_path[MAX_PATH];
    DWORD next_id;
} LOCAL_LLM_WORKER;

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
static LOCAL_LLM_WORKER g_llm_worker;
static HANDLE g_llm_worker_job;

static void set_control_font(HWND hwnd);
static WCHAR *get_window_text_alloc(HWND hwnd);
static WCHAR *dup_wide(const WCHAR *s);
static void show_error(HWND owner, const WCHAR *message);
static void do_key_transfer(HWND owner);
static void do_archive(HWND hwnd);
static void show_archive_for_active_profile(void);
static void set_textbox_overlay(HWND textbox, const WCHAR *text, BOOL show);
static BOOL start_background_work(WORK_CTX *ctx);
static WCHAR *get_required_topic_text(HWND owner, HWND topic_edit);
static DWORD WINAPI work_thread_proc(LPVOID param);
static BOOL get_message_topk_seed(WCHAR *seed, size_t seed_cch, BOOL prefer_remote, WCHAR *err, size_t err_cch);
static BOOL local_topk_encode_payload(const BYTE *payload, DWORD payload_len, const WCHAR *seed, const WCHAR *topic,
                                      const WCHAR *prefix, int tail_tokens, HWND progress_target,
                                      WCHAR **out, WCHAR *err, size_t err_cch);
static BOOL local_topk_decode_payload(const WCHAR *carrier, const WCHAR *seed, BYTE **out, DWORD *out_len,
                                     WCHAR *err, size_t err_cch);
static BOOL decrypt_clip_auto_profile(HWND hwnd, const WCHAR *clip, WCHAR **plain_w_out,
                                      WCHAR *err, size_t err_cch);
static void start_local_llm_background(void);
static void shutdown_local_llm_worker(void);
static void close_local_llm_job(void);
static void post_llm_stream_progress(HWND target_textbox, const WCHAR *partial, size_t done, size_t total, double tps);
static BOOL work_cancelled(void);
static BOOL dir_exists_w(const WCHAR *path);
static void free_work_ctx(WORK_CTX *ctx);
static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

static void *xalloc(SIZE_T bytes) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes ? bytes : 1);
}

static void *xrealloc(void *ptr, SIZE_T bytes) {
    if (!ptr) return xalloc(bytes);
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, bytes ? bytes : 1);
}

static void xfree(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

static void secure_free(void *ptr, SIZE_T bytes) {
    if (ptr) {
        SecureZeroMemory(ptr, bytes);
        xfree(ptr);
    }
}

static void secure_free_wide(WCHAR *ptr) {
    if (ptr) secure_free(ptr, (wcslen(ptr) + 1) * sizeof(WCHAR));
}

static void secure_free_str(char *ptr) {
    if (ptr) secure_free(ptr, strlen(ptr) + 1);
}

static void set_error(WCHAR *buf, size_t cch, const WCHAR *fmt, ...) {
    if (!buf || cch == 0) return;
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(buf, cch, fmt, args);
    va_end(args);
}

static BOOL strb_reserve(STRB *b, size_t extra) {
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return TRUE;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) cap *= 2;
    char *p = (char *)xrealloc(b->data, cap);
    if (!p) return FALSE;
    b->data = p;
    b->cap = cap;
    return TRUE;
}

static BOOL strb_append_n(STRB *b, const char *s, size_t n) {
    if (!strb_reserve(b, n)) return FALSE;
    CopyMemory(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return TRUE;
}

static BOOL strb_append(STRB *b, const char *s) {
    return strb_append_n(b, s, strlen(s));
}

static BOOL strb_appendf(STRB *b, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0) return FALSE;
    if (!strb_reserve(b, (size_t)needed)) return FALSE;
    va_start(args, fmt);
    vsnprintf(b->data + b->len, b->cap - b->len, fmt, args);
    va_end(args);
    b->len += (size_t)needed;
    return TRUE;
}

static void strb_free(STRB *b) {
    xfree(b->data);
    ZeroMemory(b, sizeof(*b));
}

static void strb_secure_free(STRB *b) {
    secure_free(b->data, b->cap);
    ZeroMemory(b, sizeof(*b));
}

static BOOL wstrb_reserve(WSTRB *b, size_t extra) {
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return TRUE;
    size_t cap = b->cap ? b->cap : 128;
    while (cap < need) cap *= 2;
    WCHAR *p = (WCHAR *)xrealloc(b->data, cap * sizeof(WCHAR));
    if (!p) return FALSE;
    b->data = p;
    b->cap = cap;
    return TRUE;
}

static BOOL wstrb_append_n(WSTRB *b, const WCHAR *s, size_t n) {
    if (!wstrb_reserve(b, n)) return FALSE;
    CopyMemory(b->data + b->len, s, n * sizeof(WCHAR));
    b->len += n;
    b->data[b->len] = L'\0';
    return TRUE;
}

static BOOL wstrb_append(WSTRB *b, const WCHAR *s) {
    return wstrb_append_n(b, s, wcslen(s));
}

static BOOL wstrb_append_char(WSTRB *b, WCHAR ch) {
    return wstrb_append_n(b, &ch, 1);
}

static BOOL wstrb_appendf(WSTRB *b, const WCHAR *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = _vscwprintf(fmt, args);
    va_end(args);
    if (needed < 0) return FALSE;
    if (!wstrb_reserve(b, (size_t)needed)) return FALSE;
    va_start(args, fmt);
    vswprintf(b->data + b->len, b->cap - b->len, fmt, args);
    va_end(args);
    b->len += (size_t)needed;
    return TRUE;
}

static void wstrb_free(WSTRB *b) {
    xfree(b->data);
    ZeroMemory(b, sizeof(*b));
}

static void wstrb_secure_free(WSTRB *b) {
    secure_free(b->data, b->cap * sizeof(WCHAR));
    ZeroMemory(b, sizeof(*b));
}

static BOOL wide_to_utf8(const WCHAR *ws, char **out, int *out_len) {
    *out = NULL;
    if (out_len) *out_len = 0;
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws ? ws : L"", -1, NULL, 0, NULL, NULL);
    if (needed <= 0) return FALSE;
    char *buf = (char *)xalloc((SIZE_T)needed);
    if (!buf) return FALSE;
    if (!WideCharToMultiByte(CP_UTF8, 0, ws ? ws : L"", -1, buf, needed, NULL, NULL)) {
        xfree(buf);
        return FALSE;
    }
    *out = buf;
    if (out_len) *out_len = needed - 1;
    return TRUE;
}

static BOOL utf8_to_wide_n(const char *s, int len, WCHAR **out) {
    *out = NULL;
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, len, NULL, 0);
    if (needed <= 0) return FALSE;
    WCHAR *buf = (WCHAR *)xalloc(((SIZE_T)needed + 1) * sizeof(WCHAR));
    if (!buf) return FALSE;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, len, buf, needed)) {
        xfree(buf);
        return FALSE;
    }
    buf[needed] = L'\0';
    *out = buf;
    return TRUE;
}

static BOOL append_json_escaped_wide(STRB *b, const WCHAR *ws) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(ws, &utf8, &len)) return FALSE;
    BOOL ok = TRUE;
    for (int i = 0; i < len && ok; ++i) {
        unsigned char c = (unsigned char)utf8[i];
        switch (c) {
        case '\\': ok = strb_append(b, "\\\\"); break;
        case '"': ok = strb_append(b, "\\\""); break;
        case '\b': ok = strb_append(b, "\\b"); break;
        case '\f': ok = strb_append(b, "\\f"); break;
        case '\n': ok = strb_append(b, "\\n"); break;
        case '\r': ok = strb_append(b, "\\r"); break;
        case '\t': ok = strb_append(b, "\\t"); break;
        default:
            if (c < 0x20) {
                ok = strb_appendf(b, "\\u%04x", c);
            } else {
                ok = strb_append_n(b, (const char *)&utf8[i], 1);
            }
            break;
        }
    }
    xfree(utf8);
    return ok;
}

static BOOL add_unique_hanzi(WCHAR *pool, size_t *count, size_t cap, WCHAR ch) {
    if (!ch) return TRUE;
    for (size_t i = 0; i < *count; ++i) {
        if (pool[i] == ch) return TRUE;
    }
    if (*count >= cap) return FALSE;
    pool[(*count)++] = ch;
    return TRUE;
}

static void strip_last_path_component_early(WCHAR *path) {
    if (!path) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) path[--len] = L'\0';
    WCHAR *last1 = wcsrchr(path, L'\\');
    WCHAR *last2 = wcsrchr(path, L'/');
    WCHAR *last = last1 > last2 ? last1 : last2;
    if (last) *last = L'\0';
}

static BOOL get_app_dir(WCHAR *path, size_t cch) {
    WCHAR exe[MAX_PATH];
    if (GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) {
        strip_last_path_component_early(exe);
        WCHAR portable[MAX_PATH];
        if (SUCCEEDED(StringCchPrintfW(portable, ARRAYSIZE(portable), L"%s\\data", exe)) &&
            SUCCEEDED(StringCchCopyW(path, cch, portable))) {
            if (dir_exists_w(path) || CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
                return TRUE;
            }
        }
    }

    DWORD env_len = GetEnvironmentVariableW(L"CIA_DATA_DIR", path, (DWORD)cch);
    if (env_len > 0 && env_len < cch) {
        CreateDirectoryW(path, NULL);
        return TRUE;
    }

    WCHAR base[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, base))) return FALSE;
    if (FAILED(StringCchPrintfW(path, cch, L"%s\\%s", base, APP_DIR_NAME))) return FALSE;
    CreateDirectoryW(path, NULL);
    return TRUE;
}

static BOOL get_app_file(WCHAR *path, size_t cch, const WCHAR *name) {
    WCHAR dir[MAX_PATH];
    if (!get_app_dir(dir, ARRAYSIZE(dir))) return FALSE;
    return SUCCEEDED(StringCchPrintfW(path, cch, L"%s\\%s", dir, name));
}

static uint64_t fnv1a_path_hash(const WCHAR *text) {
    uint64_t h = 1469598103934665603ull;
    for (const WCHAR *p = text ? text : L""; *p; ++p) {
        WCHAR ch = *p;
        if (ch >= L'A' && ch <= L'Z') ch = (WCHAR)(ch - L'A' + L'a');
        h ^= (uint64_t)(ch & 0xff);
        h *= 1099511628211ull;
        h ^= (uint64_t)((ch >> 8) & 0xff);
        h *= 1099511628211ull;
    }
    return h;
}

static BOOL get_scoped_wrap_key_name(const WCHAR *label, WCHAR *out, size_t cch) {
    WCHAR dir[MAX_PATH];
    if (!get_app_dir(dir, ARRAYSIZE(dir))) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"ChineseInputAgent %s %016llx",
                                     label ? label : L"Key",
                                     (unsigned long long)fnv1a_path_hash(dir)));
}

static BOOL read_file_bytes(const WCHAR *path, BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(h);
        return FALSE;
    }
    BYTE *buf = (BYTE *)xalloc((SIZE_T)size.QuadPart);
    if (!buf) {
        CloseHandle(h);
        return FALSE;
    }
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)size.QuadPart, &read, NULL) && read == (DWORD)size.QuadPart;
    CloseHandle(h);
    if (!ok) {
        xfree(buf);
        return FALSE;
    }
    *out = buf;
    *out_len = read;
    return TRUE;
}

static BOOL write_file_bytes(const WCHAR *path, const BYTE *data, DWORD len) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, len, &written, NULL) && written == len;
    CloseHandle(h);
    return ok;
}

static BOOL write_text_utf8_file(const WCHAR *path, const WCHAR *text) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(text ? text : L"", &utf8, &len)) return FALSE;
    BOOL ok = write_file_bytes(path, (const BYTE *)utf8, (DWORD)len);
    secure_free(utf8, len + 1);
    return ok;
}

static BOOL read_utf8_text_file(const WCHAR *path, WCHAR **out) {
    *out = NULL;
    BYTE *data = NULL;
    DWORD len = 0;
    if (!read_file_bytes(path, &data, &len)) return FALSE;
    BOOL ok = utf8_to_wide_n((const char *)data, (int)len, out);
    secure_free(data, len);
    return ok;
}

static BOOL file_exists_w(const WCHAR *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL dir_exists_w(const WCHAR *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static void strip_last_path_component(WCHAR *path) {
    if (!path) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) {
        path[--len] = L'\0';
    }
    WCHAR *last1 = wcsrchr(path, L'\\');
    WCHAR *last2 = wcsrchr(path, L'/');
    WCHAR *last = last1 > last2 ? last1 : last2;
    if (last) *last = L'\0';
}

static BOOL join_path(WCHAR *out, size_t cch, const WCHAR *base, const WCHAR *leaf) {
    if (!base || !base[0]) return FALSE;
    size_t len = wcslen(base);
    const WCHAR *sep = (len && (base[len - 1] == L'\\' || base[len - 1] == L'/')) ? L"" : L"\\";
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s%s%s", base, sep, leaf ? leaf : L""));
}

static BOOL find_native_worker_at_root(const WCHAR *root,
                                       WCHAR *worker, size_t worker_cch,
                                       WCHAR *workdir, size_t workdir_cch,
                                       WCHAR *python, size_t python_cch) {
    WCHAR tools[MAX_PATH];
    if (!join_path(tools, ARRAYSIZE(tools), root, L"tools\\payload_watermark")) return FALSE;
    if (!join_path(worker, worker_cch, tools, L"cia_llama_worker.exe") || !file_exists_w(worker)) return FALSE;
    if (FAILED(StringCchCopyW(workdir, workdir_cch, tools))) return FALSE;
    if (python && python_cch) python[0] = L'\0';
    return TRUE;
}

static BOOL find_native_worker_at_dir(const WCHAR *dir,
                                      WCHAR *worker, size_t worker_cch,
                                      WCHAR *workdir, size_t workdir_cch,
                                      WCHAR *python, size_t python_cch) {
    if (!join_path(worker, worker_cch, dir, L"cia_llama_worker.exe") || !file_exists_w(worker)) return FALSE;
    if (FAILED(StringCchCopyW(workdir, workdir_cch, dir))) return FALSE;
    if (python && python_cch) python[0] = L'\0';
    return TRUE;
}

static BOOL find_local_worker(WCHAR *script, size_t script_cch, WCHAR *workdir, size_t workdir_cch,
                              WCHAR *python, size_t python_cch, WCHAR *err, size_t err_cch) {
    WCHAR exe[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) {
        set_error(err, err_cch, L"");
        return FALSE;
    }

    WCHAR candidate[MAX_PATH];
    StringCchCopyW(candidate, ARRAYSIZE(candidate), exe);
    strip_last_path_component(candidate);
    WCHAR packaged_worker[MAX_PATH];
    if (join_path(packaged_worker, ARRAYSIZE(packaged_worker), candidate, L"llama_worker_package") &&
        find_native_worker_at_dir(packaged_worker, script, script_cch, workdir, workdir_cch, python, python_cch)) return TRUE;
    if (find_native_worker_at_root(candidate, script, script_cch, workdir, workdir_cch, python, python_cch)) return TRUE;

    strip_last_path_component(candidate);
    if (candidate[0] &&
        find_native_worker_at_root(candidate, script, script_cch, workdir, workdir_cch, python, python_cch)) return TRUE;

    WCHAR cwd[MAX_PATH];
    if (GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd) &&
        find_native_worker_at_root(cwd, script, script_cch, workdir, workdir_cch, python, python_cch)) return TRUE;

    set_error(err, err_cch, L"Local LLM worker executable was not found.");
    return FALSE;
}

static BOOL make_temp_path(WCHAR *path, size_t cch) {
    WCHAR dir[MAX_PATH];
    if (!GetTempPathW(ARRAYSIZE(dir), dir)) return FALSE;
    WCHAR tmp[MAX_PATH];
    if (!GetTempFileNameW(dir, L"cia", 0, tmp)) return FALSE;
    return SUCCEEDED(StringCchCopyW(path, cch, tmp));
}

static void secure_delete_file(const WCHAR *path) {
    if (!path || !path[0]) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        if (GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart <= 128LL * 1024LL * 1024LL) {
            BYTE zeros[4096];
            ZeroMemory(zeros, sizeof(zeros));
            LARGE_INTEGER pos;
            pos.QuadPart = 0;
            SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
            LONGLONG left = size.QuadPart;
            while (left > 0) {
                DWORD chunk = (DWORD)((left > (LONGLONG)sizeof(zeros)) ? sizeof(zeros) : left);
                DWORD written = 0;
                if (!WriteFile(h, zeros, chunk, &written, NULL) || written != chunk) break;
                left -= chunk;
            }
            FlushFileBuffers(h);
        }
        CloseHandle(h);
    }
    DeleteFileW(path);
}

static BOOL append_quoted_arg(WSTRB *cmd, const WCHAR *arg) {
    if (!wstrb_append_char(cmd, L'"')) return FALSE;
    size_t slashes = 0;
    for (const WCHAR *p = arg ? arg : L""; *p; ++p) {
        if (*p == L'\\') {
            ++slashes;
            continue;
        }
        if (*p == L'"') {
            for (size_t i = 0; i < slashes * 2 + 1; ++i) {
                if (!wstrb_append_char(cmd, L'\\')) return FALSE;
            }
            slashes = 0;
            if (!wstrb_append_char(cmd, L'"')) return FALSE;
            continue;
        }
        for (size_t i = 0; i < slashes; ++i) {
            if (!wstrb_append_char(cmd, L'\\')) return FALSE;
        }
        slashes = 0;
        if (!wstrb_append_char(cmd, *p)) return FALSE;
    }
    for (size_t i = 0; i < slashes * 2; ++i) {
        if (!wstrb_append_char(cmd, L'\\')) return FALSE;
    }
    return wstrb_append_char(cmd, L'"');
}

static BOOL append_process_log(WCHAR *err, size_t err_cch, const WCHAR *prefix, const WCHAR *log_path) {
    WCHAR *log = NULL;
    if (read_utf8_text_file(log_path, &log) && log && log[0]) {
        size_t len = wcslen(log);
        const WCHAR *tail = log;
        if (len > 900) tail = log + len - 900;
        set_error(err, err_cch, L"%s: %s", prefix, tail);
        secure_free_wide(log);
        return TRUE;
    }
    secure_free_wide(log);
    return FALSE;
}

static BOOL write_all_handle(HANDLE h, const void *data, DWORD len) {
    const BYTE *p = (const BYTE *)data;
    DWORD left = len;
    while (left > 0) {
        DWORD written = 0;
        if (!WriteFile(h, p, left, &written, NULL) || written == 0) return FALSE;
        p += written;
        left -= written;
    }
    return TRUE;
}

static BOOL read_line_handle(HANDLE h, STRB *line) {
    ZeroMemory(line, sizeof(*line));
    for (;;) {
        char ch = 0;
        DWORD read = 0;
        if (!ReadFile(h, &ch, 1, &read, NULL) || read != 1) {
            return line->len > 0;
        }
        if (ch == '\n') return TRUE;
        if (ch == '\r') continue;
        if (line->len > 1024 * 1024) return FALSE;
        if (!strb_append_n(line, &ch, 1)) return FALSE;
    }
}

static BOOL read_line_handle_cancelable(HANDLE h, HANDLE process, STRB *line, BOOL *cancelled) {
    ZeroMemory(line, sizeof(*line));
    if (cancelled) *cancelled = FALSE;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) {
            return line->len > 0;
        }
        if (available == 0) {
            if (process && WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
                return line->len > 0;
            }
            if (work_cancelled()) {
                if (cancelled) *cancelled = TRUE;
                return FALSE;
            }
            Sleep(50);
            continue;
        }
        char ch = 0;
        DWORD read = 0;
        if (!ReadFile(h, &ch, 1, &read, NULL) || read != 1) {
            return line->len > 0;
        }
        if (ch == '\n') return TRUE;
        if (ch == '\r') continue;
        if (line->len > 1024 * 1024) return FALSE;
        if (!strb_append_n(line, &ch, 1)) return FALSE;
    }
}

static BOOL append_json_wide_field(STRB *b, const char *name, const WCHAR *value, BOOL comma) {
    if (comma && !strb_append(b, ",")) return FALSE;
    return strb_append(b, "\"") &&
           strb_append(b, name) &&
           strb_append(b, "\":\"") &&
           append_json_escaped_wide(b, value ? value : L"") &&
           strb_append(b, "\"");
}

static BOOL build_worker_request_json(STRB *b, DWORD id, const char *cmd,
                                      const WCHAR *payload_path, const WCHAR *text_path,
                                      const WCHAR *topic_path, const WCHAR *seed,
                                      const WCHAR *out_path, int tail_tokens) {
    ZeroMemory(b, sizeof(*b));
    if (!strb_appendf(b, "{\"id\":%lu,\"cmd\":\"%s\"", (unsigned long)id, cmd)) return FALSE;
    if (payload_path && !append_json_wide_field(b, "payload", payload_path, TRUE)) return FALSE;
    if (text_path && !append_json_wide_field(b, "text", text_path, TRUE)) return FALSE;
    if (topic_path && !append_json_wide_field(b, "topic_file", topic_path, TRUE)) return FALSE;
    if (seed && !append_json_wide_field(b, "seed", seed, TRUE)) return FALSE;
    if (out_path && !append_json_wide_field(b, "out", out_path, TRUE)) return FALSE;
    if (tail_tokens >= 0 && !strb_appendf(b, ",\"tail_tokens\":%d", tail_tokens)) return FALSE;
    return strb_append(b, "}\n");
}

static BOOL response_json_ok(const char *line) {
    return line && (strstr(line, "\"ok\": true") || strstr(line, "\"ok\":true"));
}

static BOOL json_line_has_string(const char *line, const char *name, const char *value) {
    if (!line || !name || !value) return FALSE;
    char pattern[96];
    sprintf(pattern, "\"%s\":\"%s\"", name, value);
    return strstr(line, pattern) != NULL;
}

static BOOL json_get_size_t_field(const char *line, const char *name, size_t *out) {
    if (!line || !name || !out) return FALSE;
    char pattern[64];
    sprintf(pattern, "\"%s\":", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') ++p;
    size_t value = 0;
    BOOL any = FALSE;
    while (*p >= '0' && *p <= '9') {
        any = TRUE;
        value = value * 10 + (size_t)(*p - '0');
        ++p;
    }
    if (!any) return FALSE;
    *out = value;
    return TRUE;
}

static BOOL json_get_double_field(const char *line, const char *name, double *out) {
    if (!line || !name || !out) return FALSE;
    char pattern[64];
    sprintf(pattern, "\"%s\":", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') ++p;
    char *end = NULL;
    double value = strtod(p, &end);
    if (end == p) return FALSE;
    *out = value;
    return TRUE;
}

static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static BOOL strb_append_utf8_codepoint(STRB *b, unsigned cp) {
    char tmp[4];
    size_t n = 0;
    if (cp <= 0x7f) {
        tmp[n++] = (char)cp;
    } else if (cp <= 0x7ff) {
        tmp[n++] = (char)(0xc0 | (cp >> 6));
        tmp[n++] = (char)(0x80 | (cp & 0x3f));
    } else {
        tmp[n++] = (char)(0xe0 | (cp >> 12));
        tmp[n++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        tmp[n++] = (char)(0x80 | (cp & 0x3f));
    }
    return strb_append_n(b, tmp, n);
}

static BOOL json_get_wide_string_field(const char *line, const char *name, WCHAR **out) {
    *out = NULL;
    if (!line || !name) return FALSE;
    char pattern[96];
    sprintf(pattern, "\"%s\":\"", name);
    const char *p = strstr(line, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    STRB utf8 = {0};
    BOOL ok = TRUE;
    while (*p && *p != '"') {
        if (*p == '\\') {
            ++p;
            if (!*p) { ok = FALSE; break; }
            switch (*p) {
            case '"': ok = strb_append_n(&utf8, "\"", 1); break;
            case '\\': ok = strb_append_n(&utf8, "\\", 1); break;
            case '/': ok = strb_append_n(&utf8, "/", 1); break;
            case 'b': ok = strb_append_n(&utf8, "\b", 1); break;
            case 'f': ok = strb_append_n(&utf8, "\f", 1); break;
            case 'n': ok = strb_append_n(&utf8, "\n", 1); break;
            case 'r': ok = strb_append_n(&utf8, "\r", 1); break;
            case 't': ok = strb_append_n(&utf8, "\t", 1); break;
            case 'u': {
                unsigned cp = 0;
                for (int i = 0; i < 4; ++i) {
                    int h = hex_value(p[1 + i]);
                    if (h < 0) { ok = FALSE; break; }
                    cp = (cp << 4) | (unsigned)h;
                }
                if (ok) {
                    ok = strb_append_utf8_codepoint(&utf8, cp);
                    p += 4;
                }
                break;
            }
            default:
                ok = FALSE;
                break;
            }
            if (!ok) break;
            ++p;
            continue;
        }
        ok = strb_append_n(&utf8, p, 1);
        if (!ok) break;
        ++p;
    }
    if (ok && *p != '"') ok = FALSE;
    if (ok) {
        if (utf8.len == 0) {
            *out = dup_wide(L"");
            ok = *out != NULL;
        } else {
            ok = utf8_to_wide_n(utf8.data, (int)utf8.len, out);
        }
    }
    strb_free(&utf8);
    return ok;
}

static BOOL ensure_local_llm_job(void) {
    if (g_llm_worker_job) return TRUE;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) return FALSE;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
        CloseHandle(job);
        return FALSE;
    }
    g_llm_worker_job = job;
    return TRUE;
}

static void close_local_llm_job(void) {
    if (g_llm_worker_job) {
        CloseHandle(g_llm_worker_job);
        g_llm_worker_job = NULL;
    }
}

static void close_local_llm_worker_locked(BOOL terminate) {
    if (g_llm_worker.process.hProcess) {
        if (terminate) {
            TerminateProcess(g_llm_worker.process.hProcess, 1);
            WaitForSingleObject(g_llm_worker.process.hProcess, 2000);
        }
        CloseHandle(g_llm_worker.process.hProcess);
    }
    if (g_llm_worker.process.hThread) CloseHandle(g_llm_worker.process.hThread);
    if (g_llm_worker.stdin_write) CloseHandle(g_llm_worker.stdin_write);
    if (g_llm_worker.stdout_read) CloseHandle(g_llm_worker.stdout_read);
    ZeroMemory(&g_llm_worker.process, sizeof(g_llm_worker.process));
    g_llm_worker.stdin_write = NULL;
    g_llm_worker.stdout_read = NULL;
    g_llm_worker.process_ready = FALSE;
}

static BOOL local_llm_worker_alive_locked(void) {
    if (!g_llm_worker.process_ready || !g_llm_worker.process.hProcess) return FALSE;
    DWORD code = 0;
    return GetExitCodeProcess(g_llm_worker.process.hProcess, &code) && code == STILL_ACTIVE;
}

static BOOL start_local_llm_worker_locked(WCHAR *err, size_t err_cch) {
    if (local_llm_worker_alive_locked()) return TRUE;
    close_local_llm_worker_locked(FALSE);

    WCHAR script[MAX_PATH], workdir[MAX_PATH], python[MAX_PATH];
    if (!find_local_worker(script, ARRAYSIZE(script), workdir, ARRAYSIZE(workdir),
                           python, ARRAYSIZE(python), err, err_cch)) {
        return FALSE;
    }

    HANDLE stdin_read = NULL, stdin_write = NULL, stdout_read = NULL, stdout_write = NULL;
    HANDLE stderr_file = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&stdin_read, &stdin_write, &sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    if (!make_temp_path(g_llm_worker.stderr_path, ARRAYSIZE(g_llm_worker.stderr_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    stderr_file = CreateFileW(g_llm_worker.stderr_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NORMAL, NULL);
    if (stderr_file == INVALID_HANDLE_VALUE) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WSTRB cmd = {0};
    if (python[0]) {
        if (!append_quoted_arg(&cmd, python) ||
            !wstrb_append(&cmd, L" -X utf8 ") ||
            !append_quoted_arg(&cmd, script)) {
            wstrb_free(&cmd);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
    } else {
        if (!append_quoted_arg(&cmd, script)) {
            wstrb_free(&cmd);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_read;
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_file;

    WCHAR *mutable_cmd = dup_wide(cmd.data);
    wstrb_free(&cmd);
    if (!mutable_cmd) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    BOOL started = CreateProcessW(NULL, mutable_cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                                  NULL, workdir, &si, &pi);
    secure_free_wide(mutable_cmd);
    if (!started) {
        set_error(err, err_cch, L"", (unsigned long)GetLastError());
        goto fail;
    }
    if (ensure_local_llm_job()) {
        AssignProcessToJobObject(g_llm_worker_job, pi.hProcess);
    }

    CloseHandle(stdin_read);
    CloseHandle(stdout_write);
    CloseHandle(stderr_file);
    stdin_read = NULL;
    stdout_write = NULL;
    stderr_file = INVALID_HANDLE_VALUE;

    g_llm_worker.process = pi;
    g_llm_worker.stdin_write = stdin_write;
    g_llm_worker.stdout_read = stdout_read;
    stdin_write = NULL;
    stdout_read = NULL;

    STRB ready = {0};
    BOOL ready_cancelled = FALSE;
    if (!read_line_handle_cancelable(g_llm_worker.stdout_read, g_llm_worker.process.hProcess, &ready, &ready_cancelled) ||
        !response_json_ok(ready.data)) {
        WCHAR *ready_w = NULL;
        if (ready_cancelled) {
            set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        } else if (ready.data && utf8_to_wide_n(ready.data, (int)ready.len, &ready_w)) {
            set_error(err, err_cch, L"Local inference worker startup failed: %s", ready_w);
            secure_free_wide(ready_w);
        } else if (!append_process_log(err, err_cch, L"Local inference worker startup failed", g_llm_worker.stderr_path)) {
            set_error(err, err_cch, L"Local inference worker startup failed and no diagnostic log was readable.");
        }
        strb_free(&ready);
        close_local_llm_worker_locked(TRUE);
        return FALSE;
    }
    strb_free(&ready);
    g_llm_worker.process_ready = TRUE;
    return TRUE;

fail:
    if (stdin_read) CloseHandle(stdin_read);
    if (stdin_write) CloseHandle(stdin_write);
    if (stdout_read) CloseHandle(stdout_read);
    if (stdout_write) CloseHandle(stdout_write);
    if (stderr_file != INVALID_HANDLE_VALUE) CloseHandle(stderr_file);
    if (g_llm_worker.stderr_path[0]) secure_delete_file(g_llm_worker.stderr_path);
    g_llm_worker.stderr_path[0] = L'\0';
    return FALSE;
}

static BOOL local_llm_worker_request(const char *cmd, const WCHAR *payload_path, const WCHAR *text_path,
                                     const WCHAR *topic_path, const WCHAR *seed, const WCHAR *out_path,
                                     int tail_tokens, HWND progress_target, WCHAR *err, size_t err_cch) {
    if (!g_llm_worker.lock_ready) {
        return FALSE;
    }
    BOOL ok = FALSE;
    EnterCriticalSection(&g_llm_worker.lock);
    if (work_cancelled()) {
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (!start_local_llm_worker_locked(err, err_cch)) {
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (work_cancelled()) {
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }

    DWORD id = ++g_llm_worker.next_id;
    STRB request = {0};
    if (!build_worker_request_json(&request, id, cmd, payload_path, text_path, topic_path, seed, out_path, tail_tokens)) {
        strb_free(&request);
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    if (!write_all_handle(g_llm_worker.stdin_write, request.data, (DWORD)request.len)) {
        strb_free(&request);
        close_local_llm_worker_locked(TRUE);
        set_error(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
        LeaveCriticalSection(&g_llm_worker.lock);
        return FALSE;
    }
    strb_free(&request);

    for (;;) {
        STRB response = {0};
        BOOL cancelled = FALSE;
        if (!read_line_handle_cancelable(g_llm_worker.stdout_read, g_llm_worker.process.hProcess, &response, &cancelled)) {
            close_local_llm_worker_locked(TRUE);
            set_error(err, err_cch, cancelled ? L"\u5df2\u505c\u6b62\u3002" : L"\u672c\u5730 top-k worker \u672a\u8fd4\u56de\u54cd\u5e94\u3002");
            LeaveCriticalSection(&g_llm_worker.lock);
            return FALSE;
        }
        if (json_line_has_string(response.data, "type", "progress")) {
            if (progress_target && IsWindow(progress_target)) {
                size_t done = 0, total = 0;
                double tps = 0.0;
                WCHAR *partial = NULL;
                json_get_size_t_field(response.data, "done", &done);
                json_get_size_t_field(response.data, "total", &total);
                json_get_double_field(response.data, "tps", &tps);
                if (json_get_wide_string_field(response.data, "text", &partial)) {
                    post_llm_stream_progress(progress_target, partial, done, total, tps);
                    secure_free_wide(partial);
                }
            }
            strb_free(&response);
            continue;
        }
        if (response_json_ok(response.data)) {
            ok = TRUE;
        } else {
            WCHAR *worker_error = NULL;
            WCHAR *response_w = NULL;
            if (json_get_wide_string_field(response.data, "error", &worker_error)) {
                set_error(err, err_cch, L"Local top-k carrier worker returned an error: %s", worker_error);
                secure_free_wide(worker_error);
            } else if (response.data && utf8_to_wide_n(response.data, (int)response.len, &response_w)) {
                set_error(err, err_cch, L"Local top-k carrier worker returned an invalid response: %s", response_w);
                secure_free_wide(response_w);
            } else {
                set_error(err, err_cch, L"Local top-k carrier worker returned an invalid response.");
            }
        }
        strb_free(&response);
        break;
    }
    LeaveCriticalSection(&g_llm_worker.lock);
    return ok;
}

static DWORD WINAPI local_llm_boot_thread_proc(LPVOID param) {
    (void)param;
    WCHAR err[512] = L"";
    if (!g_llm_worker.lock_ready) return 0;
    EnterCriticalSection(&g_llm_worker.lock);
    start_local_llm_worker_locked(err, ARRAYSIZE(err));
    LeaveCriticalSection(&g_llm_worker.lock);
    return 0;
}

static void start_local_llm_background(void) {
    if (!g_llm_worker.lock_ready) return;
    HANDLE thread = CreateThread(NULL, 0, local_llm_boot_thread_proc, NULL, 0, NULL);
    if (thread) CloseHandle(thread);
}

static void shutdown_local_llm_worker(void) {
    if (!g_llm_worker.lock_ready) return;
    InterlockedExchange(&g_cancel_work, 1);
    EnterCriticalSection(&g_llm_worker.lock);
    if (local_llm_worker_alive_locked()) {
        STRB request = {0};
        if (strb_appendf(&request, "{\"id\":%lu,\"cmd\":\"shutdown\"}\n",
                        (unsigned long)(++g_llm_worker.next_id))) {
            write_all_handle(g_llm_worker.stdin_write, request.data, (DWORD)request.len);
            WaitForSingleObject(g_llm_worker.process.hProcess, 3000);
        }
        strb_free(&request);
    }
    if (local_llm_worker_alive_locked()) {
        close_local_llm_worker_locked(TRUE);
    } else {
        close_local_llm_worker_locked(FALSE);
    }
    if (g_llm_worker.stderr_path[0]) {
        secure_delete_file(g_llm_worker.stderr_path);
        g_llm_worker.stderr_path[0] = L'\0';
    }
    LeaveCriticalSection(&g_llm_worker.lock);
}

static BOOL local_topk_encode_payload(const BYTE *payload, DWORD payload_len, const WCHAR *seed, const WCHAR *topic,
                                      const WCHAR *prefix, int tail_tokens, HWND progress_target,
                                      WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;

    WCHAR payload_path[MAX_PATH] = L"";
    WCHAR topic_path[MAX_PATH] = L"";
    WCHAR out_path[MAX_PATH] = L"";
    if (!make_temp_path(payload_path, ARRAYSIZE(payload_path)) ||
        !make_temp_path(topic_path, ARRAYSIZE(topic_path)) ||
        !make_temp_path(out_path, ARRAYSIZE(out_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    if (!write_file_bytes(payload_path, payload, payload_len) ||
        !write_text_utf8_file(topic_path, topic && topic[0] ? topic : L"\u65e5\u5e38\u751f\u6d3b")) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WCHAR worker_err[512] = L"";
    BOOL ran = local_llm_worker_request("encode", payload_path, NULL, topic_path, seed, out_path, tail_tokens, progress_target,
                                        worker_err, ARRAYSIZE(worker_err));
    if (!ran) {
        if (work_cancelled()) {
            if (!err[0]) StringCchCopyW(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            goto fail;
        }
        StringCchCopyW(err, err_cch, worker_err[0] ? worker_err : L"Local top-k worker returned no usable result.");
        goto fail;
    }

    WCHAR *carrier = NULL;
    if (!read_utf8_text_file(out_path, &carrier)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    if (prefix && prefix[0]) {
        WSTRB b = {0};
        if (!wstrb_append(&b, prefix) || !wstrb_append(&b, carrier)) {
            secure_free_wide(carrier);
            wstrb_free(&b);
            set_error(err, err_cch, L"Carrier text assembly failed.");
            goto fail;
        }
        secure_free_wide(carrier);
        *out = b.data;
    } else {
        *out = carrier;
    }

    secure_delete_file(payload_path);
    secure_delete_file(topic_path);
    secure_delete_file(out_path);
    return TRUE;

fail:
    secure_delete_file(payload_path);
    secure_delete_file(topic_path);
    secure_delete_file(out_path);
    return FALSE;
}

static BOOL local_topk_decode_payload(const WCHAR *carrier, const WCHAR *seed, BYTE **out, DWORD *out_len,
                                     WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;

    WCHAR text_path[MAX_PATH] = L"";
    WCHAR out_path[MAX_PATH] = L"";
    if (!make_temp_path(text_path, ARRAYSIZE(text_path)) ||
        !make_temp_path(out_path, ARRAYSIZE(out_path))) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }
    if (!write_text_utf8_file(text_path, carrier ? carrier : L"")) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    WCHAR worker_err[512] = L"";
    BOOL ran = local_llm_worker_request("decode", NULL, text_path, NULL, seed, out_path, -1, NULL,
                                        worker_err, ARRAYSIZE(worker_err));
    if (!ran) {
        if (work_cancelled()) {
            if (!err[0]) StringCchCopyW(err, err_cch, L"\u5df2\u505c\u6b62\u3002");
            goto fail;
        }
        StringCchCopyW(err, err_cch, worker_err[0] ? worker_err : L"Local top-k worker returned no usable result.");
        goto fail;
    }

    BYTE *payload = NULL;
    DWORD payload_len = 0;
    if (!read_file_bytes(out_path, &payload, &payload_len)) {
        set_error(err, err_cch, L"Operation failed.");
        goto fail;
    }

    *out = payload;
    *out_len = payload_len;
    secure_delete_file(text_path);
    secure_delete_file(out_path);
    return TRUE;

fail:
    secure_delete_file(text_path);
    secure_delete_file(out_path);
    return FALSE;
}

static BOOL dpapi_protect(const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len) {
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

static BOOL dpapi_unprotect(const BYTE *blob, DWORD blob_len, BYTE **out, DWORD *out_len) {
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

static BOOL local_aes_gcm_encrypt(const BYTE key[MASTER_KEY_BYTES], const BYTE *plain, DWORD plain_len,
                                  BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
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

    DWORD total = LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES + plain_len;
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
    secure_free(envelope, envelope ? LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES + plain_len : 0);
    SecureZeroMemory(nonce, sizeof(nonce));
    return ok;
}

static BOOL local_aes_gcm_decrypt(const BYTE key[MASTER_KEY_BYTES], const BYTE *envelope, DWORD envelope_len,
                                  BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    if (envelope_len < LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES ||
        memcmp(envelope, "CIA1", 4) != 0 ||
        envelope[4] != 1 ||
        envelope[5] != LOCAL_BLOB_NONCE_BYTES ||
        envelope[6] != LOCAL_BLOB_TAG_BYTES) return FALSE;
    DWORD cipher_len = (DWORD)envelope[8] |
                       ((DWORD)envelope[9] << 8) |
                       ((DWORD)envelope[10] << 16) |
                       ((DWORD)envelope[11] << 24);
    if (LOCAL_BLOB_HEADER_BYTES + LOCAL_BLOB_NONCE_BYTES + LOCAL_BLOB_TAG_BYTES + cipher_len != envelope_len) return FALSE;

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

static void write_u32_file(HANDLE h, DWORD v, BOOL *ok) {
    DWORD written = 0;
    if (!*ok) return;
    *ok = WriteFile(h, &v, sizeof(v), &written, NULL) && written == sizeof(v);
}

static void write_bytes_file(HANDLE h, const void *data, DWORD len, BOOL *ok) {
    DWORD written = 0;
    if (!*ok) return;
    *ok = WriteFile(h, data, len, &written, NULL) && written == len;
}

static BOOL read_u32_mem(const BYTE **p, const BYTE *end, DWORD *out) {
    if ((size_t)(end - *p) < sizeof(DWORD)) return FALSE;
    CopyMemory(out, *p, sizeof(DWORD));
    *p += sizeof(DWORD);
    return TRUE;
}

static BOOL read_bytes_mem(const BYTE **p, const BYTE *end, void *out, DWORD len) {
    if ((size_t)(end - *p) < len) return FALSE;
    CopyMemory(out, *p, len);
    *p += len;
    return TRUE;
}

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

static BOOL prepend_archive_text(const KEY_PROFILE *profile, const WCHAR *plain, WCHAR *err, size_t err_cch) {
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

    DWORD total = (DWORD)record_len + old_len;
    BYTE *merged = (BYTE *)xalloc(total ? total : 1);
    if (!merged) {
        secure_free_str(record_utf8);
        secure_free(old, old_len);
        set_error(err, err_cch, L"");
        return FALSE;
    }
    CopyMemory(merged, record_utf8, (DWORD)record_len);
    if (old && old_len) CopyMemory(merged + record_len, old, old_len);
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
    secure_free_wide(archive);
}

static void do_archive(HWND hwnd) {
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
        return;
    }
    WCHAR err[256] = L"";
    if (!prepend_archive_text(&g_profiles[g_active_profile], plain, err, ARRAYSIZE(err))) {
        secure_free_wide(plain);
        show_error(hwnd, err[0] ? err : L"");
        return;
    }
    secure_free_wide(plain);
    show_archive_for_active_profile();
}

static void set_busy_controls(BOOL busy) {
    BOOL enable = !busy;
    if (g_main_window && IsWindow(g_main_window)) {
        HWND encrypt = GetDlgItem(g_main_window, IDC_ENCRYPT);
        EnableWindow(encrypt, TRUE);
        SetWindowTextW(encrypt, busy ? L"\u505c\u6b62" : L"\u52a0\u5bc6");
        EnableWindow(GetDlgItem(g_main_window, IDC_DECRYPT), enable);
        EnableWindow(GetDlgItem(g_main_window, IDC_CLEAR), enable);
        EnableWindow(GetDlgItem(g_main_window, IDC_KEY_SELECT), enable);
        EnableWindow(GetDlgItem(g_main_window, IDC_KEY_TRANSFER), enable);
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
                    } else {
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
    InitializeCriticalSection(&g_llm_worker.lock);
    g_llm_worker.lock_ready = TRUE;

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
        DeleteCriticalSection(&g_llm_worker.lock);
        return 1;
    }
    if (!activate_profile(g_active_profile, NULL, err, ARRAYSIZE(err))) {
        clear_all_profiles();
        MessageBoxW(NULL, err, APP_TITLE, MB_ICONERROR | MB_OK);
        DeleteCriticalSection(&g_llm_worker.lock);
        return 1;
    }
    if (!register_windows()) {
        if (g_crypto_ready) crypto_box_shutdown();
        clear_all_profiles();
        MessageBoxW(NULL, L"Window initialization failed.", APP_TITLE, MB_ICONERROR | MB_OK);
        DeleteCriticalSection(&g_llm_worker.lock);
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
        DeleteCriticalSection(&g_llm_worker.lock);
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

    shutdown_local_llm_worker();
    close_local_llm_job();
    if (g_crypto_ready) crypto_box_shutdown();
    clear_all_profiles();
    SecureZeroMemory(g_active_master_key, sizeof(g_active_master_key));
    if (g_ui_font) DeleteObject(g_ui_font);
    DeleteCriticalSection(&g_llm_worker.lock);
    return (int)msg.wParam;
}
