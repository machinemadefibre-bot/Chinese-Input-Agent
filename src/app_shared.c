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

#include "app_shared.h"
#include <shlobj.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdarg.h>

#define APP_DIR_NAME L"ChineseInputAgent"

void *xalloc(SIZE_T bytes) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes ? bytes : 1);
}

void *xrealloc(void *ptr, SIZE_T bytes) {
    if (!ptr) return xalloc(bytes);
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, bytes ? bytes : 1);
}

void xfree(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

void secure_free(void *ptr, SIZE_T bytes) {
    if (ptr) {
        SecureZeroMemory(ptr, bytes);
        xfree(ptr);
    }
}

void secure_free_wide(WCHAR *ptr) {
    if (ptr) secure_free(ptr, (wcslen(ptr) + 1) * sizeof(WCHAR));
}

void secure_free_str(char *ptr) {
    if (ptr) secure_free(ptr, strlen(ptr) + 1);
}

void set_error(WCHAR *buf, size_t cch, const WCHAR *fmt, ...) {
    if (!buf || cch == 0) return;
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(buf, cch, fmt, args);
    va_end(args);
}

BOOL strb_reserve(STRB *b, size_t extra) {
    if (!b) return FALSE;
    if (b->len > SIZE_MAX - 1 || extra > SIZE_MAX - b->len - 1) return FALSE;
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return TRUE;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    char *p = (char *)xrealloc(b->data, cap);
    if (!p) return FALSE;
    b->data = p;
    b->cap = cap;
    return TRUE;
}

BOOL strb_append_n(STRB *b, const char *s, size_t n) {
    if (!b || (!s && n)) return FALSE;
    if (!strb_reserve(b, n)) return FALSE;
    CopyMemory(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return TRUE;
}

BOOL strb_append(STRB *b, const char *s) {
    return strb_append_n(b, s ? s : "", s ? strlen(s) : 0);
}

BOOL strb_appendf(STRB *b, const char *fmt, ...) {
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

void strb_free(STRB *b) {
    xfree(b->data);
    ZeroMemory(b, sizeof(*b));
}

void strb_secure_free(STRB *b) {
    secure_free(b->data, b->cap);
    ZeroMemory(b, sizeof(*b));
}

BOOL wstrb_reserve(WSTRB *b, size_t extra) {
    if (!b) return FALSE;
    if (b->len > SIZE_MAX - 1 || extra > SIZE_MAX - b->len - 1) return FALSE;
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return TRUE;
    size_t cap = b->cap ? b->cap : 128;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    if (cap > SIZE_MAX / sizeof(WCHAR)) return FALSE;
    WCHAR *p = (WCHAR *)xrealloc(b->data, cap * sizeof(WCHAR));
    if (!p) return FALSE;
    b->data = p;
    b->cap = cap;
    return TRUE;
}

BOOL wstrb_append_n(WSTRB *b, const WCHAR *s, size_t n) {
    if (!b || (!s && n)) return FALSE;
    if (!wstrb_reserve(b, n)) return FALSE;
    CopyMemory(b->data + b->len, s, n * sizeof(WCHAR));
    b->len += n;
    b->data[b->len] = L'\0';
    return TRUE;
}

BOOL wstrb_append(WSTRB *b, const WCHAR *s) {
    return wstrb_append_n(b, s ? s : L"", s ? wcslen(s) : 0);
}

BOOL wstrb_append_char(WSTRB *b, WCHAR ch) {
    return wstrb_append_n(b, &ch, 1);
}

BOOL wstrb_appendf(WSTRB *b, const WCHAR *fmt, ...) {
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

void wstrb_free(WSTRB *b) {
    xfree(b->data);
    ZeroMemory(b, sizeof(*b));
}

void wstrb_secure_free(WSTRB *b) {
    secure_free(b->data, b->cap * sizeof(WCHAR));
    ZeroMemory(b, sizeof(*b));
}

BOOL wide_to_utf8(const WCHAR *ws, char **out, int *out_len) {
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

BOOL utf8_to_wide_n(const char *s, int len, WCHAR **out) {
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

BOOL append_json_escaped_wide(STRB *b, const WCHAR *ws) {
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

void strip_last_path_component_early(WCHAR *path) {
    if (!path) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) path[--len] = L'\0';
    WCHAR *last1 = wcsrchr(path, L'\\');
    WCHAR *last2 = wcsrchr(path, L'/');
    WCHAR *last = last1 > last2 ? last1 : last2;
    if (last) *last = L'\0';
}

BOOL get_app_dir(WCHAR *path, size_t cch) {
    if (!path || cch == 0) return FALSE;
    WCHAR exe[MAX_PATH];
    DWORD env_len = GetEnvironmentVariableW(L"CIA_DATA_DIR", path, (DWORD)cch);
    if (env_len > 0) {
        if (env_len >= cch) {
            path[0] = L'\0';
            return FALSE;
        }
        if (dir_exists_w(path) || CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            return TRUE;
        }
        path[0] = L'\0';
        return FALSE;
    }

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
    path[0] = L'\0';
    return FALSE;
}

BOOL get_app_file(WCHAR *path, size_t cch, const WCHAR *name) {
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

BOOL get_scoped_wrap_key_name(const WCHAR *label, WCHAR *out, size_t cch) {
    WCHAR dir[MAX_PATH];
    if (!get_app_dir(dir, ARRAYSIZE(dir))) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"ChineseInputAgent %s %016llx",
                                     label ? label : L"Key",
                                     (unsigned long long)fnv1a_path_hash(dir)));
}

BOOL read_file_bytes(const WCHAR *path, BYTE **out, DWORD *out_len) {
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

BOOL write_file_bytes(const WCHAR *path, const BYTE *data, DWORD len) {
    if (!path || !path[0] || (!data && len)) return FALSE;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, len, &written, NULL) && written == len;
    CloseHandle(h);
    return ok;
}

BOOL write_file_bytes_atomic(const WCHAR *path, const BYTE *data, DWORD len) {
    if (!path || !path[0] || (!data && len)) return FALSE;

    WCHAR dir[MAX_PATH];
    WCHAR tmp[MAX_PATH];
    if (FAILED(StringCchCopyW(dir, ARRAYSIZE(dir), path))) return FALSE;
    strip_last_path_component(dir);
    if (!dir[0]) return FALSE;
    if (!GetTempFileNameW(dir, L"cia", 0, tmp)) return FALSE;

    HANDLE h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DeleteFileW(tmp);
        return FALSE;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(h, data, len, &written, NULL) && written == len && FlushFileBuffers(h);
    CloseHandle(h);
    if (ok) {
        ok = MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (!ok) DeleteFileW(tmp);
    return ok;
}

BOOL write_text_utf8_file(const WCHAR *path, const WCHAR *text) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(text ? text : L"", &utf8, &len)) return FALSE;
    BOOL ok = write_file_bytes(path, (const BYTE *)utf8, (DWORD)len);
    secure_free(utf8, (SIZE_T)len + 1);
    return ok;
}

BOOL read_utf8_text_file(const WCHAR *path, WCHAR **out) {
    *out = NULL;
    BYTE *data = NULL;
    DWORD len = 0;
    if (!read_file_bytes(path, &data, &len)) return FALSE;
    BOOL ok = utf8_to_wide_n((const char *)data, (int)len, out);
    secure_free(data, len);
    return ok;
}

BOOL file_exists_w(const WCHAR *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL dir_exists_w(const WCHAR *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

void strip_last_path_component(WCHAR *path) {
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

BOOL join_path(WCHAR *out, size_t cch, const WCHAR *base, const WCHAR *leaf) {
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

BOOL find_local_worker(WCHAR *script, size_t script_cch, WCHAR *workdir, size_t workdir_cch,
                              WCHAR *python, size_t python_cch, WCHAR *err, size_t err_cch) {
    WCHAR exe[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe))) {
        set_error(err, err_cch, L"Unable to locate the current executable path.");
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

BOOL make_temp_path(WCHAR *path, size_t cch) {
    WCHAR dir[MAX_PATH];
    if (!GetTempPathW(ARRAYSIZE(dir), dir)) return FALSE;
    WCHAR tmp[MAX_PATH];
    if (!GetTempFileNameW(dir, L"cia", 0, tmp)) return FALSE;
    return SUCCEEDED(StringCchCopyW(path, cch, tmp));
}

void secure_delete_file(const WCHAR *path) {
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
                DWORD chunk = (DWORD)((left > (LONGLONG)sizeof(zeros)) ? (LONGLONG)sizeof(zeros) : left);
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

BOOL append_quoted_arg(WSTRB *cmd, const WCHAR *arg) {
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

BOOL append_process_log(WCHAR *err, size_t err_cch, const WCHAR *prefix, const WCHAR *log_path) {
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

BOOL write_all_handle(HANDLE h, const void *data, DWORD len) {
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
