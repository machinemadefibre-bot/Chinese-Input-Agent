#include "app_shared.h"
#include "app_constants.h"
#include "app_limits.h"
#include "app_paths.h"
#include <shlobj.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdarg.h>

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

void set_error(WCHAR *error_buffer, size_t cch, const WCHAR *fmt, ...) {
    if (!error_buffer || cch == 0) return;
    va_list args;
    va_start(args, fmt);
    StringCchVPrintfW(error_buffer, cch, fmt, args);
    va_end(args);
}

BOOL strb_reserve(STRB *builder, size_t extra) {
    if (!builder) return FALSE;
    if (builder->len > SIZE_MAX - 1 || extra > SIZE_MAX - builder->len - 1) return FALSE;
    size_t need = builder->len + extra + 1;
    if (need <= builder->cap) return TRUE;
    size_t cap = builder->cap ? builder->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    char *p = (char *)xrealloc(builder->data, cap);
    if (!p) return FALSE;
    builder->data = p;
    builder->cap = cap;
    return TRUE;
}

BOOL strb_append_n(STRB *builder, const char *s, size_t n) {
    if (!builder || (!s && n)) return FALSE;
    if (!strb_reserve(builder, n)) return FALSE;
    CopyMemory(builder->data + builder->len, s, n);
    builder->len += n;
    builder->data[builder->len] = '\0';
    return TRUE;
}

BOOL strb_append(STRB *builder, const char *s) {
    return strb_append_n(builder, s ? s : "", s ? strlen(s) : 0);
}

BOOL strb_appendf(STRB *builder, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = _vscprintf(fmt, args);
    va_end(args);
    if (needed < 0) return FALSE;
    if (!strb_reserve(builder, (size_t)needed)) return FALSE;
    va_start(args, fmt);
    vsnprintf(builder->data + builder->len, builder->cap - builder->len, fmt, args);
    va_end(args);
    builder->len += (size_t)needed;
    return TRUE;
}

void strb_free(STRB *builder) {
    xfree(builder->data);
    ZeroMemory(builder, sizeof(*builder));
}

void strb_secure_free(STRB *builder) {
    secure_free(builder->data, builder->cap);
    ZeroMemory(builder, sizeof(*builder));
}

BOOL wstrb_reserve(WSTRB *builder, size_t extra) {
    if (!builder) return FALSE;
    if (builder->len > SIZE_MAX - 1 || extra > SIZE_MAX - builder->len - 1) return FALSE;
    size_t need = builder->len + extra + 1;
    if (need <= builder->cap) return TRUE;
    size_t cap = builder->cap ? builder->cap : 128;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    if (cap > SIZE_MAX / sizeof(WCHAR)) return FALSE;
    WCHAR *p = (WCHAR *)xrealloc(builder->data, cap * sizeof(WCHAR));
    if (!p) return FALSE;
    builder->data = p;
    builder->cap = cap;
    return TRUE;
}

BOOL wstrb_append_n(WSTRB *builder, const WCHAR *s, size_t n) {
    if (!builder || (!s && n)) return FALSE;
    if (!wstrb_reserve(builder, n)) return FALSE;
    CopyMemory(builder->data + builder->len, s, n * sizeof(WCHAR));
    builder->len += n;
    builder->data[builder->len] = L'\0';
    return TRUE;
}

BOOL wstrb_append(WSTRB *builder, const WCHAR *s) {
    return wstrb_append_n(builder, s ? s : L"", s ? wcslen(s) : 0);
}

BOOL wstrb_append_char(WSTRB *builder, WCHAR ch) {
    return wstrb_append_n(builder, &ch, 1);
}

BOOL wstrb_appendf(WSTRB *builder, const WCHAR *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int needed = _vscwprintf(fmt, args);
    va_end(args);
    if (needed < 0) return FALSE;
    if (!wstrb_reserve(builder, (size_t)needed)) return FALSE;
    va_start(args, fmt);
    vswprintf(builder->data + builder->len, builder->cap - builder->len, fmt, args);
    va_end(args);
    builder->len += (size_t)needed;
    return TRUE;
}

void wstrb_free(WSTRB *builder) {
    xfree(builder->data);
    ZeroMemory(builder, sizeof(*builder));
}

void wstrb_secure_free(WSTRB *builder) {
    secure_free(builder->data, builder->cap * sizeof(WCHAR));
    ZeroMemory(builder, sizeof(*builder));
}

BOOL wide_to_utf8(const WCHAR *ws, char **out, int *out_len) {
    *out = NULL;
    if (out_len) *out_len = 0;
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws ? ws : L"", -1, NULL, 0, NULL, NULL);
    if (needed <= 0) return FALSE;
    char *utf8_buffer = (char *)xalloc((SIZE_T)needed);
    if (!utf8_buffer) return FALSE;
    if (!WideCharToMultiByte(CP_UTF8, 0, ws ? ws : L"", -1, utf8_buffer, needed, NULL, NULL)) {
        xfree(utf8_buffer);
        return FALSE;
    }
    *out = utf8_buffer;
    if (out_len) *out_len = needed - 1;
    return TRUE;
}

BOOL utf8_to_wide_n(const char *s, int len, WCHAR **out) {
    *out = NULL;
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, len, NULL, 0);
    if (needed <= 0) return FALSE;
    WCHAR *wide_buffer = (WCHAR *)xalloc(((SIZE_T)needed + 1) * sizeof(WCHAR));
    if (!wide_buffer) return FALSE;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, len, wide_buffer, needed)) {
        xfree(wide_buffer);
        return FALSE;
    }
    wide_buffer[needed] = L'\0';
    *out = wide_buffer;
    return TRUE;
}

BOOL append_json_escaped_wide(STRB *json_builder, const WCHAR *ws) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(ws, &utf8, &len)) return FALSE;
    BOOL append_succeeded = TRUE;
    for (int i = 0; i < len && append_succeeded; ++i) {
        unsigned char c = (unsigned char)utf8[i];
        switch (c) {
        case '\\': append_succeeded = strb_append(json_builder, "\\\\"); break;
        case '"': append_succeeded = strb_append(json_builder, "\\\""); break;
        case '\b': append_succeeded = strb_append(json_builder, "\\b"); break;
        case '\f': append_succeeded = strb_append(json_builder, "\\f"); break;
        case '\n': append_succeeded = strb_append(json_builder, "\\n"); break;
        case '\r': append_succeeded = strb_append(json_builder, "\\r"); break;
        case '\t': append_succeeded = strb_append(json_builder, "\\t"); break;
        default:
            if (c < 0x20) {
                append_succeeded = strb_appendf(json_builder, "\\u%04x", c);
            } else {
                append_succeeded = strb_append_n(json_builder, (const char *)&utf8[i], 1);
            }
            break;
        }
    }
    xfree(utf8);
    return append_succeeded;
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
    DWORD env_len = GetEnvironmentVariableW(APP_ENV_DATA_DIR, path, (DWORD)cch);
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
        if (SUCCEEDED(StringCchPrintfW(portable, ARRAYSIZE(portable), L"%s\\%s", exe, APP_PORTABLE_DATA_DIR_NAME)) &&
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
    return SUCCEEDED(StringCchPrintfW(out, cch, APP_WRAP_KEY_NAME_FORMAT,
                                     label ? label : APP_WRAP_KEY_DEFAULT_LABEL,
                                     (unsigned long long)fnv1a_path_hash(dir)));
}

BOOL read_file_bytes(const WCHAR *path, BYTE **out, DWORD *out_len) {
    *out = NULL;
    *out_len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 || size.QuadPart > APP_MAX_READ_FILE_BYTES) {
        CloseHandle(h);
        return FALSE;
    }
    BYTE *file_buffer = (BYTE *)xalloc((SIZE_T)size.QuadPart);
    if (!file_buffer) {
        CloseHandle(h);
        return FALSE;
    }
    DWORD read = 0;
    BOOL read_succeeded = ReadFile(h, file_buffer, (DWORD)size.QuadPart, &read, NULL) && read == (DWORD)size.QuadPart;
    CloseHandle(h);
    if (!read_succeeded) {
        xfree(file_buffer);
        return FALSE;
    }
    *out = file_buffer;
    *out_len = read;
    return TRUE;
}

BOOL write_file_bytes(const WCHAR *path, const BYTE *bytes, DWORD len) {
    if (!path || !path[0] || (!bytes && len)) return FALSE;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL write_succeeded = WriteFile(h, bytes, len, &written, NULL) && written == len;
    CloseHandle(h);
    return write_succeeded;
}

BOOL write_file_bytes_atomic(const WCHAR *path, const BYTE *bytes, DWORD len) {
    if (!path || !path[0] || (!bytes && len)) return FALSE;

    WCHAR target_dir[MAX_PATH];
    WCHAR temp_path[MAX_PATH];
    if (FAILED(StringCchCopyW(target_dir, ARRAYSIZE(target_dir), path))) return FALSE;
    strip_last_path_component(target_dir);
    if (!target_dir[0]) return FALSE;
    if (!GetTempFileNameW(target_dir, APP_TEMP_FILE_PREFIX, 0, temp_path)) return FALSE;

    HANDLE h = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DeleteFileW(temp_path);
        return FALSE;
    }

    DWORD written = 0;
    BOOL temp_file_written = WriteFile(h, bytes, len, &written, NULL) && written == len && FlushFileBuffers(h);
    CloseHandle(h);
    BOOL replace_succeeded = temp_file_written;
    if (replace_succeeded) {
        replace_succeeded = MoveFileExW(temp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (!replace_succeeded) DeleteFileW(temp_path);
    return replace_succeeded;
}

BOOL write_text_utf8_file(const WCHAR *path, const WCHAR *text) {
    char *utf8 = NULL;
    int len = 0;
    if (!wide_to_utf8(text ? text : L"", &utf8, &len)) return FALSE;
    BOOL write_succeeded = write_file_bytes(path, (const BYTE *)utf8, (DWORD)len);
    secure_free(utf8, (SIZE_T)len + 1);
    return write_succeeded;
}

BOOL read_utf8_text_file(const WCHAR *path, WCHAR **out) {
    *out = NULL;
    BYTE *utf8_bytes = NULL;
    DWORD len = 0;
    if (!read_file_bytes(path, &utf8_bytes, &len)) return FALSE;
    BOOL decode_succeeded = utf8_to_wide_n((const char *)utf8_bytes, (int)len, out);
    secure_free(utf8_bytes, len);
    return decode_succeeded;
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
    if (!join_path(tools, ARRAYSIZE(tools), root, APP_WORKER_TOOLS_DIR)) return FALSE;
    if (!join_path(worker, worker_cch, tools, APP_WORKER_EXE_NAME) || !file_exists_w(worker)) return FALSE;
    if (FAILED(StringCchCopyW(workdir, workdir_cch, tools))) return FALSE;
    if (python && python_cch) python[0] = L'\0';
    return TRUE;
}

static BOOL find_native_worker_at_dir(const WCHAR *dir,
                                      WCHAR *worker, size_t worker_cch,
                                      WCHAR *workdir, size_t workdir_cch,
                                      WCHAR *python, size_t python_cch) {
    if (!join_path(worker, worker_cch, dir, APP_WORKER_EXE_NAME) || !file_exists_w(worker)) return FALSE;
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
    if (join_path(packaged_worker, ARRAYSIZE(packaged_worker), candidate, APP_WORKER_PACKAGE_DIR_NAME) &&
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
    WCHAR generated_path[MAX_PATH];
    if (!GetTempFileNameW(dir, APP_TEMP_FILE_PREFIX, 0, generated_path)) return FALSE;
    return SUCCEEDED(StringCchCopyW(path, cch, generated_path));
}

void secure_delete_file(const WCHAR *path) {
    if (!path || !path[0]) return;
    HANDLE h = CreateFileW(path, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        if (GetFileSizeEx(h, &size) && size.QuadPart > 0 && size.QuadPart <= APP_SECURE_DELETE_MAX_BYTES) {
            BYTE zeros[APP_SECURE_DELETE_BUFFER_BYTES];
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
        if (len > APP_PROCESS_LOG_TAIL_CHARS) tail = log + len - APP_PROCESS_LOG_TAIL_CHARS;
        set_error(err, err_cch, L"%s: %s", prefix, tail);
        secure_free_wide(log);
        return TRUE;
    }
    secure_free_wide(log);
    return FALSE;
}

BOOL write_all_handle(HANDLE h, const void *bytes, DWORD len) {
    const BYTE *cursor = (const BYTE *)bytes;
    DWORD left = len;
    while (left > 0) {
        DWORD written = 0;
        if (!WriteFile(h, cursor, left, &written, NULL) || written == 0) return FALSE;
        cursor += written;
        left -= written;
    }
    return TRUE;
}
