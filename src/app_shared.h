#ifndef CHINESE_INPUT_AGENT_APP_SHARED_H
#define CHINESE_INPUT_AGENT_APP_SHARED_H

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
#include <strsafe.h>
#include <stdint.h>
#include <stddef.h>

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

void *xalloc(SIZE_T bytes);
void *xrealloc(void *ptr, SIZE_T bytes);
void xfree(void *ptr);
void secure_free(void *ptr, SIZE_T bytes);
void secure_free_wide(WCHAR *ptr);
void secure_free_str(char *ptr);
void set_error(WCHAR *buf, size_t cch, const WCHAR *fmt, ...);

BOOL strb_reserve(STRB *b, size_t extra);
BOOL strb_append_n(STRB *b, const char *s, size_t n);
BOOL strb_append(STRB *b, const char *s);
BOOL strb_appendf(STRB *b, const char *fmt, ...);
void strb_free(STRB *b);
void strb_secure_free(STRB *b);

BOOL wstrb_reserve(WSTRB *b, size_t extra);
BOOL wstrb_append_n(WSTRB *b, const WCHAR *s, size_t n);
BOOL wstrb_append(WSTRB *b, const WCHAR *s);
BOOL wstrb_append_char(WSTRB *b, WCHAR ch);
BOOL wstrb_appendf(WSTRB *b, const WCHAR *fmt, ...);
void wstrb_free(WSTRB *b);
void wstrb_secure_free(WSTRB *b);

BOOL wide_to_utf8(const WCHAR *ws, char **out, int *out_len);
BOOL utf8_to_wide_n(const char *s, int len, WCHAR **out);
BOOL append_json_escaped_wide(STRB *b, const WCHAR *ws);

void strip_last_path_component_early(WCHAR *path);
BOOL get_app_dir(WCHAR *path, size_t cch);
BOOL get_app_file(WCHAR *path, size_t cch, const WCHAR *name);
BOOL get_scoped_wrap_key_name(const WCHAR *label, WCHAR *out, size_t cch);
BOOL read_file_bytes(const WCHAR *path, BYTE **out, DWORD *out_len);
BOOL write_file_bytes(const WCHAR *path, const BYTE *data, DWORD len);
BOOL write_file_bytes_atomic(const WCHAR *path, const BYTE *data, DWORD len);
BOOL write_text_utf8_file(const WCHAR *path, const WCHAR *text);
BOOL read_utf8_text_file(const WCHAR *path, WCHAR **out);
BOOL file_exists_w(const WCHAR *path);
BOOL dir_exists_w(const WCHAR *path);
void strip_last_path_component(WCHAR *path);
BOOL join_path(WCHAR *out, size_t cch, const WCHAR *base, const WCHAR *leaf);
BOOL find_local_worker(WCHAR *script, size_t script_cch, WCHAR *workdir, size_t workdir_cch,
                       WCHAR *python, size_t python_cch, WCHAR *err, size_t err_cch);
BOOL make_temp_path(WCHAR *path, size_t cch);
void secure_delete_file(const WCHAR *path);
BOOL append_quoted_arg(WSTRB *cmd, const WCHAR *arg);
BOOL append_process_log(WCHAR *err, size_t err_cch, const WCHAR *prefix, const WCHAR *log_path);
BOOL write_all_handle(HANDLE h, const void *data, DWORD len);

#endif
