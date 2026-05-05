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

#include "app_archive.h"
#include "app_profiles.h"
#include "app_shared.h"
#include "app_storage.h"
#include <strsafe.h>
#include <stdint.h>
#include <stdlib.h>

static WCHAR *archive_dup_wide(const WCHAR *s) {
    size_t len = wcslen(s ? s : L"");
    if (len > SIZE_MAX / sizeof(WCHAR) - 1) return NULL;
    WCHAR *copy = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    if (copy) CopyMemory(copy, s ? s : L"", (len + 1) * sizeof(WCHAR));
    return copy;
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
        *out = archive_dup_wide(L"");
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
        *out = archive_dup_wide(L"");
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

BOOL archive_append_text(const KEY_PROFILE *profile, const WCHAR *plain, WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!profiles_get_archive_path(profile, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Archive path is not available.");
        return FALSE;
    }
    WCHAR *record = NULL;
    if (!build_archive_record(profile, plain, &record)) {
        set_error(err, err_cch, L"Failed to build archive record.");
        return FALSE;
    }
    char *record_utf8 = NULL;
    int record_len = 0;
    if (!wide_to_utf8(record, &record_utf8, &record_len)) {
        secure_free_wide(record);
        set_error(err, err_cch, L"Failed to encode archive record as UTF-8.");
        return FALSE;
    }
    secure_free_wide(record);

    BYTE *file = NULL;
    DWORD file_len = 0;
    BYTE *old = NULL;
    DWORD old_len = 0;
    BOOL archive_exists = file_exists_w(path);
    if (read_file_bytes(path, &file, &file_len)) {
        if (!local_aes_gcm_decrypt(profile->master_key, file, file_len, &old, &old_len)) {
            xfree(file);
            secure_free_str(record_utf8);
            set_error(err, err_cch, L"Archive file exists but could not be decrypted.");
            return FALSE;
        }
        xfree(file);
    } else if (archive_exists) {
        secure_free_str(record_utf8);
        set_error(err, err_cch, L"Archive file exists but could not be read.");
        return FALSE;
    }

    if (record_len < 0 || (DWORD)record_len > 0xffffffffu - old_len) {
        secure_free_str(record_utf8);
        secure_free(old, old_len);
        set_error(err, err_cch, L"Archive data is too large.");
        return FALSE;
    }
    DWORD total = old_len + (DWORD)record_len;
    BYTE *merged = (BYTE *)xalloc(total ? total : 1);
    if (!merged) {
        secure_free_str(record_utf8);
        secure_free(old, old_len);
        set_error(err, err_cch, L"Out of memory while updating archive.");
        return FALSE;
    }
    if (old && old_len) CopyMemory(merged, old, old_len);
    CopyMemory(merged + old_len, record_utf8, (DWORD)record_len);
    BYTE *protected_blob = NULL;
    DWORD protected_len = 0;
    BOOL ok = local_aes_gcm_encrypt(profile->master_key, merged, total, &protected_blob, &protected_len) &&
              write_file_bytes_atomic(path, protected_blob, protected_len);
    secure_free(protected_blob, protected_len);
    secure_free_str(record_utf8);
    secure_free(old, old_len);
    secure_free(merged, total);
    if (!ok) {
        set_error(err, err_cch, L"Failed to encrypt or write archive.");
        return FALSE;
    }
    return TRUE;
}

BOOL archive_load_text(const KEY_PROFILE *profile, WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    WCHAR path[MAX_PATH];
    if (!profiles_get_archive_path(profile, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Archive path is not available.");
        return FALSE;
    }
    BYTE *data = NULL;
    DWORD data_len = 0;
    if (!read_file_bytes(path, &data, &data_len)) {
        if (file_exists_w(path)) {
            set_error(err, err_cch, L"Archive file exists but could not be read.");
            return FALSE;
        }
        *out = archive_dup_wide(L"");
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
        set_error(err, err_cch, L"Archive file could not be decrypted or decoded.");
        return FALSE;
    }
    return TRUE;
}


