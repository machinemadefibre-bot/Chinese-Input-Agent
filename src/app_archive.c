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
static BOOL build_archive_record(const KEY_PROFILE *profile, const WCHAR *sender,
                                 const WCHAR *plain, WCHAR **out) {
    *out = NULL;
    SYSTEMTIME st;
    GetLocalTime(&st);
    const WCHAR *display_sender = sender && sender[0] ? sender :
        (profile && profile->name[0] ? profile->name : L"\u672a\u547d\u540d");
    WSTRB record_builder = {0};
    if (!wstrb_appendf(&record_builder, L"[%04u-%02u-%02u %02u:%02u:%02u] \u53d1\u9001\u4eba\uff1a%s\r\n",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                       display_sender) ||
        !wstrb_append(&record_builder, plain ? plain : L"")) {
        wstrb_secure_free(&record_builder);
        return FALSE;
    }
    size_t len = wcslen(plain ? plain : L"");
    if (len == 0 || (plain[len - 1] != L'\n' && plain[len - 1] != L'\r')) {
        if (!wstrb_append(&record_builder, L"\r\n")) {
            wstrb_secure_free(&record_builder);
            return FALSE;
        }
    }
    if (!wstrb_append(&record_builder, L"\r\n")) {
        wstrb_secure_free(&record_builder);
        return FALSE;
    }
    *out = record_builder.data;
    record_builder.data = NULL;
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

static int compare_archive_blocks(const void *left, const void *right) {
    const ARCHIVE_BLOCK *left_block = (const ARCHIVE_BLOCK *)left;
    const ARCHIVE_BLOCK *right_block = (const ARCHIVE_BLOCK *)right;
    int cmp = wcscmp(left_block->stamp, right_block->stamp);
    if (cmp != 0) return cmp;
    if (left_block->index < right_block->index) return -1;
    if (left_block->index > right_block->index) return 1;
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

    BOOL sort_output_built = FALSE;
    WSTRB sorted_archive_builder = {0};
    p = text;
    size_t block_idx = 0;
    while (*p && block_idx < count) {
        size_t n = 0;
        const WCHAR *next = find_archive_record_end(p, &n);
        if (n > 0) {
            blocks[block_idx].text = (WCHAR *)xalloc((n + 1) * sizeof(WCHAR));
            if (!blocks[block_idx].text) goto cleanup;
            CopyMemory(blocks[block_idx].text, p, n * sizeof(WCHAR));
            blocks[block_idx].text[n] = L'\0';
            blocks[block_idx].index = block_idx;
            if (n >= 21 && p[0] == L'[' && p[20] == L']') {
                CopyMemory(blocks[block_idx].stamp, p, 21 * sizeof(WCHAR));
                blocks[block_idx].stamp[21] = L'\0';
            } else {
                StringCchPrintfW(blocks[block_idx].stamp, ARRAYSIZE(blocks[block_idx].stamp), L"~%08zu", block_idx);
            }
            ++block_idx;
        }
        p = next;
    }

    qsort(blocks, count, sizeof(ARCHIVE_BLOCK), compare_archive_blocks);
    for (size_t block_idx = 0; block_idx < count; ++block_idx) {
        if (!wstrb_append(&sorted_archive_builder, blocks[block_idx].text ? blocks[block_idx].text : L"")) goto cleanup;
    }
    *out = sorted_archive_builder.data;
    sorted_archive_builder.data = NULL;
    sort_output_built = TRUE;

cleanup:
    wstrb_secure_free(&sorted_archive_builder);
    for (size_t block_idx = 0; block_idx < count; ++block_idx) secure_free_wide(blocks[block_idx].text);
    xfree(blocks);
    return sort_output_built;
}

BOOL archive_append_text(const KEY_PROFILE *profile, const WCHAR *sender, const WCHAR *plain,
                         WCHAR *err, size_t err_cch) {
    WCHAR path[MAX_PATH];
    if (!profiles_get_archive_path(profile, path, ARRAYSIZE(path))) {
        set_error(err, err_cch, L"Archive path is not available.");
        return FALSE;
    }
    WCHAR *record = NULL;
    if (!build_archive_record(profile, sender, plain, &record)) {
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
    BOOL archive_write_succeeded = local_aes_gcm_encrypt(profile->master_key, merged, total, &protected_blob, &protected_len) &&
                                   write_file_bytes_atomic(path, protected_blob, protected_len);
    secure_free(protected_blob, protected_len);
    secure_free_str(record_utf8);
    secure_free(old, old_len);
    secure_free(merged, total);
    if (!archive_write_succeeded) {
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
    BYTE *archive_blob = NULL;
    DWORD archive_blob_len = 0;
    if (!read_file_bytes(path, &archive_blob, &archive_blob_len)) {
        if (file_exists_w(path)) {
            set_error(err, err_cch, L"Archive file exists but could not be read.");
            return FALSE;
        }
        *out = archive_dup_wide(L"");
        return *out != NULL;
    }
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    BOOL archive_decoded = local_aes_gcm_decrypt(profile->master_key, archive_blob, archive_blob_len, &plain, &plain_len) &&
                           utf8_to_wide_n((const char *)plain, (int)plain_len, out);
    if (archive_decoded) {
        WCHAR *ordered = NULL;
        if (archive_text_oldest_first(*out, &ordered)) {
            secure_free_wide(*out);
            *out = ordered;
        }
    }
    xfree(archive_blob);
    secure_free(plain, plain_len);
    if (!archive_decoded) {
        set_error(err, err_cch, L"Archive file could not be decrypted or decoded.");
        return FALSE;
    }
    return TRUE;
}


