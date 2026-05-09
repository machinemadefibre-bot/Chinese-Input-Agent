#include "cia_platform_windows.h"

#include <bcrypt.h>
#include <strsafe.h>
#include <wincrypt.h>
#include <wchar.h>

static void *platform_alloc(SIZE_T bytes) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes ? bytes : 1);
}

static void strip_last_path_component(WCHAR *path) {
    if (!path) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) path[--len] = L'\0';
    WCHAR *last_backslash = wcsrchr(path, L'\\');
    WCHAR *last_slash = wcsrchr(path, L'/');
    WCHAR *last = last_backslash > last_slash ? last_backslash : last_slash;
    if (last) *last = L'\0';
}

BOOL cia_win_random_bytes(BYTE *out, DWORD len) {
    if (!out && len) return FALSE;
    return BCryptGenRandom(NULL, out, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

void cia_win_secure_zero(void *ptr, size_t bytes) {
    if (ptr && bytes) SecureZeroMemory(ptr, bytes);
}

BOOL cia_win_write_file_bytes_atomic(const WCHAR *path, const BYTE *bytes, DWORD len) {
    if (!path || !path[0] || (!bytes && len)) return FALSE;
    static const WCHAR temp_prefix[] = L"cia";

    WCHAR target_dir[MAX_PATH];
    WCHAR temp_path[MAX_PATH];
    if (FAILED(StringCchCopyW(target_dir, ARRAYSIZE(target_dir), path))) return FALSE;
    strip_last_path_component(target_dir);
    if (!target_dir[0]) return FALSE;
    if (!GetTempFileNameW(target_dir, temp_prefix, 0, temp_path)) return FALSE;

    HANDLE h = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DeleteFileW(temp_path);
        return FALSE;
    }
    DWORD written = 0;
    BOOL temp_file_written = WriteFile(h, bytes, len, &written, NULL) && written == len && FlushFileBuffers(h);
    CloseHandle(h);
    BOOL replace_succeeded = FALSE;
    if (temp_file_written) {
        replace_succeeded = MoveFileExW(temp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (!replace_succeeded) DeleteFileW(temp_path);
    return replace_succeeded;
}

BOOL cia_win_dpapi_protect(const BYTE *plain, DWORD plain_len,
                           const WCHAR *description,
                           const BYTE *entropy, DWORD entropy_len,
                           BYTE **out, DWORD *out_len) {
    if (!out || !out_len || (!plain && plain_len) || (!entropy && entropy_len)) return FALSE;
    *out = NULL;
    *out_len = 0;
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    DATA_BLOB entropy_blob;
    DATA_BLOB *entropy_ptr = NULL;
    in_blob.pbData = (BYTE *)plain;
    in_blob.cbData = plain_len;
    if (entropy) {
        entropy_blob.pbData = (BYTE *)entropy;
        entropy_blob.cbData = entropy_len;
        entropy_ptr = &entropy_blob;
    }
    ZeroMemory(&out_blob, sizeof(out_blob));
    if (!CryptProtectData(&in_blob, description, entropy_ptr, NULL, NULL, 0, &out_blob)) {
        return FALSE;
    }
    BYTE *copy = (BYTE *)platform_alloc(out_blob.cbData);
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

BOOL cia_win_dpapi_unprotect(const BYTE *blob, DWORD blob_len,
                             const BYTE *entropy, DWORD entropy_len,
                             BYTE **out, DWORD *out_len) {
    if (!out || !out_len || (!blob && blob_len) || (!entropy && entropy_len)) return FALSE;
    *out = NULL;
    *out_len = 0;
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    DATA_BLOB entropy_blob;
    DATA_BLOB *entropy_ptr = NULL;
    in_blob.pbData = (BYTE *)blob;
    in_blob.cbData = blob_len;
    if (entropy) {
        entropy_blob.pbData = (BYTE *)entropy;
        entropy_blob.cbData = entropy_len;
        entropy_ptr = &entropy_blob;
    }
    ZeroMemory(&out_blob, sizeof(out_blob));
    if (!CryptUnprotectData(&in_blob, NULL, entropy_ptr, NULL, NULL, 0, &out_blob)) {
        return FALSE;
    }
    BYTE *copy = (BYTE *)platform_alloc(out_blob.cbData);
    if (!copy) {
        cia_win_secure_zero(out_blob.pbData, out_blob.cbData);
        LocalFree(out_blob.pbData);
        return FALSE;
    }
    CopyMemory(copy, out_blob.pbData, out_blob.cbData);
    *out = copy;
    *out_len = out_blob.cbData;
    cia_win_secure_zero(out_blob.pbData, out_blob.cbData);
    LocalFree(out_blob.pbData);
    return TRUE;
}
