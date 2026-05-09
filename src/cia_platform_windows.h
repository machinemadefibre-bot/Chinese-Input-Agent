#ifndef CHINESE_INPUT_AGENT_CIA_PLATFORM_WINDOWS_H
#define CHINESE_INPUT_AGENT_CIA_PLATFORM_WINDOWS_H

#include <windows.h>
#include <stddef.h>

/*
 * Narrow Windows platform boundary for non-UI OS services.
 * CNG/NCrypt/Crypt32 are platform dependencies, not UI dependencies.
 */

BOOL cia_win_random_bytes(BYTE *out, DWORD len);
void cia_win_secure_zero(void *ptr, size_t bytes);

BOOL cia_win_write_file_bytes_atomic(const WCHAR *path, const BYTE *bytes, DWORD len);

/*
 * DPAPI wrappers allocate output on the process heap so existing xfree /
 * secure_free callers can release it. Optional entropy may be NULL.
 */
BOOL cia_win_dpapi_protect(const BYTE *plain, DWORD plain_len,
                           const WCHAR *description,
                           const BYTE *entropy, DWORD entropy_len,
                           BYTE **out, DWORD *out_len);
BOOL cia_win_dpapi_unprotect(const BYTE *blob, DWORD blob_len,
                             const BYTE *entropy, DWORD entropy_len,
                             BYTE **out, DWORD *out_len);

#endif
