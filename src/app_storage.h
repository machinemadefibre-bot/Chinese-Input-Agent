#ifndef CHINESE_INPUT_AGENT_APP_STORAGE_H
#define CHINESE_INPUT_AGENT_APP_STORAGE_H

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
#include <stddef.h>

#define APP_STORAGE_MASTER_KEY_BYTES 32
#define APP_STORAGE_LOCAL_BLOB_HEADER_BYTES 12
#define APP_STORAGE_LOCAL_BLOB_NONCE_BYTES 12
#define APP_STORAGE_LOCAL_BLOB_TAG_BYTES 16

BOOL dpapi_protect(const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len);
BOOL dpapi_unprotect(const BYTE *blob, DWORD blob_len, BYTE **out, DWORD *out_len);
BOOL local_aes_gcm_encrypt(const BYTE key[APP_STORAGE_MASTER_KEY_BYTES], const BYTE *plain, DWORD plain_len,
                           BYTE **out, DWORD *out_len);
BOOL local_aes_gcm_decrypt(const BYTE key[APP_STORAGE_MASTER_KEY_BYTES], const BYTE *envelope, DWORD envelope_len,
                           BYTE **out, DWORD *out_len);
BOOL read_u32_mem(const BYTE **p, const BYTE *end, DWORD *out);
BOOL read_bytes_mem(const BYTE **p, const BYTE *end, void *out, DWORD len);

#endif
