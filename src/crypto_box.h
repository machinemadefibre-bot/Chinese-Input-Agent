#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL crypto_box_init(const BYTE master_key[32], const WCHAR *state_path, WCHAR *err, size_t err_cch);
void crypto_box_shutdown(void);

BOOL crypto_box_encrypt(const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch);
BOOL crypto_box_decrypt(const BYTE *message, DWORD message_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch);
BOOL crypto_box_get_public_key(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_get_remote_public_key(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_get_public_fingerprint(WCHAR *out, size_t cch, WCHAR *err, size_t err_cch);
BOOL crypto_box_contact_package_fingerprint(const BYTE *pkg, DWORD pkg_len, WCHAR *out, size_t cch,
                                            WCHAR *err, size_t err_cch);
BOOL crypto_box_prepare_key_export(WCHAR *err, size_t err_cch);
BOOL crypto_box_export_contact_package(BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_import_contact_package(const BYTE *pkg, DWORD pkg_len, WCHAR *err, size_t err_cch);

#ifdef __cplusplus
}
#endif

#endif
