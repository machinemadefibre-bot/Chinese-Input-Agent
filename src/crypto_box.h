#ifndef CRYPTO_BOX_H
#define CRYPTO_BOX_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CRYPTO_BOX CRYPTO_BOX;

BOOL crypto_box_open(const BYTE master_key[32], const WCHAR *state_path, CRYPTO_BOX **out,
                     WCHAR *err, size_t err_cch);
void crypto_box_close(CRYPTO_BOX *box);

BOOL crypto_box_encrypt(CRYPTO_BOX *box, const BYTE *plain, DWORD plain_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch);
BOOL crypto_box_decrypt(CRYPTO_BOX *box, const BYTE *message, DWORD message_len, BYTE **out, DWORD *out_len,
                        WCHAR *err, size_t err_cch);
BOOL crypto_box_get_public_key(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_get_remote_public_key(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_get_public_fingerprint(CRYPTO_BOX *box, WCHAR *out, size_t cch, WCHAR *err, size_t err_cch);
BOOL crypto_box_contact_package_fingerprint(const BYTE *pkg, DWORD pkg_len, WCHAR *out, size_t cch,
                                            WCHAR *err, size_t err_cch);
BOOL crypto_box_contact_package_recipient_public(const BYTE *pkg, DWORD pkg_len, BYTE recipient[32],
                                                 BOOL *has_recipient, WCHAR *err, size_t err_cch);
BOOL crypto_box_prepare_key_export(CRYPTO_BOX *box, WCHAR *err, size_t err_cch);
BOOL crypto_box_export_contact_package(CRYPTO_BOX *box, BYTE **out, DWORD *out_len, WCHAR *err, size_t err_cch);
BOOL crypto_box_import_contact_package(CRYPTO_BOX *box, const BYTE *pkg, DWORD pkg_len,
                                       WCHAR *err, size_t err_cch);

#ifdef __cplusplus
}
#endif

#endif
