#ifndef CHINESE_INPUT_AGENT_APP_CARRIER_FLOW_H
#define CHINESE_INPUT_AGENT_APP_CARRIER_FLOW_H

#include <windows.h>
#include <stddef.h>

#include "app_flow.h"
#include "crypto_box.h"

BOOL app_carrier_extract_exchange_body(const WCHAR *text, APP_FLOW_EXCHANGE_KIND *kind_out,
                                       WCHAR **out, WCHAR *fingerprint, size_t fingerprint_cch,
                                       WCHAR *err, size_t err_cch);
BOOL app_carrier_extract_contact_package_body(const WCHAR *text, WCHAR **out,
                                              WCHAR *fingerprint, size_t fingerprint_cch,
                                              WCHAR *err, size_t err_cch);
BOOL app_carrier_encode_contact_package(const BYTE *pkg, DWORD pkg_len, const WCHAR *fingerprint,
                                        HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_carrier_encode_group_package(const BYTE *pkg, DWORD pkg_len, const WCHAR *fingerprint,
                                      HWND progress_target, WCHAR **out, WCHAR *err, size_t err_cch);
BOOL app_carrier_decode_exchange_package(const WCHAR *carrier, BYTE **out, DWORD *out_len,
                                         WCHAR *err, size_t err_cch);
BOOL app_carrier_get_message_seed(CRYPTO_BOX *box, WCHAR *seed, size_t seed_cch,
                                  BOOL prefer_remote, WCHAR *err, size_t err_cch);
BOOL app_carrier_encode_message_payload(const BYTE *payload, DWORD payload_len,
                                        const WCHAR *seed, const WCHAR *topic,
                                        HWND progress_target, WCHAR **out,
                                        WCHAR *err, size_t err_cch);
BOOL app_carrier_decode_message_payload(const WCHAR *carrier, const WCHAR *seed,
                                        BYTE **out, DWORD *out_len,
                                        WCHAR *err, size_t err_cch);

#endif
