#ifndef CHINESE_INPUT_AGENT_APP_IMAGE_FEC_H
#define CHINESE_INPUT_AGENT_APP_IMAGE_FEC_H

#include <windows.h>
#include <stddef.h>

BOOL app_image_fec_params_for_robustness(int robustness_level,
                                         BYTE *data_bytes,
                                         BYTE *parity_bytes);
BOOL app_image_fec_encoded_len(DWORD packet_len,
                               BYTE data_bytes,
                               BYTE parity_bytes,
                               DWORD *out_len);
BOOL app_image_fec_encode(const BYTE *packet,
                          DWORD packet_len,
                          BYTE data_bytes,
                          BYTE parity_bytes,
                          BYTE **out,
                          DWORD *out_len,
                          WCHAR *err,
                          size_t err_cch);
BOOL app_image_fec_decode(const BYTE *encoded,
                          DWORD encoded_len,
                          DWORD packet_len,
                          BYTE data_bytes,
                          BYTE parity_bytes,
                          BYTE **out,
                          DWORD *out_len,
                          WCHAR *err,
                          size_t err_cch);

#endif
