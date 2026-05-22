#ifndef CHINESE_INPUT_AGENT_APP_IMAGE_STEGO_H
#define CHINESE_INPUT_AGENT_APP_IMAGE_STEGO_H

#include <windows.h>
#include <stddef.h>

typedef struct IMAGE_STEGO_DCT_OPTIONS {
    int target_short_side;
    int jpeg_quality;
    int robustness_level;
    int secret_quality_mode;
} IMAGE_STEGO_DCT_OPTIONS;

void image_stego_options_defaults(IMAGE_STEGO_DCT_OPTIONS *options);
BOOL app_image_stego_dct_capacity(const WCHAR *jpeg_path,
                                  const BYTE locator_key[32],
                                  const IMAGE_STEGO_DCT_OPTIONS *options,
                                  size_t *payload_byte_capacity,
                                  WCHAR *err, size_t err_cch);
BOOL app_image_stego_dct_embed(const WCHAR *cover_jpeg_path,
                               const BYTE *encrypted_packet, DWORD encrypted_packet_len,
                               const BYTE locator_key[32],
                               const IMAGE_STEGO_DCT_OPTIONS *options,
                               const WCHAR *out_jpeg_path,
                               WCHAR *err, size_t err_cch);
BOOL app_image_stego_dct_extract(const WCHAR *jpeg_path,
                                 const BYTE locator_key[32],
                                 BYTE **out_encrypted_packet, DWORD *out_encrypted_packet_len,
                                 WCHAR *err, size_t err_cch);

#endif
