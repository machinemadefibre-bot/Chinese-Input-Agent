#ifndef CHINESE_INPUT_AGENT_APP_IMAGE_FLOW_H
#define CHINESE_INPUT_AGENT_APP_IMAGE_FLOW_H

#include <windows.h>

#include "app_image_stego.h"
#include "crypto_box.h"

BOOL app_image_flow_embed_private(CRYPTO_BOX *box,
                                  const WCHAR *cover_path,
                                  const WCHAR *secret_image_path,
                                  const IMAGE_STEGO_DCT_OPTIONS *options,
                                  const WCHAR *out_jpeg_path,
                                  WCHAR *err, size_t err_cch);

BOOL app_image_flow_embed_group(int group_index,
                                const WCHAR *cover_path,
                                const WCHAR *secret_image_path,
                                const IMAGE_STEGO_DCT_OPTIONS *options,
                                const WCHAR *out_jpeg_path,
                                WCHAR *err, size_t err_cch);

BOOL app_image_flow_extract_auto(CRYPTO_BOX *active_box,
                                 const WCHAR *jpeg_path,
                                 WCHAR **out_saved_image_path,
                                 BOOL *out_is_group,
                                 int *out_group_index,
                                 WCHAR *err, size_t err_cch);

#endif
