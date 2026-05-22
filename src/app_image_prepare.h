#ifndef CHINESE_INPUT_AGENT_APP_IMAGE_PREPARE_H
#define CHINESE_INPUT_AGENT_APP_IMAGE_PREPARE_H

#include <windows.h>
#include <stddef.h>

#include "app_image_stego.h"

BOOL app_image_prepare_secret_avif(const WCHAR *image_path,
                                   size_t byte_budget,
                                   const IMAGE_STEGO_DCT_OPTIONS *options,
                                   BYTE **out, DWORD *out_len,
                                   WCHAR *err, size_t err_cch);

#endif
