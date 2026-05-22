#include "app_image_prepare.h"

#include "app_shared.h"

#include <avif/avif.h>
#include <wincodec.h>
#include <objbase.h>
#include <strsafe.h>

typedef struct IMAGE_RGBA {
    UINT width;
    UINT height;
    UINT row_bytes;
    BYTE *pixels;
    SIZE_T pixels_len;
} IMAGE_RGBA;

static const UINT SECRET_SIZE_CANDIDATES[] = { 512, 384, 256, 192, 128, 96, 64 };
static const int SECRET_QUALITY_AUTO[] = { 85, 75, 65, 55, 45 };
static const int SECRET_QUALITY_SMALL[] = { 65, 55, 45 };
static const int SECRET_QUALITY_BALANCED[] = { 80, 70, 60, 50 };
static const int SECRET_QUALITY_CLEAR[] = { 90, 82, 74, 66, 58 };

static BOOL has_avif_extension(const WCHAR *path) {
    const WCHAR *dot = path ? wcsrchr(path, L'.') : NULL;
    return dot && (_wcsicmp(dot, L".avif") == 0 || _wcsicmp(dot, L".avifs") == 0);
}

static void release_unknown(IUnknown *unknown) {
    if (unknown) unknown->lpVtbl->Release(unknown);
}

static void free_rgba(IMAGE_RGBA *image) {
    if (!image) return;
    secure_free(image->pixels, image->pixels_len);
    ZeroMemory(image, sizeof(*image));
}

static BOOL compute_scaled_size(UINT src_w, UINT src_h, UINT max_side, UINT *out_w, UINT *out_h) {
    if (!src_w || !src_h || !out_w || !out_h) return FALSE;
    UINT long_side = src_w > src_h ? src_w : src_h;
    if (!max_side || long_side <= max_side) {
        *out_w = src_w;
        *out_h = src_h;
        return TRUE;
    }
    UINT64 new_w = ((UINT64)src_w * max_side + long_side / 2) / long_side;
    UINT64 new_h = ((UINT64)src_h * max_side + long_side / 2) / long_side;
    if (new_w == 0) new_w = 1;
    if (new_h == 0) new_h = 1;
    if (new_w > 0xffffu || new_h > 0xffffu) return FALSE;
    *out_w = (UINT)new_w;
    *out_h = (UINT)new_h;
    return TRUE;
}

static BOOL resize_rgba_nearest(const IMAGE_RGBA *src, UINT dst_w, UINT dst_h,
                                IMAGE_RGBA *out, WCHAR *err, size_t err_cch) {
    ZeroMemory(out, sizeof(*out));
    if (!src || !src->pixels || !src->width || !src->height || !dst_w || !dst_h ||
        dst_w > UINT_MAX / 4 || dst_h > UINT_MAX / (dst_w * 4u)) {
        set_error(err, err_cch, L"Hidden image resize failed.");
        return FALSE;
    }
    out->width = dst_w;
    out->height = dst_h;
    out->row_bytes = dst_w * 4u;
    out->pixels_len = (SIZE_T)out->row_bytes * dst_h;
    out->pixels = (BYTE *)xalloc(out->pixels_len);
    if (!out->pixels) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    for (UINT y = 0; y < dst_h; ++y) {
        UINT src_y = (UINT)(((UINT64)y * src->height) / dst_h);
        const BYTE *src_row = src->pixels + (SIZE_T)src_y * src->row_bytes;
        BYTE *dst_row = out->pixels + (SIZE_T)y * out->row_bytes;
        for (UINT x = 0; x < dst_w; ++x) {
            UINT src_x = (UINT)(((UINT64)x * src->width) / dst_w);
            CopyMemory(dst_row + (SIZE_T)x * 4u, src_row + (SIZE_T)src_x * 4u, 4);
        }
    }
    return TRUE;
}

static BOOL decode_avif_rgba_bytes(const BYTE *bytes, DWORD len, UINT max_side,
                                   IMAGE_RGBA *out, WCHAR *err, size_t err_cch) {
    ZeroMemory(out, sizeof(*out));
    if (!bytes || !len) {
        set_error(err, err_cch, L"Hidden AVIF decode failed.");
        return FALSE;
    }
    avifDecoder *decoder = NULL;
    avifImage *image = NULL;
    IMAGE_RGBA full;
    BOOL decoded = FALSE;
    ZeroMemory(&full, sizeof(full));

    decoder = avifDecoderCreate();
    image = avifImageCreateEmpty();
    if (!decoder || !image) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (avifDecoderReadMemory(decoder, image, bytes, len) != AVIF_RESULT_OK ||
        !image->width || !image->height) {
        set_error(err, err_cch, L"Hidden AVIF decode failed.");
        goto cleanup;
    }
    if (image->width > UINT_MAX / 4 || image->height > UINT_MAX / (image->width * 4u)) {
        set_error(err, err_cch, L"Hidden image is too large.");
        goto cleanup;
    }
    full.width = image->width;
    full.height = image->height;
    full.row_bytes = image->width * 4u;
    full.pixels_len = (SIZE_T)full.row_bytes * image->height;
    full.pixels = (BYTE *)xalloc(full.pixels_len);
    if (!full.pixels) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }

    avifRGBImage rgb;
    avifRGBImageSetDefaults(&rgb, image);
    rgb.format = AVIF_RGB_FORMAT_RGBA;
    rgb.depth = 8;
    rgb.pixels = full.pixels;
    rgb.rowBytes = full.row_bytes;
    if (avifImageYUVToRGB(image, &rgb) != AVIF_RESULT_OK) {
        set_error(err, err_cch, L"Hidden AVIF decode failed.");
        goto cleanup;
    }

    UINT dst_w = 0, dst_h = 0;
    if (!compute_scaled_size(full.width, full.height, max_side, &dst_w, &dst_h)) {
        set_error(err, err_cch, L"Hidden image resize failed.");
        goto cleanup;
    }
    if (dst_w == full.width && dst_h == full.height) {
        *out = full;
        ZeroMemory(&full, sizeof(full));
    } else if (!resize_rgba_nearest(&full, dst_w, dst_h, out, err, err_cch)) {
        goto cleanup;
    }
    decoded = TRUE;

cleanup:
    if (!decoded) free_rgba(out);
    free_rgba(&full);
    if (image) avifImageDestroy(image);
    if (decoder) avifDecoderDestroy(decoder);
    return decoded;
}

static BOOL decode_image_rgba(const WCHAR *path, UINT max_side, IMAGE_RGBA *out,
                              WCHAR *err, size_t err_cch) {
    ZeroMemory(out, sizeof(*out));
    HRESULT co_hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL co_initialized = SUCCEEDED(co_hr);
    if (FAILED(co_hr) && co_hr != RPC_E_CHANGED_MODE) {
        set_error(err, err_cch, L"Image codec initialization failed.");
        return FALSE;
    }
    IWICImagingFactory *factory = NULL;
    IWICBitmapDecoder *decoder = NULL;
    IWICBitmapFrameDecode *frame = NULL;
    IWICBitmapScaler *scaler = NULL;
    IWICFormatConverter *converter = NULL;
    IWICBitmapSource *source = NULL;
    BOOL decoded = FALSE;
    UINT src_w = 0, src_h = 0, dst_w = 0, dst_h = 0;

    if (FAILED(CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                                &IID_IWICImagingFactory, (void **)&factory)) ||
        FAILED(factory->lpVtbl->CreateDecoderFromFilename(factory, path, NULL, GENERIC_READ,
                                                          WICDecodeMetadataCacheOnLoad, &decoder)) ||
        FAILED(decoder->lpVtbl->GetFrame(decoder, 0, &frame)) ||
        FAILED(frame->lpVtbl->GetSize(frame, &src_w, &src_h)) ||
        !compute_scaled_size(src_w, src_h, max_side, &dst_w, &dst_h)) {
        set_error(err, err_cch, L"Hidden image decode failed.");
        goto cleanup;
    }

    if (dst_w != src_w || dst_h != src_h) {
        if (FAILED(factory->lpVtbl->CreateBitmapScaler(factory, &scaler)) ||
            FAILED(scaler->lpVtbl->Initialize(scaler, (IWICBitmapSource *)frame, dst_w, dst_h,
                                              WICBitmapInterpolationModeFant))) {
            set_error(err, err_cch, L"Hidden image resize failed.");
            goto cleanup;
        }
        source = (IWICBitmapSource *)scaler;
    } else {
        source = (IWICBitmapSource *)frame;
    }

    if (FAILED(factory->lpVtbl->CreateFormatConverter(factory, &converter)) ||
        FAILED(converter->lpVtbl->Initialize(converter, source, &GUID_WICPixelFormat32bppRGBA,
                                             WICBitmapDitherTypeNone, NULL, 0.0,
                                             WICBitmapPaletteTypeCustom))) {
        set_error(err, err_cch, L"Hidden image pixel conversion failed.");
        goto cleanup;
    }
    if (dst_w > UINT_MAX / 4 || dst_h > UINT_MAX / (dst_w * 4u)) {
        set_error(err, err_cch, L"Hidden image is too large.");
        goto cleanup;
    }
    out->width = dst_w;
    out->height = dst_h;
    out->row_bytes = dst_w * 4u;
    out->pixels_len = (SIZE_T)out->row_bytes * dst_h;
    out->pixels = (BYTE *)xalloc(out->pixels_len);
    if (!out->pixels) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (FAILED(converter->lpVtbl->CopyPixels(converter, NULL, out->row_bytes,
                                             (UINT)out->pixels_len, out->pixels))) {
        set_error(err, err_cch, L"Hidden image pixel copy failed.");
        goto cleanup;
    }
    decoded = TRUE;

cleanup:
    if (!decoded) free_rgba(out);
    release_unknown((IUnknown *)converter);
    release_unknown((IUnknown *)scaler);
    release_unknown((IUnknown *)frame);
    release_unknown((IUnknown *)decoder);
    release_unknown((IUnknown *)factory);
    if (co_initialized) CoUninitialize();
    return decoded;
}

static BOOL encode_rgba_avif(const IMAGE_RGBA *image, int quality, BYTE **out, DWORD *out_len,
                             WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    avifImage *avif_image = NULL;
    avifEncoder *encoder = NULL;
    avifRWData output = AVIF_DATA_EMPTY;
    BOOL encoded = FALSE;
    if (!image || !image->pixels || !image->width || !image->height) {
        set_error(err, err_cch, L"Invalid hidden image.");
        return FALSE;
    }
    avif_image = avifImageCreate(image->width, image->height, 8, AVIF_PIXEL_FORMAT_YUV420);
    if (!avif_image) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    avifRGBImage rgb;
    avifRGBImageSetDefaults(&rgb, avif_image);
    rgb.format = AVIF_RGB_FORMAT_RGBA;
    rgb.depth = 8;
    rgb.ignoreAlpha = AVIF_TRUE;
    rgb.pixels = image->pixels;
    rgb.rowBytes = image->row_bytes;
    if (avifImageRGBToYUV(avif_image, &rgb) != AVIF_RESULT_OK) {
        set_error(err, err_cch, L"Hidden image AVIF color conversion failed.");
        goto cleanup;
    }
    encoder = avifEncoderCreate();
    if (!encoder) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    encoder->quality = quality;
    encoder->qualityAlpha = quality;
    encoder->speed = 8;
    encoder->maxThreads = 2;
    avifResult result = avifEncoderWrite(encoder, avif_image, &output);
    if (result != AVIF_RESULT_OK || output.size > 0xffffffffu) {
        set_error(err, err_cch, L"Hidden image AVIF encode failed.");
        goto cleanup;
    }
    BYTE *copy = (BYTE *)xalloc(output.size ? output.size : 1);
    if (!copy) {
        set_error(err, err_cch, L"Out of memory.");
        goto cleanup;
    }
    if (output.size) CopyMemory(copy, output.data, output.size);
    *out = copy;
    *out_len = (DWORD)output.size;
    encoded = TRUE;
cleanup:
    avifRWDataFree(&output);
    if (encoder) avifEncoderDestroy(encoder);
    if (avif_image) avifImageDestroy(avif_image);
    return encoded;
}

static const int *quality_table(int mode, size_t *count) {
    switch (mode) {
    case 1:
        *count = ARRAYSIZE(SECRET_QUALITY_SMALL);
        return SECRET_QUALITY_SMALL;
    case 2:
        *count = ARRAYSIZE(SECRET_QUALITY_BALANCED);
        return SECRET_QUALITY_BALANCED;
    case 3:
        *count = ARRAYSIZE(SECRET_QUALITY_CLEAR);
        return SECRET_QUALITY_CLEAR;
    default:
        *count = ARRAYSIZE(SECRET_QUALITY_AUTO);
        return SECRET_QUALITY_AUTO;
    }
}

BOOL app_image_prepare_secret_avif(const WCHAR *image_path,
                                   size_t byte_budget,
                                   const IMAGE_STEGO_DCT_OPTIONS *options,
                                   BYTE **out, DWORD *out_len,
                                   WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if (!image_path || !image_path[0] || byte_budget == 0 || byte_budget > 0xffffffffu) {
        set_error(err, err_cch, L"Invalid hidden image request.");
        return FALSE;
    }
    BYTE *existing = NULL;
    DWORD existing_len = 0;
    if (has_avif_extension(image_path) && read_file_bytes(image_path, &existing, &existing_len)) {
        IMAGE_RGBA validated;
        if (!decode_avif_rgba_bytes(existing, existing_len, 0, &validated, err, err_cch)) {
            secure_free(existing, existing_len);
            return FALSE;
        }
        free_rgba(&validated);
        if (existing_len <= byte_budget) {
            *out = existing;
            *out_len = existing_len;
            return TRUE;
        }
        size_t quality_count = 0;
        const int *qualities = quality_table(options ? options->secret_quality_mode : 0, &quality_count);
        for (size_t size_idx = 0; size_idx < ARRAYSIZE(SECRET_SIZE_CANDIDATES); ++size_idx) {
            IMAGE_RGBA rgba;
            if (!decode_avif_rgba_bytes(existing, existing_len, SECRET_SIZE_CANDIDATES[size_idx],
                                        &rgba, err, err_cch)) {
                secure_free(existing, existing_len);
                return FALSE;
            }
            for (size_t quality_idx = 0; quality_idx < quality_count; ++quality_idx) {
                BYTE *candidate = NULL;
                DWORD candidate_len = 0;
                if (encode_rgba_avif(&rgba, qualities[quality_idx], &candidate, &candidate_len, err, err_cch)) {
                    if (candidate_len <= byte_budget) {
                        free_rgba(&rgba);
                        secure_free(existing, existing_len);
                        *out = candidate;
                        *out_len = candidate_len;
                        return TRUE;
                    }
                    secure_free(candidate, candidate_len);
                }
            }
            free_rgba(&rgba);
        }
        secure_free(existing, existing_len);
        set_error(err, err_cch, L"Hidden image is too large for this JPEG carrier.");
        return FALSE;
    }
    size_t quality_count = 0;
    const int *qualities = quality_table(options ? options->secret_quality_mode : 0, &quality_count);
    for (size_t size_idx = 0; size_idx < ARRAYSIZE(SECRET_SIZE_CANDIDATES); ++size_idx) {
        IMAGE_RGBA rgba;
        if (!decode_image_rgba(image_path, SECRET_SIZE_CANDIDATES[size_idx], &rgba, err, err_cch)) {
            return FALSE;
        }
        for (size_t quality_idx = 0; quality_idx < quality_count; ++quality_idx) {
            BYTE *candidate = NULL;
            DWORD candidate_len = 0;
            if (encode_rgba_avif(&rgba, qualities[quality_idx], &candidate, &candidate_len, err, err_cch)) {
                if (candidate_len <= byte_budget) {
                    free_rgba(&rgba);
                    *out = candidate;
                    *out_len = candidate_len;
                    return TRUE;
                }
                secure_free(candidate, candidate_len);
            }
        }
        free_rgba(&rgba);
    }
    set_error(err, err_cch, L"Hidden image is too large for this JPEG carrier.");
    return FALSE;
}
