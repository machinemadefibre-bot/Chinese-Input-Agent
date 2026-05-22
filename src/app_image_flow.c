#include "app_image_flow.h"

#include "app_groups.h"
#include "app_image_prepare.h"
#include "app_paths.h"
#include "app_shared.h"
#include "cia_platform_windows.h"

#include <strsafe.h>
#include <stdint.h>

#define IMAGE_RECORD_MAGIC "CIAPIC1"
#define IMAGE_RECORD_MAGIC_BYTES 7
#define IMAGE_RECORD_VERSION 1
#define IMAGE_RECORD_HEADER_BYTES 12
#define IMAGE_PREPARE_OVERHEAD_RESERVE 512

static void write_u32_le(BYTE out[4], uint32_t value) {
    out[0] = (BYTE)(value & 0xffu);
    out[1] = (BYTE)((value >> 8) & 0xffu);
    out[2] = (BYTE)((value >> 16) & 0xffu);
    out[3] = (BYTE)((value >> 24) & 0xffu);
}

static uint32_t read_u32_le(const BYTE in[4]) {
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static BOOL build_image_record(const BYTE *avif, DWORD avif_len, BYTE **out, DWORD *out_len,
                               WCHAR *err, size_t err_cch) {
    *out = NULL;
    *out_len = 0;
    if ((!avif && avif_len) || avif_len > 0xffffffffu - IMAGE_RECORD_HEADER_BYTES) {
        set_error(err, err_cch, L"Hidden image payload is too large.");
        return FALSE;
    }
    DWORD len = IMAGE_RECORD_HEADER_BYTES + avif_len;
    BYTE *record = (BYTE *)xalloc(len ? len : 1);
    if (!record) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    CopyMemory(record, IMAGE_RECORD_MAGIC, IMAGE_RECORD_MAGIC_BYTES);
    record[7] = IMAGE_RECORD_VERSION;
    write_u32_le(record + 8, avif_len);
    if (avif_len) CopyMemory(record + IMAGE_RECORD_HEADER_BYTES, avif, avif_len);
    *out = record;
    *out_len = len;
    return TRUE;
}

static BOOL parse_image_record(const BYTE *record, DWORD record_len,
                               const BYTE **avif, DWORD *avif_len,
                               WCHAR *err, size_t err_cch) {
    if (!record || record_len < IMAGE_RECORD_HEADER_BYTES ||
        memcmp(record, IMAGE_RECORD_MAGIC, IMAGE_RECORD_MAGIC_BYTES) != 0 ||
        record[7] != IMAGE_RECORD_VERSION) {
        set_error(err, err_cch, L"Hidden image record is invalid.");
        return FALSE;
    }
    DWORD len = read_u32_le(record + 8);
    if (len != record_len - IMAGE_RECORD_HEADER_BYTES) {
        set_error(err, err_cch, L"Hidden image record length is invalid.");
        return FALSE;
    }
    *avif = record + IMAGE_RECORD_HEADER_BYTES;
    *avif_len = len;
    return TRUE;
}

static BOOL build_received_image_path(WCHAR *out, size_t cch) {
    WCHAR data_dir[MAX_PATH];
    WCHAR image_dir[MAX_PATH];
    BYTE rnd[8];
    if (!get_app_dir(data_dir, ARRAYSIZE(data_dir)) ||
        !join_path(image_dir, ARRAYSIZE(image_dir), data_dir, L"received_images")) {
        return FALSE;
    }
    if (!dir_exists_w(image_dir) && !CreateDirectoryW(image_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return FALSE;
    }
    if (!cia_win_random_bytes(rnd, sizeof(rnd))) return FALSE;
    WCHAR name[64];
    if (FAILED(StringCchPrintfW(name, ARRAYSIZE(name),
                                L"image_%02x%02x%02x%02x%02x%02x%02x%02x.avif",
                                rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]))) {
        SecureZeroMemory(rnd, sizeof(rnd));
        return FALSE;
    }
    SecureZeroMemory(rnd, sizeof(rnd));
    return join_path(out, cch, image_dir, name);
}

static BOOL save_image_record_to_file(const BYTE *record, DWORD record_len,
                                      WCHAR **out_saved_image_path,
                                      WCHAR *err, size_t err_cch) {
    const BYTE *avif = NULL;
    DWORD avif_len = 0;
    WCHAR path[MAX_PATH];
    *out_saved_image_path = NULL;
    if (!parse_image_record(record, record_len, &avif, &avif_len, err, err_cch) ||
        !build_received_image_path(path, ARRAYSIZE(path)) ||
        !write_file_bytes_atomic(path, avif, avif_len)) {
        if (!err || !err[0]) set_error(err, err_cch, L"Hidden image save failed.");
        return FALSE;
    }
    size_t path_cch = wcslen(path) + 1;
    WCHAR *copy = (WCHAR *)xalloc(path_cch * sizeof(WCHAR));
    if (!copy) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    CopyMemory(copy, path, path_cch * sizeof(WCHAR));
    *out_saved_image_path = copy;
    return TRUE;
}

static BOOL prepare_secret_for_cover(const WCHAR *cover_path, const WCHAR *secret_image_path,
                                     const BYTE locator_key[32],
                                     const IMAGE_STEGO_DCT_OPTIONS *options,
                                     BYTE **record_out, DWORD *record_len_out,
                                     WCHAR *err, size_t err_cch) {
    *record_out = NULL;
    *record_len_out = 0;
    size_t capacity = 0;
    if (!app_image_stego_dct_capacity(cover_path, locator_key, options, &capacity, err, err_cch)) {
        return FALSE;
    }
    if (capacity <= IMAGE_PREPARE_OVERHEAD_RESERVE + IMAGE_RECORD_HEADER_BYTES) {
        set_error(err, err_cch, L"JPEG carrier capacity is too small.");
        return FALSE;
    }
    BYTE *avif = NULL;
    DWORD avif_len = 0;
    BYTE *record = NULL;
    DWORD record_len = 0;
    BOOL prepared = FALSE;
    if (!app_image_prepare_secret_avif(secret_image_path,
                                       capacity - IMAGE_PREPARE_OVERHEAD_RESERVE - IMAGE_RECORD_HEADER_BYTES,
                                       options, &avif, &avif_len, err, err_cch) ||
        !build_image_record(avif, avif_len, &record, &record_len, err, err_cch)) {
        goto cleanup;
    }
    *record_out = record;
    *record_len_out = record_len;
    record = NULL;
    prepared = TRUE;
cleanup:
    secure_free(avif, avif_len);
    secure_free(record, record_len);
    return prepared;
}

BOOL app_image_flow_embed_private(CRYPTO_BOX *box,
                                  const WCHAR *cover_path,
                                  const WCHAR *secret_image_path,
                                  const IMAGE_STEGO_DCT_OPTIONS *options,
                                  const WCHAR *out_jpeg_path,
                                  WCHAR *err, size_t err_cch) {
    BYTE locator_key[32];
    BYTE *record = NULL;
    DWORD record_len = 0;
    BYTE *packet = NULL;
    DWORD packet_len = 0;
    BOOL embedded = FALSE;
    ZeroMemory(locator_key, sizeof(locator_key));
    if (!crypto_box_derive_image_stego_locator_key(box, locator_key, err, err_cch) ||
        !prepare_secret_for_cover(cover_path, secret_image_path, locator_key, options,
                                  &record, &record_len, err, err_cch) ||
        !crypto_box_encrypt(box, record, record_len, &packet, &packet_len, err, err_cch) ||
        !app_image_stego_dct_embed(cover_path, packet, packet_len, locator_key, options,
                                   out_jpeg_path, err, err_cch)) {
        goto cleanup;
    }
    embedded = TRUE;
cleanup:
    SecureZeroMemory(locator_key, sizeof(locator_key));
    secure_free(record, record_len);
    secure_free(packet, packet_len);
    return embedded;
}

BOOL app_image_flow_embed_group(int group_index,
                                const WCHAR *cover_path,
                                const WCHAR *secret_image_path,
                                const IMAGE_STEGO_DCT_OPTIONS *options,
                                const WCHAR *out_jpeg_path,
                                WCHAR *err, size_t err_cch) {
    BYTE locator_key[32];
    BYTE *record = NULL;
    DWORD record_len = 0;
    BYTE *packet = NULL;
    DWORD packet_len = 0;
    BOOL embedded = FALSE;
    ZeroMemory(locator_key, sizeof(locator_key));
    if (!app_groups_derive_image_stego_locator_key(group_index, locator_key, err, err_cch) ||
        !prepare_secret_for_cover(cover_path, secret_image_path, locator_key, options,
                                  &record, &record_len, err, err_cch) ||
        !app_groups_encrypt_blob(group_index, record, record_len, &packet, &packet_len, err, err_cch) ||
        !app_image_stego_dct_embed(cover_path, packet, packet_len, locator_key, options,
                                   out_jpeg_path, err, err_cch)) {
        goto cleanup;
    }
    embedded = TRUE;
cleanup:
    SecureZeroMemory(locator_key, sizeof(locator_key));
    secure_free(record, record_len);
    secure_free(packet, packet_len);
    return embedded;
}

static BOOL extract_with_private_box(CRYPTO_BOX *box, const WCHAR *jpeg_path,
                                     WCHAR **out_saved_image_path,
                                     WCHAR *err, size_t err_cch) {
    BYTE locator_key[32];
    BYTE *packet = NULL;
    DWORD packet_len = 0;
    BYTE *record = NULL;
    DWORD record_len = 0;
    BOOL extracted = FALSE;
    ZeroMemory(locator_key, sizeof(locator_key));
    if (!crypto_box_derive_image_stego_locator_key(box, locator_key, err, err_cch)) goto cleanup;
    if (!app_image_stego_dct_extract(jpeg_path, locator_key, &packet, &packet_len, err, err_cch)) goto cleanup;
    if (!crypto_box_decrypt(box, packet, packet_len, &record, &record_len, err, err_cch)) goto cleanup;
    extracted = save_image_record_to_file(record, record_len, out_saved_image_path, err, err_cch);
cleanup:
    SecureZeroMemory(locator_key, sizeof(locator_key));
    secure_free(packet, packet_len);
    secure_free(record, record_len);
    return extracted;
}

static BOOL extract_with_group(int group_index, const WCHAR *jpeg_path,
                               WCHAR **out_saved_image_path,
                               WCHAR *err, size_t err_cch) {
    BYTE locator_key[32];
    BYTE *packet = NULL;
    DWORD packet_len = 0;
    BYTE *record = NULL;
    DWORD record_len = 0;
    WCHAR *sender = NULL;
    BOOL extracted = FALSE;
    ZeroMemory(locator_key, sizeof(locator_key));
    if (!app_groups_derive_image_stego_locator_key(group_index, locator_key, err, err_cch)) goto cleanup;
    if (!app_image_stego_dct_extract(jpeg_path, locator_key, &packet, &packet_len, err, err_cch)) goto cleanup;
    if (!app_groups_decrypt_blob(packet, packet_len, &record, &record_len, NULL, &sender, err, err_cch)) goto cleanup;
    extracted = save_image_record_to_file(record, record_len, out_saved_image_path, err, err_cch);
cleanup:
    SecureZeroMemory(locator_key, sizeof(locator_key));
    secure_free(packet, packet_len);
    secure_free(record, record_len);
    secure_free_wide(sender);
    return extracted;
}

BOOL app_image_flow_extract_auto(CRYPTO_BOX *active_box,
                                 const WCHAR *jpeg_path,
                                 WCHAR **out_saved_image_path,
                                 BOOL *out_is_group,
                                 int *out_group_index,
                                 WCHAR *err, size_t err_cch) {
    if (out_saved_image_path) *out_saved_image_path = NULL;
    if (out_is_group) *out_is_group = FALSE;
    if (out_group_index) *out_group_index = -1;
    if (!jpeg_path || !jpeg_path[0] || !out_saved_image_path) {
        set_error(err, err_cch, L"Invalid image stego extract request.");
        return FALSE;
    }
    WCHAR last_err[256] = L"";
    if (active_box && extract_with_private_box(active_box, jpeg_path, out_saved_image_path,
                                               last_err, ARRAYSIZE(last_err))) {
        return TRUE;
    }
    for (int group_index = 0; group_index < app_groups_count(); ++group_index) {
        last_err[0] = L'\0';
        if (extract_with_group(group_index, jpeg_path, out_saved_image_path,
                               last_err, ARRAYSIZE(last_err))) {
            if (out_is_group) *out_is_group = TRUE;
            if (out_group_index) *out_group_index = group_index;
            return TRUE;
        }
    }
    set_error(err, err_cch, last_err[0] ? last_err : L"No hidden image payload matched the active keys.");
    return FALSE;
}
