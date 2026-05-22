#include "app_image_stego.h"

#include "app_image_fec.h"
#include "app_shared.h"

#include <jpeglib.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DCT1_MAGIC "CIDCT1"
#define DCT2_MAGIC "CIDCT2"
#define DCT_MAGIC_BYTES 6
#define DCT1_VERSION 1
#define DCT2_VERSION 2
#define DCT1_HEADER_BYTES 16
#define DCT2_HEADER_BYTES 32
#define APP_IMAGE_STEGO_MAX_SLOTS (8u * 1024u * 1024u)
#define APP_IMAGE_STEGO_MAX_PACKET_BYTES (4u * 1024u * 1024u)

static const int DCT_COEFFS[] = { 5, 6, 9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34 };

typedef struct JPEG_ERROR_TRAP {
    struct jpeg_error_mgr pub;
    jmp_buf jump;
} JPEG_ERROR_TRAP;

static void jpeg_error_exit(j_common_ptr cinfo) {
    JPEG_ERROR_TRAP *trap = (JPEG_ERROR_TRAP *)cinfo->err;
    longjmp(trap->jump, 1);
}

void image_stego_options_defaults(IMAGE_STEGO_DCT_OPTIONS *options) {
    if (!options) return;
    options->target_short_side = 1080;
    options->jpeg_quality = 90;
    options->robustness_level = 1;
    options->secret_quality_mode = 0;
}

static int repetition_for_options(const IMAGE_STEGO_DCT_OPTIONS *options) {
    int robustness = options ? options->robustness_level : 1;
    if (robustness <= 0) return 1;
    if (robustness == 1) return 3;
    return 5;
}

static BOOL valid_repetition(int repetition) {
    return repetition == 1 || repetition == 3 || repetition == 5;
}

static uint32_t crc32_update(uint32_t crc, const BYTE *bytes, DWORD len) {
    crc = ~crc;
    for (DWORD byte_idx = 0; byte_idx < len; ++byte_idx) {
        crc ^= bytes[byte_idx];
        for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

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

static BOOL frame_fits_slots(uint32_t slot_count, DWORD frame_len, int repetition) {
    uint64_t needed = (uint64_t)frame_len * 8u * (uint64_t)repetition;
    return valid_repetition(repetition) && needed <= slot_count;
}

static uint64_t locator_seed(const BYTE locator_key[32]) {
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 32; ++i) {
        seed ^= ((uint64_t)locator_key[i]) << ((i % 8) * 8);
        seed = seed * 0xbf58476d1ce4e5b9ull + 0x94d049bb133111ebull;
    }
    return seed ? seed : 0x517cc1b727220a95ull;
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545f4914f6cdd1dull;
}

static BOOL build_permutation(uint32_t count, const BYTE locator_key[32], uint32_t **out) {
    *out = NULL;
    if (!locator_key || count == 0 || count > APP_IMAGE_STEGO_MAX_SLOTS) return FALSE;
    uint32_t *order = (uint32_t *)xalloc((SIZE_T)count * sizeof(uint32_t));
    if (!order) return FALSE;
    for (uint32_t i = 0; i < count; ++i) order[i] = i;
    uint64_t rng = locator_seed(locator_key);
    for (uint32_t i = count - 1; i > 0; --i) {
        uint32_t j = (uint32_t)(xorshift64(&rng) % (uint64_t)(i + 1u));
        uint32_t tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
    *out = order;
    return TRUE;
}

static BOOL open_input_jpeg(const WCHAR *path, FILE **file_out) {
    *file_out = _wfopen(path, L"rb");
    return *file_out != NULL;
}

static BOOL open_output_jpeg(const WCHAR *path, FILE **file_out) {
    *file_out = _wfopen(path, L"wb");
    return *file_out != NULL;
}

static uint32_t dct_slot_count(j_decompress_ptr cinfo) {
    if (!cinfo || cinfo->num_components < 1) return 0;
    jpeg_component_info *comp = &cinfo->comp_info[0];
    uint64_t blocks = (uint64_t)comp->width_in_blocks * (uint64_t)comp->height_in_blocks;
    uint64_t slots = blocks * ARRAYSIZE(DCT_COEFFS);
    if (slots > APP_IMAGE_STEGO_MAX_SLOTS) return 0;
    return (uint32_t)slots;
}

static JCOEFPTR coeff_for_slot(j_decompress_ptr cinfo, jvirt_barray_ptr *coef_arrays,
                               uint32_t slot, BOOL writable) {
    jpeg_component_info *comp = &cinfo->comp_info[0];
    uint32_t coeff_idx = slot % ARRAYSIZE(DCT_COEFFS);
    uint32_t block_idx = slot / ARRAYSIZE(DCT_COEFFS);
    JDIMENSION row = block_idx / comp->width_in_blocks;
    JDIMENSION col = block_idx % comp->width_in_blocks;
    JBLOCKARRAY row_blocks = (*cinfo->mem->access_virt_barray)((j_common_ptr)cinfo,
                                                               coef_arrays[0], row, 1, writable);
    return &row_blocks[0][col][DCT_COEFFS[coeff_idx]];
}

static int abs_int(int value) {
    return value < 0 ? -value : value;
}

static void embed_bit(JCOEFPTR coeff, int bit) {
    int value = *coeff;
    int sign = value < 0 ? -1 : 1;
    int magnitude = abs_int(value);
    if (magnitude < 2) magnitude = 2;
    int target = bit ? 3 : 1;
    int delta = target - (magnitude & 3);
    if (delta > 2) delta -= 4;
    if (delta < -2) delta += 4;
    magnitude += delta;
    if (magnitude < 1) magnitude += 4;
    *coeff = (JCOEF)(sign * magnitude);
}

static int extract_bit(JCOEF coeff) {
    int residue = abs_int((int)coeff) & 3;
    return residue >= 2 ? 1 : 0;
}

static int frame_bit(const BYTE *frame, size_t bit_index) {
    return (frame[bit_index / 8] >> (bit_index % 8)) & 1;
}

static void set_frame_bit(BYTE *frame, size_t bit_index, int bit) {
    BYTE mask = (BYTE)(1u << (bit_index % 8));
    if (bit) frame[bit_index / 8] |= mask;
    else frame[bit_index / 8] &= (BYTE)~mask;
}

static BOOL write_frame_to_coefficients(j_decompress_ptr cinfo, jvirt_barray_ptr *coef_arrays,
                                        const uint32_t *order, uint32_t slot_count,
                                        const BYTE *frame, DWORD frame_len, int repetition) {
    uint64_t needed = (uint64_t)frame_len * 8u * (uint64_t)repetition;
    if (needed > slot_count) return FALSE;
    uint32_t order_pos = 0;
    for (DWORD byte_idx = 0; byte_idx < frame_len; ++byte_idx) {
        for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
            int bit = (frame[byte_idx] >> bit_idx) & 1;
            for (int rep_idx = 0; rep_idx < repetition; ++rep_idx) {
                embed_bit(coeff_for_slot(cinfo, coef_arrays, order[order_pos++], TRUE), bit);
            }
        }
    }
    return TRUE;
}

static BOOL read_frame_from_coefficients(j_decompress_ptr cinfo, jvirt_barray_ptr *coef_arrays,
                                         const uint32_t *order, uint32_t slot_count,
                                         BYTE *frame, DWORD frame_len, int repetition) {
    uint64_t needed = (uint64_t)frame_len * 8u * (uint64_t)repetition;
    if (needed > slot_count) return FALSE;
    ZeroMemory(frame, frame_len);
    uint32_t order_pos = 0;
    for (DWORD bit_pos = 0; bit_pos < frame_len * 8u; ++bit_pos) {
        int ones = 0;
        for (int rep_idx = 0; rep_idx < repetition; ++rep_idx) {
            ones += extract_bit(*coeff_for_slot(cinfo, coef_arrays, order[order_pos++], FALSE));
        }
        set_frame_bit(frame, bit_pos, ones * 2 >= repetition);
    }
    return TRUE;
}

static void write_dct2_header(BYTE header[DCT2_HEADER_BYTES],
                              DWORD packet_len,
                              DWORD encoded_len,
                              DWORD packet_crc,
                              BYTE data_bytes,
                              BYTE parity_bytes,
                              BYTE repetition) {
    ZeroMemory(header, DCT2_HEADER_BYTES);
    CopyMemory(header, DCT2_MAGIC, DCT_MAGIC_BYTES);
    header[6] = DCT2_VERSION;
    header[7] = repetition;
    write_u32_le(header + 8, packet_len);
    write_u32_le(header + 12, encoded_len);
    write_u32_le(header + 16, packet_crc);
    header[20] = data_bytes;
    header[21] = parity_bytes;
    header[23] = DCT2_HEADER_BYTES;
    write_u32_le(header + 28, crc32_update(0, header, 28));
}

static BOOL parse_dct2_header(const BYTE header[DCT2_HEADER_BYTES],
                              int expected_repetition,
                              DWORD *packet_len,
                              DWORD *encoded_len,
                              DWORD *packet_crc,
                              BYTE *data_bytes,
                              BYTE *parity_bytes) {
    if (memcmp(header, DCT2_MAGIC, DCT_MAGIC_BYTES) != 0 ||
        header[6] != DCT2_VERSION ||
        header[7] != (BYTE)expected_repetition ||
        header[23] != DCT2_HEADER_BYTES ||
        crc32_update(0, header, 28) != read_u32_le(header + 28)) {
        return FALSE;
    }
    *packet_len = read_u32_le(header + 8);
    *encoded_len = read_u32_le(header + 12);
    *packet_crc = read_u32_le(header + 16);
    *data_bytes = header[20];
    *parity_bytes = header[21];
    if (*packet_len > APP_IMAGE_STEGO_MAX_PACKET_BYTES ||
        (int)*data_bytes + (int)*parity_bytes != 255 ||
        (*data_bytes != 239 && *data_bytes != 223 && *data_bytes != 191) ||
        (*parity_bytes != 16 && *parity_bytes != 32 && *parity_bytes != 64)) {
        return FALSE;
    }
    DWORD expected_encoded_len = 0;
    return app_image_fec_encoded_len(*packet_len, *data_bytes, *parity_bytes,
                                     &expected_encoded_len) &&
           expected_encoded_len == *encoded_len;
}

BOOL app_image_stego_dct_capacity(const WCHAR *jpeg_path,
                                  const BYTE locator_key[32],
                                  const IMAGE_STEGO_DCT_OPTIONS *options,
                                  size_t *payload_byte_capacity,
                                  WCHAR *err, size_t err_cch) {
    if (payload_byte_capacity) *payload_byte_capacity = 0;
    if (!jpeg_path || !locator_key || !payload_byte_capacity) {
        set_error(err, err_cch, L"Invalid image stego capacity request.");
        return FALSE;
    }
    FILE *infile = NULL;
    struct jpeg_decompress_struct cinfo;
    JPEG_ERROR_TRAP jerr;
    ZeroMemory(&cinfo, sizeof(cinfo));
    ZeroMemory(&jerr, sizeof(jerr));
    if (!open_input_jpeg(jpeg_path, &infile)) {
        set_error(err, err_cch, L"Cover image must be a readable JPEG file.");
        return FALSE;
    }
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpeg_error_exit;
    if (setjmp(jerr.jump)) {
        jpeg_destroy_decompress(&cinfo);
        fclose(infile);
        set_error(err, err_cch, L"JPEG coefficient read failed.");
        return FALSE;
    }
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, infile);
    jpeg_read_header(&cinfo, TRUE);
    jpeg_read_coefficients(&cinfo);
    uint32_t slots = dct_slot_count(&cinfo);
    int repetition = repetition_for_options(options);
    BYTE data_bytes = 0, parity_bytes = 0;
    if (!slots || !app_image_fec_params_for_robustness(options ? options->robustness_level : 1,
                                                       &data_bytes, &parity_bytes)) {
        *payload_byte_capacity = 0;
    } else {
        size_t logical_bytes = slots / (uint32_t)repetition / 8u;
        size_t body_bytes = logical_bytes > DCT2_HEADER_BYTES ? logical_bytes - DCT2_HEADER_BYTES : 0;
        size_t blocks = body_bytes / 255u;
        size_t capacity = blocks * data_bytes;
        *payload_byte_capacity = capacity > APP_IMAGE_STEGO_MAX_PACKET_BYTES ?
                                 APP_IMAGE_STEGO_MAX_PACKET_BYTES : capacity;
    }
    jpeg_destroy_decompress(&cinfo);
    fclose(infile);
    return TRUE;
}

BOOL app_image_stego_dct_embed(const WCHAR *cover_jpeg_path,
                               const BYTE *encrypted_packet, DWORD encrypted_packet_len,
                               const BYTE locator_key[32],
                               const IMAGE_STEGO_DCT_OPTIONS *options,
                               const WCHAR *out_jpeg_path,
                               WCHAR *err, size_t err_cch) {
    if (!cover_jpeg_path || !out_jpeg_path || !locator_key || (!encrypted_packet && encrypted_packet_len)) {
        set_error(err, err_cch, L"Invalid image stego embed request.");
        return FALSE;
    }
    if (encrypted_packet_len > APP_IMAGE_STEGO_MAX_PACKET_BYTES) {
        set_error(err, err_cch, L"Image payload is too large.");
        return FALSE;
    }
    BYTE data_bytes = 0, parity_bytes = 0;
    if (!app_image_fec_params_for_robustness(options ? options->robustness_level : 1,
                                             &data_bytes, &parity_bytes)) {
        set_error(err, err_cch, L"Invalid image robustness setting.");
        return FALSE;
    }
    BYTE *encoded = NULL;
    DWORD encoded_len = 0;
    if (!app_image_fec_encode(encrypted_packet, encrypted_packet_len,
                              data_bytes, parity_bytes, &encoded, &encoded_len,
                              err, err_cch)) {
        return FALSE;
    }
    if (encoded_len > 0xffffffffu - DCT2_HEADER_BYTES) {
        secure_free(encoded, encoded_len);
        set_error(err, err_cch, L"Image payload is too large.");
        return FALSE;
    }
    DWORD frame_len = encoded_len + DCT2_HEADER_BYTES;
    BYTE *frame = (BYTE *)xalloc(frame_len ? frame_len : 1);
    if (!frame) {
        secure_free(encoded, encoded_len);
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    write_dct2_header(frame, encrypted_packet_len, encoded_len,
                      crc32_update(0, encrypted_packet, encrypted_packet_len),
                      data_bytes, parity_bytes, (BYTE)repetition_for_options(options));
    if (encoded_len) CopyMemory(frame + DCT2_HEADER_BYTES, encoded, encoded_len);
    secure_free(encoded, encoded_len);

    FILE *infile = NULL;
    FILE *outfile = NULL;
    struct jpeg_decompress_struct srcinfo;
    struct jpeg_compress_struct dstinfo;
    JPEG_ERROR_TRAP srcerr;
    JPEG_ERROR_TRAP dsterr;
    jvirt_barray_ptr *coef_arrays = NULL;
    uint32_t *order = NULL;
    BOOL embedded = FALSE;
    BOOL src_created = FALSE;
    BOOL dst_created = FALSE;
    ZeroMemory(&srcinfo, sizeof(srcinfo));
    ZeroMemory(&dstinfo, sizeof(dstinfo));
    ZeroMemory(&srcerr, sizeof(srcerr));
    ZeroMemory(&dsterr, sizeof(dsterr));

    if (!open_input_jpeg(cover_jpeg_path, &infile)) {
        set_error(err, err_cch, L"Cover image must be a readable JPEG file.");
        goto cleanup_nojpeg;
    }
    srcinfo.err = jpeg_std_error(&srcerr.pub);
    srcerr.pub.error_exit = jpeg_error_exit;
    if (setjmp(srcerr.jump)) {
        set_error(err, err_cch, L"JPEG coefficient read failed.");
        goto cleanup;
    }
    jpeg_create_decompress(&srcinfo);
    src_created = TRUE;
    jpeg_stdio_src(&srcinfo, infile);
    jpeg_read_header(&srcinfo, TRUE);
    coef_arrays = jpeg_read_coefficients(&srcinfo);
    uint32_t slot_count = dct_slot_count(&srcinfo);
    if (!build_permutation(slot_count, locator_key, &order) ||
        !write_frame_to_coefficients(&srcinfo, coef_arrays, order, slot_count,
                                     frame, frame_len, repetition_for_options(options))) {
        set_error(err, err_cch, L"JPEG carrier capacity is too small.");
        goto cleanup;
    }
    if (!open_output_jpeg(out_jpeg_path, &outfile)) {
        set_error(err, err_cch, L"Cannot create output JPEG file.");
        goto cleanup;
    }
    dstinfo.err = jpeg_std_error(&dsterr.pub);
    dsterr.pub.error_exit = jpeg_error_exit;
    if (setjmp(dsterr.jump)) {
        set_error(err, err_cch, L"JPEG coefficient write failed.");
        goto cleanup;
    }
    jpeg_create_compress(&dstinfo);
    dst_created = TRUE;
    jpeg_stdio_dest(&dstinfo, outfile);
    jpeg_copy_critical_parameters(&srcinfo, &dstinfo);
    jpeg_write_coefficients(&dstinfo, coef_arrays);
    jpeg_finish_compress(&dstinfo);
    embedded = TRUE;

cleanup:
    if (dst_created) jpeg_destroy_compress(&dstinfo);
    if (src_created) jpeg_destroy_decompress(&srcinfo);
cleanup_nojpeg:
    if (outfile) fclose(outfile);
    if (infile) fclose(infile);
    xfree(order);
    secure_free(frame, frame_len);
    return embedded;
}

BOOL app_image_stego_dct_extract(const WCHAR *jpeg_path,
                                 const BYTE locator_key[32],
                                 BYTE **out_encrypted_packet, DWORD *out_encrypted_packet_len,
                                 WCHAR *err, size_t err_cch) {
    *out_encrypted_packet = NULL;
    *out_encrypted_packet_len = 0;
    if (!jpeg_path || !locator_key) {
        set_error(err, err_cch, L"Invalid image stego extract request.");
        return FALSE;
    }
    FILE *infile = NULL;
    struct jpeg_decompress_struct cinfo;
    JPEG_ERROR_TRAP jerr;
    jvirt_barray_ptr *coef_arrays = NULL;
    uint32_t *order = NULL;
    BYTE header[DCT2_HEADER_BYTES];
    BYTE *frame = NULL;
    DWORD frame_alloc_len = 0;
    BOOL extracted = FALSE;
    ZeroMemory(&cinfo, sizeof(cinfo));
    ZeroMemory(&jerr, sizeof(jerr));
    ZeroMemory(header, sizeof(header));

    if (!open_input_jpeg(jpeg_path, &infile)) {
        set_error(err, err_cch, L"Input image must be a readable JPEG file.");
        return FALSE;
    }
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpeg_error_exit;
    if (setjmp(jerr.jump)) {
        set_error(err, err_cch, L"JPEG coefficient read failed.");
        goto cleanup;
    }
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, infile);
    jpeg_read_header(&cinfo, TRUE);
    coef_arrays = jpeg_read_coefficients(&cinfo);
    uint32_t slot_count = dct_slot_count(&cinfo);
    if (!build_permutation(slot_count, locator_key, &order)) {
        set_error(err, err_cch, L"JPEG carrier is too large or unsupported.");
        goto cleanup;
    }

    for (int repetition = 1; repetition <= 5; repetition += 2) {
        if (!read_frame_from_coefficients(&cinfo, coef_arrays, order, slot_count,
                                          header, DCT2_HEADER_BYTES, repetition)) {
            continue;
        }
        DWORD packet_len = 0, encoded_len = 0, packet_crc = 0;
        BYTE data_bytes = 0, parity_bytes = 0;
        if (!parse_dct2_header(header, repetition, &packet_len, &encoded_len,
                               &packet_crc, &data_bytes, &parity_bytes)) {
            continue;
        }
        if (encoded_len > 0xffffffffu - DCT2_HEADER_BYTES) continue;
        DWORD frame_len = encoded_len + DCT2_HEADER_BYTES;
        if (!frame_fits_slots(slot_count, frame_len, repetition)) continue;
        frame = (BYTE *)xalloc(frame_len ? frame_len : 1);
        if (!frame) {
            set_error(err, err_cch, L"Out of memory.");
            goto cleanup;
        }
        frame_alloc_len = frame_len;
        if (!read_frame_from_coefficients(&cinfo, coef_arrays, order, slot_count,
                                          frame, frame_len, repetition)) {
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        if (!parse_dct2_header(frame, repetition, &packet_len, &encoded_len,
                               &packet_crc, &data_bytes, &parity_bytes)) {
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        BYTE *packet = NULL;
        DWORD recovered_len = 0;
        if (!app_image_fec_decode(frame + DCT2_HEADER_BYTES, encoded_len,
                                  packet_len, data_bytes, parity_bytes,
                                  &packet, &recovered_len, err, err_cch)) {
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        if (recovered_len != packet_len ||
            crc32_update(0, packet, packet_len) != packet_crc) {
            secure_free(packet, recovered_len);
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        *out_encrypted_packet = packet;
        *out_encrypted_packet_len = packet_len;
        extracted = TRUE;
        break;
    }

    for (int repetition = 1; !extracted && repetition <= 5; repetition += 2) {
        if (!read_frame_from_coefficients(&cinfo, coef_arrays, order, slot_count,
                                          header, DCT1_HEADER_BYTES, repetition)) {
            continue;
        }
        if (memcmp(header, DCT1_MAGIC, DCT_MAGIC_BYTES) != 0 ||
            header[6] != DCT1_VERSION ||
            header[7] != (BYTE)repetition) {
            continue;
        }
        DWORD payload_len = read_u32_le(header + 8);
        if (payload_len > APP_IMAGE_STEGO_MAX_PACKET_BYTES ||
            payload_len > 0xffffffffu - DCT1_HEADER_BYTES) {
            continue;
        }
        DWORD frame_len = payload_len + DCT1_HEADER_BYTES;
        if (!frame_fits_slots(slot_count, frame_len, repetition)) continue;
        frame = (BYTE *)xalloc(frame_len ? frame_len : 1);
        if (!frame) {
            set_error(err, err_cch, L"Out of memory.");
            goto cleanup;
        }
        frame_alloc_len = frame_len;
        if (!read_frame_from_coefficients(&cinfo, coef_arrays, order, slot_count,
                                          frame, frame_len, repetition)) {
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        if (memcmp(frame, DCT1_MAGIC, DCT_MAGIC_BYTES) != 0 ||
            frame[6] != DCT1_VERSION ||
            read_u32_le(frame + 8) != payload_len ||
            crc32_update(0, frame + DCT1_HEADER_BYTES, payload_len) != read_u32_le(frame + 12)) {
            secure_free(frame, frame_len);
            frame = NULL;
            frame_alloc_len = 0;
            continue;
        }
        BYTE *packet = (BYTE *)xalloc(payload_len ? payload_len : 1);
        if (!packet) {
            set_error(err, err_cch, L"Out of memory.");
            goto cleanup;
        }
        if (payload_len) CopyMemory(packet, frame + DCT1_HEADER_BYTES, payload_len);
        *out_encrypted_packet = packet;
        *out_encrypted_packet_len = payload_len;
        extracted = TRUE;
    }
    if (!extracted) set_error(err, err_cch, L"No recoverable hidden image payload was found.");

cleanup:
    secure_free(frame, frame_alloc_len);
    xfree(order);
    jpeg_destroy_decompress(&cinfo);
    if (infile) fclose(infile);
    return extracted;
}
