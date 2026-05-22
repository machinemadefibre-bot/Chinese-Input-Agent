#include "app_image_fec.h"

#include "app_shared.h"

#include <stdint.h>
#include <string.h>

#define RS_CODEWORD_BYTES 255
#define RS_MAX_PARITY_BYTES 64
#define RS_MAX_ERRORS (RS_MAX_PARITY_BYTES / 2)

static BYTE gf_exp[512];
static BYTE gf_log[256];
static BOOL gf_ready;

static void gf_init(void) {
    if (gf_ready) return;
    unsigned x = 1;
    for (int idx = 0; idx < 255; ++idx) {
        gf_exp[idx] = (BYTE)x;
        gf_log[x] = (BYTE)idx;
        x <<= 1;
        if (x & 0x100u) x ^= 0x11du;
    }
    for (int idx = 255; idx < 512; ++idx) gf_exp[idx] = gf_exp[idx - 255];
    gf_ready = TRUE;
}

static BYTE gf_mul(BYTE a, BYTE b) {
    if (!a || !b) return 0;
    return gf_exp[(int)gf_log[a] + (int)gf_log[b]];
}

static BYTE gf_div(BYTE a, BYTE b) {
    if (!a) return 0;
    if (!b) return 0;
    return gf_exp[(int)gf_log[a] + 255 - (int)gf_log[b]];
}

static BYTE gf_inv(BYTE value) {
    return value ? gf_exp[255 - gf_log[value]] : 0;
}

static BYTE gf_pow_alpha(int power) {
    power %= 255;
    if (power < 0) power += 255;
    return gf_exp[power];
}

static BYTE poly_eval_high(const BYTE *poly, int len, BYTE x) {
    BYTE y = poly[0];
    for (int idx = 1; idx < len; ++idx) {
        y = gf_mul(y, x) ^ poly[idx];
    }
    return y;
}

static BYTE poly_eval_low(const BYTE *poly, int len, BYTE x) {
    BYTE y = 0;
    for (int idx = len - 1; idx >= 0; --idx) {
        y = gf_mul(y, x) ^ poly[idx];
    }
    return y;
}

static void generator_poly(BYTE parity_bytes, BYTE *generator) {
    BYTE next[RS_MAX_PARITY_BYTES + 1];
    ZeroMemory(generator, RS_MAX_PARITY_BYTES + 1);
    generator[0] = 1;
    int len = 1;
    for (int idx = 0; idx < parity_bytes; ++idx) {
        ZeroMemory(next, sizeof(next));
        BYTE root = gf_pow_alpha(idx);
        for (int term = 0; term < len; ++term) {
            next[term] ^= generator[term];
            next[term + 1] ^= gf_mul(generator[term], root);
        }
        CopyMemory(generator, next, sizeof(next));
        ++len;
    }
    SecureZeroMemory(next, sizeof(next));
}

static void rs_encode_block(const BYTE *data, BYTE data_bytes,
                            BYTE parity_bytes, BYTE out[RS_CODEWORD_BYTES]) {
    BYTE generator[RS_MAX_PARITY_BYTES + 1];
    BYTE work[RS_CODEWORD_BYTES];
    ZeroMemory(out, RS_CODEWORD_BYTES);
    CopyMemory(out, data, data_bytes);
    CopyMemory(work, out, RS_CODEWORD_BYTES);
    generator_poly(parity_bytes, generator);
    for (int idx = 0; idx < data_bytes; ++idx) {
        BYTE coef = work[idx];
        if (!coef) continue;
        for (int gen_idx = 1; gen_idx <= parity_bytes; ++gen_idx) {
            work[idx + gen_idx] ^= gf_mul(generator[gen_idx], coef);
        }
    }
    CopyMemory(out + data_bytes, work + data_bytes, parity_bytes);
    SecureZeroMemory(generator, sizeof(generator));
    SecureZeroMemory(work, sizeof(work));
}

static BOOL calc_syndromes(const BYTE *codeword, BYTE parity_bytes, BYTE *syndromes) {
    BOOL clean = TRUE;
    for (int idx = 0; idx < parity_bytes; ++idx) {
        syndromes[idx] = poly_eval_high(codeword, RS_CODEWORD_BYTES, gf_pow_alpha(idx));
        if (syndromes[idx]) clean = FALSE;
    }
    return clean;
}

static BOOL find_error_locator(const BYTE *syndromes, BYTE parity_bytes,
                               BYTE *locator, int *out_errors) {
    BYTE previous[RS_MAX_PARITY_BYTES + 1];
    BYTE snapshot[RS_MAX_PARITY_BYTES + 1];
    int locator_degree = 0;
    int shift = 1;
    BYTE last_delta = 1;

    ZeroMemory(locator, RS_MAX_PARITY_BYTES + 1);
    ZeroMemory(previous, sizeof(previous));
    locator[0] = 1;
    previous[0] = 1;

    for (int step = 0; step < parity_bytes; ++step) {
        BYTE delta = syndromes[step];
        for (int idx = 1; idx <= locator_degree; ++idx) {
            delta ^= gf_mul(locator[idx], syndromes[step - idx]);
        }
        if (!delta) {
            ++shift;
            continue;
        }

        CopyMemory(snapshot, locator, sizeof(snapshot));
        BYTE scale = gf_div(delta, last_delta);
        for (int idx = 0; idx + shift <= parity_bytes; ++idx) {
            if (previous[idx]) locator[idx + shift] ^= gf_mul(scale, previous[idx]);
        }

        if (locator_degree * 2 <= step) {
            locator_degree = step + 1 - locator_degree;
            CopyMemory(previous, snapshot, sizeof(previous));
            last_delta = delta;
            shift = 1;
        } else {
            ++shift;
        }
    }

    SecureZeroMemory(previous, sizeof(previous));
    SecureZeroMemory(snapshot, sizeof(snapshot));
    if (locator_degree <= 0 || locator_degree > parity_bytes / 2 ||
        locator_degree > RS_MAX_ERRORS) {
        return FALSE;
    }
    *out_errors = locator_degree;
    return TRUE;
}

static BOOL solve_error_values(const BYTE *syndromes,
                               const BYTE *error_x,
                               int error_count,
                               BYTE *values) {
    BYTE matrix[RS_MAX_ERRORS][RS_MAX_ERRORS + 1];
    ZeroMemory(matrix, sizeof(matrix));
    for (int row = 0; row < error_count; ++row) {
        for (int col = 0; col < error_count; ++col) {
            BYTE value = 1;
            for (int power = 0; power < row; ++power) {
                value = gf_mul(value, error_x[col]);
            }
            matrix[row][col] = value;
        }
        matrix[row][error_count] = syndromes[row];
    }

    for (int col = 0; col < error_count; ++col) {
        int pivot = col;
        while (pivot < error_count && !matrix[pivot][col]) ++pivot;
        if (pivot == error_count) return FALSE;
        if (pivot != col) {
            for (int idx = col; idx <= error_count; ++idx) {
                BYTE tmp = matrix[col][idx];
                matrix[col][idx] = matrix[pivot][idx];
                matrix[pivot][idx] = tmp;
            }
        }
        BYTE inv = gf_inv(matrix[col][col]);
        if (!inv) return FALSE;
        for (int idx = col; idx <= error_count; ++idx) matrix[col][idx] = gf_mul(matrix[col][idx], inv);
        for (int row = 0; row < error_count; ++row) {
            if (row == col || !matrix[row][col]) continue;
            BYTE factor = matrix[row][col];
            for (int idx = col; idx <= error_count; ++idx) {
                matrix[row][idx] ^= gf_mul(factor, matrix[col][idx]);
            }
        }
    }

    for (int idx = 0; idx < error_count; ++idx) values[idx] = matrix[idx][error_count];
    SecureZeroMemory(matrix, sizeof(matrix));
    return TRUE;
}

static BOOL rs_correct_block(BYTE codeword[RS_CODEWORD_BYTES], BYTE parity_bytes) {
    BYTE syndromes[RS_MAX_PARITY_BYTES];
    BYTE locator[RS_MAX_PARITY_BYTES + 1];
    int error_positions[RS_MAX_ERRORS];
    BYTE error_x[RS_MAX_ERRORS];
    BYTE error_values[RS_MAX_ERRORS];
    int error_count = 0;
    int found = 0;

    if (calc_syndromes(codeword, parity_bytes, syndromes)) return TRUE;
    if (!find_error_locator(syndromes, parity_bytes, locator, &error_count)) return FALSE;

    for (int pos = 0; pos < RS_CODEWORD_BYTES && found < error_count; ++pos) {
        int power = (RS_CODEWORD_BYTES - 1 - pos) % 255;
        BYTE inverse_x = gf_pow_alpha(-power);
        if (poly_eval_low(locator, error_count + 1, inverse_x) == 0) {
            error_positions[found] = pos;
            error_x[found] = gf_pow_alpha(power);
            ++found;
        }
    }
    if (found != error_count) return FALSE;

    ZeroMemory(error_values, sizeof(error_values));
    if (!solve_error_values(syndromes, error_x, error_count, error_values)) return FALSE;
    for (int idx = 0; idx < error_count; ++idx) {
        codeword[error_positions[idx]] ^= error_values[idx];
    }

    SecureZeroMemory(syndromes, sizeof(syndromes));
    SecureZeroMemory(locator, sizeof(locator));
    SecureZeroMemory(error_positions, sizeof(error_positions));
    SecureZeroMemory(error_x, sizeof(error_x));
    SecureZeroMemory(error_values, sizeof(error_values));
    return calc_syndromes(codeword, parity_bytes, syndromes);
}

BOOL app_image_fec_params_for_robustness(int robustness_level,
                                         BYTE *data_bytes,
                                         BYTE *parity_bytes) {
    if (!data_bytes || !parity_bytes) return FALSE;
    if (robustness_level <= 0) {
        *data_bytes = 239;
        *parity_bytes = 16;
    } else if (robustness_level == 1) {
        *data_bytes = 223;
        *parity_bytes = 32;
    } else {
        *data_bytes = 191;
        *parity_bytes = 64;
    }
    return TRUE;
}

BOOL app_image_fec_encoded_len(DWORD packet_len,
                               BYTE data_bytes,
                               BYTE parity_bytes,
                               DWORD *out_len) {
    if (!out_len || data_bytes == 0 || (int)data_bytes + (int)parity_bytes != RS_CODEWORD_BYTES) return FALSE;
    if (packet_len == 0) {
        *out_len = 0;
        return TRUE;
    }
    DWORD blocks = (packet_len + data_bytes - 1u) / data_bytes;
    if (blocks > 0xffffffffu / RS_CODEWORD_BYTES) return FALSE;
    *out_len = blocks * RS_CODEWORD_BYTES;
    return TRUE;
}

BOOL app_image_fec_encode(const BYTE *packet,
                          DWORD packet_len,
                          BYTE data_bytes,
                          BYTE parity_bytes,
                          BYTE **out,
                          DWORD *out_len,
                          WCHAR *err,
                          size_t err_cch) {
    BYTE *encoded = NULL;
    DWORD encoded_len = 0;
    *out = NULL;
    *out_len = 0;
    if ((!packet && packet_len) ||
        !app_image_fec_encoded_len(packet_len, data_bytes, parity_bytes, &encoded_len)) {
        set_error(err, err_cch, L"Invalid image FEC request.");
        return FALSE;
    }
    gf_init();
    encoded = (BYTE *)xalloc(encoded_len ? encoded_len : 1);
    if (!encoded) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    DWORD offset = 0;
    DWORD out_pos = 0;
    while (offset < packet_len) {
        BYTE block[RS_CODEWORD_BYTES];
        BYTE data[RS_CODEWORD_BYTES];
        DWORD take = packet_len - offset;
        if (take > data_bytes) take = data_bytes;
        ZeroMemory(data, sizeof(data));
        CopyMemory(data, packet + offset, take);
        rs_encode_block(data, data_bytes, parity_bytes, block);
        CopyMemory(encoded + out_pos, block, RS_CODEWORD_BYTES);
        SecureZeroMemory(block, sizeof(block));
        SecureZeroMemory(data, sizeof(data));
        offset += take;
        out_pos += RS_CODEWORD_BYTES;
    }
    *out = encoded;
    *out_len = encoded_len;
    return TRUE;
}

BOOL app_image_fec_decode(const BYTE *encoded,
                          DWORD encoded_len,
                          DWORD packet_len,
                          BYTE data_bytes,
                          BYTE parity_bytes,
                          BYTE **out,
                          DWORD *out_len,
                          WCHAR *err,
                          size_t err_cch) {
    BYTE *packet = NULL;
    DWORD expected_len = 0;
    *out = NULL;
    *out_len = 0;
    if ((!encoded && encoded_len) ||
        !app_image_fec_encoded_len(packet_len, data_bytes, parity_bytes, &expected_len) ||
        expected_len != encoded_len) {
        set_error(err, err_cch, L"Invalid image FEC frame.");
        return FALSE;
    }
    gf_init();
    packet = (BYTE *)xalloc(packet_len ? packet_len : 1);
    if (!packet) {
        set_error(err, err_cch, L"Out of memory.");
        return FALSE;
    }
    DWORD packet_pos = 0;
    for (DWORD offset = 0; offset < encoded_len; offset += RS_CODEWORD_BYTES) {
        BYTE block[RS_CODEWORD_BYTES];
        CopyMemory(block, encoded + offset, RS_CODEWORD_BYTES);
        if (!rs_correct_block(block, parity_bytes)) {
            SecureZeroMemory(block, sizeof(block));
            secure_free(packet, packet_len);
            set_error(err, err_cch, L"Image FEC recovery failed.");
            return FALSE;
        }
        DWORD take = packet_len - packet_pos;
        if (take > data_bytes) take = data_bytes;
        if (take) CopyMemory(packet + packet_pos, block, take);
        packet_pos += take;
        SecureZeroMemory(block, sizeof(block));
    }
    *out = packet;
    *out_len = packet_len;
    return TRUE;
}
