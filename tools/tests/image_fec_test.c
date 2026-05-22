#include "app_image_fec.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

static void fill_packet(BYTE *packet, DWORD len) {
    for (DWORD idx = 0; idx < len; ++idx) {
        packet[idx] = (BYTE)((idx * 131u + 17u) & 0xffu);
    }
}

static int test_mode(int robustness, DWORD packet_len) {
    BYTE data_bytes = 0, parity_bytes = 0;
    BYTE *packet = NULL;
    BYTE *encoded = NULL;
    BYTE *decoded = NULL;
    DWORD encoded_len = 0, decoded_len = 0;
    WCHAR err[256] = L"";
    int failed = 1;

    if (!app_image_fec_params_for_robustness(robustness, &data_bytes, &parity_bytes)) goto cleanup;
    packet = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packet_len ? packet_len : 1);
    if (!packet) goto cleanup;
    fill_packet(packet, packet_len);
    if (!app_image_fec_encode(packet, packet_len, data_bytes, parity_bytes,
                              &encoded, &encoded_len, err, ARRAYSIZE(err))) goto cleanup;

    int correctable = parity_bytes / 2;
    for (int idx = 0; idx < correctable && idx < 24; ++idx) {
        DWORD pos = (DWORD)((idx * 37u + 11u) % 255u);
        encoded[pos] ^= (BYTE)(0x33u + idx);
    }
    if (!app_image_fec_decode(encoded, encoded_len, packet_len, data_bytes, parity_bytes,
                              &decoded, &decoded_len, err, ARRAYSIZE(err))) goto cleanup;
    if (decoded_len != packet_len || memcmp(packet, decoded, packet_len) != 0) goto cleanup;
    HeapFree(GetProcessHeap(), 0, decoded);
    decoded = NULL;
    decoded_len = 0;
    HeapFree(GetProcessHeap(), 0, encoded);
    encoded = NULL;
    if (!app_image_fec_encode(packet, packet_len, data_bytes, parity_bytes,
                              &encoded, &encoded_len, err, ARRAYSIZE(err))) goto cleanup;
    for (int idx = 0; idx < correctable + 1 && idx < 64; ++idx) {
        DWORD pos = (DWORD)idx;
        encoded[pos] ^= (BYTE)(0x55u + idx);
    }
    if (app_image_fec_decode(encoded, encoded_len, packet_len, data_bytes, parity_bytes,
                             &decoded, &decoded_len, err, ARRAYSIZE(err))) {
        goto cleanup;
    }

    failed = 0;
cleanup:
    if (packet) HeapFree(GetProcessHeap(), 0, packet);
    if (encoded) HeapFree(GetProcessHeap(), 0, encoded);
    if (decoded) HeapFree(GetProcessHeap(), 0, decoded);
    return failed;
}

int wmain(void) {
    if (test_mode(0, 1024)) return 1;
    if (test_mode(1, 4097)) return 1;
    if (test_mode(2, 8191)) return 1;
    return 0;
}
