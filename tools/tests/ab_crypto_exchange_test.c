#include "crypto_box.h"
#include "app_groups.h"
#include "app_paths.h"
#include "app_shared.h"

#include <windows.h>
#include <strsafe.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define SESSION_PACKET_FORMAT 0x21u
#define SESSION_HEADER_BYTES 13u
#define SESSION_TAG_BYTES 12u
#define SESSION_OVERHEAD_BYTES (SESSION_HEADER_BYTES + SESSION_TAG_BYTES)
#define GROUP_PACKET_FORMAT 0x31u
#define GROUP_HEADER_BYTES 19u
#define GROUP_TAG_BYTES 12u
#define GROUP_OVERHEAD_BYTES (GROUP_HEADER_BYTES + GROUP_TAG_BYTES)

#define CONTACT_PACKAGE_INITIAL_BYTES 73u
#define CONTACT_PACKAGE_REPLY_BYTES 105u

static const BYTE MASTER_KEY_A[32] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87,
    0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x0f
};

static const BYTE MASTER_KEY_B[32] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
    0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x01
};

typedef struct TEST_MESSAGE {
    BYTE *bytes;
    DWORD len;
    const char *plain;
} TEST_MESSAGE;

typedef struct GROUP_TEST_MESSAGE {
    BYTE *bytes;
    DWORD len;
    const WCHAR *plain;
} GROUP_TEST_MESSAGE;

static int failf(const WCHAR *fmt, ...) {
    va_list args;
    fwprintf(stderr, L"FAIL: ");
    va_start(args, fmt);
    vfwprintf(stderr, fmt, args);
    va_end(args);
    fwprintf(stderr, L"\n");
    return 1;
}

static int check_file_exists(const WCHAR *path, const WCHAR *label) {
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return failf(L"%s not found: %ls", label, path);
    }
    return 0;
}

static const WCHAR *arg_value(int argc, WCHAR **argv, const WCHAR *name) {
    for (int arg_idx = 1; arg_idx + 1 < argc; ++arg_idx) {
        if (wcscmp(argv[arg_idx], name) == 0) return argv[arg_idx + 1];
    }
    return NULL;
}

static uint32_t read_counter(const BYTE *message, DWORD len) {
    if (!message || len < SESSION_HEADER_BYTES) return UINT32_MAX;
    return (uint32_t)message[9] |
           ((uint32_t)message[10] << 8) |
           ((uint32_t)message[11] << 16) |
           ((uint32_t)message[12] << 24);
}

static void write_session_counter(BYTE *message, DWORD len, uint32_t counter) {
    if (!message || len < SESSION_HEADER_BYTES) return;
    message[9] = (BYTE)(counter & 0xffu);
    message[10] = (BYTE)((counter >> 8) & 0xffu);
    message[11] = (BYTE)((counter >> 16) & 0xffu);
    message[12] = (BYTE)((counter >> 24) & 0xffu);
}

static void write_group_counter(BYTE *message, DWORD len, uint32_t counter) {
    if (!message || len < GROUP_HEADER_BYTES) return;
    message[15] = (BYTE)(counter & 0xffu);
    message[16] = (BYTE)((counter >> 8) & 0xffu);
    message[17] = (BYTE)((counter >> 16) & 0xffu);
    message[18] = (BYTE)((counter >> 24) & 0xffu);
}

static int open_box(const WCHAR *label, const BYTE master_key[32], const WCHAR *state_path, CRYPTO_BOX **out) {
    WCHAR err[512] = L"";
    if (!crypto_box_open(master_key, state_path, out, err, ARRAYSIZE(err))) {
        return failf(L"%s open failed: %ls", label, err);
    }
    return 0;
}

static int reopen_box(const WCHAR *label, const BYTE master_key[32], const WCHAR *state_path, CRYPTO_BOX **box) {
    crypto_box_close(*box);
    *box = NULL;
    return open_box(label, master_key, state_path, box);
}

static void free_message(TEST_MESSAGE *message) {
    if (!message) return;
    secure_free(message->bytes, message->len);
    ZeroMemory(message, sizeof(*message));
}

static void free_group_message(GROUP_TEST_MESSAGE *message) {
    if (!message) return;
    secure_free(message->bytes, message->len);
    ZeroMemory(message, sizeof(*message));
}

static int duplicate_message(const TEST_MESSAGE *source, TEST_MESSAGE *out) {
    ZeroMemory(out, sizeof(*out));
    out->bytes = (BYTE *)xalloc(source->len);
    if (!out->bytes) return failf(L"failed to duplicate session message");
    CopyMemory(out->bytes, source->bytes, source->len);
    out->len = source->len;
    out->plain = source->plain;
    return 0;
}

static int duplicate_group_message(const GROUP_TEST_MESSAGE *source, GROUP_TEST_MESSAGE *out) {
    ZeroMemory(out, sizeof(*out));
    out->bytes = (BYTE *)xalloc(source->len);
    if (!out->bytes) return failf(L"failed to duplicate group message");
    CopyMemory(out->bytes, source->bytes, source->len);
    out->len = source->len;
    out->plain = source->plain;
    return 0;
}

static int encrypt_text(CRYPTO_BOX *sender, const char *plain, TEST_MESSAGE *out) {
    WCHAR err[512] = L"";
    DWORD plain_len = (DWORD)strlen(plain);
    BYTE *encrypted = NULL;
    DWORD encrypted_len = 0;

    if (!crypto_box_encrypt(sender, (const BYTE *)plain, plain_len, &encrypted, &encrypted_len,
                            err, ARRAYSIZE(err))) {
        return failf(L"encrypt failed for '%S': %ls", plain, err);
    }
    if (!encrypted || encrypted_len != plain_len + SESSION_OVERHEAD_BYTES) {
        secure_free(encrypted, encrypted_len);
        return failf(L"encrypted length mismatch for '%S'", plain);
    }
    if (encrypted[0] != SESSION_PACKET_FORMAT) {
        secure_free(encrypted, encrypted_len);
        return failf(L"encrypted packet format mismatch for '%S'", plain);
    }

    out->bytes = encrypted;
    out->len = encrypted_len;
    out->plain = plain;
    return 0;
}

static int decrypt_text(CRYPTO_BOX *receiver, const TEST_MESSAGE *message) {
    WCHAR err[512] = L"";
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    DWORD expected_len = (DWORD)strlen(message->plain);

    if (!crypto_box_decrypt(receiver, message->bytes, message->len, &plain, &plain_len,
                            err, ARRAYSIZE(err))) {
        return failf(L"decrypt failed for '%S': %ls", message->plain, err);
    }
    if (plain_len != expected_len || memcmp(plain, message->plain, expected_len) != 0) {
        secure_free(plain, plain_len);
        return failf(L"decrypted text mismatch for '%S'", message->plain);
    }
    secure_free(plain, plain_len);
    return 0;
}

static int expect_decrypt_failure(CRYPTO_BOX *receiver, const BYTE *message, DWORD len, const WCHAR *label) {
    WCHAR err[512] = L"";
    BYTE *plain = NULL;
    DWORD plain_len = 0;
    if (crypto_box_decrypt(receiver, message, len, &plain, &plain_len, err, ARRAYSIZE(err))) {
        secure_free(plain, plain_len);
        return failf(L"%s unexpectedly decrypted", label);
    }
    return 0;
}

static int exchange_keys(CRYPTO_BOX *a_box, CRYPTO_BOX *b_box) {
    WCHAR err[512] = L"";
    BYTE *pkg_a = NULL;
    BYTE *pkg_b = NULL;
    DWORD pkg_a_len = 0;
    DWORD pkg_b_len = 0;
    BYTE recipient[32];
    BOOL has_recipient = FALSE;
    int result = 1;

    ZeroMemory(recipient, sizeof(recipient));

    if (!crypto_box_export_contact_package(a_box, &pkg_a, &pkg_a_len, err, ARRAYSIZE(err))) {
        failf(L"A export initial package failed: %ls", err);
        goto cleanup;
    }
    if (pkg_a_len != CONTACT_PACKAGE_INITIAL_BYTES) {
        failf(L"A initial package length was %lu, expected %u", pkg_a_len, CONTACT_PACKAGE_INITIAL_BYTES);
        goto cleanup;
    }
    if (!crypto_box_import_contact_package(b_box, pkg_a, pkg_a_len, err, ARRAYSIZE(err))) {
        failf(L"B import initial package failed: %ls", err);
        goto cleanup;
    }

    if (!crypto_box_export_contact_package(b_box, &pkg_b, &pkg_b_len, err, ARRAYSIZE(err))) {
        failf(L"B export reply package failed: %ls", err);
        goto cleanup;
    }
    if (pkg_b_len != CONTACT_PACKAGE_REPLY_BYTES) {
        failf(L"B reply package length was %lu, expected %u", pkg_b_len, CONTACT_PACKAGE_REPLY_BYTES);
        goto cleanup;
    }
    if (!crypto_box_contact_package_recipient_public(pkg_b, pkg_b_len, recipient, &has_recipient,
                                                    err, ARRAYSIZE(err)) || !has_recipient) {
        failf(L"B reply package did not include an addressed recipient: %ls", err);
        goto cleanup;
    }
    if (!crypto_box_import_contact_package(a_box, pkg_b, pkg_b_len, err, ARRAYSIZE(err))) {
        failf(L"A import reply package failed: %ls", err);
        goto cleanup;
    }

    fwprintf(stdout, L"PASS key exchange: A initial package + B addressed reply\n");
    result = 0;

cleanup:
    secure_free(pkg_a, pkg_a_len);
    secure_free(pkg_b, pkg_b_len);
    SecureZeroMemory(recipient, sizeof(recipient));
    return result;
}

static int test_round_trip(CRYPTO_BOX *a_box, CRYPTO_BOX *b_box) {
    TEST_MESSAGE a_to_b = {0};
    TEST_MESSAGE b_to_a = {0};
    int result = 1;

    if (encrypt_text(a_box, "A to B: round trip hello", &a_to_b)) goto cleanup;
    if (decrypt_text(b_box, &a_to_b)) goto cleanup;
    if (encrypt_text(b_box, "B to A: round trip reply", &b_to_a)) goto cleanup;
    if (decrypt_text(a_box, &b_to_a)) goto cleanup;

    fwprintf(stdout, L"PASS round trip: A->B and B->A\n");
    result = 0;

cleanup:
    free_message(&a_to_b);
    free_message(&b_to_a);
    return result;
}

static int test_one_way_many(CRYPTO_BOX *a_box, CRYPTO_BOX *b_box) {
    static const char *texts[] = {
        "A stream 0",
        "A stream 1",
        "A stream 2",
        "A stream 3",
        "A stream 4"
    };
    TEST_MESSAGE messages[ARRAYSIZE(texts)];
    int result = 1;

    ZeroMemory(messages, sizeof(messages));
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(texts); ++message_idx) {
        if (encrypt_text(a_box, texts[message_idx], &messages[message_idx])) goto cleanup;
    }
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(texts); ++message_idx) {
        if (decrypt_text(b_box, &messages[message_idx])) goto cleanup;
    }

    fwprintf(stdout, L"PASS one-way many: 5 sequential A->B messages\n");
    result = 0;

cleanup:
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(texts); ++message_idx) {
        free_message(&messages[message_idx]);
    }
    return result;
}

static int test_out_of_order(CRYPTO_BOX *a_box, CRYPTO_BOX **b_box,
                             const WCHAR *b_state_path) {
    TEST_MESSAGE messages[3];
    int result = 1;

    ZeroMemory(messages, sizeof(messages));
    if (encrypt_text(a_box, "out-of-order 0", &messages[0])) goto cleanup;
    if (encrypt_text(a_box, "out-of-order 1", &messages[1])) goto cleanup;
    if (encrypt_text(a_box, "out-of-order 2", &messages[2])) goto cleanup;

    if (read_counter(messages[1].bytes, messages[1].len) != read_counter(messages[0].bytes, messages[0].len) + 1 ||
        read_counter(messages[2].bytes, messages[2].len) != read_counter(messages[1].bytes, messages[1].len) + 1) {
        failf(L"out-of-order test counters are not consecutive");
        goto cleanup;
    }

    if (decrypt_text(*b_box, &messages[2])) goto cleanup;
    if (reopen_box(L"B", MASTER_KEY_B, b_state_path, b_box)) goto cleanup;
    if (decrypt_text(*b_box, &messages[0])) goto cleanup;
    if (decrypt_text(*b_box, &messages[1])) goto cleanup;

    fwprintf(stdout, L"PASS out-of-order: 2 before 0/1, skipped keys survive reopen\n");
    result = 0;

cleanup:
    for (int message_idx = 0; message_idx < 3; ++message_idx) free_message(&messages[message_idx]);
    return result;
}

static int test_packet_loss(CRYPTO_BOX *a_box, CRYPTO_BOX *b_box) {
    TEST_MESSAGE lost_0 = {0};
    TEST_MESSAGE lost_1 = {0};
    TEST_MESSAGE delivered_2 = {0};
    TEST_MESSAGE after_loss = {0};
    int result = 1;

    if (encrypt_text(a_box, "lost packet 0", &lost_0)) goto cleanup;
    if (encrypt_text(a_box, "lost packet 1", &lost_1)) goto cleanup;
    if (encrypt_text(a_box, "delivered packet 2", &delivered_2)) goto cleanup;
    if (decrypt_text(b_box, &delivered_2)) goto cleanup;
    if (encrypt_text(a_box, "message after dropped packets", &after_loss)) goto cleanup;
    if (decrypt_text(b_box, &after_loss)) goto cleanup;

    fwprintf(stdout, L"PASS packet loss: later A->B messages decrypt after skipped packets\n");
    result = 0;

cleanup:
    free_message(&lost_0);
    free_message(&lost_1);
    free_message(&delivered_2);
    free_message(&after_loss);
    return result;
}

static int test_session_edge_cases(CRYPTO_BOX *a_box, CRYPTO_BOX *b_box) {
    TEST_MESSAGE valid = {0};
    TEST_MESSAGE tampered = {0};
    TEST_MESSAGE replay = {0};
    TEST_MESSAGE overflow[66];
    int result = 1;

    ZeroMemory(overflow, sizeof(overflow));
    if (encrypt_text(a_box, "edge valid", &valid)) goto cleanup;

    if (expect_decrypt_failure(b_box, valid.bytes, SESSION_HEADER_BYTES - 1, L"malformed session packet")) goto cleanup;

    if (duplicate_message(&valid, &tampered)) goto cleanup;
    tampered.bytes[0] = 0x99u;
    if (expect_decrypt_failure(b_box, tampered.bytes, tampered.len, L"wrong-format session packet")) goto cleanup;
    free_message(&tampered);

    if (duplicate_message(&valid, &tampered)) goto cleanup;
    tampered.bytes[1] ^= 0x40u;
    if (expect_decrypt_failure(b_box, tampered.bytes, tampered.len, L"tampered session header")) goto cleanup;
    free_message(&tampered);

    if (duplicate_message(&valid, &tampered)) goto cleanup;
    tampered.bytes[SESSION_HEADER_BYTES] ^= 0x40u;
    if (expect_decrypt_failure(b_box, tampered.bytes, tampered.len, L"tampered session tag")) goto cleanup;
    free_message(&tampered);

    if (duplicate_message(&valid, &tampered)) goto cleanup;
    write_session_counter(tampered.bytes, tampered.len, UINT32_MAX);
    if (expect_decrypt_failure(b_box, tampered.bytes, tampered.len, L"max-counter session packet")) goto cleanup;
    free_message(&tampered);

    if (decrypt_text(b_box, &valid)) goto cleanup;

    if (encrypt_text(a_box, "session replay", &replay)) goto cleanup;
    if (decrypt_text(b_box, &replay)) goto cleanup;
    if (expect_decrypt_failure(b_box, replay.bytes, replay.len, L"replayed session packet")) goto cleanup;

    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(overflow); ++message_idx) {
        if (encrypt_text(a_box, "overflow window packet", &overflow[message_idx])) goto cleanup;
    }
    if (expect_decrypt_failure(b_box, overflow[65].bytes, overflow[65].len,
                               L"session skipped-key window overflow")) goto cleanup;
    if (decrypt_text(b_box, &overflow[0])) goto cleanup;

    fwprintf(stdout, L"PASS session edges: malformed, tamper, replay, overflow, max counter\n");
    result = 0;

cleanup:
    free_message(&valid);
    free_message(&tampered);
    free_message(&replay);
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(overflow); ++message_idx) {
        free_message(&overflow[message_idx]);
    }
    return result;
}

static int test_reopen_continuation(CRYPTO_BOX **a_box, CRYPTO_BOX **b_box,
                                    const WCHAR *a_state_path,
                                    const WCHAR *b_state_path) {
    TEST_MESSAGE message = {0};
    int result = 1;

    if (reopen_box(L"A", MASTER_KEY_A, a_state_path, a_box)) goto cleanup;
    if (reopen_box(L"B", MASTER_KEY_B, b_state_path, b_box)) goto cleanup;
    if (encrypt_text(*a_box, "post-reopen continuation", &message)) goto cleanup;
    if (decrypt_text(*b_box, &message)) goto cleanup;

    fwprintf(stdout, L"PASS persistence: reopened A/B continue the session\n");
    result = 0;

cleanup:
    free_message(&message);
    return result;
}

static int make_child_dir_from_state(const WCHAR *state_path, const WCHAR *child_name, WCHAR *out, size_t cch) {
    WCHAR parent[MAX_PATH];
    if (FAILED(StringCchCopyW(parent, ARRAYSIZE(parent), state_path))) {
        return failf(L"state path is too long");
    }
    strip_last_path_component_early(parent);
    if (FAILED(StringCchPrintfW(out, cch, L"%s\\%s", parent, child_name))) {
        return failf(L"group test directory path is too long");
    }
    if (!CreateDirectoryW(out, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return failf(L"failed to create group test directory: %ls", out);
    }
    return 0;
}

static int switch_group_store(const WCHAR *label, const WCHAR *dir) {
    WCHAR err[512] = L"";
    app_groups_shutdown();
    if (!SetEnvironmentVariableW(APP_ENV_DATA_DIR, dir)) {
        return failf(L"%s failed to set group data dir: %ls", label, dir);
    }
    if (!app_groups_load(err, ARRAYSIZE(err))) {
        return failf(L"%s failed to load group store: %ls", label, err);
    }
    return 0;
}

static int setup_group_pair(const WCHAR *a_group_dir, const WCHAR *b_group_dir) {
    WCHAR err[512] = L"";
    BYTE *invite = NULL;
    DWORD invite_len = 0;
    WCHAR *import_message = NULL;
    int group_index = -1;
    int result = 1;

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (!app_groups_create(L"Test Group", L"Alice", &group_index, err, ARRAYSIZE(err))) {
        failf(L"A group create failed: %ls", err);
        goto cleanup;
    }
    if (!app_groups_export_package(group_index, &invite, &invite_len, err, ARRAYSIZE(err))) {
        failf(L"A group export failed: %ls", err);
        goto cleanup;
    }

    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (!app_groups_import_package(invite, invite_len, L"Test Group", L"Bob",
                                   &group_index, &import_message, err, ARRAYSIZE(err))) {
        failf(L"B group import failed: %ls", err);
        goto cleanup;
    }

    fwprintf(stdout, L"PASS group setup: A create/export + B import\n");
    result = 0;

cleanup:
    secure_free(invite, invite_len);
    secure_free_wide(import_message);
    return result;
}

static int group_encrypt_text(int group_index, const WCHAR *plain, GROUP_TEST_MESSAGE *out) {
    WCHAR err[512] = L"";
    BYTE *encrypted = NULL;
    DWORD encrypted_len = 0;
    if (!app_groups_encrypt_message(group_index, plain, &encrypted, &encrypted_len, err, ARRAYSIZE(err))) {
        return failf(L"group encrypt failed for '%ls': %ls", plain, err);
    }
    if (!encrypted || encrypted_len < GROUP_OVERHEAD_BYTES || encrypted[0] != GROUP_PACKET_FORMAT) {
        secure_free(encrypted, encrypted_len);
        return failf(L"group encrypted packet shape mismatch for '%ls'", plain);
    }
    out->bytes = encrypted;
    out->len = encrypted_len;
    out->plain = plain;
    return 0;
}

static int group_decrypt_text(const GROUP_TEST_MESSAGE *message) {
    WCHAR err[512] = L"";
    WCHAR *plain = NULL;
    WCHAR *sender = NULL;
    int group_index = -1;
    if (!app_groups_decrypt_message(message->bytes, message->len, &plain, &sender,
                                    &group_index, err, ARRAYSIZE(err))) {
        return failf(L"group decrypt failed for '%ls': %ls", message->plain, err);
    }
    if (wcscmp(plain ? plain : L"", message->plain) != 0) {
        secure_free_wide(plain);
        secure_free_wide(sender);
        return failf(L"group decrypted text mismatch for '%ls'", message->plain);
    }
    secure_free_wide(plain);
    secure_free_wide(sender);
    return 0;
}

static int expect_group_decrypt_failure(const BYTE *message, DWORD len, const WCHAR *label) {
    WCHAR err[512] = L"";
    WCHAR *plain = NULL;
    WCHAR *sender = NULL;
    int group_index = -1;
    if (app_groups_decrypt_message(message, len, &plain, &sender, &group_index, err, ARRAYSIZE(err))) {
        secure_free_wide(plain);
        secure_free_wide(sender);
        return failf(L"%s unexpectedly decrypted", label);
    }
    return 0;
}

static int test_group_transport_edges(const WCHAR *a_group_dir, const WCHAR *b_group_dir) {
    GROUP_TEST_MESSAGE valid = {0};
    GROUP_TEST_MESSAGE messages[3];
    GROUP_TEST_MESSAGE replay = {0};
    GROUP_TEST_MESSAGE tampered = {0};
    GROUP_TEST_MESSAGE overflow[66];
    int result = 1;

    ZeroMemory(messages, sizeof(messages));
    ZeroMemory(overflow, sizeof(overflow));

    if (setup_group_pair(a_group_dir, b_group_dir)) goto cleanup;

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (group_encrypt_text(0, L"group hello", &valid)) goto cleanup;
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (group_decrypt_text(&valid)) goto cleanup;

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (group_encrypt_text(0, L"group order 0", &messages[0])) goto cleanup;
    if (group_encrypt_text(0, L"group order 1", &messages[1])) goto cleanup;
    if (group_encrypt_text(0, L"group order 2", &messages[2])) goto cleanup;
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (group_decrypt_text(&messages[2])) goto cleanup;
    if (group_decrypt_text(&messages[0])) goto cleanup;
    if (group_decrypt_text(&messages[1])) goto cleanup;
    if (expect_group_decrypt_failure(messages[0].bytes, messages[0].len, L"replayed group packet")) goto cleanup;

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (group_encrypt_text(0, L"group tamper header", &replay)) goto cleanup;
    if (duplicate_group_message(&replay, &tampered)) goto cleanup;
    tampered.bytes[1] ^= 0x40u;
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (expect_group_decrypt_failure(tampered.bytes, tampered.len, L"tampered group header")) goto cleanup;
    if (group_decrypt_text(&replay)) goto cleanup;
    free_group_message(&tampered);
    free_group_message(&replay);

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (group_encrypt_text(0, L"group tamper tag", &replay)) goto cleanup;
    if (duplicate_group_message(&replay, &tampered)) goto cleanup;
    tampered.bytes[GROUP_HEADER_BYTES] ^= 0x40u;
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (expect_group_decrypt_failure(tampered.bytes, tampered.len, L"tampered group tag")) goto cleanup;
    if (group_decrypt_text(&replay)) goto cleanup;
    free_group_message(&tampered);
    free_group_message(&replay);

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    if (group_encrypt_text(0, L"group max counter", &replay)) goto cleanup;
    if (duplicate_group_message(&replay, &tampered)) goto cleanup;
    write_group_counter(tampered.bytes, tampered.len, UINT32_MAX);
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (expect_group_decrypt_failure(tampered.bytes, tampered.len, L"max-counter group packet")) goto cleanup;
    if (group_decrypt_text(&replay)) goto cleanup;
    free_group_message(&tampered);
    free_group_message(&replay);

    if (switch_group_store(L"A group", a_group_dir)) goto cleanup;
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(overflow); ++message_idx) {
        if (group_encrypt_text(0, L"group overflow window packet", &overflow[message_idx])) goto cleanup;
    }
    if (switch_group_store(L"B group", b_group_dir)) goto cleanup;
    if (expect_group_decrypt_failure(overflow[65].bytes, overflow[65].len,
                                     L"group skipped-key window overflow")) goto cleanup;
    if (group_decrypt_text(&overflow[0])) goto cleanup;

    fwprintf(stdout, L"PASS group edges: decrypt, out-of-order, replay, tamper, overflow, max counter\n");
    result = 0;

cleanup:
    free_group_message(&valid);
    for (int message_idx = 0; message_idx < 3; ++message_idx) free_group_message(&messages[message_idx]);
    free_group_message(&replay);
    free_group_message(&tampered);
    for (int message_idx = 0; message_idx < (int)ARRAYSIZE(overflow); ++message_idx) {
        free_group_message(&overflow[message_idx]);
    }
    app_groups_shutdown();
    SetEnvironmentVariableW(APP_ENV_DATA_DIR, NULL);
    return result;
}

int wmain(int argc, WCHAR **argv) {
    const WCHAR *a_exe = arg_value(argc, argv, L"--a-exe");
    const WCHAR *b_exe = arg_value(argc, argv, L"--b-exe");
    const WCHAR *a_state_path = arg_value(argc, argv, L"--a-state");
    const WCHAR *b_state_path = arg_value(argc, argv, L"--b-state");
    WCHAR a_group_dir[MAX_PATH] = L"";
    WCHAR b_group_dir[MAX_PATH] = L"";
    CRYPTO_BOX *a_box = NULL;
    CRYPTO_BOX *b_box = NULL;
    int result = 1;

    if (!a_exe || !b_exe || !a_state_path || !b_state_path) {
        fwprintf(stderr, L"usage: ab_crypto_exchange_test.exe --a-exe PATH --b-exe PATH --a-state PATH --b-state PATH\n");
        return 2;
    }

    if (check_file_exists(a_exe, L"A executable") ||
        check_file_exists(b_exe, L"B executable")) {
        goto cleanup;
    }

    fwprintf(stdout, L"A exe: %ls\n", a_exe);
    fwprintf(stdout, L"B exe: %ls\n", b_exe);
    fwprintf(stdout, L"A state: %ls\n", a_state_path);
    fwprintf(stdout, L"B state: %ls\n", b_state_path);
    if (make_child_dir_from_state(a_state_path, L"group_a", a_group_dir, ARRAYSIZE(a_group_dir)) ||
        make_child_dir_from_state(b_state_path, L"group_b", b_group_dir, ARRAYSIZE(b_group_dir))) {
        goto cleanup;
    }

    if (open_box(L"A", MASTER_KEY_A, a_state_path, &a_box)) goto cleanup;
    if (open_box(L"B", MASTER_KEY_B, b_state_path, &b_box)) goto cleanup;
    if (exchange_keys(a_box, b_box)) goto cleanup;
    if (test_reopen_continuation(&a_box, &b_box, a_state_path, b_state_path)) goto cleanup;
    if (test_round_trip(a_box, b_box)) goto cleanup;
    if (test_one_way_many(a_box, b_box)) goto cleanup;
    if (test_out_of_order(a_box, &b_box, b_state_path)) goto cleanup;
    if (test_packet_loss(a_box, b_box)) goto cleanup;
    if (test_reopen_continuation(&a_box, &b_box, a_state_path, b_state_path)) goto cleanup;
    if (test_session_edge_cases(a_box, b_box)) goto cleanup;
    if (test_group_transport_edges(a_group_dir, b_group_dir)) goto cleanup;

    fwprintf(stdout, L"PASS all AB install crypto exchange tests\n");
    result = 0;

cleanup:
    crypto_box_close(a_box);
    crypto_box_close(b_box);
    return result;
}
