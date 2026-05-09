#include "app_chat_history.h"
#include "app_paths.h"
#include "app_shared.h"
#include "sqlite3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

static BYTE g_master[CHAT_HISTORY_KEY_BYTES] = {
    0x10, 0x22, 0x34, 0x46, 0x58, 0x6a, 0x7c, 0x8e,
    0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfd, 0x0f,
    0x01, 0x13, 0x25, 0x37, 0x49, 0x5b, 0x6d, 0x7f,
    0x80, 0x92, 0xa4, 0xb6, 0xc8, 0xda, 0xec, 0xfe
};

static void fail_wide(const WCHAR *message)
{
    fwprintf(stderr, L"FAIL: %s\n", message ? message : L"(null)");
    ExitProcess(1);
}

static void check(BOOL condition, const WCHAR *message)
{
    if (!condition) {
        fail_wide(message);
    }
}

static BOOL set_case_dir(const WCHAR *root, const WCHAR *name, WCHAR *out, size_t out_cch)
{
    if (FAILED(StringCchPrintfW(out, out_cch, L"%s\\%s", root, name))) {
        return FALSE;
    }
    CreateDirectoryW(root, NULL);
    CreateDirectoryW(out, NULL);
    return _wputenv_s(APP_ENV_DATA_DIR, out) == 0;
}

static BOOL contains_wide(const WCHAR *text, const WCHAR *needle)
{
    return text && needle && wcsstr(text, needle) != NULL;
}

static BOOL byte_slice_contains(const BYTE *haystack, DWORD haystack_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (!haystack || !needle_len || haystack_len < needle_len) {
        return FALSE;
    }
    for (DWORD idx = 0; idx <= haystack_len - needle_len; ++idx) {
        if (memcmp(haystack + idx, needle, needle_len) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static void db_path(WCHAR *path, size_t cch)
{
    check(get_app_file(path, cch, APP_CHAT_HISTORY_DB_NAME), L"chat DB path should resolve");
}

static void test_missing_db_returns_empty(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, L"missing", dir, ARRAYSIZE(dir)), L"set missing DB test dir");
    check(chat_history_load_private(L"profile-missing", g_master, &out, err, ARRAYSIZE(err)),
          L"missing DB load should succeed");
    check(out && out[0] == L'\0', L"missing DB should load empty history");
    secure_free_wide(out);
}

static void test_private_roundtrip_and_no_plaintext(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR path[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    BYTE *db_bytes = NULL;
    DWORD db_len = 0;

    check(set_case_dir(root, L"private_basic", dir, ARRAYSIZE(dir)), L"set private test dir");
    check(chat_history_append_private(L"profile-private", g_master, L"AliceSecret", L"alpha secret body", err, ARRAYSIZE(err)),
          L"private append should succeed");
    check(chat_history_load_private(L"profile-private", g_master, &out, err, ARRAYSIZE(err)),
          L"private load should succeed");
    check(contains_wide(out, L"\u53d1\u9001\u4eba\uff1aAliceSecret\r\nalpha secret body\r\n\r\n"),
          L"private load should reconstruct display record");
    secure_free_wide(out);

    db_path(path, ARRAYSIZE(path));
    check(read_file_bytes(path, &db_bytes, &db_len), L"chat DB should be readable for plaintext scan");
    check(!byte_slice_contains(db_bytes, db_len, "AliceSecret"), L"DB should not contain plaintext sender");
    check(!byte_slice_contains(db_bytes, db_len, "alpha secret body"), L"DB should not contain plaintext body");
    xfree(db_bytes);
}

static void test_private_order(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, L"private_order", dir, ARRAYSIZE(dir)), L"set order test dir");
    check(chat_history_append_private(L"profile-order", g_master, L"A", L"first", err, ARRAYSIZE(err)),
          L"first append should succeed");
    Sleep(10);
    check(chat_history_append_private(L"profile-order", g_master, L"A", L"second", err, ARRAYSIZE(err)),
          L"second append should succeed");
    check(chat_history_load_private(L"profile-order", g_master, &out, err, ARRAYSIZE(err)),
          L"ordered load should succeed");
    WCHAR *first = wcsstr(out, L"first");
    WCHAR *second = wcsstr(out, L"second");
    check(first && second && first < second, L"history should load oldest first");
    secure_free_wide(out);
}

static void exec_tamper_sql(const char *sql)
{
    WCHAR path[MAX_PATH];
    sqlite3 *db = NULL;
    char *error = NULL;
    db_path(path, ARRAYSIZE(path));
    check(sqlite3_open16(path, &db) == SQLITE_OK, L"open DB for tamper");
    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
        sqlite3_free(error);
        sqlite3_close(db);
        fail_wide(L"tamper SQL should succeed");
    }
    sqlite3_close(db);
}

static WCHAR *make_repeated_wide(WCHAR ch, size_t count)
{
    WCHAR *out = (WCHAR *)xalloc((count + 1) * sizeof(WCHAR));
    if (!out) {
        return NULL;
    }
    for (size_t idx = 0; idx < count; ++idx) {
        out[idx] = ch;
    }
    out[count] = L'\0';
    return out;
}

static void test_private_tamper_fails(const WCHAR *root, const WCHAR *case_name, const char *sql)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, case_name, dir, ARRAYSIZE(dir)), L"set tamper test dir");
    check(chat_history_append_private(L"profile-tamper", g_master, L"A", L"tamper body", err, ARRAYSIZE(err)),
          L"tamper append should succeed");
    exec_tamper_sql(sql);
    check(!chat_history_load_private(L"profile-tamper", g_master, &out, err, ARRAYSIZE(err)),
          L"tampered row should fail load");
    secure_free_wide(out);
}

static void test_schema_version_mismatch_fails(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, L"schema_mismatch", dir, ARRAYSIZE(dir)), L"set schema mismatch test dir");
    check(chat_history_append_private(L"profile-schema", g_master, L"A", L"schema body", err, ARRAYSIZE(err)),
          L"schema append should succeed");
    exec_tamper_sql("UPDATE meta SET value='999' WHERE key='schema_version';");
    check(!chat_history_load_private(L"profile-schema", g_master, &out, err, ARRAYSIZE(err)),
          L"schema mismatch should fail load");
    check(wcsstr(err, L"Unsupported chat history schema version") != NULL,
          L"schema mismatch should report unsupported version");
    secure_free_wide(out);
}

static void test_private_long_text(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    WCHAR *sender = make_repeated_wide(L'S', 1024);
    WCHAR *body = make_repeated_wide(L'B', 8192);
    check(sender && body, L"allocate long text");
    check(set_case_dir(root, L"private_long", dir, ARRAYSIZE(dir)), L"set long text test dir");
    check(chat_history_append_private(L"profile-long", g_master, sender, body, err, ARRAYSIZE(err)),
          L"long private append should succeed");
    check(chat_history_load_private(L"profile-long", g_master, &out, err, ARRAYSIZE(err)),
          L"long private load should succeed");
    check(wcsstr(out, sender) != NULL && wcsstr(out, body) != NULL,
          L"long private load should recover sender and body");
    secure_free_wide(out);
    secure_free_wide(sender);
    secure_free_wide(body);
}

static void test_group_roundtrip(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, L"group_basic", dir, ARRAYSIZE(dir)), L"set group test dir");
    check(chat_history_append_group(0x1122334455667788ULL, L"GroupAlice", L"group body", err, ARRAYSIZE(err)),
          L"group append should succeed");
    check(chat_history_load_group(0x1122334455667788ULL, &out, err, ARRAYSIZE(err)),
          L"group load should succeed");
    check(contains_wide(out, L"\u53d1\u9001\u4eba\uff1aGroupAlice\r\ngroup body\r\n\r\n"),
          L"group load should reconstruct display record");
    secure_free_wide(out);
}

static void test_group_wrapped_key_tamper_fails(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    check(set_case_dir(root, L"group_key_tamper", dir, ARRAYSIZE(dir)), L"set group key tamper test dir");
    check(chat_history_append_group(0x1020304050607080ULL, L"GroupAlice", L"group secret body", err, ARRAYSIZE(err)),
          L"group append should succeed");
    exec_tamper_sql("UPDATE group_history_keys SET wrapped_key=zeroblob(length(wrapped_key));");
    check(!chat_history_load_group(0x1020304050607080ULL, &out, err, ARRAYSIZE(err)),
          L"tampered group history key should fail load");
    secure_free_wide(out);
}

static void test_corrupt_db_fails(const WCHAR *root)
{
    WCHAR dir[MAX_PATH];
    WCHAR path[MAX_PATH];
    WCHAR err[512] = L"";
    WCHAR *out = NULL;
    BYTE junk[] = { 'n', 'o', 't', ' ', 's', 'q', 'l', 'i', 't', 'e' };
    check(set_case_dir(root, L"corrupt", dir, ARRAYSIZE(dir)), L"set corrupt test dir");
    db_path(path, ARRAYSIZE(path));
    check(write_file_bytes(path, junk, sizeof(junk)), L"write corrupt DB");
    check(!chat_history_load_private(L"profile-corrupt", g_master, &out, err, ARRAYSIZE(err)),
          L"corrupt DB should fail clearly");
    secure_free_wide(out);
}

int wmain(int argc, WCHAR **argv)
{
    if (argc < 2) {
        fail_wide(L"usage: chat_history_sqlite_test <temp-root>");
    }

    test_missing_db_returns_empty(argv[1]);
    test_private_roundtrip_and_no_plaintext(argv[1]);
    test_private_order(argv[1]);
    test_private_tamper_fails(argv[1], L"tamper_tag", "UPDATE messages SET tag=zeroblob(16);");
    test_private_tamper_fails(argv[1], L"tamper_nonce", "UPDATE messages SET nonce=zeroblob(12);");
    test_private_tamper_fails(argv[1], L"tamper_ciphertext", "UPDATE messages SET ciphertext=zeroblob(length(ciphertext));");
    test_private_tamper_fails(argv[1], L"tamper_aad", "UPDATE messages SET timestamp_ms=timestamp_ms+1;");
    test_schema_version_mismatch_fails(argv[1]);
    test_private_long_text(argv[1]);
    test_group_roundtrip(argv[1]);
    test_group_wrapped_key_tamper_fails(argv[1]);
    test_corrupt_db_fails(argv[1]);

    wprintf(L"ok chat_history_sqlite_test\n");
    return 0;
}
