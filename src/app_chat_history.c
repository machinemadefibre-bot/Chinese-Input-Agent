#include "app_chat_history.h"
#include "app_paths.h"
#include "app_shared.h"

#include "sqlite3.h"

#include <bcrypt.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <wincrypt.h>

#define CHAT_SCHEMA_VERSION "1"
#define CHAT_KIND_PRIVATE 1
#define CHAT_KIND_GROUP 2
/* Kept at 0 intentionally: current UI does not need sent/received filtering,
   and writing it would expose more plaintext metadata in SQLite. */
#define CHAT_DIRECTION_UNKNOWN 0
#define CHAT_MESSAGE_UUID_BYTES 16
#define CHAT_NONCE_BYTES 12
#define CHAT_TAG_BYTES 16
#define CHAT_RECORD_VERSION 1
#define CHAT_TIMESTAMP_TEXT_BYTES 32
#define GROUP_HISTORY_ENTROPY_BYTES 20

typedef struct BYTE_BUILDER {
    BYTE *data;
    DWORD len;
    DWORD cap;
} BYTE_BUILDER;

static void byte_builder_free(BYTE_BUILDER *builder)
{
    if (!builder) {
        return;
    }
    xfree(builder->data);
    builder->data = NULL;
    builder->len = 0;
    builder->cap = 0;
}

static void byte_builder_secure_free(BYTE_BUILDER *builder)
{
    if (!builder) {
        return;
    }
    if (builder->data && builder->cap) {
        SecureZeroMemory(builder->data, builder->cap);
    }
    byte_builder_free(builder);
}

static BOOL byte_builder_reserve(BYTE_BUILDER *builder, DWORD needed)
{
    if (needed <= builder->cap) {
        return TRUE;
    }
    DWORD new_cap = builder->cap ? builder->cap : 256;
    while (new_cap < needed) {
        if (new_cap > 0x7fffffffU) {
            return FALSE;
        }
        new_cap *= 2;
    }
    BYTE *next = (BYTE *)xalloc(new_cap);
    if (!next) {
        return FALSE;
    }
    if (builder->data && builder->len) {
        memcpy(next, builder->data, builder->len);
    }
    if (builder->data && builder->cap) {
        SecureZeroMemory(builder->data, builder->cap);
        xfree(builder->data);
    }
    builder->data = next;
    builder->cap = new_cap;
    return TRUE;
}

static BOOL byte_builder_append(BYTE_BUILDER *builder, const void *data, DWORD len)
{
    if (!len) {
        return TRUE;
    }
    if (!data || builder->len > 0xffffffffU - len) {
        return FALSE;
    }
    if (!byte_builder_reserve(builder, builder->len + len)) {
        return FALSE;
    }
    memcpy(builder->data + builder->len, data, len);
    builder->len += len;
    return TRUE;
}

static BOOL byte_builder_append_u16_le(BYTE_BUILDER *builder, WORD value)
{
    BYTE bytes[2];
    bytes[0] = (BYTE)(value & 0xff);
    bytes[1] = (BYTE)((value >> 8) & 0xff);
    return byte_builder_append(builder, bytes, sizeof(bytes));
}

static BOOL byte_builder_append_u32_le(BYTE_BUILDER *builder, DWORD value)
{
    BYTE bytes[4];
    bytes[0] = (BYTE)(value & 0xff);
    bytes[1] = (BYTE)((value >> 8) & 0xff);
    bytes[2] = (BYTE)((value >> 16) & 0xff);
    bytes[3] = (BYTE)((value >> 24) & 0xff);
    return byte_builder_append(builder, bytes, sizeof(bytes));
}

static BOOL byte_builder_append_u64_le(BYTE_BUILDER *builder, uint64_t value)
{
    BYTE bytes[8];
    for (int idx = 0; idx < 8; ++idx) {
        bytes[idx] = (BYTE)((value >> (idx * 8)) & 0xff);
    }
    return byte_builder_append(builder, bytes, sizeof(bytes));
}

static BOOL random_bytes(BYTE *out, DWORD len)
{
    return BCryptGenRandom(NULL, out, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static WCHAR *dup_empty_wide(void)
{
    WCHAR *out = (WCHAR *)xalloc(sizeof(WCHAR));
    if (out) {
        out[0] = L'\0';
    }
    return out;
}

static void set_db_error(sqlite3 *db, WCHAR *err, size_t err_cch, const WCHAR *context)
{
    if (!err || !err_cch) {
        return;
    }
    const char *msg = db ? sqlite3_errmsg(db) : NULL;
    if (msg && msg[0]) {
        WCHAR *wide_msg = NULL;
        if (utf8_to_wide_n(msg, strlen(msg), &wide_msg) && wide_msg) {
            set_error(err, err_cch, L"%s: %s", context, wide_msg);
            secure_free_wide(wide_msg);
            return;
        }
    }
    set_error(err, err_cch, L"%s", context);
}

static BOOL chat_db_path(WCHAR *path, size_t path_cch, WCHAR *err, size_t err_cch)
{
    if (!get_app_file(path, path_cch, APP_CHAT_HISTORY_DB_NAME)) {
        set_error(err, err_cch, L"Unable to resolve chat history database path.");
        return FALSE;
    }
    return TRUE;
}

static BOOL exec_sql(sqlite3 *db, const char *sql, WCHAR *err, size_t err_cch, const WCHAR *context)
{
    char *sqlite_error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &sqlite_error);
    if (rc != SQLITE_OK) {
        if (sqlite_error) {
            WCHAR *wide_msg = NULL;
            if (utf8_to_wide_n(sqlite_error, strlen(sqlite_error), &wide_msg) && wide_msg) {
                set_error(err, err_cch, L"%s: %s", context, wide_msg);
                secure_free_wide(wide_msg);
            } else {
                set_error(err, err_cch, L"%s", context);
            }
            sqlite3_free(sqlite_error);
        } else {
            set_db_error(db, err, err_cch, context);
        }
        return FALSE;
    }
    return TRUE;
}

static BOOL configure_db(sqlite3 *db, WCHAR *err, size_t err_cch)
{
    /* DELETE journaling keeps the portable data footprint to the single .db file.
       WAL would also leave plaintext metadata and encrypted row blobs in -wal/-shm
       sidecars. FULL synchronous keeps append durability ahead of speed here. */
    static const char *pragma_sql =
        "PRAGMA foreign_keys=ON;"
        "PRAGMA secure_delete=ON;"
        "PRAGMA journal_mode=DELETE;"
        "PRAGMA synchronous=FULL;";
    return exec_sql(db, pragma_sql, err, err_cch, L"Unable to configure chat history database");
}

static BOOL verify_schema_version(sqlite3 *db, WCHAR *err, size_t err_cch)
{
    sqlite3_stmt *stmt = NULL;
    BOOL version_ok = FALSE;
    static const char *sql = "SELECT value FROM meta WHERE key='schema_version';";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        set_db_error(db, err, err_cch, L"Unable to read chat history schema version");
        return FALSE;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *version = (const char *)sqlite3_column_text(stmt, 0);
        if (version && strcmp(version, CHAT_SCHEMA_VERSION) == 0) {
            version_ok = TRUE;
        } else {
            set_error(err,
                      err_cch,
                      L"Unsupported chat history schema version. Delete chat_history.db to start fresh.");
        }
    } else if (rc == SQLITE_DONE) {
        set_error(err, err_cch, L"Chat history schema version is missing.");
    } else {
        set_db_error(db, err, err_cch, L"Unable to read chat history schema version");
    }
    sqlite3_finalize(stmt);
    return version_ok;
}

static BOOL init_schema(sqlite3 *db, WCHAR *err, size_t err_cch)
{
    static const char *schema_sql =
        "CREATE TABLE IF NOT EXISTS meta ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS group_history_keys ("
        "  group_id TEXT PRIMARY KEY,"
        "  wrapped_key BLOB NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id INTEGER PRIMARY KEY,"
        "  conversation_kind INTEGER NOT NULL,"
        "  conversation_key TEXT NOT NULL,"
        "  message_uuid BLOB NOT NULL UNIQUE,"
        "  timestamp_ms INTEGER NOT NULL,"
        "  timestamp_text TEXT NOT NULL,"
        "  direction INTEGER NOT NULL,"
        "  nonce BLOB NOT NULL,"
        "  ciphertext BLOB NOT NULL,"
        "  tag BLOB NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_messages_conversation_time "
        "ON messages(conversation_kind, conversation_key, timestamp_ms, id);"
        "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '" CHAT_SCHEMA_VERSION "');";
    return exec_sql(db, schema_sql, err, err_cch, L"Unable to initialize chat history database") &&
           verify_schema_version(db, err, err_cch);
}

static BOOL open_chat_db(sqlite3 **out_db, WCHAR *err, size_t err_cch)
{
    if (!out_db) {
        set_error(err, err_cch, L"Invalid chat history database output.");
        return FALSE;
    }
    *out_db = NULL;
    WCHAR path[MAX_PATH];
    if (!chat_db_path(path, ARRAYSIZE(path), err, err_cch)) {
        return FALSE;
    }
    sqlite3 *db = NULL;
    int rc = sqlite3_open16(path, &db);
    if (rc != SQLITE_OK) {
        set_db_error(db, err, err_cch, L"Unable to open chat history database");
        if (db) {
            sqlite3_close(db);
        }
        return FALSE;
    }
    sqlite3_busy_timeout(db, 3000);
    if (!configure_db(db, err, err_cch) || !init_schema(db, err, err_cch)) {
        sqlite3_close(db);
        return FALSE;
    }
    *out_db = db;
    return TRUE;
}

static BOOL chat_db_exists(void)
{
    WCHAR path[MAX_PATH];
    if (!get_app_file(path, ARRAYSIZE(path), APP_CHAT_HISTORY_DB_NAME)) {
        return FALSE;
    }
    return file_exists_w(path);
}

static BOOL hmac_sha256_segments(const BYTE *key,
                                 DWORD key_len,
                                 const BYTE **segments,
                                 const DWORD *segment_lens,
                                 size_t segment_count,
                                 BYTE out[CHAT_HISTORY_KEY_BYTES])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE *object = NULL;
    DWORD object_len = 0;
    DWORD result_len = 0;
    BOOL result = FALSE;

    if (BCryptOpenAlgorithmProvider(&algorithm,
                                    BCRYPT_SHA256_ALGORITHM,
                                    NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        goto cleanup;
    }
    if (BCryptGetProperty(algorithm,
                          BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&object_len,
                          sizeof(object_len),
                          &result_len,
                          0) != 0) {
        goto cleanup;
    }
    object = (BYTE *)xalloc(object_len);
    if (!object) {
        goto cleanup;
    }
    if (BCryptCreateHash(algorithm,
                         &hash,
                         object,
                         object_len,
                         (PUCHAR)key,
                         key_len,
                         0) != 0) {
        goto cleanup;
    }
    for (size_t idx = 0; idx < segment_count; ++idx) {
        if (segment_lens[idx] &&
            BCryptHashData(hash, (PUCHAR)segments[idx], segment_lens[idx], 0) != 0) {
            goto cleanup;
        }
    }
    if (BCryptFinishHash(hash, out, CHAT_HISTORY_KEY_BYTES, 0) != 0) {
        goto cleanup;
    }
    result = TRUE;

cleanup:
    if (!result) {
        SecureZeroMemory(out, CHAT_HISTORY_KEY_BYTES);
    }
    if (hash) {
        BCryptDestroyHash(hash);
    }
    if (object) {
        secure_free(object, object_len);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return result;
}

static BOOL derive_private_history_key(const WCHAR *profile_id,
                                       const BYTE profile_master[CHAT_HISTORY_KEY_BYTES],
                                       BYTE out_key[CHAT_HISTORY_KEY_BYTES],
                                       WCHAR *err,
                                       size_t err_cch)
{
    static const BYTE label[] = "ChineseInputAgent private chat history v1";
    char *profile_id_utf8 = NULL;
    if (!profile_id || !profile_id[0] || !profile_master) {
        set_error(err, err_cch, L"Invalid private chat history key input.");
        return FALSE;
    }
    if (!wide_to_utf8(profile_id, &profile_id_utf8, NULL)) {
        set_error(err, err_cch, L"Unable to encode profile id.");
        return FALSE;
    }
    const BYTE *segments[2] = { label, (const BYTE *)profile_id_utf8 };
    DWORD segment_lens[2] = {
        (DWORD)(sizeof(label) - 1),
        (DWORD)strlen(profile_id_utf8)
    };
    BOOL result = hmac_sha256_segments(profile_master,
                                       CHAT_HISTORY_KEY_BYTES,
                                       segments,
                                       segment_lens,
                                       ARRAYSIZE(segments),
                                       out_key);
    secure_free_str(profile_id_utf8);
    if (!result) {
        set_error(err, err_cch, L"Unable to derive private chat history key.");
    }
    return result;
}

static BOOL aes_gcm_encrypt_raw(const BYTE key[CHAT_HISTORY_KEY_BYTES],
                                const BYTE *nonce,
                                DWORD nonce_len,
                                const BYTE *aad,
                                DWORD aad_len,
                                const BYTE *plain,
                                DWORD plain_len,
                                BYTE **out_cipher,
                                BYTE out_tag[CHAT_TAG_BYTES])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE aes_key = NULL;
    BYTE *object = NULL;
    BYTE *cipher = NULL;
    DWORD object_len = 0;
    DWORD result_len = 0;
    DWORD bytes_done = 0;
    BOOL result = FALSE;

    *out_cipher = NULL;
    SecureZeroMemory(out_tag, CHAT_TAG_BYTES);

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        goto cleanup;
    }
    if (BCryptSetProperty(algorithm,
                          BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (DWORD)sizeof(BCRYPT_CHAIN_MODE_GCM),
                          0) != 0) {
        goto cleanup;
    }
    if (BCryptGetProperty(algorithm,
                          BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&object_len,
                          sizeof(object_len),
                          &result_len,
                          0) != 0) {
        goto cleanup;
    }
    object = (BYTE *)xalloc(object_len);
    if (!object) {
        goto cleanup;
    }
    if (BCryptGenerateSymmetricKey(algorithm,
                                   &aes_key,
                                   object,
                                   object_len,
                                   (PUCHAR)key,
                                   CHAT_HISTORY_KEY_BYTES,
                                   0) != 0) {
        goto cleanup;
    }
    cipher = (BYTE *)xalloc(plain_len ? plain_len : 1);
    if (!cipher) {
        goto cleanup;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = nonce_len;
    auth.pbAuthData = (PUCHAR)aad;
    auth.cbAuthData = aad_len;
    auth.pbTag = out_tag;
    auth.cbTag = CHAT_TAG_BYTES;
    if (BCryptEncrypt(aes_key,
                      (PUCHAR)plain,
                      plain_len,
                      &auth,
                      NULL,
                      0,
                      cipher,
                      plain_len,
                      &bytes_done,
                      0) != 0 ||
        bytes_done != plain_len) {
        goto cleanup;
    }
    *out_cipher = cipher;
    cipher = NULL;
    result = TRUE;

cleanup:
    if (cipher) {
        secure_free(cipher, plain_len ? plain_len : 1);
    }
    if (!result) {
        SecureZeroMemory(out_tag, CHAT_TAG_BYTES);
    }
    if (aes_key) {
        BCryptDestroyKey(aes_key);
    }
    if (object) {
        secure_free(object, object_len);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return result;
}

static BOOL aes_gcm_decrypt_raw(const BYTE key[CHAT_HISTORY_KEY_BYTES],
                                const BYTE *nonce,
                                DWORD nonce_len,
                                const BYTE *aad,
                                DWORD aad_len,
                                const BYTE *cipher,
                                DWORD cipher_len,
                                const BYTE tag[CHAT_TAG_BYTES],
                                BYTE **out_plain)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE aes_key = NULL;
    BYTE *object = NULL;
    BYTE *plain = NULL;
    DWORD object_len = 0;
    DWORD result_len = 0;
    DWORD bytes_done = 0;
    BOOL result = FALSE;

    *out_plain = NULL;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        goto cleanup;
    }
    if (BCryptSetProperty(algorithm,
                          BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (DWORD)sizeof(BCRYPT_CHAIN_MODE_GCM),
                          0) != 0) {
        goto cleanup;
    }
    if (BCryptGetProperty(algorithm,
                          BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&object_len,
                          sizeof(object_len),
                          &result_len,
                          0) != 0) {
        goto cleanup;
    }
    object = (BYTE *)xalloc(object_len);
    if (!object) {
        goto cleanup;
    }
    if (BCryptGenerateSymmetricKey(algorithm,
                                   &aes_key,
                                   object,
                                   object_len,
                                   (PUCHAR)key,
                                   CHAT_HISTORY_KEY_BYTES,
                                   0) != 0) {
        goto cleanup;
    }
    plain = (BYTE *)xalloc(cipher_len ? cipher_len : 1);
    if (!plain) {
        goto cleanup;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = (PUCHAR)nonce;
    auth.cbNonce = nonce_len;
    auth.pbAuthData = (PUCHAR)aad;
    auth.cbAuthData = aad_len;
    auth.pbTag = (PUCHAR)tag;
    auth.cbTag = CHAT_TAG_BYTES;
    if (BCryptDecrypt(aes_key,
                      (PUCHAR)cipher,
                      cipher_len,
                      &auth,
                      NULL,
                      0,
                      plain,
                      cipher_len,
                      &bytes_done,
                      0) != 0 ||
        bytes_done != cipher_len) {
        goto cleanup;
    }
    *out_plain = plain;
    plain = NULL;
    result = TRUE;

cleanup:
    if (plain) {
        secure_free(plain, cipher_len ? cipher_len : 1);
    }
    if (aes_key) {
        BCryptDestroyKey(aes_key);
    }
    if (object) {
        secure_free(object, object_len);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return result;
}

static BOOL build_message_record(const WCHAR *sender,
                                 const WCHAR *plain,
                                 BYTE_BUILDER *record,
                                 WCHAR *err,
                                 size_t err_cch)
{
    char *sender_utf8 = NULL;
    char *body_utf8 = NULL;
    const WCHAR *safe_sender = (sender && sender[0]) ? sender : L"\u672a\u547d\u540d";
    const WCHAR *safe_plain = plain ? plain : L"";
    if (!wide_to_utf8(safe_sender, &sender_utf8, NULL) ||
        !wide_to_utf8(safe_plain, &body_utf8, NULL)) {
        secure_free_str(sender_utf8);
        secure_free_str(body_utf8);
        set_error(err, err_cch, L"Unable to encode chat history text.");
        return FALSE;
    }
    size_t sender_len = strlen(sender_utf8);
    size_t body_len = strlen(body_utf8);
    if (sender_len > 0xffffU || body_len > 0xffffffffU) {
        secure_free_str(sender_utf8);
        secure_free_str(body_utf8);
        set_error(err, err_cch, L"Chat history text is too large.");
        return FALSE;
    }
    BOOL result =
        byte_builder_append_u16_le(record, CHAT_RECORD_VERSION) &&
        byte_builder_append_u16_le(record, (WORD)sender_len) &&
        byte_builder_append_u32_le(record, (DWORD)body_len) &&
        byte_builder_append(record, sender_utf8, (DWORD)sender_len) &&
        byte_builder_append(record, body_utf8, (DWORD)body_len);
    secure_free_str(sender_utf8);
    secure_free_str(body_utf8);
    if (!result) {
        set_error(err, err_cch, L"Unable to build chat history record.");
    }
    return result;
}

static BOOL read_u16_le(const BYTE *data, DWORD len, DWORD *offset, WORD *out)
{
    if (*offset > len || len - *offset < 2) {
        return FALSE;
    }
    *out = (WORD)(data[*offset] | (data[*offset + 1] << 8));
    *offset += 2;
    return TRUE;
}

static BOOL read_u32_le(const BYTE *data, DWORD len, DWORD *offset, DWORD *out)
{
    if (*offset > len || len - *offset < 4) {
        return FALSE;
    }
    *out = (DWORD)data[*offset] |
           ((DWORD)data[*offset + 1] << 8) |
           ((DWORD)data[*offset + 2] << 16) |
           ((DWORD)data[*offset + 3] << 24);
    *offset += 4;
    return TRUE;
}

static BOOL decode_message_record(const BYTE *record,
                                  DWORD record_len,
                                  WCHAR **out_sender,
                                  WCHAR **out_body,
                                  WCHAR *err,
                                  size_t err_cch)
{
    *out_sender = NULL;
    *out_body = NULL;
    DWORD offset = 0;
    WORD version = 0;
    WORD sender_len = 0;
    DWORD body_len = 0;
    if (!read_u16_le(record, record_len, &offset, &version) ||
        !read_u16_le(record, record_len, &offset, &sender_len) ||
        !read_u32_le(record, record_len, &offset, &body_len) ||
        version != CHAT_RECORD_VERSION ||
        offset > record_len ||
        sender_len > record_len - offset ||
        body_len > record_len - offset - sender_len) {
        set_error(err, err_cch, L"Chat history record is malformed.");
        return FALSE;
    }
    const char *sender_utf8 = (const char *)(record + offset);
    offset += sender_len;
    const char *body_utf8 = (const char *)(record + offset);
    if (sender_len) {
        if (!utf8_to_wide_n(sender_utf8, sender_len, out_sender)) {
            set_error(err, err_cch, L"Unable to decode chat history sender.");
            return FALSE;
        }
    } else {
        *out_sender = dup_empty_wide();
    }
    if (body_len) {
        if (!utf8_to_wide_n(body_utf8, body_len, out_body)) {
            secure_free_wide(*out_sender);
            *out_sender = NULL;
            set_error(err, err_cch, L"Unable to decode chat history body.");
            return FALSE;
        }
    } else {
        *out_body = dup_empty_wide();
    }
    if (!*out_sender || !*out_body) {
        secure_free_wide(*out_sender);
        secure_free_wide(*out_body);
        *out_sender = NULL;
        *out_body = NULL;
        set_error(err, err_cch, L"Unable to allocate chat history text.");
        return FALSE;
    }
    return TRUE;
}

static BOOL build_aad(int conversation_kind,
                      const char *conversation_key,
                      const BYTE message_uuid[CHAT_MESSAGE_UUID_BYTES],
                      int64_t timestamp_ms,
                      const char *timestamp_text,
                      int direction,
                      BYTE_BUILDER *aad)
{
    static const BYTE label[] = "CIACHAT1";
    size_t key_len = conversation_key ? strlen(conversation_key) : 0;
    size_t timestamp_len = timestamp_text ? strlen(timestamp_text) : 0;
    if (key_len > 0xffffffffU || timestamp_len > 0xffffffffU) {
        return FALSE;
    }
    return byte_builder_append(aad, label, (DWORD)(sizeof(label) - 1)) &&
           byte_builder_append_u32_le(aad, (DWORD)conversation_kind) &&
           byte_builder_append_u32_le(aad, (DWORD)key_len) &&
           byte_builder_append(aad, conversation_key, (DWORD)key_len) &&
           byte_builder_append(aad, message_uuid, CHAT_MESSAGE_UUID_BYTES) &&
           byte_builder_append_u64_le(aad, (uint64_t)timestamp_ms) &&
           byte_builder_append_u32_le(aad, (DWORD)timestamp_len) &&
           byte_builder_append(aad, timestamp_text, (DWORD)timestamp_len) &&
           byte_builder_append_u32_le(aad, (DWORD)direction);
}

static void current_timestamp(int64_t *out_ms, char out_text[CHAT_TIMESTAMP_TEXT_BYTES])
{
    FILETIME file_time;
    ULARGE_INTEGER value;
    SYSTEMTIME local_time;
    GetSystemTimeAsFileTime(&file_time);
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    *out_ms = (int64_t)((value.QuadPart - 116444736000000000ULL) / 10000ULL);
    GetLocalTime(&local_time);
    StringCchPrintfA(out_text,
                     CHAT_TIMESTAMP_TEXT_BYTES,
                     "[%04u-%02u-%02u %02u:%02u:%02u]",
                     local_time.wYear,
                     local_time.wMonth,
                     local_time.wDay,
                     local_time.wHour,
                     local_time.wMinute,
                     local_time.wSecond);
}

static BOOL bind_blob_checked(sqlite3_stmt *stmt, int index, const void *data, DWORD len)
{
    if (len > INT_MAX) {
        return FALSE;
    }
    return sqlite3_bind_blob(stmt, index, data, (int)len, SQLITE_TRANSIENT) == SQLITE_OK;
}

static BOOL insert_encrypted_message(sqlite3 *db,
                                     int conversation_kind,
                                     const char *conversation_key,
                                     const BYTE history_key[CHAT_HISTORY_KEY_BYTES],
                                     const WCHAR *sender,
                                     const WCHAR *plain,
                                     WCHAR *err,
                                     size_t err_cch)
{
    sqlite3_stmt *stmt = NULL;
    BYTE uuid[CHAT_MESSAGE_UUID_BYTES];
    BYTE nonce[CHAT_NONCE_BYTES];
    BYTE tag[CHAT_TAG_BYTES];
    BYTE *ciphertext = NULL;
    BYTE_BUILDER record = { 0 };
    BYTE_BUILDER aad = { 0 };
    int64_t timestamp_ms = 0;
    char timestamp_text[CHAT_TIMESTAMP_TEXT_BYTES];
    BOOL result = FALSE;

    if (!random_bytes(uuid, sizeof(uuid)) || !random_bytes(nonce, sizeof(nonce))) {
        set_error(err, err_cch, L"Unable to generate chat history randomness.");
        goto cleanup;
    }
    current_timestamp(&timestamp_ms, timestamp_text);
    if (!build_message_record(sender, plain, &record, err, err_cch) ||
        !build_aad(conversation_kind,
                   conversation_key,
                   uuid,
                   timestamp_ms,
                   timestamp_text,
                   CHAT_DIRECTION_UNKNOWN,
                   &aad)) {
        if (!err || !err[0]) {
            set_error(err, err_cch, L"Unable to build chat history encryption input.");
        }
        goto cleanup;
    }
    if (!aes_gcm_encrypt_raw(history_key,
                             nonce,
                             sizeof(nonce),
                             aad.data,
                             aad.len,
                             record.data,
                             record.len,
                             &ciphertext,
                             tag)) {
        set_error(err, err_cch, L"Unable to encrypt chat history message.");
        goto cleanup;
    }

    static const char *sql =
        "INSERT INTO messages("
        "conversation_kind, conversation_key, message_uuid, timestamp_ms, "
        "timestamp_text, direction, nonce, ciphertext, tag"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 1, conversation_kind) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, conversation_key, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        !bind_blob_checked(stmt, 3, uuid, sizeof(uuid)) ||
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)timestamp_ms) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 5, timestamp_text, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 6, CHAT_DIRECTION_UNKNOWN) != SQLITE_OK ||
        !bind_blob_checked(stmt, 7, nonce, sizeof(nonce)) ||
        !bind_blob_checked(stmt, 8, ciphertext, record.len) ||
        !bind_blob_checked(stmt, 9, tag, sizeof(tag)) ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        set_db_error(db, err, err_cch, L"Unable to insert chat history message");
        goto cleanup;
    }
    result = TRUE;

cleanup:
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    if (ciphertext) {
        secure_free(ciphertext, record.len);
    }
    SecureZeroMemory(uuid, sizeof(uuid));
    SecureZeroMemory(nonce, sizeof(nonce));
    SecureZeroMemory(tag, sizeof(tag));
    byte_builder_secure_free(&record);
    byte_builder_free(&aad);
    return result;
}

static BOOL begin_transaction(sqlite3 *db, WCHAR *err, size_t err_cch)
{
    return exec_sql(db, "BEGIN IMMEDIATE TRANSACTION;", err, err_cch, L"Unable to start chat history transaction");
}

static BOOL commit_transaction(sqlite3 *db, WCHAR *err, size_t err_cch)
{
    return exec_sql(db, "COMMIT;", err, err_cch, L"Unable to commit chat history transaction");
}

static void rollback_transaction(sqlite3 *db)
{
    if (db) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
    }
}

static void format_group_key(uint64_t group_id, char out[17])
{
    StringCchPrintfA(out, 17, "%016llx", (unsigned long long)group_id);
}

/* Group chat is intentionally independent from profiles, and current group
   state is local-only DPAPI-protected data. There is no profile master key in
   the group archive API, so the local history key follows the same local
   protection model and binds the DPAPI blob to group_id as optional entropy. */
static void group_history_key_entropy(uint64_t group_id, BYTE entropy[GROUP_HISTORY_ENTROPY_BYTES])
{
    static const BYTE label[] = "CIAGROUPHIST";
    ZeroMemory(entropy, GROUP_HISTORY_ENTROPY_BYTES);
    CopyMemory(entropy, label, sizeof(label) - 1);
    for (int idx = 0; idx < 8; ++idx) {
        entropy[sizeof(label) - 1 + idx] = (BYTE)((group_id >> (idx * 8)) & 0xff);
    }
}

static BOOL protect_group_history_key(uint64_t group_id, const BYTE key[CHAT_HISTORY_KEY_BYTES],
                                      BYTE **out, DWORD *out_len)
{
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    DATA_BLOB entropy_blob;
    BYTE entropy[GROUP_HISTORY_ENTROPY_BYTES];
    BOOL result = FALSE;

    *out = NULL;
    *out_len = 0;
    group_history_key_entropy(group_id, entropy);
    in_blob.pbData = (BYTE *)key;
    in_blob.cbData = CHAT_HISTORY_KEY_BYTES;
    entropy_blob.pbData = entropy;
    entropy_blob.cbData = sizeof(entropy);
    ZeroMemory(&out_blob, sizeof(out_blob));

    if (CryptProtectData(&in_blob,
                         L"ChineseInputAgent group chat history key",
                         &entropy_blob,
                         NULL,
                         NULL,
                         0,
                         &out_blob)) {
        BYTE *copy = (BYTE *)xalloc(out_blob.cbData);
        if (copy) {
            CopyMemory(copy, out_blob.pbData, out_blob.cbData);
            *out = copy;
            *out_len = out_blob.cbData;
            result = TRUE;
        }
        LocalFree(out_blob.pbData);
    }
    SecureZeroMemory(entropy, sizeof(entropy));
    return result;
}

static BOOL unprotect_group_history_key(uint64_t group_id, const BYTE *wrapped, DWORD wrapped_len,
                                        BYTE out_key[CHAT_HISTORY_KEY_BYTES])
{
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    DATA_BLOB entropy_blob;
    BYTE entropy[GROUP_HISTORY_ENTROPY_BYTES];
    BOOL result = FALSE;

    group_history_key_entropy(group_id, entropy);
    in_blob.pbData = (BYTE *)wrapped;
    in_blob.cbData = wrapped_len;
    entropy_blob.pbData = entropy;
    entropy_blob.cbData = sizeof(entropy);
    ZeroMemory(&out_blob, sizeof(out_blob));

    if (CryptUnprotectData(&in_blob, NULL, &entropy_blob, NULL, NULL, 0, &out_blob) &&
        out_blob.cbData == CHAT_HISTORY_KEY_BYTES) {
        CopyMemory(out_key, out_blob.pbData, CHAT_HISTORY_KEY_BYTES);
        result = TRUE;
    }
    if (out_blob.pbData) {
        SecureZeroMemory(out_blob.pbData, out_blob.cbData);
        LocalFree(out_blob.pbData);
    }
    SecureZeroMemory(entropy, sizeof(entropy));
    if (!result) {
        SecureZeroMemory(out_key, CHAT_HISTORY_KEY_BYTES);
    }
    return result;
}

static BOOL get_group_history_key(sqlite3 *db,
                                  uint64_t group_id,
                                  BOOL create_if_missing,
                                  BYTE out_key[CHAT_HISTORY_KEY_BYTES],
                                  WCHAR *err,
                                  size_t err_cch)
{
    sqlite3_stmt *stmt = NULL;
    char group_key[17];
    BOOL result = FALSE;
    format_group_key(group_id, group_key);

    static const char *select_sql = "SELECT wrapped_key FROM group_history_keys WHERE group_id=?;";
    if (sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, group_key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        set_db_error(db, err, err_cch, L"Unable to read group chat history key");
        goto cleanup;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const BYTE *wrapped = (const BYTE *)sqlite3_column_blob(stmt, 0);
        int wrapped_len = sqlite3_column_bytes(stmt, 0);
        if (!wrapped || wrapped_len <= 0 ||
            !unprotect_group_history_key(group_id, wrapped, (DWORD)wrapped_len, out_key)) {
            set_error(err, err_cch, L"Unable to decrypt group chat history key.");
            goto cleanup;
        }
        result = TRUE;
        goto cleanup;
    }
    if (rc != SQLITE_DONE) {
        set_db_error(db, err, err_cch, L"Unable to read group chat history key");
        goto cleanup;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (!create_if_missing) {
        set_error(err, err_cch, L"Group chat history key is missing.");
        goto cleanup;
    }
    if (!random_bytes(out_key, CHAT_HISTORY_KEY_BYTES)) {
        set_error(err, err_cch, L"Unable to generate group chat history key.");
        goto cleanup;
    }
    BYTE *wrapped_key = NULL;
    DWORD wrapped_len = 0;
    if (!protect_group_history_key(group_id, out_key, &wrapped_key, &wrapped_len)) {
        set_error(err, err_cch, L"Unable to protect group chat history key.");
        SecureZeroMemory(out_key, CHAT_HISTORY_KEY_BYTES);
        goto cleanup;
    }
    static const char *insert_sql = "INSERT INTO group_history_keys(group_id, wrapped_key) VALUES(?, ?);";
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, group_key, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        !bind_blob_checked(stmt, 2, wrapped_key, wrapped_len) ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        set_db_error(db, err, err_cch, L"Unable to save group chat history key");
        secure_free(wrapped_key, wrapped_len);
        SecureZeroMemory(out_key, CHAT_HISTORY_KEY_BYTES);
        goto cleanup;
    }
    secure_free(wrapped_key, wrapped_len);
    result = TRUE;

cleanup:
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    return result;
}

static BOOL conversation_has_messages(sqlite3 *db,
                                      int conversation_kind,
                                      const char *conversation_key,
                                      BOOL *out_has_messages,
                                      WCHAR *err,
                                      size_t err_cch)
{
    sqlite3_stmt *stmt = NULL;
    *out_has_messages = FALSE;
    static const char *sql =
        "SELECT 1 FROM messages WHERE conversation_kind=? AND conversation_key=? LIMIT 1;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 1, conversation_kind) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, conversation_key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        set_db_error(db, err, err_cch, L"Unable to query chat history");
        goto fail;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_has_messages = TRUE;
    } else if (rc != SQLITE_DONE) {
        set_db_error(db, err, err_cch, L"Unable to query chat history");
        goto fail;
    }
    sqlite3_finalize(stmt);
    return TRUE;

fail:
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    return FALSE;
}

static BOOL append_display_record(WSTRB *builder,
                                  const WCHAR *timestamp_text,
                                  const WCHAR *sender,
                                  const WCHAR *body)
{
    const WCHAR *safe_timestamp = timestamp_text ? timestamp_text : L"";
    const WCHAR *safe_sender = (sender && sender[0]) ? sender : L"\u672a\u547d\u540d";
    const WCHAR *safe_body = body ? body : L"";
    if (!wstrb_append(builder, safe_timestamp) ||
        !wstrb_append(builder, L" \u53d1\u9001\u4eba\uff1a") ||
        !wstrb_append(builder, safe_sender) ||
        !wstrb_append(builder, L"\r\n") ||
        !wstrb_append(builder, safe_body)) {
        return FALSE;
    }
    size_t body_len = wcslen(safe_body);
    if (body_len == 0 || (safe_body[body_len - 1] != L'\n' && safe_body[body_len - 1] != L'\r')) {
        if (!wstrb_append(builder, L"\r\n")) {
            return FALSE;
        }
    }
    return wstrb_append(builder, L"\r\n");
}

static BOOL load_messages(sqlite3 *db,
                          int conversation_kind,
                          const char *conversation_key,
                          const BYTE history_key[CHAT_HISTORY_KEY_BYTES],
                          WCHAR **out,
                          WCHAR *err,
                          size_t err_cch)
{
    sqlite3_stmt *stmt = NULL;
    WSTRB builder = { 0 };
    BOOL result = FALSE;
    *out = NULL;

    static const char *sql =
        "SELECT message_uuid, timestamp_ms, timestamp_text, direction, nonce, ciphertext, tag "
        "FROM messages WHERE conversation_kind=? AND conversation_key=? "
        "ORDER BY timestamp_ms, id;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 1, conversation_kind) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, conversation_key, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        set_db_error(db, err, err_cch, L"Unable to load chat history");
        goto cleanup;
    }

    for (;;) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            set_db_error(db, err, err_cch, L"Unable to load chat history");
            goto cleanup;
        }
        const BYTE *uuid = (const BYTE *)sqlite3_column_blob(stmt, 0);
        int uuid_len = sqlite3_column_bytes(stmt, 0);
        int64_t timestamp_ms = (int64_t)sqlite3_column_int64(stmt, 1);
        const char *timestamp_text = (const char *)sqlite3_column_text(stmt, 2);
        int direction = sqlite3_column_int(stmt, 3);
        const BYTE *nonce = (const BYTE *)sqlite3_column_blob(stmt, 4);
        int nonce_len = sqlite3_column_bytes(stmt, 4);
        const BYTE *ciphertext = (const BYTE *)sqlite3_column_blob(stmt, 5);
        int ciphertext_len = sqlite3_column_bytes(stmt, 5);
        const BYTE *tag = (const BYTE *)sqlite3_column_blob(stmt, 6);
        int tag_len = sqlite3_column_bytes(stmt, 6);
        if (!uuid || uuid_len != CHAT_MESSAGE_UUID_BYTES ||
            !timestamp_text ||
            !nonce || nonce_len != CHAT_NONCE_BYTES ||
            !ciphertext || ciphertext_len < 0 ||
            !tag || tag_len != CHAT_TAG_BYTES) {
            set_error(err, err_cch, L"Chat history row is malformed.");
            goto cleanup;
        }
        BYTE_BUILDER aad = { 0 };
        BYTE *plain_record = NULL;
        WCHAR *sender = NULL;
        WCHAR *body = NULL;
        WCHAR *timestamp_wide = NULL;
        BOOL row_ok =
            build_aad(conversation_kind,
                      conversation_key,
                      uuid,
                      timestamp_ms,
                      timestamp_text,
                      direction,
                      &aad) &&
            aes_gcm_decrypt_raw(history_key,
                                nonce,
                                nonce_len,
                                aad.data,
                                aad.len,
                                ciphertext,
                                (DWORD)ciphertext_len,
                                tag,
                                &plain_record) &&
            decode_message_record(plain_record,
                                  (DWORD)ciphertext_len,
                                  &sender,
                                  &body,
                                  err,
                                  err_cch) &&
            utf8_to_wide_n(timestamp_text, strlen(timestamp_text), &timestamp_wide) &&
            append_display_record(&builder, timestamp_wide, sender, body);
        if (!row_ok) {
            if (!err || !err[0]) {
                set_error(err, err_cch, L"Chat history message could not be authenticated.");
            }
            if (plain_record) {
                secure_free(plain_record, (DWORD)ciphertext_len);
            }
            secure_free_wide(sender);
            secure_free_wide(body);
            secure_free_wide(timestamp_wide);
            byte_builder_free(&aad);
            goto cleanup;
        }
        secure_free(plain_record, (DWORD)ciphertext_len);
        secure_free_wide(sender);
        secure_free_wide(body);
        secure_free_wide(timestamp_wide);
        byte_builder_free(&aad);
    }

    if (!builder.data) {
        *out = dup_empty_wide();
    } else {
        *out = builder.data;
        builder.data = NULL;
    }
    if (!*out) {
        set_error(err, err_cch, L"Unable to allocate chat history output.");
        goto cleanup;
    }
    result = TRUE;

cleanup:
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    if (!result && builder.data) {
        secure_free_wide(builder.data);
    }
    return result;
}

BOOL chat_history_append_private(const WCHAR *profile_id,
                                 const BYTE profile_master[CHAT_HISTORY_KEY_BYTES],
                                 const WCHAR *sender,
                                 const WCHAR *plain,
                                 WCHAR *err,
                                 size_t err_cch)
{
    sqlite3 *db = NULL;
    char *profile_key = NULL;
    BYTE history_key[CHAT_HISTORY_KEY_BYTES];
    BOOL transaction_started = FALSE;
    BOOL result = FALSE;
    SecureZeroMemory(history_key, sizeof(history_key));

    if (!profile_id || !profile_id[0] || !profile_master) {
        set_error(err, err_cch, L"Invalid private chat history input.");
        return FALSE;
    }
    if (!wide_to_utf8(profile_id, &profile_key, NULL)) {
        set_error(err, err_cch, L"Unable to encode private chat history key.");
        return FALSE;
    }
    if (!derive_private_history_key(profile_id, profile_master, history_key, err, err_cch) ||
        !open_chat_db(&db, err, err_cch) ||
        !begin_transaction(db, err, err_cch)) {
        goto cleanup;
    }
    transaction_started = TRUE;
    if (!insert_encrypted_message(db,
                                  CHAT_KIND_PRIVATE,
                                  profile_key,
                                  history_key,
                                  sender,
                                  plain,
                                  err,
                                  err_cch)) {
        goto cleanup;
    }
    if (!commit_transaction(db, err, err_cch)) {
        goto cleanup;
    }
    transaction_started = FALSE;
    result = TRUE;

cleanup:
    if (transaction_started) {
        rollback_transaction(db);
    }
    if (db) {
        sqlite3_close(db);
    }
    secure_free_str(profile_key);
    SecureZeroMemory(history_key, sizeof(history_key));
    return result;
}

BOOL chat_history_load_private(const WCHAR *profile_id,
                               const BYTE profile_master[CHAT_HISTORY_KEY_BYTES],
                               WCHAR **out,
                               WCHAR *err,
                               size_t err_cch)
{
    sqlite3 *db = NULL;
    char *profile_key = NULL;
    BYTE history_key[CHAT_HISTORY_KEY_BYTES];
    BOOL result = FALSE;
    SecureZeroMemory(history_key, sizeof(history_key));

    if (out) {
        *out = NULL;
    }
    if (!out || !profile_id || !profile_id[0] || !profile_master) {
        set_error(err, err_cch, L"Invalid private chat history load input.");
        return FALSE;
    }
    if (!chat_db_exists()) {
        *out = dup_empty_wide();
        return *out != NULL;
    }
    if (!wide_to_utf8(profile_id, &profile_key, NULL)) {
        set_error(err, err_cch, L"Unable to encode private chat history key.");
        return FALSE;
    }
    if (!derive_private_history_key(profile_id, profile_master, history_key, err, err_cch) ||
        !open_chat_db(&db, err, err_cch) ||
        !load_messages(db, CHAT_KIND_PRIVATE, profile_key, history_key, out, err, err_cch)) {
        goto cleanup;
    }
    result = TRUE;

cleanup:
    if (db) {
        sqlite3_close(db);
    }
    secure_free_str(profile_key);
    SecureZeroMemory(history_key, sizeof(history_key));
    return result;
}

BOOL chat_history_append_group(uint64_t group_id,
                               const WCHAR *sender,
                               const WCHAR *plain,
                               WCHAR *err,
                               size_t err_cch)
{
    sqlite3 *db = NULL;
    BYTE history_key[CHAT_HISTORY_KEY_BYTES];
    char group_key[17];
    BOOL transaction_started = FALSE;
    BOOL result = FALSE;
    SecureZeroMemory(history_key, sizeof(history_key));
    format_group_key(group_id, group_key);

    if (!open_chat_db(&db, err, err_cch) ||
        !begin_transaction(db, err, err_cch)) {
        goto cleanup;
    }
    transaction_started = TRUE;
    if (!get_group_history_key(db, group_id, TRUE, history_key, err, err_cch) ||
        !insert_encrypted_message(db,
                                  CHAT_KIND_GROUP,
                                  group_key,
                                  history_key,
                                  sender,
                                  plain,
                                  err,
                                  err_cch)) {
        goto cleanup;
    }
    if (!commit_transaction(db, err, err_cch)) {
        goto cleanup;
    }
    transaction_started = FALSE;
    result = TRUE;

cleanup:
    if (transaction_started) {
        rollback_transaction(db);
    }
    if (db) {
        sqlite3_close(db);
    }
    SecureZeroMemory(history_key, sizeof(history_key));
    return result;
}

BOOL chat_history_load_group(uint64_t group_id,
                             WCHAR **out,
                             WCHAR *err,
                             size_t err_cch)
{
    sqlite3 *db = NULL;
    BYTE history_key[CHAT_HISTORY_KEY_BYTES];
    char group_key[17];
    BOOL has_messages = FALSE;
    BOOL result = FALSE;
    SecureZeroMemory(history_key, sizeof(history_key));
    format_group_key(group_id, group_key);

    if (out) {
        *out = NULL;
    }
    if (!out) {
        set_error(err, err_cch, L"Invalid group chat history output.");
        return FALSE;
    }
    if (!chat_db_exists()) {
        *out = dup_empty_wide();
        return *out != NULL;
    }
    if (!open_chat_db(&db, err, err_cch) ||
        !conversation_has_messages(db, CHAT_KIND_GROUP, group_key, &has_messages, err, err_cch)) {
        goto cleanup;
    }
    if (!has_messages) {
        *out = dup_empty_wide();
        result = (*out != NULL);
        if (!result) {
            set_error(err, err_cch, L"Unable to allocate chat history output.");
        }
        goto cleanup;
    }
    if (!get_group_history_key(db, group_id, FALSE, history_key, err, err_cch) ||
        !load_messages(db, CHAT_KIND_GROUP, group_key, history_key, out, err, err_cch)) {
        goto cleanup;
    }
    result = TRUE;

cleanup:
    if (db) {
        sqlite3_close(db);
    }
    SecureZeroMemory(history_key, sizeof(history_key));
    return result;
}
