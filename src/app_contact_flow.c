#include "app_contact_flow.h"

#include "app_carrier_flow.h"
#include "app_groups.h"
#include "app_profiles.h"
#include "app_shared.h"
#include "cia_platform_windows.h"

#include <strsafe.h>
#include <string.h>

static BOOL profile_public_key_matches(int profile_index, const BYTE public_key[32],
                                       BOOL *matches, WCHAR *err, size_t err_cch) {
    *matches = FALSE;
    CRYPTO_BOX *box = NULL;
    BYTE *profile_public = NULL;
    DWORD profile_public_len = 0;
    BOOL checked = FALSE;
    if (!profiles_open_crypto(profile_index, &box, err, err_cch)) goto cleanup;
    if (!crypto_box_get_public_key(box, &profile_public, &profile_public_len, err, err_cch)) goto cleanup;
    *matches = profile_public_len == 32 && memcmp(profile_public, public_key, 32) == 0;
    checked = TRUE;
cleanup:
    secure_free(profile_public, profile_public_len);
    crypto_box_close(box);
    return checked;
}

static BOOL find_profile_by_public_key(const BYTE public_key[32], int *index_out,
                                       WCHAR *err, size_t err_cch) {
    *index_out = -1;
    int active = profiles_active_index();
    int count = profiles_count();
    WCHAR last_err[256] = L"";
    for (int pass = 0; pass < count; ++pass) {
        int profile_index = pass;
        if (active >= 0 && active < count) {
            if (pass == 0) profile_index = active;
            else {
                profile_index = pass - 1;
                if (profile_index >= active) profile_index++;
            }
        }
        if (profile_index < 0 || profile_index >= count) continue;
        BOOL matches = FALSE;
        WCHAR local_err[256] = L"";
        if (!profile_public_key_matches(profile_index, public_key, &matches, local_err, ARRAYSIZE(local_err))) {
            StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err);
            continue;
        }
        if (matches) {
            *index_out = profile_index;
            profiles_lock_inactive_masters();
            return TRUE;
        }
    }
    if (last_err[0]) {
        set_error(err, err_cch, L"Unable to find the addressed local key. Last error: %s", last_err);
    } else {
        set_error(err, err_cch, L"This key package is addressed to a different local key.");
    }
    profiles_lock_inactive_masters();
    return FALSE;
}

static BOOL fingerprints_match(const WCHAR *expected, const WCHAR *actual) {
    if (!expected || !expected[0] || !actual || !actual[0]) return FALSE;
    return CompareStringOrdinal(expected, -1, actual, -1, TRUE) == CSTR_EQUAL;
}

static BOOL build_key_import_success_message(const WCHAR *contact_name, const WCHAR *fingerprint, WCHAR **out_message,
                                             WCHAR *err, size_t err_cch) {
    WSTRB msg = {0};
    if (!wstrb_appendf(&msg, L"\u5df2\u5bfc\u5165\u8054\u7cfb\u4eba\uff1a%s\r\n\r\n\u6307\u7eb9\uff1a%s\r\n\r\n\u8bf7\u901a\u8fc7\u53ef\u4fe1\u6e20\u9053\u6838\u5bf9\u6307\u7eb9\u3002",
                       contact_name && contact_name[0] ? contact_name : L"\u8054\u7cfb\u4eba",
                       fingerprint ? fingerprint : L"")) {
        set_error(err, err_cch, L"\u5bfc\u5165\u7ed3\u679c\u6d88\u606f\u6784\u9020\u5931\u8d25\u3002");
        return FALSE;
    }
    *out_message = msg.data;
    msg.data = NULL;
    return TRUE;
}

BOOL app_contact_flow_export_key(CRYPTO_BOX *box, const CIA_PROGRESS_SINK *progress,
                                 WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    if (!crypto_box_prepare_key_export(box, err, err_cch) ||
        !crypto_box_export_contact_package(box, &pkg, &pkg_len, err, err_cch)) {
        return FALSE;
    }

    WCHAR fingerprint[32] = L"";
    if (!crypto_box_get_public_fingerprint(box, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    BOOL key_package_encoded = app_carrier_encode_contact_package(pkg, pkg_len, fingerprint,
                                                                  progress, out, err, err_cch);
    secure_free(pkg, pkg_len);
    return key_package_encoded;
}

BOOL app_contact_flow_export_group_key(int group_index, const CIA_PROGRESS_SINK *progress,
                                       WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    BYTE *pkg = NULL;
    DWORD pkg_len = 0;
    WCHAR fingerprint[32] = L"";
    if (!app_groups_export_package(group_index, &pkg, &pkg_len, err, err_cch)) {
        return FALSE;
    }
    if (!app_groups_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    BOOL package_encoded = app_carrier_encode_group_package(pkg, pkg_len, fingerprint,
                                                            progress, out, err, err_cch);
    secure_free(pkg, pkg_len);
    return package_encoded;
}

BOOL app_contact_flow_rekey_group_key(int group_index, const CIA_PROGRESS_SINK *progress,
                                      WCHAR **out, WCHAR *err, size_t err_cch) {
    *out = NULL;
    if (!app_groups_rekey(group_index, err, err_cch)) {
        return FALSE;
    }
    return app_contact_flow_export_group_key(group_index, progress, out, err, err_cch);
}

BOOL app_contact_flow_create_group(const WCHAR *group_name, const WCHAR *local_sender_name,
                                   const CIA_PROGRESS_SINK *progress,
                                   int *group_index_out, WCHAR **out,
                                   WCHAR *err, size_t err_cch) {
    if (group_index_out) *group_index_out = -1;
    *out = NULL;
    int group_index = -1;
    if (!app_groups_create(group_name && group_name[0] ? group_name : L"\u7fa4\u804a",
                           local_sender_name && local_sender_name[0] ? local_sender_name : NULL,
                           &group_index, err, err_cch)) {
        return FALSE;
    }
    if (!app_contact_flow_export_group_key(group_index, progress, out, err, err_cch)) {
        return FALSE;
    }
    if (group_index_out) *group_index_out = group_index;
    return TRUE;
}

BOOL app_contact_flow_set_group_member_alias(int group_index, const WCHAR *sender_id_hex,
                                             const WCHAR *alias, WCHAR **out,
                                             WCHAR *err, size_t err_cch) {
    *out = NULL;
    return app_groups_set_member_alias(group_index, sender_id_hex, alias, out, err, err_cch);
}

static BOOL import_decoded_key_package(BYTE *pkg, DWORD pkg_len,
                                       const WCHAR *expected_fingerprint,
                                       const WCHAR *name, const WCHAR *group_name,
                                       int *active_index_out, int *group_index_out,
                                       WCHAR **out_message, WCHAR *err, size_t err_cch) {
    if (active_index_out) *active_index_out = -1;
    if (group_index_out) *group_index_out = -1;
    *out_message = NULL;
    if (app_groups_is_package(pkg, pkg_len)) {
        WCHAR fingerprint[32] = L"";
        if (!app_groups_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
            secure_free(pkg, pkg_len);
            return FALSE;
        }
        if (!fingerprints_match(expected_fingerprint, fingerprint)) {
            secure_free(pkg, pkg_len);
            set_error(err, err_cch, L"\u5bc6\u94a5\u6307\u7eb9\u81ea\u52a8\u786e\u8ba4\u5931\u8d25\uff1a\u660e\u6587\u7f16\u53f7\u4e0e\u5bc6\u94a5\u5185\u5bb9\u4e0d\u4e00\u81f4\u3002");
            return FALSE;
        }
        BOOL group_imported = app_groups_import_package(pkg, pkg_len,
                                                        group_name && group_name[0] ? group_name : NULL,
                                                        name && name[0] ? name : NULL,
                                                        group_index_out,
                                                        out_message, err, err_cch);
        secure_free(pkg, pkg_len);
        return group_imported;
    }
    WCHAR fingerprint[32] = L"";
    if (!crypto_box_contact_package_fingerprint(pkg, pkg_len, fingerprint, ARRAYSIZE(fingerprint), err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    if (!fingerprints_match(expected_fingerprint, fingerprint)) {
        secure_free(pkg, pkg_len);
        set_error(err, err_cch, L"\u5bc6\u94a5\u6307\u7eb9\u81ea\u52a8\u786e\u8ba4\u5931\u8d25\uff1a\u660e\u6587\u7f16\u53f7\u4e0e\u5bc6\u94a5\u5185\u5bb9\u4e0d\u4e00\u81f4\u3002");
        return FALSE;
    }
    BYTE recipient_public[32];
    BOOL has_recipient = FALSE;
    if (!crypto_box_contact_package_recipient_public(pkg, pkg_len, recipient_public, &has_recipient, err, err_cch)) {
        secure_free(pkg, pkg_len);
        return FALSE;
    }

    if (has_recipient) {
        int target_index = -1;
        if (!find_profile_by_public_key(recipient_public, &target_index, err, err_cch)) {
            SecureZeroMemory(recipient_public, sizeof(recipient_public));
            secure_free(pkg, pkg_len);
            return FALSE;
        }
        WCHAR old_name[128] = L"";
        BOOL name_updated = FALSE;
        if (!profiles_get_name_copy(target_index, old_name, ARRAYSIZE(old_name))) {
            SecureZeroMemory(recipient_public, sizeof(recipient_public));
            secure_free(pkg, pkg_len);
            set_error(err, err_cch, L"Requested profile index is out of range.");
            return FALSE;
        }
        if (name && name[0]) {
            if (!profiles_set_name(target_index, name, err, err_cch)) {
                SecureZeroMemory(recipient_public, sizeof(recipient_public));
                secure_free(pkg, pkg_len);
                set_error(err, err_cch, L"Imported key name is too long.");
                return FALSE;
            }
            name_updated = TRUE;
        }
        CRYPTO_BOX *box = NULL;
        BOOL import_succeeded = profiles_open_crypto(target_index, &box, err, err_cch) &&
                                crypto_box_import_contact_package(box, pkg, pkg_len, err, err_cch) &&
                                profiles_activate(target_index, err, err_cch);
        crypto_box_close(box);
        profiles_lock_inactive_masters();
        SecureZeroMemory(recipient_public, sizeof(recipient_public));
        secure_free(pkg, pkg_len);
        if (!import_succeeded && name_updated) {
            profiles_set_name(target_index, old_name, NULL, 0);
        }
        if (!import_succeeded) return FALSE;
        if (active_index_out) *active_index_out = target_index;

        WCHAR target_name[128] = L"";
        profiles_get_name_copy(target_index, target_name, ARRAYSIZE(target_name));
        return build_key_import_success_message(target_name, fingerprint, out_message, err, err_cch);
    }
    SecureZeroMemory(recipient_public, sizeof(recipient_public));

    if (profiles_count() >= APP_PROFILE_MAX_PROFILES) {
        secure_free(pkg, pkg_len);
        set_error(err, err_cch, L"\u5bc6\u94a5\u6570\u91cf\u5df2\u8fbe\u5230\u4e0a\u9650\u3002");
        return FALSE;
    }

    BYTE master[APP_PROFILE_MASTER_KEY_BYTES];
    if (!cia_win_random_bytes(master, sizeof(master))) {
        secure_free(pkg, pkg_len);
        set_error(err, err_cch, L"\u65e0\u6cd5\u751f\u6210\u672c\u5730\u968f\u673a\u5bc6\u94a5\u3002");
        return FALSE;
    }
    int original = profiles_active_index();
    int imported_index = -1;
    if (!profiles_append_from_master(name, master, &imported_index, err, err_cch)) {
        SecureZeroMemory(master, sizeof(master));
        secure_free(pkg, pkg_len);
        return FALSE;
    }
    SecureZeroMemory(master, sizeof(master));

    CRYPTO_BOX *box = NULL;
    BOOL import_succeeded = profiles_save() &&
                            profiles_open_crypto(imported_index, &box, err, err_cch) &&
                            crypto_box_import_contact_package(box, pkg, pkg_len, err, err_cch) &&
                            profiles_activate(imported_index, err, err_cch);
    crypto_box_close(box);
    profiles_lock_inactive_masters();
    secure_free(pkg, pkg_len);

    if (!import_succeeded) {
        WCHAR state_path[MAX_PATH];
        if (profiles_get_state_path_by_index(imported_index, state_path, ARRAYSIZE(state_path))) {
            secure_delete_file(state_path);
        }
        profiles_remove_at(imported_index);
        if (original >= 0 && original < profiles_count()) {
            WCHAR restore_err[256] = L"";
            profiles_activate(original, restore_err, ARRAYSIZE(restore_err));
        } else {
            profiles_save();
        }
        profiles_lock_inactive_masters();
        return FALSE;
    }
    if (active_index_out) *active_index_out = imported_index;

    WCHAR final_name[128] = L"";
    profiles_get_name_copy(imported_index, final_name, ARRAYSIZE(final_name));
    return build_key_import_success_message(final_name[0] ? final_name : name,
                                            fingerprint, out_message, err, err_cch);
}

BOOL app_contact_flow_import_key(const WCHAR *carrier, const WCHAR *expected_fingerprint,
                                 const WCHAR *name, const WCHAR *group_name,
                                 int *active_index_out, int *group_index_out,
                                 WCHAR **out_message, WCHAR *err, size_t err_cch) {
    if (active_index_out) *active_index_out = -1;
    if (group_index_out) *group_index_out = -1;
    *out_message = NULL;

    APP_LLM_DECODE_CANDIDATE *candidates = NULL;
    DWORD candidate_count = 0;
    if (!app_carrier_decode_exchange_package_multi(carrier, &candidates, &candidate_count, err, err_cch)) {
        return FALSE;
    }

    WCHAR last_err[768] = L"";
    for (DWORD candidate_idx = 0; candidate_idx < candidate_count; ++candidate_idx) {
        BYTE *pkg = candidates[candidate_idx].payload;
        DWORD pkg_len = candidates[candidate_idx].payload_len;
        candidates[candidate_idx].payload = NULL;
        candidates[candidate_idx].payload_len = 0;

        WCHAR *local_message = NULL;
        int local_active_index = -1;
        int local_group_index = -1;
        WCHAR local_err[768] = L"";
        BOOL imported = import_decoded_key_package(pkg, pkg_len,
                                                   expected_fingerprint,
                                                   name, group_name,
                                                   &local_active_index, &local_group_index,
                                                   &local_message,
                                                   local_err, ARRAYSIZE(local_err));
        if (imported) {
            if (active_index_out) *active_index_out = local_active_index;
            if (group_index_out) *group_index_out = local_group_index;
            *out_message = local_message;
            app_llm_free_decode_candidates(candidates, candidate_count);
            return TRUE;
        }
        secure_free_wide(local_message);
        if (local_err[0]) StringCchCopyW(last_err, ARRAYSIZE(last_err), local_err);
    }

    app_llm_free_decode_candidates(candidates, candidate_count);
    if (last_err[0]) {
        set_error(err, err_cch, L"%s", last_err);
    } else {
        set_error(err, err_cch, L"No tokenizer decoded a valid key package.");
    }
    return FALSE;
}
