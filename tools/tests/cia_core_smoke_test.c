#include "cia_core.h"
#include "app_groups.h"

#include <stdio.h>
#include <wchar.h>

static int fail_with_error(const WCHAR *step, const WCHAR *err) {
    fwprintf(stderr, L"%ls failed: %ls\n", step, err && err[0] ? err : L"(no detail)");
    return 1;
}

int wmain(void) {
    WCHAR err[512] = L"";
    CIA_CORE_OPTIONS options;
    ZeroMemory(&options, sizeof(options));
    options.start_worker_background = FALSE;
    options.skip_profiles = TRUE;

    if (!cia_core_init(&options, err, ARRAYSIZE(err))) {
        return fail_with_error(L"cia_core_init", err);
    }

    int group_index = -1;
    if (!app_groups_create(L"Smoke Group", L"Smoke Member", &group_index, err, ARRAYSIZE(err))) {
        cia_core_cleanup();
        return fail_with_error(L"app_groups_create", err);
    }

    if (!cia_core_append_chat_history(CIA_CORE_CONVERSATION_GROUP, group_index,
                                      L"Smoke", L"headless core message",
                                      err, ARRAYSIZE(err))) {
        cia_core_cleanup();
        return fail_with_error(L"cia_core_append_chat_history", err);
    }

    WCHAR *history = NULL;
    if (!cia_core_load_chat_history(CIA_CORE_CONVERSATION_GROUP, group_index,
                                    &history, err, ARRAYSIZE(err))) {
        cia_core_cleanup();
        return fail_with_error(L"cia_core_load_chat_history", err);
    }

    BOOL history_contains_message = history &&
        wcsstr(history, L"Smoke") &&
        wcsstr(history, L"headless core message");
    cia_core_free_string(history);
    cia_core_cleanup();

    if (!history_contains_message) {
        fwprintf(stderr, L"loaded history did not contain the appended smoke message\n");
        return 1;
    }

    wprintf(L"ok cia_core_smoke_test\n");
    return 0;
}
