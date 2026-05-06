#ifndef CHINESE_INPUT_AGENT_APP_WORK_H
#define CHINESE_INPUT_AGENT_APP_WORK_H

#include <windows.h>
#include <stddef.h>

#include "crypto_box.h"

#define WM_APP_WORK_UPDATE (WM_APP + 10)
#define WM_APP_WORK_DONE (WM_APP + 11)
#define WM_APP_WORK_ERROR (WM_APP + 12)
#define WM_APP_WORK_CANCELLED (WM_APP + 13)

typedef enum APP_WORK_KIND {
    APP_WORK_KIND_ENCRYPT = 1,
    APP_WORK_KIND_EXPORT_KEY = 2,
    APP_WORK_KIND_DECRYPT = 3,
    APP_WORK_KIND_IMPORT_KEY = 4
} APP_WORK_KIND;

typedef struct APP_WORK_CTX {
    APP_WORK_KIND kind;
    HWND owner;
    HWND target_textbox;
    WCHAR *input;
    WCHAR *topic;
    WCHAR *name;
    WCHAR *expected_fingerprint;
} APP_WORK_CTX;

typedef struct APP_WORK_MESSAGE {
    APP_WORK_KIND kind;
    HWND target_textbox;
    WCHAR *text;
    int profile_index;
} APP_WORK_MESSAGE;

typedef struct APP_WORK_HOST {
    /* Bridge from background work to the owning UI session; app_work itself does not own windows. */
    HWND main_window;
    CRYPTO_BOX *(*get_active_box)(void *user);
    void (*set_busy)(void *user, BOOL busy);
    void (*show_error)(void *user, HWND owner, const WCHAR *message);
    void *user;
} APP_WORK_HOST;

void app_work_configure(const APP_WORK_HOST *host);
APP_WORK_CTX *app_work_alloc(APP_WORK_KIND kind, HWND owner, HWND target_textbox);
BOOL app_work_start(APP_WORK_CTX *ctx);
void app_work_cancel(void);
BOOL app_work_is_active(void);
BOOL app_work_cancelled(void);
void app_work_complete_message_handled(void);
void app_work_free_ctx(APP_WORK_CTX *ctx);
void app_work_free_message(APP_WORK_MESSAGE *message);
void app_work_post_llm_stream_progress(HWND target_textbox, const WCHAR *partial,
                                       size_t tokens_done, size_t tokens_total, double tps);

#endif
