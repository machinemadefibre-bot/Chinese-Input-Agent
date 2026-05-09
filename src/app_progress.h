#ifndef CHINESE_INPUT_AGENT_APP_PROGRESS_H
#define CHINESE_INPUT_AGENT_APP_PROGRESS_H

#include <windows.h>
#include <stddef.h>

typedef void (*CIA_PROGRESS_FN)(void *user, const WCHAR *partial,
                                size_t tokens_done, size_t tokens_total,
                                double tps);

typedef struct CIA_PROGRESS_SINK {
    CIA_PROGRESS_FN on_progress;
    void *user;
} CIA_PROGRESS_SINK;

#endif
