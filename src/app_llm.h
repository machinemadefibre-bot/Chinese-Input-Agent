#ifndef CHINESE_INPUT_AGENT_APP_LLM_H
#define CHINESE_INPUT_AGENT_APP_LLM_H

#include <windows.h>
#include <stddef.h>

#include "app_progress.h"
#include "app_carrier_options.h"

typedef BOOL (*APP_LLM_CANCEL_FN)(void);

typedef struct APP_LLM_DECODE_CANDIDATE {
    WCHAR *tokenizer_id;
    BYTE *payload;
    DWORD payload_len;
} APP_LLM_DECODE_CANDIDATE;

void app_llm_init(APP_LLM_CANCEL_FN cancel_fn);
void app_llm_cleanup(void);
void start_local_llm_background(void);
void shutdown_local_llm_worker(void);
void close_local_llm_job(void);
BOOL local_topk_encode_payload(const BYTE *payload, DWORD payload_len, const WCHAR *seed, const WCHAR *topic,
                               const WCHAR *prompt_template, const WCHAR *prefix, int tail_tokens,
                               const APP_CARRIER_OPTIONS *carrier_options,
                               const CIA_PROGRESS_SINK *progress,
                               WCHAR **out, WCHAR *err, size_t err_cch);
BOOL local_topk_decode_payload(const WCHAR *carrier, const WCHAR *seed, BYTE **out, DWORD *out_len,
                               WCHAR *err, size_t err_cch);
BOOL local_topk_decode_payload_multi(const WCHAR *carrier, const WCHAR *seed, const WCHAR *preferred_tokenizer_id,
                                     APP_LLM_DECODE_CANDIDATE **out, DWORD *out_count,
                                     WCHAR *err, size_t err_cch);
void app_llm_free_decode_candidates(APP_LLM_DECODE_CANDIDATE *candidates, DWORD count);

#endif
