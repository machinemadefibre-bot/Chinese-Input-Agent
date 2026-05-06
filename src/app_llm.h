#ifndef CHINESE_INPUT_AGENT_APP_LLM_H
#define CHINESE_INPUT_AGENT_APP_LLM_H

#include <windows.h>
#include <stddef.h>

typedef BOOL (*APP_LLM_CANCEL_FN)(void);
typedef void (*APP_LLM_PROGRESS_FN)(HWND target_textbox, const WCHAR *partial, size_t tokens_done, size_t tokens_total, double tps);

void app_llm_init(APP_LLM_CANCEL_FN cancel_fn, APP_LLM_PROGRESS_FN progress_fn);
void app_llm_cleanup(void);
void start_local_llm_background(void);
void shutdown_local_llm_worker(void);
void close_local_llm_job(void);
BOOL local_topk_encode_payload(const BYTE *payload, DWORD payload_len, const WCHAR *seed, const WCHAR *topic,
                               const WCHAR *prefix, int tail_tokens, HWND progress_target,
                               WCHAR **out, WCHAR *err, size_t err_cch);
BOOL local_topk_decode_payload(const WCHAR *carrier, const WCHAR *seed, BYTE **out, DWORD *out_len,
                               WCHAR *err, size_t err_cch);

#endif
