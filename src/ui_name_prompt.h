#ifndef CHINESE_INPUT_AGENT_UI_NAME_PROMPT_H
#define CHINESE_INPUT_AGENT_UI_NAME_PROMPT_H

#include <windows.h>
#include <stddef.h>

typedef struct UI_NAME_PROMPT_HOST {
    /* Lets the owner preserve app-level WM_CLOSE behavior without making the prompt depend on work/LLM modules. */
    void (*on_window_close_requested)(void *user);
    void *user;
} UI_NAME_PROMPT_HOST;

BOOL ui_prompt_key_name(HINSTANCE instance, HWND owner, HFONT ui_font,
                        const UI_NAME_PROMPT_HOST *host, WCHAR *name, size_t name_cch);

#endif
