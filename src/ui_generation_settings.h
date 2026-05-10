#ifndef CHINESE_INPUT_AGENT_UI_GENERATION_SETTINGS_H
#define CHINESE_INPUT_AGENT_UI_GENERATION_SETTINGS_H

#include <windows.h>
#include <stddef.h>

#include "app_carrier_options.h"

typedef struct UI_GENERATION_SETTINGS {
    WCHAR *custom_prompt;
    double temperature;
    double top_p;
    APP_CARRIER_REDUNDANCY_LEVEL redundancy_level;
    BOOL save_config;
} UI_GENERATION_SETTINGS;

void ui_generation_settings_init_defaults(UI_GENERATION_SETTINGS *settings);
void ui_generation_settings_free(UI_GENERATION_SETTINGS *settings);
void ui_generation_settings_load(UI_GENERATION_SETTINGS *settings);
BOOL ui_generation_settings_show(HINSTANCE instance, HWND owner, HFONT ui_font,
                                 UI_GENERATION_SETTINGS *settings,
                                 WCHAR *err, size_t err_cch);

#endif
