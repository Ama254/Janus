#ifndef OVERLAY_H
#define OVERLAY_H

#include <stdint.h>

#define MAX_MESSAGES 20
#define MAX_MSG_LENGTH 512
#define COLOR_RGBA(r, g, b, a) (((a) << 24) | ((r) << 16) | ((g) << 8) | (b))

typedef struct {
    char messages[MAX_MESSAGES][MAX_MSG_LENGTH];
    uint32_t colors[MAX_MESSAGES];
    int message_count;
    uint32_t bg_color;
    int duration_ms;
    int font_sizes[MAX_MESSAGES];
    void (*custom_funcs[MAX_MESSAGES])(char*);
    int counters[MAX_MESSAGES];
    int counter_steps[MAX_MESSAGES];
} overlay_config_t;


int initialize_overlay();
int launch_overlay(overlay_config_t *config);
void cleanup_overlay();

void overlay_set_duration(overlay_config_t *config, int duration_ms);
void overlay_set_background(overlay_config_t *config, uint32_t bg_color);
void overlay_add_message(overlay_config_t *config, const char *message, uint32_t color, int font_size);
void overlay_add_counter(overlay_config_t *config, const char *prefix, uint32_t color, int font_size, int initial_value, int step);
void overlay_add_function(overlay_config_t *config, const char *prefix, uint32_t color, int font_size, void (*func)(char*));


void counter_function(char *message);
void time_function(char *message);

#endif