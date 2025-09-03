#ifndef ARBITRARY_EXEC_H
#define ARBITRARY_EXEC_H

#include <linux/types.h>
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/sched.h>

#define MAX_PATH_LEN 256
#define MAX_ARGV 64
#define MAX_ENVP 64
#define MAX_LIBS 32

typedef struct {
    pid_t target_pid;
    char binary_path[MAX_PATH_LEN];
    char *argv[MAX_ARGV];
    char *envp[MAX_ENVP];
    char lib_paths[MAX_LIBS][MAX_PATH_LEN];
    int lib_count;
    unsigned long entry_point;
    unsigned long stack_base;
    unsigned long stack_size;
    int preserve_context;
    int stealth_mode;
} exec_config_t;

typedef struct {
    unsigned long mmap_start;
    unsigned long mmap_end;
    int prot;
    int flags;
} memory_region_t;

int execute_in_process(exec_config_t *config);
int inject_library(pid_t pid, const char *lib_path);
int remote_syscall(pid_t pid, long syscall_number, 
                  unsigned long arg1, unsigned long arg2, 
                  unsigned long arg3, unsigned long arg4,
                  unsigned long arg5, unsigned long arg6);

#endif