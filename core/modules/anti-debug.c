#include "anti-debug.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/uio.h>
#include <linux/hw_breakpoint.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/reboot.h>
#include <linux/bsearch.h>
#include <linux/jiffies.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <linux/minmax.h>
#include <linux/kallsyms.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#include <linux/ftrace.h>
#endif

#define CR0_WP_BIT 16
#define PATTERN_MATCH_SIZE 128

static struct protection_context global_ctx;
static struct mutex global_lock;
static rwlock_t table_lock;

typedef int (*proc_pid_status_t)(struct seq_file *, struct pid_namespace *, struct pid *, struct task_struct *);
static proc_pid_status_t orig_proc_pid_status = NULL;

static unsigned long get_cr0(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

static void set_cr0(unsigned long cr0) {
    asm volatile("mov %0, %%cr0" : : "r"(cr0));
}

static void write_read_only(unsigned long addr, unsigned long value) {
    unsigned long cr0 = get_cr0();
    set_cr0(cr0 & ~(1UL << CR0_WP_BIT));
    *(unsigned long *)addr = value;
    set_cr0(cr0);
}

static int compare_pids(const void *a, const void *b) {
    pid_t pid1 = *(const pid_t *)a;
    pid_t pid2 = *(const pid_t *)b;
    return (pid1 > pid2) - (pid1 < pid2);
}

static unsigned long pattern_scan(unsigned long start, unsigned long end, const unsigned char *pattern, const char *mask) {
    unsigned long i;
    size_t pattern_len = strlen(mask);
    
    for (i = start; i < end - pattern_len; i++) {
        int match = 1;
        size_t j;
        
        for (j = 0; j < pattern_len; j++) {
            if (mask[j] != '?' && pattern[j] != *(unsigned char *)(i + j)) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            return i;
        }
    }
    
    return 0;
}

unsigned long find_syscall_table_fallback(void) {
    unsigned long syscall_table = 0;
    unsigned long *candidate;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    candidate = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (candidate) {
        return (unsigned long)candidate;
    }
#endif

    unsigned long kernel_start = _text;
    unsigned long kernel_end = _etext;
    
    unsigned char syscall_pattern[] = { 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
    };
    const char *syscall_mask = "????????????????";
    
    syscall_table = pattern_scan(kernel_start, kernel_end, syscall_pattern, syscall_mask);
    if (!syscall_table) {
        pr_err("Failed to locate syscall table\n");
        return 0;
    }
    
    return syscall_table;
}

static unsigned long get_syscall_table(void) {
    unsigned long syscall_table;
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    syscall_table = (unsigned long)kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        syscall_table = find_syscall_table_fallback();
    }
#else
    syscall_table = find_syscall_table_fallback();
#endif
    
    if (!syscall_table) {
        pr_err("Critical: Cannot find syscall table\n");
        return 0;
    }
    
    return syscall_table;
}

int setup_encryption(struct protection_context *ctx) {
    struct crypto_skcipher *tfm;
    int ret;
    
    tfm = crypto_alloc_skcipher("gcm(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate skcipher\n");
        return PTR_ERR(tfm);
    }
    
    get_random_bytes(ctx->encryption_key, sizeof(ctx->encryption_key));
    get_random_bytes(ctx->encryption_iv, sizeof(ctx->encryption_iv));
    
    ret = crypto_skcipher_setkey(tfm, ctx->encryption_key, sizeof(ctx->encryption_key));
    if (ret) {
        pr_err("Failed to set encryption key\n");
        crypto_free_skcipher(tfm);
        return ret;
    }
    
    ctx->skcipher = tfm;
    return 0;
}

void cleanup_encryption(struct protection_context *ctx) {
    if (ctx->skcipher) {
        crypto_free_skcipher(ctx->skcipher);
        ctx->skcipher = NULL;
    }
    memzero_explicit(ctx->encryption_key, sizeof(ctx->encryption_key));
    memzero_explicit(ctx->encryption_iv, sizeof(ctx->encryption_iv));
}

int encrypt_data(struct protection_context *ctx, void *data, size_t len) {
    struct skcipher_request *req;
    struct scatterlist sg;
    int ret;
    
    if (!ctx->skcipher) return -EINVAL;
    
    req = skcipher_request_alloc(ctx->skcipher, GFP_KERNEL);
    if (!req) return -ENOMEM;
    
    sg_init_one(&sg, data, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, ctx->encryption_iv);
    
    ret = crypto_skcipher_encrypt(req);
    skcipher_request_free(req);
    
    return ret;
}

int decrypt_data(struct protection_context *ctx, void *data, size_t len) {
    struct skcipher_request *req;
    struct scatterlist sg;
    int ret;
    
    if (!ctx->skcipher) return -EINVAL;
    
    req = skcipher_request_alloc(ctx->skcipher, GFP_KERNEL);
    if (!req) return -ENOMEM;
    
    sg_init_one(&sg, data, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, ctx->encryption_iv);
    
    ret = crypto_skcipher_decrypt(req);
    skcipher_request_free(req);
    
    return ret;
}

int protect_process(pid_t pid) {
    int ret = 0;
    
    mutex_lock(&global_ctx.pid_mutex);
    
    if (global_ctx.protected_count >= MAX_PROTECTED_PIDS) {
        ret = -ENOSPC;
        goto out;
    }
    
    global_ctx.protected_pids[global_ctx.protected_count++] = pid;
    qsort(global_ctx.protected_pids, global_ctx.protected_count, sizeof(pid_t), compare_pids);
    
    ret = hide_memory_maps(pid);
    if (ret) {
        pr_err("Failed to hide memory maps for pid %d\n", pid);
        goto out;
    }
    
    struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (task) {
        ret = obfuscate_task_struct(task);
        if (ret) {
            pr_err("Failed to obfuscate task struct for pid %d\n", pid);
        }
    }
    
    ret = manipulate_procfs(pid);
    if (ret) {
        pr_err("Failed to manipulate procfs for pid %d\n", pid);
    }

out:
    mutex_unlock(&global_ctx.pid_mutex);
    return ret;
}

int unprotect_process(pid_t pid) {
    pid_t *found;
    
    mutex_lock(&global_ctx.pid_mutex);
    
    found = bsearch(&pid, global_ctx.protected_pids, global_ctx.protected_count, sizeof(pid_t), compare_pids);
    if (!found) {
        mutex_unlock(&global_ctx.pid_mutex);
        return -ENOENT;
    }
    
    size_t index = found - global_ctx.protected_pids;
    memmove(&global_ctx.protected_pids[index], &global_ctx.protected_pids[index + 1], 
            (global_ctx.protected_count - index - 1) * sizeof(pid_t));
    global_ctx.protected_count--;
    
    mutex_unlock(&global_ctx.pid_mutex);
    return 0;
}

int is_protected(pid_t pid) {
    int protected = 0;
    
    mutex_lock(&global_ctx.pid_mutex);
    protected = bsearch(&pid, global_ctx.protected_pids, global_ctx.protected_count, sizeof(pid_t), compare_pids) != NULL;
    mutex_unlock(&global_ctx.pid_mutex);
    
    return protected;
}

asmlinkage long hooked_ptrace(long request, long pid, unsigned long addr, unsigned long data) {
    read_lock(&table_lock);
    
    if (is_protected(pid) && (request == PTRACE_ATTACH || request == PTRACE_SEIZE || request == PTRACE_PEEKDATA)) {
        read_unlock(&table_lock);
        return -EPERM;
    }
    
    long ret = ((long (*)(long, long, unsigned long, unsigned long))global_ctx.original_handlers[__NR_ptrace])(request, pid, addr, data);
    read_unlock(&table_lock);
    return ret;
}

asmlinkage long hooked_kill(pid_t pid, int sig) {
    read_lock(&table_lock);
    
    if (is_protected(pid) && sig != 0) {
        read_unlock(&table_lock);
        return -EPERM;
    }
    
    long ret = ((long (*)(pid_t, int))global_ctx.original_handlers[__NR_kill])(pid, sig);
    read_unlock(&table_lock);
    return ret;
}

asmlinkage long hooked_process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags) {
    read_lock(&table_lock);
    
    if (is_protected(pid)) {
        read_unlock(&table_lock);
        return -EPERM;
    }
    
    long ret = ((long (*)(pid_t, const struct iovec *, unsigned long, const struct iovec *, unsigned long, unsigned long))global_ctx.original_handlers[__NR_process_vm_readv])(pid, lvec, liovcnt, rvec, riovcnt, flags);
    read_unlock(&table_lock);
    return ret;
}

int hide_memory_maps(pid_t pid) {
    struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) return -ESRCH;
    
    struct mm_struct *mm = task->mm;
    if (!mm) return -ESRCH;
    
    down_read(&mm->mmap_sem);
    struct vm_area_struct *vma;
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        vma->vm_flags |= VM_DONTDUMP;
        vma->vm_flags &= ~VM_IO;
    }
    up_read(&mm->mmap_sem);
    
    return 0;
}

int obfuscate_task_struct(struct task_struct *task) {
    char fake_comm[TASK_COMM_LEN];
    get_random_bytes(fake_comm, sizeof(fake_comm));
    memcpy(task->comm, fake_comm, sizeof(fake_comm));
    
    task->flags |= PF_KTHREAD;
    task->ptrace = 0;
    
    return 0;
}

static int proc_pid_status_hook(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task) {
    if (is_protected(task->pid)) {
        seq_printf(m, "Name:\t%s\n", task->comm);
        seq_printf(m, "State:\tS (sleeping)\n");
        seq_printf(m, "Tgid:\t%d\n", task->tgid);
        seq_printf(m, "Pid:\t%d\n", task->pid);
        seq_printf(m, "TracerPid:\t0\n");
        return 0;
    }
    
    return orig_proc_pid_status(m, ns, pid, task);
}

int hook_procfs_functions(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    orig_proc_pid_status = (proc_pid_status_t)kallsyms_lookup_name("proc_pid_status");
    if (!orig_proc_pid_status) {
        pr_err("Failed to find proc_pid_status\n");
        return -ENOENT;
    }
    
    write_read_only((unsigned long)orig_proc_pid_status, (unsigned long)proc_pid_status_hook);
    return 0;
#else
    pr_warn("Procfs hooking not supported on this kernel version\n");
    return -ENOSYS;
#endif
}

void unhook_procfs_functions(void) {
    if (orig_proc_pid_status) {
        write_read_only((unsigned long)proc_pid_status_hook, (unsigned long)orig_proc_pid_status);
        orig_proc_pid_status = NULL;
    }
}

void monitor_debugger_processes(struct work_struct *work) {
    struct task_struct *task;
    const char *debuggers[] = {
        "gdb", "lldb", "strace", "ltrace", "frida", "idapro", 
        "x64dbg", "ollydbg", "windbg", "ghidra", "radare2", 
        "code\\-", "debug", "analy", "reverse", "detect", 
        "scan", "inspect", "trace", "monitor", NULL
    };
    
    rcu_read_lock();
    for_each_process(task) {
        for (int i = 0; debuggers[i]; i++) {
            if (strstr(task->comm, debuggers[i])) {
                kill_pid(task_pid(task), SIGKILL, 1);
                pr_info("Terminated debugger process: %s (PID: %d)\n", task->comm, task->pid);
                break;
            }
        }
    }
    rcu_read_unlock();
}

void debugger_timer_callback(struct timer_list *t) {
    schedule_work(&global_ctx.debugger_work);
    mod_timer(&global_ctx.debugger_timer, jiffies + msecs_to_jiffies(DEBUGGER_CHECK_INTERVAL));
}

void clear_hw_breakpoints(struct task_struct *task) {
    struct thread_struct *thread = &task->thread;
    for (int i = 0; i < HBP_NUM; i++) {
        thread->ptrace_bps[i] = NULL;
    }
}

int manipulate_procfs(pid_t pid) {
    char path[64];
    struct path proc_path;
    int ret;
    
    snprintf(path, sizeof(path), "/proc/%d", pid);
    ret = kern_path(path, LOOKUP_FOLLOW, &proc_path);
    if (ret) {
        pr_err("Failed to find proc path for pid %d: %d\n", pid, ret);
        return ret;
    }
    
    inode_lock(d_inode(proc_path.dentry));
    d_inode(proc_path.dentry)->i_flags |= S_IMMUTABLE;
    inode_unlock(d_inode(proc_path.dentry));
    path_put(&proc_path);
    
    return 0;
}

int hook_critical_syscalls(struct protection_context *ctx) {
    unsigned long *syscall_table;
    unsigned long cr0;
    int ret = 0;
    
    syscall_table = (unsigned long *)get_syscall_table();
    if (!syscall_table) {
        return -ENOENT;
    }
    
    cr0 = get_cr0();
    set_cr0(cr0 & ~(1UL << CR0_WP_BIT));
    
    int syscalls_to_hook[] = {__NR_ptrace, __NR_kill, __NR_process_vm_readv, __NR_process_vm_writev, __NR_perf_event_open};
    void *handlers[] = {hooked_ptrace, hooked_kill, hooked_process_vm_readv, NULL, NULL};
    
    write_lock(&table_lock);
    for (int i = 0; i < ARRAY_SIZE(syscalls_to_hook); i++) {
        if (handlers[i] && ctx->hook_count < MAX_HOOKED_SYSCALLS) {
            ctx->syscall_hooks[ctx->hook_count] = syscall_table[syscalls_to_hook[i]];
            ctx->original_handlers[ctx->hook_count] = (void *)syscall_table[syscalls_to_hook[i]];
            syscall_table[syscalls_to_hook[i]] = (unsigned long)handlers[i];
            ctx->hook_count++;
        }
    }
    write_unlock(&table_lock);
    
    set_cr0(cr0);
    return ret;
}

void unhook_syscalls(struct protection_context *ctx) {
    unsigned long *syscall_table;
    unsigned long cr0;
    
    syscall_table = (unsigned long *)get_syscall_table();
    if (!syscall_table) {
        return;
    }
    
    cr0 = get_cr0();
    set_cr0(cr0 & ~(1UL << CR0_WP_BIT));
    
    write_lock(&table_lock);
    for (int i = 0; i < ctx->hook_count; i++) {
        syscall_table[i] = ctx->syscall_hooks[i];
    }
    write_unlock(&table_lock);
    
    set_cr0(cr0);
}

static int kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
    if (within_module(regs->ip, THIS_MODULE)) {
        regs->ip = (unsigned long)cleanup_anti_debug;
    }
    return 0;
}

static void kprobe_post_handler(struct kprobe *kp, struct pt_regs *regs, unsigned long flags) {
}

int install_kprobes(struct protection_context *ctx) {
    const char *symbols[] = {
        "do_debug", "ptrace_request", "proc_pid_readdir", 
        "security_file_permission", "__x64_sys_ptrace"
    };
    
    ctx->kprobes = kzalloc(ARRAY_SIZE(symbols) * sizeof(struct kprobe), GFP_KERNEL);
    if (!ctx->kprobes) {
        return -ENOMEM;
    }
    
    for (int i = 0; i < ARRAY_SIZE(symbols); i++) {
        unsigned long addr = kallsyms_lookup_name(symbols[i]);
        if (!addr) {
            pr_warn("Symbol %s not found\n", symbols[i]);
            continue;
        }
        
        ctx->kprobes[ctx->kprobe_count].addr = (kprobe_opcode_t *)addr;
        ctx->kprobes[ctx->kprobe_count].pre_handler = kprobe_pre_handler;
        ctx->kprobes[ctx->kprobe_count].post_handler = kprobe_post_handler;
        
        int ret = register_kprobe(&ctx->kprobes[ctx->kprobe_count]);
        if (ret) {
            pr_err("Failed to register kprobe for %s: %d\n", symbols[i], ret);
            continue;
        }
        
        ctx->kprobe_count++;
    }
    
    return 0;
}

void remove_kprobes(struct protection_context *ctx) {
    for (int i = 0; i < ctx->kprobe_count; i++) {
        unregister_kprobe(&ctx->kprobes[i]);
    }
    kfree_sensitive(ctx->kprobes);
    ctx->kprobes = NULL;
    ctx->kprobe_count = 0;
}

void ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    if (within_module(ip, THIS_MODULE)) {
        regs->ip = (unsigned long)cleanup_anti_debug;
    }
}

int secure_module_memory(void) {
    unsigned long text_start = (unsigned long)_text;
    unsigned long text_end = (unsigned long)_etext;
    unsigned long data_start = (unsigned long)_sdata;
    unsigned long data_end = (unsigned long)_edata;
    
    int ret = set_memory_ro(text_start, (text_end - text_start) / PAGE_SIZE);
    if (ret) {
        pr_err("Failed to set text memory read-only: %d\n", ret);
        return ret;
    }
    
    ret = set_memory_ro(data_start, (data_end - data_start) / PAGE_SIZE);
    if (ret) {
        pr_err("Failed to set data memory read-only: %d\n", ret);
        return ret;
    }
    
    return 0;
}

void release_module_memory(void) {
    unsigned long text_start = (unsigned long)_text;
    unsigned long text_end = (unsigned long)_etext;
    unsigned long data_start = (unsigned long)_sdata;
    unsigned long data_end = (unsigned long)_edata;
    
    set_memory_rw(text_start, (text_end - text_start) / PAGE_SIZE);
    set_memory_rw(data_start, (data_end - data_start) / PAGE_SIZE);
}

void init_anti_debug(struct protection_context *ctx) {
    int ret;
    
    memset(ctx, 0, sizeof(*ctx));
    mutex_init(&ctx->pid_mutex);
    rwlock_init(&ctx->syscall_lock);
    
    ret = setup_encryption(ctx);
    if (ret) {
        pr_err("Failed to setup encryption: %d\n", ret);
        return;
    }
    
    ret = hook_critical_syscalls(ctx);
    if (ret) {
        pr_err("Failed to hook syscalls: %d\n", ret);
        goto cleanup_enc;
    }
    
    ret = install_kprobes(ctx);
    if (ret) {
        pr_err("Failed to install kprobes: %d\n", ret);
        goto cleanup_syscalls;
    }
    
    ctx->ftrace_ops.func = ftrace_callback;
    ctx->ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
    
    ret = register_ftrace_function(&ctx->ftrace_ops);
    if (ret) {
        pr_err("Failed to register ftrace: %d\n", ret);
        goto cleanup_kprobes;
    }
    
    INIT_WORK(&ctx->debugger_work, monitor_debugger_processes);
    timer_setup(&ctx->debugger_timer, debugger_timer_callback, 0);
    mod_timer(&ctx->debugger_timer, jiffies + msecs_to_jiffies(DEBUGGER_CHECK_INTERVAL));
    
    ret = hook_procfs_functions();
    if (ret) {
        pr_warn("Failed to hook procfs functions: %d\n", ret);
    }
    
    ret = secure_module_memory();
    if (ret) {
        pr_warn("Failed to secure module memory: %d\n", ret);
    }
    
    ret = protect_process(current->pid);
    if (ret) {
        pr_err("Failed to protect initial process: %d\n", ret);
    }
    
    pr_info("Anti-debug protection initialized\n");
    return;

cleanup_kprobes:
    remove_kprobes(ctx);
cleanup_syscalls:
    unhook_syscalls(ctx);
cleanup_enc:
    cleanup_encryption(ctx);
}

void cleanup_anti_debug(struct protection_context *ctx) {
    del_timer_sync(&ctx->debugger_timer);
    cancel_work_sync(&ctx->debugger_work);
    
    unregister_ftrace_function(&ctx->ftrace_ops);
    remove_kprobes(ctx);
    unhook_syscalls(ctx);
    cleanup_encryption(ctx);
    unhook_procfs_functions();
    release_module_memory();
    
    mutex_destroy(&ctx->pid_mutex);
    
    pr_info("Anti-debug protection cleaned up\n");
}

static int __init anti_debug_init(void) {
    int ret;
    
    ret = secure_module_memory();
    if (ret) {
        pr_err("Failed to secure module memory during init: %d\n", ret);
        return ret;
    }
    
    init_anti_debug(&global_ctx);
    return 0;
}

static void __exit anti_debug_exit(void) {
    cleanup_anti_debug(&global_ctx);
}

module_init(anti_debug_init);
module_exit(anti_debug_exit);