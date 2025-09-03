#include "code_execution.h"
#include <linux/fcntl.h>
#include <linux/unistd.h>
#include <linux/auxvec.h>

#define SYSCALL6(num, a1, a2, a3, a4, a5, a6) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x3, %4\n" \
        "mov x4, %5\n" \
        "mov x5, %6\n" \
        "mov x8, %7\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (num) \
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL3(num, a1, a2, a3) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x1, %2\n" \
        "mov x2, %3\n" \
        "mov x8, %4\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (a2), "r" (a3), "r" (num) \
        : "x0", "x1", "x2", "x8", "memory" \
    ); \
    ret; \
})

#define SYSCALL1(num, a1) ({ \
    long ret; \
    asm volatile ( \
        "mov x0, %1\n" \
        "mov x8, %2\n" \
        "svc #0\n" \
        "mov %0, x0\n" \
        : "=r" (ret) \
        : "r" (a1), "r" (num) \
        : "x0", "x8", "memory" \
    ); \
    ret; \
})

static int sys_open(const char *path, int flags, int mode) {
    return SYSCALL3(__NR_open, (long)path, flags, mode);
}

static int sys_close(int fd) {
    return SYSCALL1(__NR_close, fd);
}

static ssize_t sys_read(int fd, void *buf, size_t count) {
    return SYSCALL3(__NR_read, fd, (long)buf, count);
}

static ssize_t sys_write(int fd, const void *buf, size_t count) {
    return SYSCALL3(__NR_write, fd, (long)buf, count);
}

static off_t sys_lseek(int fd, off_t offset, int whence) {
    return SYSCALL3(__NR_lseek, fd, offset, whence);
}

static void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return (void *)SYSCALL6(__NR_mmap, (long)addr, length, prot, flags, fd, offset);
}

static int sys_munmap(void *addr, size_t length) {
    return SYSCALL2(__NR_munmap, (long)addr, length);
}

static int sys_ptrace(long request, pid_t pid, void *addr, void *data) {
    return SYSCALL4(__NR_ptrace, request, pid, (long)addr, (long)data);
}

static int sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    return SYSCALL3(__NR_getdents, fd, (long)dirp, count);
}

static int sys_kill(pid_t pid, int sig) {
    return SYSCALL2(__NR_kill, pid, sig);
}

static pid_t sys_getpid() {
    return SYSCALL0(__NR_getpid);
}

static int attach_process(pid_t pid) {
    if (sys_ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    
    int status;
    asm volatile (
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x8, %3\n"
        "svc #0\n"
        : "=r" (status)
        : "r" (pid), "r" (0), "r" (__NR_wait4)
        : "x0", "x1", "x8", "memory"
    );
    
    return (status == 0) ? 0 : -1;
}

static int detach_process(pid_t pid) {
    return sys_ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static unsigned long get_register(pid_t pid, int reg) {
    struct user_pt_regs regs;
    if (sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) return 0;
    
    switch (reg) {
        case 0: return regs.regs[0];
        case 1: return regs.regs[1];
        case 2: return regs.regs[2];
        case 3: return regs.regs[3];
        case 4: return regs.regs[4];
        case 5: return regs.regs[5];
        case 6: return regs.regs[6];
        case 7: return regs.regs[7];
        case 8: return regs.regs[8];
        case 9: return regs.regs[9];
        case 10: return regs.regs[10];
        case 11: return regs.regs[11];
        case 12: return regs.regs[12];
        case 13: return regs.regs[13];
        case 14: return regs.regs[14];
        case 15: return regs.regs[15];
        case 16: return regs.regs[16];
        case 17: return regs.regs[17];
        case 18: return regs.regs[18];
        case 19: return regs.regs[19];
        case 20: return regs.regs[20];
        case 21: return regs.regs[21];
        case 22: return regs.regs[22];
        case 23: return regs.regs[23];
        case 24: return regs.regs[24];
        case 25: return regs.regs[25];
        case 26: return regs.regs[26];
        case 27: return regs.regs[27];
        case 28: return regs.regs[28];
        case 29: return regs.regs[29];
        case 30: return regs.regs[30];
        case 31: return regs.regs[31];
        case 32: return regs.sp;
        case 33: return regs.pc;
        default: return 0;
    }
}

static int set_register(pid_t pid, int reg, unsigned long value) {
    struct user_pt_regs regs;
    if (sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) return -1;
    
    switch (reg) {
        case 0: regs.regs[0] = value; break;
        case 1: regs.regs[1] = value; break;
        case 2: regs.regs[2] = value; break;
        case 3: regs.regs[3] = value; break;
        case 4: regs.regs[4] = value; break;
        case 5: regs.regs[5] = value; break;
        case 6: regs.regs[6] = value; break;
        case 7: regs.regs[7] = value; break;
        case 8: regs.regs[8] = value; break;
        case 9: regs.regs[9] = value; break;
        case 10: regs.regs[10] = value; break;
        case 11: regs.regs[11] = value; break;
        case 12: regs.regs[12] = value; break;
        case 13: regs.regs[13] = value; break;
        case 14: regs.regs[14] = value; break;
        case 15: regs.regs[15] = value; break;
        case 16: regs.regs[16] = value; break;
        case 17: regs.regs[17] = value; break;
        case 18: regs.regs[18] = value; break;
        case 19: regs.regs[19] = value; break;
        case 20: regs.regs[20] = value; break;
        case 21: regs.regs[21] = value; break;
        case 22: regs.regs[22] = value; break;
        case 23: regs.regs[23] = value; break;
        case 24: regs.regs[24] = value; break;
        case 25: regs.regs[25] = value; break;
        case 26: regs.regs[26] = value; break;
        case 27: regs.regs[27] = value; break;
        case 28: regs.regs[28] = value; break;
        case 29: regs.regs[29] = value; break;
        case 30: regs.regs[30] = value; break;
        case 31: regs.regs[31] = value; break;
        case 32: regs.sp = value; break;
        case 33: regs.pc = value; break;
        default: return -1;
    }
    
    return sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

static unsigned long read_memory(pid_t pid, unsigned long addr) {
    return sys_ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
}

static int write_memory(pid_t pid, unsigned long addr, unsigned long data) {
    return sys_ptrace(PTRACE_POKETEXT, pid, (void *)addr, data);
}

static int parse_elf_header(int fd, Elf64_Ehdr *ehdr) {
    if (sys_lseek(fd, 0, SEEK_SET) < 0) return -1;
    return (sys_read(fd, ehdr, sizeof(Elf64_Ehdr)) == sizeof(Elf64_Ehdr)) ? 0 : -1;
}

static int parse_program_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdrs) {
    if (sys_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0) return -1;
    return (sys_read(fd, phdrs, ehdr->e_phnum * sizeof(Elf64_Phdr)) == ehdr->e_phnum * sizeof(Elf64_Phdr)) ? 0 : -1;
}

static unsigned long allocate_remote_memory(pid_t pid, size_t size, int prot) {
    return remote_syscall(pid, __NR_mmap, 0, size, prot, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int inject_code(pid_t pid, unsigned long addr, const void *code, size_t size) {
    const unsigned long *code_ptr = (const unsigned long *)code;
    size_t words = (size + sizeof(unsigned long) - 1) / sizeof(unsigned long);
    
    for (size_t i = 0; i < words; i++) {
        if (write_memory(pid, addr + i * sizeof(unsigned long), code_ptr[i]) < 0) {
            return -1;
        }
    }
    return 0;
}

static int create_remote_stack(pid_t pid, unsigned long *stack_addr, size_t stack_size, 
                              char **argv, char **envp) {
    *stack_addr = allocate_remote_memory(pid, stack_size, PROT_READ | PROT_WRITE);
    if (*stack_addr == (unsigned long)-1) return -1;
    
    unsigned long stack_ptr = *stack_addr + stack_size;
    
    int argc = 0;
    while (argv[argc]) argc++;
    
    int envc = 0;
    while (envp[envc]) envc++;
    
    stack_ptr -= (argc + 1) * sizeof(unsigned long);
    unsigned long argv_ptrs = stack_ptr;
    
    stack_ptr -= (envc + 1) * sizeof(unsigned long);
    unsigned long envp_ptrs = stack_ptr;
    
    for (int i = argc - 1; i >= 0; i--) {
        stack_ptr -= strlen(argv[i]) + 1;
        inject_code(pid, stack_ptr, argv[i], strlen(argv[i]) + 1);
        write_memory(pid, argv_ptrs + i * sizeof(unsigned long), stack_ptr);
    }
    write_memory(pid, argv_ptrs + argc * sizeof(unsigned long), 0);
    
    for (int i = envc - 1; i >= 0; i--) {
        stack_ptr -= strlen(envp[i]) + 1;
        inject_code(pid, stack_ptr, envp[i], strlen(envp[i]) + 1);
        write_memory(pid, envp_ptrs + i * sizeof(unsigned long), stack_ptr);
    }
    write_memory(pid, envp_ptrs + envc * sizeof(unsigned long), 0);
    
    stack_ptr -= sizeof(unsigned long);
    write_memory(pid, stack_ptr, envp_ptrs);
    
    stack_ptr -= sizeof(unsigned long);
    write_memory(pid, stack_ptr, argv_ptrs);
    
    stack_ptr -= sizeof(unsigned long);
    write_memory(pid, stack_ptr, argc);
    
    return stack_ptr;
}

int remote_syscall(pid_t pid, long syscall_number, 
                  unsigned long arg1, unsigned long arg2, 
                  unsigned long arg3, unsigned long arg4,
                  unsigned long arg5, unsigned long arg6) {
    
    if (attach_process(pid) < 0) return -1;
    
    unsigned long original_pc = get_register(pid, 33);
    unsigned long original_sp = get_register(pid, 32);
    
    unsigned long code_addr = allocate_remote_memory(pid, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (code_addr == (unsigned long)-1) {
        detach_process(pid);
        return -1;
    }
    
    unsigned long syscall_code[] = {
        0xD2800000 | (syscall_number & 0xFFFF), 
        0xD4000001,                           
        0xD65F03C0                           
    };
    
    if (inject_code(pid, code_addr, syscall_code, sizeof(syscall_code)) < 0) {
        sys_munmap((void *)code_addr, 4096);
        detach_process(pid);
        return -1;
    }
    
    set_register(pid, 0, arg1);
    set_register(pid, 1, arg2);
    set_register(pid, 2, arg3);
    set_register(pid, 3, arg4);
    set_register(pid, 4, arg5);
    set_register(pid, 5, arg6);
    set_register(pid, 33, code_addr);
    
    sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    int status;
    asm volatile (
        "mov x0, %1\n"
        "mov x1, %2\n"
        "mov x8, %3\n"
        "svc #0\n"
        : "=r" (status)
        : "r" (pid), "r" (0), "r" (__NR_wait4)
        : "x0", "x1", "x8", "memory"
    );
    
    unsigned long result = get_register(pid, 0);
    
    set_register(pid, 33, original_pc);
    set_register(pid, 32, original_sp);
    
    sys_munmap((void *)code_addr, 4096);
    detach_process(pid);
    
    return result;
}

int execute_in_process(exec_config_t *config) {
    if (attach_process(config->target_pid) < 0) return -1;
    
    int binary_fd = sys_open(config->binary_path, O_RDONLY, 0);
    if (binary_fd < 0) {
        detach_process(config->target_pid);
        return -1;
    }
    
    Elf64_Ehdr ehdr;
    if (parse_elf_header(binary_fd, &ehdr) < 0) {
        sys_close(binary_fd);
        detach_process(config->target_pid);
        return -1;
    }
    
    Elf64_Phdr phdrs[ehdr.e_phnum];
    if (parse_program_headers(binary_fd, &ehdr, phdrs) < 0) {
        sys_close(binary_fd);
        detach_process(config->target_pid);
        return -1;
    }
    
    unsigned long base_address = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            base_address = allocate_remote_memory(config->target_pid, 
                                                phdrs[i].p_memsz, 
                                                phdrs[i].p_flags);
            if (base_address == (unsigned long)-1) {
                sys_close(binary_fd);
                detach_process(config->target_pid);
                return -1;
            }
            
            char *segment_data = sys_mmap(NULL, phdrs[i].p_filesz, PROT_READ, 
                                        MAP_PRIVATE, binary_fd, phdrs[i].p_offset);
            if (segment_data == MAP_FAILED) {
                sys_close(binary_fd);
                detach_process(config->target_pid);
                return -1;
            }
            
            inject_code(config->target_pid, base_address, segment_data, phdrs[i].p_filesz);
            sys_munmap(segment_data, phdrs[i].p_filesz);
        }
    }
    
    sys_close(binary_fd);
    
    unsigned long stack_addr;
    unsigned long stack_ptr = create_remote_stack(config->target_pid, &stack_addr, 
                                                 config->stack_size ? config->stack_size : 1024 * 1024,
                                                 config->argv, config->envp);
    
    if (stack_ptr == (unsigned long)-1) {
        detach_process(config->target_pid);
        return -1;
    }
    
    set_register(config->target_pid, 32, stack_ptr);
    set_register(config->target_pid, 33, base_address + ehdr.e_entry);
    
    if (!config->preserve_context) {
        for (int i = 0; i < 30; i++) {
            set_register(config->target_pid, i, 0);
        }
    }
    
    sys_ptrace(PTRACE_CONT, config->target_pid, NULL, NULL);
    
    if (config->stealth_mode) {
        detach_process(config->target_pid);
    }
    
    return 0;
}

int inject_library(pid_t pid, const char *lib_path) {
    unsigned long dlopen_addr = remote_syscall(pid, __NR_dlsym, RTLD_DEFAULT, (unsigned long)"dlopen", 0, 0, 0, 0);
    if (dlopen_addr == (unsigned long)-1) return -1;
    
    unsigned long lib_name_addr = allocate_remote_memory(pid, strlen(lib_path) + 1, 
                                                       PROT_READ | PROT_WRITE);
    if (lib_name_addr == (unsigned long)-1) return -1;
    
    inject_code(pid, lib_name_addr, lib_path, strlen(lib_path) + 1);
    
    unsigned long result = remote_syscall(pid, __NR_dlopen, lib_name_addr, 
                                        RTLD_NOW | RTLD_GLOBAL, 0, 0, 0, 0);
    
    sys_munmap((void *)lib_name_addr, strlen(lib_path) + 1);
    
    return (result != 0) ? 0 : -1;
}