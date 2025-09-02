#include <sys/syscall.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>
#include <asm/stat.h>

#define LOCKSCREEN_WALLPAPER_PATH "/data/system/users/0/wallpaper_lock"
#define HOMESCREEN_WALLPAPER_PATH "/data/system/users/0/wallpaper"
#define WALLPAPER_INFO_FILE "/data/system/users/0/wallpaper_info.xml"

static long raw_open(const char *pathname, int flags, mode_t mode) {
    return syscall(__NR_open, pathname, flags, mode);
}

static long raw_close(int fd) {
    return syscall(__NR_close, fd);
}

static long raw_write(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static long raw_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static long raw_lseek(int fd, off_t offset, int whence) {
    return syscall(__NR_lseek, fd, offset, whence);
}

static long raw_fstat(int fd, struct stat *statbuf) {
    return syscall(__NR_fstat, fd, statbuf);
}

static long raw_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return syscall(__NR_mmap, addr, length, prot, flags, fd, offset);
}

static long raw_munmap(void *addr, size_t length) {
    return syscall(__NR_munmap, addr, length);
}

static long raw_unlink(const char *pathname) {
    return syscall(__NR_unlink, pathname);
}

static long raw_chmod(const char *pathname, mode_t mode) {
    return syscall(__NR_chmod, pathname, mode);
}

static long raw_chown(const char *pathname, uid_t owner, gid_t group) {
    return syscall(__NR_chown, pathname, owner, group);
}

static long raw_kill(pid_t pid, int sig) {
    return syscall(__NR_kill, pid, sig);
}

static int direct_write_file(const char *path, const unsigned char *data, size_t size) {
    int fd = raw_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    
    size_t total_written = 0;
    while (total_written < size) {
        long written = raw_write(fd, data + total_written, size - total_written);
        if (written <= 0) {
            raw_close(fd);
            return -1;
        }
        total_written += written;
    }
    
    raw_close(fd);
    return 0;
}

static int direct_backup_wallpaper(const char *path, const char *backup_path) {
    int src_fd = raw_open(path, O_RDONLY, 0);
    if (src_fd < 0) return -1;
    
    struct stat st;
    if (raw_fstat(src_fd, &st) < 0) {
        raw_close(src_fd);
        return -1;
    }
    
    void *src_map = (void*)raw_mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if ((long)src_map < 0) {
        raw_close(src_fd);
        return -1;
    }
    
    int dst_fd = raw_open(backup_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dst_fd < 0) {
        raw_munmap(src_map, st.st_size);
        raw_close(src_fd);
        return -1;
    }
    
    size_t total_written = 0;
    while (total_written < st.st_size) {
        long written = raw_write(dst_fd, (char*)src_map + total_written, st.st_size - total_written);
        if (written <= 0) break;
        total_written += written;
    }
    
    raw_munmap(src_map, st.st_size);
    raw_close(src_fd);
    raw_close(dst_fd);
    
    return total_written == st.st_size ? 0 : -1;
}

static int update_wallpaper_info_direct(int width, int height) {
    char info_content[128];
    int len = 0;
    
    len += snprintf(info_content + len, sizeof(info_content) - len, "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n");
    len += snprintf(info_content + len, sizeof(info_content) - len, "<wp width=\"%d\" height=\"%d\" name=\"system_wallpaper\" />\n", width, height);
    
    return direct_write_file(WALLPAPER_INFO_FILE, (unsigned char*)info_content, len);
}

static void force_refresh_direct() {
    pid_t systemui_pid = -1;
    
    int fd = raw_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return;
    
    char buf[4096];
    long bytes = raw_getdents(fd, (struct linux_dirent *)buf, sizeof(buf));
    raw_close(fd);
    
    if (bytes <= 0) return;
    
    struct linux_dirent *d;
    long bpos = 0;
    while (bpos < bytes) {
        d = (struct linux_dirent *)(buf + bpos);
        
        if (d->d_ino && d->d_name[0] >= '0' && d->d_name[0] <= '9') {
            pid_t pid = atoi(d->d_name);
            
            char comm_path[256];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
            
            int comm_fd = raw_open(comm_path, O_RDONLY, 0);
            if (comm_fd >= 0) {
                char comm[64];
                long comm_len = raw_read(comm_fd, comm, sizeof(comm)-1);
                raw_close(comm_fd);
                
                if (comm_len > 0) {
                    comm[comm_len] = 0;
                    if (strstr(comm, "systemui") || strstr(comm, "SystemUI")) {
                        systemui_pid = pid;
                        break;
                    }
                }
            }
        }
        bpos += d->d_reclen;
    }
    
    if (systemui_pid > 0) {
        raw_kill(systemui_pid, SIGTERM);
    }
}

int change_lockscreen_wallpaper_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup) {
    char backup_path[128];
    snprintf(backup_path, sizeof(backup_path), "%s.bak", LOCKSCREEN_WALLPAPER_PATH);
    
    if (backup) {
        direct_backup_wallpaper(LOCKSCREEN_WALLPAPER_PATH, backup_path);
    }
    
    if (direct_write_file(LOCKSCREEN_WALLPAPER_PATH, image_data, image_size) != 0) {
        return -1;
    }
    
    update_wallpaper_info_direct(width, height);
    raw_chmod(LOCKSCREEN_WALLPAPER_PATH, 0600);
    raw_chown(LOCKSCREEN_WALLPAPER_PATH, 0, 0);
    
    return 0;
}

int change_homescreen_wallpaper_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup) {
    char backup_path[128];
    snprintf(backup_path, sizeof(backup_path), "%s.bak", HOMESCREEN_WALLPAPER_PATH);
    
    if (backup) {
        direct_backup_wallpaper(HOMESCREEN_WALLPAPER_PATH, backup_path);
    }
    
    if (direct_write_file(HOMESCREEN_WALLPAPER_PATH, image_data, image_size) != 0) {
        return -1;
    }
    
    update_wallpaper_info_direct(width, height);
    raw_chmod(HOMESCREEN_WALLPAPER_PATH, 0600);
    raw_chown(HOMESCREEN_WALLPAPER_PATH, 0, 0);
    
    return 0;
}

int change_both_wallpapers_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup) {
    if (change_lockscreen_wallpaper_baremetal(image_data, image_size, width, height, backup) != 0) {
        return -1;
    }
    
    if (change_homescreen_wallpaper_baremetal(image_data, image_size, width, height, backup) != 0) {
        return -1;
    }
    
    force_refresh_direct();
    return 0;
}

int restore_wallpaper_baremetal(int target) {
    char backup_path[128];
    char *target_path = NULL;
    
    if (target == 0) {
        target_path = LOCKSCREEN_WALLPAPER_PATH;
        snprintf(backup_path, sizeof(backup_path), "%s.bak", LOCKSCREEN_WALLPAPER_PATH);
    } else if (target == 1) {
        target_path = HOMESCREEN_WALLPAPER_PATH;
        snprintf(backup_path, sizeof(backup_path), "%s.bak", HOMESCREEN_WALLPAPER_PATH);
    } else {
        return -1;
    }
    
    int src_fd = raw_open(backup_path, O_RDONLY, 0);
    if (src_fd < 0) return -1;
    
    struct stat st;
    if (raw_fstat(src_fd, &st) < 0) {
        raw_close(src_fd);
        return -1;
    }
    
    void *src_map = (void*)raw_mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if ((long)src_map < 0) {
        raw_close(src_fd);
        return -1;
    }
    
    int dst_fd = raw_open(target_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (dst_fd < 0) {
        raw_munmap(src_map, st.st_size);
        raw_close(src_fd);
        return -1;
    }
    
    size_t total_written = 0;
    while (total_written < st.st_size) {
        long written = raw_write(dst_fd, (char*)src_map + total_written, st.st_size - total_written);
        if (written <= 0) break;
        total_written += written;
    }
    
    raw_munmap(src_map, st.st_size);
    raw_close(src_fd);
    raw_close(dst_fd);
    
    if (total_written != st.st_size) {
        return -1;
    }
    
    raw_chmod(target_path, 0600);
    raw_chown(target_path, 0, 0);
    raw_unlink(backup_path);
    
    force_refresh_direct();
    return 0;
}