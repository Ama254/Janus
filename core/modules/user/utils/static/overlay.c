#include <linux/fb.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <asm/unistd.h>

#define MAX_MESSAGES 20
#define MAX_MSG_LENGTH 512
#define MAX_FB_PATHS 12
#define MAX_COLORS 10
#define COLOR_RGBA(r, g, b, a) (((a) << 24) | ((r) << 16) | ((g) << 8) | (b))

typedef struct {
    uint32_t *framebuffer;
    uint32_t *backbuffer;
    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;
    int fbfd;
    size_t screensize;
    int is_arm64;
} overlay_ctx_t;

typedef struct {
    char messages[MAX_MESSAGES][MAX_MSG_LENGTH];
    uint32_t colors[MAX_MESSAGES];
    int message_count;
    uint32_t bg_color;
    int duration_ms;
    int font_sizes[MAX_MESSAGES];
    void (*custom_funcs[MAX_MESSAGES])(char*);
    int counters[MAX_MESSAGES];
    int counter_steps[MAX_MESSAGES];
} overlay_config_t;

static overlay_ctx_t ctx;
static volatile int running = 1;

const char *fb_paths[MAX_FB_PATHS] = {
    "/dev/graphics/fb0", "/dev/fb0", "/dev/graphics/fb1", "/dev/fb1",
    "/dev/gpu/fb0", "/dev/video/fb0", "/dev/surfaceflinger/fb0", 
    "/dev/display/fb0", "/dev/graphics/display", "/dev/gfx0",
    "/dev/dri/card0", "/dev/dri/controlD64"
};

static int detect_architecture() {
    unsigned long machine_arch = 0;
    
    asm volatile (
        "mrc p15, 0, %0, c0, c0, 0\n"
        : "=r" (machine_arch)
    );
    
    if ((machine_arch & 0xFF000000) == 0x41000000) {
        return 64;
    }
    
    asm volatile (
        "mov %0, #0\n"
        "mrc p15, 0, %0, c0, c0, 0\n"
        : "=r" (machine_arch)
    );
    
    return 32;
}

static int sys_open(const char *path, int flags, int mode) {
    int ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x1, %2\n"
            "mov x2, %3\n"
            "mov x8, #56\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (path), "r" (flags), "r" (mode)
            : "x0", "x1", "x2", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r1, %2\n"
            "mov r2, %3\n"
            "mov r7, #5\n"
            "svc #0\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (path), "r" (flags), "r" (mode)
            : "r0", "r1", "r2", "r7", "memory"
        );
    }
    return ret;
}

static int sys_close(int fd) {
    int ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x8, #57\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (fd)
            : "x0", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r7, #6\n"
            "svc #0\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (fd)
            : "r0", "r7", "memory"
        );
    }
    return ret;
}

static int sys_ioctl(int fd, unsigned long request, void *arg) {
    int ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x1, %2\n"
            "mov x2, %3\n"
            "mov x8, #29\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (fd), "r" (request), "r" (arg)
            : "x0", "x1", "x2", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r1, %2\n"
            "mov r2, %3\n"
            "mov r7, #54\n"
            "svc #0\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (fd), "r" (request), "r" (arg)
            : "r0", "r1", "r2", "r7", "memory"
        );
    }
    return ret;
}

static void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x1, %2\n"
            "mov x2, %3\n"
            "mov x3, %4\n"
            "mov x4, %5\n"
            "mov x5, %6\n"
            "mov x8, #222\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (addr), "r" (length), "r" (prot), "r" (flags), "r" (fd), "r" (offset)
            : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r1, %2\n"
            "mov r2, %3\n"
            "mov r3, %4\n"
            "push {%5, %6}\n"
            "mov r7, #192\n"
            "svc #0\n"
            "add sp, sp, #8\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (addr), "r" (length), "r" (prot), "r" (flags), "r" (fd), "r" (offset)
            : "r0", "r1", "r2", "r3", "r7", "memory"
        );
    }
    return ret;
}

static int sys_munmap(void *addr, size_t length) {
    int ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x1, %2\n"
            "mov x8, #215\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (addr), "r" (length)
            : "x0", "x1", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r1, %2\n"
            "mov r7, #91\n"
            "svc #0\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (addr), "r" (length)
            : "r0", "r1", "r7", "memory"
        );
    }
    return ret;
}

static int sys_write(int fd, const void *buf, size_t count) {
    int ret;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %1\n"
            "mov x1, %2\n"
            "mov x2, %3\n"
            "mov x8, #64\n"
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (ret)
            : "r" (fd), "r" (buf), "r" (count)
            : "x0", "x1", "x2", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %1\n"
            "mov r1, %2\n"
            "mov r2, %3\n"
            "mov r7, #4\n"
            "svc #0\n"
            "mov %0, r0\n"
            : "=r" (ret)
            : "r" (fd), "r" (buf), "r" (count)
            : "r0", "r1", "r2", "r7", "memory"
        );
    }
    return ret;
}

static void grab_input_device(int fd) {
    int grab = 1;
    sys_ioctl(fd, EVIOCGRAB, &grab);
}

static void detect_fb_path(char *found_path) {
    for (int i = 0; i < MAX_FB_PATHS; i++) {
        int fd = sys_open(fb_paths[i], O_RDWR, 0);
        if (fd >= 0) {
            struct fb_fix_screeninfo finfo;
            if (sys_ioctl(fd, FBIOGET_FSCREENINFO, &finfo) == 0) {
                int len = 0;
                while (fb_paths[i][len] && len < 63) {
                    found_path[len] = fb_paths[i][len];
                    len++;
                }
                found_path[len] = 0;
                sys_close(fd);
                return;
            }
            sys_close(fd);
        }
    }
    found_path[0] = 0;
}

static int open_framebuffer() {
    char fb_path[64];
    detect_fb_path(fb_path);
    if (fb_path[0] == 0) return -1;

    ctx.fbfd = sys_open(fb_path, O_RDWR, 0);
    if (ctx.fbfd == -1) return -1;

    if (sys_ioctl(ctx.fbfd, FBIOGET_FSCREENINFO, &ctx.finfo) == -1) {
        sys_close(ctx.fbfd);
        return -1;
    }

    if (sys_ioctl(ctx.fbfd, FBIOGET_VSCREENINFO, &ctx.vinfo) == -1) {
        sys_close(ctx.fbfd);
        return -1;
    }

    ctx.screensize = ctx.vinfo.xres * ctx.vinfo.yres * (ctx.vinfo.bits_per_pixel / 8);
    ctx.framebuffer = sys_mmap(0, ctx.screensize, PROT_READ | PROT_WRITE, MAP_SHARED, ctx.fbfd, 0);
    if (ctx.framebuffer == MAP_FAILED) {
        sys_close(ctx.fbfd);
        return -1;
    }

    ctx.backbuffer = sys_mmap(0, ctx.screensize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx.backbuffer == MAP_FAILED) {
        sys_munmap(ctx.framebuffer, ctx.screensize);
        sys_close(ctx.fbfd);
        return -1;
    }

    for (size_t i = 0; i < ctx.screensize / sizeof(uint32_t); i++) {
        ctx.backbuffer[i] = ctx.framebuffer[i];
    }

    return 0;
}

static void close_framebuffer() {
    if (ctx.framebuffer != MAP_FAILED) {
        if (ctx.backbuffer != MAP_FAILED) {
            for (size_t i = 0; i < ctx.screensize / sizeof(uint32_t); i++) {
                ctx.framebuffer[i] = ctx.backbuffer[i];
            }
            sys_munmap(ctx.backbuffer, ctx.screensize);
        }
        sys_munmap(ctx.framebuffer, ctx.screensize);
    }
    if (ctx.fbfd != -1) sys_close(ctx.fbfd);
}

static void draw_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t color) {
    for (uint32_t row = y; row < y + height && row < ctx.vinfo.yres; row++) {
        for (uint32_t col = x; col < x + width && col < ctx.vinfo.xres; col++) {
            size_t offset = row * ctx.vinfo.xres + col;
            ctx.framebuffer[offset] = color;
        }
    }
}

static void draw_text(const char *text, uint32_t x, uint32_t y, uint32_t color, int font_size) {
    int char_width = font_size / 2;
    int char_height = font_size;
    
    for (int i = 0; text[i] != '\0'; i++) {
        uint32_t char_x = x + i * (char_width + 2);
        if (char_x + char_width >= ctx.vinfo.xres) break;

        for (int py = 0; py < char_height && y + py < ctx.vinfo.yres; py++) {
            for (int px = 0; px < char_width && char_x + px < ctx.vinfo.xres; px++) {
                size_t offset = (y + py) * ctx.vinfo.xres + (char_x + px);
                ctx.framebuffer[offset] = color;
            }
        }
    }
}

static void block_input_events() {
    const char *input_paths[] = {"/dev/input/event0", "/dev/input/event1", "/dev/input/event2", "/dev/input/event3"};
    
    for (int i = 0; i < 4; i++) {
        int fd = sys_open(input_paths[i], O_RDWR, 0);
        if (fd >= 0) {
            grab_input_device(fd);
            char buf[64];
            while (sys_read(fd, buf, sizeof(buf)) > 0) {}
            sys_close(fd);
        }
    }
}

static void hide_system_ui() {
    int fd = sys_open("/proc/self/root/system/bin/am", O_WRONLY, 0);
    if (fd >= 0) {
        const char *cmd = "am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS\n";
        sys_write(fd, cmd, 55);
        sys_close(fd);
    }
}

static void update_counters(overlay_config_t *config) {
    for (int i = 0; i < config->message_count; i++) {
        if (config->counter_steps[i] != 0) {
            config->counters[i] += config->counter_steps[i];
        }
    }
}

static void process_custom_functions(overlay_config_t *config) {
    for (int i = 0; i < config->message_count; i++) {
        if (config->custom_funcs[i]) {
            config->custom_funcs[i](config->messages[i]);
        }
    }
}

static void create_overlay(overlay_config_t *config) {
    draw_rect(0, 0, ctx.vinfo.xres, ctx.vinfo.yres, config->bg_color);
    
    int total_height = 0;
    for (int i = 0; i < config->message_count; i++) {
        total_height += config->font_sizes[i] + 10;
    }
    
    int current_y = (ctx.vinfo.yres - total_height) / 2;

    for (int i = 0; i < config->message_count; i++) {
        int text_width = 0;
        while (config->messages[i][text_width]) text_width++;
        text_width = text_width * (config->font_sizes[i] / 2);
        
        int start_x = (ctx.vinfo.xres - text_width) / 2;
        
        draw_text(config->messages[i], start_x, current_y, config->colors[i], config->font_sizes[i]);
        current_y += config->font_sizes[i] + 10;
    }
}

static void nanosleep_delay(long ns) {
    struct timespec req = {0, ns};
    if (ctx.is_arm64) {
        asm volatile (
            "mov x0, %0\n"
            "mov x8, #35\n"
            "svc #0\n"
            :
            : "r" (&req)
            : "x0", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r0, %0\n"
            "mov r7, #162\n"
            "svc #0\n"
            :
            : "r" (&req)
            : "r0", "r7", "memory"
        );
    }
}

int launch_overlay(overlay_config_t *config) {
    ctx.is_arm64 = (detect_architecture() == 64);
    
    if (open_framebuffer() == -1) return -1;
    hide_system_ui();

    unsigned long long start_time = 0;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x8, #96\n"
            "mov x0, %0\n"
            "svc #0\n"
            :
            : "r" (&start_time)
            : "x0", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r7, #78\n"
            "mov r0, %0\n"
            "svc #0\n"
            :
            : "r" (&start_time)
            : "r0", "r7", "memory"
        );
    }

    while (running) {
        unsigned long long current_time = 0;
        if (ctx.is_arm64) {
            asm volatile (
                "mov x8, #96\n"
                "mov x0, %0\n"
                "svc #0\n"
                :
                : "r" (&current_time)
                : "x0", "x8", "memory"
            );
        } else {
            asm volatile (
                "mov r7, #78\n"
                "mov r0, %0\n"
                "svc #0\n"
                :
                : "r" (&current_time)
                : "r0", "r7", "memory"
            );
        }

        if ((current_time - start_time) / 1000000 >= config->duration_ms) break;
        
        update_counters(config);
        process_custom_functions(config);
        create_overlay(config);
        block_input_events();
        nanosleep_delay(16666000);
    }

    close_framebuffer();
    return 0;
}

// Example custom functions
void counter_function(char *message) {
    static int count = 0;
    count++;
    char *ptr = message;
    while (*ptr) ptr++;
    if (ptr - message < MAX_MSG_LENGTH - 10) {
        int len = 0;
        while (message[len] && message[len] != ':') len++;
        message[len] = ':';
        message[len+1] = ' ';
        int num = count;
        int pos = len + 2;
        do {
            message[pos++] = '0' + (num % 10);
            num /= 10;
        } while (num > 0 && pos < MAX_MSG_LENGTH - 1);
        message[pos] = 0;
        
        // Reverse the number string
        for (int i = len + 2, j = pos - 1; i < j; i++, j--) {
            char temp = message[i];
            message[i] = message[j];
            message[j] = temp;
        }
    }
}

void time_function(char *message) {
    unsigned long long time_val = 0;
    if (ctx.is_arm64) {
        asm volatile (
            "mov x8, #96\n"
            "mov x0, %0\n"
            "svc #0\n"
            :
            : "r" (&time_val)
            : "x0", "x8", "memory"
        );
    } else {
        asm volatile (
            "mov r7, #78\n"
            "mov r0, %0\n"
            "svc #0\n"
            :
            : "r" (&time_val)
            : "r0", "r7", "memory"
        );
    }
    
    int seconds = (time_val / 1000000000) % 60;
    int minutes = (time_val / 60000000000) % 60;
    
    char *ptr = message;
    while (*ptr) ptr++;
    if (ptr - message < MAX_MSG_LENGTH - 10) {
        ptr[0] = ' ';
        ptr[1] = '[';
        ptr[2] = '0' + (minutes / 10);
        ptr[3] = '0' + (minutes % 10);
        ptr[4] = ':';
        ptr[5] = '0' + (seconds / 10);
        ptr[6] = '0' + (seconds % 10);
        ptr[7] = ']';
        ptr[8] = 0;
    }
}

