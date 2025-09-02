#ifndef _WALLPAPER_MODULE_H_
#define _WALLPAPER_MODULE_H_

#define LOCKSCREEN_WALLPAPER_PATH "/data/system/users/0/wallpaper_lock"
#define HOMESCREEN_WALLPAPER_PATH "/data/system/users/0/wallpaper"
#define WALLPAPER_INFO_FILE "/data/system/users/0/wallpaper_info.xml"

#define WALLPAPER_TARGET_LOCKSCREEN 0
#define WALLPAPER_TARGET_HOMESCREEN 1
#define WALLPAPER_TARGET_BOTH 2

int change_lockscreen_wallpaper_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup);
int change_homescreen_wallpaper_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup);
int change_both_wallpapers_baremetal(const unsigned char *image_data, size_t image_size, int width, int height, int backup);
int restore_wallpaper_baremetal(int target);
void force_refresh_direct();

#endif