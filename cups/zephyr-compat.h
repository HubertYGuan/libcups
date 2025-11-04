#ifndef _CUPS_ZEPHYR_COMPAT_H
#define _CUPS_ZEPHYR_COMPAT_H
#include <zephyr/sys/timeutil.h>
#include <zephyr/toolchain.h>
#include <time.h>

#define getuid() 0 // User is always "root"
#define timegm timeutil_timegm
#define X_OK 0
#define R_OK 0
#define W_OK 0
#define WCOREDUMP(status) 	((status) & 0x80)
#ifdef __cplusplus
extern "C" {
#endif
int access(const char *path, int amode);
int isatty (int fd); // Do not use
struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *ZRESTRICT timep, struct tm *ZRESTRICT result);

#ifdef __cplusplus
}
#endif
#endif // !_CUPS_ZEPHYR_COMPAT_H