#include "zephyr-compat.h"
#include <zephyr/fs/fs.h>
#include <unistd.h>
#include <errno.h>

static struct tm gmtime_result;

// Only check for existence
int access(const char *path, int amode)
{
    struct fs_dirent buf;
    return fs_stat(path, &buf);
}

// From newlib, I found it's actually best to just never use isatty actually
/* int isatty(int fd)
{
  struct stat buf;

  if (fstat (fd, &buf) < 0) {
    errno = EBADF;
    return 0;
  }
  if (S_ISCHR (buf.st_mode))
    return 1;
  errno = ENOTTY;
  return 0;
} */

// Below functions from minimal libc

struct tm *gmtime(const time_t *timep)
{
    return gmtime_r(timep, &gmtime_result);
}

static void time_civil_from_days(time_t z,
				 struct tm *ZRESTRICT tp)
{
	tp->tm_wday = (z >= -4) ? ((z + 4) % 7) : ((z + 5) % 7 + 6);
	z += 719468;

	time_t era = ((z >= 0) ? z : (z - 146096)) / 146097;
	unsigned int doe = (z - era * (time_t)146097);
	unsigned int yoe = (doe - doe / 1460U + doe / 36524U - doe / 146096U)
		/ 365U;
	time_t y = (time_t)yoe + era * 400;
	unsigned int doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
	unsigned int mp = (5U * doy + 2U) / 153U;
	unsigned int d = doy - (153U * mp + 2U) / 5U + 1U;
	unsigned int m = mp + ((mp < 10) ? 3 : -9);

	tp->tm_year = y + (m <= 2) - 1900;
	tp->tm_mon = m - 1;
	tp->tm_mday = d;

	/* Everything above is explained on the referenced page, but
	 * doy is relative to --03-01 and we need it relative to
	 * --01-01.
	 *
	 * doy=306 corresponds to --01-01, doy=364 to --02-28, and
	 * doy=365 to --02-29.  So we can just subtract 306 to handle
	 * January and February.
	 *
	 * For doy<306 we have to add the number of days before
	 * --03-01, which is 59 in a common year and 60 in a leap
	 * year.  Note that the first year in the era is a leap year.
	 */
	if (doy >= 306U) {
		tp->tm_yday = doy - 306U;
	} else {
		tp->tm_yday = doy + 59U + (((yoe % 4U == 0U) && (yoe % 100U != 0U)) || (yoe == 0U));
	}
}

struct tm *gmtime_r(const time_t *ZRESTRICT timep, struct tm *ZRESTRICT result)
{
    time_t z = *timep;
	time_t days = (z >= 0 ? z : z - 86399) / 86400;
	unsigned int rem = z - days * 86400;

	*result = (struct tm){ 0 };

	time_civil_from_days(days, result);

	result->tm_hour = rem / 60U / 60U;
	rem -= result->tm_hour * 60 * 60;
	result->tm_min = rem / 60;
	result->tm_sec = rem - result->tm_min * 60;

	return result;
}