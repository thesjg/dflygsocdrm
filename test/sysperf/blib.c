/*
 * BLIB.C
 *
 * Simple benchmarking library
 *
 * $DragonFly: src/test/sysperf/blib.c,v 1.6 2007/08/21 19:23:46 corecode Exp $
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static struct timeval tv1;
static struct timeval tv2;
static long long last_us;

void
start_timing(void)
{
    gettimeofday(&tv1, NULL);
}

int
stop_timing(long long count, const char *ctl, ...)
{
    long long us;
    va_list va;

    gettimeofday(&tv2, NULL);
    us = (tv2.tv_usec - tv1.tv_usec) + (tv2.tv_sec - tv1.tv_sec) * 1000000LL;
    last_us = us;
    if (ctl == NULL) 	/* dummy call to pre-cache */
	return(us > 1000000);

    va_start(va, ctl);
    vfprintf(stderr, ctl, va);
    va_end(va);

    fprintf(stderr, " %6.3fs %lld loops = %6.3fuS/loop\n",
	(double)us / 1000000.0,
	count,
	(double)us / (double)count
    );

    tv1 = tv2;

    return(0);
}

int
stop_timing2(long long count, long long us, const char *ctl, ...)
{
    va_list va;

    va_start(va, ctl);
    vfprintf(stderr, ctl, va);
    va_end(va);

    fprintf(stderr, " %6.3fs %lld loops = %6.3fnS/loop\n",
	(double)us / 1000000.0,
	count,
	(double)us * 1000.0 / (double)count
    );
    return(0);
}

long long
get_timing(void)
{
    return (last_us);
}

void
nop(void)
{
}
