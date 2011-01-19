/*
 * Copyright (c) 2009 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Alex Hornung <ahornung@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "namespace.h"
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <paths.h>
#include <errno.h>
#include <machine/stdint.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "reentrant.h"
#include "un-namespace.h"

#include "libc_private.h"

#define TTYNAME_DEVFS_COMPAT 1

static char ptsname_buf[sizeof(_PATH_DEV) + NAME_MAX];

static once_t		ptsname_init_once = ONCE_INITIALIZER;
static thread_key_t	ptsname_key;
static int		ptsname_keycreated = 0;

static int
__isptmaster(int fd)
{
	int error;

	error = _ioctl(fd, TIOCISPTMASTER);
	if ((error) && (errno != EBADF))
		errno = EINVAL;

	return error;
}

static void
ptsname_keycreate(void)
{
	ptsname_keycreated = (thr_keycreate(&ptsname_key, free) == 0);
}

char *
ptsname(int fd)
{
	int	error;
	size_t used;
	char	*buf;

	error = __isptmaster(fd);
	if (error)
		return (NULL);

	if (thr_main() != 0)
		buf = ptsname_buf;
	else {
		if (thr_once(&ptsname_init_once, ptsname_keycreate) != 0 ||
		    !ptsname_keycreated)
			return (NULL);
		if ((buf = thr_getspecific(ptsname_key)) == NULL) {
			if ((buf = malloc(sizeof ptsname_buf)) == NULL)
				return (NULL);
			if (thr_setspecific(ptsname_key, buf) != 0) {
				free(buf);
				return (NULL);
			}
		}
	}

	strcpy(buf, "/dev/");
	used = strlen(buf);

	if (((error = fdevname_r(fd, buf+used, sizeof(ptsname_buf)-used))) != 0) {
		errno = error;
		return (NULL);
	}

	buf[used+2] = 's';

	return (buf);
}

int
posix_openpt(int oflag)
{
	return _open("/dev/ptmx", oflag);
}

int
unlockpt(int fd)
{
	return __isptmaster(fd);
}

int
grantpt(int fd)
{
	return __isptmaster(fd);
}
