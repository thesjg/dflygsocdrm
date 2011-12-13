/*
 * Copyright (c) 2011 François Tigeot <ftigeot@wolfpond.org>
 * All rights reserved.
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

#include <sys/stat.h>
#include <sys/mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <fts.h>
#include <inttypes.h>

static void usage(int);
static int get_dirsize(char *);
static int get_fslist(void);

static void
usage(int retcode)
{
	fprintf(stderr, "usage: vquota check directory\n");
	fprintf(stderr, "       vquota lsfs\n");
	exit(retcode);
}

static int
get_dirsize(char* dirname)
{
	FTS		*fts;
	FTSENT		*p;
	char*		fts_args[2];
	uint64_t	size_of_files = 0;
	int		retval = 0;

	/* TODO: check directory name sanity */
	fts_args[0] = dirname;
	fts_args[1] = NULL;

	if ((fts = fts_open(fts_args, FTS_PHYSICAL, NULL)) == NULL)
		err(1, "fts_open() failed");

	while ((p = fts_read(fts)) != NULL) {
		switch (p->fts_info) {
		/* directories, ignore them */
		case FTS_D:
		case FTS_DC:
		case FTS_DP:
			break;
		/* read errors, warn, continue and flag */
		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:
			warnx("%s: %s", p->fts_path, strerror(p->fts_errno));
			retval = 1;
			break;
		default:
			size_of_files += p->fts_statp->st_size;
		}
	}
	fts_close(fts);

	printf("%"PRIu64"\n", size_of_files);
	return retval;
}

/* print a list of filesystems with accounting enabled */
static int get_fslist(void) {
	struct statfs *mntbufp;
	int nloc, i;

	/* read mount table from kernel */
	nloc = getmntinfo(&mntbufp, MNT_NOWAIT|MNT_LOCAL);
	if (nloc <= 0) {
		perror("getmntinfo");
		exit(1);
	}

	/* iterate mounted filesystems */
	for (i=0; i<nloc; i++) {
	    /* vfs accounting enabled on this one ? */
	    if (mntbufp[i].f_flags & MNT_ACCOUNTING)
		printf("%s on %s\n", mntbufp[i].f_mntfromname,
						mntbufp[i].f_mntonname);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		usage(1);
	
	if (strcmp(argv[1], "check") == 0) {
		if (argc < 3)
			usage(1);
		return get_dirsize(argv[2]);
	}
	if (strcmp(argv[1], "lsfs") == 0) {
		return get_fslist();
	}

	return(0);
}
