/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
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
 * 
 * $DragonFly: src/usr.bin/undo/undo.c,v 1.1 2008/06/01 02:03:10 dillon Exp $
 */
/*
 * UNDO - retrieve an older version of a file.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <vfs/hammer/hammer_disk.h>
#include <vfs/hammer/hammer_ioctl.h>

enum undo_type { TYPE_FILE, TYPE_DIFF, TYPE_RDIFF, TYPE_HISTORY };

static void doiterate(const char *orig_filename, const char *outFileName,
		   const char *outFilePostfix, int mult, enum undo_type type);
static void dogenerate(const char *filename, const char *outFileName,
		   const char *outFilePostfix,
		   int mult, int idx, enum undo_type type,
		   hammer_tid_t ts1, hammer_tid_t ts2);
static hammer_tid_t find_recent(const char *filename);
static hammer_tid_t output_history(const char *filename, int fd, FILE *fp,
		   hammer_tid_t **tid_ary, int *tid_num);
static hammer_tid_t parse_delta_time(const char *timeStr);
static void runcmd(int fd, const char *cmd, ...);
static char *timestamp(hammer_tid_t tid);
static void usage(void);

static int VerboseOpt;

int
main(int ac, char **av)
{
	const char *outFileName = NULL;
	const char *outFilePostfix = NULL;
	enum { CMD_DUMP, CMD_ITERATEALL } cmd;
	enum undo_type type;
	hammer_tid_t ts1 = 0;
	hammer_tid_t ts2 = 0;
	int c;
	int mult;

	cmd = CMD_DUMP;
	type = TYPE_FILE;

	while ((c = getopt(ac, av, "dDhiuvo:t:")) != -1) {
		switch(c) {
		case 'd':
			if (type != TYPE_FILE)
				usage();
			type = TYPE_DIFF;
			break;
		case 'D':
			if (type != TYPE_FILE)
				usage();
			type = TYPE_RDIFF;
			break;
		case 'i':
			if (type != TYPE_FILE)
				usage();
			type = TYPE_HISTORY;
			break;
		case 'h':
			cmd = CMD_ITERATEALL;
			break;
		case 'u':
			outFilePostfix = ".undo";
			break;
		case 'v':
			++VerboseOpt;
			break;
		case 'o':
			outFileName = optarg;
			break;
		case 't':
			if (ts1 && ts2)
				usage();
			else if (ts1 == 0)
				ts1 = parse_delta_time(optarg);
			else
				ts2 = parse_delta_time(optarg);
			break;
		default:
			usage();
			/* NOT REACHED */
			break;
		}
	}

	/*
	 * Option validation
	 */
	if (outFileName && outFilePostfix) {
		fprintf(stderr, "The -o option may not be combined with -u\n");
		usage();
	}

	ac -= optind;
	av += optind;
	mult = (ac > 1);

	if (ac == 0)
		usage();

	/*
	 * Validate the output template, if specified.
	 */
	if (outFileName && mult) {
		const char *ptr = outFileName;
		int didStr = 0;

		while ((ptr = strchr(ptr, '%')) != NULL) {
			if (ptr[1] == 's') {
				if (didStr) {
					fprintf(stderr, "Malformed output "
							"template\n");
					usage();
				}
				didStr = 1;
				++ptr;
			} else if (ptr[1] != '%') {
				fprintf(stderr, "Malformed output template\n");
				usage();
			} else {
				ptr += 2;
			}
		}
	}

	while (ac) {
		switch(cmd) {
		case CMD_DUMP:
			dogenerate(*av, outFileName, outFilePostfix,
				   mult, -1, type,
				   ts1, ts2);
			break;
		case CMD_ITERATEALL:
			doiterate(*av, outFileName, outFilePostfix,
				  mult, type);
			break;
		}
		++av;
		--ac;
	}
	return(0);
}

/*
 * Iterate through a file's history
 */
static
void
doiterate(const char *orig_filename, const char *outFileName,
	   const char *outFilePostfix, int mult, enum undo_type type)
{
	hammer_tid_t *tid_ary = NULL;
	hammer_tid_t ts1;
	const char *use_filename;
	char *path = NULL;
	int tid_num = 0;
	int i;
	int fd;

	use_filename = orig_filename;
	if ((fd = open(orig_filename, O_RDONLY)) < 0) {
		ts1 = find_recent(orig_filename);
		if (ts1) {
			asprintf(&path, "%s@@0x%016llx", orig_filename, ts1);
			use_filename = path;
		}
	}

	if ((fd = open(use_filename, O_RDONLY)) >= 0) {
		printf("%s: ITERATE ENTIRE HISTORY\n", orig_filename);
		output_history(NULL, fd, NULL, &tid_ary, &tid_num);
		close(fd);

		for (i = 0; i < tid_num; ++i) {
			if (i && tid_ary[i] == tid_ary[i-1])
				continue;

			if (i == tid_num - 1) {
				dogenerate(orig_filename,
					   outFileName, outFilePostfix,
					   mult, i, type,
					   tid_ary[i], HAMMER_MAX_TID);
			} else {
				dogenerate(orig_filename,
					   outFileName, outFilePostfix,
					   mult, i, type,
					   tid_ary[i], tid_ary[i+1]);
			}
		}

	} else {
		printf("%s: ITERATE ENTIRE HISTORY: %s\n",
			orig_filename, strerror(errno));
	}
	if (path)
		free(path);
}

/*
 * Generate output for a file as-of ts1 (ts1 may be 0!), if diffing then
 * through ts2.
 */
static
void
dogenerate(const char *filename, const char *outFileName,
	   const char *outFilePostfix,
	   int mult, int idx, enum undo_type type,
	   hammer_tid_t ts1, hammer_tid_t ts2)
{
	struct stat st;
	const char *elm;
	char *ipath1 = NULL;
	char *ipath2 = NULL;
	FILE *fi;
	FILE *fp; 
	char *buf;
	char *path;
	int n;

	buf = malloc(8192);

	/*
	 * Open the input file.  If ts1 is 0 try to locate the most recent
	 * version of the file prior to the current version.
	 */
	if (ts1 == 0)
		ts1 = find_recent(filename);
	asprintf(&ipath1, "%s@@0x%016llx", filename, ts1);
	if (lstat(ipath1, &st) < 0) {
		if (VerboseOpt) {
			fprintf(stderr, "Cannot locate src/historical "
					"idx=%d %s\n",
				idx, ipath1);
		}
		goto done;
	}

	if (ts2 == 0) {
		asprintf(&ipath2, "%s", filename);
	} else {
		asprintf(&ipath2, "%s@@0x%015llx", filename, ts2);
	}
	if (lstat(ipath2, &st) < 0) {
		if (VerboseOpt) {
			if (ts2) {
				fprintf(stderr, "Cannot locate tgt/historical "
						"idx=%d %s\n",
					idx, ipath2);
			} else if (VerboseOpt > 1) {
				fprintf(stderr, "Cannot locate %s\n", filename);
			}
		}
		ipath2 = strdup("/dev/null");
	}

	/*
	 * elm is the last component of the input file name
	 */
	if ((elm = strrchr(filename, '/')) != NULL)
		++elm;
	else
		elm = filename;

	/*
	 * Where do we stuff our output?
	 */
	if (outFileName) {
		if (mult) {
			asprintf(&path, outFileName, elm);
			fp = fopen(path, "w");
			if (fp == NULL) {
				perror(path);
				exit(1);
			}
			free(path);
		} else {
			fp = fopen(outFileName, "w");
			if (fp == NULL) {
				perror(outFileName);
				exit(1);
			}
		}
	} else if (outFilePostfix) {
		if (idx >= 0) {
			asprintf(&path, "%s%s.%04d", filename,
				 outFilePostfix, idx);
		} else {
			asprintf(&path, "%s%s", filename, outFilePostfix);
		}
		fp = fopen(path, "w");
		if (fp == NULL) {
			perror(path);
			exit(1);
		}
		free(path);
	} else {
		if (mult && type == TYPE_FILE) {
			if (idx >= 0) {
				printf("\n>>> %s %04d 0x%016llx %s\n\n",
				       filename, idx, ts1, timestamp(ts1));
			} else {
				printf("\n>>> %s ---- 0x%016llx %s\n\n",
				       filename, ts1, timestamp(ts1));
			}
		} else if (idx >= 0 && type == TYPE_FILE) {
			printf("\n>>> %s %04d 0x%016llx %s\n\n", 
			       filename, idx, ts1, timestamp(ts1));
		}
		fp = stdout;
	}

	switch(type) {
	case TYPE_FILE:
		if ((fi = fopen(ipath1, "r")) != NULL) {
			while ((n = fread(buf, 1, 8192, fi)) > 0)
				fwrite(buf, 1, n, fp);
			fclose(fi);
		}
		break;
	case TYPE_DIFF:
		printf("diff -u %s %s\n", ipath1, ipath2);
		fflush(stdout);
		runcmd(fileno(fp), "/usr/bin/diff", "diff", "-u", ipath1, ipath2, NULL);
		break;
	case TYPE_RDIFF:
		printf("diff -u %s %s\n", ipath2, ipath1);
		fflush(stdout);
		runcmd(fileno(fp), "/usr/bin/diff", "diff", "-u", ipath2, ipath1, NULL);
		break;
	case TYPE_HISTORY:
		if ((fi = fopen(ipath1, "r")) != NULL) {
			output_history(filename, fileno(fi), fp, NULL, NULL);
			fclose(fi);
		}
		break;
	}

	if (fp != stdout)
		fclose(fp);
done:
	free(buf);
}

/*
 * Try to find a recent version of the file.
 *
 * XXX if file cannot be found
 */
static hammer_tid_t
find_recent(const char *filename)
{
	hammer_tid_t *tid_ary = NULL;
	int tid_num = 0;
	hammer_tid_t tid;
	char *dirname;
	char *path;
	int fd;
	int i;

	if ((fd = open(filename, O_RDONLY)) >= 0) {
		tid = output_history(NULL, fd, NULL, NULL, NULL);
		close(fd);
		return(tid);
	}

	/*
	 * If the object does not exist acquire the history of its
	 * directory and then try accessing the object at each TID.
	 */
	if (strrchr(filename, '/')) {
		dirname = strdup(filename);
		*strrchr(dirname, '/') = 0;
	} else {
		dirname = strdup(".");
	}

	tid = 0;
	if ((fd = open(dirname, O_RDONLY)) >= 0) {
		output_history(NULL, fd, NULL, &tid_ary, &tid_num);
		close(fd);
		free(dirname);

		for (i = tid_num - 1; i >= 0; --i) {
			asprintf(&path, "%s@@0x%016llx", filename, tid_ary[i]);
			if ((fd = open(path, O_RDONLY)) >= 0) {
				tid = output_history(NULL, fd, NULL, NULL, NULL);
				close(fd);
				free(path);
				break;
			}
			free(path);
		}
	}
	return(tid);
}

/*
 * Collect all the transaction ids representing changes made to the
 * file, sort, and output (weeding out duplicates).  If fp is NULL
 * we do not output anything and simply return the most recent TID we
 * can find.
 */
static int
tid_cmp(const void *arg1, const void *arg2)
{
	const hammer_tid_t *tid1 = arg1;
	const hammer_tid_t *tid2 = arg2;

	if (*tid1 < *tid2)
		return(-1);
	if (*tid1 > *tid2)
		return(1);
	return(0);
}

static hammer_tid_t
output_history(const char *filename, int fd, FILE *fp,
		hammer_tid_t **tid_aryp, int *tid_nump)
{
	struct hammer_ioc_history hist;
	char datestr[64];
	struct tm *tp;
	time_t t;
	int tid_max = 32;
	int tid_num = 0;
	int i;
	hammer_tid_t *tid_ary = malloc(tid_max * sizeof(*tid_ary));
	hammer_tid_t tid;

	bzero(&hist, sizeof(hist));
	hist.beg_tid = HAMMER_MIN_TID;
	hist.end_tid = HAMMER_MAX_TID;
	hist.head.flags |= HAMMER_IOC_HISTORY_ATKEY;
	hist.key = 0;
	hist.nxt_key = HAMMER_MAX_KEY;

	tid = 0;

	if (ioctl(fd, HAMMERIOC_GETHISTORY, &hist) < 0) {
		if (filename)
			printf("%s: %s\n", filename, strerror(errno));
		goto done;
	}
	if (filename)
		printf("%s: objid=0x%016llx\n", filename, hist.obj_id);
	for (;;) {
		if (tid_num + hist.count >= tid_max) {
			tid_max = (tid_max * 3 / 2) + hist.count;
			tid_ary = realloc(tid_ary, tid_max * sizeof(*tid_ary));
		}
		for (i = 0; i < hist.count; ++i) {
			tid_ary[tid_num++] = hist.tid_ary[i];
		}
		if (hist.head.flags & HAMMER_IOC_HISTORY_EOF)
			break;
		if (hist.head.flags & HAMMER_IOC_HISTORY_NEXT_KEY) {
			hist.key = hist.nxt_key;
			hist.nxt_key = HAMMER_MAX_KEY;
		}
		if (hist.head.flags & HAMMER_IOC_HISTORY_NEXT_TID) 
			hist.beg_tid = hist.nxt_tid;
		if (ioctl(fd, HAMMERIOC_GETHISTORY, &hist) < 0) {
			if (filename)
				printf("%s: %s\n", filename, strerror(errno));
			break;
		}
	}
	qsort(tid_ary, tid_num, sizeof(*tid_ary), tid_cmp);
	if (tid_num == 0)
		goto done;
	for (i = 0; fp && i < tid_num; ++i) {
		if (i && tid_ary[i] == tid_ary[i-1])
			continue;
		t = (time_t)(tid_ary[i] / 1000000000);
		tp = localtime(&t);
		strftime(datestr, sizeof(datestr), "%d-%m-%Y %H:%M:%S", tp);
		printf("\t0x%016llx %s\n", tid_ary[i], datestr);
	}
	if (tid_num > 1)
		tid = tid_ary[tid_num-2];
done:
	if (tid_aryp) {
		*tid_aryp = tid_ary;
		*tid_nump = tid_num;
	} else {
		free(tid_ary);
	}
	return(tid);
}

static
hammer_tid_t
parse_delta_time(const char *timeStr)
{
	hammer_tid_t tid;
	char *ptr;

	if (timeStr[0] == '0' && (timeStr[1] == 'x' || timeStr[1] == 'X')) {
		tid = strtoull(timeStr, NULL, 0);
	} else {
		tid = strtol(timeStr, &ptr, 0);

		switch(*ptr) {
		case 'd':
			tid *= 24;
			/* fall through */
		case 'h':
			tid *= 60;
			/* fall through */
		case 'm':
			tid *= 60;
			/* fall through */
		case 's':
			break;
		default:
			usage();
		}
		tid = time(NULL) - tid;
		tid *= 1000000000;
	}
	return(tid);
}

static void
runcmd(int fd, const char *cmd, ...)
{
	va_list va;
	pid_t pid;
	char **av;
	int ac;
	int i;

	va_start(va, cmd);
	for (ac = 0; va_arg(va, void *) != NULL; ++ac)
		;
	va_end(va);

	av = malloc((ac + 1) * sizeof(char *));
	va_start(va, cmd);
	for (i = 0; i < ac; ++i)
		av[i] = va_arg(va, char *);
	va_end(va);
	av[i] = NULL;

	if ((pid = fork()) < 0) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		if (fd != 1) {
			dup2(fd, 1);
			close(fd);
		}
		execv(cmd, av);
		_exit(1);
	} else {
		while (waitpid(pid, NULL, 0) != pid)
			;
	}
	free(av);
}

/*
 * Convert tid to timestamp.
 */
static char *
timestamp(hammer_tid_t tid)
{
	static char timebuf[64];
	time_t t = (time_t)(tid / 1000000000);
	struct tm *tp;

	tp = localtime(&t);
	strftime(timebuf, sizeof(timebuf), "%d-%m-%Y %H:%M:%S", tp);
	return(timebuf);
}

static void
usage(void)
{
	fprintf(stderr, "undo [-dDhiuv] [-t n{s,m,h,d}] [-t n...] "
			"file1....fileN\n");
	fprintf(stderr, "    -d       Forward diff\n"
			"    -D       Reverse diff\n"
			"    -i       Dump history transaction ids\n"
			"    -h       Iterate all historical segments\n"
			"    -u       Generate .undo files\n"
			"    -v       Verbose\n"
			"    -t spec  Retrieve as of n secs,mins,etc ago\n"
			"             (a second one to diff two versions)\n"
			"             (a 0x TID may also be specified)\n");
	exit(1);
}
