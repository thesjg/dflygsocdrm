/*-
 * Copyright (c) 2004, The DragonFly Project.  All rights reserved.
 * Copyright (c) 1998, Peter Wemm <peter@netplex.com.au>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/usr.bin/objformat/objformat.c,v 1.6 1998/10/24 02:01:30 jdp Exp $
 */

#include <sys/param.h>

#include <err.h>
#include <objformat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CCVER_DEFAULT
#define CCVER_DEFAULT "gcc44"
#endif

#ifndef BINUTILSVER_DEFAULT
#define	BINUTILSVER_DEFAULT "binutils221"
#endif

#ifndef OBJFORMAT_PATH_DEFAULT
#define OBJFORMAT_PATH_DEFAULT ""
#endif

enum cmd_type { OBJFORMAT, COMPILER, BINUTILS };

struct command {
	const char *cmd;
	enum cmd_type type;
};

static struct command commands[] = {
	{"CC",		COMPILER},
	{"c++",		COMPILER},
	{"cc",		COMPILER},
	{"cpp",		COMPILER},
	{"g++",		COMPILER},
	{"gcc",		COMPILER},
	{"gcov",	COMPILER},
	{"addr2line",	BINUTILS},
	{"ar",		BINUTILS},
	{"as",		BINUTILS},
	{"c++filt",	BINUTILS},
	{"elfedit",	BINUTILS},
	{"gprof",       BINUTILS},
	{"ld",		BINUTILS},
	{"nm",		BINUTILS},
	{"objcopy",	BINUTILS},
	{"objdump",	BINUTILS},
	{"ranlib",	BINUTILS},
	{"readelf",	BINUTILS},
	{"size",	BINUTILS},
	{"strings",	BINUTILS},
	{"strip",	BINUTILS},
	{"objformat",	OBJFORMAT},
	{"",		-1}
};

int
main(int argc, char **argv)
{
	struct command *cmds;
	char objformat[32];
	char *path, *chunk;
	char *cmd, *newcmd = NULL;
	const char *objformat_path;
	const char *ccver;
	const char *buver;
	const char *env_value = NULL;
	const char *base_path = NULL;
	int use_objformat = 0;

	if (getobjformat(objformat, sizeof objformat, &argc, argv) == -1)
		errx(1, "Invalid object format");

	/*
	 * Get the last path element of the program name being executed
	 */
	cmd = strrchr(argv[0], '/');
	if (cmd != NULL)
		cmd++;
	else
		cmd = argv[0];

	for (cmds = commands; cmds < &commands[NELEM(commands) - 1]; ++cmds) {
		if (strcmp(cmd, cmds->cmd) == 0)
			break;
	}

	if ((ccver = getenv("CCVER")) == NULL || ccver[0] == 0)
		ccver = CCVER_DEFAULT;
	if ((buver = getenv("BINUTILSVER")) == NULL) {
		buver = BINUTILSVER_DEFAULT;
	}

	if (cmds) {
		switch (cmds->type) {
		case COMPILER:
			base_path = "/usr/libexec";
			use_objformat = 0;
			env_value = ccver;
			break;
		case BINUTILS:
			base_path = "/usr/libexec";
			use_objformat = 1;
			env_value = buver;
			break;
		case OBJFORMAT:
			break;
		default:
			errx(1, "unknown command type");
			break;
		}
	}

	/*
	 * The objformat command itself doesn't need another exec
	 */
	if (cmds->type == OBJFORMAT) {
		if (argc != 1) {
			fprintf(stderr, "Usage: objformat\n");
			exit(1);
		}

		printf("%s\n", objformat);
		exit(0);
	}

	/*
	 * make buildworld glue and CCVER overrides.
	 */
	objformat_path = getenv("OBJFORMAT_PATH");
	if (objformat_path == NULL)
		objformat_path = OBJFORMAT_PATH_DEFAULT;

again:
	path = strdup(objformat_path);

	if (setenv("OBJFORMAT", objformat, 1) == -1)
		err(1, "setenv: cannot set OBJFORMAT=%s", objformat);

	/*
	 * objformat_path could be sequence of colon-separated paths.
	 */
	while ((chunk = strsep(&path, ":")) != NULL) {
		if (newcmd != NULL) {
			free(newcmd);
			newcmd = NULL;
		}
		if (use_objformat) {
			asprintf(&newcmd, "%s%s/%s/%s/%s",
				chunk, base_path, env_value, objformat, cmd);
		} else {
			asprintf(&newcmd, "%s%s/%s/%s",
				chunk, base_path, env_value, cmd);
		}
		if (newcmd == NULL)
			err(1, "cannot allocate memory");

		argv[0] = newcmd;
		execv(newcmd, argv);
	}

	/*
	 * Fallback:  if we're searching for a compiler, but didn't
	 * find any, try again using the custom compiler driver.
	 */
	if (cmds && cmds->type == COMPILER &&
	    strcmp(env_value, "custom") != 0) {
		env_value = "custom";
		goto again;
	}

	if (use_objformat) {
		err(1, "in path [%s]%s/%s/%s/%s",
			objformat_path, base_path, env_value, objformat, cmd);
	} else {
		err(1, "in path [%s]%s/%s/%s",
			objformat_path, base_path, env_value, cmd);
	}
}
