/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#)cmds.c	8.1 (Berkeley) 6/6/93
 * $FreeBSD: src/usr.bin/tip/tip/cmds.c,v 1.11.2.2 2000/07/01 12:24:23 ps Exp $
 */

#include "tipconf.h"
#include "tip.h"
#include "pathnames.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <libutil.h>
#include <stdio.h>
#include <unistd.h>

/*
 * tip
 *
 * miscellaneous commands
 */

int	quant[] = { 60, 60, 24 };

char	null = '\0';
char	*sep[] = { "second", "minute", "hour" };
static char *argv[10];		/* argument vector for take and put */

void		timeout(int);		/* timeout function called on alarm */
static void	stopsnd(int);		/* SIGINT handler during file transfers */
static void	intcopy();		/* interrupt routine for file transfers */

void suspend(char);
void genbrk(void);
void variable(void);
void finish(void);
void tipabort(char *);
void chdirectory(void);
void shell(void);
void cu_put(char);
void sendfile(char);
void pipefile(void);
void cu_take(char);
void getfl(char);

static int anyof(char *, char *);
static void tandem(char *);
static void prtime(char *, time_t);
static int args(char *, char **, int);
static void execute(char *);
static void send(char);
static void transmit(FILE *, char *, char *);
static void transfer(char *, int, char *);
static void xfer(char *, int, char *);

void
usedefchars (void)
{
#if HAVE_TERMIOS
	int cnt;
	struct termios ttermios;
	ttermios = ctermios;
	for (cnt = 0; cnt < NCCS; cnt++)
		ttermios.c_cc [cnt] = otermios.c_cc [cnt];
	tcsetattr (0, TCSANOW, &ttermios);
#else
	ioctl(0, TIOCSETC, &defchars);
#endif
}

void
usetchars (void)
{
#if HAVE_TERMIOS
	tcsetattr (0, TCSANOW, &ctermios);
#else
	ioctl(0, TIOCSETC, &tchars);
#endif
}

void
flush_remote (void)
{
#ifdef TIOCFLUSH
	int cmd = 0;
	ioctl (FD, TIOCFLUSH, &cmd);
#else
	struct sgttyb buf;
	ioctl (FD, TIOCGETP, &buf);	/* this does a */
	ioctl (FD, TIOCSETP, &buf);	/*   wflushtty */
#endif
}

/*
 * FTP - remote ==> local
 *  get a file from the remote host
 */
void
getfl(char c)
{
	char buf[256], *cp, *expand();

	putchar(c);
	/*
	 * get the UNIX receiving file's name
	 */
	if (prompt("Local file name? ", copyname, sizeof(copyname)))
		return;
	cp = expand(copyname);
	if ((sfd = creat(cp, 0666)) < 0) {
		printf("\r\n%s: cannot creat\r\n", copyname);
		return;
	}

	/*
	 * collect parameters
	 */
	if (prompt("List command for remote system? ", buf, sizeof(buf))) {
		unlink(copyname);
		return;
	}
	transfer(buf, sfd, value(EOFREAD));
}

/*
 * Cu-like take command
 */
void
cu_take(char cc)
{
	int fd, argc;
	char line[BUFSIZ], *expand(), *cp;

	if (prompt("[take] ", copyname, sizeof(copyname)))
		return;
	if ((argc = args(copyname, argv, sizeof(argv)/sizeof(argv[0]))) < 1 || argc > 2) {
		printf("usage: <take> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	cp = expand(argv[1]);
	if ((fd = creat(cp, 0666)) < 0) {
		printf("\r\n%s: cannot create\r\n", argv[1]);
		return;
	}
	(void)snprintf(line, sizeof(line), "cat %s ; echo \"\" ; echo ___tip_end_of_file_marker___", argv[0]);
	xfer(line, fd, "\n___tip_end_of_file_marker___\n");
}

static jmp_buf intbuf;

static void
xfer(char *buf, int fd, char *eofchars)
{
	int ct;
	char c, *match;
	int cnt, eof, v;
	time_t start;
	sig_t f;
	char r;
	FILE *ff;

	v = boolean(value(VERBOSE));

	if ((ff = fdopen (fd, "w")) == NULL) {
		warn("file open");
		return;
	}
	if ((cnt = number(value(FRAMESIZE))) != BUFSIZ)
		if (setvbuf(ff, NULL, _IOFBF, cnt) != 0) {
			warn("file allocation");
			(void)fclose(ff);
			return;
		}

	xpwrite(FD, buf, size(buf));
	quit = 0;
	kill(pid, SIGIOT);
	read(repdes[0], (char *)&ccc, 1);  /* Wait until read process stops */

	/*
	 * finish command
	 */
	r = '\r';
	xpwrite(FD, &r, 1);
	do
		read(FD, &c, 1);
	while ((c&0177) != '\n');

	usedefchars ();

	(void) setjmp(intbuf);
	f = signal(SIGINT, intcopy);
	start = time(0);
	match = eofchars;
	for (ct = 0; !quit;) {
		eof = read(FD, &c, 1) <= 0;
		c &= 0177;
		if (quit)
			continue;
		if (eof)
			break;
		if (c == 0)
			continue;	/* ignore nulls */
		if (c == '\r')
			continue;
		if (c != *match && match > eofchars) {
			char *p = eofchars;
			while (p < match) {
				if (*p == '\n'&& v)
					(void)printf("\r%d", ++ct);
				fputc(*p++, ff);
			}
			match = eofchars;
		}
		if (c == *match) {
			if (*++match == '\0')
				break;
		} else {
			if (c == '\n' && v)
				(void)printf("\r%d", ++ct);
			fputc(c, ff);
		}
	}
	if (v)
		prtime(" lines transferred in ", time(0)-start);
	usetchars ();
	write(fildes[1], (char *)&ccc, 1);
	signal(SIGINT, f);
	(void)fclose(ff);
}

/*
 * Bulk transfer routine --
 *  used by getfl(), cu_take(), and pipefile()
 */
static void
transfer(char *buf, int fd, char *eofchars)
{
	int ct;
	char c;
	int cnt, eof, v;
	time_t start;
	sig_t f;
	char r;
	FILE *ff;

	v = boolean(value(VERBOSE));

	if ((ff = fdopen (fd, "w")) == NULL) {
		warn("file open");
		return;
	}
	if ((cnt = number(value(FRAMESIZE))) != BUFSIZ)
		if (setvbuf(ff, NULL, _IOFBF, cnt) != 0) {
			warn("file allocation");
			(void)fclose(ff);
			return;
		}

	xpwrite(FD, buf, size(buf));
	quit = 0;
	kill(pid, SIGIOT);
	read(repdes[0], (char *)&ccc, 1);  /* Wait until read process stops */

	/*
	 * finish command
	 */
	r = '\r';
	xpwrite(FD, &r, 1);
	do
		read(FD, &c, 1);
	while ((c&0177) != '\n');
	usedefchars ();
	(void) setjmp(intbuf);
	f = signal(SIGINT, intcopy);
	start = time(0);
	for (ct = 0; !quit;) {
		eof = read(FD, &c, 1) <= 0;
		c &= 0177;
		if (quit)
			continue;
		if (eof || any(c, eofchars))
			break;
		if (c == 0)
			continue;	/* ignore nulls */
		if (c == '\r')
			continue;
		if (c == '\n' && v)
			printf("\r%d", ++ct);
		fputc(c, ff);
	}
	if (v)
		prtime(" lines transferred in ", time(0)-start);
	usetchars ();
	write(fildes[1], (char *)&ccc, 1);
	signal(SIGINT, f);
	(void)fclose(ff);
}

/*
 * FTP - remote ==> local process
 *   send remote input to local process via pipe
 */
void
pipefile(void)
{
	int cpid, pdes[2];
	char buf[256];
	int status, p;

	if (prompt("Local command? ", buf, sizeof(buf)))
		return;

	if (pipe(pdes)) {
		printf("can't establish pipe\r\n");
		return;
	}

	if ((cpid = fork()) < 0) {
		printf("can't fork!\r\n");
		return;
	} else if (cpid) {
		if (prompt("List command for remote system? ", buf, sizeof(buf))) {
			close(pdes[0]), close(pdes[1]);
			kill (cpid, SIGKILL);
		} else {
			close(pdes[0]);
			signal(SIGPIPE, intcopy);
			transfer(buf, pdes[1], value(EOFREAD));
			signal(SIGPIPE, SIG_DFL);
			while ((p = wait(&status)) > 0 && p != cpid)
				;
		}
	} else {
		int f;

		dup2(pdes[0], 0);
		close(pdes[0]);
		for (f = 3; f < 20; f++)
			close(f);
		execute(buf);
		printf("can't execl!\r\n");
		exit(0);
	}
}

/*
 * Interrupt service routine for FTP
 */
void
stopsnd(int __dummy)
{

	stop = 1;
	signal(SIGINT, SIG_IGN);
}

/*
 * FTP - local ==> remote
 *  send local file to remote host
 *  terminate transmission with pseudo EOF sequence
 */
void
sendfile(char cc)
{
	FILE *fd;
	char *fnamex;
	char *expand();

	putchar(cc);
	/*
	 * get file name
	 */
	if (prompt("Local file name? ", fname, sizeof(fname)))
		return;

	/*
	 * look up file
	 */
	fnamex = expand(fname);
	if ((fd = fopen(fnamex, "r")) == NULL) {
		printf("%s: cannot open\r\n", fname);
		return;
	}
	transmit(fd, value(EOFWRITE), NULL);
	if (!boolean(value(ECHOCHECK))) {
		flush_remote ();
	}
}

/*
 * Bulk transfer routine to remote host --
 *   used by sendfile() and cu_put()
 */
static void
transmit(FILE *fd, char *eofchars, char *command)
{
	char *pc, lastc;
	int c, ccount, lcount;
	time_t start_t, stop_t;
	sig_t f;

	kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	stop = 0;
	f = signal(SIGINT, stopsnd);
	usedefchars ();
	read(repdes[0], (char *)&ccc, 1);
	if (command != NULL) {
		for (pc = command; *pc; pc++)
			send(*pc);
		if (boolean(value(ECHOCHECK)))
			read(FD, (char *)&c, 1);	/* trailing \n */
		else {
			flush_remote ();
			sleep(5); /* wait for remote stty to take effect */
		}
	}
	lcount = 0;
	lastc = '\0';
	start_t = time(0);
	while (1) {
		ccount = 0;
		do {
			c = getc(fd);
			if (stop)
				goto out;
			if (c == EOF)
				goto out;
			if (c == 0177 && !boolean(value(RAWFTP)))
				continue;
			lastc = c;
			if (c < 040) {
				if (c == '\n') {
					if (!boolean(value(RAWFTP)))
						c = '\r';
				}
				else if (c == '\t') {
					if (!boolean(value(RAWFTP))) {
						if (boolean(value(TABEXPAND))) {
							send(' ');
							while ((++ccount % 8) != 0)
								send(' ');
							continue;
						}
					}
				} else
					if (!boolean(value(RAWFTP)))
						continue;
			}
			send(c);
		} while (c != '\r' && !boolean(value(RAWFTP)));
		if (boolean(value(VERBOSE)))
			printf("\r%d", ++lcount);
		if (boolean(value(ECHOCHECK))) {
			timedout = 0;
			alarm(number(value(ETIMEOUT)));
			do {	/* wait for prompt */
				read(FD, (char *)&c, 1);
				if (timedout || stop) {
					if (timedout)
						printf("\r\ntimed out at eol\r\n");
					alarm(0);
					goto out;
				}
			} while ((c&0177) != character(value(PROMPT)));
			alarm(0);
		}
	}
out:
	if (lastc != '\n' && !boolean(value(RAWFTP)))
		send('\r');
	for (pc = eofchars; pc && *pc; pc++)
		send(*pc);
	stop_t = time(0);
	fclose(fd);
	signal(SIGINT, f);
	if (boolean(value(VERBOSE)))
		if (boolean(value(RAWFTP)))
			prtime(" chars transferred in ", stop_t-start_t);
		else
			prtime(" lines transferred in ", stop_t-start_t);
	write(fildes[1], (char *)&ccc, 1);
	usetchars ();
}

/*
 * Cu-like put command
 */
void
cu_put(char cc)
{
	FILE *fd;
	char line[BUFSIZ];
	int argc;
	char *expand();
	char *copynamex;

	if (prompt("[put] ", copyname, sizeof(copyname)))
		return;
	if ((argc = args(copyname, argv, sizeof(argv)/sizeof(argv[0]))) < 1 || argc > 2) {
		printf("usage: <put> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	copynamex = expand(argv[0]);
	if ((fd = fopen(copynamex, "r")) == NULL) {
		printf("%s: cannot open\r\n", copynamex);
		return;
	}
	if (boolean(value(ECHOCHECK)))
		snprintf(line, sizeof(line), "cat>%s\r", argv[1]);
	else
		snprintf(line, sizeof(line), "stty -echo;cat>%s;stty echo\r", argv[1]);
	transmit(fd, "\04", line);
}


static int
nap(int msec)
{
	if (usleep(msec*1000) != 0) {
		fprintf ( stderr, "warning: ldelay or cdelay interrupted, "
			  "delay time cut short: %s\n",
			  strerror(errno) );
	}

	return 0;
}


/*
 * FTP - send single character
 *  wait for echo & handle timeout
 */
static void
send(char c)
{
	char cc;
	int retry = 0;

	cc = c;
	xpwrite(FD, &cc, 1);
	if (number(value(CDELAY)) > 0 && c != '\r')
		nap(number(value(CDELAY)));
	if (!boolean(value(ECHOCHECK))) {
		if (number(value(LDELAY)) > 0 && c == '\r')
			nap(number(value(LDELAY)));
		return;
	}
tryagain:
	timedout = 0;
	alarm(number(value(ETIMEOUT)));
	read(FD, &cc, 1);
	alarm(0);
	if (timedout) {
		printf("\r\ntimeout error (%s)\r\n", ctrl(c));
		if (retry++ > 3)
			return;
		xpwrite(FD, &null, 1); /* poke it */
		goto tryagain;
	}
}

void
timeout(int __dummy)
{
	signal(SIGALRM, timeout);
	timedout = 1;
}

/*
 * Stolen from consh() -- puts a remote file on the output of a local command.
 *	Identical to consh() except for where stdout goes.
 */
void
pipeout(int c)
{
	char buf[256];
	int cpid, status, p;
	time_t start;

	putchar(c);
	if (prompt("Local command? ", buf, sizeof(buf)))
		return;
	kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	usedefchars ();
	read(repdes[0], (char *)&ccc, 1);
	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
	} else {
		int i;

		dup2(FD, 1);
		for (i = 3; i < 20; i++)
			close(i);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		execute(buf);
		printf("can't find `%s'\r\n", buf);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		prtime("away for ", time(0)-start);
	write(fildes[1], (char *)&ccc, 1);
	usetchars ();
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
}

#if CONNECT

int
tiplink (char *cmd, unsigned int flags)
{
	int cpid, status, p;
	time_t start;

	if (flags & TL_SIGNAL_TIPOUT) {
		kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		usedefchars ();
		read(repdes[0], (char *)&ccc, 1);
	}

	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
	} else {
		int fd;

		dup2(FD, 0);
		dup2(3, 1);
		for (fd = 3; fd < 20; fd++)
			close (fd);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		execute (cmd);
		printf("can't find `%s'\r\n", cmd);
		exit(0);
	}

	if (flags & TL_VERBOSE && boolean(value(VERBOSE)))
		prtime("away for ", time(0)-start);

	if (flags & TL_SIGNAL_TIPOUT) {
		write(fildes[1], (char *)&ccc, 1);
		usetchars ();
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
	}

	return 0;
}

/*
 * Fork a program with:
 *  0 <-> remote tty in
 *  1 <-> remote tty out
 *  2 <-> local tty out
 */
int
consh(int c)
{
	char buf[256];
	putchar(c);
	if (prompt("Local command? ", buf, sizeof(buf)))
		return;
	tiplink (buf, TL_SIGNAL_TIPOUT | TL_VERBOSE);
	return 0;
}
#endif

/*
 * Escape to local shell
 */
void
shell(void)
{
	int shpid, status;
	char *cp;

	printf("[sh]\r\n");
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	unraw();
	if ((shpid = fork())) {
		while (shpid != wait(&status));
		raw();
		printf("\r\n!\r\n");
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		return;
	} else {
		signal(SIGQUIT, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		if ((cp = rindex(value(SHELL), '/')) == NULL)
			cp = value(SHELL);
		else
			cp++;
		shell_uid();
		execl(value(SHELL), cp, NULL);
		printf("\r\ncan't execl!\r\n");
		exit(1);
	}
}

/*
 * TIPIN portion of scripting
 *   initiate the conversation with TIPOUT
 */
void
setscript(void)
{
	char c;
	/*
	 * enable TIPOUT side for dialogue
	 */
	kill(pid, SIGEMT);
	if (boolean(value(SCRIPT)))
		write(fildes[1], value(RECORD), size(value(RECORD)));
	write(fildes[1], "\n", 1);
	/*
	 * wait for TIPOUT to finish
	 */
	read(repdes[0], &c, 1);
	if (c == 'n')
		printf("can't create %s\r\n", value(RECORD));
}

/*
 * Change current working directory of
 *   local portion of tip
 */
void
chdirectory(void)
{
	char dirname[PATH_MAX];
	char *cp = dirname;

	if (prompt("[cd] ", dirname, sizeof(dirname))) {
		if (stoprompt)
			return;
		cp = value(HOME);
	}
	if (chdir(cp) < 0)
		printf("%s: bad directory\r\n", cp);
	printf("!\r\n");
}

void
tipabort(char *msg)
{

	kill(pid, SIGTERM);
	disconnect(msg);
	if (msg != NULL)
		printf("\r\n%s", msg);
	printf("\r\n[EOT]\r\n");
	daemon_uid();
	(void)uu_unlock(uucplock);
	unraw();
	exit(0);
}

void
finish(void)
{
	char *abortmsg = NULL, *dismsg;

	if (LO != NULL && tiplink (LO, TL_SIGNAL_TIPOUT) != 0) {
		abortmsg = "logout failed";
	}

	if ((dismsg = value(DISCONNECT)) != NULL) {
		write(FD, dismsg, strlen(dismsg));
		sleep (2);
	}
	tipabort(abortmsg);
}

void
intcopy(void)
{
	raw();
	quit = 1;
	longjmp(intbuf, 1);
}

static void
execute(char *s)
{
	char *cp;

	if ((cp = rindex(value(SHELL), '/')) == NULL)
		cp = value(SHELL);
	else
		cp++;
	shell_uid();
	execl(value(SHELL), cp, "-c", s, NULL);
}

static int
args(char *buf, char **a, int num)
{
	char *p = buf, *start;
	char **parg = a;
	int n = 0;

	while (*p && n < num) {
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		start = p;
		if (*p)
			*parg = p;
		while (*p && (*p != ' ' && *p != '\t'))
			p++;
		if (p != start)
			parg++, n++;
		if (*p)
			*p++ = '\0';
	}
	return(n);
}

static void
prtime(char *s, time_t a)
{
	int i;
	int nums[3];

	for (i = 0; i < 3; i++) {
		nums[i] = (int)(a % quant[i]);
		a /= quant[i];
	}
	printf("%s", s);
	while (--i >= 0)
		if (nums[i] || (i == 0 && nums[1] == 0 && nums[2] == 0))
			printf("%d %s%c ", nums[i], sep[i],
				nums[i] == 1 ? '\0' : 's');
	printf("\r\n!\r\n");
}

void
variable(void)
{
	char	buf[256];

	if (prompt("[set] ", buf, sizeof(buf)))
		return;
	vlex(buf);
	if (vtable[BEAUTIFY].v_access&CHANGED) {
		vtable[BEAUTIFY].v_access &= ~CHANGED;
		kill(pid, SIGSYS);
	}
	if (vtable[SCRIPT].v_access&CHANGED) {
		vtable[SCRIPT].v_access &= ~CHANGED;
		setscript();
		/*
		 * So that "set record=blah script" doesn't
		 *  cause two transactions to occur.
		 */
		if (vtable[RECORD].v_access&CHANGED)
			vtable[RECORD].v_access &= ~CHANGED;
	}
	if (vtable[RECORD].v_access&CHANGED) {
		vtable[RECORD].v_access &= ~CHANGED;
		if (boolean(value(SCRIPT)))
			setscript();
	}
	if (vtable[TAND].v_access&CHANGED) {
		vtable[TAND].v_access &= ~CHANGED;
		if (boolean(value(TAND)))
			tandem("on");
		else
			tandem("off");
	}
 	if (vtable[LECHO].v_access&CHANGED) {
 		vtable[LECHO].v_access &= ~CHANGED;
 		HD = boolean(value(LECHO));
 	}
	if (vtable[PARITY].v_access&CHANGED) {
		vtable[PARITY].v_access &= ~CHANGED;
		setparity(value(PARITY));
	}
}

/*
 * Turn tandem mode on or off for remote tty.
 */
static void
tandem(char *option)
{
#if HAVE_TERMIOS
	struct termios ttermios;
	tcgetattr (FD, &ttermios);
	if (strcmp(option,"on") == 0) {
		ttermios.c_iflag |= IXOFF;
		ctermios.c_iflag |= IXOFF;
	}
	else {
		ttermios.c_iflag &= ~IXOFF;
		ctermios.c_iflag &= ~IXOFF;
	}
	tcsetattr (FD, TCSANOW, &ttermios);
	tcsetattr (0, TCSANOW, &ctermios);
#else /* HAVE_TERMIOS */
	struct sgttyb rmtty;

	ioctl(FD, TIOCGETP, &rmtty);
	if (strcmp(option,"on") == 0) {
		rmtty.sg_flags |= TANDEM;
		arg.sg_flags |= TANDEM;
	} else {
		rmtty.sg_flags &= ~TANDEM;
		arg.sg_flags &= ~TANDEM;
	}
	ioctl(FD, TIOCSETP, &rmtty);
	ioctl(0,  TIOCSETP, &arg);
#endif /* HAVE_TERMIOS */
}

/*
 * Send a break.
 */
void
genbrk(void)
{

	ioctl(FD, TIOCSBRK, NULL);
	sleep(1);
	ioctl(FD, TIOCCBRK, NULL);
}

/*
 * Suspend tip
 */
void
suspend(char c)
{

	unraw();
	kill(c == CTRL('y') ? getpid() : 0, SIGTSTP);
	raw();
}

/*
 *	expand a file name if it includes shell meta characters
 */

char *
expand(char *name)
{
	static char xname[BUFSIZ];
	char cmdbuf[BUFSIZ];
	int pid, l;
	char *cp, *Shell;
	int s, pivec[2] /*, (*sigint)()*/;

	if (!anyof(name, "~{[*?$`'\"\\"))
		return(name);
	/* sigint = signal(SIGINT, SIG_IGN); */
	if (pipe(pivec) < 0) {
		warn("pipe");
		/* signal(SIGINT, sigint) */
		return(name);
	}
	snprintf(cmdbuf, sizeof(cmdbuf), "echo %s", name);
	if ((pid = vfork()) == 0) {
		Shell = value(SHELL);
		if (Shell == NULL)
			Shell = _PATH_BSHELL;
		close(pivec[0]);
		close(1);
		dup(pivec[1]);
		close(pivec[1]);
		close(2);
		shell_uid();
		execl(Shell, Shell, "-c", cmdbuf, NULL);
		_exit(1);
	}
	if (pid == -1) {
		warn("fork");
		close(pivec[0]);
		close(pivec[1]);
		return(NULL);
	}
	close(pivec[1]);
	l = read(pivec[0], xname, BUFSIZ);
	close(pivec[0]);
	while (wait(&s) != pid);
		;
	s &= 0377;
	if (s != 0 && s != SIGPIPE) {
		fprintf(stderr, "\"Echo\" failed\n");
		return(NULL);
	}
	if (l < 0) {
		warn("read");
		return(NULL);
	}
	if (l == 0) {
		fprintf(stderr, "\"%s\": No match\n", name);
		return(NULL);
	}
	if (l == BUFSIZ) {
		fprintf(stderr, "Buffer overflow expanding \"%s\"\n", name);
		return(NULL);
	}
	xname[l] = 0;
	for (cp = &xname[l-1]; *cp == '\n' && cp > xname; cp--)
		;
	*++cp = '\0';
	return(xname);
}

/*
 * Are any of the characters in the two strings the same?
 */

static int
anyof(char *s1, char *s2)
{
	int c;

	while ((c = *s1++))
		if (any(c, s2))
			return(1);
	return(0);
}
