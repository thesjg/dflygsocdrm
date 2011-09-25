/*
 * Copryight 1997 Sean Eric Fagan
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
 *	This product includes software developed by Sean Eric Fagan
 * 4. Neither the name of the author may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $FreeBSD: src/usr.bin/truss/main.c,v 1.15.2.3 2002/05/16 23:41:23 peter Exp $
 */

/*
 * The main module for truss.  Suprisingly simple, but, then, the other
 * files handle the bulk of the work.  And, of course, the kernel has to
 * do a lot of the work :).
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/pioctl.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "truss.h"
#include "extern.h"

/*
 * These should really be parameterized -- I don't like having globals,
 * but this is the easiest way, right now, to deal with them.
 */

int Procfd;

static inline void
usage(void)
{
  fprintf(stderr, "%s\n%s\n",
	"usage: truss [-S] [-o file] -p pid",
	"       truss [-S] [-o file] command [args]");
  exit(1);
}

struct ex_types {
  const char *type;
  void (*enter_syscall)(struct trussinfo *, int);
  int (*exit_syscall)(struct trussinfo *, int);
} ex_types[] = {
#ifdef __i386__
  { "DragonFly ELF32", i386_syscall_entry, i386_syscall_exit },
  { "FreeBSD ELF32", i386_syscall_entry, i386_syscall_exit },
  { "Linux ELF32", i386_linux_syscall_entry, i386_linux_syscall_exit },
#endif
#ifdef __x86_64__
  { "DragonFly ELF64", x86_64_syscall_entry, x86_64_syscall_exit },
  { "FreeBSD ELF64", x86_64_syscall_entry, x86_64_syscall_exit },
#endif
  { 0, 0, 0 },
};

/*
 * Set the execution type.  This is called after every exec, and when
 * a process is first monitored.  The procfs pseudo-file "etype" has
 * the execution module type -- see /proc/curproc/etype for an example.
 */

static struct ex_types *
set_etype(struct trussinfo *trussinfo) {
  struct ex_types *funcs;
  char *etype;
  char progt[32];
  int fd;

  asprintf(&etype, "%s/%d/etype", procfs_path, trussinfo->pid);
  if (etype == NULL)
    err(1, "Out of memory");
  if ((fd = open(etype, O_RDONLY)) == -1) {
    strcpy(progt, "FreeBSD a.out");
  } else {
    int len = read(fd, progt, sizeof(progt));
    progt[len-1] = '\0';
    close(fd);
  }
  free(etype);

  for (funcs = ex_types; funcs->type; funcs++)
    if (!strcmp(funcs->type, progt))
      break;

  if (funcs->type == NULL) {
    funcs = &ex_types[0];
    warn("Execution type %s is not supported -- using %s\n",
      progt, funcs->type);
  }
  return funcs;
}

int
main(int ac, char **av) {
  int c, i, mntsize;
  char **command;
  struct procfs_status pfs;
  struct ex_types *funcs;
  struct statfs *mntbuf;
  int in_exec = 0;
  char *fname = NULL;
  int sigexit = 0;
  struct trussinfo *trussinfo;

  /* Initialize the trussinfo struct */
  trussinfo = (struct trussinfo *)malloc(sizeof(struct trussinfo));
  if (trussinfo == NULL)
	  errx(1, "malloc() failed");
  bzero(trussinfo, sizeof(struct trussinfo));
  trussinfo->outfile = stderr;

  /* Check where procfs is mounted if it is mounted */
  if ((mntsize = getmntinfo(&mntbuf, MNT_NOWAIT)) == 0)
	  err(1, "getmntinfo");
  for (i = 0; i < mntsize; i++) {
	  if (strcasecmp(mntbuf[i].f_mntfromname, "procfs") == 0) {
		  strlcpy(procfs_path, mntbuf[i].f_mntonname, sizeof(procfs_path));
		  have_procfs = 1;
		  break;
	  }
  }
  if (!have_procfs) {
	  errno = 2;
	  err(1, "You must have a mounted procfs to use truss");
  }

  while ((c = getopt(ac, av, "p:o:S")) != -1) {
    switch (c) {
    case 'p':	/* specified pid */
      trussinfo->pid = atoi(optarg);
      if (trussinfo->pid == getpid()) {
	      /* make sure truss doesn't trace itself */
	      fprintf(stderr, "truss: attempt to self trace: %d\n", trussinfo->pid);
	      exit(2);
      }
      break;
    case 'o':	/* Specified output file */
      fname = optarg;
      break;
    case 'S':	/* Don't trace signals */ 
      trussinfo->flags |= NOSIGS;
      break;
    default:
      usage();
    }
  }

  ac -= optind; av += optind;
  if ((trussinfo->pid == 0 && ac == 0) || (trussinfo->pid != 0 && ac != 0))
    usage();

  if (fname != NULL) { /* Use output file */
    if ((trussinfo->outfile = fopen(fname, "w")) == NULL)
      errx(1, "cannot open %s", fname);
  }

  /*
   * If truss starts the process itself, it will ignore some signals --
   * they should be passed off to the process, which may or may not
   * exit.  If, however, we are examining an already-running process,
   * then we restore the event mask on these same signals.
   */

  if (trussinfo->pid == 0) {	/* Start a command ourselves */
    command = av;
    trussinfo->pid = setup_and_wait(command);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
  } else {
    signal(SIGINT, restore_proc);
    signal(SIGTERM, restore_proc);
    signal(SIGQUIT, restore_proc);
  }


  /*
   * At this point, if we started the process, it is stopped waiting to
   * be woken up, either in exit() or in execve().
   */

  Procfd = start_tracing(
      trussinfo->pid, S_EXEC | S_SCE | S_SCX | S_CORE | S_EXIT |
		     ((trussinfo->flags & NOSIGS) ? 0 : S_SIG));
  if (Procfd == -1)
    return 0;

  pfs.why = 0;

  funcs = set_etype(trussinfo);
  /*
   * At this point, it's a simple loop, waiting for the process to
   * stop, finding out why, printing out why, and then continuing it.
   * All of the grunt work is done in the support routines.
   */

  do {
    int val = 0;

    if (ioctl(Procfd, PIOCWAIT, &pfs) == -1)
      warn("PIOCWAIT top of loop");
    else {
      switch(i = pfs.why) {
      case S_SCE:
	funcs->enter_syscall(trussinfo, pfs.val);
	break;
      case S_SCX:
	/*
	 * This is so we don't get two messages for an exec -- one
	 * for the S_EXEC, and one for the syscall exit.  It also,
	 * conveniently, ensures that the first message printed out
	 * isn't the return-from-syscall used to create the process.
	 */

	if (in_exec) {
	  in_exec = 0;
	  break;
	}
	funcs->exit_syscall(trussinfo, pfs.val);
	break;
      case S_SIG:
	fprintf(trussinfo->outfile, "SIGNAL %lu\n", pfs.val);
	sigexit = pfs.val;
	break;
      case S_EXIT:
	fprintf (trussinfo->outfile, "process exit, rval = %lu\n", pfs.val);
	break;
      case S_EXEC:
	funcs = set_etype(trussinfo);
	in_exec = 1;
	break;
      default:
	fprintf (trussinfo->outfile, "Process stopped because of:  %d\n", i);
	break;
      }
    }
    if (ioctl(Procfd, PIOCCONT, val) == -1) {
      if (kill(trussinfo->pid, 0) == -1 && errno == ESRCH)
	break;
      else
	warn("PIOCCONT");
    }
  } while (pfs.why != S_EXIT);
  fflush(trussinfo->outfile);
  if (sigexit) {
    if (sigexit == SIGQUIT)
      exit(sigexit);
    (void) signal(sigexit, SIG_DFL);
    (void) kill(getpid(), sigexit);
  }
  return 0;
}
