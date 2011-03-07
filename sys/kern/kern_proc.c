/*
 * (MPSAFE)
 *
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_proc.c	8.7 (Berkeley) 2/14/95
 * $FreeBSD: src/sys/kern/kern_proc.c,v 1.63.2.9 2003/05/08 07:47:16 kbyanc Exp $
 * $DragonFly: src/sys/kern/kern_proc.c,v 1.45 2008/06/12 23:25:02 dillon Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/filedesc.h>
#include <sys/tty.h>
#include <sys/dsched.h>
#include <sys/signalvar.h>
#include <sys/spinlock.h>
#include <vm/vm.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <sys/user.h>
#include <machine/smp.h>

#include <sys/refcount.h>
#include <sys/spinlock2.h>
#include <sys/mplock2.h>

static MALLOC_DEFINE(M_PGRP, "pgrp", "process group header");
MALLOC_DEFINE(M_SESSION, "session", "session header");
MALLOC_DEFINE(M_PROC, "proc", "Proc structures");
MALLOC_DEFINE(M_LWP, "lwp", "lwp structures");
MALLOC_DEFINE(M_SUBPROC, "subproc", "Proc sub-structures");

int ps_showallprocs = 1;
static int ps_showallthreads = 1;
SYSCTL_INT(_security, OID_AUTO, ps_showallprocs, CTLFLAG_RW,
    &ps_showallprocs, 0,
    "Unprivileged processes can see proccesses with different UID/GID");
SYSCTL_INT(_security, OID_AUTO, ps_showallthreads, CTLFLAG_RW,
    &ps_showallthreads, 0,
    "Unprivileged processes can see kernel threads");

static void pgdelete(struct pgrp *);
static void orphanpg(struct pgrp *pg);
static pid_t proc_getnewpid_locked(int random_offset);

/*
 * Other process lists
 */
struct pidhashhead *pidhashtbl;
u_long pidhash;
struct pgrphashhead *pgrphashtbl;
u_long pgrphash;
struct proclist allproc;
struct proclist zombproc;

/*
 * Random component to nextpid generation.  We mix in a random factor to make
 * it a little harder to predict.  We sanity check the modulus value to avoid
 * doing it in critical paths.  Don't let it be too small or we pointlessly
 * waste randomness entropy, and don't let it be impossibly large.  Using a
 * modulus that is too big causes a LOT more process table scans and slows
 * down fork processing as the pidchecked caching is defeated.
 */
static int randompid = 0;

/*
 * No requirements.
 */
static int
sysctl_kern_randompid(SYSCTL_HANDLER_ARGS)
{
	int error, pid;

	pid = randompid;
	error = sysctl_handle_int(oidp, &pid, 0, req);
	if (error || !req->newptr)
		return (error);
	if (pid < 0 || pid > PID_MAX - 100)     /* out of range */
		pid = PID_MAX - 100;
	else if (pid < 2)                       /* NOP */
		pid = 0;
	else if (pid < 100)                     /* Make it reasonable */
		pid = 100;
	randompid = pid;
	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, randompid, CTLTYPE_INT|CTLFLAG_RW,
	    0, 0, sysctl_kern_randompid, "I", "Random PID modulus");

/*
 * Initialize global process hashing structures.
 *
 * Called from the low level boot code only.
 */
void
procinit(void)
{
	LIST_INIT(&allproc);
	LIST_INIT(&zombproc);
	lwkt_init();
	pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);
	pgrphashtbl = hashinit(maxproc / 4, M_PROC, &pgrphash);
	uihashinit();
}

/*
 * Is p an inferior of the current process?
 *
 * No requirements.
 * The caller must hold proc_token if the caller wishes a stable result.
 */
int
inferior(struct proc *p)
{
	lwkt_gettoken(&proc_token);
	while (p != curproc) {
		if (p->p_pid == 0) {
			lwkt_reltoken(&proc_token);
			return (0);
		}
		p = p->p_pptr;
	}
	lwkt_reltoken(&proc_token);
	return (1);
}

/*
 * Locate a process by number.  The returned process will be referenced and
 * must be released with PRELE().
 *
 * No requirements.
 */
struct proc *
pfind(pid_t pid)
{
	struct proc *p;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, PIDHASH(pid), p_hash) {
		if (p->p_pid == pid) {
			PHOLD(p);
			lwkt_reltoken(&proc_token);
			return (p);
		}
	}
	lwkt_reltoken(&proc_token);
	return (NULL);
}

/*
 * Locate a process by number.  The returned process is NOT referenced.
 * The caller should hold proc_token if the caller wishes a stable result.
 *
 * No requirements.
 */
struct proc *
pfindn(pid_t pid)
{
	struct proc *p;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, PIDHASH(pid), p_hash) {
		if (p->p_pid == pid) {
			lwkt_reltoken(&proc_token);
			return (p);
		}
	}
	lwkt_reltoken(&proc_token);
	return (NULL);
}

void
pgref(struct pgrp *pgrp)
{
	refcount_acquire(&pgrp->pg_refs);
}

void
pgrel(struct pgrp *pgrp)
{
	if (refcount_release(&pgrp->pg_refs))
		pgdelete(pgrp);
}

/*
 * Locate a process group by number.  The returned process group will be
 * referenced w/pgref() and must be released with pgrel() (or assigned
 * somewhere if you wish to keep the reference).
 *
 * No requirements.
 */
struct pgrp *
pgfind(pid_t pgid)
{
	struct pgrp *pgrp;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(pgrp, PGRPHASH(pgid), pg_hash) {
		if (pgrp->pg_id == pgid) {
			refcount_acquire(&pgrp->pg_refs);
			lwkt_reltoken(&proc_token);
			return (pgrp);
		}
	}
	lwkt_reltoken(&proc_token);
	return (NULL);
}

/*
 * Move p to a new or existing process group (and session)
 *
 * No requirements.
 */
int
enterpgrp(struct proc *p, pid_t pgid, int mksess)
{
	struct pgrp *pgrp;
	struct pgrp *opgrp;
	int error;

	pgrp = pgfind(pgid);

	KASSERT(pgrp == NULL || !mksess,
		("enterpgrp: setsid into non-empty pgrp"));
	KASSERT(!SESS_LEADER(p),
		("enterpgrp: session leader attempted setpgrp"));

	if (pgrp == NULL) {
		pid_t savepid = p->p_pid;
		struct proc *np;
		/*
		 * new process group
		 */
		KASSERT(p->p_pid == pgid,
			("enterpgrp: new pgrp and pid != pgid"));
		if ((np = pfindn(savepid)) == NULL || np != p) {
			error = ESRCH;
			goto fatal;
		}
		MALLOC(pgrp, struct pgrp *, sizeof(struct pgrp),
		       M_PGRP, M_WAITOK);
		if (mksess) {
			struct session *sess;

			/*
			 * new session
			 */
			MALLOC(sess, struct session *, sizeof(struct session),
			       M_SESSION, M_WAITOK);
			sess->s_leader = p;
			sess->s_sid = p->p_pid;
			sess->s_count = 1;
			sess->s_ttyvp = NULL;
			sess->s_ttyp = NULL;
			bcopy(p->p_session->s_login, sess->s_login,
			      sizeof(sess->s_login));
			p->p_flag &= ~P_CONTROLT;
			pgrp->pg_session = sess;
			KASSERT(p == curproc,
				("enterpgrp: mksession and p != curproc"));
		} else {
			pgrp->pg_session = p->p_session;
			sess_hold(pgrp->pg_session);
		}
		pgrp->pg_id = pgid;
		LIST_INIT(&pgrp->pg_members);
		LIST_INSERT_HEAD(PGRPHASH(pgid), pgrp, pg_hash);
		pgrp->pg_jobc = 0;
		SLIST_INIT(&pgrp->pg_sigiolst);
		lwkt_token_init(&pgrp->pg_token, "pgrp_token");
		refcount_init(&pgrp->pg_refs, 1);
		lockinit(&pgrp->pg_lock, "pgwt", 0, 0);
	} else if (pgrp == p->p_pgrp) {
		pgrel(pgrp);
		goto done;
	} /* else pgfind() referenced the pgrp */

	/*
	 * Adjust eligibility of affected pgrps to participate in job control.
	 * Increment eligibility counts before decrementing, otherwise we
	 * could reach 0 spuriously during the first call.
	 */
	lwkt_gettoken(&pgrp->pg_token);
	lwkt_gettoken(&p->p_token);
	fixjobc(p, pgrp, 1);
	fixjobc(p, p->p_pgrp, 0);
	while ((opgrp = p->p_pgrp) != NULL) {
		opgrp = p->p_pgrp;
		lwkt_gettoken(&opgrp->pg_token);
		LIST_REMOVE(p, p_pglist);
		p->p_pgrp = NULL;
		lwkt_reltoken(&opgrp->pg_token);
		pgrel(opgrp);
	}
	p->p_pgrp = pgrp;
	LIST_INSERT_HEAD(&pgrp->pg_members, p, p_pglist);
	lwkt_reltoken(&p->p_token);
	lwkt_reltoken(&pgrp->pg_token);
done:
	error = 0;
fatal:
	return (error);
}

/*
 * Remove process from process group
 *
 * No requirements.
 */
int
leavepgrp(struct proc *p)
{
	struct pgrp *pg = p->p_pgrp;

	lwkt_gettoken(&p->p_token);
	pg = p->p_pgrp;
	if (pg) {
		pgref(pg);
		lwkt_gettoken(&pg->pg_token);
		if (p->p_pgrp == pg) {
			p->p_pgrp = NULL;
			LIST_REMOVE(p, p_pglist);
			pgrel(pg);
		}
		lwkt_reltoken(&pg->pg_token);
		lwkt_reltoken(&p->p_token);	/* avoid chaining on rel */
		pgrel(pg);
	} else {
		lwkt_reltoken(&p->p_token);
	}
	return (0);
}

/*
 * Delete a process group.  Must be called only after the last ref has been
 * released.
 */
static void
pgdelete(struct pgrp *pgrp)
{
	/*
	 * Reset any sigio structures pointing to us as a result of
	 * F_SETOWN with our pgid.
	 */
	funsetownlst(&pgrp->pg_sigiolst);

	if (pgrp->pg_session->s_ttyp != NULL &&
	    pgrp->pg_session->s_ttyp->t_pgrp == pgrp)
		pgrp->pg_session->s_ttyp->t_pgrp = NULL;
	LIST_REMOVE(pgrp, pg_hash);
	sess_rele(pgrp->pg_session);
	kfree(pgrp, M_PGRP);
}

/*
 * Adjust the ref count on a session structure.  When the ref count falls to
 * zero the tty is disassociated from the session and the session structure
 * is freed.  Note that tty assocation is not itself ref-counted.
 *
 * No requirements.
 */
void
sess_hold(struct session *sp)
{
	lwkt_gettoken(&tty_token);
	++sp->s_count;
	lwkt_reltoken(&tty_token);
}

/*
 * No requirements.
 */
void
sess_rele(struct session *sp)
{
	struct tty *tp;

	KKASSERT(sp->s_count > 0);
	lwkt_gettoken(&tty_token);
	if (--sp->s_count == 0) {
		if (sp->s_ttyp && sp->s_ttyp->t_session) {
#ifdef TTY_DO_FULL_CLOSE
			/* FULL CLOSE, see ttyclearsession() */
			KKASSERT(sp->s_ttyp->t_session == sp);
			sp->s_ttyp->t_session = NULL;
#else
			/* HALF CLOSE, see ttyclearsession() */
			if (sp->s_ttyp->t_session == sp)
				sp->s_ttyp->t_session = NULL;
#endif
		}
		if ((tp = sp->s_ttyp) != NULL) {
			sp->s_ttyp = NULL;
			ttyunhold(tp);
		}
		kfree(sp, M_SESSION);
	}
	lwkt_reltoken(&tty_token);
}

/*
 * Adjust pgrp jobc counters when specified process changes process group.
 * We count the number of processes in each process group that "qualify"
 * the group for terminal job control (those with a parent in a different
 * process group of the same session).  If that count reaches zero, the
 * process group becomes orphaned.  Check both the specified process'
 * process group and that of its children.
 * entering == 0 => p is leaving specified group.
 * entering == 1 => p is entering specified group.
 *
 * No requirements.
 */
void
fixjobc(struct proc *p, struct pgrp *pgrp, int entering)
{
	struct pgrp *hispgrp;
	struct session *mysession;
	struct proc *np;

	/*
	 * Check p's parent to see whether p qualifies its own process
	 * group; if so, adjust count for p's process group.
	 */
	lwkt_gettoken(&p->p_token);	/* p_children scan */
	lwkt_gettoken(&pgrp->pg_token);

	mysession = pgrp->pg_session;
	if ((hispgrp = p->p_pptr->p_pgrp) != pgrp &&
	    hispgrp->pg_session == mysession) {
		if (entering)
			pgrp->pg_jobc++;
		else if (--pgrp->pg_jobc == 0)
			orphanpg(pgrp);
	}

	/*
	 * Check this process' children to see whether they qualify
	 * their process groups; if so, adjust counts for children's
	 * process groups.
	 */
	LIST_FOREACH(np, &p->p_children, p_sibling) {
		PHOLD(np);
		lwkt_gettoken(&np->p_token);
		if ((hispgrp = np->p_pgrp) != pgrp &&
		    hispgrp->pg_session == mysession &&
		    np->p_stat != SZOMB) {
			pgref(hispgrp);
			lwkt_gettoken(&hispgrp->pg_token);
			if (entering)
				hispgrp->pg_jobc++;
			else if (--hispgrp->pg_jobc == 0)
				orphanpg(hispgrp);
			lwkt_reltoken(&hispgrp->pg_token);
			pgrel(hispgrp);
		}
		lwkt_reltoken(&np->p_token);
		PRELE(np);
	}
	KKASSERT(pgrp->pg_refs > 0);
	lwkt_reltoken(&pgrp->pg_token);
	lwkt_reltoken(&p->p_token);
}

/*
 * A process group has become orphaned;
 * if there are any stopped processes in the group,
 * hang-up all process in that group.
 *
 * The caller must hold pg_token.
 */
static void
orphanpg(struct pgrp *pg)
{
	struct proc *p;

	LIST_FOREACH(p, &pg->pg_members, p_pglist) {
		if (p->p_stat == SSTOP) {
			LIST_FOREACH(p, &pg->pg_members, p_pglist) {
				ksignal(p, SIGHUP);
				ksignal(p, SIGCONT);
			}
			return;
		}
	}
}

/*
 * Add a new process to the allproc list and the PID hash.  This
 * also assigns a pid to the new process.
 *
 * No requirements.
 */
void
proc_add_allproc(struct proc *p)
{
	int random_offset;

	if ((random_offset = randompid) != 0) {
		get_mplock();
		random_offset = karc4random() % random_offset;
		rel_mplock();
	}

	lwkt_gettoken(&proc_token);
	p->p_pid = proc_getnewpid_locked(random_offset);
	LIST_INSERT_HEAD(&allproc, p, p_list);
	LIST_INSERT_HEAD(PIDHASH(p->p_pid), p, p_hash);
	lwkt_reltoken(&proc_token);
}

/*
 * Calculate a new process pid.  This function is integrated into
 * proc_add_allproc() to guarentee that the new pid is not reused before
 * the new process can be added to the allproc list.
 *
 * The caller must hold proc_token.
 */
static
pid_t
proc_getnewpid_locked(int random_offset)
{
	static pid_t nextpid;
	static pid_t pidchecked;
	struct proc *p;

	/*
	 * Find an unused process ID.  We remember a range of unused IDs
	 * ready to use (from nextpid+1 through pidchecked-1).
	 */
	nextpid = nextpid + 1 + random_offset;
retry:
	/*
	 * If the process ID prototype has wrapped around,
	 * restart somewhat above 0, as the low-numbered procs
	 * tend to include daemons that don't exit.
	 */
	if (nextpid >= PID_MAX) {
		nextpid = nextpid % PID_MAX;
		if (nextpid < 100)
			nextpid += 100;
		pidchecked = 0;
	}
	if (nextpid >= pidchecked) {
		int doingzomb = 0;

		pidchecked = PID_MAX;

		/*
		 * Scan the active and zombie procs to check whether this pid
		 * is in use.  Remember the lowest pid that's greater
		 * than nextpid, so we can avoid checking for a while.
		 *
		 * NOTE: Processes in the midst of being forked may not
		 *	 yet have p_pgrp and p_pgrp->pg_session set up
		 *	 yet, so we have to check for NULL.
		 *
		 *	 Processes being torn down should be interlocked
		 *	 with proc_token prior to the clearing of their
		 *	 p_pgrp.
		 */
		p = LIST_FIRST(&allproc);
again:
		for (; p != NULL; p = LIST_NEXT(p, p_list)) {
			while (p->p_pid == nextpid ||
			    (p->p_pgrp && p->p_pgrp->pg_id == nextpid) ||
			    (p->p_pgrp && p->p_session &&
			     p->p_session->s_sid == nextpid)) {
				nextpid++;
				if (nextpid >= pidchecked)
					goto retry;
			}
			if (p->p_pid > nextpid && pidchecked > p->p_pid)
				pidchecked = p->p_pid;
			if (p->p_pgrp &&
			    p->p_pgrp->pg_id > nextpid &&
			    pidchecked > p->p_pgrp->pg_id) {
				pidchecked = p->p_pgrp->pg_id;
			}
			if (p->p_pgrp && p->p_session &&
			    p->p_session->s_sid > nextpid &&
			    pidchecked > p->p_session->s_sid) {
				pidchecked = p->p_session->s_sid;
			}
		}
		if (!doingzomb) {
			doingzomb = 1;
			p = LIST_FIRST(&zombproc);
			goto again;
		}
	}
	return(nextpid);
}

/*
 * Called from exit1 to remove a process from the allproc
 * list and move it to the zombie list.
 *
 * No requirements.
 */
void
proc_move_allproc_zombie(struct proc *p)
{
	lwkt_gettoken(&proc_token);
	while (p->p_lock) {
		tsleep(p, 0, "reap1", hz / 10);
	}
	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);
	LIST_REMOVE(p, p_hash);
	p->p_stat = SZOMB;
	lwkt_reltoken(&proc_token);
	dsched_exit_proc(p);
}

/*
 * This routine is called from kern_wait() and will remove the process
 * from the zombie list and the sibling list.  This routine will block
 * if someone has a lock on the proces (p_lock).
 *
 * No requirements.
 */
void
proc_remove_zombie(struct proc *p)
{
	lwkt_gettoken(&proc_token);
	while (p->p_lock) {
		tsleep(p, 0, "reap1", hz / 10);
	}
	LIST_REMOVE(p, p_list); /* off zombproc */
	LIST_REMOVE(p, p_sibling);
	lwkt_reltoken(&proc_token);
}

/*
 * Scan all processes on the allproc list.  The process is automatically
 * held for the callback.  A return value of -1 terminates the loop.
 *
 * No requirements.
 * The callback is made with the process held and proc_token held.
 */
void
allproc_scan(int (*callback)(struct proc *, void *), void *data)
{
	struct proc *p;
	int r;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, &allproc, p_list) {
		PHOLD(p);
		r = callback(p, data);
		PRELE(p);
		if (r < 0)
			break;
	}
	lwkt_reltoken(&proc_token);
}

/*
 * Scan all lwps of processes on the allproc list.  The lwp is automatically
 * held for the callback.  A return value of -1 terminates the loop.
 *
 * No requirements.
 * The callback is made with the proces and lwp both held, and proc_token held.
 */
void
alllwp_scan(int (*callback)(struct lwp *, void *), void *data)
{
	struct proc *p;
	struct lwp *lp;
	int r = 0;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, &allproc, p_list) {
		PHOLD(p);
		FOREACH_LWP_IN_PROC(lp, p) {
			LWPHOLD(lp);
			r = callback(lp, data);
			LWPRELE(lp);
		}
		PRELE(p);
		if (r < 0)
			break;
	}
	lwkt_reltoken(&proc_token);
}

/*
 * Scan all processes on the zombproc list.  The process is automatically
 * held for the callback.  A return value of -1 terminates the loop.
 *
 * No requirements.
 * The callback is made with the proces held and proc_token held.
 */
void
zombproc_scan(int (*callback)(struct proc *, void *), void *data)
{
	struct proc *p;
	int r;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, &zombproc, p_list) {
		PHOLD(p);
		r = callback(p, data);
		PRELE(p);
		if (r < 0)
			break;
	}
	lwkt_reltoken(&proc_token);
}

#include "opt_ddb.h"
#ifdef DDB
#include <ddb/ddb.h>

/*
 * Debugging only
 */
DB_SHOW_COMMAND(pgrpdump, pgrpdump)
{
	struct pgrp *pgrp;
	struct proc *p;
	int i;

	for (i = 0; i <= pgrphash; i++) {
		if (!LIST_EMPTY(&pgrphashtbl[i])) {
			kprintf("\tindx %d\n", i);
			LIST_FOREACH(pgrp, &pgrphashtbl[i], pg_hash) {
				kprintf(
			"\tpgrp %p, pgid %ld, sess %p, sesscnt %d, mem %p\n",
				    (void *)pgrp, (long)pgrp->pg_id,
				    (void *)pgrp->pg_session,
				    pgrp->pg_session->s_count,
				    (void *)LIST_FIRST(&pgrp->pg_members));
				LIST_FOREACH(p, &pgrp->pg_members, p_pglist) {
					kprintf("\t\tpid %ld addr %p pgrp %p\n", 
					    (long)p->p_pid, (void *)p,
					    (void *)p->p_pgrp);
				}
			}
		}
	}
}
#endif /* DDB */

/*
 * Locate a process on the zombie list.  Return a process or NULL.
 * The returned process will be referenced and the caller must release
 * it with PRELE().
 *
 * No other requirements.
 */
struct proc *
zpfind(pid_t pid)
{
	struct proc *p;

	lwkt_gettoken(&proc_token);
	LIST_FOREACH(p, &zombproc, p_list) {
		if (p->p_pid == pid) {
			PHOLD(p);
			lwkt_reltoken(&proc_token);
			return (p);
		}
	}
	lwkt_reltoken(&proc_token);
	return (NULL);
}

/*
 * The caller must hold proc_token.
 */
static int
sysctl_out_proc(struct proc *p, struct sysctl_req *req, int flags)
{
	struct kinfo_proc ki;
	struct lwp *lp;
	int skp = 0, had_output = 0;
	int error;

	bzero(&ki, sizeof(ki));
	fill_kinfo_proc(p, &ki);
	if ((flags & KERN_PROC_FLAG_LWP) == 0)
		skp = 1;
	error = 0;
	FOREACH_LWP_IN_PROC(lp, p) {
		LWPHOLD(lp);
		fill_kinfo_lwp(lp, &ki.kp_lwp);
		had_output = 1;
		error = SYSCTL_OUT(req, &ki, sizeof(ki));
		LWPRELE(lp);
		if (error)
			break;
		if (skp)
			break;
	}
	/* We need to output at least the proc, even if there is no lwp. */
	if (had_output == 0) {
		error = SYSCTL_OUT(req, &ki, sizeof(ki));
	}
	return (error);
}

/*
 * The caller must hold proc_token.
 */
static int
sysctl_out_proc_kthread(struct thread *td, struct sysctl_req *req, int flags)
{
	struct kinfo_proc ki;
	int error;

	fill_kinfo_proc_kthread(td, &ki);
	error = SYSCTL_OUT(req, &ki, sizeof(ki));
	if (error)
		return error;
	return(0);
}

/*
 * No requirements.
 */
static int
sysctl_kern_proc(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	int oid = oidp->oid_number;
	u_int namelen = arg2;
	struct proc *p;
	struct proclist *plist;
	struct thread *td;
	int doingzomb, flags = 0;
	int error = 0;
	int n;
	int origcpu;
	struct ucred *cr1 = curproc->p_ucred;

	flags = oid & KERN_PROC_FLAGMASK;
	oid &= ~KERN_PROC_FLAGMASK;

	if ((oid == KERN_PROC_ALL && namelen != 0) ||
	    (oid != KERN_PROC_ALL && namelen != 1))
		return (EINVAL);

	lwkt_gettoken(&proc_token);
	if (oid == KERN_PROC_PID) {
		p = pfindn((pid_t)name[0]);
		if (p == NULL)
			goto post_threads;
		if (!PRISON_CHECK(cr1, p->p_ucred))
			goto post_threads;
		PHOLD(p);
		error = sysctl_out_proc(p, req, flags);
		PRELE(p);
		goto post_threads;
	}

	if (!req->oldptr) {
		/* overestimate by 5 procs */
		error = SYSCTL_OUT(req, 0, sizeof (struct kinfo_proc) * 5);
		if (error)
			goto post_threads;
	}
	for (doingzomb = 0; doingzomb <= 1; doingzomb++) {
		if (doingzomb)
			plist = &zombproc;
		else
			plist = &allproc;
		LIST_FOREACH(p, plist, p_list) {
			/*
			 * Show a user only their processes.
			 */
			if ((!ps_showallprocs) && p_trespass(cr1, p->p_ucred))
				continue;
			/*
			 * Skip embryonic processes.
			 */
			if (p->p_stat == SIDL)
				continue;
			/*
			 * TODO - make more efficient (see notes below).
			 * do by session.
			 */
			switch (oid) {
			case KERN_PROC_PGRP:
				/* could do this by traversing pgrp */
				if (p->p_pgrp == NULL || 
				    p->p_pgrp->pg_id != (pid_t)name[0])
					continue;
				break;

			case KERN_PROC_TTY:
				if ((p->p_flag & P_CONTROLT) == 0 ||
				    p->p_session == NULL ||
				    p->p_session->s_ttyp == NULL ||
				    dev2udev(p->p_session->s_ttyp->t_dev) != 
					(udev_t)name[0])
					continue;
				break;

			case KERN_PROC_UID:
				if (p->p_ucred == NULL || 
				    p->p_ucred->cr_uid != (uid_t)name[0])
					continue;
				break;

			case KERN_PROC_RUID:
				if (p->p_ucred == NULL || 
				    p->p_ucred->cr_ruid != (uid_t)name[0])
					continue;
				break;
			}

			if (!PRISON_CHECK(cr1, p->p_ucred))
				continue;
			PHOLD(p);
			error = sysctl_out_proc(p, req, flags);
			PRELE(p);
			if (error)
				goto post_threads;
		}
	}

	/*
	 * Iterate over all active cpus and scan their thread list.  Start
	 * with the next logical cpu and end with our original cpu.  We
	 * migrate our own thread to each target cpu in order to safely scan
	 * its thread list.  In the last loop we migrate back to our original
	 * cpu.
	 */
	origcpu = mycpu->gd_cpuid;
	if (!ps_showallthreads || jailed(cr1))
		goto post_threads;

	for (n = 1; n <= ncpus; ++n) {
		globaldata_t rgd;
		int nid;

		nid = (origcpu + n) % ncpus;
		if ((smp_active_mask & CPUMASK(nid)) == 0)
			continue;
		rgd = globaldata_find(nid);
		lwkt_setcpu_self(rgd);

		TAILQ_FOREACH(td, &mycpu->gd_tdallq, td_allq) {
			if (td->td_proc)
				continue;
			switch (oid) {
			case KERN_PROC_PGRP:
			case KERN_PROC_TTY:
			case KERN_PROC_UID:
			case KERN_PROC_RUID:
				continue;
			default:
				break;
			}
			lwkt_hold(td);
			error = sysctl_out_proc_kthread(td, req, doingzomb);
			lwkt_rele(td);
			if (error)
				goto post_threads;
		}
	}
post_threads:
	lwkt_reltoken(&proc_token);
	return (error);
}

/*
 * This sysctl allows a process to retrieve the argument list or process
 * title for another process without groping around in the address space
 * of the other process.  It also allow a process to set its own "process 
 * title to a string of its own choice.
 *
 * No requirements.
 */
static int
sysctl_kern_proc_args(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	struct pargs *opa;
	struct pargs *pa;
	int error = 0;
	struct ucred *cr1 = curproc->p_ucred;

	if (namelen != 1) 
		return (EINVAL);

	p = pfindn((pid_t)name[0]);
	if (p == NULL)
		goto done2;
	lwkt_gettoken(&p->p_token);
	PHOLD(p);

	if ((!ps_argsopen) && p_trespass(cr1, p->p_ucred))
		goto done;

	if (req->newptr && curproc != p) {
		error = EPERM;
		goto done;
	}
	if (req->oldptr && p->p_args != NULL) {
		error = SYSCTL_OUT(req, p->p_args->ar_args,
				   p->p_args->ar_length);
	}
	if (req->newptr == NULL)
		goto done;

	if (req->newlen + sizeof(struct pargs) > ps_arg_cache_limit) {
		goto done;
	}

	pa = kmalloc(sizeof(struct pargs) + req->newlen, M_PARGS, M_WAITOK);
	refcount_init(&pa->ar_ref, 1);
	pa->ar_length = req->newlen;
	error = SYSCTL_IN(req, pa->ar_args, req->newlen);
	if (error) {
		kfree(pa, M_PARGS);
		goto done;
	}

	opa = p->p_args;
	p->p_args = pa;

	KKASSERT(opa->ar_ref > 0);
	if (refcount_release(&opa->ar_ref)) {
		kfree(opa, M_PARGS);
	}
done:
	PRELE(p);
	lwkt_reltoken(&p->p_token);
done2:
	return (error);
}

static int
sysctl_kern_proc_cwd(SYSCTL_HANDLER_ARGS)
{
	int *name = (int*) arg1;
	u_int namelen = arg2;
	struct proc *p;
	int error = 0;
	char *fullpath, *freepath;
	struct ucred *cr1 = curproc->p_ucred;

	if (namelen != 1) 
		return (EINVAL);

	lwkt_gettoken(&proc_token);
	p = pfindn((pid_t)name[0]);
	if (p == NULL)
		goto done;

	/*
	 * If we are not allowed to see other args, we certainly shouldn't
	 * get the cwd either. Also check the usual trespassing.
	 */
	if ((!ps_argsopen) && p_trespass(cr1, p->p_ucred))
		goto done;

	PHOLD(p);
	if (req->oldptr && p->p_fd != NULL) {
		error = cache_fullpath(p, &p->p_fd->fd_ncdir,
		    &fullpath, &freepath, 0);
		if (error)
			goto done;
		error = SYSCTL_OUT(req, fullpath, strlen(fullpath) + 1);
		kfree(freepath, M_TEMP);
	}

	PRELE(p);

done:
	lwkt_reltoken(&proc_token);
	return (error);
}

SYSCTL_NODE(_kern, KERN_PROC, proc, CTLFLAG_RD,  0, "Process table");

SYSCTL_PROC(_kern_proc, KERN_PROC_ALL, all, CTLFLAG_RD|CTLTYPE_STRUCT,
	0, 0, sysctl_kern_proc, "S,proc", "Return entire process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_PGRP, pgrp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_TTY, tty, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_UID, uid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_RUID, ruid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_PID, pid, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_ALL | KERN_PROC_FLAG_LWP), all_lwp, CTLFLAG_RD,
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_PGRP | KERN_PROC_FLAG_LWP), pgrp_lwp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_TTY | KERN_PROC_FLAG_LWP), tty_lwp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_UID | KERN_PROC_FLAG_LWP), uid_lwp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_RUID | KERN_PROC_FLAG_LWP), ruid_lwp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, (KERN_PROC_PID | KERN_PROC_FLAG_LWP), pid_lwp, CTLFLAG_RD, 
	sysctl_kern_proc, "Process table");

SYSCTL_NODE(_kern_proc, KERN_PROC_ARGS, args, CTLFLAG_RW | CTLFLAG_ANYBODY,
	sysctl_kern_proc_args, "Process argument list");

SYSCTL_NODE(_kern_proc, KERN_PROC_CWD, cwd, CTLFLAG_RD | CTLFLAG_ANYBODY,
	sysctl_kern_proc_cwd, "Process argument list");
