/*-
 * Copyright (C) 1994, David Greenman
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the University of Utah, and William Jolitz.
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
 *	from: @(#)trap.c	7.4 (Berkeley) 5/13/91
 * $FreeBSD: src/sys/i386/i386/trap.c,v 1.147.2.11 2003/02/27 19:09:59 luoqi Exp $
 * $DragonFly: src/sys/platform/vkernel/i386/trap.c,v 1.35 2008/09/09 04:06:19 dillon Exp $
 */

/*
 * 386 Trap and System call handling
 */

#include "use_isa.h"
#include "use_npx.h"

#include "opt_ddb.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pioctl.h>
#include <sys/kernel.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/signal2.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/uio.h>
#include <sys/vmmeter.h>
#include <sys/malloc.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/ktr.h>
#include <sys/upcall.h>
#include <sys/vkernel.h>
#include <sys/sysproto.h>
#include <sys/sysunion.h>
#include <sys/vmspace.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>

#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/smp.h>
#include <machine/tss.h>
#include <machine/globaldata.h>

#include <machine/vm86.h>

#include <ddb/ddb.h>

#include <sys/msgport2.h>
#include <sys/thread2.h>
#include <sys/mplock2.h>

#ifdef SMP

#define MAKEMPSAFE(have_mplock)			\
	if (have_mplock == 0) {			\
		get_mplock();			\
		have_mplock = 1;		\
	}

#else

#define MAKEMPSAFE(have_mplock)

#endif

int (*pmath_emulate) (struct trapframe *);

static int trap_pfault (struct trapframe *, int, vm_offset_t);
static void trap_fatal (struct trapframe *, int, vm_offset_t);
void dblfault_handler (void);

#if 0
extern inthand_t IDTVEC(syscall);
#endif

#define MAX_TRAP_MSG		28
static char *trap_msg[] = {
	"",					/*  0 unused */
	"privileged instruction fault",		/*  1 T_PRIVINFLT */
	"",					/*  2 unused */
	"breakpoint instruction fault",		/*  3 T_BPTFLT */
	"",					/*  4 unused */
	"",					/*  5 unused */
	"arithmetic trap",			/*  6 T_ARITHTRAP */
	"system forced exception",		/*  7 T_ASTFLT */
	"",					/*  8 unused */
	"general protection fault",		/*  9 T_PROTFLT */
	"trace trap",				/* 10 T_TRCTRAP */
	"",					/* 11 unused */
	"page fault",				/* 12 T_PAGEFLT */
	"",					/* 13 unused */
	"alignment fault",			/* 14 T_ALIGNFLT */
	"",					/* 15 unused */
	"",					/* 16 unused */
	"",					/* 17 unused */
	"integer divide fault",			/* 18 T_DIVIDE */
	"non-maskable interrupt trap",		/* 19 T_NMI */
	"overflow trap",			/* 20 T_OFLOW */
	"FPU bounds check fault",		/* 21 T_BOUND */
	"FPU device not available",		/* 22 T_DNA */
	"double fault",				/* 23 T_DOUBLEFLT */
	"FPU operand fetch fault",		/* 24 T_FPOPFLT */
	"invalid TSS fault",			/* 25 T_TSSFLT */
	"segment not present fault",		/* 26 T_SEGNPFLT */
	"stack fault",				/* 27 T_STKFLT */
	"machine check trap",			/* 28 T_MCHK */
};

#ifdef DDB
static int ddb_on_nmi = 1;
SYSCTL_INT(_machdep, OID_AUTO, ddb_on_nmi, CTLFLAG_RW,
	&ddb_on_nmi, 0, "Go to DDB on NMI");
#endif
static int panic_on_nmi = 1;
SYSCTL_INT(_machdep, OID_AUTO, panic_on_nmi, CTLFLAG_RW,
	&panic_on_nmi, 0, "Panic on NMI");
static int fast_release;
SYSCTL_INT(_machdep, OID_AUTO, fast_release, CTLFLAG_RW,
	&fast_release, 0, "Passive Release was optimal");
static int slow_release;
SYSCTL_INT(_machdep, OID_AUTO, slow_release, CTLFLAG_RW,
	&slow_release, 0, "Passive Release was nonoptimal");

MALLOC_DEFINE(M_SYSMSG, "sysmsg", "sysmsg structure");
extern int max_sysmsg;

/*
 * Passively intercepts the thread switch function to increase
 * the thread priority from a user priority to a kernel priority, reducing
 * syscall and trap overhead for the case where no switch occurs.
 *
 * Synchronizes td_ucred with p_ucred.  This is used by system calls,
 * signal handling, faults, AST traps, and anything else that enters the
 * kernel from userland and provides the kernel with a stable read-only
 * copy of the process ucred.
 */
static __inline void
userenter(struct thread *curtd, struct proc *curp)
{
	struct ucred *ocred;
	struct ucred *ncred;

	curtd->td_release = lwkt_passive_release;

	if (curtd->td_ucred != curp->p_ucred) {
		ncred = crhold(curp->p_ucred);
		ocred = curtd->td_ucred;
		curtd->td_ucred = ncred;
		if (ocred)
			crfree(ocred);
	}
}

/*
 * Handle signals, upcalls, profiling, and other AST's and/or tasks that
 * must be completed before we can return to or try to return to userland.
 *
 * Note that td_sticks is a 64 bit quantity, but there's no point doing 64
 * arithmatic on the delta calculation so the absolute tick values are
 * truncated to an integer.
 */
static void
userret(struct lwp *lp, struct trapframe *frame, int sticks)
{
	struct proc *p = lp->lwp_proc;
	int sig;

	/*
	 * Charge system time if profiling.  Note: times are in microseconds.
	 * This may do a copyout and block, so do it first even though it
	 * means some system time will be charged as user time.
	 */
	if (p->p_flags & P_PROFIL) {
		addupc_task(p, frame->tf_eip, 
			(u_int)((int)lp->lwp_thread->td_sticks - sticks));
	}

recheck:
	/*
	 * If the jungle wants us dead, so be it.
	 */
	if (lp->lwp_mpflags & LWP_MP_WEXIT) {
		lwkt_gettoken(&p->p_token);
		lwp_exit(0);
		lwkt_reltoken(&p->p_token);	/* NOT REACHED */
	}

	/*
	 * Block here if we are in a stopped state.
	 */
	if (p->p_stat == SSTOP) {
		lwkt_gettoken(&p->p_token);
		tstop();
		lwkt_reltoken(&p->p_token);
		goto recheck;
	}

	/*
	 * Post any pending upcalls.  If running a virtual kernel be sure
	 * to restore the virtual kernel's vmspace before posting the upcall.
	 */
	if (p->p_flags & (P_SIGVTALRM | P_SIGPROF | P_UPCALLPEND)) {
		lwkt_gettoken(&p->p_token);
		if (p->p_flags & P_SIGVTALRM) {
			p->p_flags &= ~P_SIGVTALRM;
			ksignal(p, SIGVTALRM);
		}
		if (p->p_flags & P_SIGPROF) {
			p->p_flags &= ~P_SIGPROF;
			ksignal(p, SIGPROF);
		}
		if (p->p_flags & P_UPCALLPEND) {
			p->p_flags &= ~P_UPCALLPEND;
			postupcall(lp);
		}
		lwkt_reltoken(&p->p_token);
		goto recheck;
	}

	/*
	 * Post any pending signals
	 *
	 * WARNING!  postsig() can exit and not return.
	 */
	if ((sig = CURSIG_TRACE(lp)) != 0) {
		lwkt_gettoken(&p->p_token);
		postsig(sig);
		lwkt_reltoken(&p->p_token);
		goto recheck;
	}

	/*
	 * block here if we are swapped out, but still process signals
	 * (such as SIGKILL).  proc0 (the swapin scheduler) is already
	 * aware of our situation, we do not have to wake it up.
	 */
	if (p->p_flags & P_SWAPPEDOUT) {
		lwkt_gettoken(&p->p_token);
		get_mplock();
		p->p_flags |= P_SWAPWAIT;
		swapin_request();
		if (p->p_flags & P_SWAPWAIT)
			tsleep(p, PCATCH, "SWOUT", 0);
		p->p_flags &= ~P_SWAPWAIT;
		rel_mplock();
		lwkt_reltoken(&p->p_token);
		goto recheck;
	}

	/*
	 * Make sure postsig() handled request to restore old signal mask after
	 * running signal handler.
	 */
	KKASSERT((lp->lwp_flags & LWP_OLDMASK) == 0);
}

/*
 * Cleanup from userenter and any passive release that might have occured.
 * We must reclaim the current-process designation before we can return
 * to usermode.  We also handle both LWKT and USER reschedule requests.
 */
static __inline void
userexit(struct lwp *lp)
{
	struct thread *td = lp->lwp_thread;
	/* globaldata_t gd = td->td_gd; */

	/*
	 * Handle stop requests at kernel priority.  Any requests queued
	 * after this loop will generate another AST.
	 */
	while (lp->lwp_proc->p_stat == SSTOP) {
		lwkt_gettoken(&lp->lwp_proc->p_token);
		tstop();
		lwkt_reltoken(&lp->lwp_proc->p_token);
	}

	/*
	 * Reduce our priority in preparation for a return to userland.  If
	 * our passive release function was still in place, our priority was
	 * never raised and does not need to be reduced.
	 */
	lwkt_passive_recover(td);

	/*
	 * Become the current user scheduled process if we aren't already,
	 * and deal with reschedule requests and other factors.
	 */
	lp->lwp_proc->p_usched->acquire_curproc(lp);
	/* WARNING: we may have migrated cpu's */
	/* gd = td->td_gd; */
}

#if !defined(KTR_KERNENTRY)
#define	KTR_KERNENTRY	KTR_ALL
#endif
KTR_INFO_MASTER(kernentry);
KTR_INFO(KTR_KERNENTRY, kernentry, trap, 0, "pid=%d, tid=%d, trapno=%d, eva=%p",
	 sizeof(int) + sizeof(int) + sizeof(int) + sizeof(vm_offset_t));
KTR_INFO(KTR_KERNENTRY, kernentry, trap_ret, 0, "pid=%d, tid=%d",
	 sizeof(int) + sizeof(int));
KTR_INFO(KTR_KERNENTRY, kernentry, syscall, 0, "pid=%d, tid=%d, call=%d",
	 sizeof(int) + sizeof(int) + sizeof(int));
KTR_INFO(KTR_KERNENTRY, kernentry, syscall_ret, 0, "pid=%d, tid=%d, err=%d",
	 sizeof(int) + sizeof(int) + sizeof(int));
KTR_INFO(KTR_KERNENTRY, kernentry, fork_ret, 0, "pid=%d, tid=%d",
	 sizeof(int) + sizeof(int));

/*
 * Exception, fault, and trap interface to the kernel.
 * This common code is called from assembly language IDT gate entry
 * routines that prepare a suitable stack frame, and restore this
 * frame after the exception has been processed.
 *
 * This function is also called from doreti in an interlock to handle ASTs.
 * For example:  hardwareint->INTROUTINE->(set ast)->doreti->trap
 *
 * NOTE!  We have to retrieve the fault address prior to obtaining the
 * MP lock because get_mplock() may switch out.  YYY cr2 really ought
 * to be retrieved by the assembly code, not here.
 *
 * XXX gd_trap_nesting_level currently prevents lwkt_switch() from panicing
 * if an attempt is made to switch from a fast interrupt or IPI.  This is
 * necessary to properly take fatal kernel traps on SMP machines if 
 * get_mplock() has to block.
 */

void
user_trap(struct trapframe *frame)
{
	struct globaldata *gd = mycpu;
	struct thread *td = gd->gd_curthread;
	struct lwp *lp = td->td_lwp;
	struct proc *p;
	int sticks = 0;
	int i = 0, ucode = 0, type, code;
#ifdef SMP
	int have_mplock = 0;
#endif
#ifdef INVARIANTS
	int crit_count = td->td_critcount;
	lwkt_tokref_t curstop = td->td_toks_stop;
#endif
	vm_offset_t eva;

	p = td->td_proc;

	/*
	 * This is a bad kludge to avoid changing the various trapframe
	 * structures.  Because we are enabled as a virtual kernel,
	 * the original tf_err field will be passed to us shifted 16
	 * over in the tf_trapno field for T_PAGEFLT.
	 */
	if (frame->tf_trapno == T_PAGEFLT)
		eva = frame->tf_err;
	else
		eva = 0;
#if 0
	kprintf("USER_TRAP AT %08x xflags %d trapno %d eva %08x\n", 
		frame->tf_eip, frame->tf_xflags, frame->tf_trapno, eva);
#endif

	/*
	 * Everything coming from user mode runs through user_trap,
	 * including system calls.
	 */
	if (frame->tf_trapno == T_SYSCALL80) {
		syscall2(frame);
		return;
	}

	KTR_LOG(kernentry_trap, lp->lwp_proc->p_pid, lp->lwp_tid,
		frame->tf_trapno, eva);

#ifdef DDB
	if (db_active) {
		eva = (frame->tf_trapno == T_PAGEFLT ? rcr2() : 0);
		++gd->gd_trap_nesting_level;
		MAKEMPSAFE(have_mplock);
		trap_fatal(frame, TRUE, eva);
		--gd->gd_trap_nesting_level;
		goto out2;
	}
#endif

#if defined(I586_CPU) && !defined(NO_F00F_HACK)
restart:
#endif
	type = frame->tf_trapno;
	code = frame->tf_err;

	userenter(td, p);

	sticks = (int)td->td_sticks;
	lp->lwp_md.md_regs = frame;

	switch (type) {
	case T_PRIVINFLT:	/* privileged instruction fault */
		ucode = ILL_PRVOPC;
		i = SIGILL;
		break;

	case T_BPTFLT:		/* bpt instruction fault */
	case T_TRCTRAP:		/* trace trap */
		frame->tf_eflags &= ~PSL_T;
		ucode = TRAP_TRACE;
		i = SIGTRAP;
		break;

	case T_ARITHTRAP:	/* arithmetic trap */
		ucode = code;
		i = SIGFPE;
		break;

	case T_ASTFLT:		/* Allow process switch */
		mycpu->gd_cnt.v_soft++;
		if (mycpu->gd_reqflags & RQF_AST_OWEUPC) {
			atomic_clear_int(&mycpu->gd_reqflags,
				    RQF_AST_OWEUPC);
			addupc_task(p, p->p_prof.pr_addr,
				    p->p_prof.pr_ticks);
		}
		goto out;

		/*
		 * The following two traps can happen in
		 * vm86 mode, and, if so, we want to handle
		 * them specially.
		 */
	case T_PROTFLT:		/* general protection fault */
	case T_STKFLT:		/* stack fault */
#if 0
		if (frame->tf_eflags & PSL_VM) {
			i = vm86_emulate((struct vm86frame *)frame);
			if (i == 0)
				goto out;
			break;
		}
#endif
		i = SIGBUS;
		ucode = (type == T_PROTFLT) ? BUS_OBJERR : BUS_ADRERR;
		break;
	case T_SEGNPFLT:	/* segment not present fault */
		i = SIGBUS;
		ucode = BUS_ADRERR;
		break;
	case T_TSSFLT:		/* invalid TSS fault */
	case T_DOUBLEFLT:	/* double fault */
		i = SIGBUS;
		ucode = BUS_OBJERR;
	default:
#if 0
		ucode = code + BUS_SEGM_FAULT ; /* XXX: ???*/
#endif
		ucode = BUS_OBJERR;
		i = SIGBUS;
		break;

	case T_PAGEFLT:		/* page fault */
		MAKEMPSAFE(have_mplock);
		i = trap_pfault(frame, TRUE, eva);
		if (i == -1)
			goto out;
#if defined(I586_CPU) && !defined(NO_F00F_HACK)
		if (i == -2)
			goto restart;
#endif
		if (i == 0)
			goto out;

#if 0
		ucode = T_PAGEFLT;
#endif
		if (i == SIGSEGV)
			ucode = SEGV_MAPERR;
		else
			ucode = BUS_ADRERR;
		break;

	case T_DIVIDE:		/* integer divide fault */
		ucode = FPE_INTDIV;
		i = SIGFPE;
		break;

#if NISA > 0
	case T_NMI:
		MAKEMPSAFE(have_mplock);
		/* machine/parity/power fail/"kitchen sink" faults */
		if (isa_nmi(code) == 0) {
#ifdef DDB
			/*
			 * NMI can be hooked up to a pushbutton
			 * for debugging.
			 */
			if (ddb_on_nmi) {
				kprintf ("NMI ... going to debugger\n");
				kdb_trap (type, 0, frame);
			}
#endif /* DDB */
			goto out2;
		} else if (panic_on_nmi)
			panic("NMI indicates hardware failure");
		break;
#endif /* NISA > 0 */

	case T_OFLOW:		/* integer overflow fault */
		ucode = FPE_INTOVF;
		i = SIGFPE;
		break;

	case T_BOUND:		/* bounds check fault */
		ucode = FPE_FLTSUB;
		i = SIGFPE;
		break;

	case T_DNA:
		/*
		 * Virtual kernel intercept - pass the DNA exception
		 * to the (emulated) virtual kernel if it asked to handle 
		 * it.  This occurs when the virtual kernel is holding
		 * onto the FP context for a different emulated
		 * process then the one currently running.
		 *
		 * We must still call npxdna() since we may have
		 * saved FP state that the (emulated) virtual kernel
		 * needs to hand over to a different emulated process.
		 */
		if (lp->lwp_vkernel && lp->lwp_vkernel->ve &&
		    (td->td_pcb->pcb_flags & FP_VIRTFP)
		) {
			npxdna(frame);
			break;
		}
#if NNPX > 0
		/* 
		 * The kernel may have switched out the FP unit's
		 * state, causing the user process to take a fault
		 * when it tries to use the FP unit.  Restore the
		 * state here
		 */
		if (npxdna(frame))
			goto out;
#endif
		if (!pmath_emulate) {
			i = SIGFPE;
			ucode = FPE_FPU_NP_TRAP;
			break;
		}
		i = (*pmath_emulate)(frame);
		if (i == 0) {
			if (!(frame->tf_eflags & PSL_T))
				goto out2;
			frame->tf_eflags &= ~PSL_T;
			i = SIGTRAP;
		}
		/* else ucode = emulator_only_knows() XXX */
		break;

	case T_FPOPFLT:		/* FPU operand fetch fault */
		ucode = ILL_COPROC;
		i = SIGILL;
		break;

	case T_XMMFLT:		/* SIMD floating-point exception */
		ucode = 0; /* XXX */
		i = SIGFPE;
		break;
	}

	/*
	 * Virtual kernel intercept - if the fault is directly related to a
	 * VM context managed by a virtual kernel then let the virtual kernel
	 * handle it.
	 */
	if (lp->lwp_vkernel && lp->lwp_vkernel->ve) {
		vkernel_trap(lp, frame);
		goto out;
	}

	/*
	 * Translate fault for emulators (e.g. Linux) 
	 */
	if (*p->p_sysent->sv_transtrap)
		i = (*p->p_sysent->sv_transtrap)(i, type);

	MAKEMPSAFE(have_mplock);
	trapsignal(lp, i, ucode);

#ifdef DEBUG
	if (type <= MAX_TRAP_MSG) {
		uprintf("fatal process exception: %s",
			trap_msg[type]);
		if ((type == T_PAGEFLT) || (type == T_PROTFLT))
			uprintf(", fault VA = 0x%lx", (u_long)eva);
		uprintf("\n");
	}
#endif

out:
	userret(lp, frame, sticks);
	userexit(lp);
out2:	;
#ifdef SMP
	if (have_mplock)
		rel_mplock();
#endif
	KTR_LOG(kernentry_trap_ret, lp->lwp_proc->p_pid, lp->lwp_tid);
#ifdef INVARIANTS
	KASSERT(crit_count == td->td_critcount,
		("trap: critical section count mismatch! %d/%d",
		crit_count, td->td_pri));
	KASSERT(curstop == td->td_toks_stop,
		("trap: extra tokens held after trap! %zd/%zd",
		curstop - &td->td_toks_base,
		td->td_toks_stop - &td->td_toks_base));
#endif
}

void
kern_trap(struct trapframe *frame)
{
	struct globaldata *gd = mycpu;
	struct thread *td = gd->gd_curthread;
	struct lwp *lp;
	struct proc *p;
	int i = 0, ucode = 0, type, code;
#ifdef SMP
	int have_mplock = 0;
#endif
#ifdef INVARIANTS
	int crit_count = td->td_critcount;
	lwkt_tokref_t curstop = td->td_toks_stop;
#endif
	vm_offset_t eva;

	lp = td->td_lwp;
	p = td->td_proc;

	if (frame->tf_trapno == T_PAGEFLT) 
		eva = frame->tf_err;
	else
		eva = 0;

#ifdef DDB
	if (db_active) {
		++gd->gd_trap_nesting_level;
		MAKEMPSAFE(have_mplock);
		trap_fatal(frame, FALSE, eva);
		--gd->gd_trap_nesting_level;
		goto out2;
	}
#endif
	type = frame->tf_trapno;
	code = frame->tf_err;

#if 0
kernel_trap:
#endif
	/* kernel trap */

	switch (type) {
	case T_PAGEFLT:			/* page fault */
		MAKEMPSAFE(have_mplock);
		trap_pfault(frame, FALSE, eva);
		goto out2;

	case T_DNA:
#if NNPX > 0
		/*
		 * The kernel may be using npx for copying or other
		 * purposes.
		 */
		panic("kernel NPX should not happen");
		if (npxdna(frame))
			goto out2;
#endif
		break;

	case T_PROTFLT:		/* general protection fault */
	case T_SEGNPFLT:	/* segment not present fault */
		/*
		 * Invalid segment selectors and out of bounds
		 * %eip's and %esp's can be set up in user mode.
		 * This causes a fault in kernel mode when the
		 * kernel tries to return to user mode.  We want
		 * to get this fault so that we can fix the
		 * problem here and not have to check all the
		 * selectors and pointers when the user changes
		 * them.
		 */
		if (mycpu->gd_intr_nesting_level == 0) {
			if (td->td_pcb->pcb_onfault) {
				frame->tf_eip = 
				    (register_t)td->td_pcb->pcb_onfault;
				goto out2;
			}
		}
		break;

	case T_TSSFLT:
		/*
		 * PSL_NT can be set in user mode and isn't cleared
		 * automatically when the kernel is entered.  This
		 * causes a TSS fault when the kernel attempts to
		 * `iret' because the TSS link is uninitialized.  We
		 * want to get this fault so that we can fix the
		 * problem here and not every time the kernel is
		 * entered.
		 */
		if (frame->tf_eflags & PSL_NT) {
			frame->tf_eflags &= ~PSL_NT;
			goto out2;
		}
		break;

	case T_TRCTRAP:	 /* trace trap */
#if 0
		if (frame->tf_eip == (int)IDTVEC(syscall)) {
			/*
			 * We've just entered system mode via the
			 * syscall lcall.  Continue single stepping
			 * silently until the syscall handler has
			 * saved the flags.
			 */
			goto out2;
		}
		if (frame->tf_eip == (int)IDTVEC(syscall) + 1) {
			/*
			 * The syscall handler has now saved the
			 * flags.  Stop single stepping it.
			 */
			frame->tf_eflags &= ~PSL_T;
			goto out2;
		}
#endif
#if 0
		/*
		 * Ignore debug register trace traps due to
		 * accesses in the user's address space, which
		 * can happen under several conditions such as
		 * if a user sets a watchpoint on a buffer and
		 * then passes that buffer to a system call.
		 * We still want to get TRCTRAPS for addresses
		 * in kernel space because that is useful when
		 * debugging the kernel.
		 */
		if (user_dbreg_trap()) {
			/*
			 * Reset breakpoint bits because the
			 * processor doesn't
			 */
			load_dr6(rdr6() & 0xfffffff0);
			goto out2;
		}
#endif
		/*
		 * Fall through (TRCTRAP kernel mode, kernel address)
		 */
	case T_BPTFLT:
		/*
		 * If DDB is enabled, let it handle the debugger trap.
		 * Otherwise, debugger traps "can't happen".
		 */
#ifdef DDB
		MAKEMPSAFE(have_mplock);
		if (kdb_trap (type, 0, frame))
			goto out2;
#endif
		break;
	case T_DIVIDE:
		MAKEMPSAFE(have_mplock);
		trap_fatal(frame, FALSE, eva);
		goto out2;
	case T_NMI:
		MAKEMPSAFE(have_mplock);
		trap_fatal(frame, FALSE, eva);
		goto out2;
	case T_SYSCALL80:
		/*
		 * Ignore this trap generated from a spurious SIGTRAP.
		 *
		 * single stepping in / syscalls leads to spurious / SIGTRAP
		 * so ignore
		 *
		 * Haiku (c) 2007 Simon 'corecode' Schubert
		 */
		goto out2;
	}

	/*
	 * Translate fault for emulators (e.g. Linux) 
	 */
	if (*p->p_sysent->sv_transtrap)
		i = (*p->p_sysent->sv_transtrap)(i, type);

	MAKEMPSAFE(have_mplock);
	trapsignal(lp, i, ucode);

#ifdef DEBUG
	if (type <= MAX_TRAP_MSG) {
		uprintf("fatal process exception: %s",
			trap_msg[type]);
		if ((type == T_PAGEFLT) || (type == T_PROTFLT))
			uprintf(", fault VA = 0x%lx", (u_long)eva);
		uprintf("\n");
	}
#endif

out2:	
	;
#ifdef SMP
	if (have_mplock)
		rel_mplock();
#endif
#ifdef INVARIANTS
	KASSERT(crit_count == td->td_critcount,
		("trap: critical section count mismatch! %d/%d",
		crit_count, td->td_pri));
	KASSERT(curstop == td->td_toks_stop,
		("trap: extra tokens held after trap! %zd/%zd",
		curstop - &td->td_toks_base,
		td->td_toks_stop - &td->td_toks_base));
#endif
}

int
trap_pfault(struct trapframe *frame, int usermode, vm_offset_t eva)
{
	vm_offset_t va;
	struct vmspace *vm = NULL;
	vm_map_t map = 0;
	int rv = 0;
	int fault_flags;
	vm_prot_t ftype;
	thread_t td = curthread;
	struct lwp *lp = td->td_lwp;

	va = trunc_page(eva);
	if (usermode == FALSE) {
		/*
		 * This is a fault on kernel virtual memory.
		 */
		map = &kernel_map;
	} else {
		/*
		 * This is a fault on non-kernel virtual memory.
		 * vm is initialized above to NULL. If curproc is NULL
		 * or curproc->p_vmspace is NULL the fault is fatal.
		 */
		if (lp != NULL)
			vm = lp->lwp_vmspace;

		if (vm == NULL)
			goto nogo;

		map = &vm->vm_map;
	}

	if (frame->tf_xflags & PGEX_W)
		ftype = VM_PROT_READ | VM_PROT_WRITE;
	else
		ftype = VM_PROT_READ;

	if (map != &kernel_map) {
		/*
		 * Keep swapout from messing with us during this
		 *	critical time.
		 */
		PHOLD(lp->lwp_proc);

		/*
		 * Issue fault
		 */
		fault_flags = 0;
		if (usermode)
			fault_flags |= VM_FAULT_BURST;
		if (ftype & VM_PROT_WRITE)
			fault_flags |= VM_FAULT_DIRTY;
		else
			fault_flags |= VM_FAULT_NORMAL;
		rv = vm_fault(map, va, ftype, fault_flags);

		PRELE(lp->lwp_proc);
	} else {
		/*
		 * Don't have to worry about process locking or stacks in the kernel.
		 */
		rv = vm_fault(map, va, ftype, VM_FAULT_NORMAL);
	}

	if (rv == KERN_SUCCESS)
		return (0);
nogo:
	if (!usermode) {
		if (td->td_gd->gd_intr_nesting_level == 0 &&
		    td->td_pcb->pcb_onfault) {
			frame->tf_eip = (register_t)td->td_pcb->pcb_onfault;
			return (0);
		}
		trap_fatal(frame, usermode, eva);
		return (-1);
	}
	return((rv == KERN_PROTECTION_FAILURE) ? SIGBUS : SIGSEGV);
}

static void
trap_fatal(struct trapframe *frame, int usermode, vm_offset_t eva)
{
	int code, type, ss, esp;

	code = frame->tf_xflags;
	type = frame->tf_trapno;

	if (type <= MAX_TRAP_MSG) {
		kprintf("\n\nFatal trap %d: %s while in %s mode\n",
			type, trap_msg[type],
			(usermode ? "user" : "kernel"));
	}
#ifdef SMP
	/* two separate prints in case of a trap on an unmapped page */
	kprintf("cpuid = %d\n", mycpu->gd_cpuid);
#endif
	if (type == T_PAGEFLT) {
		kprintf("fault virtual address	= %p\n", (void *)eva);
		kprintf("fault code		= %s %s, %s\n",
			usermode ? "user" : "supervisor",
			code & PGEX_W ? "write" : "read",
			code & PGEX_P ? "protection violation" : "page not present");
	}
	kprintf("instruction pointer	= 0x%x:0x%x\n",
	       frame->tf_cs & 0xffff, frame->tf_eip);
	if (usermode) {
		ss = frame->tf_ss & 0xffff;
		esp = frame->tf_esp;
	} else {
		ss = GSEL(GDATA_SEL, SEL_KPL);
		esp = (int)&frame->tf_esp;
	}
	kprintf("stack pointer	        = 0x%x:0x%x\n", ss, esp);
	kprintf("frame pointer	        = 0x%x:0x%x\n", ss, frame->tf_ebp);
	kprintf("processor eflags	= ");
	if (frame->tf_eflags & PSL_T)
		kprintf("trace trap, ");
	if (frame->tf_eflags & PSL_I)
		kprintf("interrupt enabled, ");
	if (frame->tf_eflags & PSL_NT)
		kprintf("nested task, ");
	if (frame->tf_eflags & PSL_RF)
		kprintf("resume, ");
#if 0
	if (frame->tf_eflags & PSL_VM)
		kprintf("vm86, ");
#endif
	kprintf("IOPL = %d\n", (frame->tf_eflags & PSL_IOPL) >> 12);
	kprintf("current process		= ");
	if (curproc) {
		kprintf("%lu (%s)\n",
		    (u_long)curproc->p_pid, curproc->p_comm ?
		    curproc->p_comm : "");
	} else {
		kprintf("Idle\n");
	}
	kprintf("current thread          = pri %d ", curthread->td_pri);
	if (curthread->td_critcount)
		kprintf("(CRIT)");
	kprintf("\n");
#ifdef SMP
/**
 *  XXX FIXME:
 *	we probably SHOULD have stopped the other CPUs before now!
 *	another CPU COULD have been touching cpl at this moment...
 */
	kprintf(" <- SMP: XXX");
#endif
	kprintf("\n");

#ifdef KDB
	if (kdb_trap(&psl))
		return;
#endif
#ifdef DDB
	if ((debugger_on_panic || db_active) && kdb_trap(type, code, frame))
		return;
#endif
	kprintf("trap number		= %d\n", type);
	if (type <= MAX_TRAP_MSG)
		panic("%s", trap_msg[type]);
	else
		panic("unknown/reserved trap");
}

/*
 * Double fault handler. Called when a fault occurs while writing
 * a frame for a trap/exception onto the stack. This usually occurs
 * when the stack overflows (such is the case with infinite recursion,
 * for example).
 *
 * XXX Note that the current PTD gets replaced by IdlePTD when the
 * task switch occurs. This means that the stack that was active at
 * the time of the double fault is not available at <kstack> unless
 * the machine was idle when the double fault occurred. The downside
 * of this is that "trace <ebp>" in ddb won't work.
 */
void
dblfault_handler(void)
{
	struct mdglobaldata *gd = mdcpu;

	kprintf("\nFatal double fault:\n");
	kprintf("eip = 0x%x\n", gd->gd_common_tss.tss_eip);
	kprintf("esp = 0x%x\n", gd->gd_common_tss.tss_esp);
	kprintf("ebp = 0x%x\n", gd->gd_common_tss.tss_ebp);
#ifdef SMP
	/* two separate prints in case of a trap on an unmapped page */
	kprintf("cpuid = %d\n", mycpu->gd_cpuid);
#endif
	panic("double fault");
}

/*
 * syscall2 -	MP aware system call request C handler
 *
 * A system call is essentially treated as a trap except that the
 * MP lock is not held on entry or return.  We are responsible for
 * obtaining the MP lock if necessary and for handling ASTs
 * (e.g. a task switch) prior to return.
 *
 * MPSAFE
 */
void
syscall2(struct trapframe *frame)
{
	struct thread *td = curthread;
	struct proc *p = td->td_proc;
	struct lwp *lp = td->td_lwp;
	caddr_t params;
	struct sysent *callp;
	register_t orig_tf_eflags;
	int sticks;
	int error;
	int narg;
#ifdef INVARIANTS
	int crit_count = td->td_critcount;
#endif
#ifdef SMP
	int have_mplock = 0;
#endif
	u_int code;
	union sysunion args;

	KTR_LOG(kernentry_syscall, lp->lwp_proc->p_pid, lp->lwp_tid,
		frame->tf_eax);

	userenter(td, p);	/* lazy raise our priority */

	/*
	 * Misc
	 */
	sticks = (int)td->td_sticks;
	orig_tf_eflags = frame->tf_eflags;

	/*
	 * Virtual kernel intercept - if a VM context managed by a virtual
	 * kernel issues a system call the virtual kernel handles it, not us.
	 * Restore the virtual kernel context and return from its system
	 * call.  The current frame is copied out to the virtual kernel.
	 */
	if (lp->lwp_vkernel && lp->lwp_vkernel->ve) {
		vkernel_trap(lp, frame);
		error = EJUSTRETURN;
		goto out;
	}

	/*
	 * Get the system call parameters and account for time
	 */
	lp->lwp_md.md_regs = frame;
	params = (caddr_t)frame->tf_esp + sizeof(int);
	code = frame->tf_eax;

	if (p->p_sysent->sv_prepsyscall) {
		(*p->p_sysent->sv_prepsyscall)(
			frame, (int *)(&args.nosys.sysmsg + 1),
			&code, &params);
	} else {
		/*
		 * Need to check if this is a 32 bit or 64 bit syscall.
		 * fuword is MP aware.
		 */
		if (code == SYS_syscall) {
			/*
			 * Code is first argument, followed by actual args.
			 */
			code = fuword(params);
			params += sizeof(int);
		} else if (code == SYS___syscall) {
			/*
			 * Like syscall, but code is a quad, so as to maintain
			 * quad alignment for the rest of the arguments.
			 */
			code = fuword(params);
			params += sizeof(quad_t);
		}
	}

	code &= p->p_sysent->sv_mask;
	if (code >= p->p_sysent->sv_size)
		callp = &p->p_sysent->sv_table[0];
	else
		callp = &p->p_sysent->sv_table[code];

	narg = callp->sy_narg & SYF_ARGMASK;

	/*
	 * copyin is MP aware, but the tracing code is not
	 */
	if (narg && params) {
		error = copyin(params, (caddr_t)(&args.nosys.sysmsg + 1),
				narg * sizeof(register_t));
		if (error) {
#ifdef KTRACE
			if (KTRPOINT(td, KTR_SYSCALL)) {
				MAKEMPSAFE(have_mplock);
				
				ktrsyscall(lp, code, narg,
					(void *)(&args.nosys.sysmsg + 1));
			}
#endif
			goto bad;
		}
	}

#ifdef KTRACE
	if (KTRPOINT(td, KTR_SYSCALL)) {
		MAKEMPSAFE(have_mplock);
		ktrsyscall(lp, code, narg, (void *)(&args.nosys.sysmsg + 1));
	}
#endif

	/*
	 * For traditional syscall code edx is left untouched when 32 bit
	 * results are returned.  Since edx is loaded from fds[1] when the 
	 * system call returns we pre-set it here.
	 */
	args.sysmsg_fds[0] = 0;
	args.sysmsg_fds[1] = frame->tf_edx;

	/*
	 * The syscall might manipulate the trap frame. If it does it
	 * will probably return EJUSTRETURN.
	 */
	args.sysmsg_frame = frame;

	STOPEVENT(p, S_SCE, narg);	/* MP aware */

	/*
	 * NOTE: All system calls run MPSAFE now.  The system call itself
	 *	 is responsible for getting the MP lock.
	 */
	error = (*callp->sy_call)(&args);

#if 0
	kprintf("system call %d returned %d\n", code, error);
#endif

out:
	/*
	 * MP SAFE (we may or may not have the MP lock at this point)
	 */
	switch (error) {
	case 0:
		/*
		 * Reinitialize proc pointer `p' as it may be different
		 * if this is a child returning from fork syscall.
		 */
		p = curproc;
		lp = curthread->td_lwp;
		frame->tf_eax = args.sysmsg_fds[0];
		frame->tf_edx = args.sysmsg_fds[1];
		frame->tf_eflags &= ~PSL_C;
		break;
	case ERESTART:
		/*
		 * Reconstruct pc, assuming lcall $X,y is 7 bytes,
		 * int 0x80 is 2 bytes. We saved this in tf_err.
		 */
		frame->tf_eip -= frame->tf_err;
		break;
	case EJUSTRETURN:
		break;
	case EASYNC:
		panic("Unexpected EASYNC return value (for now)");
	default:
bad:
		if (p->p_sysent->sv_errsize) {
			if (error >= p->p_sysent->sv_errsize)
				error = -1;	/* XXX */
			else
				error = p->p_sysent->sv_errtbl[error];
		}
		frame->tf_eax = error;
		frame->tf_eflags |= PSL_C;
		break;
	}

	/*
	 * Traced syscall.  trapsignal() is not MP aware.
	 */
	if ((orig_tf_eflags & PSL_T) /*&& !(orig_tf_eflags & PSL_VM)*/) {
		MAKEMPSAFE(have_mplock);
		frame->tf_eflags &= ~PSL_T;
		trapsignal(lp, SIGTRAP, TRAP_TRACE);
	}

	/*
	 * Handle reschedule and other end-of-syscall issues
	 */
	userret(lp, frame, sticks);

#ifdef KTRACE
	if (KTRPOINT(td, KTR_SYSRET)) {
		MAKEMPSAFE(have_mplock);
		ktrsysret(lp, code, error, args.sysmsg_result);
	}
#endif

	/*
	 * This works because errno is findable through the
	 * register set.  If we ever support an emulation where this
	 * is not the case, this code will need to be revisited.
	 */
	STOPEVENT(p, S_SCX, code);

	userexit(lp);
#ifdef SMP
	/*
	 * Release the MP lock if we had to get it
	 */
	if (have_mplock)
		rel_mplock();
#endif
	KTR_LOG(kernentry_syscall_ret, lp->lwp_proc->p_pid, lp->lwp_tid, error);
#ifdef INVARIANTS
	KASSERT(crit_count == td->td_critcount,
		("syscall: critical section count mismatch! %d/%d",
		crit_count, td->td_pri));
	KASSERT(&td->td_toks_base == td->td_toks_stop,
		("syscall: extra tokens held after trap! %zd",
		td->td_toks_stop - &td->td_toks_base));
#endif
}

/*
 * NOTE: mplock not held at any point
 */
void
fork_return(struct lwp *lp, struct trapframe *frame)
{
	frame->tf_eax = 0;		/* Child returns zero */
	frame->tf_eflags &= ~PSL_C;	/* success */
	frame->tf_edx = 1;

	generic_lwp_return(lp, frame);
	KTR_LOG(kernentry_fork_ret, lp->lwp_proc->p_pid, lp->lwp_tid);
}

/*
 * Simplified back end of syscall(), used when returning from fork()
 * directly into user mode.
 *
 * This code will return back into the fork trampoline code which then
 * runs doreti.
 *
 * NOTE: The mplock is not held at any point.
 */
void
generic_lwp_return(struct lwp *lp, struct trapframe *frame)
{
	struct proc *p = lp->lwp_proc;

	/*
	 * Newly forked processes are given a kernel priority.  We have to
	 * adjust the priority to a normal user priority and fake entry
	 * into the kernel (call userenter()) to install a passive release
	 * function just in case userret() decides to stop the process.  This
	 * can occur when ^Z races a fork.  If we do not install the passive
	 * release function the current process designation will not be
	 * released when the thread goes to sleep.
	 */
	lwkt_setpri_self(TDPRI_USER_NORM);
	userenter(lp->lwp_thread, p);
	userret(lp, frame, 0);
#ifdef KTRACE
	if (KTRPOINT(lp->lwp_thread, KTR_SYSRET))
		ktrsysret(lp, SYS_fork, 0, 0);
#endif
	lp->lwp_flags |= LWP_PASSIVE_ACQ;
	userexit(lp);
	lp->lwp_flags &= ~LWP_PASSIVE_ACQ;
}

/*
 * doreti has turned into this.  The frame is directly on the stack.  We
 * pull everything else we need (fpu and tls context) from the current
 * thread.
 *
 * Note on fpu interactions: In a virtual kernel, the fpu context for
 * an emulated user mode process is not shared with the virtual kernel's
 * fpu context, so we only have to 'stack' fpu contexts within the virtual
 * kernel itself, and not even then since the signal() contexts that we care
 * about save and restore the FPU state (I think anyhow).
 *
 * vmspace_ctl() returns an error only if it had problems instaling the
 * context we supplied or problems copying data to/from our VM space.
 */
void
go_user(struct intrframe *frame)
{
	struct trapframe *tf = (void *)&frame->if_gs;
	int r;

	/*
	 * Interrupts may be disabled on entry, make sure all signals
	 * can be received before beginning our loop.
	 */
	sigsetmask(0);

	/*
	 * Switch to the current simulated user process, then call
	 * user_trap() when we break out of it (usually due to a signal).
	 */
	for (;;) {
		/*
		 * Tell the real kernel whether it is ok to use the FP
		 * unit or not.
		 *
		 * The critical section is required to prevent an interrupt
		 * from causing a preemptive task switch and changing
		 * the FP state.
		 */
		crit_enter();
		if (mdcpu->gd_npxthread == curthread) {
			tf->tf_xflags &= ~PGEX_FPFAULT;
		} else {
			tf->tf_xflags |= PGEX_FPFAULT;
		}

		/*
		 * Run emulated user process context.  This call interlocks
		 * with new mailbox signals.
		 *
		 * Set PGEX_U unconditionally, indicating a user frame (the
		 * bit is normally set only by T_PAGEFLT).
		 */
		r = vmspace_ctl(&curproc->p_vmspace->vm_pmap, VMSPACE_CTL_RUN,
				tf, &curthread->td_savevext);
		crit_exit();
		frame->if_xflags |= PGEX_U;
#if 0
		kprintf("GO USER %d trap %d EVA %08x EIP %08x ESP %08x XFLAGS %02x/%02x\n", 
			r, tf->tf_trapno, tf->tf_err, tf->tf_eip, tf->tf_esp,
			tf->tf_xflags, frame->if_xflags);
#endif
		if (r < 0) {
			if (errno != EINTR)
				panic("vmspace_ctl failed error %d", errno);
		} else {
			if (tf->tf_trapno) {
				user_trap(tf);
			}
		}
		if (mycpu->gd_reqflags & RQF_AST_MASK) {
			tf->tf_trapno = T_ASTFLT;
			user_trap(tf);
		}
		tf->tf_trapno = 0;
	}
}

/*
 * If PGEX_FPFAULT is set then set FP_VIRTFP in the PCB to force a T_DNA
 * fault (which is then passed back to the virtual kernel) if an attempt is
 * made to use the FP unit.
 * 
 * XXX this is a fairly big hack.
 */
void
set_vkernel_fp(struct trapframe *frame)
{
	struct thread *td = curthread;

	if (frame->tf_xflags & PGEX_FPFAULT) {
		td->td_pcb->pcb_flags |= FP_VIRTFP;
		if (mdcpu->gd_npxthread == td)
			npxexit();
	} else {
		td->td_pcb->pcb_flags &= ~FP_VIRTFP;
	}
}

/*
 * Called from vkernel_trap() to fixup the vkernel's syscall
 * frame for vmspace_ctl() return.
 */
void
cpu_vkernel_trap(struct trapframe *frame, int error)
{
	frame->tf_eax = error;
	if (error)
		frame->tf_eflags |= PSL_C;
	else
		frame->tf_eflags &= ~PSL_C;
}
