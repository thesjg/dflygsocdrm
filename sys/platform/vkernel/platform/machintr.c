/*
 * Copyright (c) 2006 The DragonFly Project.  All rights reserved.
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
 * $DragonFly: src/sys/platform/vkernel/platform/machintr.c,v 1.17 2008/04/30 16:59:45 dillon Exp $
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/machintr.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/globaldata.h>
#include <sys/interrupt.h>
#include <stdio.h>
#include <signal.h>
#include <machine/globaldata.h>
#include <machine/md_var.h>
#include <sys/thread2.h>

/*
 * Interrupt Subsystem ABI
 */

static void dummy_intrdis(int);
static void dummy_intren(int);
static void dummy_intr_setup(int, int);
static void dummy_intr_teardown(int);
static void dummy_finalize(void);
static void dummy_intrcleanup(void);
static void dummy_stabilize(void);

struct machintr_abi MachIntrABI = {
	MACHINTR_GENERIC,
	.intrdis =	dummy_intrdis,
	.intren =	dummy_intren,
	.intr_setup =	dummy_intr_setup,
	.intr_teardown = dummy_intr_teardown,
	.finalize =	dummy_finalize,
	.cleanup =	dummy_intrcleanup,
	.stabilize =	dummy_stabilize
};

static void
dummy_intrdis(int intr)
{
}

static void
dummy_intren(int intr)
{
}

static void
dummy_intr_setup(int intr, int flags)
{
}

static void
dummy_intr_teardown(int intr)
{
}

static void
dummy_finalize(void)
{
}

static void
dummy_intrcleanup(void)
{
}

static void
dummy_stabilize(void)
{
}

/*
 * Process pending interrupts
 */
void
splz(void)
{
	struct mdglobaldata *gd = mdcpu;
	thread_t td = gd->mi.gd_curthread;
	int irq;

	while (gd->mi.gd_reqflags & (RQF_IPIQ|RQF_INTPEND)) {
		crit_enter_quick(td);
#ifdef SMP
		if (gd->mi.gd_reqflags & RQF_IPIQ) {
			atomic_clear_int(&gd->mi.gd_reqflags, RQF_IPIQ);
			lwkt_process_ipiq();
		}
#endif
		if (gd->mi.gd_reqflags & RQF_INTPEND) {
			atomic_clear_int(&gd->mi.gd_reqflags, RQF_INTPEND);
			while ((irq = ffs(gd->gd_spending)) != 0) {
				--irq;
				atomic_clear_int(&gd->gd_spending, 1 << irq);
				irq += FIRST_SOFTINT;
				sched_ithd(irq);
			}
			while ((irq = ffs(gd->gd_fpending)) != 0) {
				--irq;
				atomic_clear_int(&gd->gd_fpending, 1 << irq);
				sched_ithd(irq);
			}
		}
		crit_exit_noyield(td);
	}
}

/*
 * Allows an unprotected signal handler or mailbox to signal an interrupt
 *
 * For sched_ithd() to properly preempt via lwkt_schedule() we cannot
 * enter a critical section here.  We use td_nest_count instead.
 */
void
signalintr(int intr)
{
	struct mdglobaldata *gd = mdcpu;
	thread_t td = gd->mi.gd_curthread;

	if (td->td_critcount || td->td_nest_count) {
		atomic_set_int_nonlocked(&gd->gd_fpending, 1 << intr);
		atomic_set_int(&gd->mi.gd_reqflags, RQF_INTPEND);
	} else {
		++td->td_nest_count;
		atomic_clear_int(&gd->gd_fpending, 1 << intr);
		sched_ithd(intr);
		--td->td_nest_count;
	}
}

void
cpu_disable_intr(void)
{
	sigblock(sigmask(SIGALRM)|sigmask(SIGIO)|sigmask(SIGUSR1));
}

void
cpu_enable_intr(void)
{
	sigsetmask(0);
}

void
cpu_mask_all_signals(void)
{
	sigblock(sigmask(SIGALRM)|sigmask(SIGIO)|sigmask(SIGQUIT)|
		 sigmask(SIGUSR1)|sigmask(SIGTERM)|sigmask(SIGWINCH)|
		 sigmask(SIGUSR2));
}

void
cpu_unmask_all_signals(void)
{
	sigsetmask(0);
}

void
cpu_invlpg(void *addr)
{
	madvise(addr, PAGE_SIZE, MADV_INVAL);
}

void
cpu_invltlb(void)
{
	madvise((void *)KvaStart, KvaEnd - KvaStart, MADV_INVAL);
}

