/*
 * Copyright (c) 2003,2004 The DragonFly Project.  All rights reserved.
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
 * Copyright (c) Peter Wemm <peter@netplex.com.au> All rights reserved.
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
 * $FreeBSD: src/sys/i386/include/globaldata.h,v 1.11.2.1 2000/05/16 06:58:10 dillon Exp $
 * $DragonFly: src/sys/sys/globaldata.h,v 1.49 2008/06/02 16:54:20 dillon Exp $
 */

#ifndef _SYS_GLOBALDATA_H_
#define _SYS_GLOBALDATA_H_

#if defined(_KERNEL) || defined(_KERNEL_STRUCTURES)

#ifndef _SYS_STDINT_H_
#include <sys/stdint.h>	/* __int types */
#endif
#ifndef _SYS_TIME_H_
#include <sys/time.h>	/* struct timeval */
#endif
#ifndef _SYS_VMMETER_H_
#include <sys/vmmeter.h> /* struct vmmeter */
#endif
#ifndef _SYS_THREAD_H_
#include <sys/thread.h>	/* struct thread */
#endif
#ifndef _SYS_SLABALLOC_H_
#include <sys/slaballoc.h> /* SLGlobalData */
#endif
#ifndef _SYS_SYSTIMER_H_
#include <sys/systimer.h> /* fine-grained system timers */
#endif
#ifndef _SYS_NCHSTATS_H_
#include <sys/nchstats.h>
#endif
#ifndef _SYS_SYSID_H_
#include <sys/sysid.h>	  /* sysid_t */
#endif

/*
 * This structure maps out the global data that needs to be kept on a
 * per-cpu basis.  genassym uses this to generate offsets for the assembler
 * code.  The machine-dependant portions of this file can be found in
 * <machine/globaldata.h>, but only MD code should retrieve it.
 *
 * The SMP parts are setup in pmap.c and locore.s for the BSP, and
 * mp_machdep.c sets up the data for the AP's to "see" when they awake.
 * The reason for doing it via a struct is so that an array of pointers
 * to each CPU's data can be set up for things like "check curproc on all
 * other processors"
 *
 * NOTE! this structure needs to remain compatible between module accessors
 * and the kernel, so we can't throw in lots of #ifdef's.
 *
 * gd_reqflags serves serveral purposes, but it is primarily an interrupt
 * rollup flag used by the task switcher and spl mechanisms to decide that
 * further checks are necessary.  Interrupts are typically managed on a
 * per-processor basis at least until you leave a critical section, but
 * may then be scheduled to other cpus.
 *
 * gd_vme_avail and gd_vme_base cache free vm_map_entry structures for use
 * in various vm_map related operations.  gd_vme_avail is *NOT* a count of
 * the number of structures in the cache but is instead a count of the number
 * of unreserved structures in the cache.  See vm_map_entry_reserve().
 */

struct sysmsg;
struct tslpentry;
struct privatespace;
struct vm_map_entry;
struct spinlock;
struct pipe;

struct globaldata {
	struct privatespace *gd_prvspace;	/* self-reference */
	struct thread	*gd_curthread;
	struct thread	*gd_freetd;		/* cache one free td */
	__uint32_t	gd_reqflags;		/* (see note above) */
	long		gd_flags;
	lwkt_queue	gd_tdallq;		/* all threads */
	lwkt_queue	gd_tdrunq;		/* runnable threads */
	__uint32_t	gd_cpuid;
	cpumask_t	gd_cpumask;		/* mask = 1<<cpuid */
	cpumask_t	gd_other_cpus;		/* mask of 'other' cpus */
	struct timeval	gd_stattv;
	int		gd_intr_nesting_level;	/* hard code, intrs, ipis */
	struct vmmeter	gd_cnt;
	struct lwkt_ipiq *gd_ipiq;		/* array[ncpu] of ipiq's */
	struct lwkt_ipiq gd_cpusyncq;		/* ipiq for cpu synchro */
	int		gd_fairq_total_pri;
	struct thread	gd_unused02B;
	struct thread	gd_idlethread;
	SLGlobalData	gd_slab;		/* slab allocator */
	int		gd_trap_nesting_level;	/* track traps */
	int		gd_vme_avail;		/* vm_map_entry reservation */
	struct vm_map_entry *gd_vme_base;	/* vm_map_entry reservation */
	struct systimerq gd_systimerq;		/* per-cpu system timers */
	int		gd_syst_nest;
	struct systimer gd_hardclock;		/* scheduler periodic */
	struct systimer gd_statclock;		/* statistics periodic */
	struct systimer gd_schedclock;		/* scheduler periodic */
	volatile __uint32_t gd_time_seconds;	/* uptime in seconds */
	volatile sysclock_t gd_cpuclock_base;	/* cpuclock relative base */

	struct pipe	*gd_pipeq;		/* cache pipe structures */
	struct nchstats	*gd_nchstats;		/* namecache effectiveness */
	int		gd_pipeqcount;		/* number of structures */
	sysid_t		gd_sysid_alloc;		/* allocate unique sysid */

	struct tslpque	*gd_tsleep_hash;	/* tsleep/wakeup support */
	void		*gd_unused08;
	int		gd_spinlocks_wr;	/* Exclusive spinlocks held */
	struct systimer	*gd_systimer_inprog;	/* in-progress systimer */
	int		gd_timer_running;
	void		*gd_reserved[11];	/* future fields */
	/* extended by <machine/globaldata.h> */
};

typedef struct globaldata *globaldata_t;

#define RQB_IPIQ		0
#define RQB_INTPEND		1
#define RQB_AST_OWEUPC		2
#define RQB_AST_SIGNAL		3
#define RQB_AST_USER_RESCHED	4
#define RQB_AST_LWKT_RESCHED	5
#define RQB_AST_UPCALL		6
#define RQB_TIMER		7
#define RQB_RUNNING		8

#define RQF_IPIQ		(1 << RQB_IPIQ)
#define RQF_INTPEND		(1 << RQB_INTPEND)
#define RQF_TIMER		(1 << RQB_TIMER)
#define RQF_AST_OWEUPC		(1 << RQB_AST_OWEUPC)
#define RQF_AST_SIGNAL		(1 << RQB_AST_SIGNAL)
#define RQF_AST_USER_RESCHED	(1 << RQB_AST_USER_RESCHED)
#define RQF_AST_LWKT_RESCHED	(1 << RQB_AST_LWKT_RESCHED)
#define RQF_AST_UPCALL		(1 << RQB_AST_UPCALL)
#define RQF_RUNNING		(1 << RQB_RUNNING)
#define RQF_AST_MASK		(RQF_AST_OWEUPC|RQF_AST_SIGNAL|\
				RQF_AST_USER_RESCHED|RQF_AST_LWKT_RESCHED|\
				RQF_AST_UPCALL)
#define RQF_IDLECHECK_MASK	(RQF_IPIQ|RQF_INTPEND|RQF_TIMER)

/*
 * globaldata flags
 */
#define GDF_KPRINTF		0x0001	/* kprintf() reentrancy */

#endif

#ifdef _KERNEL
struct globaldata *globaldata_find(int cpu);
int is_globaldata_space(vm_offset_t saddr, vm_offset_t eaddr);
#endif

#endif
