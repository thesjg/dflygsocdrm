/*
 * (MPSAFE)
 *
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 * Copyright (c) 1994 David Greenman
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
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
 *	from:	@(#)pmap.c	7.7 (Berkeley)	5/12/91
 * $FreeBSD: src/sys/i386/i386/pmap.c,v 1.250.2.18 2002/03/06 22:48:53 silby Exp $
 * $DragonFly: src/sys/platform/pc32/i386/pmap.c,v 1.87 2008/08/25 17:01:38 dillon Exp $
 */

/*
 * Manages physical address maps.
 *
 * In most cases we hold page table pages busy in order to manipulate them.
 */
/*
 * PMAP_DEBUG - see platform/pc32/include/pmap.h
 */

#include "opt_disable_pse.h"
#include "opt_pmap.h"
#include "opt_msgbuf.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/msgbuf.h>
#include <sys/vmmeter.h>
#include <sys/mman.h>
#include <sys/thread.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_zone.h>

#include <sys/user.h>
#include <sys/thread2.h>
#include <sys/sysref2.h>
#include <sys/spinlock2.h>

#include <machine/cputypes.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/smp.h>
#include <machine_base/apic/apicreg.h>
#include <machine/globaldata.h>
#include <machine/pmap.h>
#include <machine/pmap_inval.h>

#define PMAP_KEEP_PDIRS
#ifndef PMAP_SHPGPERPROC
#define PMAP_SHPGPERPROC 200
#define PMAP_PVLIMIT	 1400000	/* i386 kvm problems */
#endif

#if defined(DIAGNOSTIC)
#define PMAP_DIAGNOSTIC
#endif

#define MINPV 2048

#if !defined(PMAP_DIAGNOSTIC)
#define PMAP_INLINE __inline
#else
#define PMAP_INLINE
#endif

/*
 * Get PDEs and PTEs for user/kernel address space
 */
#define	pmap_pde(m, v)	(&((m)->pm_pdir[(vm_offset_t)(v) >> PDRSHIFT]))
#define pdir_pde(m, v) (m[(vm_offset_t)(v) >> PDRSHIFT])

#define pmap_pde_v(pte)		((*(int *)pte & PG_V) != 0)
#define pmap_pte_w(pte)		((*(int *)pte & PG_W) != 0)
#define pmap_pte_m(pte)		((*(int *)pte & PG_M) != 0)
#define pmap_pte_u(pte)		((*(int *)pte & PG_A) != 0)
#define pmap_pte_v(pte)		((*(int *)pte & PG_V) != 0)

/*
 * Given a map and a machine independent protection code,
 * convert to a vax protection code.
 */
#define pte_prot(m, p)		\
	(protection_codes[p & (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)])
static int protection_codes[8];

struct pmap kernel_pmap;
static TAILQ_HEAD(,pmap)	pmap_list = TAILQ_HEAD_INITIALIZER(pmap_list);

vm_paddr_t avail_start;		/* PA of first available physical page */
vm_paddr_t avail_end;		/* PA of last available physical page */
vm_offset_t virtual_start;	/* VA of first avail page (after kernel bss) */
vm_offset_t virtual_end;	/* VA of last avail page (end of kernel AS) */
vm_offset_t virtual2_start;
vm_offset_t virtual2_end;
vm_offset_t KvaStart;		/* VA start of KVA space */
vm_offset_t KvaEnd;		/* VA end of KVA space (non-inclusive) */
vm_offset_t KvaSize;		/* max size of kernel virtual address space */
static boolean_t pmap_initialized = FALSE;	/* Has pmap_init completed? */
static int pgeflag;		/* PG_G or-in */
static int pseflag;		/* PG_PS or-in */

static vm_object_t kptobj;

static int nkpt;
vm_offset_t kernel_vm_end;

/*
 * Data for the pv entry allocation mechanism
 */
static vm_zone_t pvzone;
static struct vm_zone pvzone_store;
static struct vm_object pvzone_obj;
static int pv_entry_count=0, pv_entry_max=0, pv_entry_high_water=0;
static int pmap_pagedaemon_waken = 0;
static struct pv_entry *pvinit;

/*
 * Considering all the issues I'm having with pmap caching, if breakage
 * continues to occur, and for debugging, I've added a sysctl that will
 * just do an unconditional invltlb.
 */
static int dreadful_invltlb;

SYSCTL_INT(_vm, OID_AUTO, dreadful_invltlb,
	   CTLFLAG_RW, &dreadful_invltlb, 0, "Debugging sysctl to force invltlb on pmap operations");

/*
 * All those kernel PT submaps that BSD is so fond of
 */
pt_entry_t *CMAP1 = 0, *ptmmap;
caddr_t CADDR1 = 0, ptvmmap = 0;
static pt_entry_t *msgbufmap;
struct msgbuf *msgbufp=0;

/*
 * Crashdump maps.
 */
static pt_entry_t *pt_crashdumpmap;
static caddr_t crashdumpmap;

extern pt_entry_t *SMPpt;

static PMAP_INLINE void	free_pv_entry (pv_entry_t pv);
static unsigned * get_ptbase (pmap_t pmap);
static pv_entry_t get_pv_entry (void);
static void	i386_protection_init (void);
static __inline void	pmap_clearbit (vm_page_t m, int bit);

static void	pmap_remove_all (vm_page_t m);
static int pmap_remove_pte (struct pmap *pmap, unsigned *ptq, 
				vm_offset_t sva, pmap_inval_info_t info);
static void pmap_remove_page (struct pmap *pmap, 
				vm_offset_t va, pmap_inval_info_t info);
static int pmap_remove_entry (struct pmap *pmap, vm_page_t m,
				vm_offset_t va, pmap_inval_info_t info);
static boolean_t pmap_testbit (vm_page_t m, int bit);
static void pmap_insert_entry (pmap_t pmap, vm_offset_t va,
		vm_page_t mpte, vm_page_t m);

static vm_page_t pmap_allocpte (pmap_t pmap, vm_offset_t va);

static int pmap_release_free_page (pmap_t pmap, vm_page_t p);
static vm_page_t _pmap_allocpte (pmap_t pmap, unsigned ptepindex);
static unsigned * pmap_pte_quick (pmap_t pmap, vm_offset_t va);
static vm_page_t pmap_page_lookup (vm_object_t object, vm_pindex_t pindex);
static int pmap_unuse_pt (pmap_t, vm_offset_t, vm_page_t, pmap_inval_info_t);
static vm_offset_t pmap_kmem_choose(vm_offset_t addr);

static unsigned pdir4mb;

/*
 * Move the kernel virtual free pointer to the next
 * 4MB.  This is used to help improve performance
 * by using a large (4MB) page for much of the kernel
 * (.text, .data, .bss)
 */
static
vm_offset_t
pmap_kmem_choose(vm_offset_t addr)
{
	vm_offset_t newaddr = addr;
#ifndef DISABLE_PSE
	if (cpu_feature & CPUID_PSE) {
		newaddr = (addr + (NBPDR - 1)) & ~(NBPDR - 1);
	}
#endif
	return newaddr;
}

/*
 * This function returns a pointer to the pte entry in the pmap and has
 * the side effect of potentially retaining a cached mapping of the pmap.
 *
 * The caller must hold vm_token and the returned value is only valid
 * until the caller blocks or releases the token.
 */
static
unsigned *
pmap_pte(pmap_t pmap, vm_offset_t va)
{
	unsigned *pdeaddr;

	ASSERT_LWKT_TOKEN_HELD(&vm_token);
	if (pmap) {
		pdeaddr = (unsigned *) pmap_pde(pmap, va);
		if (*pdeaddr & PG_PS)
			return pdeaddr;
		if (*pdeaddr)
			return get_ptbase(pmap) + i386_btop(va);
	}
	return (0);
}

/*
 * pmap_pte using the kernel_pmap
 *
 * Used for debugging, no requirements.
 */
unsigned *
pmap_kernel_pte(vm_offset_t va)
{
	unsigned *pdeaddr;

	pdeaddr = (unsigned *) pmap_pde(&kernel_pmap, va);
	if (*pdeaddr & PG_PS)
		return pdeaddr;
	if (*pdeaddr)
		return (unsigned *)vtopte(va);
	return(0);
}

/*
 * pmap_pte_quick:
 *
 * Super fast pmap_pte routine best used when scanning the pv lists.
 * This eliminates many course-grained invltlb calls.  Note that many of
 * the pv list scans are across different pmaps and it is very wasteful
 * to do an entire invltlb when checking a single mapping.
 *
 * Should only be called while in a critical section.
 *
 * The caller must hold vm_token and the returned value is only valid
 * until the caller blocks or releases the token.
 */
static
unsigned *
pmap_pte_quick(pmap_t pmap, vm_offset_t va)
{
	struct mdglobaldata *gd = mdcpu;
	unsigned pde, newpf;

	ASSERT_LWKT_TOKEN_HELD(&vm_token);
	if ((pde = (unsigned) pmap->pm_pdir[va >> PDRSHIFT]) != 0) {
		unsigned frame = (unsigned) pmap->pm_pdir[PTDPTDI] & PG_FRAME;
		unsigned index = i386_btop(va);
		/* are we current address space or kernel? */
		if ((pmap == &kernel_pmap) ||
			(frame == (((unsigned) PTDpde) & PG_FRAME))) {
			return (unsigned *) PTmap + index;
		}
		newpf = pde & PG_FRAME;
		if (((*(unsigned *)gd->gd_PMAP1) & PG_FRAME) != newpf) {
			*(unsigned *)gd->gd_PMAP1 = newpf | PG_RW | PG_V;
			cpu_invlpg(gd->gd_PADDR1);
		}
		return gd->gd_PADDR1 + ((unsigned) index & (NPTEPG - 1));
	}
	return (0);
}


/*
 * Bootstrap the system enough to run with virtual memory.
 *
 * On the i386 this is called after mapping has already been enabled
 * and just syncs the pmap module with what has already been done.
 * [We can't call it easily with mapping off since the kernel is not
 * mapped with PA == VA, hence we would have to relocate every address
 * from the linked base (virtual) address "KERNBASE" to the actual
 * (physical) address starting relative to 0]
 */
void
pmap_bootstrap(vm_paddr_t firstaddr, vm_paddr_t loadaddr)
{
	vm_offset_t va;
	pt_entry_t *pte;
	struct mdglobaldata *gd;
	int i;
	int pg;

	KvaStart = (vm_offset_t)VADDR(PTDPTDI, 0);
	KvaSize = (vm_offset_t)VADDR(APTDPTDI, 0) - KvaStart;
	KvaEnd  = KvaStart + KvaSize;

	avail_start = firstaddr;

	/*
	 * XXX The calculation of virtual_start is wrong. It's NKPT*PAGE_SIZE
	 * too large. It should instead be correctly calculated in locore.s and
	 * not based on 'first' (which is a physical address, not a virtual
	 * address, for the start of unused physical memory). The kernel
	 * page tables are NOT double mapped and thus should not be included
	 * in this calculation.
	 */
	virtual_start = (vm_offset_t) KERNBASE + firstaddr;
	virtual_start = pmap_kmem_choose(virtual_start);
	virtual_end = VADDR(KPTDI+NKPDE-1, NPTEPG-1);

	/*
	 * Initialize protection array.
	 */
	i386_protection_init();

	/*
	 * The kernel's pmap is statically allocated so we don't have to use
	 * pmap_create, which is unlikely to work correctly at this part of
	 * the boot sequence (XXX and which no longer exists).
	 *
	 * The kernel_pmap's pm_pteobj is used only for locking and not
	 * for mmu pages.
	 */
	kernel_pmap.pm_pdir = (pd_entry_t *)(KERNBASE + (u_int)IdlePTD);
	kernel_pmap.pm_count = 1;
	kernel_pmap.pm_active = (cpumask_t)-1 & ~CPUMASK_LOCK;
	kernel_pmap.pm_pteobj = &kernel_object;
	TAILQ_INIT(&kernel_pmap.pm_pvlist);
	TAILQ_INIT(&kernel_pmap.pm_pvlist_free);
	spin_init(&kernel_pmap.pm_spin);
	lwkt_token_init(&kernel_pmap.pm_token, "kpmap_tok");
	nkpt = NKPT;

	/*
	 * Reserve some special page table entries/VA space for temporary
	 * mapping of pages.
	 */
#define	SYSMAP(c, p, v, n)	\
	v = (c)va; va += ((n)*PAGE_SIZE); p = pte; pte += (n);

	va = virtual_start;
	pte = (pt_entry_t *) pmap_kernel_pte(va);

	/*
	 * CMAP1/CMAP2 are used for zeroing and copying pages.
	 */
	SYSMAP(caddr_t, CMAP1, CADDR1, 1)

	/*
	 * Crashdump maps.
	 */
	SYSMAP(caddr_t, pt_crashdumpmap, crashdumpmap, MAXDUMPPGS);

	/*
	 * ptvmmap is used for reading arbitrary physical pages via
	 * /dev/mem.
	 */
	SYSMAP(caddr_t, ptmmap, ptvmmap, 1)

	/*
	 * msgbufp is used to map the system message buffer.
	 * XXX msgbufmap is not used.
	 */
	SYSMAP(struct msgbuf *, msgbufmap, msgbufp,
	       atop(round_page(MSGBUF_SIZE)))

	virtual_start = va;

	*(int *) CMAP1 = 0;
	for (i = 0; i < NKPT; i++)
		PTD[i] = 0;

	/*
	 * PG_G is terribly broken on SMP because we IPI invltlb's in some
	 * cases rather then invl1pg.  Actually, I don't even know why it
	 * works under UP because self-referential page table mappings
	 */
#ifdef SMP
	pgeflag = 0;
#else
	if (cpu_feature & CPUID_PGE)
		pgeflag = PG_G;
#endif
	
/*
 * Initialize the 4MB page size flag
 */
	pseflag = 0;
/*
 * The 4MB page version of the initial
 * kernel page mapping.
 */
	pdir4mb = 0;

#if !defined(DISABLE_PSE)
	if (cpu_feature & CPUID_PSE) {
		unsigned ptditmp;
		/*
		 * Note that we have enabled PSE mode
		 */
		pseflag = PG_PS;
		ptditmp = *((unsigned *)PTmap + i386_btop(KERNBASE));
		ptditmp &= ~(NBPDR - 1);
		ptditmp |= PG_V | PG_RW | PG_PS | PG_U | pgeflag;
		pdir4mb = ptditmp;

#ifndef SMP
		/*
		 * Enable the PSE mode.  If we are SMP we can't do this
		 * now because the APs will not be able to use it when
		 * they boot up.
		 */
		load_cr4(rcr4() | CR4_PSE);

		/*
		 * We can do the mapping here for the single processor
		 * case.  We simply ignore the old page table page from
		 * now on.
		 */
		/*
		 * For SMP, we still need 4K pages to bootstrap APs,
		 * PSE will be enabled as soon as all APs are up.
		 */
		PTD[KPTDI] = (pd_entry_t)ptditmp;
		kernel_pmap.pm_pdir[KPTDI] = (pd_entry_t)ptditmp;
		cpu_invltlb();
#endif
	}
#endif

	/*
	 * We need to finish setting up the globaldata page for the BSP.
	 * locore has already populated the page table for the mdglobaldata
	 * portion.
	 */
	pg = MDGLOBALDATA_BASEALLOC_PAGES;
	gd = &CPU_prvspace[0].mdglobaldata;
	gd->gd_CMAP1 = &SMPpt[pg + 0];
	gd->gd_CMAP2 = &SMPpt[pg + 1];
	gd->gd_CMAP3 = &SMPpt[pg + 2];
	gd->gd_PMAP1 = &SMPpt[pg + 3];
	gd->gd_GDMAP1 = &PTD[APTDPTDI];
	gd->gd_CADDR1 = CPU_prvspace[0].CPAGE1;
	gd->gd_CADDR2 = CPU_prvspace[0].CPAGE2;
	gd->gd_CADDR3 = CPU_prvspace[0].CPAGE3;
	gd->gd_PADDR1 = (unsigned *)CPU_prvspace[0].PPAGE1;
	gd->gd_GDADDR1= (unsigned *)VADDR(APTDPTDI, 0);

	cpu_invltlb();
}

#ifdef SMP
/*
 * Set 4mb pdir for mp startup
 */
void
pmap_set_opt(void)
{
	if (pseflag && (cpu_feature & CPUID_PSE)) {
		load_cr4(rcr4() | CR4_PSE);
		if (pdir4mb && mycpu->gd_cpuid == 0) {	/* only on BSP */
			kernel_pmap.pm_pdir[KPTDI] =
			    PTD[KPTDI] = (pd_entry_t)pdir4mb;
			cpu_invltlb();
		}
	}
}
#endif

/*
 * Initialize the pmap module, called by vm_init()
 *
 * Called from the low level boot code only.
 */
void
pmap_init(void)
{
	int i;
	int initial_pvs;

	/*
	 * object for kernel page table pages
	 */
	kptobj = vm_object_allocate(OBJT_DEFAULT, NKPDE);

	/*
	 * Allocate memory for random pmap data structures.  Includes the
	 * pv_head_table.
	 */

	for(i = 0; i < vm_page_array_size; i++) {
		vm_page_t m;

		m = &vm_page_array[i];
		TAILQ_INIT(&m->md.pv_list);
		m->md.pv_list_count = 0;
	}

	/*
	 * init the pv free list
	 */
	initial_pvs = vm_page_array_size;
	if (initial_pvs < MINPV)
		initial_pvs = MINPV;
	pvzone = &pvzone_store;
	pvinit = (void *)kmem_alloc(&kernel_map,
				    initial_pvs * sizeof (struct pv_entry));
	zbootinit(pvzone, "PV ENTRY", sizeof (struct pv_entry),
		  pvinit, initial_pvs);

	/*
	 * Now it is safe to enable pv_table recording.
	 */
	pmap_initialized = TRUE;
}

/*
 * Initialize the address space (zone) for the pv_entries.  Set a
 * high water mark so that the system can recover from excessive
 * numbers of pv entries.
 *
 * Called from the low level boot code only.
 */
void
pmap_init2(void)
{
	int shpgperproc = PMAP_SHPGPERPROC;
	int entry_max;

	TUNABLE_INT_FETCH("vm.pmap.shpgperproc", &shpgperproc);
	pv_entry_max = shpgperproc * maxproc + vm_page_array_size;

#ifdef PMAP_PVLIMIT
	/*
	 * Horrible hack for systems with a lot of memory running i386.
	 * the calculated pv_entry_max can wind up eating a ton of KVM
	 * so put a cap on the number of entries if the user did not
	 * change any of the values.   This saves about 44MB of KVM on
	 * boxes with 3+GB of ram.
	 *
	 * On the flip side, this makes it more likely that some setups
	 * will run out of pv entries.  Those sysads will have to bump
	 * the limit up with vm.pamp.pv_entries or vm.pmap.shpgperproc.
	 */
	if (shpgperproc == PMAP_SHPGPERPROC) {
		if (pv_entry_max > PMAP_PVLIMIT)
			pv_entry_max = PMAP_PVLIMIT;
	}
#endif
	TUNABLE_INT_FETCH("vm.pmap.pv_entries", &pv_entry_max);
	pv_entry_high_water = 9 * (pv_entry_max / 10);

	/*
	 * Subtract out pages already installed in the zone (hack)
	 */
	entry_max = pv_entry_max - vm_page_array_size;
	if (entry_max <= 0)
		entry_max = 1;

	zinitna(pvzone, &pvzone_obj, NULL, 0, entry_max, ZONE_INTERRUPT, 1);
}


/***************************************************
 * Low level helper routines.....
 ***************************************************/

#ifdef PMAP_DEBUG

static void
test_m_maps_pv(vm_page_t m, pv_entry_t pv)
{
	pv_entry_t spv;

	crit_enter();
#ifdef PMAP_DEBUG
	KKASSERT(pv->pv_m == m);
#endif
	TAILQ_FOREACH(spv, &m->md.pv_list, pv_list) {
		if (pv == spv) {
			crit_exit();
			return;
		}
	}
	crit_exit();
	panic("test_m_maps_pv: failed m %p pv %p\n", m, pv);
}

static void
ptbase_assert(struct pmap *pmap)
{
	unsigned frame = (unsigned) pmap->pm_pdir[PTDPTDI] & PG_FRAME;

	/* are we current address space or kernel? */
	if (pmap == &kernel_pmap || frame == (((unsigned)PTDpde) & PG_FRAME))
		return;
	KKASSERT(frame == (*mdcpu->gd_GDMAP1 & PG_FRAME));
}

#else

#define test_m_maps_pv(m, pv)
#define ptbase_assert(pmap)

#endif

#if defined(PMAP_DIAGNOSTIC)

/*
 * This code checks for non-writeable/modified pages.
 * This should be an invalid condition.
 */
static int
pmap_nw_modified(pt_entry_t ptea)
{
	int pte;

	pte = (int) ptea;

	if ((pte & (PG_M|PG_RW)) == PG_M)
		return 1;
	else
		return 0;
}
#endif


/*
 * This routine defines the region(s) of memory that should not be tested
 * for the modified bit.
 *
 * No requirements.
 */
static PMAP_INLINE int
pmap_track_modified(vm_offset_t va)
{
	if ((va < clean_sva) || (va >= clean_eva)) 
		return 1;
	else
		return 0;
}

/*
 * Retrieve the mapped page table base for a particular pmap.  Use our self
 * mapping for the kernel_pmap or our current pmap.
 *
 * For foreign pmaps we use the per-cpu page table map.  Since this involves
 * installing a ptd it's actually (per-process x per-cpu).  However, we
 * still cannot depend on our mapping to survive thread switches because
 * the process might be threaded and switching to another thread for the
 * same process on the same cpu will allow that other thread to make its
 * own mapping.
 *
 * This could be a bit confusing but the jist is for something like the
 * vkernel which uses foreign pmaps all the time this represents a pretty
 * good cache that avoids unnecessary invltlb()s.
 *
 * The caller must hold vm_token and the returned value is only valid
 * until the caller blocks or releases the token.
 */
static unsigned *
get_ptbase(pmap_t pmap)
{
	unsigned frame = (unsigned) pmap->pm_pdir[PTDPTDI] & PG_FRAME;
	struct mdglobaldata *gd = mdcpu;

	ASSERT_LWKT_TOKEN_HELD(&vm_token);

	/*
	 * We can use PTmap if the pmap is our current address space or
	 * the kernel address space.
	 */
	if (pmap == &kernel_pmap || frame == (((unsigned) PTDpde) & PG_FRAME)) {
		return (unsigned *) PTmap;
	}

	/*
	 * Otherwise we use the per-cpu alternative page table map.  Each
	 * cpu gets its own map.  Because of this we cannot use this map
	 * from interrupts or threads which can preempt.
	 *
	 * Even if we already have the map cached we may still have to
	 * invalidate the TLB if another cpu modified a PDE in the map.
	 */
	KKASSERT(gd->mi.gd_intr_nesting_level == 0 &&
		 (gd->mi.gd_curthread->td_flags & TDF_INTTHREAD) == 0);

	if ((*gd->gd_GDMAP1 & PG_FRAME) != frame) {
		*gd->gd_GDMAP1 = frame | PG_RW | PG_V;
		pmap->pm_cached |= gd->mi.gd_cpumask;
		cpu_invltlb();
	} else if ((pmap->pm_cached & gd->mi.gd_cpumask) == 0) {
		pmap->pm_cached |= gd->mi.gd_cpumask;
		cpu_invltlb();
	} else if (dreadful_invltlb) {
		cpu_invltlb();
	}
	return ((unsigned *)gd->gd_GDADDR1);
}

/*
 * pmap_extract:
 *
 * Extract the physical page address associated with the map/VA pair.
 *
 * The caller may hold vm_token if it desires non-blocking operation.
 */
vm_paddr_t 
pmap_extract(pmap_t pmap, vm_offset_t va)
{
	vm_offset_t rtval;
	vm_offset_t pdirindex;

	lwkt_gettoken(&vm_token);
	pdirindex = va >> PDRSHIFT;
	if (pmap && (rtval = (unsigned) pmap->pm_pdir[pdirindex])) {
		unsigned *pte;
		if ((rtval & PG_PS) != 0) {
			rtval &= ~(NBPDR - 1);
			rtval |= va & (NBPDR - 1);
		} else {
			pte = get_ptbase(pmap) + i386_btop(va);
			rtval = ((*pte & PG_FRAME) | (va & PAGE_MASK));
		}
	} else {
		rtval = 0;
	}
	lwkt_reltoken(&vm_token);
	return rtval;
}

/***************************************************
 * Low level mapping routines.....
 ***************************************************/

/*
 * Map a wired VM page to a KVA, fully SMP synchronized.
 *
 * No requirements, non blocking.
 */
void 
pmap_kenter(vm_offset_t va, vm_paddr_t pa)
{
	unsigned *pte;
	unsigned npte;
	pmap_inval_info info;

	pmap_inval_init(&info);
	npte = pa | PG_RW | PG_V | pgeflag;
	pte = (unsigned *)vtopte(va);
	pmap_inval_interlock(&info, &kernel_pmap, va);
	*pte = npte;
	pmap_inval_deinterlock(&info, &kernel_pmap);
	pmap_inval_done(&info);
}

/*
 * Map a wired VM page to a KVA, synchronized on current cpu only.
 *
 * No requirements, non blocking.
 */
void
pmap_kenter_quick(vm_offset_t va, vm_paddr_t pa)
{
	unsigned *pte;
	unsigned npte;

	npte = pa | PG_RW | PG_V | pgeflag;
	pte = (unsigned *)vtopte(va);
	*pte = npte;
	cpu_invlpg((void *)va);
}

/*
 * Synchronize a previously entered VA on all cpus.
 *
 * No requirements, non blocking.
 */
void
pmap_kenter_sync(vm_offset_t va)
{
	pmap_inval_info info;

	pmap_inval_init(&info);
	pmap_inval_interlock(&info, &kernel_pmap, va);
	pmap_inval_deinterlock(&info, &kernel_pmap);
	pmap_inval_done(&info);
}

/*
 * Synchronize a previously entered VA on the current cpu only.
 *
 * No requirements, non blocking.
 */
void
pmap_kenter_sync_quick(vm_offset_t va)
{
	cpu_invlpg((void *)va);
}

/*
 * Remove a page from the kernel pagetables, fully SMP synchronized.
 *
 * No requirements, non blocking.
 */
void
pmap_kremove(vm_offset_t va)
{
	unsigned *pte;
	pmap_inval_info info;

	pmap_inval_init(&info);
	pte = (unsigned *)vtopte(va);
	pmap_inval_interlock(&info, &kernel_pmap, va);
	*pte = 0;
	pmap_inval_deinterlock(&info, &kernel_pmap);
	pmap_inval_done(&info);
}

/*
 * Remove a page from the kernel pagetables, synchronized on current cpu only.
 *
 * No requirements, non blocking.
 */
void
pmap_kremove_quick(vm_offset_t va)
{
	unsigned *pte;
	pte = (unsigned *)vtopte(va);
	*pte = 0;
	cpu_invlpg((void *)va);
}

/*
 * Adjust the permissions of a page in the kernel page table,
 * synchronized on the current cpu only.
 *
 * No requirements, non blocking.
 */
void
pmap_kmodify_rw(vm_offset_t va)
{
	atomic_set_int(vtopte(va), PG_RW);
	cpu_invlpg((void *)va);
}

/*
 * Adjust the permissions of a page in the kernel page table,
 * synchronized on the current cpu only.
 *
 * No requirements, non blocking.
 */
void
pmap_kmodify_nc(vm_offset_t va)
{
	atomic_set_int(vtopte(va), PG_N);
	cpu_invlpg((void *)va);
}

/*
 * Map a range of physical addresses into kernel virtual address space.
 *
 * No requirements, non blocking.
 */
vm_offset_t
pmap_map(vm_offset_t *virtp, vm_paddr_t start, vm_paddr_t end, int prot)
{
	vm_offset_t	sva, virt;

	sva = virt = *virtp;
	while (start < end) {
		pmap_kenter(virt, start);
		virt += PAGE_SIZE;
		start += PAGE_SIZE;
	}
	*virtp = virt;
	return (sva);
}

/*
 * Add a list of wired pages to the kva, fully SMP synchronized.
 *
 * No requirements, non blocking.
 */
void
pmap_qenter(vm_offset_t va, vm_page_t *m, int count)
{
	vm_offset_t end_va;

	end_va = va + count * PAGE_SIZE;
		
	while (va < end_va) {
		unsigned *pte;

		pte = (unsigned *)vtopte(va);
		*pte = VM_PAGE_TO_PHYS(*m) | PG_RW | PG_V | pgeflag;
		cpu_invlpg((void *)va);
		va += PAGE_SIZE;
		m++;
	}
#ifdef SMP
	smp_invltlb();	/* XXX */
#endif
}

/*
 * Remove pages from KVA, fully SMP synchronized.
 *
 * No requirements, non blocking.
 */
void
pmap_qremove(vm_offset_t va, int count)
{
	vm_offset_t end_va;

	end_va = va + count*PAGE_SIZE;

	while (va < end_va) {
		unsigned *pte;

		pte = (unsigned *)vtopte(va);
		*pte = 0;
		cpu_invlpg((void *)va);
		va += PAGE_SIZE;
	}
#ifdef SMP
	smp_invltlb();
#endif
}

/*
 * This routine works like vm_page_lookup() but also blocks as long as the
 * page is busy.  This routine does not busy the page it returns.
 *
 * The caller must hold the object.
 */
static vm_page_t
pmap_page_lookup(vm_object_t object, vm_pindex_t pindex)
{
	vm_page_t m;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(object));
	m = vm_page_lookup_busy_wait(object, pindex, FALSE, "pplookp");

	return(m);
}

/*
 * Create a new thread and optionally associate it with a (new) process.
 * NOTE! the new thread's cpu may not equal the current cpu.
 */
void
pmap_init_thread(thread_t td)
{
	/* enforce pcb placement */
	td->td_pcb = (struct pcb *)(td->td_kstack + td->td_kstack_size) - 1;
	td->td_savefpu = &td->td_pcb->pcb_save;
	td->td_sp = (char *)td->td_pcb - 16;
}

/*
 * This routine directly affects the fork perf for a process.
 */
void
pmap_init_proc(struct proc *p)
{
}

/*
 * Dispose the UPAGES for a process that has exited.
 * This routine directly impacts the exit perf of a process.
 */
void
pmap_dispose_proc(struct proc *p)
{
	KASSERT(p->p_lock == 0, ("attempt to dispose referenced proc! %p", p));
}

/***************************************************
 * Page table page management routines.....
 ***************************************************/

/*
 * This routine unholds page table pages, and if the hold count
 * drops to zero, then it decrements the wire count.
 *
 * The caller must hold vm_token.
 * This function can block.
 */
static int 
_pmap_unwire_pte_hold(pmap_t pmap, vm_page_t m, pmap_inval_info_t info) 
{
	/* 
	 * Wait until we can busy the page ourselves.  We cannot have
	 * any active flushes if we block.
	 */
	vm_page_busy_wait(m, FALSE, "pmuwpt");
	KASSERT(m->queue == PQ_NONE,
		("_pmap_unwire_pte_hold: %p->queue != PQ_NONE", m));

	if (m->hold_count == 1) {
		/*
		 * Unmap the page table page.
		 *
		 * NOTE: We must clear pm_cached for all cpus, including
		 *	 the current one, when clearing a page directory
		 *	 entry.
		 */
		pmap_inval_interlock(info, pmap, -1);
		KKASSERT(pmap->pm_pdir[m->pindex]);
		pmap->pm_pdir[m->pindex] = 0;
		pmap->pm_cached = 0;
		pmap_inval_deinterlock(info, pmap);

		KKASSERT(pmap->pm_stats.resident_count > 0);
		--pmap->pm_stats.resident_count;

		if (pmap->pm_ptphint == m)
			pmap->pm_ptphint = NULL;

		/*
		 * This was our last hold, the page had better be unwired
		 * after we decrement wire_count.
		 * 
		 * FUTURE NOTE: shared page directory page could result in
		 * multiple wire counts.
		 */
		vm_page_unhold(m);
		--m->wire_count;
		KKASSERT(m->wire_count == 0);
		atomic_add_int(&vmstats.v_wire_count, -1);
		vm_page_flag_clear(m, PG_MAPPED | PG_WRITEABLE);
		vm_page_flash(m);
		vm_page_free_zero(m);
		return 1;
	} else {
		KKASSERT(m->hold_count > 1);
		vm_page_unhold(m);
		vm_page_wakeup(m);
		return 0;
	}
}

/*
 * The caller must hold vm_token.
 * This function can block.
 */
static PMAP_INLINE int
pmap_unwire_pte_hold(pmap_t pmap, vm_page_t m, pmap_inval_info_t info)
{
	KKASSERT(m->hold_count > 0);
	if (m->hold_count > 1) {
		vm_page_unhold(m);
		return 0;
	} else {
		return _pmap_unwire_pte_hold(pmap, m, info);
	}
}

/*
 * After removing a (user) page table entry, this routine is used to
 * conditionally free the page, and manage the hold/wire counts.
 *
 * The caller must hold vm_token.
 * This function can block regardless.
 */
static int
pmap_unuse_pt(pmap_t pmap, vm_offset_t va, vm_page_t mpte,
	      pmap_inval_info_t info)
{
	unsigned ptepindex;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(pmap->pm_pteobj));

	if (va >= UPT_MIN_ADDRESS)
		return 0;

	if (mpte == NULL) {
		ptepindex = (va >> PDRSHIFT);
		if (pmap->pm_ptphint &&
			(pmap->pm_ptphint->pindex == ptepindex)) {
			mpte = pmap->pm_ptphint;
		} else {
			mpte = pmap_page_lookup(pmap->pm_pteobj, ptepindex);
			pmap->pm_ptphint = mpte;
			vm_page_wakeup(mpte);
		}
	}

	return pmap_unwire_pte_hold(pmap, mpte, info);
}

/*
 * Initialize pmap0/vmspace0.  This pmap is not added to pmap_list because
 * it, and IdlePTD, represents the template used to update all other pmaps.
 *
 * On architectures where the kernel pmap is not integrated into the user
 * process pmap, this pmap represents the process pmap, not the kernel pmap.
 * kernel_pmap should be used to directly access the kernel_pmap.
 *
 * No requirements.
 */
void
pmap_pinit0(struct pmap *pmap)
{
	pmap->pm_pdir =
		(pd_entry_t *)kmem_alloc_pageable(&kernel_map, PAGE_SIZE);
	pmap_kenter((vm_offset_t)pmap->pm_pdir, (vm_offset_t) IdlePTD);
	pmap->pm_count = 1;
	pmap->pm_active = 0;
	pmap->pm_cached = 0;
	pmap->pm_ptphint = NULL;
	TAILQ_INIT(&pmap->pm_pvlist);
	TAILQ_INIT(&pmap->pm_pvlist_free);
	spin_init(&pmap->pm_spin);
	lwkt_token_init(&pmap->pm_token, "pmap_tok");
	bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
}

/*
 * Initialize a preallocated and zeroed pmap structure,
 * such as one in a vmspace structure.
 *
 * No requirements.
 */
void
pmap_pinit(struct pmap *pmap)
{
	vm_page_t ptdpg;

	/*
	 * No need to allocate page table space yet but we do need a valid
	 * page directory table.
	 */
	if (pmap->pm_pdir == NULL) {
		pmap->pm_pdir =
		    (pd_entry_t *)kmem_alloc_pageable(&kernel_map, PAGE_SIZE);
	}

	/*
	 * Allocate an object for the ptes
	 */
	if (pmap->pm_pteobj == NULL)
		pmap->pm_pteobj = vm_object_allocate(OBJT_DEFAULT, PTDPTDI + 1);

	/*
	 * Allocate the page directory page, unless we already have
	 * one cached.  If we used the cached page the wire_count will
	 * already be set appropriately.
	 */
	if ((ptdpg = pmap->pm_pdirm) == NULL) {
		ptdpg = vm_page_grab(pmap->pm_pteobj, PTDPTDI,
				     VM_ALLOC_NORMAL | VM_ALLOC_RETRY);
		pmap->pm_pdirm = ptdpg;
		vm_page_flag_clear(ptdpg, PG_MAPPED);
		vm_page_wire(ptdpg);
		ptdpg->valid = VM_PAGE_BITS_ALL;
		pmap_kenter((vm_offset_t)pmap->pm_pdir, VM_PAGE_TO_PHYS(ptdpg));
		vm_page_wakeup(ptdpg);
	}
	if ((ptdpg->flags & PG_ZERO) == 0)
		bzero(pmap->pm_pdir, PAGE_SIZE);
#ifdef PMAP_DEBUG
	else
		pmap_page_assertzero(VM_PAGE_TO_PHYS(ptdpg));
#endif

	pmap->pm_pdir[MPPTDI] = PTD[MPPTDI];

	/* install self-referential address mapping entry */
	*(unsigned *) (pmap->pm_pdir + PTDPTDI) =
		VM_PAGE_TO_PHYS(ptdpg) | PG_V | PG_RW | PG_A | PG_M;

	pmap->pm_count = 1;
	pmap->pm_active = 0;
	pmap->pm_cached = 0;
	pmap->pm_ptphint = NULL;
	TAILQ_INIT(&pmap->pm_pvlist);
	TAILQ_INIT(&pmap->pm_pvlist_free);
	spin_init(&pmap->pm_spin);
	lwkt_token_init(&pmap->pm_token, "pmap_tok");
	bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
	pmap->pm_stats.resident_count = 1;
}

/*
 * Clean up a pmap structure so it can be physically freed.  This routine
 * is called by the vmspace dtor function.  A great deal of pmap data is
 * left passively mapped to improve vmspace management so we have a bit
 * of cleanup work to do here.
 *
 * No requirements.
 */
void
pmap_puninit(pmap_t pmap)
{
	vm_page_t p;

	KKASSERT(pmap->pm_active == 0);
	if ((p = pmap->pm_pdirm) != NULL) {
		KKASSERT(pmap->pm_pdir != NULL);
		pmap_kremove((vm_offset_t)pmap->pm_pdir);
		vm_page_busy_wait(p, FALSE, "pgpun");
		p->wire_count--;
		atomic_add_int(&vmstats.v_wire_count, -1);
		vm_page_free_zero(p);
		pmap->pm_pdirm = NULL;
	}
	if (pmap->pm_pdir) {
		kmem_free(&kernel_map, (vm_offset_t)pmap->pm_pdir, PAGE_SIZE);
		pmap->pm_pdir = NULL;
	}
	if (pmap->pm_pteobj) {
		vm_object_deallocate(pmap->pm_pteobj);
		pmap->pm_pteobj = NULL;
	}
}

/*
 * Wire in kernel global address entries.  To avoid a race condition
 * between pmap initialization and pmap_growkernel, this procedure
 * adds the pmap to the master list (which growkernel scans to update),
 * then copies the template.
 *
 * No requirements.
 */
void
pmap_pinit2(struct pmap *pmap)
{
	/*
	 * XXX copies current process, does not fill in MPPTDI
	 */
	spin_lock(&pmap_spin);
	TAILQ_INSERT_TAIL(&pmap_list, pmap, pm_pmnode);
	bcopy(PTD + KPTDI, pmap->pm_pdir + KPTDI, nkpt * PTESIZE);
	spin_unlock(&pmap_spin);
}

/*
 * Attempt to release and free a vm_page in a pmap.  Returns 1 on success,
 * 0 on failure (if the procedure had to sleep).
 *
 * When asked to remove the page directory page itself, we actually just
 * leave it cached so we do not have to incur the SMP inval overhead of
 * removing the kernel mapping.  pmap_puninit() will take care of it.
 *
 * The caller must hold vm_token.
 * This function can block regardless.
 */
static int
pmap_release_free_page(struct pmap *pmap, vm_page_t p)
{
	unsigned *pde = (unsigned *) pmap->pm_pdir;

	/*
	 * This code optimizes the case of freeing non-busy
	 * page-table pages.  Those pages are zero now, and
	 * might as well be placed directly into the zero queue.
	 */
	if (vm_page_busy_try(p, FALSE)) {
		vm_page_sleep_busy(p, FALSE, "pmaprl");
		return 0;
	}

	/*
	 * Remove the page table page from the processes address space.
	 */
	KKASSERT(pmap->pm_stats.resident_count > 0);
	KKASSERT(pde[p->pindex]);
	pde[p->pindex] = 0;
	--pmap->pm_stats.resident_count;
	pmap->pm_cached = 0;

	if (p->hold_count)  {
		panic("pmap_release: freeing held page table page");
	}
	if (pmap->pm_ptphint && (pmap->pm_ptphint->pindex == p->pindex))
		pmap->pm_ptphint = NULL;

	/*
	 * We leave the page directory page cached, wired, and mapped in
	 * the pmap until the dtor function (pmap_puninit()) gets called.
	 * However, still clean it up so we can set PG_ZERO.
	 *
	 * The pmap has already been removed from the pmap_list in the
	 * PTDPTDI case.
	 */
	if (p->pindex == PTDPTDI) {
		bzero(pde + KPTDI, nkpt * PTESIZE);
		bzero(pde + MPPTDI, (NPDEPG - MPPTDI) * PTESIZE);
		vm_page_flag_set(p, PG_ZERO);
		vm_page_wakeup(p);
	} else {
		p->wire_count--;
		atomic_add_int(&vmstats.v_wire_count, -1);
		vm_page_free_zero(p);
	}
	return 1;
}

/*
 * This routine is called if the page table page is not mapped correctly.
 *
 * The caller must hold vm_token.
 */
static vm_page_t
_pmap_allocpte(pmap_t pmap, unsigned ptepindex)
{
	vm_offset_t pteva, ptepa;
	vm_page_t m;

	/*
	 * Find or fabricate a new pagetable page
	 */
	m = vm_page_grab(pmap->pm_pteobj, ptepindex,
			VM_ALLOC_NORMAL | VM_ALLOC_ZERO | VM_ALLOC_RETRY);

	KASSERT(m->queue == PQ_NONE,
		("_pmap_allocpte: %p->queue != PQ_NONE", m));

	/*
	 * Increment the hold count for the page we will be returning to
	 * the caller.
	 */
	m->hold_count++;

	/*
	 * It is possible that someone else got in and mapped by the page
	 * directory page while we were blocked, if so just unbusy and
	 * return the held page.
	 */
	if ((ptepa = pmap->pm_pdir[ptepindex]) != 0) {
		KKASSERT((ptepa & PG_FRAME) == VM_PAGE_TO_PHYS(m));
		vm_page_wakeup(m);
		return(m);
	}

	if (m->wire_count == 0)
		atomic_add_int(&vmstats.v_wire_count, 1);
	m->wire_count++;


	/*
	 * Map the pagetable page into the process address space, if
	 * it isn't already there.
	 *
	 * NOTE: For safety clear pm_cached for all cpus including the
	 * 	 current one when adding a PDE to the map.
	 */
	++pmap->pm_stats.resident_count;

	ptepa = VM_PAGE_TO_PHYS(m);
	pmap->pm_pdir[ptepindex] =
		(pd_entry_t) (ptepa | PG_U | PG_RW | PG_V | PG_A | PG_M);
	pmap->pm_cached = 0;

	/*
	 * Set the page table hint
	 */
	pmap->pm_ptphint = m;

	/*
	 * Try to use the new mapping, but if we cannot, then
	 * do it with the routine that maps the page explicitly.
	 */
	if (m->valid == 0) {
		if ((m->flags & PG_ZERO) == 0) {
			if ((((unsigned)pmap->pm_pdir[PTDPTDI]) & PG_FRAME) ==
				(((unsigned) PTDpde) & PG_FRAME)) {
				pteva = UPT_MIN_ADDRESS + i386_ptob(ptepindex);
				bzero((caddr_t) pteva, PAGE_SIZE);
			} else {
				pmap_zero_page(ptepa);
			}
		}
		m->valid = VM_PAGE_BITS_ALL;
		vm_page_flag_clear(m, PG_ZERO);
	} else {
		KKASSERT((m->flags & PG_ZERO) == 0);
	}

	vm_page_flag_set(m, PG_MAPPED);
	vm_page_wakeup(m);

	return m;
}

/*
 * Allocate a page table entry for a va.
 *
 * The caller must hold vm_token.
 */
static vm_page_t
pmap_allocpte(pmap_t pmap, vm_offset_t va)
{
	unsigned ptepindex;
	vm_offset_t ptepa;
	vm_page_t m;

	ASSERT_LWKT_TOKEN_HELD(vm_object_token(pmap->pm_pteobj));

	/*
	 * Calculate pagetable page index
	 */
	ptepindex = va >> PDRSHIFT;

	/*
	 * Get the page directory entry
	 */
	ptepa = (vm_offset_t) pmap->pm_pdir[ptepindex];

	/*
	 * This supports switching from a 4MB page to a
	 * normal 4K page.
	 */
	if (ptepa & PG_PS) {
		pmap->pm_pdir[ptepindex] = 0;
		ptepa = 0;
		cpu_invltlb();
		smp_invltlb();
	}

	/*
	 * If the page table page is mapped, we just increment the
	 * hold count, and activate it.
	 */
	if (ptepa) {
		/*
		 * In order to get the page table page, try the
		 * hint first.
		 */
		if (pmap->pm_ptphint &&
			(pmap->pm_ptphint->pindex == ptepindex)) {
			m = pmap->pm_ptphint;
		} else {
			m = pmap_page_lookup(pmap->pm_pteobj, ptepindex);
			pmap->pm_ptphint = m;
			vm_page_wakeup(m);
		}
		m->hold_count++;
		return m;
	}
	/*
	 * Here if the pte page isn't mapped, or if it has been deallocated.
	 */
	return _pmap_allocpte(pmap, ptepindex);
}


/***************************************************
 * Pmap allocation/deallocation routines.
 ***************************************************/

/*
 * Release any resources held by the given physical map.
 * Called when a pmap initialized by pmap_pinit is being released.
 * Should only be called if the map contains no valid mappings.
 *
 * Caller must hold pmap->pm_token
 */
static int pmap_release_callback(struct vm_page *p, void *data);

void
pmap_release(struct pmap *pmap)
{
	vm_object_t object = pmap->pm_pteobj;
	struct rb_vm_page_scan_info info;

	KASSERT(pmap->pm_active == 0,
		("pmap still active! %08x", pmap->pm_active));
#if defined(DIAGNOSTIC)
	if (object->ref_count != 1)
		panic("pmap_release: pteobj reference count != 1");
#endif
	
	info.pmap = pmap;
	info.object = object;

	spin_lock(&pmap_spin);
	TAILQ_REMOVE(&pmap_list, pmap, pm_pmnode);
	spin_unlock(&pmap_spin);

	vm_object_hold(object);
	do {
		info.error = 0;
		info.mpte = NULL;
		info.limit = object->generation;

		vm_page_rb_tree_RB_SCAN(&object->rb_memq, NULL, 
				        pmap_release_callback, &info);
		if (info.error == 0 && info.mpte) {
			if (!pmap_release_free_page(pmap, info.mpte))
				info.error = 1;
		}
	} while (info.error);
	vm_object_drop(object);

	pmap->pm_cached = 0;
}

/*
 * The caller must hold vm_token.
 */
static int
pmap_release_callback(struct vm_page *p, void *data)
{
	struct rb_vm_page_scan_info *info = data;

	if (p->pindex == PTDPTDI) {
		info->mpte = p;
		return(0);
	}
	if (!pmap_release_free_page(info->pmap, p)) {
		info->error = 1;
		return(-1);
	}
	if (info->object->generation != info->limit) {
		info->error = 1;
		return(-1);
	}
	return(0);
}

/*
 * Grow the number of kernel page table entries, if needed.
 *
 * No requirements.
 */
void
pmap_growkernel(vm_offset_t kstart, vm_offset_t kend)
{
	vm_offset_t addr = kend;
	struct pmap *pmap;
	vm_offset_t ptppaddr;
	vm_page_t nkpg;
	pd_entry_t newpdir;

	vm_object_hold(kptobj);
	if (kernel_vm_end == 0) {
		kernel_vm_end = KERNBASE;
		nkpt = 0;
		while (pdir_pde(PTD, kernel_vm_end)) {
			kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) &
					~(PAGE_SIZE * NPTEPG - 1);
			nkpt++;
		}
	}
	addr = (addr + PAGE_SIZE * NPTEPG) & ~(PAGE_SIZE * NPTEPG - 1);
	while (kernel_vm_end < addr) {
		if (pdir_pde(PTD, kernel_vm_end)) {
			kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) &
					~(PAGE_SIZE * NPTEPG - 1);
			continue;
		}

		/*
		 * This index is bogus, but out of the way
		 */
		nkpg = vm_page_alloc(kptobj, nkpt, VM_ALLOC_NORMAL |
						   VM_ALLOC_SYSTEM |
						   VM_ALLOC_INTERRUPT);
		if (nkpg == NULL)
			panic("pmap_growkernel: no memory to grow kernel");

		vm_page_wire(nkpg);
		ptppaddr = VM_PAGE_TO_PHYS(nkpg);
		pmap_zero_page(ptppaddr);
		newpdir = (pd_entry_t) (ptppaddr | PG_V | PG_RW | PG_A | PG_M);
		pdir_pde(PTD, kernel_vm_end) = newpdir;
		*pmap_pde(&kernel_pmap, kernel_vm_end) = newpdir;
		nkpt++;

		/*
		 * This update must be interlocked with pmap_pinit2.
		 */
		spin_lock(&pmap_spin);
		TAILQ_FOREACH(pmap, &pmap_list, pm_pmnode) {
			*pmap_pde(pmap, kernel_vm_end) = newpdir;
		}
		spin_unlock(&pmap_spin);
		kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) &
				~(PAGE_SIZE * NPTEPG - 1);
	}
	vm_object_drop(kptobj);
}

/*
 * Retire the given physical map from service.
 *
 * Should only be called if the map contains no valid mappings.
 *
 * No requirements.
 */
void
pmap_destroy(pmap_t pmap)
{
	if (pmap == NULL)
		return;

	lwkt_gettoken(&vm_token);
	if (--pmap->pm_count == 0) {
		pmap_release(pmap);
		panic("destroying a pmap is not yet implemented");
	}
	lwkt_reltoken(&vm_token);
}

/*
 * Add a reference to the specified pmap.
 *
 * No requirements.
 */
void
pmap_reference(pmap_t pmap)
{
	if (pmap) {
		lwkt_gettoken(&vm_token);
		++pmap->pm_count;
		lwkt_reltoken(&vm_token);
	}
}

/***************************************************
 * page management routines.
 ***************************************************/

/*
 * free the pv_entry back to the free list.  This function may be
 * called from an interrupt.
 *
 * The caller must hold vm_token.
 */
static PMAP_INLINE void
free_pv_entry(pv_entry_t pv)
{
#ifdef PMAP_DEBUG
	KKASSERT(pv->pv_m != NULL);
	pv->pv_m = NULL;
#endif
	pv_entry_count--;
	zfree(pvzone, pv);
}

/*
 * get a new pv_entry, allocating a block from the system
 * when needed.  This function may be called from an interrupt.
 *
 * The caller must hold vm_token.
 */
static pv_entry_t
get_pv_entry(void)
{
	pv_entry_count++;
	if (pv_entry_high_water &&
	    (pv_entry_count > pv_entry_high_water) &&
	    (pmap_pagedaemon_waken == 0)) {
		pmap_pagedaemon_waken = 1;
		wakeup (&vm_pages_needed);
	}
	return zalloc(pvzone);
}

/*
 * This routine is very drastic, but can save the system
 * in a pinch.
 *
 * No requirements.
 */
void
pmap_collect(void)
{
	int i;
	vm_page_t m;
	static int warningdone=0;

	if (pmap_pagedaemon_waken == 0)
		return;
	lwkt_gettoken(&vm_token);
	pmap_pagedaemon_waken = 0;

	if (warningdone < 5) {
		kprintf("pmap_collect: collecting pv entries -- "
			"suggest increasing PMAP_SHPGPERPROC\n");
		warningdone++;
	}

	for (i = 0; i < vm_page_array_size; i++) {
		m = &vm_page_array[i];
		if (m->wire_count || m->hold_count)
			continue;
		if (vm_page_busy_try(m, TRUE) == 0) {
			if (m->wire_count == 0 && m->hold_count == 0) {
				pmap_remove_all(m);
			}
			vm_page_wakeup(m);
		}
	}
	lwkt_reltoken(&vm_token);
}
	

/*
 * If it is the first entry on the list, it is actually
 * in the header and we must copy the following entry up
 * to the header.  Otherwise we must search the list for
 * the entry.  In either case we free the now unused entry.
 *
 * The caller must hold vm_token.
 */
static int
pmap_remove_entry(struct pmap *pmap, vm_page_t m, 
		  vm_offset_t va, pmap_inval_info_t info)
{
	pv_entry_t pv;
	int rtval;

	ASSERT_LWKT_TOKEN_HELD(&vm_token);
	if (m->md.pv_list_count < pmap->pm_stats.resident_count) {
		TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
			if (pmap == pv->pv_pmap && va == pv->pv_va) 
				break;
		}
	} else {
		TAILQ_FOREACH(pv, &pmap->pm_pvlist, pv_plist) {
#ifdef PMAP_DEBUG
			KKASSERT(pv->pv_pmap == pmap);
#endif
			if (va == pv->pv_va)
				break;
		}
	}
	KKASSERT(pv);

	rtval = 0;
	test_m_maps_pv(m, pv);
	TAILQ_REMOVE(&m->md.pv_list, pv, pv_list);
	m->md.pv_list_count--;
	atomic_add_int(&m->object->agg_pv_list_count, -1);
	if (TAILQ_EMPTY(&m->md.pv_list))
		vm_page_flag_clear(m, PG_MAPPED | PG_WRITEABLE);
	TAILQ_REMOVE(&pmap->pm_pvlist, pv, pv_plist);
	++pmap->pm_generation;
	vm_object_hold(pmap->pm_pteobj);
	rtval = pmap_unuse_pt(pmap, va, pv->pv_ptem, info);
	vm_object_drop(pmap->pm_pteobj);
	free_pv_entry(pv);

	return rtval;
}

/*
 * Create a pv entry for page at pa for (pmap, va).
 *
 * The caller must hold vm_token.
 */
static void
pmap_insert_entry(pmap_t pmap, vm_offset_t va, vm_page_t mpte, vm_page_t m)
{
	pv_entry_t pv;

	pv = get_pv_entry();
#ifdef PMAP_DEBUG
	KKASSERT(pv->pv_m == NULL);
	pv->pv_m = m;
#endif
	pv->pv_va = va;
	pv->pv_pmap = pmap;
	pv->pv_ptem = mpte;

	TAILQ_INSERT_TAIL(&pmap->pm_pvlist, pv, pv_plist);
	TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_list);
	++pmap->pm_generation;
	m->md.pv_list_count++;
	atomic_add_int(&m->object->agg_pv_list_count, 1);
}

/*
 * pmap_remove_pte: do the things to unmap a page in a process.
 *
 * The caller must hold vm_token.
 *
 * WARNING! As with most other pmap functions this one can block, so
 *	    callers using temporary page table mappings must reload
 *	    them.
 */
static int
pmap_remove_pte(struct pmap *pmap, unsigned *ptq, vm_offset_t va,
		pmap_inval_info_t info)
{
	unsigned oldpte;
	vm_page_t m;

	ptbase_assert(pmap);
	pmap_inval_interlock(info, pmap, va);
	ptbase_assert(pmap);
	oldpte = loadandclear(ptq);
	if (oldpte & PG_W)
		pmap->pm_stats.wired_count -= 1;
	pmap_inval_deinterlock(info, pmap);
	KKASSERT(oldpte);
	/*
	 * Machines that don't support invlpg, also don't support
	 * PG_G.  XXX PG_G is disabled for SMP so don't worry about
	 * the SMP case.
	 */
	if (oldpte & PG_G)
		cpu_invlpg((void *)va);
	KKASSERT(pmap->pm_stats.resident_count > 0);
	--pmap->pm_stats.resident_count;
	if (oldpte & PG_MANAGED) {
		m = PHYS_TO_VM_PAGE(oldpte);
		if (oldpte & PG_M) {
#if defined(PMAP_DIAGNOSTIC)
			if (pmap_nw_modified((pt_entry_t) oldpte)) {
				kprintf("pmap_remove: modified page not "
					"writable: va: %p, pte: 0x%lx\n",
					(void *)va, (long)oldpte);
			}
#endif
			if (pmap_track_modified(va))
				vm_page_dirty(m);
		}
		if (oldpte & PG_A)
			vm_page_flag_set(m, PG_REFERENCED);
		return pmap_remove_entry(pmap, m, va, info);
	} else {
		return pmap_unuse_pt(pmap, va, NULL, info);
	}

	return 0;
}

/*
 * Remove a single page from a process address space.
 *
 * The caller must hold vm_token.
 */
static void
pmap_remove_page(struct pmap *pmap, vm_offset_t va, pmap_inval_info_t info)
{
	unsigned *ptq;

	/*
	 * if there is no pte for this address, just skip it!!!  Otherwise
	 * get a local va for mappings for this pmap and remove the entry.
	 */
	if (*pmap_pde(pmap, va) != 0) {
		ptq = get_ptbase(pmap) + i386_btop(va);
		if (*ptq) {
			pmap_remove_pte(pmap, ptq, va, info);
			/* ptq invalid */
		}
	}
}

/*
 * Remove the given range of addresses from the specified map.
 *
 * It is assumed that the start and end are properly rounded to the page
 * size.
 *
 * No requirements.
 */
void
pmap_remove(struct pmap *pmap, vm_offset_t sva, vm_offset_t eva)
{
	unsigned *ptbase;
	vm_offset_t pdnxt;
	vm_offset_t ptpaddr;
	vm_offset_t sindex, eindex;
	struct pmap_inval_info info;

	if (pmap == NULL)
		return;

	vm_object_hold(pmap->pm_pteobj);
	lwkt_gettoken(&vm_token);
	if (pmap->pm_stats.resident_count == 0) {
		lwkt_reltoken(&vm_token);
		vm_object_drop(pmap->pm_pteobj);
		return;
	}

	pmap_inval_init(&info);

	/*
	 * special handling of removing one page.  a very
	 * common operation and easy to short circuit some
	 * code.
	 */
	if (((sva + PAGE_SIZE) == eva) && 
		(((unsigned) pmap->pm_pdir[(sva >> PDRSHIFT)] & PG_PS) == 0)) {
		pmap_remove_page(pmap, sva, &info);
		pmap_inval_done(&info);
		lwkt_reltoken(&vm_token);
		vm_object_drop(pmap->pm_pteobj);
		return;
	}

	/*
	 * Get a local virtual address for the mappings that are being
	 * worked with.
	 */
	sindex = i386_btop(sva);
	eindex = i386_btop(eva);

	for (; sindex < eindex; sindex = pdnxt) {
		unsigned pdirindex;

		/*
		 * Calculate index for next page table.
		 */
		pdnxt = ((sindex + NPTEPG) & ~(NPTEPG - 1));
		if (pmap->pm_stats.resident_count == 0)
			break;

		pdirindex = sindex / NPDEPG;
		if (((ptpaddr = (unsigned) pmap->pm_pdir[pdirindex]) & PG_PS) != 0) {
			pmap_inval_interlock(&info, pmap, -1);
			pmap->pm_pdir[pdirindex] = 0;
			pmap->pm_stats.resident_count -= NBPDR / PAGE_SIZE;
			pmap->pm_cached = 0;
			pmap_inval_deinterlock(&info, pmap);
			continue;
		}

		/*
		 * Weed out invalid mappings. Note: we assume that the page
		 * directory table is always allocated, and in kernel virtual.
		 */
		if (ptpaddr == 0)
			continue;

		/*
		 * Limit our scan to either the end of the va represented
		 * by the current page table page, or to the end of the
		 * range being removed.
		 */
		if (pdnxt > eindex) {
			pdnxt = eindex;
		}

		/*
		 * NOTE: pmap_remove_pte() can block and wipe the temporary
		 *	 ptbase.
		 */
		for (; sindex != pdnxt; sindex++) {
			vm_offset_t va;

			ptbase = get_ptbase(pmap);
			if (ptbase[sindex] == 0)
				continue;
			va = i386_ptob(sindex);
			if (pmap_remove_pte(pmap, ptbase + sindex, va, &info))
				break;
		}
	}
	pmap_inval_done(&info);
	lwkt_reltoken(&vm_token);
	vm_object_drop(pmap->pm_pteobj);
}

/*
 * Removes this physical page from all physical maps in which it resides.
 * Reflects back modify bits to the pager.
 *
 * No requirements.
 */
static void
pmap_remove_all(vm_page_t m)
{
	struct pmap_inval_info info;
	unsigned *pte, tpte;
	pv_entry_t pv;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return;

	pmap_inval_init(&info);
	while ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {
		KKASSERT(pv->pv_pmap->pm_stats.resident_count > 0);
		--pv->pv_pmap->pm_stats.resident_count;

		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_va);
		pmap_inval_interlock(&info, pv->pv_pmap, pv->pv_va);
		tpte = loadandclear(pte);
		if (tpte & PG_W)
			pv->pv_pmap->pm_stats.wired_count--;
		pmap_inval_deinterlock(&info, pv->pv_pmap);
		if (tpte & PG_A)
			vm_page_flag_set(m, PG_REFERENCED);
#ifdef PMAP_DEBUG
		KKASSERT(PHYS_TO_VM_PAGE(tpte) == m);
#endif

		/*
		 * Update the vm_page_t clean and reference bits.
		 */
		if (tpte & PG_M) {
#if defined(PMAP_DIAGNOSTIC)
			if (pmap_nw_modified((pt_entry_t) tpte)) {
				kprintf("pmap_remove_all: modified page "
					"not writable: va: %p, pte: 0x%lx\n",
					(void *)pv->pv_va, (long)tpte);
			}
#endif
			if (pmap_track_modified(pv->pv_va))
				vm_page_dirty(m);
		}
#ifdef PMAP_DEBUG
		KKASSERT(pv->pv_m == m);
#endif
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_list);
		TAILQ_REMOVE(&pv->pv_pmap->pm_pvlist, pv, pv_plist);
		++pv->pv_pmap->pm_generation;
		m->md.pv_list_count--;
		atomic_add_int(&m->object->agg_pv_list_count, -1);
		if (TAILQ_EMPTY(&m->md.pv_list))
			vm_page_flag_clear(m, PG_MAPPED | PG_WRITEABLE);
		vm_object_hold(pv->pv_pmap->pm_pteobj);
		pmap_unuse_pt(pv->pv_pmap, pv->pv_va, pv->pv_ptem, &info);
		vm_object_drop(pv->pv_pmap->pm_pteobj);
		free_pv_entry(pv);
	}
	KKASSERT((m->flags & (PG_MAPPED|PG_WRITEABLE)) == 0);
	pmap_inval_done(&info);
}

/*
 * Set the physical protection on the specified range of this map
 * as requested.
 *
 * No requirements.
 */
void
pmap_protect(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, vm_prot_t prot)
{
	unsigned *ptbase;
	vm_offset_t pdnxt, ptpaddr;
	vm_pindex_t sindex, eindex;
	pmap_inval_info info;

	if (pmap == NULL)
		return;

	if ((prot & VM_PROT_READ) == VM_PROT_NONE) {
		pmap_remove(pmap, sva, eva);
		return;
	}

	if (prot & VM_PROT_WRITE)
		return;

	lwkt_gettoken(&vm_token);
	pmap_inval_init(&info);

	ptbase = get_ptbase(pmap);

	sindex = i386_btop(sva);
	eindex = i386_btop(eva);

	for (; sindex < eindex; sindex = pdnxt) {
		unsigned pdirindex;

		pdnxt = ((sindex + NPTEPG) & ~(NPTEPG - 1));

		pdirindex = sindex / NPDEPG;
		if (((ptpaddr = (unsigned) pmap->pm_pdir[pdirindex]) & PG_PS) != 0) {
			pmap_inval_interlock(&info, pmap, -1);
			pmap->pm_pdir[pdirindex] &= ~(PG_M|PG_RW);
			pmap->pm_stats.resident_count -= NBPDR / PAGE_SIZE;
			pmap_inval_deinterlock(&info, pmap);
			continue;
		}

		/*
		 * Weed out invalid mappings. Note: we assume that the page
		 * directory table is always allocated, and in kernel virtual.
		 */
		if (ptpaddr == 0)
			continue;

		if (pdnxt > eindex) {
			pdnxt = eindex;
		}

		for (; sindex != pdnxt; sindex++) {
			unsigned pbits;
			unsigned cbits;
			vm_page_t m;

			/*
			 * XXX non-optimal.
			 */
			pmap_inval_interlock(&info, pmap, i386_ptob(sindex));
again:
			pbits = ptbase[sindex];
			cbits = pbits;

			if (pbits & PG_MANAGED) {
				m = NULL;
				if (pbits & PG_A) {
					m = PHYS_TO_VM_PAGE(pbits);
					vm_page_flag_set(m, PG_REFERENCED);
					cbits &= ~PG_A;
				}
				if (pbits & PG_M) {
					if (pmap_track_modified(i386_ptob(sindex))) {
						if (m == NULL)
							m = PHYS_TO_VM_PAGE(pbits);
						vm_page_dirty(m);
						cbits &= ~PG_M;
					}
				}
			}
			cbits &= ~PG_RW;
			if (pbits != cbits &&
			    !atomic_cmpset_int(ptbase + sindex, pbits, cbits)) {
				goto again;
			}
			pmap_inval_deinterlock(&info, pmap);
		}
	}
	pmap_inval_done(&info);
	lwkt_reltoken(&vm_token);
}

/*
 * Insert the given physical page (p) at the specified virtual address (v)
 * in the target physical map with the protection requested.
 *
 * If specified, the page will be wired down, meaning that the related pte
 * cannot be reclaimed.
 *
 * No requirements.
 */
void
pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
	   boolean_t wired)
{
	vm_paddr_t pa;
	unsigned *pte;
	vm_paddr_t opa;
	vm_offset_t origpte, newpte;
	vm_page_t mpte;
	pmap_inval_info info;

	if (pmap == NULL)
		return;

	va &= PG_FRAME;
#ifdef PMAP_DIAGNOSTIC
	if (va >= KvaEnd)
		panic("pmap_enter: toobig");
	if ((va >= UPT_MIN_ADDRESS) && (va < UPT_MAX_ADDRESS)) {
		panic("pmap_enter: invalid to pmap_enter page "
		      "table pages (va: %p)", (void *)va);
	}
#endif
	if (va < UPT_MAX_ADDRESS && pmap == &kernel_pmap) {
		kprintf("Warning: pmap_enter called on UVA with kernel_pmap\n");
		print_backtrace(-1);
	}
	if (va >= UPT_MAX_ADDRESS && pmap != &kernel_pmap) {
		kprintf("Warning: pmap_enter called on KVA without kernel_pmap\n");
		print_backtrace(-1);
	}

	vm_object_hold(pmap->pm_pteobj);
	lwkt_gettoken(&vm_token);

	/*
	 * In the case that a page table page is not
	 * resident, we are creating it here.
	 */
	if (va < UPT_MIN_ADDRESS)
		mpte = pmap_allocpte(pmap, va);
	else
		mpte = NULL;

	if ((prot & VM_PROT_NOSYNC) == 0)
		pmap_inval_init(&info);
	pte = pmap_pte(pmap, va);

	/*
	 * Page Directory table entry not valid, we need a new PT page
	 */
	if (pte == NULL) {
		panic("pmap_enter: invalid page directory pdir=0x%lx, va=%p\n",
		     (long)pmap->pm_pdir[PTDPTDI], (void *)va);
	}

	pa = VM_PAGE_TO_PHYS(m) & PG_FRAME;
	origpte = *(vm_offset_t *)pte;
	opa = origpte & PG_FRAME;

	if (origpte & PG_PS)
		panic("pmap_enter: attempted pmap_enter on 4MB page");

	/*
	 * Mapping has not changed, must be protection or wiring change.
	 */
	if (origpte && (opa == pa)) {
		/*
		 * Wiring change, just update stats. We don't worry about
		 * wiring PT pages as they remain resident as long as there
		 * are valid mappings in them. Hence, if a user page is wired,
		 * the PT page will be also.
		 */
		if (wired && ((origpte & PG_W) == 0))
			pmap->pm_stats.wired_count++;
		else if (!wired && (origpte & PG_W))
			pmap->pm_stats.wired_count--;

#if defined(PMAP_DIAGNOSTIC)
		if (pmap_nw_modified((pt_entry_t) origpte)) {
			kprintf("pmap_enter: modified page not "
				"writable: va: %p, pte: 0x%lx\n",
				(void *)va, (long )origpte);
		}
#endif

		/*
		 * Remove the extra pte reference.  Note that we cannot
		 * optimize the RO->RW case because we have adjusted the
		 * wiring count above and may need to adjust the wiring
		 * bits below.
		 */
		if (mpte)
			mpte->hold_count--;

		/*
		 * We might be turning off write access to the page,
		 * so we go ahead and sense modify status.
		 */
		if (origpte & PG_MANAGED) {
			if ((origpte & PG_M) && pmap_track_modified(va)) {
				vm_page_t om;
				om = PHYS_TO_VM_PAGE(opa);
				vm_page_dirty(om);
			}
			pa |= PG_MANAGED;
			KKASSERT(m->flags & PG_MAPPED);
		}
		goto validate;
	} 
	/*
	 * Mapping has changed, invalidate old range and fall through to
	 * handle validating new mapping.
	 *
	 * Since we have a ref on the page directory page pmap_pte()
	 * will always return non-NULL.
	 *
	 * NOTE: pmap_remove_pte() can block and cause the temporary ptbase
	 *	 to get wiped.  reload the ptbase.  I'm not sure if it is
	 *	 also possible to race another pmap_enter() but check for
	 *	 that case too.
	 */
	while (opa) {
		int err;

		KKASSERT((origpte & PG_FRAME) ==
			 (*(vm_offset_t *)pte & PG_FRAME));
		err = pmap_remove_pte(pmap, pte, va, &info);
		if (err)
			panic("pmap_enter: pte vanished, va: %p", (void *)va);
		pte = pmap_pte(pmap, va);
		origpte = *(vm_offset_t *)pte;
		opa = origpte & PG_FRAME;
		if (opa) {
			kprintf("pmap_enter: Warning, raced pmap %p va %p\n",
				pmap, (void *)va);
		}
	}

	/*
	 * Enter on the PV list if part of our managed memory. Note that we
	 * raise IPL while manipulating pv_table since pmap_enter can be
	 * called at interrupt time.
	 */
	if (pmap_initialized && 
	    (m->flags & (PG_FICTITIOUS|PG_UNMANAGED)) == 0) {
		pmap_insert_entry(pmap, va, mpte, m);
		ptbase_assert(pmap);
		pa |= PG_MANAGED;
		vm_page_flag_set(m, PG_MAPPED);
	}

	/*
	 * Increment counters
	 */
	++pmap->pm_stats.resident_count;
	if (wired)
		pmap->pm_stats.wired_count++;
	KKASSERT(*pte == 0);

validate:
	/*
	 * Now validate mapping with desired protection/wiring.
	 */
	ptbase_assert(pmap);
	newpte = (vm_offset_t) (pa | pte_prot(pmap, prot) | PG_V);

	if (wired)
		newpte |= PG_W;
	if (va < UPT_MIN_ADDRESS)
		newpte |= PG_U;
	if (pmap == &kernel_pmap)
		newpte |= pgeflag;

	/*
	 * if the mapping or permission bits are different, we need
	 * to update the pte.
	 */
	if ((origpte & ~(PG_M|PG_A)) != newpte) {
		if (prot & VM_PROT_NOSYNC)
			cpu_invlpg((void *)va);
		else
			pmap_inval_interlock(&info, pmap, va);
		ptbase_assert(pmap);
		KKASSERT(*pte == 0 ||
			 (*pte & PG_FRAME) == (newpte & PG_FRAME));
		*pte = newpte | PG_A;
		if ((prot & VM_PROT_NOSYNC) == 0)
			pmap_inval_deinterlock(&info, pmap);
		if (newpte & PG_RW)
			vm_page_flag_set(m, PG_WRITEABLE);
	}
	KKASSERT((newpte & PG_MANAGED) == 0 || (m->flags & PG_MAPPED));
	if ((prot & VM_PROT_NOSYNC) == 0)
		pmap_inval_done(&info);
	lwkt_reltoken(&vm_token);
	vm_object_drop(pmap->pm_pteobj);
}

/*
 * This code works like pmap_enter() but assumes VM_PROT_READ and not-wired.
 * This code also assumes that the pmap has no pre-existing entry for this
 * VA.
 *
 * This code currently may only be used on user pmaps, not kernel_pmap.
 *
 * No requirements.
 */
void
pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m)
{
	unsigned *pte;
	vm_paddr_t pa;
	vm_page_t mpte;
	unsigned ptepindex;
	vm_offset_t ptepa;
	pmap_inval_info info;

	vm_object_hold(pmap->pm_pteobj);
	lwkt_gettoken(&vm_token);
	pmap_inval_init(&info);

	if (va < UPT_MAX_ADDRESS && pmap == &kernel_pmap) {
		kprintf("Warning: pmap_enter_quick called on UVA with kernel_pmap\n");
		print_backtrace(-1);
	}
	if (va >= UPT_MAX_ADDRESS && pmap != &kernel_pmap) {
		kprintf("Warning: pmap_enter_quick called on KVA without kernel_pmap\n");
		print_backtrace(-1);
	}

	KKASSERT(va < UPT_MIN_ADDRESS);	/* assert used on user pmaps only */

	/*
	 * Calculate the page table page (mpte), allocating it if necessary.
	 *
	 * A held page table page (mpte), or NULL, is passed onto the
	 * section following.
	 */
	if (va < UPT_MIN_ADDRESS) {
		/*
		 * Calculate pagetable page index
		 */
		ptepindex = va >> PDRSHIFT;

		do {
			/*
			 * Get the page directory entry
			 */
			ptepa = (vm_offset_t) pmap->pm_pdir[ptepindex];

			/*
			 * If the page table page is mapped, we just increment
			 * the hold count, and activate it.
			 */
			if (ptepa) {
				if (ptepa & PG_PS)
					panic("pmap_enter_quick: unexpected mapping into 4MB page");
				if (pmap->pm_ptphint &&
				    (pmap->pm_ptphint->pindex == ptepindex)) {
					mpte = pmap->pm_ptphint;
				} else {
					mpte = pmap_page_lookup(pmap->pm_pteobj, ptepindex);
					pmap->pm_ptphint = mpte;
					vm_page_wakeup(mpte);
				}
				if (mpte)
					mpte->hold_count++;
			} else {
				mpte = _pmap_allocpte(pmap, ptepindex);
			}
		} while (mpte == NULL);
	} else {
		mpte = NULL;
		/* this code path is not yet used */
	}

	/*
	 * With a valid (and held) page directory page, we can just use
	 * vtopte() to get to the pte.  If the pte is already present
	 * we do not disturb it.
	 */
	pte = (unsigned *)vtopte(va);
	if (*pte & PG_V) {
		if (mpte)
			pmap_unwire_pte_hold(pmap, mpte, &info);
		pa = VM_PAGE_TO_PHYS(m);
		KKASSERT(((*pte ^ pa) & PG_FRAME) == 0);
		pmap_inval_done(&info);
		lwkt_reltoken(&vm_token);
		vm_object_drop(pmap->pm_pteobj);
		return;
	}

	/*
	 * Enter on the PV list if part of our managed memory
	 */
	if ((m->flags & (PG_FICTITIOUS|PG_UNMANAGED)) == 0) {
		pmap_insert_entry(pmap, va, mpte, m);
		vm_page_flag_set(m, PG_MAPPED);
	}

	/*
	 * Increment counters
	 */
	++pmap->pm_stats.resident_count;

	pa = VM_PAGE_TO_PHYS(m);

	/*
	 * Now validate mapping with RO protection
	 */
	if (m->flags & (PG_FICTITIOUS|PG_UNMANAGED))
		*pte = pa | PG_V | PG_U;
	else
		*pte = pa | PG_V | PG_U | PG_MANAGED;
/*	pmap_inval_add(&info, pmap, va); shouldn't be needed inval->valid */
	pmap_inval_done(&info);
	lwkt_reltoken(&vm_token);
	vm_object_drop(pmap->pm_pteobj);
}

/*
 * Make a temporary mapping for a physical address.  This is only intended
 * to be used for panic dumps.
 *
 * The caller is responsible for calling smp_invltlb().
 *
 * No requirements.
 */
void *
pmap_kenter_temporary(vm_paddr_t pa, long i)
{
	pmap_kenter_quick((vm_offset_t)crashdumpmap + (i * PAGE_SIZE), pa);
	return ((void *)crashdumpmap);
}

#define MAX_INIT_PT (96)

/*
 * This routine preloads the ptes for a given object into the specified pmap.
 * This eliminates the blast of soft faults on process startup and
 * immediately after an mmap.
 *
 * No requirements.
 */
static int pmap_object_init_pt_callback(vm_page_t p, void *data);

void
pmap_object_init_pt(pmap_t pmap, vm_offset_t addr, vm_prot_t prot,
		    vm_object_t object, vm_pindex_t pindex, 
		    vm_size_t size, int limit)
{
	struct rb_vm_page_scan_info info;
	struct lwp *lp;
	int psize;

	/*
	 * We can't preinit if read access isn't set or there is no pmap
	 * or object.
	 */
	if ((prot & VM_PROT_READ) == 0 || pmap == NULL || object == NULL)
		return;

	/*
	 * We can't preinit if the pmap is not the current pmap
	 */
	lp = curthread->td_lwp;
	if (lp == NULL || pmap != vmspace_pmap(lp->lwp_vmspace))
		return;

	psize = i386_btop(size);

	if ((object->type != OBJT_VNODE) ||
		((limit & MAP_PREFAULT_PARTIAL) && (psize > MAX_INIT_PT) &&
			(object->resident_page_count > MAX_INIT_PT))) {
		return;
	}

	if (psize + pindex > object->size) {
		if (object->size < pindex)
			return;		  
		psize = object->size - pindex;
	}

	if (psize == 0)
		return;

	/*
	 * Use a red-black scan to traverse the requested range and load
	 * any valid pages found into the pmap.
	 *
	 * We cannot safely scan the object's memq unless we are in a
	 * critical section since interrupts can remove pages from objects.
	 */
	info.start_pindex = pindex;
	info.end_pindex = pindex + psize - 1;
	info.limit = limit;
	info.mpte = NULL;
	info.addr = addr;
	info.pmap = pmap;

	vm_object_hold(object);
	vm_page_rb_tree_RB_SCAN(&object->rb_memq, rb_vm_page_scancmp,
				pmap_object_init_pt_callback, &info);
	vm_object_drop(object);
}

/*
 * The caller must hold vm_token.
 */
static
int
pmap_object_init_pt_callback(vm_page_t p, void *data)
{
	struct rb_vm_page_scan_info *info = data;
	vm_pindex_t rel_index;
	/*
	 * don't allow an madvise to blow away our really
	 * free pages allocating pv entries.
	 */
	if ((info->limit & MAP_PREFAULT_MADVISE) &&
		vmstats.v_free_count < vmstats.v_free_reserved) {
		    return(-1);
	}
	if (vm_page_busy_try(p, TRUE))
		return 0;
	if (((p->valid & VM_PAGE_BITS_ALL) == VM_PAGE_BITS_ALL) &&
	    (p->flags & PG_FICTITIOUS) == 0) {
		if ((p->queue - p->pc) == PQ_CACHE)
			vm_page_deactivate(p);
		rel_index = p->pindex - info->start_pindex;
		pmap_enter_quick(info->pmap,
				 info->addr + i386_ptob(rel_index), p);
	}
	vm_page_wakeup(p);
	return(0);
}

/*
 * Return TRUE if the pmap is in shape to trivially
 * pre-fault the specified address.
 *
 * Returns FALSE if it would be non-trivial or if a
 * pte is already loaded into the slot.
 *
 * No requirements.
 */
int
pmap_prefault_ok(pmap_t pmap, vm_offset_t addr)
{
	unsigned *pte;
	int ret;

	lwkt_gettoken(&vm_token);
	if ((*pmap_pde(pmap, addr)) == 0) {
		ret = 0;
	} else {
		pte = (unsigned *) vtopte(addr);
		ret = (*pte) ? 0 : 1;
	}
	lwkt_reltoken(&vm_token);
	return(ret);
}

/*
 * Change the wiring attribute for a map/virtual-adderss pair.  The mapping
 * must already exist.
 *
 * No requirements.
 */
void
pmap_change_wiring(pmap_t pmap, vm_offset_t va, boolean_t wired)
{
	unsigned *pte;

	if (pmap == NULL)
		return;

	lwkt_gettoken(&vm_token);
	pte = pmap_pte(pmap, va);

	if (wired && !pmap_pte_w(pte))
		pmap->pm_stats.wired_count++;
	else if (!wired && pmap_pte_w(pte))
		pmap->pm_stats.wired_count--;

	/*
	 * Wiring is not a hardware characteristic so there is no need to
	 * invalidate TLB.  However, in an SMP environment we must use
	 * a locked bus cycle to update the pte (if we are not using 
	 * the pmap_inval_*() API that is)... it's ok to do this for simple
	 * wiring changes.
	 */
#ifdef SMP
	if (wired)
		atomic_set_int(pte, PG_W);
	else
		atomic_clear_int(pte, PG_W);
#else
	if (wired)
		atomic_set_int_nonlocked(pte, PG_W);
	else
		atomic_clear_int_nonlocked(pte, PG_W);
#endif
	lwkt_reltoken(&vm_token);
}

/*
 * Copy the range specified by src_addr/len from the source map to the
 * range dst_addr/len in the destination map.
 *
 * This routine is only advisory and need not do anything.
 *
 * No requirements.
 */
void
pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vm_offset_t dst_addr, 
	  vm_size_t len, vm_offset_t src_addr)
{
	/* does nothing */
}	

/*
 * Zero the specified PA by mapping the page into KVM and clearing its
 * contents.
 *
 * No requirements.
 */
void
pmap_zero_page(vm_paddr_t phys)
{
	struct mdglobaldata *gd = mdcpu;

	crit_enter();
	if (*(int *)gd->gd_CMAP3)
		panic("pmap_zero_page: CMAP3 busy");
	*(int *)gd->gd_CMAP3 =
		    PG_V | PG_RW | (phys & PG_FRAME) | PG_A | PG_M;
	cpu_invlpg(gd->gd_CADDR3);

#if defined(I686_CPU)
	if (cpu_class == CPUCLASS_686)
		i686_pagezero(gd->gd_CADDR3);
	else
#endif
		bzero(gd->gd_CADDR3, PAGE_SIZE);
	*(int *) gd->gd_CMAP3 = 0;
	crit_exit();
}

/*
 * Assert that a page is empty, panic if it isn't.
 *
 * No requirements.
 */
void
pmap_page_assertzero(vm_paddr_t phys)
{
	struct mdglobaldata *gd = mdcpu;
	int i;

	crit_enter();
	if (*(int *)gd->gd_CMAP3)
		panic("pmap_zero_page: CMAP3 busy");
	*(int *)gd->gd_CMAP3 =
		    PG_V | PG_RW | (phys & PG_FRAME) | PG_A | PG_M;
	cpu_invlpg(gd->gd_CADDR3);
	for (i = 0; i < PAGE_SIZE; i += 4) {
	    if (*(int *)((char *)gd->gd_CADDR3 + i) != 0) {
		panic("pmap_page_assertzero() @ %p not zero!\n",
		    (void *)gd->gd_CADDR3);
	    }
	}
	*(int *) gd->gd_CMAP3 = 0;
	crit_exit();
}

/*
 * Zero part of a physical page by mapping it into memory and clearing
 * its contents with bzero.
 *
 * off and size may not cover an area beyond a single hardware page.
 *
 * No requirements.
 */
void
pmap_zero_page_area(vm_paddr_t phys, int off, int size)
{
	struct mdglobaldata *gd = mdcpu;

	crit_enter();
	if (*(int *) gd->gd_CMAP3)
		panic("pmap_zero_page: CMAP3 busy");
	*(int *) gd->gd_CMAP3 = PG_V | PG_RW | (phys & PG_FRAME) | PG_A | PG_M;
	cpu_invlpg(gd->gd_CADDR3);

#if defined(I686_CPU)
	if (cpu_class == CPUCLASS_686 && off == 0 && size == PAGE_SIZE)
		i686_pagezero(gd->gd_CADDR3);
	else
#endif
		bzero((char *)gd->gd_CADDR3 + off, size);
	*(int *) gd->gd_CMAP3 = 0;
	crit_exit();
}

/*
 * Copy the physical page from the source PA to the target PA.
 * This function may be called from an interrupt.  No locking
 * is required.
 *
 * No requirements.
 */
void
pmap_copy_page(vm_paddr_t src, vm_paddr_t dst)
{
	struct mdglobaldata *gd = mdcpu;

	crit_enter();
	if (*(int *) gd->gd_CMAP1)
		panic("pmap_copy_page: CMAP1 busy");
	if (*(int *) gd->gd_CMAP2)
		panic("pmap_copy_page: CMAP2 busy");

	*(int *) gd->gd_CMAP1 = PG_V | (src & PG_FRAME) | PG_A;
	*(int *) gd->gd_CMAP2 = PG_V | PG_RW | (dst & PG_FRAME) | PG_A | PG_M;

	cpu_invlpg(gd->gd_CADDR1);
	cpu_invlpg(gd->gd_CADDR2);

	bcopy(gd->gd_CADDR1, gd->gd_CADDR2, PAGE_SIZE);

	*(int *) gd->gd_CMAP1 = 0;
	*(int *) gd->gd_CMAP2 = 0;
	crit_exit();
}

/*
 * Copy the physical page from the source PA to the target PA.
 * This function may be called from an interrupt.  No locking
 * is required.
 *
 * No requirements.
 */
void
pmap_copy_page_frag(vm_paddr_t src, vm_paddr_t dst, size_t bytes)
{
	struct mdglobaldata *gd = mdcpu;

	crit_enter();
	if (*(int *) gd->gd_CMAP1)
		panic("pmap_copy_page: CMAP1 busy");
	if (*(int *) gd->gd_CMAP2)
		panic("pmap_copy_page: CMAP2 busy");

	*(int *) gd->gd_CMAP1 = PG_V | (src & PG_FRAME) | PG_A;
	*(int *) gd->gd_CMAP2 = PG_V | PG_RW | (dst & PG_FRAME) | PG_A | PG_M;

	cpu_invlpg(gd->gd_CADDR1);
	cpu_invlpg(gd->gd_CADDR2);

	bcopy((char *)gd->gd_CADDR1 + (src & PAGE_MASK),
	      (char *)gd->gd_CADDR2 + (dst & PAGE_MASK),
	      bytes);

	*(int *) gd->gd_CMAP1 = 0;
	*(int *) gd->gd_CMAP2 = 0;
	crit_exit();
}

/*
 * Returns true if the pmap's pv is one of the first
 * 16 pvs linked to from this page.  This count may
 * be changed upwards or downwards in the future; it
 * is only necessary that true be returned for a small
 * subset of pmaps for proper page aging.
 *
 * No requirements.
 */
boolean_t
pmap_page_exists_quick(pmap_t pmap, vm_page_t m)
{
	pv_entry_t pv;
	int loops = 0;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return FALSE;

	lwkt_gettoken(&vm_token);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		if (pv->pv_pmap == pmap) {
			lwkt_reltoken(&vm_token);
			return TRUE;
		}
		loops++;
		if (loops >= 16)
			break;
	}
	lwkt_reltoken(&vm_token);
	return (FALSE);
}

/*
 * Remove all pages from specified address space
 * this aids process exit speeds.  Also, this code
 * is special cased for current process only, but
 * can have the more generic (and slightly slower)
 * mode enabled.  This is much faster than pmap_remove
 * in the case of running down an entire address space.
 *
 * No requirements.
 */
void
pmap_remove_pages(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	struct lwp *lp;
	unsigned *pte, tpte;
	pv_entry_t pv, npv;
	vm_page_t m;
	pmap_inval_info info;
	int iscurrentpmap;
	int32_t save_generation;

	lp = curthread->td_lwp;
	if (lp && pmap == vmspace_pmap(lp->lwp_vmspace))
		iscurrentpmap = 1;
	else
		iscurrentpmap = 0;

	if (pmap->pm_pteobj)
		vm_object_hold(pmap->pm_pteobj);
	lwkt_gettoken(&vm_token);
	pmap_inval_init(&info);

	for (pv = TAILQ_FIRST(&pmap->pm_pvlist); pv; pv = npv) {
		if (pv->pv_va >= eva || pv->pv_va < sva) {
			npv = TAILQ_NEXT(pv, pv_plist);
			continue;
		}

		KKASSERT(pmap == pv->pv_pmap);

		if (iscurrentpmap)
			pte = (unsigned *)vtopte(pv->pv_va);
		else
			pte = pmap_pte_quick(pmap, pv->pv_va);
		KKASSERT(*pte);
		pmap_inval_interlock(&info, pmap, pv->pv_va);

		/*
		 * We cannot remove wired pages from a process' mapping
		 * at this time
		 */
		if (*pte & PG_W) {
			pmap_inval_deinterlock(&info, pmap);
			npv = TAILQ_NEXT(pv, pv_plist);
			continue;
		}
		KKASSERT(*pte);
		tpte = loadandclear(pte);
		pmap_inval_deinterlock(&info, pmap);

		m = PHYS_TO_VM_PAGE(tpte);
		test_m_maps_pv(m, pv);

		KASSERT(m < &vm_page_array[vm_page_array_size],
			("pmap_remove_pages: bad tpte %x", tpte));

		KKASSERT(pmap->pm_stats.resident_count > 0);
		--pmap->pm_stats.resident_count;

		/*
		 * Update the vm_page_t clean and reference bits.
		 */
		if (tpte & PG_M) {
			vm_page_dirty(m);
		}

		npv = TAILQ_NEXT(pv, pv_plist);
#ifdef PMAP_DEBUG
		KKASSERT(pv->pv_m == m);
		KKASSERT(pv->pv_pmap == pmap);
#endif
		TAILQ_REMOVE(&pmap->pm_pvlist, pv, pv_plist);
		save_generation = ++pmap->pm_generation;

		m->md.pv_list_count--;
		atomic_add_int(&m->object->agg_pv_list_count, -1);
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_list);
		if (TAILQ_EMPTY(&m->md.pv_list))
			vm_page_flag_clear(m, PG_MAPPED | PG_WRITEABLE);

		pmap_unuse_pt(pmap, pv->pv_va, pv->pv_ptem, &info);
		free_pv_entry(pv);

		/*
		 * Restart the scan if we blocked during the unuse or free
		 * calls and other removals were made.
		 */
		if (save_generation != pmap->pm_generation) {
			kprintf("Warning: pmap_remove_pages race-A avoided\n");
			npv = TAILQ_FIRST(&pmap->pm_pvlist);
		}
	}
	pmap_inval_done(&info);
	lwkt_reltoken(&vm_token);
	if (pmap->pm_pteobj)
		vm_object_drop(pmap->pm_pteobj);
}

/*
 * pmap_testbit tests bits in pte's
 * note that the testbit/clearbit routines are inline,
 * and a lot of things compile-time evaluate.
 *
 * The caller must hold vm_token.
 */
static boolean_t
pmap_testbit(vm_page_t m, int bit)
{
	pv_entry_t pv;
	unsigned *pte;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return FALSE;

	if (TAILQ_FIRST(&m->md.pv_list) == NULL)
		return FALSE;

	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		/*
		 * if the bit being tested is the modified bit, then
		 * mark clean_map and ptes as never
		 * modified.
		 */
		if (bit & (PG_A|PG_M)) {
			if (!pmap_track_modified(pv->pv_va))
				continue;
		}

#if defined(PMAP_DIAGNOSTIC)
		if (!pv->pv_pmap) {
			kprintf("Null pmap (tb) at va: %p\n",
				(void *)pv->pv_va);
			continue;
		}
#endif
		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_va);
		if (*pte & bit) {
			return TRUE;
		}
	}
	return (FALSE);
}

/*
 * This routine is used to modify bits in ptes
 *
 * The caller must hold vm_token.
 */
static __inline void
pmap_clearbit(vm_page_t m, int bit)
{
	struct pmap_inval_info info;
	pv_entry_t pv;
	unsigned *pte;
	unsigned pbits;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return;

	pmap_inval_init(&info);

	/*
	 * Loop over all current mappings setting/clearing as appropos If
	 * setting RO do we need to clear the VAC?
	 */
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		/*
		 * don't write protect pager mappings
		 */
		if (bit == PG_RW) {
			if (!pmap_track_modified(pv->pv_va))
				continue;
		}

#if defined(PMAP_DIAGNOSTIC)
		if (!pv->pv_pmap) {
			kprintf("Null pmap (cb) at va: %p\n",
				(void *)pv->pv_va);
			continue;
		}
#endif

		/*
		 * Careful here.  We can use a locked bus instruction to
		 * clear PG_A or PG_M safely but we need to synchronize
		 * with the target cpus when we mess with PG_RW.
		 *
		 * We do not have to force synchronization when clearing
		 * PG_M even for PTEs generated via virtual memory maps,
		 * because the virtual kernel will invalidate the pmap
		 * entry when/if it needs to resynchronize the Modify bit.
		 */
		if (bit & PG_RW)
			pmap_inval_interlock(&info, pv->pv_pmap, pv->pv_va);
		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_va);
again:
		pbits = *pte;
		if (pbits & bit) {
			if (bit == PG_RW) {
				if (pbits & PG_M) {
					vm_page_dirty(m);
					atomic_clear_int(pte, PG_M|PG_RW);
				} else {
					/*
					 * The cpu may be trying to set PG_M
					 * simultaniously with our clearing
					 * of PG_RW.
					 */
					if (!atomic_cmpset_int(pte, pbits,
							       pbits & ~PG_RW))
						goto again;
				}
			} else if (bit == PG_M) {
				/*
				 * We could also clear PG_RW here to force
				 * a fault on write to redetect PG_M for
				 * virtual kernels, but it isn't necessary
				 * since virtual kernels invalidate the pte 
				 * when they clear the VPTE_M bit in their
				 * virtual page tables.
				 */
				atomic_clear_int(pte, PG_M);
			} else {
				atomic_clear_int(pte, bit);
			}
		}
		if (bit & PG_RW)
			pmap_inval_deinterlock(&info, pv->pv_pmap);
	}
	pmap_inval_done(&info);
}

/*
 * Lower the permission for all mappings to a given page.
 *
 * No requirements.
 */
void
pmap_page_protect(vm_page_t m, vm_prot_t prot)
{
	if ((prot & VM_PROT_WRITE) == 0) {
		lwkt_gettoken(&vm_token);
		if (prot & (VM_PROT_READ | VM_PROT_EXECUTE)) {
			pmap_clearbit(m, PG_RW);
			vm_page_flag_clear(m, PG_WRITEABLE);
		} else {
			pmap_remove_all(m);
		}
		lwkt_reltoken(&vm_token);
	}
}

/*
 * Return the physical address given a physical page index.
 *
 * No requirements.
 */
vm_paddr_t
pmap_phys_address(vm_pindex_t ppn)
{
	return (i386_ptob(ppn));
}

/*
 * Return a count of reference bits for a page, clearing those bits.
 * It is not necessary for every reference bit to be cleared, but it
 * is necessary that 0 only be returned when there are truly no
 * reference bits set.
 *
 * No requirements.
 */
int
pmap_ts_referenced(vm_page_t m)
{
	pv_entry_t pv, pvf, pvn;
	unsigned *pte;
	int rtval = 0;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return (rtval);

	lwkt_gettoken(&vm_token);

	if ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {

		pvf = pv;

		do {
			pvn = TAILQ_NEXT(pv, pv_list);

			TAILQ_REMOVE(&m->md.pv_list, pv, pv_list);
			TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_list);

			if (!pmap_track_modified(pv->pv_va))
				continue;

			pte = pmap_pte_quick(pv->pv_pmap, pv->pv_va);

			if (pte && (*pte & PG_A)) {
#ifdef SMP
				atomic_clear_int(pte, PG_A);
#else
				atomic_clear_int_nonlocked(pte, PG_A);
#endif
				rtval++;
				if (rtval > 4) {
					break;
				}
			}
		} while ((pv = pvn) != NULL && pv != pvf);
	}

	lwkt_reltoken(&vm_token);

	return (rtval);
}

/*
 * Return whether or not the specified physical page was modified
 * in any physical maps.
 *
 * No requirements.
 */
boolean_t
pmap_is_modified(vm_page_t m)
{
	boolean_t res;

	lwkt_gettoken(&vm_token);
	res = pmap_testbit(m, PG_M);
	lwkt_reltoken(&vm_token);
	return (res);
}

/*
 * Clear the modify bits on the specified physical page.
 *
 * No requirements.
 */
void
pmap_clear_modify(vm_page_t m)
{
	lwkt_gettoken(&vm_token);
	pmap_clearbit(m, PG_M);
	lwkt_reltoken(&vm_token);
}

/*
 * Clear the reference bit on the specified physical page.
 *
 * No requirements.
 */
void
pmap_clear_reference(vm_page_t m)
{
	lwkt_gettoken(&vm_token);
	pmap_clearbit(m, PG_A);
	lwkt_reltoken(&vm_token);
}

/*
 * Miscellaneous support routines follow
 *
 * Called from the low level boot code only.
 */
static void
i386_protection_init(void)
{
	int *kp, prot;

	kp = protection_codes;
	for (prot = 0; prot < 8; prot++) {
		switch (prot) {
		case VM_PROT_NONE | VM_PROT_NONE | VM_PROT_NONE:
			/*
			 * Read access is also 0. There isn't any execute bit,
			 * so just make it readable.
			 */
		case VM_PROT_READ | VM_PROT_NONE | VM_PROT_NONE:
		case VM_PROT_READ | VM_PROT_NONE | VM_PROT_EXECUTE:
		case VM_PROT_NONE | VM_PROT_NONE | VM_PROT_EXECUTE:
			*kp++ = 0;
			break;
		case VM_PROT_NONE | VM_PROT_WRITE | VM_PROT_NONE:
		case VM_PROT_NONE | VM_PROT_WRITE | VM_PROT_EXECUTE:
		case VM_PROT_READ | VM_PROT_WRITE | VM_PROT_NONE:
		case VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE:
			*kp++ = PG_RW;
			break;
		}
	}
}

/*
 * Map a set of physical memory pages into the kernel virtual
 * address space. Return a pointer to where it is mapped. This
 * routine is intended to be used for mapping device memory,
 * NOT real memory.
 *
 * NOTE: we can't use pgeflag unless we invalidate the pages one at
 * a time.
 *
 * No requirements.
 */
void *
pmap_mapdev(vm_paddr_t pa, vm_size_t size)
{
	vm_offset_t va, tmpva, offset;
	unsigned *pte;

	offset = pa & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);

	va = kmem_alloc_nofault(&kernel_map, size, PAGE_SIZE);
	if (!va)
		panic("pmap_mapdev: Couldn't alloc kernel virtual memory");

	pa = pa & PG_FRAME;
	for (tmpva = va; size > 0;) {
		pte = (unsigned *)vtopte(tmpva);
		*pte = pa | PG_RW | PG_V; /* | pgeflag; */
		size -= PAGE_SIZE;
		tmpva += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
	cpu_invltlb();
	smp_invltlb();

	return ((void *)(va + offset));
}

void *
pmap_mapdev_uncacheable(vm_paddr_t pa, vm_size_t size)
{
	vm_offset_t va, tmpva, offset;
	unsigned *pte;

	offset = pa & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);

	va = kmem_alloc_nofault(&kernel_map, size, PAGE_SIZE);
	if (va == 0) {
		panic("pmap_mapdev_uncacheable: "
		    "Couldn't alloc kernel virtual memory");
	}

	pa = pa & PG_FRAME;
	for (tmpva = va; size > 0;) {
		pte = (unsigned *)vtopte(tmpva);
		*pte = pa | PG_RW | PG_V | PG_N; /* | pgeflag; */
		size -= PAGE_SIZE;
		tmpva += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
	cpu_invltlb();
	smp_invltlb();

	return ((void *)(va + offset));
}

/*
 * No requirements.
 */
void
pmap_unmapdev(vm_offset_t va, vm_size_t size)
{
	vm_offset_t base, offset;

	base = va & PG_FRAME;
	offset = va & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);
	pmap_qremove(va, size >> PAGE_SHIFT);
	kmem_free(&kernel_map, base, size);
}

/*
 * Perform the pmap work for mincore
 *
 * The caller must hold vm_token if the caller wishes a stable result,
 * and even in that case some bits can change due to third party accesses
 * to the pmap.
 *
 * No requirements.
 */
int
pmap_mincore(pmap_t pmap, vm_offset_t addr)
{
	unsigned *ptep, pte;
	vm_page_t m;
	int val = 0;

	lwkt_gettoken(&vm_token);
	ptep = pmap_pte(pmap, addr);

	if (ptep && (pte = *ptep) != 0) {
		vm_offset_t pa;

		val = MINCORE_INCORE;
		if ((pte & PG_MANAGED) == 0)
			goto done;

		pa = pte & PG_FRAME;

		m = PHYS_TO_VM_PAGE(pa);

		if (pte & PG_M) {
			/*
			 * Modified by us
			 */
			val |= MINCORE_MODIFIED|MINCORE_MODIFIED_OTHER;
		} else if (m->dirty || pmap_is_modified(m)) {
			/*
			 * Modified by someone else
			 */
			val |= MINCORE_MODIFIED_OTHER;
		}

		if (pte & PG_A) {
			/*
			 * Referenced by us
			 */
			val |= MINCORE_REFERENCED|MINCORE_REFERENCED_OTHER;
		} else if ((m->flags & PG_REFERENCED) ||
			   pmap_ts_referenced(m)) {
			/*
			 * Referenced by someone else
			 */
			val |= MINCORE_REFERENCED_OTHER;
			vm_page_flag_set(m, PG_REFERENCED);
		}
	} 
done:
	lwkt_reltoken(&vm_token);
	return val;
}

/*
 * Replace p->p_vmspace with a new one.  If adjrefs is non-zero the new
 * vmspace will be ref'd and the old one will be deref'd.
 *
 * cr3 will be reloaded if any lwp is the current lwp.
 *
 * Only called with new VM spaces.
 * The process must have only a single thread.
 * The process must hold the vmspace->vm_map.token for oldvm and newvm
 * No other requirements.
 */
void
pmap_replacevm(struct proc *p, struct vmspace *newvm, int adjrefs)
{
	struct vmspace *oldvm;
	struct lwp *lp;

	oldvm = p->p_vmspace;
	if (oldvm != newvm) {
		if (adjrefs)
			sysref_get(&newvm->vm_sysref);
		p->p_vmspace = newvm;
		KKASSERT(p->p_nthreads == 1);
		lp = RB_ROOT(&p->p_lwp_tree);
		pmap_setlwpvm(lp, newvm);
		if (adjrefs) 
			sysref_put(&oldvm->vm_sysref);
	}
}

/*
 * Set the vmspace for a LWP.  The vmspace is almost universally set the
 * same as the process vmspace, but virtual kernels need to swap out contexts
 * on a per-lwp basis.
 *
 * Always called with a lp under the caller's direct control, either
 * unscheduled or the current lwp.
 *
 * No requirements.
 */
void
pmap_setlwpvm(struct lwp *lp, struct vmspace *newvm)
{
	struct vmspace *oldvm;
	struct pmap *pmap;

	oldvm = lp->lwp_vmspace;

	if (oldvm != newvm) {
		lp->lwp_vmspace = newvm;
		if (curthread->td_lwp == lp) {
			pmap = vmspace_pmap(newvm);
#if defined(SMP)
			atomic_set_cpumask(&pmap->pm_active, mycpu->gd_cpumask);
			if (pmap->pm_active & CPUMASK_LOCK)
				pmap_interlock_wait(newvm);
#else
			pmap->pm_active |= 1;
#endif
#if defined(SWTCH_OPTIM_STATS)
			tlb_flush_count++;
#endif
			curthread->td_pcb->pcb_cr3 = vtophys(pmap->pm_pdir);
			load_cr3(curthread->td_pcb->pcb_cr3);
			pmap = vmspace_pmap(oldvm);
#if defined(SMP)
			atomic_clear_cpumask(&pmap->pm_active,
					     mycpu->gd_cpumask);
#else
			pmap->pm_active &= ~(cpumask_t)1;
#endif
		}
	}
}

#ifdef SMP
/*
 * Called when switching to a locked pmap, used to interlock against pmaps
 * undergoing modifications to prevent us from activating the MMU for the
 * target pmap until all such modifications have completed.  We have to do
 * this because the thread making the modifications has already set up its
 * SMP synchronization mask.
 *
 * No requirements.
 */
void
pmap_interlock_wait(struct vmspace *vm)
{
	struct pmap *pmap = &vm->vm_pmap;

	if (pmap->pm_active & CPUMASK_LOCK) {
		crit_enter();
		DEBUG_PUSH_INFO("pmap_interlock_wait");
		while (pmap->pm_active & CPUMASK_LOCK) {
			cpu_ccfence();
			lwkt_process_ipiq();
		}
		DEBUG_POP_INFO();
		crit_exit();
	}
}

#endif

/*
 * Return a page-directory alignment hint for device mappings which will
 * allow the use of super-pages for the mapping.
 *
 * No requirements.
 */
vm_offset_t
pmap_addr_hint(vm_object_t obj, vm_offset_t addr, vm_size_t size)
{

	if ((obj == NULL) || (size < NBPDR) || (obj->type != OBJT_DEVICE)) {
		return addr;
	}

	addr = (addr + (NBPDR - 1)) & ~(NBPDR - 1);
	return addr;
}

/*
 * Return whether the PGE flag is supported globally.
 *
 * No requirements.
 */
int
pmap_get_pgeflag(void)
{
	return pgeflag;
}

/*
 * Used by kmalloc/kfree, page already exists at va
 */
vm_page_t
pmap_kvtom(vm_offset_t va)
{
	return(PHYS_TO_VM_PAGE(*vtopte(va) & PG_FRAME));
}
