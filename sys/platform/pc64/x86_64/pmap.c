/*
 * Copyright (c) 1991 Regents of the University of California.
 * Copyright (c) 1994 John S. Dyson
 * Copyright (c) 1994 David Greenman
 * Copyright (c) 2003 Peter Wemm
 * Copyright (c) 2005-2008 Alan L. Cox <alc@cs.rice.edu>
 * Copyright (c) 2008, 2009 The DragonFly Project.
 * Copyright (c) 2008, 2009 Jordan Gordeev.
 * Copyright (c) 2011 Matthew Dillon
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
 */
/*
 * Manage physical address maps for x86-64 systems.
 */

#if JG
#include "opt_disable_pse.h"
#include "opt_pmap.h"
#endif
#include "opt_msgbuf.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/msgbuf.h>
#include <sys/vmmeter.h>
#include <sys/mman.h>

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
#include <vm/vm_page2.h>

#include <machine/cputypes.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/smp.h>
#include <machine_base/apic/apicreg.h>
#include <machine/globaldata.h>
#include <machine/pmap.h>
#include <machine/pmap_inval.h>
#include <machine/inttypes.h>

#include <ddb/ddb.h>

#define PMAP_KEEP_PDIRS
#ifndef PMAP_SHPGPERPROC
#define PMAP_SHPGPERPROC 2000
#endif

#if defined(DIAGNOSTIC)
#define PMAP_DIAGNOSTIC
#endif

#define MINPV 2048

/*
 * pmap debugging will report who owns a pv lock when blocking.
 */
#ifdef PMAP_DEBUG

#define PMAP_DEBUG_DECL		,const char *func, int lineno
#define PMAP_DEBUG_ARGS		, __func__, __LINE__
#define PMAP_DEBUG_COPY		, func, lineno

#define pv_get(pmap, pindex)		_pv_get(pmap, pindex		\
							PMAP_DEBUG_ARGS)
#define pv_lock(pv)			_pv_lock(pv			\
							PMAP_DEBUG_ARGS)
#define pv_hold_try(pv)			_pv_hold_try(pv			\
							PMAP_DEBUG_ARGS)
#define pv_alloc(pmap, pindex, isnewp)	_pv_alloc(pmap, pindex, isnewp	\
							PMAP_DEBUG_ARGS)

#else

#define PMAP_DEBUG_DECL
#define PMAP_DEBUG_ARGS
#define PMAP_DEBUG_COPY

#define pv_get(pmap, pindex)		_pv_get(pmap, pindex)
#define pv_lock(pv)			_pv_lock(pv)
#define pv_hold_try(pv)			_pv_hold_try(pv)
#define pv_alloc(pmap, pindex, isnewp)	_pv_alloc(pmap, pindex, isnewp)

#endif

/*
 * Get PDEs and PTEs for user/kernel address space
 */
#define pdir_pde(m, v) (m[(vm_offset_t)(v) >> PDRSHIFT])

#define pmap_pde_v(pte)		((*(pd_entry_t *)pte & PG_V) != 0)
#define pmap_pte_w(pte)		((*(pt_entry_t *)pte & PG_W) != 0)
#define pmap_pte_m(pte)		((*(pt_entry_t *)pte & PG_M) != 0)
#define pmap_pte_u(pte)		((*(pt_entry_t *)pte & PG_A) != 0)
#define pmap_pte_v(pte)		((*(pt_entry_t *)pte & PG_V) != 0)

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
vm_offset_t virtual2_start;	/* cutout free area prior to kernel start */
vm_offset_t virtual2_end;
vm_offset_t virtual_start;	/* VA of first avail page (after kernel bss) */
vm_offset_t virtual_end;	/* VA of last avail page (end of kernel AS) */
vm_offset_t KvaStart;		/* VA start of KVA space */
vm_offset_t KvaEnd;		/* VA end of KVA space (non-inclusive) */
vm_offset_t KvaSize;		/* max size of kernel virtual address space */
static boolean_t pmap_initialized = FALSE;	/* Has pmap_init completed? */
static int pgeflag;		/* PG_G or-in */
static int pseflag;		/* PG_PS or-in */

static int ndmpdp;
static vm_paddr_t dmaplimit;
static int nkpt;
vm_offset_t kernel_vm_end = VM_MIN_KERNEL_ADDRESS;

static uint64_t KPTbase;
static uint64_t KPTphys;
static uint64_t	KPDphys;	/* phys addr of kernel level 2 */
static uint64_t	KPDbase;	/* phys addr of kernel level 2 @ KERNBASE */
uint64_t KPDPphys;	/* phys addr of kernel level 3 */
uint64_t KPML4phys;	/* phys addr of kernel level 4 */

static uint64_t	DMPDphys;	/* phys addr of direct mapped level 2 */
static uint64_t	DMPDPphys;	/* phys addr of direct mapped level 3 */

/*
 * Data for the pv entry allocation mechanism
 */
static vm_zone_t pvzone;
static struct vm_zone pvzone_store;
static struct vm_object pvzone_obj;
static int pv_entry_max=0, pv_entry_high_water=0;
static int pmap_pagedaemon_waken = 0;
static struct pv_entry *pvinit;

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

static int pmap_yield_count = 64;
SYSCTL_INT(_machdep, OID_AUTO, pmap_yield_count, CTLFLAG_RW,
    &pmap_yield_count, 0, "Yield during init_pt/release");

#define DISABLE_PSE

static void pv_hold(pv_entry_t pv);
static int _pv_hold_try(pv_entry_t pv
				PMAP_DEBUG_DECL);
static void pv_drop(pv_entry_t pv);
static void _pv_lock(pv_entry_t pv
				PMAP_DEBUG_DECL);
static void pv_unlock(pv_entry_t pv);
static pv_entry_t _pv_alloc(pmap_t pmap, vm_pindex_t pindex, int *isnew
				PMAP_DEBUG_DECL);
static pv_entry_t _pv_get(pmap_t pmap, vm_pindex_t pindex
				PMAP_DEBUG_DECL);
static pv_entry_t pv_get_try(pmap_t pmap, vm_pindex_t pindex, int *errorp);
static pv_entry_t pv_find(pmap_t pmap, vm_pindex_t pindex);
static void pv_put(pv_entry_t pv);
static void pv_free(pv_entry_t pv);
static void *pv_pte_lookup(pv_entry_t pv, vm_pindex_t pindex);
static pv_entry_t pmap_allocpte(pmap_t pmap, vm_pindex_t ptepindex,
		      pv_entry_t *pvpp);
static void pmap_remove_pv_pte(pv_entry_t pv, pv_entry_t pvp,
		      struct pmap_inval_info *info);
static vm_page_t pmap_remove_pv_page(pv_entry_t pv);

static void pmap_remove_callback(pmap_t pmap, struct pmap_inval_info *info,
		      pv_entry_t pte_pv, pv_entry_t pt_pv, vm_offset_t va,
		      pt_entry_t *ptep, void *arg __unused);
static void pmap_protect_callback(pmap_t pmap, struct pmap_inval_info *info,
		      pv_entry_t pte_pv, pv_entry_t pt_pv, vm_offset_t va,
		      pt_entry_t *ptep, void *arg __unused);

static void i386_protection_init (void);
static void create_pagetables(vm_paddr_t *firstaddr);
static void pmap_remove_all (vm_page_t m);
static boolean_t pmap_testbit (vm_page_t m, int bit);

static pt_entry_t * pmap_pte_quick (pmap_t pmap, vm_offset_t va);
static vm_offset_t pmap_kmem_choose(vm_offset_t addr);

static unsigned pdir4mb;

static int
pv_entry_compare(pv_entry_t pv1, pv_entry_t pv2)
{
	if (pv1->pv_pindex < pv2->pv_pindex)
		return(-1);
	if (pv1->pv_pindex > pv2->pv_pindex)
		return(1);
	return(0);
}

RB_GENERATE2(pv_entry_rb_tree, pv_entry, pv_entry,
             pv_entry_compare, vm_pindex_t, pv_pindex);

/*
 * Move the kernel virtual free pointer to the next
 * 2MB.  This is used to help improve performance
 * by using a large (2MB) page for much of the kernel
 * (.text, .data, .bss)
 */
static
vm_offset_t
pmap_kmem_choose(vm_offset_t addr)
{
	vm_offset_t newaddr = addr;

	newaddr = (addr + (NBPDR - 1)) & ~(NBPDR - 1);
	return newaddr;
}

/*
 * pmap_pte_quick:
 *
 *	Super fast pmap_pte routine best used when scanning the pv lists.
 *	This eliminates many course-grained invltlb calls.  Note that many of
 *	the pv list scans are across different pmaps and it is very wasteful
 *	to do an entire invltlb when checking a single mapping.
 */
static __inline pt_entry_t *pmap_pte(pmap_t pmap, vm_offset_t va);

static
pt_entry_t *
pmap_pte_quick(pmap_t pmap, vm_offset_t va)
{
	return pmap_pte(pmap, va);
}

/*
 * Returns the pindex of a page table entry (representing a terminal page).
 * There are NUPTE_TOTAL page table entries possible (a huge number)
 *
 * x86-64 has a 48-bit address space, where bit 47 is sign-extended out.
 * We want to properly translate negative KVAs.
 */
static __inline
vm_pindex_t
pmap_pte_pindex(vm_offset_t va)
{
	return ((va >> PAGE_SHIFT) & (NUPTE_TOTAL - 1));
}

/*
 * Returns the pindex of a page table.
 */
static __inline
vm_pindex_t
pmap_pt_pindex(vm_offset_t va)
{
	return (NUPTE_TOTAL + ((va >> PDRSHIFT) & (NUPT_TOTAL - 1)));
}

/*
 * Returns the pindex of a page directory.
 */
static __inline
vm_pindex_t
pmap_pd_pindex(vm_offset_t va)
{
	return (NUPTE_TOTAL + NUPT_TOTAL +
		((va >> PDPSHIFT) & (NUPD_TOTAL - 1)));
}

static __inline
vm_pindex_t
pmap_pdp_pindex(vm_offset_t va)
{
	return (NUPTE_TOTAL + NUPT_TOTAL + NUPD_TOTAL +
		((va >> PML4SHIFT) & (NUPDP_TOTAL - 1)));
}

static __inline
vm_pindex_t
pmap_pml4_pindex(void)
{
	return (NUPTE_TOTAL + NUPT_TOTAL + NUPD_TOTAL + NUPDP_TOTAL);
}

/*
 * Return various clipped indexes for a given VA
 *
 * Returns the index of a pte in a page table, representing a terminal
 * page.
 */
static __inline
vm_pindex_t
pmap_pte_index(vm_offset_t va)
{
	return ((va >> PAGE_SHIFT) & ((1ul << NPTEPGSHIFT) - 1));
}

/*
 * Returns the index of a pt in a page directory, representing a page
 * table.
 */
static __inline
vm_pindex_t
pmap_pt_index(vm_offset_t va)
{
	return ((va >> PDRSHIFT) & ((1ul << NPDEPGSHIFT) - 1));
}

/*
 * Returns the index of a pd in a page directory page, representing a page
 * directory.
 */
static __inline
vm_pindex_t
pmap_pd_index(vm_offset_t va)
{
	return ((va >> PDPSHIFT) & ((1ul << NPDPEPGSHIFT) - 1));
}

/*
 * Returns the index of a pdp in the pml4 table, representing a page
 * directory page.
 */
static __inline
vm_pindex_t
pmap_pdp_index(vm_offset_t va)
{
	return ((va >> PML4SHIFT) & ((1ul << NPML4EPGSHIFT) - 1));
}

/*
 * Generic procedure to index a pte from a pt, pd, or pdp.
 */
static
void *
pv_pte_lookup(pv_entry_t pv, vm_pindex_t pindex)
{
	pt_entry_t *pte;

	pte = (pt_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pv->pv_m));
	return(&pte[pindex]);
}

/*
 * Return pointer to PDP slot in the PML4
 */
static __inline
pml4_entry_t *
pmap_pdp(pmap_t pmap, vm_offset_t va)
{
	return (&pmap->pm_pml4[pmap_pdp_index(va)]);
}

/*
 * Return pointer to PD slot in the PDP given a pointer to the PDP
 */
static __inline
pdp_entry_t *
pmap_pdp_to_pd(pml4_entry_t *pdp, vm_offset_t va)
{
	pdp_entry_t *pd;

	pd = (pdp_entry_t *)PHYS_TO_DMAP(*pdp & PG_FRAME);
	return (&pd[pmap_pd_index(va)]);
}

/*
 * Return pointer to PD slot in the PDP
 **/
static __inline
pdp_entry_t *
pmap_pd(pmap_t pmap, vm_offset_t va)
{
	pml4_entry_t *pdp;

	pdp = pmap_pdp(pmap, va);
	if ((*pdp & PG_V) == 0)
		return NULL;
	return (pmap_pdp_to_pd(pdp, va));
}

/*
 * Return pointer to PT slot in the PD given a pointer to the PD
 */
static __inline
pd_entry_t *
pmap_pd_to_pt(pdp_entry_t *pd, vm_offset_t va)
{
	pd_entry_t *pt;

	pt = (pd_entry_t *)PHYS_TO_DMAP(*pd & PG_FRAME);
	return (&pt[pmap_pt_index(va)]);
}

/*
 * Return pointer to PT slot in the PD
 */
static __inline
pd_entry_t *
pmap_pt(pmap_t pmap, vm_offset_t va)
{
	pdp_entry_t *pd;

	pd = pmap_pd(pmap, va);
	if (pd == NULL || (*pd & PG_V) == 0)
		 return NULL;
	return (pmap_pd_to_pt(pd, va));
}

/*
 * Return pointer to PTE slot in the PT given a pointer to the PT
 */
static __inline
pt_entry_t *
pmap_pt_to_pte(pd_entry_t *pt, vm_offset_t va)
{
	pt_entry_t *pte;

	pte = (pt_entry_t *)PHYS_TO_DMAP(*pt & PG_FRAME);
	return (&pte[pmap_pte_index(va)]);
}

/*
 * Return pointer to PTE slot in the PT
 */
static __inline
pt_entry_t *
pmap_pte(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *pt;

	pt = pmap_pt(pmap, va);
	if (pt == NULL || (*pt & PG_V) == 0)
		 return NULL;
	if ((*pt & PG_PS) != 0)
		return ((pt_entry_t *)pt);
	return (pmap_pt_to_pte(pt, va));
}

/*
 * Of all the layers (PTE, PT, PD, PDP, PML4) the best one to cache is
 * the PT layer.  This will speed up core pmap operations considerably.
 */
static __inline
void
pv_cache(pv_entry_t pv, vm_pindex_t pindex)
{
	if (pindex >= pmap_pt_pindex(0) && pindex <= pmap_pd_pindex(0))
		pv->pv_pmap->pm_pvhint = pv;
}


/*
 * KVM - return address of PT slot in PD
 */
static __inline
pd_entry_t *
vtopt(vm_offset_t va)
{
	uint64_t mask = ((1ul << (NPDEPGSHIFT + NPDPEPGSHIFT +
				  NPML4EPGSHIFT)) - 1);

	return (PDmap + ((va >> PDRSHIFT) & mask));
}

/*
 * KVM - return address of PTE slot in PT
 */
static __inline
pt_entry_t *
vtopte(vm_offset_t va)
{
	uint64_t mask = ((1ul << (NPTEPGSHIFT + NPDEPGSHIFT +
				  NPDPEPGSHIFT + NPML4EPGSHIFT)) - 1);

	return (PTmap + ((va >> PAGE_SHIFT) & mask));
}

static uint64_t
allocpages(vm_paddr_t *firstaddr, long n)
{
	uint64_t ret;

	ret = *firstaddr;
	bzero((void *)ret, n * PAGE_SIZE);
	*firstaddr += n * PAGE_SIZE;
	return (ret);
}

static
void
create_pagetables(vm_paddr_t *firstaddr)
{
	long i;		/* must be 64 bits */
	long nkpt_base;
	long nkpt_phys;
	int j;

	/*
	 * We are running (mostly) V=P at this point
	 *
	 * Calculate NKPT - number of kernel page tables.  We have to
	 * accomodoate prealloction of the vm_page_array, dump bitmap,
	 * MSGBUF_SIZE, and other stuff.  Be generous.
	 *
	 * Maxmem is in pages.
	 *
	 * ndmpdp is the number of 1GB pages we wish to map.
	 */
	ndmpdp = (ptoa(Maxmem) + NBPDP - 1) >> PDPSHIFT;
	if (ndmpdp < 4)		/* Minimum 4GB of dirmap */
		ndmpdp = 4;
	KKASSERT(ndmpdp <= NKPDPE * NPDEPG);

	/*
	 * Starting at the beginning of kvm (not KERNBASE).
	 */
	nkpt_phys = (Maxmem * sizeof(struct vm_page) + NBPDR - 1) / NBPDR;
	nkpt_phys += (Maxmem * sizeof(struct pv_entry) + NBPDR - 1) / NBPDR;
	nkpt_phys += ((nkpt + nkpt + 1 + NKPML4E + NKPDPE + NDMPML4E +
		       ndmpdp) + 511) / 512;
	nkpt_phys += 128;

	/*
	 * Starting at KERNBASE - map 2G worth of page table pages.
	 * KERNBASE is offset -2G from the end of kvm.
	 */
	nkpt_base = (NPDPEPG - KPDPI) * NPTEPG;	/* typically 2 x 512 */

	/*
	 * Allocate pages
	 */
	KPTbase = allocpages(firstaddr, nkpt_base);
	KPTphys = allocpages(firstaddr, nkpt_phys);
	KPML4phys = allocpages(firstaddr, 1);
	KPDPphys = allocpages(firstaddr, NKPML4E);
	KPDphys = allocpages(firstaddr, NKPDPE);

	/*
	 * Calculate the page directory base for KERNBASE,
	 * that is where we start populating the page table pages.
	 * Basically this is the end - 2.
	 */
	KPDbase = KPDphys + ((NKPDPE - (NPDPEPG - KPDPI)) << PAGE_SHIFT);

	DMPDPphys = allocpages(firstaddr, NDMPML4E);
	if ((amd_feature & AMDID_PAGE1GB) == 0)
		DMPDphys = allocpages(firstaddr, ndmpdp);
	dmaplimit = (vm_paddr_t)ndmpdp << PDPSHIFT;

	/*
	 * Fill in the underlying page table pages for the area around
	 * KERNBASE.  This remaps low physical memory to KERNBASE.
	 *
	 * Read-only from zero to physfree
	 * XXX not fully used, underneath 2M pages
	 */
	for (i = 0; (i << PAGE_SHIFT) < *firstaddr; i++) {
		((pt_entry_t *)KPTbase)[i] = i << PAGE_SHIFT;
		((pt_entry_t *)KPTbase)[i] |= PG_RW | PG_V | PG_G;
	}

	/*
	 * Now map the initial kernel page tables.  One block of page
	 * tables is placed at the beginning of kernel virtual memory,
	 * and another block is placed at KERNBASE to map the kernel binary,
	 * data, bss, and initial pre-allocations.
	 */
	for (i = 0; i < nkpt_base; i++) {
		((pd_entry_t *)KPDbase)[i] = KPTbase + (i << PAGE_SHIFT);
		((pd_entry_t *)KPDbase)[i] |= PG_RW | PG_V;
	}
	for (i = 0; i < nkpt_phys; i++) {
		((pd_entry_t *)KPDphys)[i] = KPTphys + (i << PAGE_SHIFT);
		((pd_entry_t *)KPDphys)[i] |= PG_RW | PG_V;
	}

	/*
	 * Map from zero to end of allocations using 2M pages as an
	 * optimization.  This will bypass some of the KPTBase pages
	 * above in the KERNBASE area.
	 */
	for (i = 0; (i << PDRSHIFT) < *firstaddr; i++) {
		((pd_entry_t *)KPDbase)[i] = i << PDRSHIFT;
		((pd_entry_t *)KPDbase)[i] |= PG_RW | PG_V | PG_PS | PG_G;
	}

	/*
	 * And connect up the PD to the PDP.  The kernel pmap is expected
	 * to pre-populate all of its PDs.  See NKPDPE in vmparam.h.
	 */
	for (i = 0; i < NKPDPE; i++) {
		((pdp_entry_t *)KPDPphys)[NPDPEPG - NKPDPE + i] =
				KPDphys + (i << PAGE_SHIFT);
		((pdp_entry_t *)KPDPphys)[NPDPEPG - NKPDPE + i] |=
				PG_RW | PG_V | PG_U;
	}

	/*
	 * Now set up the direct map space using either 2MB or 1GB pages
	 * Preset PG_M and PG_A because demotion expects it.
	 *
	 * When filling in entries in the PD pages make sure any excess
	 * entries are set to zero as we allocated enough PD pages
	 */
	if ((amd_feature & AMDID_PAGE1GB) == 0) {
		for (i = 0; i < NPDEPG * ndmpdp; i++) {
			((pd_entry_t *)DMPDphys)[i] = i << PDRSHIFT;
			((pd_entry_t *)DMPDphys)[i] |= PG_RW | PG_V | PG_PS |
						       PG_G | PG_M | PG_A;
		}

		/*
		 * And the direct map space's PDP
		 */
		for (i = 0; i < ndmpdp; i++) {
			((pdp_entry_t *)DMPDPphys)[i] = DMPDphys +
							(i << PAGE_SHIFT);
			((pdp_entry_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_U;
		}
	} else {
		for (i = 0; i < ndmpdp; i++) {
			((pdp_entry_t *)DMPDPphys)[i] =
						(vm_paddr_t)i << PDPSHIFT;
			((pdp_entry_t *)DMPDPphys)[i] |= PG_RW | PG_V | PG_PS |
							 PG_G | PG_M | PG_A;
		}
	}

	/* And recursively map PML4 to itself in order to get PTmap */
	((pdp_entry_t *)KPML4phys)[PML4PML4I] = KPML4phys;
	((pdp_entry_t *)KPML4phys)[PML4PML4I] |= PG_RW | PG_V | PG_U;

	/*
	 * Connect the Direct Map slots up to the PML4
	 */
	for (j = 0; j < NDMPML4E; ++j) {
		((pdp_entry_t *)KPML4phys)[DMPML4I + j] =
			(DMPDPphys + ((vm_paddr_t)j << PML4SHIFT)) |
			PG_RW | PG_V | PG_U;
	}

	/*
	 * Connect the KVA slot up to the PML4
	 */
	((pdp_entry_t *)KPML4phys)[KPML4I] = KPDPphys;
	((pdp_entry_t *)KPML4phys)[KPML4I] |= PG_RW | PG_V | PG_U;
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 *
 *	On the i386 this is called after mapping has already been enabled
 *	and just syncs the pmap module with what has already been done.
 *	[We can't call it easily with mapping off since the kernel is not
 *	mapped with PA == VA, hence we would have to relocate every address
 *	from the linked base (virtual) address "KERNBASE" to the actual
 *	(physical) address starting relative to 0]
 */
void
pmap_bootstrap(vm_paddr_t *firstaddr)
{
	vm_offset_t va;
	pt_entry_t *pte;
	struct mdglobaldata *gd;
	int pg;

	KvaStart = VM_MIN_KERNEL_ADDRESS;
	KvaEnd = VM_MAX_KERNEL_ADDRESS;
	KvaSize = KvaEnd - KvaStart;

	avail_start = *firstaddr;

	/*
	 * Create an initial set of page tables to run the kernel in.
	 */
	create_pagetables(firstaddr);

	virtual2_start = KvaStart;
	virtual2_end = PTOV_OFFSET;

	virtual_start = (vm_offset_t) PTOV_OFFSET + *firstaddr;
	virtual_start = pmap_kmem_choose(virtual_start);

	virtual_end = VM_MAX_KERNEL_ADDRESS;

	/* XXX do %cr0 as well */
	load_cr4(rcr4() | CR4_PGE | CR4_PSE);
	load_cr3(KPML4phys);

	/*
	 * Initialize protection array.
	 */
	i386_protection_init();

	/*
	 * The kernel's pmap is statically allocated so we don't have to use
	 * pmap_create, which is unlikely to work correctly at this part of
	 * the boot sequence (XXX and which no longer exists).
	 */
	kernel_pmap.pm_pml4 = (pdp_entry_t *) (PTOV_OFFSET + KPML4phys);
	kernel_pmap.pm_count = 1;
	kernel_pmap.pm_active = (cpumask_t)-1 & ~CPUMASK_LOCK;
	RB_INIT(&kernel_pmap.pm_pvroot);
	spin_init(&kernel_pmap.pm_spin);
	lwkt_token_init(&kernel_pmap.pm_token, "kpmap_tok");

	/*
	 * Reserve some special page table entries/VA space for temporary
	 * mapping of pages.
	 */
#define	SYSMAP(c, p, v, n)	\
	v = (c)va; va += ((n)*PAGE_SIZE); p = pte; pte += (n);

	va = virtual_start;
	pte = vtopte(va);

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

	*CMAP1 = 0;

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
		pt_entry_t ptditmp;
		/*
		 * Note that we have enabled PSE mode
		 */
		pseflag = PG_PS;
		ptditmp = *(PTmap + x86_64_btop(KERNBASE));
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
			cpu_invltlb();
		}
	}
}
#endif

/*
 *	Initialize the pmap module.
 *	Called by vm_init, to initialize any structures that the pmap
 *	system needs to map virtual memory.
 *	pmap_init has been enhanced to support in a fairly consistant
 *	way, discontiguous physical memory.
 */
void
pmap_init(void)
{
	int i;
	int initial_pvs;

	/*
	 * Allocate memory for random pmap data structures.  Includes the
	 * pv_head_table.
	 */

	for (i = 0; i < vm_page_array_size; i++) {
		vm_page_t m;

		m = &vm_page_array[i];
		TAILQ_INIT(&m->md.pv_list);
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
 */
void
pmap_init2(void)
{
	int shpgperproc = PMAP_SHPGPERPROC;
	int entry_max;

	TUNABLE_INT_FETCH("vm.pmap.shpgperproc", &shpgperproc);
	pv_entry_max = shpgperproc * maxproc + vm_page_array_size;
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

#if defined(PMAP_DIAGNOSTIC)

/*
 * This code checks for non-writeable/modified pages.
 * This should be an invalid condition.
 */
static
int
pmap_nw_modified(pt_entry_t pte)
{
	if ((pte & (PG_M|PG_RW)) == PG_M)
		return 1;
	else
		return 0;
}
#endif


/*
 * this routine defines the region(s) of memory that should
 * not be tested for the modified bit.
 */
static __inline
int
pmap_track_modified(vm_pindex_t pindex)
{
	vm_offset_t va = (vm_offset_t)pindex << PAGE_SHIFT;
	if ((va < clean_sva) || (va >= clean_eva)) 
		return 1;
	else
		return 0;
}

/*
 * Extract the physical page address associated with the map/VA pair.
 * The page must be wired for this to work reliably.
 *
 * XXX for the moment we're using pv_find() instead of pv_get(), as
 *     callers might be expecting non-blocking operation.
 */
vm_paddr_t 
pmap_extract(pmap_t pmap, vm_offset_t va)
{
	vm_paddr_t rtval;
	pv_entry_t pt_pv;
	pt_entry_t *ptep;

	rtval = 0;
	if (va >= VM_MAX_USER_ADDRESS) {
		/*
		 * Kernel page directories might be direct-mapped and
		 * there is typically no PV tracking of pte's
		 */
		pd_entry_t *pt;

		pt = pmap_pt(pmap, va);
		if (pt && (*pt & PG_V)) {
			if (*pt & PG_PS) {
				rtval = *pt & PG_PS_FRAME;
				rtval |= va & PDRMASK;
			} else {
				ptep = pmap_pt_to_pte(pt, va);
				if (*pt & PG_V) {
					rtval = *ptep & PG_FRAME;
					rtval |= va & PAGE_MASK;
				}
			}
		}
	} else {
		/*
		 * User pages currently do not direct-map the page directory
		 * and some pages might not used managed PVs.  But all PT's
		 * will have a PV.
		 */
		pt_pv = pv_find(pmap, pmap_pt_pindex(va));
		if (pt_pv) {
			ptep = pv_pte_lookup(pt_pv, pmap_pte_index(va));
			if (*ptep & PG_V) {
				rtval = *ptep & PG_FRAME;
				rtval |= va & PAGE_MASK;
			}
			pv_drop(pt_pv);
		}
	}
	return rtval;
}

/*
 * Extract the physical page address associated kernel virtual address.
 */
vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	pd_entry_t pt;		/* pt entry in pd */
	vm_paddr_t pa;

	if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS) {
		pa = DMAP_TO_PHYS(va);
	} else {
		pt = *vtopt(va);
		if (pt & PG_PS) {
			pa = (pt & PG_PS_FRAME) | (va & PDRMASK);
		} else {
			/*
			 * Beware of a concurrent promotion that changes the
			 * PDE at this point!  For example, vtopte() must not
			 * be used to access the PTE because it would use the
			 * new PDE.  It is, however, safe to use the old PDE
			 * because the page table page is preserved by the
			 * promotion.
			 */
			pa = *pmap_pt_to_pte(&pt, va);
			pa = (pa & PG_FRAME) | (va & PAGE_MASK);
		}
	}
	return pa;
}

/***************************************************
 * Low level mapping routines.....
 ***************************************************/

/*
 * Routine: pmap_kenter
 * Function:
 *  	Add a wired page to the KVA
 *  	NOTE! note that in order for the mapping to take effect -- you
 *  	should do an invltlb after doing the pmap_kenter().
 */
void 
pmap_kenter(vm_offset_t va, vm_paddr_t pa)
{
	pt_entry_t *pte;
	pt_entry_t npte;
	pmap_inval_info info;

	pmap_inval_init(&info);				/* XXX remove */
	npte = pa | PG_RW | PG_V | pgeflag;
	pte = vtopte(va);
	pmap_inval_interlock(&info, &kernel_pmap, va);	/* XXX remove */
	*pte = npte;
	pmap_inval_deinterlock(&info, &kernel_pmap);	/* XXX remove */
	pmap_inval_done(&info);				/* XXX remove */
}

/*
 * Routine: pmap_kenter_quick
 * Function:
 *  	Similar to pmap_kenter(), except we only invalidate the
 *  	mapping on the current CPU.
 */
void
pmap_kenter_quick(vm_offset_t va, vm_paddr_t pa)
{
	pt_entry_t *pte;
	pt_entry_t npte;

	npte = pa | PG_RW | PG_V | pgeflag;
	pte = vtopte(va);
	*pte = npte;
	cpu_invlpg((void *)va);
}

void
pmap_kenter_sync(vm_offset_t va)
{
	pmap_inval_info info;

	pmap_inval_init(&info);
	pmap_inval_interlock(&info, &kernel_pmap, va);
	pmap_inval_deinterlock(&info, &kernel_pmap);
	pmap_inval_done(&info);
}

void
pmap_kenter_sync_quick(vm_offset_t va)
{
	cpu_invlpg((void *)va);
}

/*
 * remove a page from the kernel pagetables
 */
void
pmap_kremove(vm_offset_t va)
{
	pt_entry_t *pte;
	pmap_inval_info info;

	pmap_inval_init(&info);
	pte = vtopte(va);
	pmap_inval_interlock(&info, &kernel_pmap, va);
	(void)pte_load_clear(pte);
	pmap_inval_deinterlock(&info, &kernel_pmap);
	pmap_inval_done(&info);
}

void
pmap_kremove_quick(vm_offset_t va)
{
	pt_entry_t *pte;
	pte = vtopte(va);
	(void)pte_load_clear(pte);
	cpu_invlpg((void *)va);
}

/*
 * XXX these need to be recoded.  They are not used in any critical path.
 */
void
pmap_kmodify_rw(vm_offset_t va)
{
	atomic_set_long(vtopte(va), PG_RW);
	cpu_invlpg((void *)va);
}

void
pmap_kmodify_nc(vm_offset_t va)
{
	atomic_set_long(vtopte(va), PG_N);
	cpu_invlpg((void *)va);
}

/*
 * Used to map a range of physical addresses into kernel virtual
 * address space during the low level boot, typically to map the
 * dump bitmap, message buffer, and vm_page_array.
 *
 * These mappings are typically made at some pointer after the end of the
 * kernel text+data.
 *
 * We could return PHYS_TO_DMAP(start) here and not allocate any
 * via (*virtp), but then kmem from userland and kernel dumps won't
 * have access to the related pointers.
 */
vm_offset_t
pmap_map(vm_offset_t *virtp, vm_paddr_t start, vm_paddr_t end, int prot)
{
	vm_offset_t va;
	vm_offset_t va_start;

	/*return PHYS_TO_DMAP(start);*/

	va_start = *virtp;
	va = va_start;

	while (start < end) {
		pmap_kenter_quick(va, start);
		va += PAGE_SIZE;
		start += PAGE_SIZE;
	}
	*virtp = va;
	return va_start;
}


/*
 * Add a list of wired pages to the kva
 * this routine is only used for temporary
 * kernel mappings that do not need to have
 * page modification or references recorded.
 * Note that old mappings are simply written
 * over.  The page *must* be wired.
 */
void
pmap_qenter(vm_offset_t va, vm_page_t *m, int count)
{
	vm_offset_t end_va;

	end_va = va + count * PAGE_SIZE;
		
	while (va < end_va) {
		pt_entry_t *pte;

		pte = vtopte(va);
		*pte = VM_PAGE_TO_PHYS(*m) | PG_RW | PG_V | pgeflag;
		cpu_invlpg((void *)va);
		va += PAGE_SIZE;
		m++;
	}
	smp_invltlb();
}

/*
 * This routine jerks page mappings from the
 * kernel -- it is meant only for temporary mappings.
 *
 * MPSAFE, INTERRUPT SAFE (cluster callback)
 */
void
pmap_qremove(vm_offset_t va, int count)
{
	vm_offset_t end_va;

	end_va = va + count * PAGE_SIZE;

	while (va < end_va) {
		pt_entry_t *pte;

		pte = vtopte(va);
		(void)pte_load_clear(pte);
		cpu_invlpg((void *)va);
		va += PAGE_SIZE;
	}
	smp_invltlb();
}

/*
 * Create a new thread and optionally associate it with a (new) process.
 * NOTE! the new thread's cpu may not equal the current cpu.
 */
void
pmap_init_thread(thread_t td)
{
	/* enforce pcb placement & alignment */
	td->td_pcb = (struct pcb *)(td->td_kstack + td->td_kstack_size) - 1;
	td->td_pcb = (struct pcb *)((intptr_t)td->td_pcb & ~(intptr_t)0xF);
	td->td_savefpu = &td->td_pcb->pcb_save;
	td->td_sp = (char *)td->td_pcb;	/* no -16 */
}

/*
 * This routine directly affects the fork perf for a process.
 */
void
pmap_init_proc(struct proc *p)
{
}

/*
 * Initialize pmap0/vmspace0.  This pmap is not added to pmap_list because
 * it, and IdlePTD, represents the template used to update all other pmaps.
 *
 * On architectures where the kernel pmap is not integrated into the user
 * process pmap, this pmap represents the process pmap, not the kernel pmap.
 * kernel_pmap should be used to directly access the kernel_pmap.
 */
void
pmap_pinit0(struct pmap *pmap)
{
	pmap->pm_pml4 = (pml4_entry_t *)(PTOV_OFFSET + KPML4phys);
	pmap->pm_count = 1;
	pmap->pm_active = 0;
	pmap->pm_pvhint = NULL;
	RB_INIT(&pmap->pm_pvroot);
	spin_init(&pmap->pm_spin);
	lwkt_token_init(&pmap->pm_token, "pmap_tok");
	bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
}

/*
 * Initialize a preallocated and zeroed pmap structure,
 * such as one in a vmspace structure.
 */
void
pmap_pinit(struct pmap *pmap)
{
	pv_entry_t pv;
	int j;

	/*
	 * Misc initialization
	 */
	pmap->pm_count = 1;
	pmap->pm_active = 0;
	pmap->pm_pvhint = NULL;
	if (pmap->pm_pmlpv == NULL) {
		RB_INIT(&pmap->pm_pvroot);
		bzero(&pmap->pm_stats, sizeof pmap->pm_stats);
		spin_init(&pmap->pm_spin);
		lwkt_token_init(&pmap->pm_token, "pmap_tok");
	}

	/*
	 * No need to allocate page table space yet but we do need a valid
	 * page directory table.
	 */
	if (pmap->pm_pml4 == NULL) {
		pmap->pm_pml4 =
		    (pml4_entry_t *)kmem_alloc_pageable(&kernel_map, PAGE_SIZE);
	}

	/*
	 * Allocate the page directory page, which wires it even though
	 * it isn't being entered into some higher level page table (it
	 * being the highest level).  If one is already cached we don't
	 * have to do anything.
	 */
	if ((pv = pmap->pm_pmlpv) == NULL) {
		pv = pmap_allocpte(pmap, pmap_pml4_pindex(), NULL);
		pmap->pm_pmlpv = pv;
		pmap_kenter((vm_offset_t)pmap->pm_pml4,
			    VM_PAGE_TO_PHYS(pv->pv_m));
		pv_put(pv);

		/*
		 * Install DMAP and KMAP.
		 */
		for (j = 0; j < NDMPML4E; ++j) {
			pmap->pm_pml4[DMPML4I + j] =
				(DMPDPphys + ((vm_paddr_t)j << PML4SHIFT)) |
				PG_RW | PG_V | PG_U;
		}
		pmap->pm_pml4[KPML4I] = KPDPphys | PG_RW | PG_V | PG_U;

		/*
		 * install self-referential address mapping entry
		 */
		pmap->pm_pml4[PML4PML4I] = VM_PAGE_TO_PHYS(pv->pv_m) |
					   PG_V | PG_RW | PG_A | PG_M;
	} else {
		KKASSERT(pv->pv_m->flags & PG_MAPPED);
		KKASSERT(pv->pv_m->flags & PG_WRITEABLE);
	}
}

/*
 * Clean up a pmap structure so it can be physically freed.  This routine
 * is called by the vmspace dtor function.  A great deal of pmap data is
 * left passively mapped to improve vmspace management so we have a bit
 * of cleanup work to do here.
 */
void
pmap_puninit(pmap_t pmap)
{
	pv_entry_t pv;
	vm_page_t p;

	KKASSERT(pmap->pm_active == 0);
	if ((pv = pmap->pm_pmlpv) != NULL) {
		if (pv_hold_try(pv) == 0)
			pv_lock(pv);
		p = pmap_remove_pv_page(pv);
		pv_free(pv);
		pmap_kremove((vm_offset_t)pmap->pm_pml4);
		vm_page_busy_wait(p, FALSE, "pgpun");
		KKASSERT(p->flags & (PG_FICTITIOUS|PG_UNMANAGED));
		vm_page_unwire(p, 0);
		vm_page_flag_clear(p, PG_MAPPED | PG_WRITEABLE);

		/*
		 * XXX eventually clean out PML4 static entries and
		 * use vm_page_free_zero()
		 */
		vm_page_free(p);
		pmap->pm_pmlpv = NULL;
	}
	if (pmap->pm_pml4) {
		KKASSERT(pmap->pm_pml4 != (void *)(PTOV_OFFSET + KPML4phys));
		kmem_free(&kernel_map, (vm_offset_t)pmap->pm_pml4, PAGE_SIZE);
		pmap->pm_pml4 = NULL;
	}
	KKASSERT(pmap->pm_stats.resident_count == 0);
	KKASSERT(pmap->pm_stats.wired_count == 0);
}

/*
 * Wire in kernel global address entries.  To avoid a race condition
 * between pmap initialization and pmap_growkernel, this procedure
 * adds the pmap to the master list (which growkernel scans to update),
 * then copies the template.
 */
void
pmap_pinit2(struct pmap *pmap)
{
	/*
	 * XXX copies current process, does not fill in MPPTDI
	 */
	spin_lock(&pmap_spin);
	TAILQ_INSERT_TAIL(&pmap_list, pmap, pm_pmnode);
	spin_unlock(&pmap_spin);
}

/*
 * This routine is called when various levels in the page table need to
 * be populated.  This routine cannot fail.
 *
 * This function returns two locked pv_entry's, one representing the
 * requested pv and one representing the requested pv's parent pv.  If
 * the pv did not previously exist it will be mapped into its parent
 * and wired, otherwise no additional wire count will be added.
 */
static
pv_entry_t
pmap_allocpte(pmap_t pmap, vm_pindex_t ptepindex, pv_entry_t *pvpp)
{
	pt_entry_t *ptep;
	pv_entry_t pv;
	pv_entry_t pvp;
	vm_pindex_t pt_pindex;
	vm_page_t m;
	int isnew;

	/*
	 * If the pv already exists and we aren't being asked for the
	 * parent page table page we can just return it.  A locked+held pv
	 * is returned.
	 */
	pv = pv_alloc(pmap, ptepindex, &isnew);
	if (isnew == 0 && pvpp == NULL)
		return(pv);

	/*
	 * This is a new PV, we have to resolve its parent page table and
	 * add an additional wiring to the page if necessary.
	 */

	/*
	 * Special case terminal PVs.  These are not page table pages so
	 * no vm_page is allocated (the caller supplied the vm_page).  If
	 * pvpp is non-NULL we are being asked to also removed the pt_pv
	 * for this pv.
	 *
	 * Note that pt_pv's are only returned for user VAs. We assert that
	 * a pt_pv is not being requested for kernel VAs.
	 */
	if (ptepindex < pmap_pt_pindex(0)) {
		if (ptepindex >= NUPTE_USER)
			KKASSERT(pvpp == NULL);
		else
			KKASSERT(pvpp != NULL);
		if (pvpp) {
			pt_pindex = NUPTE_TOTAL + (ptepindex >> NPTEPGSHIFT);
			pvp = pmap_allocpte(pmap, pt_pindex, NULL);
			if (isnew)
				vm_page_wire_quick(pvp->pv_m);
			*pvpp = pvp;
		} else {
			pvp = NULL;
		}
		return(pv);
	}

	/*
	 * Non-terminal PVs allocate a VM page to represent the page table,
	 * so we have to resolve pvp and calculate ptepindex for the pvp
	 * and then for the page table entry index in the pvp for
	 * fall-through.
	 */
	if (ptepindex < pmap_pd_pindex(0)) {
		/*
		 * pv is PT, pvp is PD
		 */
		ptepindex = (ptepindex - pmap_pt_pindex(0)) >> NPDEPGSHIFT;
		ptepindex += NUPTE_TOTAL + NUPT_TOTAL;
		pvp = pmap_allocpte(pmap, ptepindex, NULL);
		if (!isnew)
			goto notnew;

		/*
		 * PT index in PD
		 */
		ptepindex = pv->pv_pindex - pmap_pt_pindex(0);
		ptepindex &= ((1ul << NPDEPGSHIFT) - 1);
	} else if (ptepindex < pmap_pdp_pindex(0)) {
		/*
		 * pv is PD, pvp is PDP
		 */
		ptepindex = (ptepindex - pmap_pd_pindex(0)) >> NPDPEPGSHIFT;
		ptepindex += NUPTE_TOTAL + NUPT_TOTAL + NUPD_TOTAL;
		pvp = pmap_allocpte(pmap, ptepindex, NULL);
		if (!isnew)
			goto notnew;

		/*
		 * PD index in PDP
		 */
		ptepindex = pv->pv_pindex - pmap_pd_pindex(0);
		ptepindex &= ((1ul << NPDPEPGSHIFT) - 1);
	} else if (ptepindex < pmap_pml4_pindex()) {
		/*
		 * pv is PDP, pvp is the root pml4 table
		 */
		pvp = pmap_allocpte(pmap, pmap_pml4_pindex(), NULL);
		if (!isnew)
			goto notnew;

		/*
		 * PDP index in PML4
		 */
		ptepindex = pv->pv_pindex - pmap_pdp_pindex(0);
		ptepindex &= ((1ul << NPML4EPGSHIFT) - 1);
	} else {
		/*
		 * pv represents the top-level PML4, there is no parent.
		 */
		pvp = NULL;
		if (!isnew)
			goto notnew;
	}

	/*
	 * This code is only reached if isnew is TRUE and this is not a
	 * terminal PV.  We need to allocate a vm_page for the page table
	 * at this level and enter it into the parent page table.
	 *
	 * page table pages are marked PG_WRITEABLE and PG_MAPPED.
	 */
	for (;;) {
		m = vm_page_alloc(NULL, pv->pv_pindex,
				  VM_ALLOC_NORMAL | VM_ALLOC_SYSTEM |
				  VM_ALLOC_INTERRUPT);
		if (m)
			break;
		vm_wait(0);
	}
	vm_page_spin_lock(m);
	TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_list);
	pv->pv_m = m;
	vm_page_flag_set(m, PG_MAPPED | PG_WRITEABLE);
	vm_page_spin_unlock(m);
	vm_page_unmanage(m);	/* m must be spinunlocked */

	if ((m->flags & PG_ZERO) == 0) {
		pmap_zero_page(VM_PAGE_TO_PHYS(m));
	}
#ifdef PMAP_DEBUG
	else {
		pmap_page_assertzero(VM_PAGE_TO_PHYS(m));
	}
#endif
	m->valid = VM_PAGE_BITS_ALL;
	vm_page_flag_clear(m, PG_ZERO);
	vm_page_wire(m);	/* wire for mapping in parent */

	/*
	 * Wire the page into pvp, bump the wire-count for pvp's page table
	 * page.  Bump the resident_count for the pmap.  There is no pvp
	 * for the top level, address the pm_pml4[] array directly.
	 *
	 * If the caller wants the parent we return it, otherwise
	 * we just put it away.
	 *
	 * No interlock is needed for pte 0 -> non-zero.
	 */
	if (pvp) {
		vm_page_wire_quick(pvp->pv_m);
		ptep = pv_pte_lookup(pvp, ptepindex);
		KKASSERT((*ptep & PG_V) == 0);
		*ptep = VM_PAGE_TO_PHYS(m) | (PG_U | PG_RW | PG_V |
					      PG_A | PG_M);
	}
	vm_page_wakeup(m);
notnew:
	if (pvpp)
		*pvpp = pvp;
	else if (pvp)
		pv_put(pvp);
	return (pv);
}

/*
 * Release any resources held by the given physical map.
 *
 * Called when a pmap initialized by pmap_pinit is being released.  Should
 * only be called if the map contains no valid mappings.
 *
 * Caller must hold pmap->pm_token
 */
struct pmap_release_info {
	pmap_t	pmap;
	int	retry;
};

static int pmap_release_callback(pv_entry_t pv, void *data);

void
pmap_release(struct pmap *pmap)
{
	struct pmap_release_info info;

	KASSERT(pmap->pm_active == 0,
		("pmap still active! %016jx", (uintmax_t)pmap->pm_active));

	spin_lock(&pmap_spin);
	TAILQ_REMOVE(&pmap_list, pmap, pm_pmnode);
	spin_unlock(&pmap_spin);

	/*
	 * Pull pv's off the RB tree in order from low to high and release
	 * each page.
	 */
	info.pmap = pmap;
	do {
		info.retry = 0;
		spin_lock(&pmap->pm_spin);
		RB_SCAN(pv_entry_rb_tree, &pmap->pm_pvroot, NULL,
			pmap_release_callback, &info);
		spin_unlock(&pmap->pm_spin);
	} while (info.retry);


	/*
	 * One resident page (the pml4 page) should remain.
	 * No wired pages should remain.
	 */
	KKASSERT(pmap->pm_stats.resident_count == 1);
	KKASSERT(pmap->pm_stats.wired_count == 0);
}

static int
pmap_release_callback(pv_entry_t pv, void *data)
{
	struct pmap_release_info *info = data;
	pmap_t pmap = info->pmap;
	vm_page_t p;

	if (pv_hold_try(pv)) {
		spin_unlock(&pmap->pm_spin);
	} else {
		spin_unlock(&pmap->pm_spin);
		pv_lock(pv);
		if (pv->pv_pmap != pmap) {
			pv_put(pv);
			spin_lock(&pmap->pm_spin);
			info->retry = 1;
			return(-1);
		}
	}

	/*
	 * The pmap is currently not spinlocked, pv is held+locked.
	 * Remove the pv's page from its parent's page table.  The
	 * parent's page table page's wire_count will be decremented.
	 */
	pmap_remove_pv_pte(pv, NULL, NULL);

	/*
	 * Terminal pvs are unhooked from their vm_pages.  Because
	 * terminal pages aren't page table pages they aren't wired
	 * by us, so we have to be sure not to unwire them either.
	 */
	if (pv->pv_pindex < pmap_pt_pindex(0)) {
		pmap_remove_pv_page(pv);
		goto skip;
	}

	/*
	 * We leave the top-level page table page cached, wired, and
	 * mapped in the pmap until the dtor function (pmap_puninit())
	 * gets called.
	 *
	 * Since we are leaving the top-level pv intact we need
	 * to break out of what would otherwise be an infinite loop.
	 */
	if (pv->pv_pindex == pmap_pml4_pindex()) {
		pv_put(pv);
		spin_lock(&pmap->pm_spin);
		return(-1);
	}

	/*
	 * For page table pages (other than the top-level page),
	 * remove and free the vm_page.  The representitive mapping
	 * removed above by pmap_remove_pv_pte() did not undo the
	 * last wire_count so we have to do that as well.
	 */
	p = pmap_remove_pv_page(pv);
	vm_page_busy_wait(p, FALSE, "pmaprl");
	if (p->wire_count != 1) {
		kprintf("p->wire_count was %016lx %d\n",
			pv->pv_pindex, p->wire_count);
	}
	KKASSERT(p->wire_count == 1);
	KKASSERT(p->flags & PG_UNMANAGED);

	vm_page_unwire(p, 0);
	KKASSERT(p->wire_count == 0);
	/* JG eventually revert to using vm_page_free_zero() */
	vm_page_free(p);
skip:
	pv_free(pv);
	spin_lock(&pmap->pm_spin);
	return(0);
}

/*
 * This function will remove the pte associated with a pv from its parent.
 * Terminal pv's are supported.  The removal will be interlocked if info
 * is non-NULL.  The caller must dispose of pv instead of just unlocking
 * it.
 *
 * The wire count will be dropped on the parent page table.  The wire
 * count on the page being removed (pv->pv_m) from the parent page table
 * is NOT touched.  Note that terminal pages will not have any additional
 * wire counts while page table pages will have at least one representing
 * the mapping, plus others representing sub-mappings.
 *
 * NOTE: Cannot be called on kernel page table pages, only KVM terminal
 *	 pages and user page table and terminal pages.
 *
 * The pv must be locked.
 *
 * XXX must lock parent pv's if they exist to remove pte XXX
 */
static
void
pmap_remove_pv_pte(pv_entry_t pv, pv_entry_t pvp, struct pmap_inval_info *info)
{
	vm_pindex_t ptepindex = pv->pv_pindex;
	pmap_t pmap = pv->pv_pmap;
	vm_page_t p;
	int gotpvp = 0;

	KKASSERT(pmap);

	if (ptepindex == pmap_pml4_pindex()) {
		/*
		 * We are the top level pml4 table, there is no parent.
		 */
		p = pmap->pm_pmlpv->pv_m;
	} else if (ptepindex >= pmap_pdp_pindex(0)) {
		/*
		 * Remove a PDP page from the pml4e.  This can only occur
		 * with user page tables.  We do not have to lock the
		 * pml4 PV so just ignore pvp.
		 */
		vm_pindex_t pml4_pindex;
		vm_pindex_t pdp_index;
		pml4_entry_t *pdp;

		pdp_index = ptepindex - pmap_pdp_pindex(0);
		if (pvp == NULL) {
			pml4_pindex = pmap_pml4_pindex();
			pvp = pv_get(pv->pv_pmap, pml4_pindex);
			gotpvp = 1;
		}
		pdp = &pmap->pm_pml4[pdp_index & ((1ul << NPML4EPGSHIFT) - 1)];
		KKASSERT((*pdp & PG_V) != 0);
		p = PHYS_TO_VM_PAGE(*pdp & PG_FRAME);
		*pdp = 0;
		KKASSERT(info == NULL);
	} else if (ptepindex >= pmap_pd_pindex(0)) {
		/*
		 *  Remove a PD page from the pdp
		 */
		vm_pindex_t pdp_pindex;
		vm_pindex_t pd_index;
		pdp_entry_t *pd;

		pd_index = ptepindex - pmap_pd_pindex(0);

		if (pvp == NULL) {
			pdp_pindex = NUPTE_TOTAL + NUPT_TOTAL + NUPD_TOTAL +
				     (pd_index >> NPML4EPGSHIFT);
			pvp = pv_get(pv->pv_pmap, pdp_pindex);
			gotpvp = 1;
		}
		pd = pv_pte_lookup(pvp, pd_index & ((1ul << NPDPEPGSHIFT) - 1));
		KKASSERT((*pd & PG_V) != 0);
		p = PHYS_TO_VM_PAGE(*pd & PG_FRAME);
		*pd = 0;
		KKASSERT(info == NULL);
	} else if (ptepindex >= pmap_pt_pindex(0)) {
		/*
		 *  Remove a PT page from the pd
		 */
		vm_pindex_t pd_pindex;
		vm_pindex_t pt_index;
		pd_entry_t *pt;

		pt_index = ptepindex - pmap_pt_pindex(0);

		if (pvp == NULL) {
			pd_pindex = NUPTE_TOTAL + NUPT_TOTAL +
				    (pt_index >> NPDPEPGSHIFT);
			pvp = pv_get(pv->pv_pmap, pd_pindex);
			gotpvp = 1;
		}
		pt = pv_pte_lookup(pvp, pt_index & ((1ul << NPDPEPGSHIFT) - 1));
		KKASSERT((*pt & PG_V) != 0);
		p = PHYS_TO_VM_PAGE(*pt & PG_FRAME);
		*pt = 0;
		KKASSERT(info == NULL);
	} else {
		/*
		 * Remove a PTE from the PT page
		 *
		 * NOTE: pv's must be locked bottom-up to avoid deadlocking.
		 *	 pv is a pte_pv so we can safely lock pt_pv.
		 */
		vm_pindex_t pt_pindex;
		pt_entry_t *ptep;
		pt_entry_t pte;
		vm_offset_t va;

		pt_pindex = ptepindex >> NPTEPGSHIFT;
		va = (vm_offset_t)ptepindex << PAGE_SHIFT;

		if (ptepindex >= NUPTE_USER) {
			ptep = vtopte(ptepindex << PAGE_SHIFT);
			KKASSERT(pvp == NULL);
		} else {
			if (pvp == NULL) {
				pt_pindex = NUPTE_TOTAL +
					    (ptepindex >> NPDPEPGSHIFT);
				pvp = pv_get(pv->pv_pmap, pt_pindex);
				gotpvp = 1;
			}
			ptep = pv_pte_lookup(pvp, ptepindex &
						  ((1ul << NPDPEPGSHIFT) - 1));
		}

		if (info)
			pmap_inval_interlock(info, pmap, va);
		pte = pte_load_clear(ptep);
		if (info)
			pmap_inval_deinterlock(info, pmap);
		else
			cpu_invlpg((void *)va);

		/*
		 * Now update the vm_page_t
		 */
		if ((pte & (PG_MANAGED|PG_V)) != (PG_MANAGED|PG_V)) {
			kprintf("remove_pte badpte %016lx %016lx %d\n",
				pte, pv->pv_pindex,
				pv->pv_pindex < pmap_pt_pindex(0));
		}
		/*KKASSERT((pte & (PG_MANAGED|PG_V)) == (PG_MANAGED|PG_V));*/
		p = PHYS_TO_VM_PAGE(pte & PG_FRAME);

		if (pte & PG_M) {
			if (pmap_track_modified(ptepindex))
				vm_page_dirty(p);
		}
		if (pte & PG_A) {
			vm_page_flag_set(p, PG_REFERENCED);
		}
		if (pte & PG_W)
			atomic_add_long(&pmap->pm_stats.wired_count, -1);
		if (pte & PG_G)
			cpu_invlpg((void *)va);
	}

	/*
	 * Unwire the parent page table page.  The wire_count cannot go below
	 * 1 here because the parent page table page is itself still mapped.
	 *
	 * XXX remove the assertions later.
	 */
	KKASSERT(pv->pv_m == p);
	if (pvp && vm_page_unwire_quick(pvp->pv_m))
		panic("pmap_remove_pv_pte: Insufficient wire_count");

	if (gotpvp)
		pv_put(pvp);
}

static
vm_page_t
pmap_remove_pv_page(pv_entry_t pv)
{
	vm_page_t m;

	m = pv->pv_m;
	KKASSERT(m);
	vm_page_spin_lock(m);
	pv->pv_m = NULL;
	TAILQ_REMOVE(&m->md.pv_list, pv, pv_list);
	/*
	if (m->object)
		atomic_add_int(&m->object->agg_pv_list_count, -1);
	*/
	if (TAILQ_EMPTY(&m->md.pv_list))
		vm_page_flag_clear(m, PG_MAPPED | PG_WRITEABLE);
	vm_page_spin_unlock(m);
	return(m);
}

/*
 * Grow the number of kernel page table entries, if needed.
 *
 * This routine is always called to validate any address space
 * beyond KERNBASE (for kldloads).  kernel_vm_end only governs the address
 * space below KERNBASE.
 */
void
pmap_growkernel(vm_offset_t kstart, vm_offset_t kend)
{
	vm_paddr_t paddr;
	vm_offset_t ptppaddr;
	vm_page_t nkpg;
	pd_entry_t *pt, newpt;
	pdp_entry_t newpd;
	int update_kernel_vm_end;

	/*
	 * bootstrap kernel_vm_end on first real VM use
	 */
	if (kernel_vm_end == 0) {
		kernel_vm_end = VM_MIN_KERNEL_ADDRESS;
		nkpt = 0;
		while ((*pmap_pt(&kernel_pmap, kernel_vm_end) & PG_V) != 0) {
			kernel_vm_end = (kernel_vm_end + PAGE_SIZE * NPTEPG) &
					~(PAGE_SIZE * NPTEPG - 1);
			nkpt++;
			if (kernel_vm_end - 1 >= kernel_map.max_offset) {
				kernel_vm_end = kernel_map.max_offset;
				break;                       
			}
		}
	}

	/*
	 * Fill in the gaps.  kernel_vm_end is only adjusted for ranges
	 * below KERNBASE.  Ranges above KERNBASE are kldloaded and we
	 * do not want to force-fill 128G worth of page tables.
	 */
	if (kstart < KERNBASE) {
		if (kstart > kernel_vm_end)
			kstart = kernel_vm_end;
		KKASSERT(kend <= KERNBASE);
		update_kernel_vm_end = 1;
	} else {
		update_kernel_vm_end = 0;
	}

	kstart = rounddown2(kstart, PAGE_SIZE * NPTEPG);
	kend = roundup2(kend, PAGE_SIZE * NPTEPG);

	if (kend - 1 >= kernel_map.max_offset)
		kend = kernel_map.max_offset;

	while (kstart < kend) {
		pt = pmap_pt(&kernel_pmap, kstart);
		if (pt == NULL) {
			/* We need a new PDP entry */
			nkpg = vm_page_alloc(NULL, nkpt,
			                     VM_ALLOC_NORMAL |
					     VM_ALLOC_SYSTEM |
					     VM_ALLOC_INTERRUPT);
			if (nkpg == NULL) {
				panic("pmap_growkernel: no memory to grow "
				      "kernel");
			}
			paddr = VM_PAGE_TO_PHYS(nkpg);
			if ((nkpg->flags & PG_ZERO) == 0)
				pmap_zero_page(paddr);
			vm_page_flag_clear(nkpg, PG_ZERO);
			newpd = (pdp_entry_t)
				(paddr | PG_V | PG_RW | PG_A | PG_M);
			*pmap_pd(&kernel_pmap, kstart) = newpd;
			nkpt++;
			continue; /* try again */
		}
		if ((*pt & PG_V) != 0) {
			kstart = (kstart + PAGE_SIZE * NPTEPG) &
				 ~(PAGE_SIZE * NPTEPG - 1);
			if (kstart - 1 >= kernel_map.max_offset) {
				kstart = kernel_map.max_offset;
				break;                       
			}
			continue;
		}

		/*
		 * This index is bogus, but out of the way
		 */
		nkpg = vm_page_alloc(NULL, nkpt,
				     VM_ALLOC_NORMAL |
				     VM_ALLOC_SYSTEM |
				     VM_ALLOC_INTERRUPT);
		if (nkpg == NULL)
			panic("pmap_growkernel: no memory to grow kernel");

		vm_page_wire(nkpg);
		ptppaddr = VM_PAGE_TO_PHYS(nkpg);
		pmap_zero_page(ptppaddr);
		vm_page_flag_clear(nkpg, PG_ZERO);
		newpt = (pd_entry_t) (ptppaddr | PG_V | PG_RW | PG_A | PG_M);
		*pmap_pt(&kernel_pmap, kstart) = newpt;
		nkpt++;

		kstart = (kstart + PAGE_SIZE * NPTEPG) &
			  ~(PAGE_SIZE * NPTEPG - 1);

		if (kstart - 1 >= kernel_map.max_offset) {
			kstart = kernel_map.max_offset;
			break;                       
		}
	}

	/*
	 * Only update kernel_vm_end for areas below KERNBASE.
	 */
	if (update_kernel_vm_end && kernel_vm_end < kstart)
		kernel_vm_end = kstart;
}

/*
 *	Retire the given physical map from service.
 *	Should only be called if the map contains
 *	no valid mappings.
 */
void
pmap_destroy(pmap_t pmap)
{
	int count;

	if (pmap == NULL)
		return;

	lwkt_gettoken(&pmap->pm_token);
	count = --pmap->pm_count;
	if (count == 0) {
		pmap_release(pmap);	/* eats pm_token */
		panic("destroying a pmap is not yet implemented");
	}
	lwkt_reltoken(&pmap->pm_token);
}

/*
 *	Add a reference to the specified pmap.
 */
void
pmap_reference(pmap_t pmap)
{
	if (pmap != NULL) {
		lwkt_gettoken(&pmap->pm_token);
		pmap->pm_count++;
		lwkt_reltoken(&pmap->pm_token);
	}
}

/***************************************************
 * page management routines.
 ***************************************************/

/*
 * Hold a pv without locking it
 */
static void
pv_hold(pv_entry_t pv)
{
	u_int count;

	if (atomic_cmpset_int(&pv->pv_hold, 0, 1))
		return;

	for (;;) {
		count = pv->pv_hold;
		cpu_ccfence();
		if (atomic_cmpset_int(&pv->pv_hold, count, count + 1))
			return;
		/* retry */
	}
}

/*
 * Hold a pv_entry, preventing its destruction.  TRUE is returned if the pv
 * was successfully locked, FALSE if it wasn't.  The caller must dispose of
 * the pv properly.
 *
 * Either the pmap->pm_spin or the related vm_page_spin (if traversing a
 * pv list via its page) must be held by the caller.
 */
static int
_pv_hold_try(pv_entry_t pv PMAP_DEBUG_DECL)
{
	u_int count;

	if (atomic_cmpset_int(&pv->pv_hold, 0, PV_HOLD_LOCKED | 1)) {
#ifdef PMAP_DEBUG
		pv->pv_func = func;
		pv->pv_line = lineno;
#endif
		return TRUE;
	}

	for (;;) {
		count = pv->pv_hold;
		cpu_ccfence();
		if ((count & PV_HOLD_LOCKED) == 0) {
			if (atomic_cmpset_int(&pv->pv_hold, count,
					      (count + 1) | PV_HOLD_LOCKED)) {
#ifdef PMAP_DEBUG
				pv->pv_func = func;
				pv->pv_line = lineno;
#endif
				return TRUE;
			}
		} else {
			if (atomic_cmpset_int(&pv->pv_hold, count, count + 1))
				return FALSE;
		}
		/* retry */
	}
}

/*
 * Drop a previously held pv_entry which could not be locked, allowing its
 * destruction.
 *
 * Must not be called with a spinlock held as we might zfree() the pv if it
 * is no longer associated with a pmap and this was the last hold count.
 */
static void
pv_drop(pv_entry_t pv)
{
	u_int count;

	if (atomic_cmpset_int(&pv->pv_hold, 1, 0)) {
		if (pv->pv_pmap == NULL)
			zfree(pvzone, pv);
		return;
	}

	for (;;) {
		count = pv->pv_hold;
		cpu_ccfence();
		KKASSERT((count & PV_HOLD_MASK) > 0);
		KKASSERT((count & (PV_HOLD_LOCKED | PV_HOLD_MASK)) !=
			 (PV_HOLD_LOCKED | 1));
		if (atomic_cmpset_int(&pv->pv_hold, count, count - 1)) {
			if (count == 1 && pv->pv_pmap == NULL)
				zfree(pvzone, pv);
			return;
		}
		/* retry */
	}
}

/*
 * Find or allocate the requested PV entry, returning a locked pv
 */
static
pv_entry_t
_pv_alloc(pmap_t pmap, vm_pindex_t pindex, int *isnew PMAP_DEBUG_DECL)
{
	pv_entry_t pv;
	pv_entry_t pnew = NULL;

	spin_lock(&pmap->pm_spin);
	for (;;) {
		if ((pv = pmap->pm_pvhint) == NULL || pv->pv_pindex != pindex) {
			pv = pv_entry_rb_tree_RB_LOOKUP(&pmap->pm_pvroot,
							pindex);
		}
		if (pv == NULL) {
			if (pnew == NULL) {
				spin_unlock(&pmap->pm_spin);
				pnew = zalloc(pvzone);
				spin_lock(&pmap->pm_spin);
				continue;
			}
			pnew->pv_pmap = pmap;
			pnew->pv_pindex = pindex;
			pnew->pv_hold = PV_HOLD_LOCKED | 1;
#ifdef PMAP_DEBUG
			pnew->pv_func = func;
			pnew->pv_line = lineno;
#endif
			pv_entry_rb_tree_RB_INSERT(&pmap->pm_pvroot, pnew);
			atomic_add_long(&pmap->pm_stats.resident_count, 1);
			spin_unlock(&pmap->pm_spin);
			*isnew = 1;
			return(pnew);
		}
		if (pnew) {
			spin_unlock(&pmap->pm_spin);
			zfree(pvzone, pnew);
			pnew = NULL;
			spin_lock(&pmap->pm_spin);
			continue;
		}
		if (_pv_hold_try(pv PMAP_DEBUG_COPY)) {
			spin_unlock(&pmap->pm_spin);
			*isnew = 0;
			return(pv);
		}
		spin_unlock(&pmap->pm_spin);
		_pv_lock(pv PMAP_DEBUG_COPY);
		if (pv->pv_pmap == pmap && pv->pv_pindex == pindex) {
			*isnew = 0;
			return(pv);
		}
		pv_put(pv);
		spin_lock(&pmap->pm_spin);
	}


}

/*
 * Find the requested PV entry, returning a locked+held pv or NULL
 */
static
pv_entry_t
_pv_get(pmap_t pmap, vm_pindex_t pindex PMAP_DEBUG_DECL)
{
	pv_entry_t pv;

	spin_lock(&pmap->pm_spin);
	for (;;) {
		/*
		 * Shortcut cache
		 */
		if ((pv = pmap->pm_pvhint) == NULL || pv->pv_pindex != pindex) {
			pv = pv_entry_rb_tree_RB_LOOKUP(&pmap->pm_pvroot,
							pindex);
		}
		if (pv == NULL) {
			spin_unlock(&pmap->pm_spin);
			return NULL;
		}
		if (_pv_hold_try(pv PMAP_DEBUG_COPY)) {
			pv_cache(pv, pindex);
			spin_unlock(&pmap->pm_spin);
			return(pv);
		}
		spin_unlock(&pmap->pm_spin);
		_pv_lock(pv PMAP_DEBUG_COPY);
		if (pv->pv_pmap == pmap && pv->pv_pindex == pindex)
			return(pv);
		pv_put(pv);
		spin_lock(&pmap->pm_spin);
	}
}

/*
 * Lookup, hold, and attempt to lock (pmap,pindex).
 *
 * If the entry does not exist NULL is returned and *errorp is set to 0
 *
 * If the entry exists and could be successfully locked it is returned and
 * errorp is set to 0.
 *
 * If the entry exists but could NOT be successfully locked it is returned
 * held and *errorp is set to 1.
 */
static
pv_entry_t
pv_get_try(pmap_t pmap, vm_pindex_t pindex, int *errorp)
{
	pv_entry_t pv;

	spin_lock(&pmap->pm_spin);
	if ((pv = pmap->pm_pvhint) == NULL || pv->pv_pindex != pindex)
		pv = pv_entry_rb_tree_RB_LOOKUP(&pmap->pm_pvroot, pindex);
	if (pv == NULL) {
		spin_unlock(&pmap->pm_spin);
		*errorp = 0;
		return NULL;
	}
	if (pv_hold_try(pv)) {
		pv_cache(pv, pindex);
		spin_unlock(&pmap->pm_spin);
		*errorp = 0;
		return(pv);	/* lock succeeded */
	}
	spin_unlock(&pmap->pm_spin);
	*errorp = 1;
	return (pv);		/* lock failed */
}

/*
 * Find the requested PV entry, returning a held pv or NULL
 */
static
pv_entry_t
pv_find(pmap_t pmap, vm_pindex_t pindex)
{
	pv_entry_t pv;

	spin_lock(&pmap->pm_spin);

	if ((pv = pmap->pm_pvhint) == NULL || pv->pv_pindex != pindex)
		pv = pv_entry_rb_tree_RB_LOOKUP(&pmap->pm_pvroot, pindex);
	if (pv == NULL) {
		spin_unlock(&pmap->pm_spin);
		return NULL;
	}
	pv_hold(pv);
	pv_cache(pv, pindex);
	spin_unlock(&pmap->pm_spin);
	return(pv);
}

/*
 * Lock a held pv, keeping the hold count
 */
static
void
_pv_lock(pv_entry_t pv PMAP_DEBUG_DECL)
{
	u_int count;

	for (;;) {
		count = pv->pv_hold;
		cpu_ccfence();
		if ((count & PV_HOLD_LOCKED) == 0) {
			if (atomic_cmpset_int(&pv->pv_hold, count,
					      count | PV_HOLD_LOCKED)) {
#ifdef PMAP_DEBUG
				pv->pv_func = func;
				pv->pv_line = lineno;
#endif
				return;
			}
			continue;
		}
		tsleep_interlock(pv, 0);
		if (atomic_cmpset_int(&pv->pv_hold, count,
				      count | PV_HOLD_WAITING)) {
#ifdef PMAP_DEBUG
			kprintf("pv waiting on %s:%d\n",
					pv->pv_func, pv->pv_line);
#endif
			tsleep(pv, PINTERLOCKED, "pvwait", hz);
		}
		/* retry */
	}
}

/*
 * Unlock a held and locked pv, keeping the hold count.
 */
static
void
pv_unlock(pv_entry_t pv)
{
	u_int count;

	if (atomic_cmpset_int(&pv->pv_hold, PV_HOLD_LOCKED | 1, 1))
		return;

	for (;;) {
		count = pv->pv_hold;
		cpu_ccfence();
		KKASSERT((count & (PV_HOLD_LOCKED|PV_HOLD_MASK)) >=
			 (PV_HOLD_LOCKED | 1));
		if (atomic_cmpset_int(&pv->pv_hold, count,
				      count &
				      ~(PV_HOLD_LOCKED | PV_HOLD_WAITING))) {
			if (count & PV_HOLD_WAITING)
				wakeup(pv);
			break;
		}
	}
}

/*
 * Unlock and drop a pv.  If the pv is no longer associated with a pmap
 * and the hold count drops to zero we will free it.
 *
 * Caller should not hold any spin locks.  We are protected from hold races
 * by virtue of holds only occuring only with a pmap_spin or vm_page_spin
 * lock held.  A pv cannot be located otherwise.
 */
static
void
pv_put(pv_entry_t pv)
{
	if (atomic_cmpset_int(&pv->pv_hold, PV_HOLD_LOCKED | 1, 0)) {
		if (pv->pv_pmap == NULL)
			zfree(pvzone, pv);
		return;
	}
	pv_unlock(pv);
	pv_drop(pv);
}

/*
 * Unlock, drop, and free a pv, destroying it.  The pv is removed from its
 * pmap.  Any pte operations must have already been completed.
 */
static
void
pv_free(pv_entry_t pv)
{
	pmap_t pmap;

	KKASSERT(pv->pv_m == NULL);
	if ((pmap = pv->pv_pmap) != NULL) {
		spin_lock(&pmap->pm_spin);
		pv_entry_rb_tree_RB_REMOVE(&pmap->pm_pvroot, pv);
		if (pmap->pm_pvhint == pv)
			pmap->pm_pvhint = NULL;
		atomic_add_long(&pmap->pm_stats.resident_count, -1);
		pv->pv_pmap = NULL;
		pv->pv_pindex = 0;
		spin_unlock(&pmap->pm_spin);
	}
	pv_put(pv);
}

/*
 * This routine is very drastic, but can save the system
 * in a pinch.
 */
void
pmap_collect(void)
{
	int i;
	vm_page_t m;
	static int warningdone=0;

	if (pmap_pagedaemon_waken == 0)
		return;
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
}

/*
 * Scan the pmap for active page table entries and issue a callback.
 * The callback must dispose of pte_pv.
 *
 * NOTE: Unmanaged page table entries will not have a pte_pv
 *
 * NOTE: Kernel page table entries will not have a pt_pv.  That is, wiring
 *	 counts are not tracked in kernel page table pages.
 *
 * It is assumed that the start and end are properly rounded to the page size.
 */
static void
pmap_scan(struct pmap *pmap, vm_offset_t sva, vm_offset_t eva,
	  void (*func)(pmap_t, struct pmap_inval_info *,
		       pv_entry_t, pv_entry_t, vm_offset_t,
		       pt_entry_t *, void *),
	  void *arg)
{
	pv_entry_t pdp_pv;	/* A page directory page PV */
	pv_entry_t pd_pv;	/* A page directory PV */
	pv_entry_t pt_pv;	/* A page table PV */
	pv_entry_t pte_pv;	/* A page table entry PV */
	pt_entry_t *ptep;
	vm_offset_t va_next;
	struct pmap_inval_info info;
	int error;

	if (pmap == NULL)
		return;

	/*
	 * Hold the token for stability; if the pmap is empty we have nothing
	 * to do.
	 */
	lwkt_gettoken(&pmap->pm_token);
#if 0
	if (pmap->pm_stats.resident_count == 0) {
		lwkt_reltoken(&pmap->pm_token);
		return;
	}
#endif

	pmap_inval_init(&info);

	/*
	 * Special handling for removing one page, which is a very common
	 * operation (it is?).
	 * NOTE: Locks must be ordered bottom-up. pte,pt,pd,pdp,pml4
	 */
	if (sva + PAGE_SIZE == eva) {
		if (sva >= VM_MAX_USER_ADDRESS) {
			/*
			 * Kernel mappings do not track wire counts on
			 * page table pages.
			 */
			pt_pv = NULL;
			pte_pv = pv_get(pmap, pmap_pte_pindex(sva));
			ptep = vtopte(sva);
		} else {
			/*
			 * User mappings may or may not have a pte_pv but
			 * will always have a pt_pv if the page is present.
			 */
			pte_pv = pv_get(pmap, pmap_pte_pindex(sva));
			pt_pv = pv_get(pmap, pmap_pt_pindex(sva));
			if (pt_pv == NULL) {
				KKASSERT(pte_pv == NULL);
				goto fast_skip;
			}
			ptep = pv_pte_lookup(pt_pv, pmap_pte_index(sva));
		}
		if (*ptep == 0) {
			/*
			 * Unlike the pv_find() case below we actually
			 * acquired a locked pv in this case so any
			 * race should have been resolved.  It is expected
			 * to not exist.
			 */
			KKASSERT(pte_pv == NULL);
		} else if (pte_pv) {
			KASSERT((*ptep & (PG_MANAGED|PG_V)) == (PG_MANAGED|
								PG_V),
				("bad *ptep %016lx sva %016lx pte_pv %p",
				*ptep, sva, pte_pv));
			func(pmap, &info, pte_pv, pt_pv, sva, ptep, arg);
		} else {
			KASSERT((*ptep & (PG_MANAGED|PG_V)) == PG_V,
				("bad *ptep %016lx sva %016lx pte_pv NULL",
				*ptep, sva));
			func(pmap, &info, pte_pv, pt_pv, sva, ptep, arg);
		}
		if (pt_pv)
			pv_put(pt_pv);
fast_skip:
		pmap_inval_done(&info);
		lwkt_reltoken(&pmap->pm_token);
		return;
	}

	/*
	 * NOTE: kernel mappings do not track page table pages, only
	 * 	 terminal pages.
	 *
	 * NOTE: Locks must be ordered bottom-up. pte,pt,pd,pdp,pml4.
	 *	 However, for the scan to be efficient we try to
	 *	 cache items top-down.
	 */
	pdp_pv = NULL;
	pd_pv = NULL;
	pt_pv = NULL;

	for (; sva < eva; sva = va_next) {
		lwkt_yield();
		if (sva >= VM_MAX_USER_ADDRESS) {
			if (pt_pv) {
				pv_put(pt_pv);
				pt_pv = NULL;
			}
			goto kernel_skip;
		}

		/*
		 * PDP cache
		 */
		if (pdp_pv == NULL) {
			pdp_pv = pv_get(pmap, pmap_pdp_pindex(sva));
		} else if (pdp_pv->pv_pindex != pmap_pdp_pindex(sva)) {
			pv_put(pdp_pv);
			pdp_pv = pv_get(pmap, pmap_pdp_pindex(sva));
		}
		if (pdp_pv == NULL) {
			va_next = (sva + NBPML4) & ~PML4MASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		/*
		 * PD cache
		 */
		if (pd_pv == NULL) {
			if (pdp_pv) {
				pv_put(pdp_pv);
				pdp_pv = NULL;
			}
			pd_pv = pv_get(pmap, pmap_pd_pindex(sva));
		} else if (pd_pv->pv_pindex != pmap_pd_pindex(sva)) {
			pv_put(pd_pv);
			if (pdp_pv) {
				pv_put(pdp_pv);
				pdp_pv = NULL;
			}
			pd_pv = pv_get(pmap, pmap_pd_pindex(sva));
		}
		if (pd_pv == NULL) {
			va_next = (sva + NBPDP) & ~PDPMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		/*
		 * PT cache
		 */
		if (pt_pv == NULL) {
			if (pdp_pv) {
				pv_put(pdp_pv);
				pdp_pv = NULL;
			}
			if (pd_pv) {
				pv_put(pd_pv);
				pd_pv = NULL;
			}
			pt_pv = pv_get(pmap, pmap_pt_pindex(sva));
		} else if (pt_pv->pv_pindex != pmap_pt_pindex(sva)) {
			if (pdp_pv) {
				pv_put(pdp_pv);
				pdp_pv = NULL;
			}
			if (pd_pv) {
				pv_put(pd_pv);
				pd_pv = NULL;
			}
			pv_put(pt_pv);
			pt_pv = pv_get(pmap, pmap_pt_pindex(sva));
		}

		/*
		 * We will scan or skip a page table page so adjust va_next
		 * either way.
		 */
		if (pt_pv == NULL) {
			va_next = (sva + NBPDR) & ~PDRMASK;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		/*
		 * From this point in the loop testing pt_pv for non-NULL
		 * means we are in UVM, else if it is NULL we are in KVM.
		 */
kernel_skip:
		va_next = (sva + NBPDR) & ~PDRMASK;
		if (va_next < sva)
			va_next = eva;

		/*
		 * Limit our scan to either the end of the va represented
		 * by the current page table page, or to the end of the
		 * range being removed.
		 *
		 * Scan the page table for pages.  Some pages may not be
		 * managed (might not have a pv_entry).
		 *
		 * There is no page table management for kernel pages so
		 * pt_pv will be NULL in that case, but otherwise pt_pv
		 * is non-NULL, locked, and referenced.
		 */
		if (va_next > eva)
			va_next = eva;

		/*
		 * At this point a non-NULL pt_pv means a UVA, and a NULL
		 * pt_pv means a KVA.
		 */
		if (pt_pv)
			ptep = pv_pte_lookup(pt_pv, pmap_pte_index(sva));
		else
			ptep = vtopte(sva);

		while (sva < va_next) {
			/*
			 * Acquire the related pte_pv, if any.  If *ptep == 0
			 * the related pte_pv should not exist, but if *ptep
			 * is not zero the pte_pv may or may not exist (e.g.
			 * will not exist for an unmanaged page).
			 *
			 * However a multitude of races are possible here.
			 *
			 * In addition, the (pt_pv, pte_pv) lock order is
			 * backwards, so we have to be careful in aquiring
			 * a properly locked pte_pv.
			 */
			lwkt_yield();
			if (pt_pv) {
				pte_pv = pv_get_try(pmap, pmap_pte_pindex(sva),
						    &error);
				if (error) {
					if (pdp_pv) {
						pv_put(pdp_pv);
						pdp_pv = NULL;
					}
					if (pd_pv) {
						pv_put(pd_pv);
						pd_pv = NULL;
					}
					pv_put(pt_pv);	 /* must be non-NULL */
					pt_pv = NULL;
					pv_lock(pte_pv); /* safe to block now */
					pv_put(pte_pv);
					pte_pv = NULL;
					pt_pv = pv_get(pmap,
						       pmap_pt_pindex(sva));
					continue;
				}
			} else {
				pte_pv = pv_get(pmap, pmap_pte_pindex(sva));
			}

			/*
			 * Ok, if *ptep == 0 we had better NOT have a pte_pv.
			 */
			if (*ptep == 0) {
				if (pte_pv) {
					kprintf("Unexpected non-NULL pte_pv "
						"%p pt_pv %p *ptep = %016lx\n",
						pte_pv, pt_pv, *ptep);
					panic("Unexpected non-NULL pte_pv");
				}
				sva += PAGE_SIZE;
				++ptep;
				continue;
			}

			/*
			 * Ready for the callback.  The locked pte_pv (if any)
			 * is consumed by the callback.  pte_pv will exist if
			 *  the page is managed, and will not exist if it
			 * isn't.
			 */
			if (pte_pv) {
				KASSERT((*ptep & (PG_MANAGED|PG_V)) ==
					 (PG_MANAGED|PG_V),
					("bad *ptep %016lx sva %016lx "
					 "pte_pv %p",
					 *ptep, sva, pte_pv));
				func(pmap, &info, pte_pv, pt_pv, sva,
				     ptep, arg);
			} else {
				KASSERT((*ptep & (PG_MANAGED|PG_V)) ==
					 PG_V,
					("bad *ptep %016lx sva %016lx "
					 "pte_pv NULL",
					 *ptep, sva));
				func(pmap, &info, pte_pv, pt_pv, sva,
				     ptep, arg);
			}
			pte_pv = NULL;
			sva += PAGE_SIZE;
			++ptep;
		}
	}
	if (pdp_pv) {
		pv_put(pdp_pv);
		pdp_pv = NULL;
	}
	if (pd_pv) {
		pv_put(pd_pv);
		pd_pv = NULL;
	}
	if (pt_pv) {
		pv_put(pt_pv);
		pt_pv = NULL;
	}
	pmap_inval_done(&info);
	lwkt_reltoken(&pmap->pm_token);
}

void
pmap_remove(struct pmap *pmap, vm_offset_t sva, vm_offset_t eva)
{
	pmap_scan(pmap, sva, eva, pmap_remove_callback, NULL);
}

static void
pmap_remove_callback(pmap_t pmap, struct pmap_inval_info *info,
		     pv_entry_t pte_pv, pv_entry_t pt_pv, vm_offset_t va,
		     pt_entry_t *ptep, void *arg __unused)
{
	pt_entry_t pte;

	if (pte_pv) {
		/*
		 * This will also drop pt_pv's wire_count. Note that
		 * terminal pages are not wired based on mmu presence.
		 */
		pmap_remove_pv_pte(pte_pv, pt_pv, info);
		pmap_remove_pv_page(pte_pv);
		pv_free(pte_pv);
	} else {
		/*
		 * pt_pv's wire_count is still bumped by unmanaged pages
		 * so we must decrement it manually.
		 */
		pmap_inval_interlock(info, pmap, va);
		pte = pte_load_clear(ptep);
		pmap_inval_deinterlock(info, pmap);
		if (pte & PG_W)
			atomic_add_long(&pmap->pm_stats.wired_count, -1);
		atomic_add_long(&pmap->pm_stats.resident_count, -1);
		if (pt_pv && vm_page_unwire_quick(pt_pv->pv_m))
			panic("pmap_remove: insufficient wirecount");
	}
}

/*
 * Removes this physical page from all physical maps in which it resides.
 * Reflects back modify bits to the pager.
 *
 * This routine may not be called from an interrupt.
 */
static
void
pmap_remove_all(vm_page_t m)
{
	struct pmap_inval_info info;
	pv_entry_t pv;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return;

	pmap_inval_init(&info);
	vm_page_spin_lock(m);
	while ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {
		KKASSERT(pv->pv_m == m);
		if (pv_hold_try(pv)) {
			vm_page_spin_unlock(m);
		} else {
			vm_page_spin_unlock(m);
			pv_lock(pv);
			if (pv->pv_m != m) {
				pv_put(pv);
				vm_page_spin_lock(m);
				continue;
			}
		}
		/*
		 * Holding no spinlocks, pv is locked.
		 */
		pmap_remove_pv_pte(pv, NULL, &info);
		pmap_remove_pv_page(pv);
		pv_free(pv);
		vm_page_spin_lock(m);
	}
	KKASSERT((m->flags & (PG_MAPPED|PG_WRITEABLE)) == 0);
	vm_page_spin_unlock(m);
	pmap_inval_done(&info);
}

/*
 * pmap_protect:
 *
 *	Set the physical protection on the specified range of this map
 *	as requested.
 *
 *	This function may not be called from an interrupt if the map is
 *	not the kernel_pmap.
 */
void
pmap_protect(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, vm_prot_t prot)
{
	/* JG review for NX */

	if (pmap == NULL)
		return;
	if ((prot & VM_PROT_READ) == VM_PROT_NONE) {
		pmap_remove(pmap, sva, eva);
		return;
	}
	if (prot & VM_PROT_WRITE)
		return;
	pmap_scan(pmap, sva, eva, pmap_protect_callback, &prot);
}

static
void
pmap_protect_callback(pmap_t pmap, struct pmap_inval_info *info,
		      pv_entry_t pte_pv, pv_entry_t pt_pv, vm_offset_t va,
		      pt_entry_t *ptep, void *arg __unused)
{
	pt_entry_t pbits;
	pt_entry_t cbits;
	vm_page_t m;

	/*
	 * XXX non-optimal.
	 */
	pmap_inval_interlock(info, pmap, va);
again:
	pbits = *ptep;
	cbits = pbits;
	if (pte_pv) {
		m = NULL;
		if (pbits & PG_A) {
			m = PHYS_TO_VM_PAGE(pbits & PG_FRAME);
			KKASSERT(m == pte_pv->pv_m);
			vm_page_flag_set(m, PG_REFERENCED);
			cbits &= ~PG_A;
		}
		if (pbits & PG_M) {
			if (pmap_track_modified(pte_pv->pv_pindex)) {
				if (m == NULL)
					m = PHYS_TO_VM_PAGE(pbits & PG_FRAME);
				vm_page_dirty(m);
				cbits &= ~PG_M;
			}
		}
	}
	cbits &= ~PG_RW;
	if (pbits != cbits && !atomic_cmpset_long(ptep, pbits, cbits)) {
		goto again;
	}
	pmap_inval_deinterlock(info, pmap);
	if (pte_pv)
		pv_put(pte_pv);
}

/*
 * Insert the vm_page (m) at the virtual address (va), replacing any prior
 * mapping at that address.  Set protection and wiring as requested.
 *
 * NOTE: This routine MUST insert the page into the pmap now, it cannot
 *	 lazy-evaluate.
 */
void
pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
	   boolean_t wired)
{
	pmap_inval_info info;
	pv_entry_t pt_pv;	/* page table */
	pv_entry_t pte_pv;	/* page table entry */
	pt_entry_t *ptep;
	vm_paddr_t opa;
	pt_entry_t origpte, newpte;
	vm_paddr_t pa;

	if (pmap == NULL)
		return;
	va = trunc_page(va);
#ifdef PMAP_DIAGNOSTIC
	if (va >= KvaEnd)
		panic("pmap_enter: toobig");
	if ((va >= UPT_MIN_ADDRESS) && (va < UPT_MAX_ADDRESS))
		panic("pmap_enter: invalid to pmap_enter page table "
		      "pages (va: 0x%lx)", va);
#endif
	if (va < UPT_MAX_ADDRESS && pmap == &kernel_pmap) {
		kprintf("Warning: pmap_enter called on UVA with "
			"kernel_pmap\n");
#ifdef DDB
		db_print_backtrace();
#endif
	}
	if (va >= UPT_MAX_ADDRESS && pmap != &kernel_pmap) {
		kprintf("Warning: pmap_enter called on KVA without"
			"kernel_pmap\n");
#ifdef DDB
		db_print_backtrace();
#endif
	}

	/*
	 * Get locked PV entries for our new page table entry (pte_pv)
	 * and for its parent page table (pt_pv).  We need the parent
	 * so we can resolve the location of the ptep.
	 *
	 * Only hardware MMU actions can modify the ptep out from
	 * under us.
	 *
	 * if (m) is fictitious or unmanaged we do not create a managing
	 * pte_pv for it.  Any pre-existing page's management state must
	 * match (avoiding code complexity).
	 *
	 * If the pmap is still being initialized we assume existing
	 * page tables.
	 *
	 * Kernel mapppings do not track page table pages (i.e. pt_pv).
	 * pmap_allocpte() checks the
	 */
	if (pmap_initialized == FALSE) {
		pte_pv = NULL;
		pt_pv = NULL;
		ptep = vtopte(va);
	} else if (m->flags & (PG_FICTITIOUS | PG_UNMANAGED)) {
		pte_pv = NULL;
		if (va >= VM_MAX_USER_ADDRESS) {
			pt_pv = NULL;
			ptep = vtopte(va);
		} else {
			pt_pv = pmap_allocpte(pmap, pmap_pt_pindex(va), NULL);
			ptep = pv_pte_lookup(pt_pv, pmap_pte_index(va));
		}
		KKASSERT(*ptep == 0 || (*ptep & PG_MANAGED) == 0);
	} else {
		if (va >= VM_MAX_USER_ADDRESS) {
			pt_pv = NULL;
			pte_pv = pmap_allocpte(pmap, pmap_pte_pindex(va), NULL);
			ptep = vtopte(va);
		} else {
			pte_pv = pmap_allocpte(pmap, pmap_pte_pindex(va),
					       &pt_pv);
			ptep = pv_pte_lookup(pt_pv, pmap_pte_index(va));
		}
		KKASSERT(*ptep == 0 || (*ptep & PG_MANAGED));
	}

	pa = VM_PAGE_TO_PHYS(m);
	origpte = *ptep;
	opa = origpte & PG_FRAME;

	newpte = (pt_entry_t)(pa | pte_prot(pmap, prot) | PG_V | PG_A);
	if (wired)
		newpte |= PG_W;
	if (va < VM_MAX_USER_ADDRESS)
		newpte |= PG_U;
	if (pte_pv)
		newpte |= PG_MANAGED;
	if (pmap == &kernel_pmap)
		newpte |= pgeflag;

	/*
	 * It is possible for multiple faults to occur in threaded
	 * environments, the existing pte might be correct.
	 */
	if (((origpte ^ newpte) & ~(pt_entry_t)(PG_M|PG_A)) == 0)
		goto done;

	if ((prot & VM_PROT_NOSYNC) == 0)
		pmap_inval_init(&info);

	/*
	 * Ok, either the address changed or the protection or wiring
	 * changed.
	 *
	 * Clear the current entry, interlocking the removal.  For managed
	 * pte's this will also flush the modified state to the vm_page.
	 * Atomic ops are mandatory in order to ensure that PG_M events are
	 * not lost during any transition.
	 */
	if (opa) {
		if (pte_pv) {
			/*
			 * pmap_remove_pv_pte() unwires pt_pv and assumes
			 * we will free pte_pv, but since we are reusing
			 * pte_pv we want to retain the wire count.
			 *
			 * pt_pv won't exist for a kernel page (managed or
			 * otherwise).
			 */
			if (pt_pv)
				vm_page_wire_quick(pt_pv->pv_m);
			if (prot & VM_PROT_NOSYNC)
				pmap_remove_pv_pte(pte_pv, pt_pv, NULL);
			else
				pmap_remove_pv_pte(pte_pv, pt_pv, &info);
			if (pte_pv->pv_m)
				pmap_remove_pv_page(pte_pv);
		} else if (prot & VM_PROT_NOSYNC) {
			/* leave wire count on PT page intact */
			(void)pte_load_clear(ptep);
			cpu_invlpg((void *)va);
			atomic_add_long(&pmap->pm_stats.resident_count, -1);
		} else {
			/* leave wire count on PT page intact */
			pmap_inval_interlock(&info, pmap, va);
			(void)pte_load_clear(ptep);
			pmap_inval_deinterlock(&info, pmap);
			atomic_add_long(&pmap->pm_stats.resident_count, -1);
		}
		KKASSERT(*ptep == 0);
	}

	if (pte_pv) {
		/*
		 * Enter on the PV list if part of our managed memory.
		 * Wiring of the PT page is already handled.
		 */
		KKASSERT(pte_pv->pv_m == NULL);
		vm_page_spin_lock(m);
		pte_pv->pv_m = m;
		TAILQ_INSERT_TAIL(&m->md.pv_list, pte_pv, pv_list);
		/*
		if (m->object)
			atomic_add_int(&m->object->agg_pv_list_count, 1);
		*/
		vm_page_flag_set(m, PG_MAPPED);
		vm_page_spin_unlock(m);
	} else if (pt_pv && opa == 0) {
		/*
		 * We have to adjust the wire count on the PT page ourselves
		 * for unmanaged entries.  If opa was non-zero we retained
		 * the existing wire count from the removal.
		 */
		vm_page_wire_quick(pt_pv->pv_m);
	}

	/*
	 * Ok, for UVM (pt_pv != NULL) we don't need to interlock or
	 * invalidate anything, the TLB won't have any stale entries to
	 * remove.
	 *
	 * For KVM there appear to still be issues.  Theoretically we
	 * should be able to scrap the interlocks entirely but we
	 * get crashes.
	 */
	if ((prot & VM_PROT_NOSYNC) == 0 && pt_pv == NULL)
		pmap_inval_interlock(&info, pmap, va);
	*(volatile pt_entry_t *)ptep = newpte;

	if ((prot & VM_PROT_NOSYNC) == 0 && pt_pv == NULL)
		pmap_inval_deinterlock(&info, pmap);
	else if (pt_pv == NULL)
		cpu_invlpg((void *)va);

	if (wired)
		atomic_add_long(&pmap->pm_stats.wired_count, 1);
	if (newpte & PG_RW)
		vm_page_flag_set(m, PG_WRITEABLE);
	if (pte_pv == NULL)
		atomic_add_long(&pmap->pm_stats.resident_count, 1);

	/*
	 * Cleanup
	 */
	if ((prot & VM_PROT_NOSYNC) == 0 || pte_pv == NULL)
		pmap_inval_done(&info);
done:
	KKASSERT((newpte & PG_MANAGED) == 0 || (m->flags & PG_MAPPED));

	/*
	 * Cleanup the pv entry, allowing other accessors.
	 */
	if (pte_pv)
		pv_put(pte_pv);
	if (pt_pv)
		pv_put(pt_pv);
}

/*
 * This code works like pmap_enter() but assumes VM_PROT_READ and not-wired.
 * This code also assumes that the pmap has no pre-existing entry for this
 * VA.
 *
 * This code currently may only be used on user pmaps, not kernel_pmap.
 */
void
pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m)
{
	pmap_enter(pmap, va, m, VM_PROT_READ, FALSE);
}

/*
 * Make a temporary mapping for a physical address.  This is only intended
 * to be used for panic dumps.
 *
 * The caller is responsible for calling smp_invltlb().
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
 */
static int pmap_object_init_pt_callback(vm_page_t p, void *data);

void
pmap_object_init_pt(pmap_t pmap, vm_offset_t addr, vm_prot_t prot,
		    vm_object_t object, vm_pindex_t pindex, 
		    vm_size_t size, int limit)
{
	struct rb_vm_page_scan_info info;
	struct lwp *lp;
	vm_size_t psize;

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

	psize = x86_64_btop(size);

	if ((object->type != OBJT_VNODE) ||
		((limit & MAP_PREFAULT_PARTIAL) && (psize > MAX_INIT_PT) &&
			(object->resident_page_count > MAX_INIT_PT))) {
		return;
	}

	if (pindex + psize > object->size) {
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
	 * We cannot safely scan the object's memq without holding the
	 * object token.
	 */
	info.start_pindex = pindex;
	info.end_pindex = pindex + psize - 1;
	info.limit = limit;
	info.mpte = NULL;
	info.addr = addr;
	info.pmap = pmap;

	vm_object_hold_shared(object);
	vm_page_rb_tree_RB_SCAN(&object->rb_memq, rb_vm_page_scancmp,
				pmap_object_init_pt_callback, &info);
	vm_object_drop(object);
}

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
				 info->addr + x86_64_ptob(rel_index), p);
	}
	vm_page_wakeup(p);
	lwkt_yield();
	return(0);
}

/*
 * Return TRUE if the pmap is in shape to trivially pre-fault the specified
 * address.
 *
 * Returns FALSE if it would be non-trivial or if a pte is already loaded
 * into the slot.
 *
 * XXX This is safe only because page table pages are not freed.
 */
int
pmap_prefault_ok(pmap_t pmap, vm_offset_t addr)
{
	pt_entry_t *pte;

	/*spin_lock(&pmap->pm_spin);*/
	if ((pte = pmap_pte(pmap, addr)) != NULL) {
		if (*pte & PG_V) {
			/*spin_unlock(&pmap->pm_spin);*/
			return FALSE;
		}
	}
	/*spin_unlock(&pmap->pm_spin);*/
	return TRUE;
}

/*
 * Change the wiring attribute for a pmap/va pair.  The mapping must already
 * exist in the pmap.  The mapping may or may not be managed.
 */
void
pmap_change_wiring(pmap_t pmap, vm_offset_t va, boolean_t wired)
{
	pt_entry_t *ptep;
	pv_entry_t pv;

	if (pmap == NULL)
		return;
	lwkt_gettoken(&pmap->pm_token);
	pv = pmap_allocpte(pmap, pmap_pt_pindex(va), NULL);
	ptep = pv_pte_lookup(pv, pmap_pte_index(va));

	if (wired && !pmap_pte_w(ptep))
		atomic_add_long(&pmap->pm_stats.wired_count, 1);
	else if (!wired && pmap_pte_w(ptep))
		atomic_add_long(&pmap->pm_stats.wired_count, -1);

	/*
	 * Wiring is not a hardware characteristic so there is no need to
	 * invalidate TLB.  However, in an SMP environment we must use
	 * a locked bus cycle to update the pte (if we are not using 
	 * the pmap_inval_*() API that is)... it's ok to do this for simple
	 * wiring changes.
	 */
#ifdef SMP
	if (wired)
		atomic_set_long(ptep, PG_W);
	else
		atomic_clear_long(ptep, PG_W);
#else
	if (wired)
		atomic_set_long_nonlocked(ptep, PG_W);
	else
		atomic_clear_long_nonlocked(ptep, PG_W);
#endif
	pv_put(pv);
	lwkt_reltoken(&pmap->pm_token);
}



/*
 * Copy the range specified by src_addr/len from the source map to
 * the range dst_addr/len in the destination map.
 *
 * This routine is only advisory and need not do anything.
 */
void
pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vm_offset_t dst_addr, 
	  vm_size_t len, vm_offset_t src_addr)
{
}	

/*
 * pmap_zero_page:
 *
 *	Zero the specified physical page.
 *
 *	This function may be called from an interrupt and no locking is
 *	required.
 */
void
pmap_zero_page(vm_paddr_t phys)
{
	vm_offset_t va = PHYS_TO_DMAP(phys);

	pagezero((void *)va);
}

/*
 * pmap_page_assertzero:
 *
 *	Assert that a page is empty, panic if it isn't.
 */
void
pmap_page_assertzero(vm_paddr_t phys)
{
	vm_offset_t va = PHYS_TO_DMAP(phys);
	size_t i;

	for (i = 0; i < PAGE_SIZE; i += sizeof(long)) {
		if (*(long *)((char *)va + i) != 0) {
			panic("pmap_page_assertzero() @ %p not zero!\n",
			      (void *)(intptr_t)va);
		}
	}
}

/*
 * pmap_zero_page:
 *
 *	Zero part of a physical page by mapping it into memory and clearing
 *	its contents with bzero.
 *
 *	off and size may not cover an area beyond a single hardware page.
 */
void
pmap_zero_page_area(vm_paddr_t phys, int off, int size)
{
	vm_offset_t virt = PHYS_TO_DMAP(phys);

	bzero((char *)virt + off, size);
}

/*
 * pmap_copy_page:
 *
 *	Copy the physical page from the source PA to the target PA.
 *	This function may be called from an interrupt.  No locking
 *	is required.
 */
void
pmap_copy_page(vm_paddr_t src, vm_paddr_t dst)
{
	vm_offset_t src_virt, dst_virt;

	src_virt = PHYS_TO_DMAP(src);
	dst_virt = PHYS_TO_DMAP(dst);
	bcopy((void *)src_virt, (void *)dst_virt, PAGE_SIZE);
}

/*
 * pmap_copy_page_frag:
 *
 *	Copy the physical page from the source PA to the target PA.
 *	This function may be called from an interrupt.  No locking
 *	is required.
 */
void
pmap_copy_page_frag(vm_paddr_t src, vm_paddr_t dst, size_t bytes)
{
	vm_offset_t src_virt, dst_virt;

	src_virt = PHYS_TO_DMAP(src);
	dst_virt = PHYS_TO_DMAP(dst);

	bcopy((char *)src_virt + (src & PAGE_MASK),
	      (char *)dst_virt + (dst & PAGE_MASK),
	      bytes);
}

/*
 * Returns true if the pmap's pv is one of the first 16 pvs linked to from
 * this page.  This count may be changed upwards or downwards in the future;
 * it is only necessary that true be returned for a small subset of pmaps
 * for proper page aging.
 */
boolean_t
pmap_page_exists_quick(pmap_t pmap, vm_page_t m)
{
	pv_entry_t pv;
	int loops = 0;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return FALSE;

	vm_page_spin_lock(m);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		if (pv->pv_pmap == pmap) {
			vm_page_spin_unlock(m);
			return TRUE;
		}
		loops++;
		if (loops >= 16)
			break;
	}
	vm_page_spin_unlock(m);
	return (FALSE);
}

/*
 * Remove all pages from specified address space this aids process exit
 * speeds.  Also, this code may be special cased for the current process
 * only.
 */
void
pmap_remove_pages(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	pmap_remove(pmap, sva, eva);
}

/*
 * pmap_testbit tests bits in pte's note that the testbit/clearbit
 * routines are inline, and a lot of things compile-time evaluate.
 */
static
boolean_t
pmap_testbit(vm_page_t m, int bit)
{
	pv_entry_t pv;
	pt_entry_t *pte;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return FALSE;

	if (TAILQ_FIRST(&m->md.pv_list) == NULL)
		return FALSE;
	vm_page_spin_lock(m);
	if (TAILQ_FIRST(&m->md.pv_list) == NULL) {
		vm_page_spin_unlock(m);
		return FALSE;
	}

	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		/*
		 * if the bit being tested is the modified bit, then
		 * mark clean_map and ptes as never
		 * modified.
		 */
		if (bit & (PG_A|PG_M)) {
			if (!pmap_track_modified(pv->pv_pindex))
				continue;
		}

#if defined(PMAP_DIAGNOSTIC)
		if (pv->pv_pmap == NULL) {
			kprintf("Null pmap (tb) at pindex: %"PRIu64"\n",
			    pv->pv_pindex);
			continue;
		}
#endif
		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_pindex << PAGE_SHIFT);
		if (*pte & bit) {
			vm_page_spin_unlock(m);
			return TRUE;
		}
	}
	vm_page_spin_unlock(m);
	return (FALSE);
}

/*
 * This routine is used to modify bits in ptes.  Only one bit should be
 * specified.  PG_RW requires special handling.
 *
 * Caller must NOT hold any spin locks
 */
static __inline
void
pmap_clearbit(vm_page_t m, int bit)
{
	struct pmap_inval_info info;
	pv_entry_t pv;
	pt_entry_t *pte;
	pt_entry_t pbits;
	pmap_t save_pmap;

	if (bit == PG_RW)
		vm_page_flag_clear(m, PG_WRITEABLE);
	if (!pmap_initialized || (m->flags & PG_FICTITIOUS)) {
		return;
	}

	/*
	 * PG_M or PG_A case
	 *
	 * Loop over all current mappings setting/clearing as appropos If
	 * setting RO do we need to clear the VAC?
	 *
	 * NOTE: When clearing PG_M we could also (not implemented) drop
	 *	 through to the PG_RW code and clear PG_RW too, forcing
	 *	 a fault on write to redetect PG_M for virtual kernels, but
	 *	 it isn't necessary since virtual kernels invalidate the
	 *	 pte when they clear the VPTE_M bit in their virtual page
	 *	 tables.
	 *
	 * NOTE: Does not re-dirty the page when clearing only PG_M.
	 */
	if ((bit & PG_RW) == 0) {
		vm_page_spin_lock(m);
		TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
	#if defined(PMAP_DIAGNOSTIC)
			if (pv->pv_pmap == NULL) {
				kprintf("Null pmap (cb) at pindex: %"PRIu64"\n",
				    pv->pv_pindex);
				continue;
			}
	#endif
			pte = pmap_pte_quick(pv->pv_pmap,
					     pv->pv_pindex << PAGE_SHIFT);
			pbits = *pte;
			if (pbits & bit)
				atomic_clear_long(pte, bit);
		}
		vm_page_spin_unlock(m);
		return;
	}

	/*
	 * Clear PG_RW.  Also clears PG_M and marks the page dirty if PG_M
	 * was set.
	 */
	pmap_inval_init(&info);

restart:
	vm_page_spin_lock(m);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		/*
		 * don't write protect pager mappings
		 */
		if (!pmap_track_modified(pv->pv_pindex))
			continue;

#if defined(PMAP_DIAGNOSTIC)
		if (pv->pv_pmap == NULL) {
			kprintf("Null pmap (cb) at pindex: %"PRIu64"\n",
			    pv->pv_pindex);
			continue;
		}
#endif
		/*
		 * Skip pages which do not have PG_RW set.
		 */
		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_pindex << PAGE_SHIFT);
		if ((*pte & PG_RW) == 0)
			continue;

		/*
		 * Lock the PV
		 */
		if (pv_hold_try(pv) == 0) {
			vm_page_spin_unlock(m);
			pv_lock(pv);	/* held, now do a blocking lock */
			pv_put(pv);	/* and release */
			goto restart;	/* anything could have happened */
		}

		save_pmap = pv->pv_pmap;
		vm_page_spin_unlock(m);
		pmap_inval_interlock(&info, save_pmap,
				     (vm_offset_t)pv->pv_pindex << PAGE_SHIFT);
		KKASSERT(pv->pv_pmap == save_pmap);
		for (;;) {
			pbits = *pte;
			cpu_ccfence();
			if (atomic_cmpset_long(pte, pbits,
					       pbits & ~(PG_RW|PG_M))) {
				break;
			}
		}
		pmap_inval_deinterlock(&info, save_pmap);
		vm_page_spin_lock(m);

		/*
		 * If PG_M was found to be set while we were clearing PG_RW
		 * we also clear PG_M (done above) and mark the page dirty.
		 * Callers expect this behavior.
		 */
		if (pbits & PG_M)
			vm_page_dirty(m);
		pv_put(pv);
	}
	vm_page_spin_unlock(m);
	pmap_inval_done(&info);
}

/*
 * Lower the permission for all mappings to a given page.
 *
 * Page must be busied by caller.
 */
void
pmap_page_protect(vm_page_t m, vm_prot_t prot)
{
	/* JG NX support? */
	if ((prot & VM_PROT_WRITE) == 0) {
		if (prot & (VM_PROT_READ | VM_PROT_EXECUTE)) {
			/*
			 * NOTE: pmap_clearbit(.. PG_RW) also clears
			 *	 the PG_WRITEABLE flag in (m).
			 */
			pmap_clearbit(m, PG_RW);
		} else {
			pmap_remove_all(m);
		}
	}
}

vm_paddr_t
pmap_phys_address(vm_pindex_t ppn)
{
	return (x86_64_ptob(ppn));
}

/*
 * Return a count of reference bits for a page, clearing those bits.
 * It is not necessary for every reference bit to be cleared, but it
 * is necessary that 0 only be returned when there are truly no
 * reference bits set.
 *
 * XXX: The exact number of bits to check and clear is a matter that
 * should be tested and standardized at some point in the future for
 * optimal aging of shared pages.
 *
 * This routine may not block.
 */
int
pmap_ts_referenced(vm_page_t m)
{
	pv_entry_t pv;
	pt_entry_t *pte;
	int rtval = 0;

	if (!pmap_initialized || (m->flags & PG_FICTITIOUS))
		return (rtval);

	vm_page_spin_lock(m);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_list) {
		if (!pmap_track_modified(pv->pv_pindex))
			continue;
		pte = pmap_pte_quick(pv->pv_pmap, pv->pv_pindex << PAGE_SHIFT);
		if (pte && (*pte & PG_A)) {
#ifdef SMP
			atomic_clear_long(pte, PG_A);
#else
			atomic_clear_long_nonlocked(pte, PG_A);
#endif
			rtval++;
			if (rtval > 4)
				break;
		}
	}
	vm_page_spin_unlock(m);
	return (rtval);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page was modified
 *	in any physical maps.
 */
boolean_t
pmap_is_modified(vm_page_t m)
{
	boolean_t res;

	res = pmap_testbit(m, PG_M);
	return (res);
}

/*
 *	Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(vm_page_t m)
{
	pmap_clearbit(m, PG_M);
}

/*
 *	pmap_clear_reference:
 *
 *	Clear the reference bit on the specified physical page.
 */
void
pmap_clear_reference(vm_page_t m)
{
	pmap_clearbit(m, PG_A);
}

/*
 * Miscellaneous support routines follow
 */

static
void
i386_protection_init(void)
{
	int *kp, prot;

	/* JG NX support may go here; No VM_PROT_EXECUTE ==> set NX bit  */
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
 */
void *
pmap_mapdev(vm_paddr_t pa, vm_size_t size)
{
	vm_offset_t va, tmpva, offset;
	pt_entry_t *pte;

	offset = pa & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);

	va = kmem_alloc_nofault(&kernel_map, size, PAGE_SIZE);
	if (va == 0)
		panic("pmap_mapdev: Couldn't alloc kernel virtual memory");

	pa = pa & ~PAGE_MASK;
	for (tmpva = va; size > 0;) {
		pte = vtopte(tmpva);
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
	pt_entry_t *pte;

	offset = pa & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);

	va = kmem_alloc_nofault(&kernel_map, size, PAGE_SIZE);
	if (va == 0)
		panic("pmap_mapdev: Couldn't alloc kernel virtual memory");

	pa = pa & ~PAGE_MASK;
	for (tmpva = va; size > 0;) {
		pte = vtopte(tmpva);
		*pte = pa | PG_RW | PG_V | PG_N; /* | pgeflag; */
		size -= PAGE_SIZE;
		tmpva += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
	cpu_invltlb();
	smp_invltlb();

	return ((void *)(va + offset));
}

void
pmap_unmapdev(vm_offset_t va, vm_size_t size)
{
	vm_offset_t base, offset;

	base = va & ~PAGE_MASK;
	offset = va & PAGE_MASK;
	size = roundup(offset + size, PAGE_SIZE);
	pmap_qremove(va, size >> PAGE_SHIFT);
	kmem_free(&kernel_map, base, size);
}

/*
 * perform the pmap work for mincore
 */
int
pmap_mincore(pmap_t pmap, vm_offset_t addr)
{
	pt_entry_t *ptep, pte;
	vm_page_t m;
	int val = 0;
	
	lwkt_gettoken(&pmap->pm_token);
	ptep = pmap_pte(pmap, addr);

	if (ptep && (pte = *ptep) != 0) {
		vm_offset_t pa;

		val = MINCORE_INCORE;
		if ((pte & PG_MANAGED) == 0)
			goto done;

		pa = pte & PG_FRAME;

		m = PHYS_TO_VM_PAGE(pa);

		/*
		 * Modified by us
		 */
		if (pte & PG_M)
			val |= MINCORE_MODIFIED|MINCORE_MODIFIED_OTHER;
		/*
		 * Modified by someone
		 */
		else if (m->dirty || pmap_is_modified(m))
			val |= MINCORE_MODIFIED_OTHER;
		/*
		 * Referenced by us
		 */
		if (pte & PG_A)
			val |= MINCORE_REFERENCED|MINCORE_REFERENCED_OTHER;

		/*
		 * Referenced by someone
		 */
		else if ((m->flags & PG_REFERENCED) || pmap_ts_referenced(m)) {
			val |= MINCORE_REFERENCED_OTHER;
			vm_page_flag_set(m, PG_REFERENCED);
		}
	} 
done:
	lwkt_reltoken(&pmap->pm_token);

	return val;
}

/*
 * Replace p->p_vmspace with a new one.  If adjrefs is non-zero the new
 * vmspace will be ref'd and the old one will be deref'd.
 *
 * The vmspace for all lwps associated with the process will be adjusted
 * and cr3 will be reloaded if any lwp is the current lwp.
 *
 * The process must hold the vmspace->vm_map.token for oldvm and newvm
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
 * Caller does not necessarily hold any vmspace tokens.  Caller must control
 * the lwp (typically be in the context of the lwp).  We use a critical
 * section to protect against statclock and hardclock (statistics collection).
 */
void
pmap_setlwpvm(struct lwp *lp, struct vmspace *newvm)
{
	struct vmspace *oldvm;
	struct pmap *pmap;

	oldvm = lp->lwp_vmspace;

	if (oldvm != newvm) {
		crit_enter();
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
			curthread->td_pcb->pcb_cr3 = vtophys(pmap->pm_pml4);
			curthread->td_pcb->pcb_cr3 |= PG_RW | PG_U | PG_V;
			load_cr3(curthread->td_pcb->pcb_cr3);
			pmap = vmspace_pmap(oldvm);
#if defined(SMP)
			atomic_clear_cpumask(&pmap->pm_active, mycpu->gd_cpumask);
#else
			pmap->pm_active &= ~(cpumask_t)1;
#endif
		}
		crit_exit();
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
 * This function cannot sleep!
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
 * Used by kmalloc/kfree, page already exists at va
 */
vm_page_t
pmap_kvtom(vm_offset_t va)
{
	return(PHYS_TO_VM_PAGE(*vtopte(va) & PG_FRAME));
}
