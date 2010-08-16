/*
 * (MPSAFE)
 *
 * Copyright (c) 1990 University of Utah.
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 *	@(#)device_pager.c	8.1 (Berkeley) 6/11/93
 * $FreeBSD: src/sys/vm/device_pager.c,v 1.46.2.1 2000/08/02 21:54:37 peter Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/mman.h>
#include <sys/device.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/thread2.h>
#include <sys/mutex2.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_zone.h>

static void dev_pager_dealloc (vm_object_t);
static int dev_pager_getpage (vm_object_t, vm_page_t *, int);
static void dev_pager_putpages (vm_object_t, vm_page_t *, int,
		boolean_t, int *);
static boolean_t dev_pager_haspage (vm_object_t, vm_pindex_t);

struct pagerops drmpagerops = {
	dev_pager_dealloc,
	dev_pager_getpage,
	dev_pager_putpages,
	dev_pager_haspage
};

static struct mtx dev_pager_mtx = MTX_INITIALIZER;

/*
 * No requirements.
 */
vm_object_t
drm_pager_alloc(void *handle, off_t size, vm_prot_t prot, off_t foff)
{
	vm_object_t object;
	vm_offset_t i;
	vm_page_t m;

	/*
	 * Offset should be page aligned.
	 */
	if (foff & PAGE_MASK)
		return (NULL);

	size = round_page64(size);

	mtx_lock(&dev_pager_mtx);

	/*
	 * Allocate object and associate it with the pager.
	 */
	object = vm_object_allocate(OBJT_DRM,
				    OFF_TO_IDX(foff + size));
	object->handle = handle;

	/* Allocate fictitious pages for the full size GEM object */
	for (i = 0; i < size; i += PAGE_SIZE) {
		m = vm_page_alloc(object, i >> PAGE_SHIFT, VM_ALLOC_NORMAL | VM_ALLOC_ZERO);
		if (m == NULL) {
			mtx_unlock(&dev_pager_mtx);
			vm_wait(0);
			mtx_lock(&dev_pager_mtx);
			i -= PAGE_SIZE;
			continue;
		}
		lwkt_gettoken(&vm_token);
		crit_enter();
		vm_page_insert(m, object, i >> PAGE_SHIFT);
		crit_exit();
		lwkt_reltoken(&vm_token);
	}

	mtx_unlock(&dev_pager_mtx);

	return (object);
}

/*
 * No requirements.
 */
static void
dev_pager_dealloc(vm_object_t object)
{
	mtx_lock(&dev_pager_mtx);
	vm_object_page_remove(object, 0, object->size, FALSE);
	mtx_unlock(&dev_pager_mtx);
}

/*
 * No requirements.
 */
static int
dev_pager_getpage(vm_object_t object, vm_page_t *mpp, int seqaccess)
{
	vm_page_t page = *mpp;

	mtx_lock(&dev_pager_mtx);

	*mpp = vm_page_lookup(object, page->pindex);
	if (*mpp == NULL) {
		mtx_unlock(&dev_pager_mtx);
		return VM_PAGER_BAD;
	}

	mtx_unlock(&dev_pager_mtx);
	return (VM_PAGER_OK);
}

/*
 * No requirements.
 */
static void
dev_pager_putpages(vm_object_t object, vm_page_t *m,
		   int count, boolean_t sync, int *rtvals)
{
	panic("dev_pager_putpage called");
}

/*
 * No requirements.
 */
static boolean_t
dev_pager_haspage(vm_object_t object, vm_pindex_t pindex)
{
	return (pindex < object->size);
}
