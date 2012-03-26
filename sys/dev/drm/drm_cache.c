/**************************************************************************
 *
 * Copyright (c) 2006-2007 Tungsten Graphics, Inc., Cedar Park, TX., USA
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/
/*
 * Authors: Thomas Hellström <thomas-at-tungstengraphics-dot-com>
 */

#include "drmP.h"
#ifndef __linux__ /* for CPUID_CLFSH */
#include <machine/specialreg.h>
#include <sys/thread2.h>
#endif

#if defined(CONFIG_X86)
static void
#ifdef __linux__
drm_clflush_page(struct page *page)
#else
drm_clflush_page(DRM_PAGE_T page)
#endif
{
	uint8_t *page_virtual;
	unsigned int i;
#ifndef __linux__
	DRM_LWBUF_T *lwbuf;
	DRM_LWBUF_T lwbuf_cache;
#endif

	if (unlikely(page == NULL))
		return;

#ifdef __linux__
	page_virtual = kmap_atomic(page, KM_USER0);
#else
	page_virtual = drm_kmap_atomic(page, &lwbuf_cache, &lwbuf);
#endif
#ifdef __linux__
	for (i = 0; i < PAGE_SIZE; i += boot_cpu_data.x86_clflush_size)
		clflush(page_virtual + i);
#endif
#if 0 /* UNIMPLEMENTED */
	for (i = 0; i < PAGE_SIZE; i += cpu_clflush_line_size)
		clflush((unsigned long)(page_virtual + i));
#endif
#ifdef __linux__
	kunmap_atomic(page_virtual, KM_USER0);
#else
	drm_kunmap_atomic(page_virtual, lwbuf);
#endif
}

#ifdef __linux__
static void drm_cache_flush_clflush(struct page *pages[],
				    unsigned long num_pages)
#else
static void drm_cache_flush_clflush(DRM_PAGE_T pages[],
				    unsigned long num_pages)
#endif
{
	unsigned long i;

	mb();
	for (i = 0; i < num_pages; i++)
		drm_clflush_page(*pages++);
	mb();
}

static void
drm_clflush_ipi_handler(void *null)
{
	wbinvd();
}
#endif

void
#ifdef __linux__
drm_clflush_pages(struct page *pages[], unsigned long num_pages)
#else
drm_clflush_pages(DRM_PAGE_T pages[], unsigned long num_pages)
#endif
{

#if defined(CONFIG_X86)
#ifdef __linux__
	if (cpu_has_clflush) {
		drm_cache_flush_clflush(pages, num_pages);
		return;
	}
#endif
#if 0 /* UNIMPLEMENTED */
	if (cpu_feature & CPUID_CLFSH) {
		drm_cache_flush_clflush(pages, num_pages);
		return;
	}
#endif

#ifdef __linux__
	if (on_each_cpu(drm_clflush_ipi_handler, NULL, 1) != 0)
		printk(KERN_ERR "Timed out waiting for cache flush.\n");
#else /* !__linux__ */
#ifdef SMP
	int n;
	int retcode = 0;
	for (n = 0; n < ncpus; ++n) {
		int res = lwkt_send_ipiq(globaldata_find(n), (ipifunc1_t)drm_clflush_ipi_handler, NULL);
		if (res != 0) {
			retcode = res;
		}	
	}
	if (retcode)
		printk(KERN_ERR "Timed out waiting for cache flush.\n");
#else
	drm_clflush_ipi_handler(NULL);
#endif
#endif /* !__linux__ */

#elif defined(__powerpc__)
	unsigned long i;
	for (i = 0; i < num_pages; i++) {
		struct page *page = pages[i];
		void *page_virtual;

		if (unlikely(page == NULL))
			continue;

		page_virtual = kmap_atomic(page, KM_USER0);
		flush_dcache_range((unsigned long)page_virtual,
				   (unsigned long)page_virtual + PAGE_SIZE);
		kunmap_atomic(page_virtual, KM_USER0);
	}
#else
	printk(KERN_ERR "Architecture has no drm_cache.c support\n");
	WARN_ON_ONCE(1);
#endif
}
EXPORT_SYMBOL(drm_clflush_pages);
