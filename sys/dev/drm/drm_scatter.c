/**
 * \file drm_scatter.c
 * IOCTLs to manage scatter/gather memory
 *
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Mon Dec 18 23:20:54 2000 by gareth@valinux.com
 *
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

 /*
 * Authors:
 *   Gareth Hughes <gareth@valinux.com>
 *   Eric Anholt <anholt@FreeBSD.org>
 *
 */

#ifdef __linux__
#include <linux/vmalloc.h>
#include <linux/slab.h>
#endif /* __linux__ */
#include "drmP.h"

#define DEBUG_SCATTER 0

static inline void *drm_vmalloc_dma(unsigned long size)
{
#if defined(__powerpc__) && defined(CONFIG_NOT_COHERENT_CACHE)
	return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL | _PAGE_NO_CACHE);
#else
	return malloc(size, DRM_MEM_DMA, M_WAITOK | M_ZERO);
#endif
}

void drm_sg_cleanup(struct drm_sg_mem * entry)
{
	struct drm_dma_handle *dmah = entry->dmah;

	bus_dmamap_unload(dmah->tag, dmah->map);
	bus_dmamem_free(dmah->tag, dmah->vaddr, dmah->map);
	bus_dma_tag_destroy(dmah->tag);
	free(dmah, DRM_MEM_DMA);
	free(entry->busaddr, DRM_MEM_PAGES);
	free(entry, DRM_MEM_SGLISTS);
}

#ifdef _LP64
# define ScatterHandle(x) (unsigned int)((x >> 32) + (x & ((1L << 32) - 1)))
#else
# define ScatterHandle(x) (unsigned int)(x)
#endif

static void drm_sg_alloc_cb(void *arg, bus_dma_segment_t *segs,
			    int nsegs, int error);

int drm_sg_alloc(struct drm_device *dev, struct drm_scatter_gather * request)
{
	struct drm_sg_mem *entry;
	struct drm_dma_handle *dmah;
	unsigned long pages;
	int ret;

	DRM_DEBUG("\n");

	if (!drm_core_check_feature(dev, DRIVER_SG))
		return -EINVAL;

	if (dev->sg)
		return -EINVAL;

	entry = malloc(sizeof(*entry), DRM_MEM_SGLISTS, M_WAITOK | M_ZERO);
	if (!entry)
		return -ENOMEM;

	pages = round_page(request->size) / PAGE_SIZE;
	DRM_DEBUG("size=%ld pages=%ld\n", request->size, pages);

	entry->pages = pages;
	entry->busaddr = malloc(pages * sizeof(*entry->busaddr),
		DRM_MEM_PAGES, M_WAITOK | M_ZERO);
	if (!entry->busaddr) {
		free(entry, DRM_MEM_SGLISTS);
		return -ENOMEM;
	}

	dmah = malloc(sizeof(struct drm_dma_handle),
		DRM_MEM_DMA, M_WAITOK | M_ZERO);
	if (dmah == NULL) {
		free(entry->busaddr, DRM_MEM_PAGES);
		free(entry, DRM_MEM_SGLISTS);
		return -ENOMEM;
	}

	ret = bus_dma_tag_create(NULL, PAGE_SIZE, 0, /* tag, align, boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR, /* lowaddr, highaddr */
	    NULL, NULL, /* filtfunc, filtfuncargs */
	    request->size, pages, /* maxsize, nsegs */
	    PAGE_SIZE, 0, /* maxsegsize, flags */
	    &dmah->tag);
	if (ret != 0) {
		free(dmah, DRM_MEM_DMA);
		free(entry->busaddr, DRM_MEM_PAGES);
		free(entry, DRM_MEM_SGLISTS);
		return -ENOMEM;
	}

	/* XXX BUS_DMA_NOCACHE */
	ret = bus_dmamem_alloc(dmah->tag, &dmah->vaddr,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO , &dmah->map);
	if (ret != 0) {
		bus_dma_tag_destroy(dmah->tag);
		free(dmah, DRM_MEM_DMA);
		free(entry->busaddr, DRM_MEM_PAGES);
		free(entry, DRM_MEM_SGLISTS);
		return -ENOMEM;
	}

	ret = bus_dmamap_load(dmah->tag, dmah->map, dmah->vaddr,
	    request->size, drm_sg_alloc_cb, entry, BUS_DMA_NOWAIT);
	if (ret != 0) {
		bus_dmamem_free(dmah->tag, dmah->vaddr, dmah->map);
		bus_dma_tag_destroy(dmah->tag);
		free(dmah, DRM_MEM_DMA);
		free(entry->busaddr, DRM_MEM_PAGES);
		free(entry, DRM_MEM_SGLISTS);
		return -ENOMEM;
	}

	entry->dmah = dmah;
	entry->handle = (unsigned long)dmah->vaddr;
	entry->virtual = (void *)entry->handle;

	DRM_DEBUG("handle  = %08lx\n", entry->handle);
	DRM_DEBUG("virtual = %p\n", entry->virtual);

	request->handle = entry->handle;

	dev->sg = entry;

	return 0;
}

static void
drm_sg_alloc_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	struct drm_sg_mem *entry = arg;
	int i;

	if (error != 0)
	    return;

	for(i = 0 ; i < nsegs ; i++) {
		entry->busaddr[i] = segs[i].ds_addr;
	}
}

int drm_sg_alloc_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_scatter_gather *request = data;

	return drm_sg_alloc(dev, request);
}

int drm_sg_free(struct drm_device *dev, void *data,
		struct drm_file *file_priv)
{
	struct drm_scatter_gather *request = data;
	struct drm_sg_mem *entry;

	if (!drm_core_check_feature(dev, DRIVER_SG))
		return -EINVAL;

	entry = dev->sg;
	dev->sg = NULL;

	if (!entry || entry->handle != request->handle)
		return -EINVAL;

	DRM_DEBUG("virtual  = %p\n", entry->virtual);

	drm_sg_cleanup(entry);

	return 0;
}
