/*-
 * Copyright 2003 Eric Anholt
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
 * ERIC ANHOLT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/** @file drm_vm.c
 * Support code for mmaping of DRM maps.
 */

#include "dev/drm/drmP.h"
#include "dev/drm/drm.h"

int drm_mmap(struct dev_mmap_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	vm_offset_t offset = ap->a_offset;
	struct drm_device *dev = drm_get_device_from_kdev(kdev);
	struct drm_file *file_priv = NULL;
	drm_local_map_t *map;
	enum drm_map_type type;
	vm_paddr_t phys;

        DRM_LOCK();
        file_priv = drm_find_file_by_proc(dev, DRM_CURPROC);
        DRM_UNLOCK();

        if (file_priv == NULL) {
                DRM_ERROR("can't find authenticator\n");
                return EINVAL;
        }

        if (!file_priv->authenticated)
                return EACCES;

	if (dev->dma && offset < ptoa(dev->dma->page_count)) {
		drm_device_dma_t *dma = dev->dma;

		DRM_SPINLOCK(&dev->dma_lock);

		if (dma->pagelist != NULL) {
			unsigned long page = offset >> PAGE_SHIFT;
			unsigned long phys = dma->pagelist[page];
			ap->a_result = atop(phys);
			DRM_SPINUNLOCK(&dev->dma_lock);
			return 0;
		} else {
			DRM_SPINUNLOCK(&dev->dma_lock);
			return -1;
		}
	}

				/* A sequential search of a linked list is
				   fine here because: 1) there will only be
				   about 5-10 entries in the list and, 2) a
				   DRI client only has to do this mapping
				   once, so it doesn't have to be optimized
				   for performance, even if the list was a
				   bit longer. */
	DRM_LOCK();
	TAILQ_FOREACH(map, &dev->maplist_legacy, link) {
		if (offset >= map->offset && offset < map->offset + map->size)
			break;
	}

	if (map == NULL) {
		DRM_DEBUG("Can't find map, requested offset = %016lx\n",
		    (unsigned long)offset);
		TAILQ_FOREACH(map, &dev->maplist_legacy, link) {
			DRM_DEBUG("map offset = %016lx, handle = %016lx\n",
			    (unsigned long)map->offset,
			    (unsigned long)map->handle);
		}
		DRM_UNLOCK();
		return -1;
	}
	if (((map->flags&_DRM_RESTRICTED) && !DRM_SUSER(DRM_CURPROC))) {
		DRM_UNLOCK();
		DRM_DEBUG("restricted map\n");
		return -1;
	}
	type = map->type;
	DRM_UNLOCK();

	switch (type) {
	case _DRM_FRAME_BUFFER:
	case _DRM_REGISTERS:
	case _DRM_AGP:
		phys = offset;
		break;
	case _DRM_CONSISTENT:
		phys = vtophys((char *)map->handle + (offset - map->offset));
		break;
	case _DRM_SCATTER_GATHER:
	case _DRM_SHM:
		phys = vtophys(offset);
		break;
	default:
		DRM_ERROR("bad map type %d\n", type);
		return -1;	/* This should never happen. */
	}

	ap->a_result = atop(phys);
	return 0;
}

