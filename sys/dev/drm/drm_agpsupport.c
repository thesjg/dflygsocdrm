/*-
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
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
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/** @file drm_agpsupport.c
 * Support code for tying the kernel AGP support to DRM drivers and
 * the DRM's AGP ioctls.
 */

#include "dev/drm/drmP.h"

#include <dev/agp/agpreg.h>
#include <bus/pci/pcireg.h>

/* Returns 1 if AGP or 0 if not. */
static int
drm_device_find_capability(struct drm_device *dev, int cap)
{
	return (pci_find_extcap(dev->device, cap, NULL) == 0);
}

int drm_device_is_agp(struct drm_device *dev)
{
	if (dev->driver->device_is_agp != NULL) {
		int ret;

		/* device_is_agp returns a tristate, 0 = not AGP, 1 = definitely
		 * AGP, 2 = fall back to PCI capability
		 */
		ret = (*dev->driver->device_is_agp)(dev);
		if (ret != DRM_MIGHT_BE_AGP)
			return ret;
	}

	return (drm_device_find_capability(dev, PCIY_AGP));
}

int drm_device_is_pcie(struct drm_device *dev)
{
	return (drm_device_find_capability(dev, PCIY_EXPRESS));
}

int drm_agp_info(struct drm_device * dev, struct drm_agp_info *info)
{
	struct agp_info *kern;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	kern                   = &dev->agp->info;
	agp_get_info(dev->agp->agpdev, kern);
	info->agp_version_major = 1;
	info->agp_version_minor = 0;
	info->mode              = kern->ai_mode;
	info->aperture_base     = kern->ai_aperture_base;
	info->aperture_size     = kern->ai_aperture_size;
	info->memory_allowed    = kern->ai_memory_allowed;
	info->memory_used       = kern->ai_memory_used;
	info->id_vendor         = kern->ai_devid & 0xffff;
	info->id_device         = kern->ai_devid >> 16;

	return 0;
}

int drm_agp_info_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	int err;
	struct drm_agp_info info;

	err = drm_agp_info(dev, &info);
	if (err != 0)
		return err;

	*(struct drm_agp_info *) data = info;
	return 0;
}

int drm_agp_acquire_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{

	return drm_agp_acquire(dev);
}

int drm_agp_acquire(struct drm_device *dev)
{
	int retcode;

	if (!dev->agp || dev->agp->acquired)
		return EINVAL;

	retcode = agp_acquire(dev->agp->agpdev);
	if (retcode)
		return retcode;

	dev->agp->acquired = 1;
	return 0;
}

int drm_agp_release_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{

	return drm_agp_release(dev);
}

int drm_agp_release(struct drm_device * dev)
{
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
	agp_release(dev->agp->agpdev);
	dev->agp->acquired = 0;
	return 0;
}

int drm_agp_enable(struct drm_device *dev, struct drm_agp_mode mode)
{

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
	
	dev->agp->mode    = mode.mode;
	agp_enable(dev->agp->agpdev, mode.mode);
	dev->agp->enabled = 1;
	return 0;
}

int drm_agp_enable_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	struct drm_agp_mode mode;

	mode = *(struct drm_agp_mode *) data;

	return drm_agp_enable(dev, mode);
}

int drm_agp_alloc(struct drm_device *dev, struct drm_agp_buffer *request)
{
	struct drm_agp_mem *entry;
	DRM_AGP_MEM *memory;
#if 0
	void	         *handle;
#endif
	unsigned long    pages;
	u_int32_t	 type;
	struct agp_memory_info info;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	entry = malloc(sizeof(*entry), DRM_MEM_AGPLISTS, M_NOWAIT | M_ZERO);
	if (entry == NULL)
		return ENOMEM;

	pages = (request->size + PAGE_SIZE - 1) / PAGE_SIZE;
	type = (u_int32_t) request->type;

	DRM_UNLOCK();
	memory = drm_agp_allocate_memory((struct agp_bridge_data*)NULL, pages,
		type);
	DRM_LOCK();
	if (memory == NULL) {
		free(entry, DRM_MEM_AGPLISTS);
		return ENOMEM;
	}

/* Assume sizeof(unsigned long) >= sizeof(void *) */
	entry->handle    = (unsigned long)memory;
	entry->memory    = memory;
	entry->bound     = 0;
	entry->pages     = pages;
#if 0
	entry->prev      = NULL;
	entry->next      = dev->agp->memory_legacy;
	if (dev->agp->memory_legacy)
		dev->agp->memory_legacy->prev = entry;
	dev->agp->memory_legacy = entry;
#endif
	list_add(&entry->head, &dev->agp->memory);

	agp_memory_info(dev->agp->agpdev, entry->memory, &info);

	request->handle   = entry->handle;
        request->physical = info.ami_physical;

	return 0;
}

int drm_agp_alloc_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	struct drm_agp_buffer request;
	int retcode;

	request = *(struct drm_agp_buffer *) data;

	DRM_LOCK();
	retcode = drm_agp_alloc(dev, &request);
	DRM_UNLOCK();

	*(struct drm_agp_buffer *) data = request;

	return retcode;
}

static struct drm_agp_mem * drm_agp_lookup_entry(struct drm_device *dev,
					    unsigned long handle)
{
	struct drm_agp_mem *entry;

#if 0
	for (entry = dev->agp->memory_legacy; entry; entry = entry->next) {
		if (entry->handle == handle) return entry;
	}
#endif
	list_for_each_entry(entry, &dev->agp->memory, head) {
		if (entry->handle == handle)
			return entry;
	}
	return NULL;
}

int drm_agp_unbind(struct drm_device *dev, struct drm_agp_binding *request)
{
	struct drm_agp_mem *entry;
	int retcode;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL || !entry->bound)
		return EINVAL;

	DRM_UNLOCK();
	retcode = drm_agp_unbind_memory(entry->memory);
	DRM_LOCK();

	if (retcode == 0)
		entry->bound = 0;

	return retcode;
}

int drm_agp_unbind_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	struct drm_agp_binding request;
	int retcode;

	request = *(struct drm_agp_binding *) data;

	DRM_LOCK();
	retcode = drm_agp_unbind(dev, &request);
	DRM_UNLOCK();

	return retcode;
}

int drm_agp_bind(struct drm_device *dev, struct drm_agp_binding *request)
{
	struct drm_agp_mem *entry;
	int               retcode;
	int               page;
	
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	DRM_DEBUG("agp_bind, page_size=%x\n", PAGE_SIZE);

	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL || entry->bound)
		return EINVAL;

	page = (request->offset + PAGE_SIZE - 1) / PAGE_SIZE;

	DRM_UNLOCK();
	retcode = drm_agp_bind_memory(entry->memory, page);
	DRM_LOCK();
	if (retcode == 0)
		entry->bound = dev->agp->base + (page << PAGE_SHIFT);

	return retcode;
}

int drm_agp_bind_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_binding request;
	int retcode;

	request = *(struct drm_agp_binding *) data;

	DRM_LOCK();
	retcode = drm_agp_bind(dev, &request);
	DRM_UNLOCK();

	return retcode;
}

int drm_agp_free(struct drm_device *dev, struct drm_agp_buffer *request)
{
	struct drm_agp_mem *entry;
	
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL)
		return EINVAL;

#if 0
	if (entry->prev)
		entry->prev->next = entry->next;
	else
		dev->agp->memory_legacy  = entry->next;
	if (entry->next)
		entry->next->prev = entry->prev;
#endif
	list_del(&entry->head);

	DRM_UNLOCK();
	if (entry->bound)
		drm_agp_unbind_memory(entry->memory);
	drm_agp_free_memory(entry->memory);
	DRM_LOCK();

	free(entry, DRM_MEM_AGPLISTS);

	return 0;

}

int drm_agp_free_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_buffer request;
	int retcode;

	request = *(struct drm_agp_buffer *) data;

	DRM_LOCK();
	retcode = drm_agp_free(dev, &request);
	DRM_UNLOCK();

	return retcode;
}

struct drm_agp_head *drm_agp_init(struct drm_device *dev)
{
	device_t agpdev;
	struct drm_agp_head *head   = NULL;
	int      agp_available = 1;
   
	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev)
		agp_available = 0;

	DRM_DEBUG("agp_available = %d\n", agp_available);

	if (agp_available) {
		head = malloc(sizeof(*head), DRM_MEM_AGPLISTS,
		    M_NOWAIT | M_ZERO);
		if (head == NULL)
			return NULL;
		head->agpdev = agpdev;
		agp_get_info(agpdev, &head->info);
		head->base = head->info.ai_aperture_base;
#if 0
		head->memory_legacy = NULL;
#endif
	INIT_LIST_HEAD(&head->memory);

		DRM_INFO("AGP at 0x%08lx %dMB\n",
			 (long)head->info.ai_aperture_base,
			 (int)(head->info.ai_aperture_size >> 20));
	}
	return head;
}

DRM_AGP_MEM *drm_agp_allocate_memory(struct agp_bridge_data * bridge,
				     size_t pages, u32 type)
{
	DRM_AGP_MEM *handle = malloc(sizeof(DRM_AGP_MEM), DRM_MEM_AGPLISTS,
		M_WAITOK);
	if (handle == NULL)
		return NULL;

	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev)
		return NULL;

	handle->pages = malloc(sizeof (struct page *) * pages, DRM_MEM_AGPLISTS,
		M_WAITOK);
	if (handle->pages == NULL)
		return NULL;

	handle->memory = agp_alloc_memory(agpdev, type, pages << AGP_PAGE_SHIFT);
	return handle;
}

int drm_agp_free_memory(DRM_AGP_MEM *handle)
{
	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (agpdev && handle && handle->memory)
		agp_free_memory(agpdev, handle->memory);
	if (handle) {
		if (handle->pages)
			free(handle->pages, DRM_MEM_AGPLISTS);
		free(handle, DRM_MEM_AGPLISTS);
	}
	if (!agpdev || !handle || !handle->memory)
		return 0;

	return 1;
}

int drm_agp_bind_memory(DRM_AGP_MEM *handle, off_t start)
{
	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev || !handle || !handle->memory)
		return EINVAL;

	return agp_bind_memory(agpdev, handle->memory, start * PAGE_SIZE);
}

int drm_agp_unbind_memory(DRM_AGP_MEM *handle)
{
	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev || !handle || !handle->memory)
		return EINVAL;

	return agp_unbind_memory(agpdev, handle->memory);
}

/**
 * Binds a collection of pages into AGP memory at the given offset, returning
 * the AGP memory structure containing them.
 *
 * No reference is held on the pages during this time -- it is up to the
 * caller to handle that.
 */
DRM_AGP_MEM *
drm_agp_bind_pages(struct drm_device *dev,
		   struct page **pages,
		   unsigned long num_pages,
		   uint32_t gtt_offset,
		   u32 type)
{
	DRM_AGP_MEM *mem;
	int ret, i;

	DRM_DEBUG("\n");

	mem = drm_agp_allocate_memory(dev->agp->bridge, num_pages,
				      type);
	if (mem == NULL) {
		DRM_ERROR("Failed to allocate memory for %ld pages\n",
			  num_pages);
		return NULL;
	}

	for (i = 0; i < num_pages; i++)
		mem->pages[i] = pages[i];
	mem->page_count = num_pages;

	mem->is_flushed = true;
	ret = drm_agp_bind_memory(mem, gtt_offset / PAGE_SIZE);
	if (ret != 0) {
		DRM_ERROR("Failed to bind AGP memory: %d\n", ret);
		drm_agp_free_memory(mem);
		return NULL;
	}

	return mem;
}
EXPORT_SYMBOL(drm_agp_bind_pages);

void drm_agp_chipset_flush(struct drm_device *dev)
{
	agp_flush_chipset(dev->agp->bridge);
}
EXPORT_SYMBOL(drm_agp_chipset_flush);
