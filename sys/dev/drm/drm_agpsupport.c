/**
 * \file drm_agpsupport.c
 * DRM support for AGP/GART backend
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
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
 */

#include "drmP.h"

#include <dev/agp/agpreg.h>
#include <dev/agp/agppriv.h>
#include <bus/pci/pcireg.h>
MALLOC_DECLARE(M_AGP);

DRM_DEVICE_T drm_agp_find_bridge(void *data) {
	return agp_find_device();
}

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

void
drm_agp_copy_info(DRM_AGP_BRIDGE_DATA_T bridge, DRM_AGP_KERN *agp_info)
{
	struct agp_info asked;
	agp_get_info(bridge, &asked);
	agp_info->version.major = 1;
	agp_info->version.minor = 0;
	agp_info->mode = asked.ai_mode;
	agp_info->aper_base = asked.ai_aperture_base;
	agp_info->aper_size = asked.ai_aperture_size >> 20;
	agp_info->max_memory = asked.ai_memory_allowed >> PAGE_SHIFT;
	agp_info->current_memory = asked.ai_memory_used >> PAGE_SHIFT;
	agp_info->id_vendor = pci_get_vendor(bridge);
	agp_info->id_device = pci_get_device(bridge);
}

/**
 * Get AGP information.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a (output) drm_agp_info structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device has been initialized and acquired and fills in the
 * drm_agp_info structure with the information in drm_agp_head::agp_info.
 */
int drm_agp_info(struct drm_device *dev, struct drm_agp_info *info)
{
	struct agp_info *kern;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	kern = &dev->agp->info;
	agp_get_info(dev->agp->agpdev, kern);
	info->agp_version_major = 1;
	info->agp_version_minor = 0;
	info->mode = kern->ai_mode;
	info->aperture_base = kern->ai_aperture_base;
	info->aperture_size = kern->ai_aperture_size;
	info->memory_allowed = kern->ai_memory_allowed;
	info->memory_used = kern->ai_memory_used;
	info->id_vendor = pci_get_vendor(dev->agp->agpdev);
	info->id_device = pci_get_device(dev->agp->agpdev);
#if 0
	info->id_vendor = kern->ai_devid & 0xffff;
	info->id_device = kern->ai_devid >> 16;
#endif

	return 0;
}
EXPORT_SYMBOL(drm_agp_info);

int drm_agp_info_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_info info;
	int err;

	err = drm_agp_info(dev, &info);
	if (err)
		return err;

	*(struct drm_agp_info *) data = info;
	return 0;
}

/**
 * Acquire the AGP device.
 *
 * \param dev DRM device that is to acquire AGP.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device hasn't been acquired before and calls
 * \c agp_backend_acquire.
 */
int drm_agp_acquire(struct drm_device * dev)
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

EXPORT_SYMBOL(drm_agp_acquire);

/**
 * Acquire the AGP device (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device hasn't been acquired before and calls
 * \c agp_backend_acquire.
 */
int drm_agp_acquire_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{
#ifdef __linux__
	return drm_agp_acquire((struct drm_device *) file_priv->minor->dev);
#else
	return drm_agp_acquire(dev);
#endif
}

/**
 * Release the AGP device.
 *
 * \param dev DRM device that is to release AGP.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device has been acquired and calls \c agp_backend_release.
 */
int drm_agp_release(struct drm_device * dev)
{
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
	agp_release(dev->agp->agpdev);
	dev->agp->acquired = 0;
	return 0;
}
EXPORT_SYMBOL(drm_agp_release);

int drm_agp_release_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{
	return drm_agp_release(dev);
}

/**
 * Enable the AGP bus.
 *
 * \param dev DRM device that has previously acquired AGP.
 * \param mode Requested AGP mode.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device has been acquired but not enabled, and calls
 * \c agp_enable.
 */
int drm_agp_enable(struct drm_device * dev, struct drm_agp_mode mode)
{
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
	
	dev->agp->mode = mode.mode;
	agp_enable(dev->agp->agpdev, mode.mode);
	dev->agp->enabled = 1;
	return 0;
}

EXPORT_SYMBOL(drm_agp_enable);

int drm_agp_enable_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	struct drm_agp_mode mode;

	mode = *(struct drm_agp_mode *) data;

	return drm_agp_enable(dev, mode);
}

/**
 * Allocate AGP memory.
 *
 * \param inode device inode.
 * \param file_priv file private pointer.
 * \param cmd command.
 * \param arg pointer to a drm_agp_buffer structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device is present and has been acquired, allocates the
 * memory via alloc_agp() and creates a drm_agp_mem entry for it.
 */
int drm_agp_alloc(struct drm_device *dev, struct drm_agp_buffer *request)
{
	struct drm_agp_mem *entry;
	DRM_AGP_MEM *memory;
	unsigned long pages;
	u32 type;

	struct agp_memory_info info;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	entry = malloc(sizeof(*entry), DRM_MEM_AGPLISTS, M_WAITOK | M_ZERO);
	if (entry == NULL)
		return ENOMEM;

	pages = (request->size + PAGE_SIZE - 1) / PAGE_SIZE;
	type = (u32) request->type;
	if (!(memory = drm_alloc_agp(dev, pages, type))) {
		free(entry, DRM_MEM_AGPLISTS);
		return ENOMEM;
	}

/* Have not implemented in legacy using the key yet to add to handle */
#ifdef __linux__
	entry->handle = (unsigned long)memory->key + 1;
#else
	entry->handle = (unsigned long)memory;
#endif /* __linux__ */
	entry->memory = memory;
	entry->bound = 0;
	entry->pages = pages;
	list_add(&entry->head, &dev->agp->memory);

	agp_memory_info(dev->agp->agpdev, entry->memory, &info);

	request->handle = entry->handle;
        request->physical = info.ami_physical;

	return 0;
}
EXPORT_SYMBOL(drm_agp_alloc);

int drm_agp_alloc_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	struct drm_agp_buffer request;
	int retcode;

	request = *(struct drm_agp_buffer *) data;

	retcode = drm_agp_alloc(dev, &request);

	*(struct drm_agp_buffer *) data = request;

	return retcode;
}

/**
 * Search for the AGP memory entry associated with a handle.
 *
 * \param dev DRM device structure.
 * \param handle AGP memory handle.
 * \return pointer to the drm_agp_mem structure associated with \p handle.
 *
 * Walks through drm_agp_head::memory until finding a matching handle.
 */
static struct drm_agp_mem * drm_agp_lookup_entry(struct drm_device *dev,
					    unsigned long handle)
{
	struct drm_agp_mem *entry;

	list_for_each_entry(entry, &dev->agp->memory, head) {
		if (entry->handle == handle)
			return entry;
	}
	return NULL;
}

/**
 * Unbind AGP memory from the GATT (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_agp_binding structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device is present and acquired, looks-up the AGP memory
 * entry and passes it to the unbind_agp() function.
 */
int drm_agp_unbind(struct drm_device *dev, struct drm_agp_binding *request)
{
	struct drm_agp_mem *entry;
	int ret;

	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL || !entry->bound)
		return EINVAL;
#ifdef __linux__
	ret = drm_unbind_agp(entry->memory);
#else
	ret = drm_agp_unbind_memory(entry->memory);
#endif
	if (ret == 0)
		entry->bound = 0;
	return ret;
}
EXPORT_SYMBOL(drm_agp_unbind);


int drm_agp_unbind_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	struct drm_agp_binding request;
	int retcode;

	request = *(struct drm_agp_binding *) data;

	retcode = drm_agp_unbind(dev, &request);

	return retcode;
}

/**
 * Bind AGP memory into the GATT (ioctl)
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_agp_binding structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device is present and has been acquired and that no memory
 * is currently bound into the GATT. Looks-up the AGP memory entry and passes
 * it to bind_agp() function.
 */
int drm_agp_bind(struct drm_device *dev, struct drm_agp_binding *request)
{
	struct drm_agp_mem *entry;
	int retcode;
	int page;
	
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;
#if 0
	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL || entry->bound)
		return EINVAL;
#endif
	if (!(entry = drm_agp_lookup_entry(dev, request->handle)))
		return -EINVAL;
	if (entry->bound)
		return -EINVAL;
	page = (request->offset + PAGE_SIZE - 1) / PAGE_SIZE;

#ifdef __linux__
	if ((retcode = drm_bind_agp(entry->memory, page)))
		return retcode;
#else
	if ((retcode = drm_agp_bind_memory(entry->memory, page)))
		return retcode;
#endif
	entry->bound = dev->agp->base + (page << PAGE_SHIFT);
	DRM_DEBUG("base = 0x%lx entry->bound = 0x%lx\n",
		  dev->agp->base, entry->bound);
	return 0;
}
EXPORT_SYMBOL(drm_agp_bind);

int drm_agp_bind_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_binding request;
	int retcode;

	request = *(struct drm_agp_binding *) data;

	retcode = drm_agp_bind(dev, &request);

	return retcode;
}

/**
 * Free AGP memory (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_agp_buffer structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies the AGP device is present and has been acquired and looks up the
 * AGP memory entry. If the memory it's currently bound, unbind it via
 * unbind_agp(). Frees it via free_agp() as well as the entry itself
 * and unlinks from the doubly linked list it's inserted in.
 */
int drm_agp_free(struct drm_device *dev, struct drm_agp_buffer *request)
{
	struct drm_agp_mem *entry;
	
	if (!dev->agp || !dev->agp->acquired)
		return EINVAL;

	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL)
		return EINVAL;

	list_del(&entry->head);

	if (entry->bound)
		drm_agp_unbind_memory(entry->memory);
	drm_agp_free_memory(entry->memory);

	free(entry, DRM_MEM_AGPLISTS);
	return 0;
}

int drm_agp_free_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_buffer request;
	int retcode;

	request = *(struct drm_agp_buffer *) data;

	retcode = drm_agp_free(dev, &request);

	return retcode;
}

/**
 * Initialize the AGP resources.
 *
 * \return pointer to a drm_agp_head structure.
 *
 * Gets the drm_agp_t structure which is made available by the agpgart module
 * via the inter_module_* functions. Creates and initializes a drm_agp_head
 * structure.
 */
struct drm_agp_head *drm_agp_init(struct drm_device *dev)
{
	device_t agpdev;
	struct drm_agp_head *head   = NULL;
	int      agp_available = 1;
   
	agpdev = drm_agp_find_bridge(NULL);
	if (!agpdev)
		agp_available = 0;

	DRM_DEBUG("agp_available = %d\n", agp_available);

	if (agp_available) {
		head = malloc(sizeof(*head), DRM_MEM_AGPLISTS,
		    M_WAITOK | M_ZERO);
		if (head == NULL)
			return NULL;
		head->agpdev = agpdev;
		agp_get_info(agpdev, &head->info);
		drm_agp_copy_info(agpdev, &head->agp_info);
		INIT_LIST_HEAD(&head->memory);
/* legacy guesses at cant_use_aperture and page_mask */
		head->cant_use_aperture = 0;
		head->page_mask = 0x0fff;
		head->base = head->info.ai_aperture_base;

		DRM_INFO("AGP at 0x%08lx %dMB\n",
			 (long)head->info.ai_aperture_base,
			 (int)(head->info.ai_aperture_size >> 20));
	}
	return head;
}

/** Calls agp_allocate_memory() */
DRM_AGP_MEM *drm_agp_allocate_memory(DRM_AGP_BRIDGE_DATA_T bridge,
				     size_t pages, u32 type)
{
	DRM_AGP_MEM *handle = malloc(sizeof(DRM_AGP_MEM),
		DRM_MEM_AGPLISTS, M_WAITOK | M_ZERO);
	if (handle == NULL)
		return NULL;

	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev) {
		free(handle, DRM_MEM_AGPLISTS);
		return NULL;
	}

	if (bridge == NULL) {
		DRM_ERROR("bridge == null\n");
	}
	if (agpdev != bridge) {
		DRM_ERROR("agpdev != bridge argument\n");
	}
	handle->bridge = agpdev;

#ifdef __linux__
	handle->pages = malloc(sizeof (struct page *) * pages,
		DRM_MEM_AGPLISTS, M_WAITOK);
	if (handle->pages == NULL)
		return NULL;
#else
	handle->pages = NULL;
#endif /* __linux__ */

/* QUESTION: Should one use PAGE_SHIFT or AGP_PAGE_SHIFT? */
/* On DragonFly AGP_PAGE_SHIFT is defined to be 12 */
	handle->memory = agp_alloc_memory(agpdev, type, pages << AGP_PAGE_SHIFT);
	return handle;
}

/** Calls agp_free_memory() */
int drm_agp_free_memory(DRM_AGP_MEM * handle)
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

/** Calls agp_bind_memory() */
int drm_agp_bind_memory(DRM_AGP_MEM * handle, off_t start)
{
	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev || !handle || !handle->memory)
		return EINVAL;

	return agp_bind_memory(agpdev, handle->memory, start * PAGE_SIZE);
}

/** Calls agp_unbind_memory() */
int drm_agp_unbind_memory(DRM_AGP_MEM * handle)
{
	device_t agpdev;

	agpdev = DRM_AGP_FIND_DEVICE();
	if (!agpdev || !handle || !handle->memory)
		return EINVAL;

	return agp_unbind_memory(agpdev, handle->memory);
}

/**
 * Binds pages from a vm_object into AGP memory at the given offset, returning
 * the drm AGP memory structure containing them.
 *
 * No reference is held on the pages during this time -- it is up to the
 * caller to handle that.
 */
DRM_AGP_MEM *
drm_agp_bind_object(struct drm_device *dev,
		   vm_object_t object,
		   unsigned long num_pages,
		   uint32_t gtt_offset,
		   u32 type)
{
	DRM_AGP_MEM *mem;
	int ret;
	device_t agpdev = drm_agp_find_bridge(NULL);

	struct agp_memory *memory = malloc(sizeof(struct agp_memory), M_AGP, M_WAITOK | M_ZERO);
	if (!memory) {
		DRM_ERROR("Failed to allocate memory for %ld pages\n",
			  num_pages);
		return NULL;
	}
	memory->am_size = num_pages << PAGE_SHIFT;
	memory->am_type = type;
	memory->am_obj = object;
	memory->am_offset = gtt_offset;
	memory->am_is_bound = 0;

	DRM_DEBUG("\n");

	mem = drm_agp_allocate_memory(dev->agp->agpdev, num_pages,
				      type);
	if (mem == NULL) {
		DRM_ERROR("Failed to allocate memory for %ld pages\n",
			  num_pages);
		free(memory, M_AGP);
		return NULL;
	}

	mem->page_count = num_pages;

	mem->is_flushed = true;
	mem->memory = memory;
	ret = agp_bind_memory(agpdev, memory, gtt_offset);
	if (ret != 0) {
		DRM_ERROR("Failed to bind AGP memory: %d\n", ret);
		free(memory, M_AGP);
		drm_agp_free_memory(mem);
		return NULL;
	}
	return mem;
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
#ifdef __linux__
	int ret, i;
#else
	int ret;
#endif /* __linux__ */

	DRM_DEBUG("\n");

	mem = drm_agp_allocate_memory(dev->agp->agpdev, num_pages,
				      type);
	if (mem == NULL) {
		DRM_ERROR("Failed to allocate memory for %ld pages\n",
			  num_pages);
		return NULL;
	}

#ifdef __linux__
	for (i = 0; i < num_pages; i++)
		mem->pages[i] = pages[i];
#endif /* __linux__ */
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
#if defined(__i386__) || defined(__x86_64__)
	wbinvd();
#endif
#ifdef __linux__
	agp_flush_chipset(dev->agp->bridge);
#endif /* __linux__ */
}
EXPORT_SYMBOL(drm_agp_chipset_flush);
