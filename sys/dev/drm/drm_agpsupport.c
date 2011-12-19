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
#ifdef __linux__
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <dev/agp/agpreg.h>
#include <dev/agp/agppriv.h>
#include <bus/pci/pcireg.h>
MALLOC_DECLARE(M_AGP);
#endif

static int
drm_device_find_capability(struct drm_device *dev, int cap)
{
	return (pci_find_extcap(dev->device, cap, NULL) == 0);
}

int drm_device_is_pcie(struct drm_device *dev)
{
	return (drm_device_find_capability(dev, PCIY_EXPRESS));
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

#if __OS_HAS_AGP

#ifdef __linux__
#include <asm/agp.h>
#endif

DRM_DEVICE_T drm_agp_find_bridge(void *data) {
	return agp_find_device();
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
#ifdef __linux__
	DRM_AGP_KERN *kern;
#else
	struct agp_info *kern;
#endif

	if (!dev->agp || !dev->agp->acquired)
		return -EINVAL;

#ifdef __linux__
	kern = &dev->agp->agp_info;
	info->agp_version_major = kern->version.major;
	info->agp_version_minor = kern->version.minor;
	info->mode = kern->mode;
	info->aperture_base = kern->aper_base;
	info->aperture_size = kern->aper_size * 1024 * 1024;
	info->memory_allowed = kern->max_memory << PAGE_SHIFT;
	info->memory_used = kern->current_memory << PAGE_SHIFT;
	info->id_vendor = kern->device->vendor;
	info->id_device = kern->device->device;
#else
	kern = &dev->agp->info;
	agp_get_info(dev->agp->bridge, kern);
/* INVESTIGATE */
	info->agp_version_major = 1;
	info->agp_version_minor = 0;
	info->mode = kern->ai_mode;
	info->aperture_base = kern->ai_aperture_base;
	info->aperture_size = kern->ai_aperture_size;
	info->memory_allowed = kern->ai_memory_allowed;
	info->memory_used = kern->ai_memory_used;
	info->id_vendor = pci_get_vendor(dev->agp->bridge);
	info->id_device = pci_get_device(dev->agp->bridge);
#endif
#if 0
	info->id_vendor = kern->ai_devid & 0xffff;
	info->id_device = kern->ai_devid >> 16;
#endif
#ifndef __linux__
	if (info->id_vendor != (unsigned short)(kern->ai_devid & 0xffff))
		DRM_ERROR("info vendor %d != ai_devid %d!\n",
			info->id_vendor, kern->ai_devid & 0xffff); 
	if (info->id_device != (unsigned short)(kern->ai_devid >> 16))
		DRM_ERROR("info device %d != ai_devid %d!\n",
			info->id_device, kern->ai_devid >> 16);
#endif

	return 0;
}

EXPORT_SYMBOL(drm_agp_info);

int drm_agp_info_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_info *info = data;
	int err;

	err = drm_agp_info(dev, info);
	if (err)
		return err;

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
	if (!dev->agp)
		return -ENODEV;
	if (dev->agp->acquired)
		return -EBUSY;
#ifdef __linux__
	if (!(dev->agp->bridge = agp_backend_acquire(dev->pdev)))
		return -ENODEV;
#else
	if (agp_acquire(dev->agp->bridge))
		return -ENODEV;
#endif
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
	return drm_agp_acquire((struct drm_device *) file_priv->minor->dev);
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
		return -EINVAL;
#ifdef __linux__
	agp_backend_release(dev->agp->bridge);
#else
	agp_release(dev->agp->bridge);
#endif
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
		return -EINVAL;
	
	dev->agp->mode = mode.mode;
#ifdef __linux__
	agp_enable(dev->agp->bridge, mode.mode);
#else
	agp_enable(dev->agp->bridge, mode.mode);
#endif
	dev->agp->enabled = 1;
	return 0;
}

EXPORT_SYMBOL(drm_agp_enable);

int drm_agp_enable_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	struct drm_agp_mode *mode = data;

	return drm_agp_enable(dev, *mode);
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

#ifndef __linux__
	DRM_INFO("drm_agp_alloc TRIED: size (%016lx), type (%016lx)\n",
		request->size, request->type);
#endif
	if (!dev->agp || !dev->agp->acquired)
		return -EINVAL;

	entry = malloc(sizeof(*entry), DRM_MEM_AGPLISTS, M_WAITOK | M_ZERO);
	if (entry == NULL)
		return -ENOMEM;

	pages = (request->size + PAGE_SIZE - 1) / PAGE_SIZE;
	type = (u32) request->type;
	if (!(memory = drm_alloc_agp(dev, pages, type))) {
		free(entry, DRM_MEM_AGPLISTS);
		return -ENOMEM;
	}

/* Have not implemented in legacy using the key yet to add to handle */
#ifdef __linux__ /* UNIMPLEMENTED */
	entry->handle = (unsigned long)memory->key + 1;
#else
	entry->handle = (unsigned long)memory;
#endif /* __linux__ */
	entry->memory = memory;
	entry->bound = 0;
	entry->pages = pages;
	list_add(&entry->head, &dev->agp->memory);

#ifndef __linux__
	agp_memory_info(dev->agp->bridge, entry->memory, &info);
#endif

	request->handle = entry->handle;
#ifdef __linux__
	request->physical = memory->physical;
#else
        request->physical = info.ami_physical;
#endif

#ifndef __linux__
	DRM_INFO("drm_agp_alloc SUCCESS: handle (%016lx), physical (%016lx)\n",
		request->handle, request->physical);
#endif
	return 0;
}
EXPORT_SYMBOL(drm_agp_alloc);


int drm_agp_alloc_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	struct drm_agp_buffer *request = data;

	return drm_agp_alloc(dev, request);
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
static struct drm_agp_mem *drm_agp_lookup_entry(struct drm_device * dev,
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
		return -EINVAL;
	entry = drm_agp_lookup_entry(dev, request->handle);
	if (entry == NULL || !entry->bound)
		return -EINVAL;
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
	struct drm_agp_binding *request = data;

	return drm_agp_unbind(dev, request);
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
		return -EINVAL;
	if (!(entry = drm_agp_lookup_entry(dev, request->handle)))
		return -EINVAL;
	if (entry->bound)
		return -EINVAL;
	page = (request->offset + PAGE_SIZE - 1) / PAGE_SIZE;

	if ((retcode = drm_bind_agp(entry->memory, page)))
		return retcode;
	entry->bound = dev->agp->base + (page << PAGE_SHIFT);
	DRM_DEBUG("base = 0x%lx entry->bound = 0x%lx\n",
		  dev->agp->base, entry->bound);
	return 0;
}
EXPORT_SYMBOL(drm_agp_bind);


int drm_agp_bind_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_binding *request = data;

	return drm_agp_bind(dev, request);
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
		return -EINVAL;
	if (!(entry = drm_agp_lookup_entry(dev, request->handle)))
		return -EINVAL;
	if (entry->bound)
		drm_unbind_agp(entry->memory);

	list_del(&entry->head);

	drm_free_agp(entry->memory, entry->pages);
	free(entry, DRM_MEM_AGPLISTS);
	return 0;
}
EXPORT_SYMBOL(drm_agp_free);



int drm_agp_free_ioctl(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_agp_buffer *request = data;

	return drm_agp_free(dev, request);
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
	struct drm_agp_head *head = NULL;

#ifdef __linux__
	if (!(head = kmalloc(sizeof(*head), GFP_KERNEL)))
		return NULL;
#else
	if (!(head = malloc(sizeof(*head), DRM_MEM_AGPLISTS, M_WAITOK)))
		return NULL;
#endif
	memset((void *)head, 0, sizeof(*head));
#ifdef __linux__
	head->bridge = agp_find_bridge(dev->pdev);
#else
	head->bridge = drm_agp_find_bridge(NULL);
#endif
	if (!head->bridge) {
#ifdef __linux__
		if (!(head->bridge = agp_backend_acquire(dev->pdev))) {
			kfree(head);
			return NULL;
		}
		agp_copy_info(head->bridge, &head->agp_info);
		agp_backend_release(head->bridge);
#else
		free(head, DRM_MEM_AGPLISTS);
		return NULL;

#endif
	} else {
#ifdef __linux__
		agp_copy_info(head->bridge, &head->agp_info);
#else
		drm_agp_copy_info(head->bridge, &head->agp_info);
		agp_get_info(head->bridge, &head->info);
#endif
	}

	INIT_LIST_HEAD(&head->memory);
/* legacy guesses at cant_use_aperture and page_mask */
	head->cant_use_aperture = 0;
	head->page_mask = 0x0fff;
	head->base = head->info.ai_aperture_base;
#ifndef __linux__
	DRM_INFO("drm_agp_init(): AGP at 0x%08lx %dMB\n",
		 (long)head->info.ai_aperture_base,
		 (int)(head->info.ai_aperture_size >> 20));
#endif
	return head;
}

/** Calls agp_allocate_memory() */
DRM_AGP_MEM *drm_agp_allocate_memory(DRM_AGP_BRIDGE_DATA_T bridge,
				     size_t pages, u32 type)
{
#ifdef __linux__
	return agp_allocate_memory(bridge, pages, type);
#else
	DRM_AGP_MEM *handle = malloc(sizeof(DRM_AGP_MEM),
		DRM_MEM_AGPLISTS, M_WAITOK | M_ZERO);
	if (handle == NULL)
		return NULL;

	handle->bridge = bridge;

/* QUESTION: Should one use PAGE_SHIFT or AGP_PAGE_SHIFT? */
/* On DragonFly AGP_PAGE_SHIFT is defined to be 12 */
	handle->memory = agp_alloc_memory(handle->bridge, type, pages << AGP_PAGE_SHIFT);
	return handle;
#endif
}

/** Calls agp_free_memory() */
int drm_agp_free_memory(DRM_AGP_MEM * handle)
{
	if (!handle)
		return 0;

#ifdef __linux__
	agp_free_memory(handle);
#else
	if (handle->bridge && handle->memory)
		agp_free_memory(handle->bridge, handle->memory);
	free(handle, DRM_MEM_AGPLISTS);
#endif
	return 1;
}

/** Calls agp_bind_memory() */
int drm_agp_bind_memory(DRM_AGP_MEM * handle, off_t start)
{
	if (!handle)
		return -EINVAL;
#ifdef __linux__
	return agp_bind_memory(handle, start);
#else
	return agp_bind_memory(handle->bridge, handle->memory, start * PAGE_SIZE);
#endif
}

/** Calls agp_unbind_memory() */
int drm_agp_unbind_memory(DRM_AGP_MEM * handle)
{
	if (!handle)
		return -EINVAL;
#ifdef __linux__
	return agp_unbind_memory(handle);
#else
	return agp_unbind_memory(handle->bridge, handle->memory);
#endif
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

	mem = drm_agp_allocate_memory(dev->agp->bridge, num_pages,
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
	mem->bridge = dev->agp->bridge;

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
#ifdef __linux__
	agp_flush_chipset(dev->agp->bridge);
#else /* !__linux__ */
#if defined(__i386__) || defined(__x86_64__)
	wbinvd();
#endif
#endif /* __linux__ */
}
EXPORT_SYMBOL(drm_agp_chipset_flush);


/** Calls agp_allocate_memory() */
static DRM_AGP_MEM *drm_agp_alloc_given(DRM_AGP_BRIDGE_DATA_T bridge,
				     size_t pages, u32 type, void *object)
{
	DRM_AGP_MEM *handle = malloc(sizeof(DRM_AGP_MEM),
		DRM_MEM_AGPLISTS, M_WAITOK | M_ZERO);
	if (handle == NULL)
		return NULL;

	handle->bridge = bridge;
	handle->object = (vm_object_t)object;

/* QUESTION: Should one use PAGE_SHIFT or AGP_PAGE_SHIFT? */
/* On DragonFly AGP_PAGE_SHIFT is defined to be 12 */
	handle->memory = agp_alloc_given(handle->bridge, type, pages << AGP_PAGE_SHIFT, object);
	return handle;
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

	DRM_DEBUG("\n");

	mem = drm_agp_alloc_given(dev->agp->bridge, num_pages,
				      type, (void *)object);
	if (mem == NULL) {
		DRM_ERROR("Failed to allocate memory for %ld pages\n",
			  num_pages);
		return NULL;
	}

	mem->page_count = num_pages;
	mem->bridge = dev->agp->bridge;

	mem->is_flushed = true;
	ret = drm_agp_bind_memory(mem, gtt_offset / PAGE_SIZE);
	if (ret != 0) {
		DRM_ERROR("Failed to bind AGP memory: %d\n", ret);
		drm_agp_free_memory(mem);
		return NULL;
	}

	return mem;
}

#endif /* __OS_HAS_AGP */
