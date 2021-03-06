/**
 * \file drm_bufs.c
 * Generic buffer template
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Thu Nov 23 03:10:50 2000 by gareth@valinux.com
 *
 * Copyright 1999, 2000 Precision Insight, Inc., Cedar Park, Texas.
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

#ifdef __linux__
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <asm/shmparam.h>
#else
#include "bus/pci/pcireg.h"
#endif /* __linux__ */

#include "drmP.h"

#ifndef __linux__
#define DRM_NEWER_BUFS 1
#define DRM_NEWER_37 1
#define DRM_NEWER_BUFTRY 1
static const char *types[] = { "FB", "REG", "SHM", "AGP", "SG", "CON" };
#endif

/* Allocation of PCI memory resources (framebuffer, registers, etc.) for
 * drm_get_resource_*.  Note that they are not RF_ACTIVE, so there's no virtual
 * address for accessing them.  Cleaned up at unload.
 */
static int drm_alloc_resource(struct drm_device *dev, int resource)
{
	if (resource >= DRM_MAX_PCI_RESOURCE) {
		DRM_ERROR("Resource %d too large\n", resource);
		return 1;
	}

	if (dev->pcir[resource] != NULL) {
		return 0;
	}

	dev->pcirid[resource] = PCIR_BAR(resource);
	dev->pcir[resource] = bus_alloc_resource_any(dev->device,
	    SYS_RES_MEMORY, &dev->pcirid[resource], RF_SHAREABLE);

	if (dev->pcir[resource] == NULL) {
		DRM_ERROR("Couldn't find resource 0x%x\n", resource);
		return 1;
	}

	return 0;
}

resource_size_t drm_get_resource_start(struct drm_device *dev, unsigned int resource)
{
#ifdef __linux__
	return pci_resource_start(dev->pdev, resource);
#else
	if (drm_alloc_resource(dev, resource) != 0)
		return 0;

	return rman_get_start(dev->pcir[resource]);
#endif
}
EXPORT_SYMBOL(drm_get_resource_start);

resource_size_t drm_get_resource_len(struct drm_device *dev, unsigned int resource)
{
#ifdef __linux__
	return pci_resource_len(dev->pdev, resource);
#else
	if (drm_alloc_resource(dev, resource) != 0)
		return 0;

	return rman_get_size(dev->pcir[resource]);
#endif
}

EXPORT_SYMBOL(drm_get_resource_len);

static struct drm_map_list *drm_find_matching_map(struct drm_device *dev,
						  struct drm_local_map *map)
{
	struct drm_map_list *entry;
#ifndef __linux__
	const char *typestr;

	if (map->type < 0 || map->type > 5)
		typestr = "??";
	else
		typestr = types[map->type];
#endif
	list_for_each_entry(entry, &dev->maplist, head) {
		/*
		 * Because the kernel-userspace ABI is fixed at a 32-bit offset
		 * while PCI resources may live above that, we ignore the map
		 * offset for maps of type _DRM_FRAMEBUFFER or _DRM_REGISTERS.
		 * It is assumed that each driver will have only one resource of
		 * each type.
		 */
#ifdef __linux__
		if (!entry->map ||
		    map->type != entry->map->type ||
		    entry->master != dev->primary->master)
			continue;
#else
		if (!entry->map ||
		    map->type != entry->map->type)
			continue;
		if (entry->master != dev->primary->master) {
			if ((map->type == _DRM_REGISTERS) || (map->type == _DRM_FRAME_BUFFER)
				|| (entry->map->offset == map->offset)) {
				DRM_ERROR("mismatched master: type (%4.4s), offset (%016lx), handle (%016lx), pid (%d), svuid (%u), euid (%u), ruid (%u), entry (%p) != dev (%p)\n",
					typestr,
					(uint64_t)map->offset,
					(uint64_t)map->handle,
					DRM_CURRENTPID,
					DRM_CURRENTUID,
					DRM_CURRENTEUID,
					DRM_CURRENTRUID,
					entry->master,
					dev->primary->master);
			}
		}
		if ((map->type != _DRM_REGISTERS) && (map->type != _DRM_FRAME_BUFFER) &&
			(entry->master != dev->primary->master))
			continue;
#endif /* __linux__ */
		switch (map->type) {
		case _DRM_SHM:
			if (map->flags != _DRM_CONTAINS_LOCK)
				break;
		case _DRM_REGISTERS:
		case _DRM_FRAME_BUFFER:
			return entry;
		default: /* Make gcc happy */
			;
		}
		if (entry->map->offset == map->offset)
			return entry;
	}
#ifndef __linux__
	DRM_INFO("map not found: type (%4.4s), offset (%016lx), handle (%016lx), pid (%d), svuid (%u), euid (%u), ruid (%u)\n",
		typestr,
		(uint64_t)map->offset,
		(uint64_t)map->handle,
		DRM_CURRENTPID,
		DRM_CURRENTUID,
		DRM_CURRENTEUID,
		DRM_CURRENTRUID
	);
#endif

	return NULL;
}

static int drm_map_handle(struct drm_device *dev, struct drm_hash_item *hash,
			  unsigned long user_token, int hashed_handle, int shm)
{
	int use_hashed_handle, shift;
	unsigned long add;

#ifdef DRM_NEWER_USER_TOKEN
#if (BITS_PER_LONG == 64)
	use_hashed_handle = ((user_token & 0xFFFFFFFF00000000UL) || hashed_handle);
#else /* BITS_PER_LONG == 32 */
	use_hashed_handle = hashed_handle;
#endif
#else
/* sizeof(int) == 4 all supported platforms for DragonFly BSD */
	use_hashed_handle = hashed_handle;
#endif /* DRM_NEWER_USER_TOKEN */

	if (!use_hashed_handle) {
		int ret;
		hash->key = user_token >> PAGE_SHIFT;
		ret = drm_ht_insert_item(&dev->map_hash, hash);
		if (ret != -EINVAL)
			return ret;
	}

	shift = 0;
	add = DRM_MAP_HASH_OFFSET >> PAGE_SHIFT;

#if 0
/* SHMLBA in sys/shm.h is defined to be PAGE_SIZE
 * in DragonFly BSD and in FreeBSD */
	if (shm && (SHMLBA > PAGE_SIZE)) {
		int bits = ilog2(SHMLBA >> PAGE_SHIFT) + 1;

		/* For shared memory, we have to preserve the SHMLBA
		 * bits of the eventual vma->vm_pgoff value during
		 * mmap().  Otherwise we run into cache aliasing problems
		 * on some platforms.  On these platforms, the pgoff of
		 * a mmap() request is used to pick a suitable virtual
		 * address for the mmap() region such that it will not
		 * cause cache aliasing problems.
		 *
		 * Therefore, make sure the SHMLBA relevant bits of the
		 * hash value we use are equal to those in the original
		 * kernel virtual address.
		 */
		shift = bits;
		add |= ((user_token >> PAGE_SHIFT) & ((1UL << bits) - 1UL));
	}
#endif
	DRM_INFO("call to drm_ht_just_insert_please(): user_token (%016lx), shift (%08x), add (%016lx)\n",
		user_token, shift, add);

	return drm_ht_just_insert_please(&dev->map_hash, hash,
					 user_token, 32 - PAGE_SHIFT - 3,
					 shift, add);
}

/**
 * Core function to create a range of memory available for mapping by a
 * non-root process.
 *
 * Adjusts the memory offset to its absolute value according to the mapping
 * type.  Adds the map to the map list drm_device::maplist. Adds MTRR's where
 * applicable and if supported by the kernel.
 */
static int drm_addmap_core(struct drm_device * dev, resource_size_t offset,
			   unsigned int size, enum drm_map_type type,
			   enum drm_map_flags flags,
			   struct drm_map_list ** maplist)
{
	struct drm_local_map *map;
	struct drm_map_list *list;
	drm_dma_handle_t *dmah;
	unsigned long user_token;
	int ret;

	int align;

	if ((offset & PAGE_MASK) || (size & PAGE_MASK)) {
		DRM_ERROR("offset/size not page aligned: 0x%lx/0x%lx\n",
			offset, size);
		return -EINVAL;
	}

	if (offset + size < offset) {
		DRM_ERROR("offset and size wrap around: 0x%lx/0x%lx\n",
		    offset, size);
		return -EINVAL;
	}
	if (size == 0) {
		DRM_ERROR("size is 0: 0x%lx/0x%lx\n", offset, size);
		return -EINVAL;
	}

	map = malloc(sizeof(*map), DRM_MEM_MAPS, M_WAITOK | M_ZERO);
	if (!map)
		return -ENOMEM;

	map->offset = offset;
	map->size = size;
	map->flags = flags;
	map->type = type;

	/* Only allow shared memory to be removable since we only keep enough
	 * book keeping information about shared memory to allow for removal
	 * when processes fork.
	 */
	if ((map->flags & _DRM_REMOVABLE) && map->type != _DRM_SHM) {
		free(map, DRM_MEM_MAPS);
		return -EINVAL;
	}
	DRM_DEBUG("offset = 0x%08llx, size = 0x%08lx, type = %d\n",
		  (unsigned long long)map->offset, map->size, map->type);

	/* page-align _DRM_SHM maps. They are allocated here so there is no security
	 * hole created by that and it works around various broken drivers that use
	 * a non-aligned quantity to map the SAREA. --BenH
	 */
	if (map->type == _DRM_SHM)
		map->size = PAGE_ALIGN(map->size);

#if __linux__ /* QUESTION: required -1? */
	map->mtrr = -1;
#else /* legacy BSD drm test for map->mtrr >= 0 */
	map->mtrr = 0;
#endif
	map->handle = NULL;

	switch (map->type) {
	case _DRM_REGISTERS:
	case _DRM_FRAME_BUFFER:
#ifdef __linux__
#if !defined(__sparc__) && !defined(__alpha__) && !defined(__ia64__) && !defined(__powerpc64__) && !defined(__x86_64__)
		if (map->offset + (map->size-1) < map->offset ||
		    map->offset < virt_to_phys(high_memory)) {
			kfree(map);
			return -EINVAL;
		}
#endif
#ifdef __alpha__
		map->offset += dev->hose->mem_space->start;
#endif
#endif /* __linux__ */
		/* Some drivers preinitialize some maps, without the X Server
		 * needing to be aware of it.  Therefore, we just return success
		 * when the server tries to create a duplicate map.
		 */
		list = drm_find_matching_map(dev, map);
		if (list != NULL) {
			if (list->map->size != map->size) {
				DRM_DEBUG("Matching maps of type %d with "
					  "mismatched sizes, (%ld vs %ld)\n",
					  map->type, map->size,
					  list->map->size);
				list->map->size = map->size;
			}

			free(map, DRM_MEM_MAPS);
			*maplist = list;
			return 0;
		}

		if (drm_core_has_MTRR(dev)) {
			if (map->type == _DRM_FRAME_BUFFER ||
			    (map->flags & _DRM_WRITE_COMBINING)) {
#if __linux__
				map->mtrr = mtrr_add(map->offset, map->size,
						     MTRR_TYPE_WRCOMB, 1);
#else
				if (drm_mtrr_add(map->offset, map->size, DRM_MTRR_WC) >= 0)
					map->mtrr = 1;
#endif
			}
		}

		if (map->type == _DRM_REGISTERS) {
			map->handle = drm_ioremap(dev, map);
			if (!map->handle) {
				free(map, DRM_MEM_MAPS);
				return -ENOMEM;
			}
		}

		break;
	case _DRM_SHM:
		list = drm_find_matching_map(dev, map);
		if (list != NULL) {
			if(list->map->size != map->size) {
				DRM_DEBUG("Matching maps of type %d with "
					  "mismatched sizes, (%ld vs %ld)\n",
					  map->type, map->size, list->map->size);
				list->map->size = map->size;
			}

			free(map, DRM_MEM_MAPS);
			*maplist = list;
			return 0;
		}

#ifdef __linux__
		map->handle = vmalloc_user(map->size);
#else /* UNIMPLEMENTED for mapping to user space */
		map->handle = malloc(map->size, DRM_MEM_MAPS, M_WAITOK | M_ZERO);
#endif /* __linux__ */
		DRM_DEBUG("%lu %d %p\n",
			  map->size, drm_order(map->size), map->handle);
		if (!map->handle) {
			free(map, DRM_MEM_MAPS);
			return -ENOMEM;
		}
		map->offset = (unsigned long)map->handle;
		if (map->flags & _DRM_CONTAINS_LOCK) {
			/* Prevent a 2nd X Server from creating a 2nd lock */
			if (dev->primary->master->lock.hw_lock != NULL) {
				free(map->handle, DRM_MEM_MAPS);
				free(map, DRM_MEM_MAPS);
				return -EBUSY;
			}
			dev->sigdata.lock = dev->primary->master->lock.hw_lock = map->handle;	/* Pointer to lock */
		}
		break;
	case _DRM_AGP: {
		struct drm_agp_mem *entry;
		int valid = 0;

		if (!drm_core_has_AGP(dev)) {
			free(map, DRM_MEM_MAPS);
			return -EINVAL;
		}
#ifdef __alpha__
		map->offset += dev->hose->mem_space->start;
#endif
		/* In some cases (i810 driver), user space may have already
		 * added the AGP base itself, because dev->agp->base previously
		 * only got set during AGP enable.  So, only add the base
		 * address if the map's offset isn't already within the
		 * aperture.
		 */
		if (map->offset < dev->agp->base ||
		    map->offset > dev->agp->base +
		    dev->agp->agp_info.aper_size * 1024 * 1024 - 1) {
			map->offset += dev->agp->base;
		}
		map->mtrr = dev->agp->agp_mtrr;	/* for getmap */

		/* This assumes the DRM is in total control of AGP space.
		 * It's not always the case as AGP can be in the control
		 * of user space (i.e. i810 driver). So this loop will get
		 * skipped and we double check that dev->agp->memory is
		 * actually set as well as being invalid before EPERM'ing
		 */
		list_for_each_entry(entry, &dev->agp->memory, head) {
			if ((map->offset >= entry->bound) &&
			    (map->offset + map->size <= entry->bound + entry->pages * PAGE_SIZE)) {
				valid = 1;
				break;
			}
		}
		if (!list_empty(&dev->agp->memory) && !valid) {
#ifndef __linux__
			DRM_ERROR("drm_addmap_core() agp invalid\n");
#endif
			free(map, DRM_MEM_MAPS);
			return -EPERM;
		}
		DRM_DEBUG("AGP offset = 0x%08llx, size = 0x%08lx\n",
			  (unsigned long long)map->offset, map->size);

		break;
	}
	case _DRM_GEM:
		DRM_ERROR("tried to addmap GEM object\n");
		break;
	case _DRM_SCATTER_GATHER:
		if (!dev->sg) {
			free(map, DRM_MEM_MAPS);
			return -EINVAL;
		}
		map->offset += (unsigned long)dev->sg->virtual;
		break;
	case _DRM_CONSISTENT:
		/* dma_addr_t is 64bit on i386 with CONFIG_HIGHMEM64G,
		 * As we're limiting the address to 2^32-1 (or less),
		 * casting it down to 32 bits is no problem, but we
		 * need to point to a 64bit variable first. */
		dmah = drm_pci_alloc(dev, map->size, map->size);
		if (!dmah) {
			free(map, DRM_MEM_MAPS);
			return -ENOMEM;
		}
		map->handle = dmah->vaddr;
		map->offset = (unsigned long)dmah->busaddr;
#ifdef __linux__
		kfree(dmah);
#else
/* legacy BSD drm: dmah remembered because of dmah->tag for dma free */
		map->dmah = dmah;
#endif
		break;
	default:
		free(map, DRM_MEM_MAPS);
		return -EINVAL;
	}

	list = malloc(sizeof(*list), DRM_MEM_MAPS, M_WAITOK | M_ZERO);
	if (!list) {
		if (map->type == _DRM_REGISTERS)
#ifdef __linux__
			iounmap(map->handle);
#else
			drm_iounmap(map->handle, map->size);
#endif
		free(map, DRM_MEM_MAPS);
		return -EINVAL;
	}
	list->map = map;

	mutex_lock(&dev->struct_mutex);
	list_add(&list->head, &dev->maplist);

	/* Assign a 32-bit handle */
	/* We do it here so that dev->struct_mutex protects the increment */
	user_token = (map->type == _DRM_SHM) ? (unsigned long)map->handle :
		map->offset;
	ret = drm_map_handle(dev, &list->hash, user_token, 0,
			     (map->type == _DRM_SHM));
	if (ret) {
		if (map->type == _DRM_REGISTERS)
#ifdef __linux__
			iounmap(map->handle);
#else
			drm_iounmap(map->handle, map->size);
#endif
		free(map, DRM_MEM_MAPS);
		free(list, DRM_MEM_MAPS);
		mutex_unlock(&dev->struct_mutex);
		return ret;
	}

	list->user_token = list->hash.key << PAGE_SHIFT;
	mutex_unlock(&dev->struct_mutex);

	if (!(map->flags & _DRM_DRIVER))
		list->master = dev->primary->master;
#ifndef __linux__
	const char *typestr;
	if (list->map->type < 0 || list->map->type > 5)
		typestr = "??";
	else
		typestr = types[list->map->type];
	DRM_INFO("drm_addmap_locked(): type (%4.4s), offset (%016lx), handle (%016lx), master (%p), pid (%d), svuid (%u), euid (%u), ruid(%u)\n",
		typestr,
		(uint64_t)map->offset,
		(uint64_t)map->handle,
		list->master,
		DRM_CURRENTPID,
		DRM_CURRENTUID,
		DRM_CURRENTEUID,
		DRM_CURRENTRUID
	);
#endif
	*maplist = list;
	return 0;
}

int drm_addmap(struct drm_device * dev, resource_size_t offset,
/* QUESTION: does userland know size to be unsigned int or unsigned long? */
#ifdef DRM_NEWER_USER_TOKEN
	       unsigned int size, enum drm_map_type type,
#else
	       unsigned long size, enum drm_map_type type,
#endif
	       enum drm_map_flags flags, struct drm_local_map ** map_ptr)
{
	struct drm_map_list *list;
	int rc;

#ifndef __linux__
	if (size > 0x7FFFFFFFUL) {
		DRM_ERROR("drm_addmap() size (%16lx) > max_uint\n", size);
	}
#endif /* __linux__ */

	rc = drm_addmap_core(dev, offset, size, type, flags, &list);
	if (!rc)
		*map_ptr = list->map;
	return rc;
}

EXPORT_SYMBOL(drm_addmap);

/**
 * Ioctl to specify a range of memory that is available for mapping by a
 * non-root process.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_map structure.
 * \return zero on success or a negative value on error.
 *
 */
int drm_addmap_ioctl(struct drm_device *dev, void *data,
		     struct drm_file *file_priv)
{

#ifdef DRM_NEWER_USER_TOKEN

	struct drm_map *map = data;
	struct drm_map_list *maplist;
	int err;

#ifdef __linux__
	if (!(capable(CAP_SYS_ADMIN) || map->type == _DRM_AGP || map->type == _DRM_SHM))
		return -EPERM;
#else /* !__linux__ */
	if (!(dev->flags & (FREAD|FWRITE)))
		return -EPERM; /* Require read/write */

	if (!(DRM_SUSER(DRM_CURPROC) || map->type == _DRM_AGP || map->type == _DRM_SHM))
		return -EPERM;
#endif /* __linux__ */

	err = drm_addmap_core(dev, map->offset, map->size, map->type,
			      map->flags, &maplist);

	if (err)
		return err;

	/* avoid a warning on 64-bit, this casting isn't very nice, but the API is set so too late */
	map->handle = (void *)(unsigned long)maplist->user_token;

#else /* !DRM_NEWER_USER_TOKEN */

#if 1
	struct drm_map *map = data;
	struct drm_map_list *maplist;
	int err;

#ifndef __linux__
	if (!(dev->flags & (FREAD|FWRITE)))
		return -EPERM; /* Require read/write */
#endif
	if (!(capable(CAP_SYS_ADMIN) || map->type == _DRM_AGP || map->type == _DRM_SHM))
		return -EPERM;

	err = drm_addmap_core(dev, map->offset, map->size, map->type,
			      map->flags, &maplist);

	if (err)
		return err;

#ifdef __linux__
	/* avoid a warning on 64-bit, this casting isn't very nice, but the API is set so too late */
	map->handle = (void *)(unsigned long)maplist->user_token;
#else
	if (map->type != _DRM_SHM) {
		map->handle = (void *)(maplist->map->offset);
	}
	else {
		map->handle =  maplist->map->handle;
	}
	map->mtrr = maplist->map->mtrr;
#endif
	return 0;

#else
	struct drm_map *request = data;
	drm_local_map_t *map;
	int err;

	if (!(dev->flags & (FREAD|FWRITE)))
		return -EPERM; /* Require read/write */

	if (!(capable(CAP_SYS_ADMIN) || request->type == _DRM_AGP || request->type == _DRM_SHM))
		return -EPERM;

	err = drm_addmap(dev, request->offset, request->size, request->type,
	    request->flags, &map);

	if (err)
		return err;

	request->offset = map->offset;
	request->size = map->size;
	request->type = map->type;
	request->flags = map->flags;
	request->mtrr   = map->mtrr;
	request->handle = map->handle;

	if (request->type != _DRM_SHM) {
		request->handle = (void *)request->offset;
	}
#endif

#endif /* DRM_NEWER_USER_TOKEN */

	return 0;
}

/**
 * Remove a map private from list and deallocate resources if the mapping
 * isn't in use.
 *
 * Searches the map on drm_device::maplist, removes it from the list, see if
 * its being used, and free any associate resource (such as MTRR's) if it's not
 * being on use.
 *
 * \sa drm_addmap
 */
int drm_rmmap_locked(struct drm_device *dev, struct drm_local_map *map)
{
	if (map == NULL) {
		DRM_ERROR("map arg NULL\n");
		return -EINVAL;
	}

	struct drm_map_list *r_list = NULL, *list_t;
#ifdef __linux__
	drm_dma_handle_t dmah;
#endif /* __linux__ */
	int found = 0;
	struct drm_master *master;

	/* Find the list entry for the map and remove it */
	list_for_each_entry_safe(r_list, list_t, &dev->maplist, head) {
		if (r_list->map == map) {
			master = r_list->master;
			list_del(&r_list->head);
#ifdef __linux__
			drm_ht_remove_key(&dev->map_hash,
					  r_list->user_token >> PAGE_SHIFT);
#else
			int rethash;
			unsigned long key = r_list->user_token >> PAGE_SHIFT;
			rethash = drm_ht_remove_key(&dev->map_hash,
					  r_list->user_token >> PAGE_SHIFT);
			if (rethash)
				DRM_ERROR("FAILED drm_ht_remove_key(): offset (%016lx), handle (%016lx), key (%016lx)\n",
					(uint64_t)map->offset,
					(uint64_t)map->handle,
					key);
#endif
			free(r_list, DRM_MEM_MAPS);
			found = 1;
			break;
		}
	}

	if (!found) {
		DRM_ERROR("not removed map->type (%d), offset (%016lx), handle (%016lx)\n",
			map->type, (unsigned long)map->offset, (unsigned long)map->handle);
		return -EINVAL;
	}

#ifndef __linux__
	const char *typestr;
	if (map->type < 0 || map->type > 5)
		typestr = "??";
	else
		typestr = types[map->type];
	DRM_INFO("drm_rmmap_locked(): type (%4.4s), offset (%016lx), handle (%016lx), pid (%d), svuid (%u), euid(%d), ruid(%d)\n",
		typestr,
		(uint64_t)map->offset,
		(uint64_t)map->handle,
		DRM_CURRENTPID,
		DRM_CURRENTUID,
		DRM_CURRENTEUID,
		DRM_CURRENTRUID
	);
#endif

	switch (map->type) {
	case _DRM_REGISTERS:
#ifdef __linux__
		iounmap(map->handle);
#else
		drm_iounmap(map->handle, map->size);
#endif
		/* FALLTHROUGH */
	case _DRM_FRAME_BUFFER:
#if __linux__
		if (drm_core_has_MTRR(dev) && map->mtrr >= 0) {
			int retcode;
			retcode = mtrr_del(map->mtrr, map->offset, map->size);
			DRM_DEBUG("mtrr_del=%d\n", retcode);
		}
#else
		if (drm_core_has_MTRR(dev) && map->mtrr > 0) {
			int retcode;
			retcode = mtrr_del(map->mtrr, map->offset, map->size);
			DRM_DEBUG("mtrr_del=%d\n", retcode);
		}
#endif
#if 0
		if (map->mtrr) {
			int retcode;
			retcode = drm_mtrr_del(0, map->offset, map->size,
			    DRM_MTRR_WC);
			DRM_DEBUG("mtrr_del=%d\n", retcode);
		}
#endif
		break;
	case _DRM_SHM:
		free(map->handle, DRM_MEM_MAPS);
		if (master) {
			if (dev->sigdata.lock == master->lock.hw_lock)
				dev->sigdata.lock = NULL;
			master->lock.hw_lock = NULL;   /* SHM removed */
			master->lock.file_priv = NULL;
			wake_up_interruptible_all(&master->lock.lock_queue);
		}
		break;
	case _DRM_AGP:
	case _DRM_SCATTER_GATHER:
		break;
	case _DRM_CONSISTENT:
#ifdef __linux__
		dmah.vaddr = map->handle;
		dmah.busaddr = map->offset;
		dmah.size = map->size;
		__drm_pci_free(dev, &dmah);
#else
		drm_pci_free(dev, map->dmah);
#endif /* __linux__ */
		break;
	case _DRM_GEM:
		DRM_ERROR("tried to rmmap GEM object\n");
		break;
	default:
		DRM_ERROR("Bad map type %d\n", map->type);
		break;
	}
	free(map, DRM_MEM_MAPS);

	return 0;
}
EXPORT_SYMBOL(drm_rmmap_locked);

int drm_rmmap(struct drm_device *dev, struct drm_local_map *map)
{
	int ret;

	mutex_lock(&dev->struct_mutex);
	ret = drm_rmmap_locked(dev, map);
	mutex_unlock(&dev->struct_mutex);

	return ret;
}
EXPORT_SYMBOL(drm_rmmap);

/* The rmmap ioctl appears to be unnecessary.  All mappings are torn down on
 * the last close of the device, and this is necessary for cleanup when things
 * exit uncleanly.  Therefore, having userland manually remove mappings seems
 * like a pointless exercise since they're going away anyway.
 *
 * One use case might be after addmap is allowed for normal users for SHM and
 * gets used by drivers that the server doesn't need to care about.  This seems
 * unlikely.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a struct drm_map structure.
 * \return zero on success or a negative value on error.
 */
int drm_rmmap_ioctl(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct drm_map *request = data;
	struct drm_local_map *map = NULL;
	struct drm_map_list *r_list;
	int ret;

#ifndef __linux__
	const char *type;
	if (request->type < 0 || request->type > 5)
		type = "??";
	else
		type = types[request->type];
	DRM_INFO("drm_rmmap_ioctl(): request->type (%4.4s), request->handle (0x%016lx)\n",
		type, (uint64_t)request->handle);
#endif

	mutex_lock(&dev->struct_mutex);
	list_for_each_entry(r_list, &dev->maplist, head) {
#ifdef DRM_NEWER_USER_TOKEN
		if (r_list->map &&
		    r_list->user_token == (unsigned long)request->handle &&
		    r_list->map->flags & _DRM_REMOVABLE) {
			map = r_list->map;
			break;
		}
#else
		if (r_list->map &&
			((r_list->map->handle == request->handle) ||
			(r_list->user_token == (unsigned long)request->handle)) &&
			r_list->map->flags & _DRM_REMOVABLE) {
			map = r_list->map;
			break;
		}
#endif /* DRM_NEWER_USER_TOKEN */
	}

	/* List has wrapped around to the head pointer, or its empty we didn't
	 * find anything.
	 */
	if (list_empty(&dev->maplist) || !map) {
#ifndef __linux__
		DRM_ERROR("FAILED: type (%4.4s), handle (0x%016lx)\n",
			type, (uint64_t)request->handle);
#endif
		mutex_unlock(&dev->struct_mutex);
		return -EINVAL;
	}

	/* Register and framebuffer maps are permanent */
	if ((map->type == _DRM_REGISTERS) || (map->type == _DRM_FRAME_BUFFER)) {
		mutex_unlock(&dev->struct_mutex);
		return 0;
	}

	ret = drm_rmmap_locked(dev, map);

	mutex_unlock(&dev->struct_mutex);

	return ret;
}

/**
 * Cleanup after an error on one of the addbufs() functions.
 *
 * \param dev DRM device.
 * \param entry buffer entry where the error occurred.
 *
 * Frees any pages and buffers associated with the given entry.
 */
static void drm_cleanup_buf_error(struct drm_device * dev,
				  struct drm_buf_entry * entry)
{
	int i;

	if (entry->seg_count) {
		for (i = 0; i < entry->seg_count; i++) {
			if (entry->seglist[i]) {
				drm_pci_free(dev, entry->seglist[i]);
			}
		}
		free(entry->seglist, DRM_MEM_SEGS);

		entry->seg_count = 0;
	}

	if (entry->buf_count) {
		for (i = 0; i < entry->buf_count; i++) {
			free(entry->buflist[i].dev_private, DRM_MEM_BUFS);
		}
		free(entry->buflist, DRM_MEM_BUFS);

		entry->buf_count = 0;
	}
}

#if __OS_HAS_AGP
/**
 * Add AGP buffers for DMA transfers.
 *
 * \param dev struct drm_device to which the buffers are to be added.
 * \param request pointer to a struct drm_buf_desc describing the request.
 * \return zero on success or a negative number on failure.
 *
 * After some sanity checks creates a drm_buf structure for each buffer and
 * reallocates the buffer list of the same size order to accommodate the new
 * buffers.
 */
int drm_addbufs_agp(struct drm_device * dev, struct drm_buf_desc * request)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_entry *entry;
	struct drm_agp_mem *agp_entry;
	struct drm_buf *buf;
	unsigned long offset;
	unsigned long agp_offset;
	int count;
	int order;
	int size;
	int alignment;
	int page_order;
	int total;
	int byte_count;
	int i, valid;
	struct drm_buf **temp_buflist;

	if (!dma)
		return -EINVAL;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment = (request->flags & _DRM_PAGE_ALIGN)
	    ? PAGE_ALIGN(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	byte_count = 0;
	agp_offset = dev->agp->base + request->agp_start;

	DRM_DEBUG("count:      %d\n", count);
	DRM_DEBUG("order:      %d\n", order);
	DRM_DEBUG("size:       %d\n", size);
	DRM_DEBUG("agp_offset: %lx\n", agp_offset);
	DRM_DEBUG("alignment:  %d\n", alignment);
	DRM_DEBUG("page_order: %d\n", page_order);
	DRM_DEBUG("total:      %d\n", total);

	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER)
		return -EINVAL;
	if (dev->queue_count)
		return -EBUSY;	/* Not while in use */

	/* Make sure buffers are located in AGP memory that we own */
	valid = 0;
	list_for_each_entry(agp_entry, &dev->agp->memory, head) {
		if ((agp_offset >= agp_entry->bound) &&
		    (agp_offset + total * count <= agp_entry->bound + agp_entry->pages * PAGE_SIZE)) {
			valid = 1;
			break;
		}
	}
	if (!list_empty(&dev->agp->memory) && !valid) {
#ifdef __linux__
		DRM_DEBUG("zone invalid\n");
#else
		DRM_ERROR("drm_addbufs_agp(): zone invalid\n");
#endif
		return -EINVAL;
	}

	spin_lock(&dev->count_lock);
	if (dev->buf_use) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	atomic_inc(&dev->buf_alloc);
	spin_unlock(&dev->count_lock);

	mutex_lock(&dev->struct_mutex);
	entry = &dma->bufs[order];
	if (entry->buf_count) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;	/* May only call once for each order */
	}

	if (count < 0 || count > 4096) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -EINVAL;
	}

	entry->buflist = malloc(count * sizeof(*entry->buflist),
		DRM_MEM_BUFS, M_WAITOK | M_ZERO);
	if (!entry->buflist) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}

	entry->buf_size = size;
	entry->page_order = page_order;

	offset = 0;

	while (entry->buf_count < count) {
		buf = &entry->buflist[entry->buf_count];
		buf->idx = dma->buf_count + entry->buf_count;
		buf->total = alignment;
		buf->order = order;
		buf->used = 0;

		buf->offset = (dma->byte_count + offset);
		buf->bus_address = agp_offset + offset;
		buf->address = (void *)(agp_offset + offset);
		buf->next = NULL;
		buf->waiting = 0;
		buf->pending = 0;
		init_waitqueue_head(&buf->dma_wait);
		buf->file_priv = NULL;

		buf->dev_priv_size = dev->driver->dev_priv_size;
		buf->dev_private = malloc(buf->dev_priv_size,
			DRM_MEM_BUFS, M_WAITOK | M_ZERO);
		if (!buf->dev_private) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			mutex_unlock(&dev->struct_mutex);
			atomic_dec(&dev->buf_alloc);
			return -ENOMEM;
		}

		DRM_DEBUG("buffer %d @ %p\n", entry->buf_count, buf->address);

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	DRM_DEBUG("byte_count: %d\n", byte_count);

	temp_buflist = realloc(dma->buflist,
		(dma->buf_count + entry->buf_count) * sizeof(*dma->buflist),
		DRM_MEM_BUFS, M_WAITOK);
	if (!temp_buflist) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->seg_count += entry->seg_count;
	dma->page_count += byte_count >> PAGE_SHIFT;
	dma->byte_count += byte_count;

	DRM_DEBUG("dma->buf_count : %d\n", dma->buf_count);
	DRM_DEBUG("entry->buf_count : %d\n", entry->buf_count);

	mutex_unlock(&dev->struct_mutex);

	request->count = entry->buf_count;
	request->size = size;

	dma->flags = _DRM_DMA_USE_AGP;

	atomic_dec(&dev->buf_alloc);
	return 0;
}
EXPORT_SYMBOL(drm_addbufs_agp);
#endif				/* __OS_HAS_AGP */

int drm_addbufs_pci(struct drm_device * dev, struct drm_buf_desc * request)
{
	struct drm_device_dma *dma = dev->dma;
	int count;
	int order;
	int size;
	int total;
	int page_order;
	struct drm_buf_entry *entry;
	drm_dma_handle_t *dmah;
	struct drm_buf *buf;
	int alignment;
	unsigned long offset;
	int i;
	int byte_count;
	int page_count;
	unsigned long *temp_pagelist;
	struct drm_buf **temp_buflist;

	if (!drm_core_check_feature(dev, DRIVER_PCI_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	DRM_DEBUG("count=%d, size=%d (%d), order=%d, queue_count=%d\n",
		  request->count, request->size, size, order, dev->queue_count);

	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER)
		return -EINVAL;
	if (dev->queue_count)
		return -EBUSY;	/* Not while in use */

	alignment = (request->flags & _DRM_PAGE_ALIGN)
	    ? PAGE_ALIGN(size) : size;

#ifndef __linux__
	if (alignment != 0x1000) {
		DRM_ERROR("drm_addbufs_pci(): alignment (%x) != (%x)\n",
			alignment, 0x1000);
	}
#endif /* !__linux__ */

	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	spin_lock(&dev->count_lock);
	if (dev->buf_use) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	atomic_inc(&dev->buf_alloc);
	spin_unlock(&dev->count_lock);

	mutex_lock(&dev->struct_mutex);
	entry = &dma->bufs[order];
	if (entry->buf_count) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;	/* May only call once for each order */
	}

	if (count < 0 || count > 4096) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -EINVAL;
	}

	entry->buflist = malloc(count * sizeof(*entry->buflist),
		DRM_MEM_BUFS, M_WAITOK | M_ZERO);
	if (!entry->buflist) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}

	entry->seglist = malloc(count * sizeof(*entry->seglist),
		DRM_MEM_SEGS, M_WAITOK | M_ZERO);
	if (!entry->seglist) {
		free(entry->buflist, DRM_MEM_BUFS);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}

	/* Keep the original pagelist until we know all the allocations
	 * have succeeded
	 */
	temp_pagelist = malloc((dma->page_count + (count << page_order)) *
	    sizeof(*dma->pagelist), DRM_MEM_PAGES, M_WAITOK);

	if (!temp_pagelist) {
		free(entry->seglist, DRM_MEM_SEGS);
		free(entry->buflist, DRM_MEM_BUFS);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}
	memcpy(temp_pagelist,
	       dma->pagelist, dma->page_count * sizeof(*dma->pagelist));
	DRM_DEBUG("pagelist: %d entries\n",
		  dma->page_count + (count << page_order));

	entry->buf_size = size;
	entry->page_order = page_order;
	byte_count = 0;
	page_count = 0;

	while (entry->buf_count < count) {

		dmah = drm_pci_alloc(dev, PAGE_SIZE << page_order, 0x1000);

		if (!dmah) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			entry->seg_count = count;
			drm_cleanup_buf_error(dev, entry);
			free(temp_pagelist, DRM_MEM_PAGES);
			mutex_unlock(&dev->struct_mutex);
			atomic_dec(&dev->buf_alloc);
			return -ENOMEM;
		}
		entry->seglist[entry->seg_count++] = dmah;
		for (i = 0; i < (1 << page_order); i++) {
			DRM_DEBUG("page %d @ 0x%08lx\n",
				  dma->page_count + page_count,
				  (unsigned long)dmah->vaddr + PAGE_SIZE * i);
			temp_pagelist[dma->page_count + page_count++]
				= (unsigned long)dmah->vaddr + PAGE_SIZE * i;
		}
		for (offset = 0;
		     offset + size <= total && entry->buf_count < count;
		     offset += alignment, ++entry->buf_count) {
			buf = &entry->buflist[entry->buf_count];
			buf->idx = dma->buf_count + entry->buf_count;
			buf->total = alignment;
			buf->order = order;
			buf->used = 0;
			buf->offset = (dma->byte_count + byte_count + offset);
			buf->address = (void *)(dmah->vaddr + offset);
			buf->bus_address = dmah->busaddr + offset;
			buf->next = NULL;
			buf->waiting = 0;
			buf->pending = 0;
			init_waitqueue_head(&buf->dma_wait);
			buf->file_priv = NULL;

			buf->dev_priv_size = dev->driver->dev_priv_size;
			buf->dev_private = malloc(buf->dev_priv_size,
				DRM_MEM_BUFS, M_WAITOK | M_ZERO);
			if (!buf->dev_private) {
				/* Set count correctly so we free the proper amount. */
				entry->buf_count = count;
				entry->seg_count = count;
				drm_cleanup_buf_error(dev, entry);
				free(temp_pagelist, DRM_MEM_PAGES);
				mutex_unlock(&dev->struct_mutex);
				atomic_dec(&dev->buf_alloc);
				return -ENOMEM;
			}

			DRM_DEBUG("buffer %d @ %p\n",
				  entry->buf_count, buf->address);
		}
		byte_count += PAGE_SIZE << page_order;
	}

	temp_buflist = realloc(dma->buflist,
		(dma->buf_count + entry->buf_count) * sizeof(*dma->buflist),
		DRM_MEM_BUFS, M_WAITOK);

	if (!temp_buflist) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		free(temp_pagelist, DRM_MEM_PAGES);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	/* No allocations failed, so now we can replace the orginal pagelist
	 * with the new one.
	 */
	if (dma->page_count) {
		free(dma->pagelist, DRM_MEM_PAGES);
	}
	dma->pagelist = temp_pagelist;

	dma->buf_count += entry->buf_count;
	dma->seg_count += entry->seg_count;
	dma->page_count += entry->seg_count << page_order;
	dma->byte_count += PAGE_SIZE * (entry->seg_count << page_order);

	mutex_unlock(&dev->struct_mutex);

	request->count = entry->buf_count;
	request->size = size;

	if (request->flags & _DRM_PCI_BUFFER_RO)
		dma->flags = _DRM_DMA_USE_PCI_RO;

	atomic_dec(&dev->buf_alloc);
	return 0;

}
EXPORT_SYMBOL(drm_addbufs_pci);

static int drm_addbufs_sg(struct drm_device * dev, struct drm_buf_desc * request)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_entry *entry;
	struct drm_buf *buf;
	unsigned long offset;
	unsigned long agp_offset;
	int count;
	int order;
	int size;
	int alignment;
	int page_order;
	int total;
	int byte_count;
	int i;
	struct drm_buf **temp_buflist;

	if (!drm_core_check_feature(dev, DRIVER_SG))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment = (request->flags & _DRM_PAGE_ALIGN)
	    ? PAGE_ALIGN(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	byte_count = 0;
	agp_offset = request->agp_start;

	DRM_DEBUG("count:      %d\n", count);
	DRM_DEBUG("order:      %d\n", order);
	DRM_DEBUG("size:       %d\n", size);
	DRM_DEBUG("agp_offset: %lu\n", agp_offset);
	DRM_DEBUG("alignment:  %d\n", alignment);
	DRM_DEBUG("page_order: %d\n", page_order);
	DRM_DEBUG("total:      %d\n", total);

	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER)
		return -EINVAL;
	if (dev->queue_count)
		return -EBUSY;	/* Not while in use */

	spin_lock(&dev->count_lock);
	if (dev->buf_use) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	atomic_inc(&dev->buf_alloc);
	spin_unlock(&dev->count_lock);

	mutex_lock(&dev->struct_mutex);
	entry = &dma->bufs[order];
	if (entry->buf_count) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;	/* May only call once for each order */
	}

	if (count < 0 || count > 4096) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -EINVAL;
	}

	entry->buflist = malloc(count * sizeof(*entry->buflist),
		DRM_MEM_BUFS, M_WAITOK | M_ZERO);
	if (!entry->buflist) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}

	entry->buf_size = size;
	entry->page_order = page_order;

	offset = 0;

	while (entry->buf_count < count) {
		buf = &entry->buflist[entry->buf_count];
		buf->idx = dma->buf_count + entry->buf_count;
		buf->total = alignment;
		buf->order = order;
		buf->used = 0;

		buf->offset = (dma->byte_count + offset);
		buf->bus_address = agp_offset + offset;
		buf->address = (void *)(agp_offset + offset
					+ (unsigned long)dev->sg->virtual);
		buf->next = NULL;
		buf->waiting = 0;
		buf->pending = 0;
		init_waitqueue_head(&buf->dma_wait);
		buf->file_priv = NULL;

		buf->dev_priv_size = dev->driver->dev_priv_size;
		buf->dev_private = malloc(buf->dev_priv_size,
			DRM_MEM_BUFS, M_WAITOK | M_ZERO);
		if (!buf->dev_private) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			mutex_unlock(&dev->struct_mutex);
			atomic_dec(&dev->buf_alloc);
			return -ENOMEM;
		}

		DRM_DEBUG("buffer %d @ %p\n", entry->buf_count, buf->address);

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	DRM_DEBUG("byte_count: %d\n", byte_count);

	temp_buflist = realloc(dma->buflist,
		(dma->buf_count + entry->buf_count) * sizeof(*dma->buflist),
		DRM_MEM_BUFS, M_WAITOK);
	if (!temp_buflist) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->seg_count += entry->seg_count;
	dma->page_count += byte_count >> PAGE_SHIFT;
	dma->byte_count += byte_count;

	DRM_DEBUG("dma->buf_count : %d\n", dma->buf_count);
	DRM_DEBUG("entry->buf_count : %d\n", entry->buf_count);

	mutex_unlock(&dev->struct_mutex);

	request->count = entry->buf_count;
	request->size = size;

	dma->flags = _DRM_DMA_USE_SG;

	atomic_dec(&dev->buf_alloc);
	return 0;
}

static int drm_addbufs_fb(struct drm_device * dev, struct drm_buf_desc * request)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_entry *entry;
	struct drm_buf *buf;
	unsigned long offset;
	unsigned long agp_offset;
	int count;
	int order;
	int size;
	int alignment;
	int page_order;
	int total;
	int byte_count;
	int i;
	struct drm_buf **temp_buflist;

	if (!drm_core_check_feature(dev, DRIVER_FB_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment = (request->flags & _DRM_PAGE_ALIGN)
	    ? PAGE_ALIGN(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	byte_count = 0;
	agp_offset = request->agp_start;

	DRM_DEBUG("count:      %d\n", count);
	DRM_DEBUG("order:      %d\n", order);
	DRM_DEBUG("size:       %d\n", size);
	DRM_DEBUG("agp_offset: %lu\n", agp_offset);
	DRM_DEBUG("alignment:  %d\n", alignment);
	DRM_DEBUG("page_order: %d\n", page_order);
	DRM_DEBUG("total:      %d\n", total);

	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER)
		return -EINVAL;
	if (dev->queue_count)
		return -EBUSY;	/* Not while in use */

	spin_lock(&dev->count_lock);
	if (dev->buf_use) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	atomic_inc(&dev->buf_alloc);
	spin_unlock(&dev->count_lock);

	mutex_lock(&dev->struct_mutex);
	entry = &dma->bufs[order];
	if (entry->buf_count) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;	/* May only call once for each order */
	}

	if (count < 0 || count > 4096) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -EINVAL;
	}

	entry->buflist = malloc(count * sizeof(*entry->buflist),
		DRM_MEM_BUFS, M_WAITOK | M_ZERO);
	if (!entry->buflist) {
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}

	entry->buf_size = size;
	entry->page_order = page_order;

	offset = 0;

	while (entry->buf_count < count) {
		buf = &entry->buflist[entry->buf_count];
		buf->idx = dma->buf_count + entry->buf_count;
		buf->total = alignment;
		buf->order = order;
		buf->used = 0;

		buf->offset = (dma->byte_count + offset);
		buf->bus_address = agp_offset + offset;
		buf->address = (void *)(agp_offset + offset);
		buf->next = NULL;
		buf->waiting = 0;
		buf->pending = 0;
		init_waitqueue_head(&buf->dma_wait);
		buf->file_priv = NULL;

		buf->dev_priv_size = dev->driver->dev_priv_size;
		buf->dev_private = malloc(buf->dev_priv_size,
			DRM_MEM_BUFS, M_WAITOK | M_ZERO);
		if (!buf->dev_private) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			mutex_unlock(&dev->struct_mutex);
			atomic_dec(&dev->buf_alloc);
			return -ENOMEM;
		}

		DRM_DEBUG("buffer %d @ %p\n", entry->buf_count, buf->address);

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	DRM_DEBUG("byte_count: %d\n", byte_count);

	temp_buflist = realloc(dma->buflist,
		(dma->buf_count + entry->buf_count) * sizeof(*dma->buflist),
		DRM_MEM_BUFS, M_WAITOK);
	if (!temp_buflist) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		mutex_unlock(&dev->struct_mutex);
		atomic_dec(&dev->buf_alloc);
		return -ENOMEM;
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->seg_count += entry->seg_count;
	dma->page_count += byte_count >> PAGE_SHIFT;
	dma->byte_count += byte_count;

	DRM_DEBUG("dma->buf_count : %d\n", dma->buf_count);
	DRM_DEBUG("entry->buf_count : %d\n", entry->buf_count);

	mutex_unlock(&dev->struct_mutex);

	request->count = entry->buf_count;
	request->size = size;

	dma->flags = _DRM_DMA_USE_FB;

	atomic_dec(&dev->buf_alloc);
	return 0;
}


/**
 * Add buffers for DMA transfers (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a struct drm_buf_desc request.
 * \return zero on success or a negative number on failure.
 *
 * According with the memory type specified in drm_buf_desc::flags and the
 * build options, it dispatches the call either to addbufs_agp(),
 * addbufs_sg() or addbufs_pci() for AGP, scatter-gather or consistent
 * PCI memory respectively.
 */
int drm_addbufs(struct drm_device *dev, void *data,
		struct drm_file *file_priv)
{
	struct drm_buf_desc *request = data;
	int ret;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_DMA))
		return -EINVAL;

#if __OS_HAS_AGP
	if (request->flags & _DRM_AGP_BUFFER)
		ret = drm_addbufs_agp(dev, request);
	else
#endif
	if (request->flags & _DRM_SG_BUFFER)
		ret = drm_addbufs_sg(dev, request);
	else if (request->flags & _DRM_FB_BUFFER)
		ret = drm_addbufs_fb(dev, request);
	else
		ret = drm_addbufs_pci(dev, request);

	return ret;
}

/**
 * Get information about the buffer mappings.
 *
 * This was originally mean for debugging purposes, or by a sophisticated
 * client library to determine how best to use the available buffers (e.g.,
 * large buffers can be used for image transfer).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_buf_info structure.
 * \return zero on success or a negative number on failure.
 *
 * Increments drm_device::buf_use while holding the drm_device::count_lock
 * lock, preventing of allocating more buffers after this call. Information
 * about each requested buffer is then copied into user space.
 */
int drm_infobufs(struct drm_device *dev, void *data,
		 struct drm_file *file_priv)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_info *request = data;
	int i;
	int count;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	spin_lock(&dev->count_lock);
	if (atomic_read(&dev->buf_alloc)) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	++dev->buf_use;		/* Can't allocate more after this call */
	spin_unlock(&dev->count_lock);

	for (i = 0, count = 0; i < DRM_MAX_ORDER + 1; i++) {
		if (dma->bufs[i].buf_count)
			++count;
	}

	DRM_DEBUG("count = %d\n", count);

	if (request->count >= count) {
		for (i = 0, count = 0; i < DRM_MAX_ORDER + 1; i++) {
			if (dma->bufs[i].buf_count) {
				struct drm_buf_desc __user *to =
				    &request->list[count];
				struct drm_buf_entry *from = &dma->bufs[i];
				struct drm_freelist *list = &dma->bufs[i].freelist;
				if (copy_to_user(&to->count,
						 &from->buf_count,
						 sizeof(from->buf_count)) ||
				    copy_to_user(&to->size,
						 &from->buf_size,
						 sizeof(from->buf_size)) ||
				    copy_to_user(&to->low_mark,
						 &list->low_mark,
						 sizeof(list->low_mark)) ||
				    copy_to_user(&to->high_mark,
						 &list->high_mark,
						 sizeof(list->high_mark)))
					return -EFAULT;

				DRM_DEBUG("%d %d %d %d %d\n",
					  i,
					  dma->bufs[i].buf_count,
					  dma->bufs[i].buf_size,
					  dma->bufs[i].freelist.low_mark,
					  dma->bufs[i].freelist.high_mark);
				++count;
			}
		}
	}
	request->count = count;

	return 0;
}

/**
 * Specifies a low and high water mark for buffer allocation
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg a pointer to a drm_buf_desc structure.
 * \return zero on success or a negative number on failure.
 *
 * Verifies that the size order is bounded between the admissible orders and
 * updates the respective drm_device_dma::bufs entry low and high water mark.
 *
 * \note This ioctl is deprecated and mostly never used.
 */
int drm_markbufs(struct drm_device *dev, void *data,
		 struct drm_file *file_priv)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_desc *request = data;
	int order;
	struct drm_buf_entry *entry;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	DRM_DEBUG("%d, %d, %d\n",
		  request->size, request->low_mark, request->high_mark);
	order = drm_order(request->size);
	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER)
		return -EINVAL;
	entry = &dma->bufs[order];

	if (request->low_mark < 0 || request->low_mark > entry->buf_count)
		return -EINVAL;
	if (request->high_mark < 0 || request->high_mark > entry->buf_count)
		return -EINVAL;

	entry->freelist.low_mark = request->low_mark;
	entry->freelist.high_mark = request->high_mark;

	return 0;
}

/**
 * Unreserve the buffers in list, previously reserved using drmDMA.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_buf_free structure.
 * \return zero on success or a negative number on failure.
 *
 * Calls free_buffer() for each used buffer.
 * This function is primarily used for debugging.
 */
int drm_freebufs(struct drm_device *dev, void *data,
		 struct drm_file *file_priv)
{
	struct drm_device_dma *dma = dev->dma;
	struct drm_buf_free *request = data;
	int i;
	int idx;
	struct drm_buf *buf;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	DRM_DEBUG("%d\n", request->count);
	for (i = 0; i < request->count; i++) {
		if (copy_from_user(&idx, &request->list[i], sizeof(idx)))
			return -EFAULT;
		if (idx < 0 || idx >= dma->buf_count) {
			DRM_ERROR("Index %d (of %d max)\n",
				  idx, dma->buf_count - 1);
			return -EINVAL;
		}
		buf = dma->buflist[idx];
		if (buf->file_priv != file_priv) {
			DRM_ERROR("Process %d freeing buffer not owned\n",
				  task_pid_nr(current));
			return -EINVAL;
		}
		drm_free_buffer(dev, buf);
	}

	return 0;
}

/**
 * Maps all of the DMA buffers into client-virtual space (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_buf_map structure.
 * \return zero on success or a negative number on failure.
 *
 * Maps the AGP, SG or PCI buffer region with do_mmap(), and copies information
 * about each buffer into user space. For PCI buffers, it calls do_mmap() with
 * offset equal to 0, which drm_mmap() interpretes as PCI buffers and calls
 * drm_mmap_dma().
 */
int drm_mapbufs(struct drm_device *dev, void *data,
	        struct drm_file *file_priv)
{
	struct drm_device_dma *dma = dev->dma;
	int retcode = 0;
	const int zero = 0;
	vm_offset_t address;
	struct vmspace *vms;
	vm_ooffset_t foff;
	vm_size_t size;
	vm_offset_t vaddr;
	struct drm_buf_map *request = data;
	int i;

	vms = DRM_CURPROC->td_proc->p_vmspace;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_DMA))
		return -EINVAL;

	if (!dma)
		return -EINVAL;

	spin_lock(&dev->count_lock);
	if (atomic_read(&dev->buf_alloc)) {
		spin_unlock(&dev->count_lock);
		return -EBUSY;
	}
	dev->buf_use++;		/* Can't allocate more after this call */
	spin_unlock(&dev->count_lock);

	if (request->count < dma->buf_count)
		goto done;

	if ((drm_core_has_AGP(dev) && (dma->flags & _DRM_DMA_USE_AGP))
	    || (drm_core_check_feature(dev, DRIVER_SG)
		&& (dma->flags & _DRM_DMA_USE_SG))
	    || (drm_core_check_feature(dev, DRIVER_FB_DMA)
		&& (dma->flags & _DRM_DMA_USE_FB))) {
		drm_local_map_t *map = dev->agp_buffer_map;
		unsigned long token = dev->agp_buffer_token_long;

		if (!map) {
			retcode = -EINVAL;
			goto done;
		}
#ifndef __linux__
		if ((unsigned long)map->offset != dev->agp_buffer_token_long) {
			DRM_ERROR("map->offset (0x%016lx) != agp_buffer_token_long (0x%016lx)\n",
				(unsigned long)map->offset,
				dev->agp_buffer_token_long);
		}
#endif
		size = round_page(map->size);
#ifdef DRM_NEWER_USER_TOKEN
		foff = token;
#else
		foff = map->offset;
#endif
	} else {
		size = round_page(dma->byte_count);
		foff = 0;
	}

	vaddr = round_page((vm_offset_t)vms->vm_daddr + MAXDSIZ);

#ifndef __linux__
	DRM_INFO("vm_mmap() before: vaddr (%016lx), size (%016lx), foff (%016lx), pid (%d), svuid (%u), euid(%d), ruid(%u)\n",
		(unsigned long)vaddr,
		(unsigned long)size,
		foff,
		DRM_CURRENTPID,
		DRM_CURRENTUID,
		DRM_CURRENTEUID,
		DRM_CURRENTRUID
	);
#endif

#if defined(__DragonFly__)
	retcode = vm_mmap(&vms->vm_map, &vaddr, size, PROT_READ | PROT_WRITE,
	    VM_PROT_ALL, MAP_SHARED | MAP_NOSYNC,
	    SLIST_FIRST(&dev->devnode->si_hlist), foff);
#elif __FreeBSD_version >= 600023
	retcode = vm_mmap(&vms->vm_map, &vaddr, size, PROT_READ | PROT_WRITE,
	    VM_PROT_ALL, MAP_SHARED | MAP_NOSYNC, OBJT_DEVICE,
	    dev->devnode, foff);
#else
	retcode = vm_mmap(&vms->vm_map, &vaddr, size, PROT_READ | PROT_WRITE,
	    VM_PROT_ALL, MAP_SHARED | MAP_NOSYNC,
	    SLIST_FIRST(&dev->devnode->si_hlist), foff);
#endif

#ifndef __linux__
	DRM_INFO("vm_mmap() after: vaddr (%016lx), size (%016lx), foff (%016lx)\n",
		(unsigned long)vaddr,
		(unsigned long)size,
		foff);
	if (retcode)
		DRM_ERROR("vm_mmap() retcode (%d)\n", retcode);
#endif

	if (retcode)
		goto done;

	request->virtual = (void *)vaddr;

	for (i = 0; i < dma->buf_count; i++) {
		if (DRM_COPY_TO_USER(&request->list[i].idx,
		    &dma->buflist[i]->idx, sizeof(request->list[0].idx))) {
			retcode = EFAULT;
			goto done;
		}
		if (DRM_COPY_TO_USER(&request->list[i].total,
		    &dma->buflist[i]->total, sizeof(request->list[0].total))) {
			retcode = EFAULT;
			goto done;
		}
		if (DRM_COPY_TO_USER(&request->list[i].used, &zero,
		    sizeof(zero))) {
			retcode = EFAULT;
			goto done;
		}
		address = vaddr + dma->buflist[i]->offset; /* *** */
		if (DRM_COPY_TO_USER(&request->list[i].address, &address,
		    sizeof(address))) {
			retcode = EFAULT;
			goto done;
		}
	}

 done:
	request->count = dma->buf_count;
	DRM_DEBUG("%d buffers, retcode = %d\n", request->count, retcode);

	return retcode;
}

/**
 * Compute size order.  Returns the exponent of the smaller power of two which
 * is greater or equal to given number.
 *
 * \param size size.
 * \return order.
 *
 * \todo Can be made faster.
 */
int drm_order(unsigned long size)
{
	int order;
	unsigned long tmp;

	for (order = 0, tmp = size >> 1; tmp; tmp >>= 1, order++) ;

	if (size & (size - 1))
		++order;
#if 0

	if (size == 0)
		return 0;

	order = flsl(size) - 1;
	if (size & ~(1ul << order))
		++order;
#endif

	return order;
}
EXPORT_SYMBOL(drm_order);
