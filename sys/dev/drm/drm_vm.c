/**
 * \file drm_vm.c
 * Memory mapping for DRM
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Mon Jan  4 08:58:31 1999 by faith@valinux.com
 *
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

/*
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

#include "drmP.h"
#ifdef __linux__
#if defined(__ia64__)
#include <linux/efi.h>
#include <linux/slab.h>
#endif
#endif /* __linux__ */

#ifdef DRM_NEWER_FOFF
	static const char *types[] = { "FB", "REG", "SHM", "AGP", "SG", "CON" };
	static off_t previous_foff = (off_t)(-2);
#endif

/**
 * mmap DMA memory.
 *
 * \param file_priv DRM file private.
 * \param vma virtual memory area.
 * \return zero on success or a negative number on failure.
 *
 * If the virtual memory area has no offset associated with it then it's a DMA
 * area, so calls mmap_dma(). Otherwise searches the map in drm_device::maplist,
 * checks that the restricted flag is not set, sets the virtual memory operations
 * according to the mapping type and remaps the pages. Finally sets the file
 * pointer and calls vm_open().
 */
static int drm_mmap_legacy_locked(struct dev_mmap_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
#ifdef DRM_NEWER_FOFF
	unsigned long foff = (unsigned long)ap->a_foff;
#endif
	vm_offset_t offset = ap->a_offset;
	struct drm_device *dev = drm_get_device_from_kdev(kdev);
	struct drm_file *file_priv = NULL;
	struct drm_local_map *map = NULL;
	struct drm_map_list *r_list;
	struct drm_map_list *r_list_found = NULL;
	enum drm_map_type type;
	vm_paddr_t phys;
#ifdef DRM_NEWER_FOFF
	struct drm_local_map *map_foff = NULL;
	struct drm_hash_item *hash;

	if ((off_t)ap->a_foff != previous_foff) {
		DRM_INFO("drm_mmap_legacy(): foff (%016lx) offset (%016lx), pid (%d), uid (%d)\n",
			(unsigned long)ap->a_foff,
			offset,
			DRM_CURRENTPID,
			DRM_CURRENTUID);
		previous_foff = ap->a_foff;
		if (foff && !drm_ht_find_item(&dev->map_hash, foff >> PAGE_SHIFT, &hash)) {
			map_foff = drm_hash_entry(hash, struct drm_map_list, hash)->map;
			const char *typestr;
			if (map_foff->type < 0 || map_foff->type > 5)
				typestr = "??";
			else
				typestr = types[map_foff->type];
			DRM_INFO("MAP FOUND: type (%4.4s), foff (0x%016lx), hash key (%016lx), offset (0x%016lx), handle (0x%016lx)\n",
				typestr,
				(unsigned long)foff,
				(unsigned long)hash->key,
				(unsigned long)map_foff->offset,
				(unsigned long)map_foff->handle);
		}
	}
#endif

        file_priv = drm_find_file_by_proc(dev, DRM_CURPROC);

        if (file_priv == NULL) {
                DRM_ERROR("can't find authenticator\n");
                return EINVAL;
        }
	if (dev != file_priv->minor->dev) {
                DRM_ERROR("dev != priv->minor->dev!\n");
	}

        if (!file_priv->authenticated)
                return EACCES;

#ifdef DRM_NEWER_USER_TOKEN
#if 0
	/* We check for "dma". On Apple's UniNorth, it's valid to have
	 * the AGP mapped at physical address 0
	 * --BenH.
	 */
	if (!foff
#if __OS_HAS_AGP
	    && (!dev->agp
#ifdef __linux__
		|| dev->agp->agp_info.device->vendor != PCI_VENDOR_ID_APPLE
#endif
		)
#endif
	    ) {
#endif
	if (dev->dma && offset < ptoa(dev->dma->page_count)) {
		struct drm_device_dma *dma = dev->dma;

		if (dma->pagelist != NULL) {
			unsigned long page = offset >> PAGE_SHIFT;
			unsigned long phys = dma->pagelist[page];
			ap->a_result = atop(phys);
			return 0;
		} else {
			return -1;
		}
	}
#if 0
	}
#endif

#endif /* DRM_NEWER_USER_TOKEN */

#ifndef DRM_NEWER_USER_TOKEN
	if (dev->dma && offset < ptoa(dev->dma->page_count)) {
		struct drm_device_dma *dma = dev->dma;

		if (dma->pagelist != NULL) {
			unsigned long page = offset >> PAGE_SHIFT;
			unsigned long phys = dma->pagelist[page];
			ap->a_result = atop(phys);
			return 0;
		} else {
			return -1;
		}
	}
#endif /* !DRM_NEWER_USER_TOKEN */

				/* A sequential search of a linked list is
				   fine here because: 1) there will only be
				   about 5-10 entries in the list and, 2) a
				   DRI client only has to do this mapping
				   once, so it doesn't have to be optimized
				   for performance, even if the list was a
				   bit longer. */
	list_for_each_entry(r_list, &dev->maplist, head) {
		if (offset >= r_list->map->offset && offset < r_list->map->offset + r_list->map->size) {
			r_list_found = r_list;
			break;
		}
	}
	if (r_list_found == NULL) {
		map = NULL;
	}
	else {
		map = r_list_found->map;
	}

	if (map == NULL) {
		DRM_ERROR("Could not find map, requested offset = %016lx\n",
			(unsigned long)offset);
#ifdef DRM_NEWER_FOFF
		if (drm_ht_find_item(&dev->map_hash, foff >> PAGE_SHIFT, &hash)) {
			DRM_ERROR("Could not find map for foff = 0x%016lx\n", (unsigned long)foff);
			return -1;
		}
		map = drm_hash_entry(hash, struct drm_map_list, hash)->map;
#else
		return EINVAL;
#endif
	}

#ifdef DRM_NEWER_FOFF
	if (foff && drm_ht_find_item(&dev->map_hash, foff >> PAGE_SHIFT, &hash)) {
		DRM_ERROR("Could not find map for foff = 0x%016lx\n", (unsigned long)foff);
	}
	else if (foff && !drm_ht_find_item(&dev->map_hash, foff >> PAGE_SHIFT, &hash)) {
		map_foff = drm_hash_entry(hash, struct drm_map_list, hash)->map;
		if (map != map_foff) {
			DRM_ERROR("map != map_foff for foff = 0x%016lx, offset = 0x%016lx\n",
				(unsigned long)foff,
				(unsigned long)map->offset);
		}
	}
#endif

	if (((map->flags &_DRM_RESTRICTED) && !capable(CAP_SYS_ADMIN))) {
		DRM_ERROR("restricted map\n");
		return EPERM;
	}
	type = map->type;

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

int drm_mmap_legacy(struct dev_mmap_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	struct drm_device *dev = drm_get_device_from_kdev(kdev);
	int ret;

	spin_lock(&dev->file_priv_lock);
	mutex_lock(&dev->struct_mutex);
	ret = drm_mmap_legacy_locked(ap);
	mutex_unlock(&dev->struct_mutex);
	spin_unlock(&dev->file_priv_lock);

	return ret;
}

/* newer UNIMPLEMENTED */
static void drm_vm_open(struct vm_area_struct *vma);
static void drm_vm_close(struct vm_area_struct *vma);

static pgprot_t drm_io_prot(uint32_t map_type, struct vm_area_struct *vma)
{
	pgprot_t tmp = vm_get_page_prot(vma->vm_flags);

#ifdef __linux__
#if defined(__i386__) || defined(__x86_64__)
	if (boot_cpu_data.x86 > 3 && map_type != _DRM_AGP) {
		pgprot_val(tmp) |= _PAGE_PCD;
		pgprot_val(tmp) &= ~_PAGE_PWT;
	}
#elif defined(__powerpc__)
	pgprot_val(tmp) |= _PAGE_NO_CACHE;
	if (map_type == _DRM_REGISTERS)
		pgprot_val(tmp) |= _PAGE_GUARDED;
#elif defined(__ia64__)
	if (efi_range_is_wc(vma->vm_start, vma->vm_end -
				    vma->vm_start))
		tmp = pgprot_writecombine(tmp);
	else
		tmp = pgprot_noncached(tmp);
#elif defined(__sparc__)
	tmp = pgprot_noncached(tmp);
#endif
#endif /* __linux__ */
	return tmp;
}

static pgprot_t drm_dma_prot(uint32_t map_type, struct vm_area_struct *vma)
{
	pgprot_t tmp = vm_get_page_prot(vma->vm_flags);

#if defined(__powerpc__) && defined(CONFIG_NOT_COHERENT_CACHE)
	tmp |= _PAGE_NO_CACHE;
#endif
	return tmp;
}

/**
 * \c fault method for AGP virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Find the right map and if it's AGP memory find the real physical page to
 * map, get the page, increment the use count and return it.
 */
#if __OS_HAS_AGP
static int drm_do_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_local_map *map = NULL;
	struct drm_map_list *r_list;
	struct drm_hash_item *hash;

	/*
	 * Find the right map
	 */
	if (!drm_core_has_AGP(dev))
		goto vm_fault_error;

	if (!dev->agp || !dev->agp->cant_use_aperture)
		goto vm_fault_error;

	if (drm_ht_find_item(&dev->map_hash, vma->vm_pgoff, &hash))
		goto vm_fault_error;

	r_list = drm_hash_entry(hash, struct drm_map_list, hash);
	map = r_list->map;

	if (map && map->type == _DRM_AGP) {
		/*
		 * Using vm_pgoff as a selector forces us to use this unusual
		 * addressing scheme.
		 */
		resource_size_t offset = (unsigned long)vmf->virtual_address -
			vma->vm_start;
		resource_size_t baddr = map->offset + offset;
		struct drm_agp_mem *agpmem;
		struct page *page;

#ifdef __alpha__
		/*
		 * Adjust to a bus-relative address
		 */
		baddr -= dev->hose->mem_space->start;
#endif

		/*
		 * It's AGP memory - find the real physical page to map
		 */
		list_for_each_entry(agpmem, &dev->agp->memory, head) {
			if (agpmem->bound <= baddr &&
			    agpmem->bound + agpmem->pages * PAGE_SIZE > baddr)
				break;
		}

		if (!agpmem)
			goto vm_fault_error;

		/*
		 * Get the page, inc the use count, and return it
		 */
		offset = (baddr - agpmem->bound) >> PAGE_SHIFT;
		page = agpmem->memory->pages[offset];
		get_page(page);
		vmf->page = page;

		DRM_DEBUG
		    ("baddr = 0x%llx page = 0x%p, offset = 0x%llx, count=%d\n",
		     (unsigned long long)baddr,
		     agpmem->memory->pages[offset],
		     (unsigned long long)offset,
		     page_count(page));
		return 0;
	}
vm_fault_error:
	return VM_FAULT_SIGBUS;	/* Disallow mremap */
}
#else				/* __OS_HAS_AGP */
static int drm_do_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}
#endif				/* __OS_HAS_AGP */

/**
 * \c nopage method for shared virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Get the mapping, find the real physical page to map, get the page, and
 * return it.
 */
static int drm_do_vm_shm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct drm_local_map *map = vma->vm_private_data;
	unsigned long offset;
	unsigned long i;
	struct page *page;

	if (!map)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = (unsigned long)vmf->virtual_address - vma->vm_start;
	i = (unsigned long)map->handle + offset;
	page = vmalloc_to_page((void *)i);
	if (!page)
		return VM_FAULT_SIGBUS;
	get_page(page);
	vmf->page = page;

	DRM_DEBUG("shm_fault 0x%lx\n", offset);
	return 0;
}

/**
 * \c close method for shared virtual memory.
 *
 * \param vma virtual memory area.
 *
 * Deletes map information if we are the last
 * person to close a mapping and it's not in the global maplist.
 */
static void drm_vm_shm_close(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_vma_entry *pt, *temp;
	struct drm_local_map *map;
	struct drm_map_list *r_list;
	int found_maps = 0;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);
	atomic_dec(&dev->vma_count);

	map = vma->vm_private_data;

	mutex_lock(&dev->struct_mutex);
	list_for_each_entry_safe(pt, temp, &dev->vmalist, head) {
		if (pt->vma->vm_private_data == map)
			found_maps++;
		if (pt->vma == vma) {
			list_del(&pt->head);
#ifdef __linux__
			kfree(pt);
#else
			free(pt, DRM_MEM_DEFAULT);
#endif
		}
	}

	/* We were the only map that was found */
	if (found_maps == 1 && map->flags & _DRM_REMOVABLE) {
		/* Check to see if we are in the maplist, if we are not, then
		 * we delete this mappings information.
		 */
		found_maps = 0;
		list_for_each_entry(r_list, &dev->maplist, head) {
			if (r_list->map == map)
				found_maps++;
		}

		if (!found_maps) {
			drm_dma_handle_t dmah;

			switch (map->type) {
			case _DRM_REGISTERS:
			case _DRM_FRAME_BUFFER:
				if (drm_core_has_MTRR(dev) && map->mtrr >= 0) {
					int retcode;
					retcode = mtrr_del(map->mtrr,
							   map->offset,
							   map->size);
					DRM_DEBUG("mtrr_del = %d\n", retcode);
				}
#ifdef __linux__
				iounmap(map->handle);
#else
				drm_iounmap(map->handle, map->size);
#endif
				break;
			case _DRM_SHM:
				vfree(map->handle);
				break;
			case _DRM_AGP:
			case _DRM_SCATTER_GATHER:
				break;
			case _DRM_CONSISTENT:
				dmah.vaddr = map->handle;
				dmah.busaddr = map->offset;
				dmah.size = map->size;
				__drm_pci_free(dev, &dmah);
				break;
			case _DRM_GEM:
				DRM_ERROR("tried to rmmap GEM object\n");
				break;
			}
#ifdef __linux__
			kfree(map);
#else
			free(map, DRM_MEM_DEFAULT);
#endif
		}
	}
	mutex_unlock(&dev->struct_mutex);
}


/**
 * \c fault method for DMA virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Determine the page number from the page offset and get it from drm_device_dma::pagelist.
 */
static int drm_do_vm_dma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_device_dma *dma = dev->dma;
	unsigned long offset;
	unsigned long page_nr;
	struct page *page;

	if (!dma)
		return VM_FAULT_SIGBUS;	/* Error */
	if (!dma->pagelist)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = (unsigned long)vmf->virtual_address - vma->vm_start;	/* vm_[pg]off[set] should be 0 */
	page_nr = offset >> PAGE_SHIFT; /* page_nr could just be vmf->pgoff */
	page = virt_to_page((dma->pagelist[page_nr] + (offset & (~PAGE_MASK))));

	get_page(page);
	vmf->page = page;

	DRM_DEBUG("dma_fault 0x%lx (page %lu)\n", offset, page_nr);
	return 0;
}


/**
 * \c fault method for scatter-gather virtual memory.
 *
 * \param vma virtual memory area.
 * \param address access address.
 * \return pointer to the page structure.
 *
 * Determine the map offset from the page offset and get it from drm_sg_mem::pagelist.
 */
static int drm_do_vm_sg_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct drm_local_map *map = vma->vm_private_data;
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_sg_mem *entry = dev->sg;
	unsigned long offset;
	unsigned long map_offset;
	unsigned long page_offset;
	struct page *page;

	if (!entry)
		return VM_FAULT_SIGBUS;	/* Error */
	if (!entry->pagelist)
		return VM_FAULT_SIGBUS;	/* Nothing allocated */

	offset = (unsigned long)vmf->virtual_address - vma->vm_start;
#ifdef __linux__
	map_offset = map->offset - (unsigned long)dev->sg->virtual;
#else
	map_offset = map->offset - dev->sg->handle;
#endif
	page_offset = (offset >> PAGE_SHIFT) + (map_offset >> PAGE_SHIFT);
	page = entry->pagelist[page_offset];
	get_page(page);
	vmf->page = page;

	return 0;
}

static int drm_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return drm_do_vm_fault(vma, vmf);
}

static int drm_vm_shm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return drm_do_vm_shm_fault(vma, vmf);
}

static int drm_vm_dma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return drm_do_vm_dma_fault(vma, vmf);
}

static int drm_vm_sg_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return drm_do_vm_sg_fault(vma, vmf);
}

/** AGP virtual memory operations */
static const struct vm_operations_struct drm_vm_ops = {
	.fault = drm_vm_fault,
	.open = drm_vm_open,
	.close = drm_vm_close,
};

/** Shared virtual memory operations */
static const struct vm_operations_struct drm_vm_shm_ops = {
	.fault = drm_vm_shm_fault,
	.open = drm_vm_open,
	.close = drm_vm_shm_close,
};

/** DMA virtual memory operations */
static const struct vm_operations_struct drm_vm_dma_ops = {
	.fault = drm_vm_dma_fault,
	.open = drm_vm_open,
	.close = drm_vm_close,
};

/** Scatter-gather virtual memory operations */
static const struct vm_operations_struct drm_vm_sg_ops = {
	.fault = drm_vm_sg_fault,
	.open = drm_vm_open,
	.close = drm_vm_close,
};

/**
 * \c open method for shared virtual memory.
 *
 * \param vma virtual memory area.
 *
 * Create a new drm_vma_entry structure as the \p vma private data entry and
 * add it to drm_device::vmalist.
 */
void drm_vm_open_locked(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_vma_entry *vma_entry;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);
	atomic_inc(&dev->vma_count);

#ifdef __linux__
	vma_entry = kmalloc(sizeof(*vma_entry), GFP_KERNEL);
#else
	vma_entry = malloc(sizeof(*vma_entry), DRM_MEM_DEFAULT, M_WAITOK);
#endif
	if (vma_entry) {
		vma_entry->vma = vma;
#ifdef __linux__
		vma_entry->pid = current->pid;
#else /* UNIMPLEMENTED just to compile */
		vma_entry->pid = 0;
#endif
		list_add(&vma_entry->head, &dev->vmalist);
	}
}

static void drm_vm_open(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;

	mutex_lock(&dev->struct_mutex);
	drm_vm_open_locked(vma);
	mutex_unlock(&dev->struct_mutex);
}


/**
 * \c close method for all virtual memory types.
 *
 * \param vma virtual memory area.
 *
 * Search the \p vma private data entry in drm_device::vmalist, unlink it, and
 * free it.
 */
static void drm_vm_close(struct vm_area_struct *vma)
{
	struct drm_file *priv = vma->vm_file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_vma_entry *pt, *temp;

	DRM_DEBUG("0x%08lx,0x%08lx\n",
		  vma->vm_start, vma->vm_end - vma->vm_start);
	atomic_dec(&dev->vma_count);

	mutex_lock(&dev->struct_mutex);
	list_for_each_entry_safe(pt, temp, &dev->vmalist, head) {
		if (pt->vma == vma) {
			list_del(&pt->head);
#ifdef __linux__
			kfree(pt);
#else
			free(pt, DRM_MEM_DEFAULT);
#endif
			break;
		}
	}
	mutex_unlock(&dev->struct_mutex);
}

/**
 * mmap DMA memory.
 *
 * \param file_priv DRM file private.
 * \param vma virtual memory area.
 * \return zero on success or a negative number on failure.
 *
 * Sets the virtual memory area operations structure to vm_dma_ops, the file
 * pointer, and calls vm_open().
 */
static int drm_mmap_dma(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev;
	struct drm_device_dma *dma;
	unsigned long length = vma->vm_end - vma->vm_start;

	dev = priv->minor->dev;
	dma = dev->dma;
	DRM_DEBUG("start = 0x%lx, end = 0x%lx, page offset = 0x%lx\n",
		  vma->vm_start, vma->vm_end, vma->vm_pgoff);

	/* Length must match exact page count */
	if (!dma || (length >> PAGE_SHIFT) != dma->page_count) {
		return -EINVAL;
	}

	if (!capable(CAP_SYS_ADMIN) &&
	    (dma->flags & _DRM_DMA_USE_PCI_RO)) {
		vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
#if defined(__i386__) || defined(__x86_64__)
		pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
#else
		/* Ye gads this is ugly.  With more thought
		   we could move this up higher and use
		   `protection_map' instead.  */
		vma->vm_page_prot =
		    __pgprot(pte_val
			     (pte_wrprotect
			      (__pte(pgprot_val(vma->vm_page_prot)))));
#endif
	}

	vma->vm_ops = &drm_vm_dma_ops;

	vma->vm_flags |= VM_RESERVED;	/* Don't swap */
	vma->vm_flags |= VM_DONTEXPAND;

	vma->vm_file = filp;	/* Needed for drm_vm_open() */
	drm_vm_open_locked(vma);
	return 0;
}

resource_size_t drm_core_get_map_ofs(struct drm_local_map * map)
{
	return map->offset;
}

EXPORT_SYMBOL(drm_core_get_map_ofs);

resource_size_t drm_core_get_reg_ofs(struct drm_device *dev)
{
#ifdef __alpha__
	return dev->hose->dense_mem_base - dev->hose->mem_space->start;
#else
	return 0;
#endif
}

EXPORT_SYMBOL(drm_core_get_reg_ofs);

/**
 * mmap DMA memory.
 *
 * \param file_priv DRM file private.
 * \param vma virtual memory area.
 * \return zero on success or a negative number on failure.
 *
 * If the virtual memory area has no offset associated with it then it's a DMA
 * area, so calls mmap_dma(). Otherwise searches the map in drm_device::maplist,
 * checks that the restricted flag is not set, sets the virtual memory operations
 * according to the mapping type and remaps the pages. Finally sets the file
 * pointer and calls vm_open().
 */
int drm_mmap_locked(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_local_map *map = NULL;
	resource_size_t offset = 0;
	struct drm_hash_item *hash;

	DRM_DEBUG("start = 0x%lx, end = 0x%lx, page offset = 0x%lx\n",
		  vma->vm_start, vma->vm_end, vma->vm_pgoff);

	if (!priv->authenticated)
		return -EACCES;

	/* We check for "dma". On Apple's UniNorth, it's valid to have
	 * the AGP mapped at physical address 0
	 * --BenH.
	 */
	if (!vma->vm_pgoff
#if __OS_HAS_AGP
	    && (!dev->agp
		|| dev->agp->agp_info.id_vendor != PCI_VENDOR_ID_APPLE)
#endif
	    )
		return drm_mmap_dma(filp, vma);

	if (drm_ht_find_item(&dev->map_hash, vma->vm_pgoff, &hash)) {
		DRM_ERROR("Could not find map\n");
		return -EINVAL;
	}

	map = drm_hash_entry(hash, struct drm_map_list, hash)->map;
	if (!map || ((map->flags & _DRM_RESTRICTED) && !capable(CAP_SYS_ADMIN)))
		return -EPERM;

	/* Check for valid size. */
	if (map->size < vma->vm_end - vma->vm_start)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN) && (map->flags & _DRM_READ_ONLY)) {
		vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
#if defined(__i386__) || defined(__x86_64__)
		pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
#else
		/* Ye gads this is ugly.  With more thought
		   we could move this up higher and use
		   `protection_map' instead.  */
		vma->vm_page_prot =
		    __pgprot(pte_val
			     (pte_wrprotect
			      (__pte(pgprot_val(vma->vm_page_prot)))));
#endif
	}

	switch (map->type) {
	case _DRM_AGP:
		if (drm_core_has_AGP(dev) && dev->agp->cant_use_aperture) {
			/*
			 * On some platforms we can't talk to bus dma address from the CPU, so for
			 * memory of type DRM_AGP, we'll deal with sorting out the real physical
			 * pages and mappings in fault()
			 */
#if defined(__powerpc__)
			pgprot_val(vma->vm_page_prot) |= _PAGE_NO_CACHE;
#endif
			vma->vm_ops = &drm_vm_ops;
			break;
		}
		/* fall through to _DRM_FRAME_BUFFER... */
	case _DRM_FRAME_BUFFER:
	case _DRM_REGISTERS:
		offset = dev->driver->get_reg_ofs(dev);
		vma->vm_flags |= VM_IO;	/* not in core dump */
		vma->vm_page_prot = drm_io_prot(map->type, vma);
		if (io_remap_pfn_range(vma, vma->vm_start,
				       (map->offset + offset) >> PAGE_SHIFT,
				       vma->vm_end - vma->vm_start,
				       vma->vm_page_prot))
			return -EAGAIN;
		DRM_DEBUG("   Type = %d; start = 0x%lx, end = 0x%lx,"
			  " offset = 0x%llx\n",
			  map->type,
			  vma->vm_start, vma->vm_end, (unsigned long long)(map->offset + offset));
		vma->vm_ops = &drm_vm_ops;
		break;
	case _DRM_CONSISTENT:
		/* Consistent memory is really like shared memory. But
		 * it's allocated in a different way, so avoid fault */
		if (remap_pfn_range(vma, vma->vm_start,
#ifdef __linux__
		    page_to_pfn(virt_to_page(map->handle)),
#else
		    page_to_pfn(virt_to_page((unsigned long)map->handle)),
#endif
		    vma->vm_end - vma->vm_start, vma->vm_page_prot))
			return -EAGAIN;
		vma->vm_page_prot = drm_dma_prot(map->type, vma);
	/* fall through to _DRM_SHM */
	case _DRM_SHM:
		vma->vm_ops = &drm_vm_shm_ops;
		vma->vm_private_data = (void *)map;
		/* Don't let this area swap.  Change when
		   DRM_KERNEL advisory is supported. */
		vma->vm_flags |= VM_RESERVED;
		break;
	case _DRM_SCATTER_GATHER:
		vma->vm_ops = &drm_vm_sg_ops;
		vma->vm_private_data = (void *)map;
		vma->vm_flags |= VM_RESERVED;
		vma->vm_page_prot = drm_dma_prot(map->type, vma);
		break;
	default:
		return -EINVAL;	/* This should never happen. */
	}
	vma->vm_flags |= VM_RESERVED;	/* Don't swap */
	vma->vm_flags |= VM_DONTEXPAND;

	vma->vm_file = filp;	/* Needed for drm_vm_open() */
	drm_vm_open_locked(vma);
	return 0;
}

int drm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;
	int ret;

	mutex_lock(&dev->struct_mutex);
	ret = drm_mmap_locked(filp, vma);
	mutex_unlock(&dev->struct_mutex);

	return ret;
}
EXPORT_SYMBOL(drm_mmap);
