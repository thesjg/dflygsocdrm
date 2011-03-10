/**
 * \file ati_pcigart.c
 * ATI PCI GART support
 *
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Wed Dec 13 21:52:19 2000 by gareth@valinux.com
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

#include "drmP.h"

# define ATI_PCIGART_PAGE_SIZE		4096	/**< PCI GART page size */

#define ATI_PCIGART_PAGE_MASK		(~(ATI_PCIGART_PAGE_SIZE-1))

#define ATI_PCIE_WRITE 0x4
#define ATI_PCIE_READ 0x8

#if 0
static void
drm_ati_alloc_pcigart_table_cb(void *arg, bus_dma_segment_t *segs,
			       int nsegs, int error)
{
	struct drm_dma_handle *dmah = arg;

	if (error != 0)
		return;

	KASSERT(nsegs == 1,
	    ("drm_ati_alloc_pcigart_table_cb: bad dma segment count"));

	dmah->busaddr = segs[0].ds_addr;
}
#endif

static int drm_ati_alloc_pcigart_table(struct drm_device *dev,
				       struct drm_ati_pcigart_info *gart_info)
{
#if 0
	struct drm_dma_handle *dmah;
	int flags, ret;

	dmah = malloc(sizeof(struct drm_dma_handle), DRM_MEM_DMA,
	    M_ZERO | M_NOWAIT);
	if (dmah == NULL)
		return ENOMEM;

	ret = bus_dma_tag_create(NULL, PAGE_SIZE, 0, /* tag, align, boundary */
	    gart_info->table_mask, BUS_SPACE_MAXADDR, /* lowaddr, highaddr */
	    NULL, NULL, /* filtfunc, filtfuncargs */
	    gart_info->table_size, 1, /* maxsize, nsegs */
	    gart_info->table_size, /* maxsegsize */
	    0, /* flags */
	    &dmah->tag);
	if (ret != 0) {
		free(dmah, DRM_MEM_DMA);
		return ENOMEM;
	}

	flags = BUS_DMA_WAITOK | BUS_DMA_ZERO;

#if 0
	if (gart_info->gart_reg_if == DRM_ATI_GART_IGP)
	    flags |= BUS_DMA_NOCACHE;
#endif
	
	ret = bus_dmamem_alloc(dmah->tag, &dmah->vaddr, flags, &dmah->map);
	if (ret != 0) {
		bus_dma_tag_destroy(dmah->tag);
		free(dmah, DRM_MEM_DMA);
		return ENOMEM;
	}

	ret = bus_dmamap_load(dmah->tag, dmah->map, dmah->vaddr,
	    gart_info->table_size, drm_ati_alloc_pcigart_table_cb, dmah,
	    BUS_DMA_NOWAIT);
	if (ret != 0) {
		bus_dmamem_free(dmah->tag, dmah->vaddr, dmah->map);
		bus_dma_tag_destroy(dmah->tag);
		free(dmah, DRM_MEM_DMA);
		return ENOMEM;
	}

	gart_info->dmah = dmah;
#endif /* 0 */

	gart_info->table_handle = drm_pci_alloc(dev, gart_info->table_size,
						PAGE_SIZE);
	if (gart_info->table_handle == NULL)
		return -ENOMEM;

	return 0;
}

static void drm_ati_free_pcigart_table(struct drm_device *dev,
				       struct drm_ati_pcigart_info *gart_info)
{
#if 0
	struct drm_dma_handle *dmah = gart_info->dmah;

	bus_dmamem_free(dmah->tag, dmah->vaddr, dmah->map);
	bus_dma_tag_destroy(dmah->tag);
	free(dmah, DRM_MEM_DMA);
	gart_info->dmah = NULL;
#endif
	drm_pci_free(dev, gart_info->table_handle);
	gart_info->table_handle = NULL;
}

int drm_ati_pcigart_cleanup(struct drm_device *dev, struct drm_ati_pcigart_info *gart_info)
{
#if 0
	/* we need to support large memory configurations */
	if (dev->sg == NULL) {
		DRM_ERROR("no scatter/gather memory!\n");
		return 0;
	}

	if (gart_info->bus_addr) {
		if (gart_info->gart_table_location == DRM_ATI_GART_MAIN) {
			gart_info->bus_addr = 0;
			if (gart_info->dmah)
				drm_ati_free_pcigart_table(dev, gart_info);
		}
	}
#endif
	struct drm_sg_mem *entry = dev->sg;
#if __linux__
	unsigned long pages;
	int i;
	int max_pages;
#endif

	/* we need to support large memory configurations */
	if (!entry) {
		DRM_ERROR("no scatter/gather memory!\n");
		return 0;
	}

	if (gart_info->bus_addr) {

#ifdef __linux__
		max_pages = (gart_info->table_size / sizeof(u32));
		pages = (entry->pages <= max_pages)
		  ? entry->pages : max_pages;

		for (i = 0; i < pages; i++) {
			if (!entry->busaddr[i])
				break;
			pci_unmap_page(dev->pdev, entry->busaddr[i],
					 PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		}
#endif

		if (gart_info->gart_table_location == DRM_ATI_GART_MAIN)
			gart_info->bus_addr = 0;
	}

	if (gart_info->gart_table_location == DRM_ATI_GART_MAIN &&
	    gart_info->table_handle) {
		drm_ati_free_pcigart_table(dev, gart_info);
	}

	return 1;
}
EXPORT_SYMBOL(drm_ati_pcigart_cleanup);

int drm_ati_pcigart_init(struct drm_device *dev, struct drm_ati_pcigart_info *gart_info)
{
#ifdef DRM_NEWER_PCIGART
	struct drm_local_map *map = &gart_info->mapping;
#endif
	struct drm_sg_mem *entry = dev->sg;
	void *address = NULL;
	unsigned long pages;
	u32 *pci_gart = NULL, page_base, gart_idx;
	dma_addr_t bus_address = 0;
	int i, j, ret = 0;
#ifdef DRM_NEWER_PCIGART
	int max_ati_pages, max_real_pages;
#else
	dma_addr_t entry_addr;
	int max_pages;
#endif

	if (!entry) {
		DRM_ERROR("no scatter/gather memory!\n");
		goto done;
	}

	if (gart_info->gart_table_location == DRM_ATI_GART_MAIN) {
		DRM_DEBUG("PCI: no table in VRAM: using normal RAM\n");

#ifdef __linux__
		if (pci_set_dma_mask(dev->pdev, gart_info->table_mask)) {
			DRM_ERROR("fail to set dma mask to 0x%Lx\n",
				  (unsigned long long)gart_info->table_mask);
			ret = 1;
			goto done;
		}
#endif
		ret = drm_ati_alloc_pcigart_table(dev, gart_info);
		if (ret) {
			DRM_ERROR("cannot allocate PCI GART page!\n");
			goto done;
		}

#if 0
		address = (void *)gart_info->dmah->vaddr;
		bus_address = gart_info->dmah->busaddr;
#endif

#if DRM_NEWER_PCIGART
		pci_gart = gart_info->table_handle->vaddr;
#endif
		address = gart_info->table_handle->vaddr;
		bus_address = gart_info->table_handle->busaddr;
	} else {
		address = gart_info->addr;
		bus_address = gart_info->bus_addr;
		DRM_DEBUG("PCI: Gart Table: VRAM %08LX mapped at %08lX\n",
			  (unsigned long long)bus_address,
			  (unsigned long)address);
	}

#ifdef DRM_NEWER_PCIGART
	max_ati_pages = (gart_info->table_size / sizeof(u32));
	max_real_pages = max_ati_pages / (PAGE_SIZE / ATI_PCIGART_PAGE_SIZE);
	pages = (entry->pages <= max_real_pages)
	    ? entry->pages : max_real_pages;

	if (gart_info->gart_table_location == DRM_ATI_GART_MAIN) {
		memset(pci_gart, 0, max_ati_pages * sizeof(u32));
	} else {
		memset_io((void __iomem *)map->handle, 0, max_ati_pages * sizeof(u32));
	}
#else /* !DRM_NEWER_PCIGART */
	pci_gart = (u32 *) address;

	max_pages = (gart_info->table_size / sizeof(u32));
	pages = (dev->sg->pages <= max_pages)
	    ? dev->sg->pages : max_pages;

	memset(pci_gart, 0, max_pages * sizeof(u32));

	KASSERT(PAGE_SIZE >= ATI_PCIGART_PAGE_SIZE, ("page size too small"));
#endif /* !DRM_NEWER_PCIGART */

	gart_idx = 0;
	for (i = 0; i < pages; i++) {
		/* we need to support large memory configurations */
#ifdef __linux__
		entry->busaddr[i] = pci_map_page(dev->pdev, entry->pagelist[i],
						 0, PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		if (entry->busaddr[i] == 0) {
			DRM_ERROR("unable to map PCIGART pages!\n");
			drm_ati_pcigart_cleanup(dev, gart_info);
			address = NULL;
			bus_address = 0;
			goto done;
		}
#endif /* __linux__ */

#ifdef DRM_NEWER_PCIGART
		if ((unsigned long)entry->busaddr[i] > 0xFFFFFFFFUL) {
			DRM_ERROR("Over 32-bit ptr busaddr[%d] (%016lx)\n",
				i, (unsigned long)entry->busaddr[i]);
		}
		page_base = (u32) entry->busaddr[i];
#else
		entry_addr = dev->sg->busaddr[i];
#endif

		for (j = 0; j < (PAGE_SIZE / ATI_PCIGART_PAGE_SIZE); j++) {
#ifdef DRM_NEWER_PCIGART
			u32 val;

			switch(gart_info->gart_reg_if) {
			case DRM_ATI_GART_IGP:
				val = page_base | 0xc;
				break;
			case DRM_ATI_GART_PCIE:
				val = (page_base >> 8) | 0xc;
				break;
			default:
			case DRM_ATI_GART_PCI:
				val = page_base;
				break;
			}
			if (gart_info->gart_table_location ==
			    DRM_ATI_GART_MAIN)
				pci_gart[gart_idx] = cpu_to_le32(val);
			else
				DRM_WRITE32(map, gart_idx * sizeof(u32), val);
			gart_idx++;
			page_base += ATI_PCIGART_PAGE_SIZE;
#else /* !DRM_NEWER_PCIGART */
			page_base = (u32) entry_addr & ATI_PCIGART_PAGE_MASK;
			switch(gart_info->gart_reg_if) {
			case DRM_ATI_GART_IGP:
				page_base |=
				    (upper_32_bits(entry_addr) & 0xff) << 4;
				page_base |= 0xc;
				break;
			case DRM_ATI_GART_PCIE:
				page_base >>= 8;
				page_base |=
				    (upper_32_bits(entry_addr) & 0xff) << 24;
				page_base |= ATI_PCIE_READ | ATI_PCIE_WRITE;
				break;
			default:
			case DRM_ATI_GART_PCI:
				break;
			}
			*pci_gart = cpu_to_le32(page_base);
			pci_gart++;
			entry_addr += ATI_PCIGART_PAGE_SIZE;
#endif /* !DRM_NEWER_PCIGART */
		}
	}
	ret = 1;

#if defined(__i386__) || defined(__x86_64__)
	wbinvd();
#else
	mb();
#endif

      done:
	gart_info->addr = address;
	gart_info->bus_addr = bus_address;
	return ret;
}
EXPORT_SYMBOL(drm_ati_pcigart_init);
