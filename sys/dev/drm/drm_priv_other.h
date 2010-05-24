/* drm_priv_other.h -- Header for Direct Rendering Manager other OS -*- linux-c -*-
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
 * ... AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    David Shao <davshao@gmail.com>
 *
 */

#ifndef _DRM_PRIV_OTHER_H_
#define _DRM_PRIV_OTHER_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#include "dev/drm/drm_priv_include.h"
#include "dev/drm/drm_linux_list.h"

/* For current implementation of idr */
#include <sys/tree.h>

MALLOC_DECLARE(DRM_MEM_DMA);
MALLOC_DECLARE(DRM_MEM_SAREA);
MALLOC_DECLARE(DRM_MEM_DRIVER);
MALLOC_DECLARE(DRM_MEM_MAGIC);
MALLOC_DECLARE(DRM_MEM_IOCTLS);
MALLOC_DECLARE(DRM_MEM_MAPS);
MALLOC_DECLARE(DRM_MEM_BUFS);
MALLOC_DECLARE(DRM_MEM_SEGS);
MALLOC_DECLARE(DRM_MEM_PAGES);
MALLOC_DECLARE(DRM_MEM_FILES);
MALLOC_DECLARE(DRM_MEM_QUEUES);
MALLOC_DECLARE(DRM_MEM_CMDS);
MALLOC_DECLARE(DRM_MEM_MAPPINGS);
MALLOC_DECLARE(DRM_MEM_BUFLISTS);
MALLOC_DECLARE(DRM_MEM_AGPLISTS);
MALLOC_DECLARE(DRM_MEM_CTXBITMAP);
MALLOC_DECLARE(DRM_MEM_SGLISTS);
MALLOC_DECLARE(DRM_MEM_DRAWABLE);
MALLOC_DECLARE(DRM_MEM_MM);
MALLOC_DECLARE(DRM_MEM_HASHTAB);

/*
 * Non-Linux from drmP.h
 */

#define EXPORT_SYMBOL(sym)

/* drm_mm.c function drm_mm_takedown() */
#define BUG_ON(cond)

/* Don't want to deal with seq_printf in
 * drm_mm.c function drm_mm_dump_table
 */
#ifdef CONFIG_DEBUG_FS
#undef CONFIG_DEBUG_FS
#endif

/* DRM_MEM_ERROR appears unused and so is drm_mem_stats */

#define KERN_DEBUG "KERN_DEBUG"
#define KERN_ERR   "KERN_ERR"
#define KERN_INFO  "KERN_INFO"

#define __GFP_COLD      0x4
#define __GFP_COMP      0x8
#define __GFP_DMA32     0x10
#define __GFP_HIGHMEM   0x20
#define __GFP_NORETRY   0x40
#define __GFP_NOWARN    0x80
#define __GFP_ZERO      0x100

#define PAGE_KERNEL     0x200
#define _PAGE_NO_CACHE  0x400

#define printk    printf
#define vprintk   kvprintf

#define printf	kprintf
#define snprintf ksnprintf
#define sscanf	ksscanf
#define malloc	kmalloc
#define realloc	krealloc
#define reallocf krealloc	/* XXX XXX XXX */

__inline static void
free(void *addr, struct malloc_type *type)
{
	if (addr != NULL)
		kfree(addr, type);
}

#define spinlock_t   struct lock
#define spin_lock(l)   lockmgr(l, LK_EXCLUSIVE | LK_RETRY | LK_CANRECURSE)
#define spin_unlock(u) lockmgr(u, LK_RELEASE)
#define spin_lock_init(l) lockinit(l, "spin_lock_init", 0, LK_CANRECURSE)

/* drm_drawable.c drm_addraw() and previous drmP.h */
#define spin_lock_irqsave(l, irqflags) \
        do {                           \
                spin_lock(l);          \
                (void)irqflags;        \
        } while (0)

#define spin_unlock_irqrestore(u, irqflags) spin_unlock(u)

/* DragonFly drmP.h */
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(x[0]))

/* drm_buf_t is already defined as struct drm_buf */

/* idr */

/* Brute force implementation of idr API
 * using current red-black tree backing
 *
 * Adapted from FreeBSD port of drm_drawable.c
 */

struct drm_rb_info {
	void *data;
	int handle;
	RB_ENTRY(drm_rb_info) tree;
};

int
drm_rb_compare(struct drm_rb_info *a, struct drm_rb_info *b);

RB_HEAD(drm_rb_tree, drm_rb_info);

RB_PROTOTYPE(drm_rb_tree, drm_rb_info, tree, drm_rb_compare);

struct idr {
	struct drm_rb_tree *tree;
};

void idr_init(struct idr *pidr);

void *idr_find(struct idr *pidr, int id);

/* Every mention of idr_pre_get has GPP_KERNEL */
int
idr_pre_get(struct idr *pidr, unsigned int flags);

int
idr_get_new_above(struct idr * pidr, void *data, int floor, int *id);

int
idr_get_new(struct idr *pidr, void *data, int *id);

void
idr_remove(struct idr *pidr, int id);

void
idr_remove_all(struct idr *pidr);

void
idr_for_each(struct idr *pidr,
	int (*func)(int id, void *ptr, void *data), void * data);

void *
idr_replace(struct idr *pidr, void *newData, int id);

void
idr_destroy(struct idr *pidr);

/* Called in drm_drawable.c, function drm_update_drawable_info().
 * Negative of error indicators sometimes assigned to (void *).
 * Tests return value from idr_replace().
 * Assume pointers are no more than 64-bit.
 */
#define IS_ERR(ptr) (((int64_t)ptr) < 0)

/* Referencing counting */

struct kref {
	int placeholder;
};

#endif /* __KERNEL__ */
#endif /* _DRM_PRIV_OTHER_H_ */
