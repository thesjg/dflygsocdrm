/* drm_porting_layer.c -- Implementation Direct Rendering Manager other OS -*- linux-c -*-
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

/* For drm_pci_rom_map and drm_pci_rom_unmap to access pci extension bios */
/*	$OpenBSD: sti_pci.c,v 1.7 2009/02/06 22:51:04 miod Exp $	*/

/*
 * Copyright (c) 2006, 2007 Miodrag Vallat.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice, this permission notice, and the disclaimer below
 * appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "dev/drm/drm_porting_layer.h"

#include <sys/tree.h>

/********************************************************************
 * TIME                                                             *
 ********************************************************************/

/* Pointer to local variable for tsleep ident
 * is done in sys/dev/disk/ahci/ahci_dragonfly.c
 */
int
schedule_timeout(signed long timo) {
	int tosleep = (int)timo;
	int result = EINVAL;
	if (curproc != NULL) {
		result = tsleep(&tosleep, PCATCH, "schtim", tosleep);
		if (result == EWOULDBLOCK) {
			return 0;
		}
	}
	return result;
}

int
schedule_timeout_uninterruptible(signed long timo) {
	int tosleep = (int)timo;
	int result = EINVAL;
	if (curproc != NULL) {
		result = tsleep(&tosleep, 0, "schtiu", tosleep);
		if (result == EWOULDBLOCK) {
			return 0;
		}
	}
	return result;
}

void
msleep(unsigned int millis) {
	int tosleep = (int)msecs_to_jiffies(millis);
	tsleep(&tosleep, 0, "msleep", tosleep);
}

void
msleep_interruptible(unsigned int millis) {
	int tosleep = (int)msecs_to_jiffies(millis);
	tsleep(&tosleep, PCATCH, "msleep", tosleep);
}

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

/**********************************************************
 * RED-BLACK TREES                                        *
 **********************************************************/

/*
 * Assume that x has non-null child y.
 */
static void
rb_left_rotate(struct rb_node *x, struct rb_root *root) {
	struct rb_node *y = x->rb_right;
	x->rb_right = y->rb_left;
	if (y->rb_left) {
		y->rb_left->rb_parent = x;
	}
	y->rb_parent = x->rb_parent;
	if (x->rb_parent == NULL) {
		root->rb_node = y;	
	}
	else {
		if (x == x->rb_parent->rb_left) {
			x->rb_parent->rb_left = y;
		}
		else {
			x->rb_parent->rb_right = y;
		}
	}
	y->rb_left = x;
	x->rb_parent = y;
}

/*
 * Assume that y has non-null left child x.
 */
static void
rb_right_rotate(struct rb_node *y, struct rb_root *root) {
	struct rb_node *x = y->rb_left;
	y->rb_left = x->rb_right;
	if (x->rb_right) {
		x->rb_right->rb_parent = y;
	}
	x->rb_parent = y->rb_parent;
	if (y->rb_parent == NULL) {
		root->rb_node = x;	
	}
	else {
		if (y == y->rb_parent->rb_right) {
			y->rb_parent->rb_right = x;
		}
		else {
			y->rb_parent->rb_left = x;
		}
	}
	x->rb_right = y;
	y->rb_parent = x;
}

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
void
rb_link_node(struct rb_node *x, struct rb_node *parent, struct rb_node **cur) {
	if (cur == &(parent->rb_left)) {
		parent->rb_left = x;
	}
	else {
		parent->rb_right = x;
	}
	x->rb_parent = parent;
	x->color = 0; /* color red */
}

void
rb_insert_color(struct rb_node *z, struct rb_root *root) {
	struct rb_node *y;
	if (z == root->rb_node)
		goto finished;
	while (z->rb_parent->color == 0) {
		if (z->rb_parent == z->rb_parent->rb_parent->rb_left) {
			y = z->rb_parent->rb_parent->rb_right;
			if (y->color == 0) {
				z->rb_parent->color = 1;
				y->color = 1;
				z->rb_parent->rb_parent->color = 0;
				z = z->rb_parent->rb_parent;
			}
			else {
				if (z == z->rb_parent->rb_right) {
					z = z->rb_parent;
					rb_left_rotate(z, root);
				}
				z->rb_parent->color = 1;
				z->rb_parent->rb_parent->color = 0;
				rb_right_rotate(z->rb_parent->rb_parent, root);
			}
		}
		else {
			y = z->rb_parent->rb_parent->rb_left;
			if (y->color == 0) {
				z->rb_parent->color = 1;
				y->color = 1;
				z->rb_parent->rb_parent->color = 0;
				z = z->rb_parent->rb_parent;
			}
			else {
				if (z == z->rb_parent->rb_left) {
					z = z->rb_parent;
					rb_right_rotate(z, root);
				}
				z->rb_parent->color = 1;
				z->rb_parent->rb_parent->color = 0;
				rb_left_rotate(z->rb_parent->rb_parent, root);
			}
		}
	}
finished:
	root->rb_node->color = 1;
}

static struct rb_node *rb_minimum(struct rb_node *x) {
	while (x->rb_left != NULL) {
		x = x->rb_left;
	}
	return x;
}

static struct rb_node *rb_next(struct rb_node *x) {
	struct rb_node *y;
	if (x->rb_right != NULL) {
		return rb_minimum(x->rb_right);
	}
	y = x->rb_parent;
	while ((y != NULL) && (x == y->rb_right)) {
		x = y;
		y = y->rb_parent;
	}
	return y;
}

/* Required: x != NULL */
static void rb_erase_fixup(struct rb_node *x, struct rb_root *root) {
	struct rb_node *w;
	while ((x != root->rb_node) && (x->color == 0)) {
		if (x == x->rb_parent->rb_left) {
			w = x->rb_parent->rb_right;
			if ((w != NULL) && (w->color == 0)) {
				w->color = 1;
				x->rb_parent->color = 0;
				rb_left_rotate(x->rb_parent, root);
				w = x->rb_parent->rb_right;
			}
			if (((w->rb_left == NULL) || (w->rb_left->color == 1))
			&& ((w->rb_right == NULL) || (w->rb_right->color == 1))) {
				w->color = 0;
				x = x->rb_parent;
			}
			else {
				if ((w->rb_right == NULL) || (w->rb_right->color == 1)) {
					w->rb_left->color = 1;
					w->color = 0;
					rb_right_rotate(w, root);
					w = x->rb_parent->rb_right;
				}
				w->color = x->rb_parent->color;
				x->rb_parent->color = 1;
				w->rb_right->color = 1;
				rb_left_rotate(x->rb_parent, root);
				x = root->rb_node;
			}
		}
		else { /* x == x->rb_parent->rb_right */
			w = x->rb_parent->rb_left;
			if ((w != NULL) && (w->color == 0)) {
				w->color = 1;
				x->rb_parent->color = 0;
				rb_right_rotate(x->rb_parent, root);
				w = x->rb_parent->rb_left;
			}
			if (((w->rb_right == NULL) || (w->rb_right->color == 1))
			&& ((w->rb_left == NULL) || (w->rb_left->color == 1))) {
				w->color = 0;
				x = x->rb_parent;
			}
			else {
				if ((w->rb_left == NULL) || (w->rb_left->color == 1)) {
					w->rb_right->color = 1;
					w->color = 0;
					rb_left_rotate(w, root);
					w = x->rb_parent->rb_left;
				}
				w->color = x->rb_parent->color;
				x->rb_parent->color = 1;
				w->rb_left->color = 1;
				rb_right_rotate(x->rb_parent, root);
				x = root->rb_node;
			}

		}	
	}
	x->color = 1;
}

void
rb_erase(struct rb_node *z, struct rb_root *root) {
	struct rb_node *y;
	struct rb_node *x;
	int old_y_color;
	if ((z->rb_left == NULL) || (z->rb_right == NULL)) {
		y = z;
	}
	else {
		y = rb_next(z);
	}
	if (y->rb_left != NULL) {
		x = y->rb_left;
	}
	else {
		x = y->rb_right;
	}
	if (x != NULL) {
		x->rb_parent = y->rb_parent;
	}
	if (y->rb_parent == NULL) {
		root->rb_node = x;
	}
	else {
		if (y == y->rb_parent->rb_left) {
			y->rb_parent->rb_left = x;
		}
		else {
			y->rb_parent->rb_right = x;
		}
	}
	old_y_color = y->color;
	if (y != z) {
		y->rb_left = z->rb_left;
		y->rb_right = z->rb_left;
		y->rb_parent = z->rb_parent;
		y->color = z->color;
		if (z->rb_parent != NULL) {
			if (z == z->rb_parent->rb_left) {
				z->rb_parent->rb_left = y;
			}
			else {
				z->rb_parent->rb_right = y;
			}
		}
	}
	if  ((old_y_color == 1) && (x != NULL)) {
		rb_erase_fixup(x, root);
	}
}


/**********************************************************
 * idr                                                    *
 **********************************************************/

/* Brute force implementation of idr API
 * using current red-black tree backing
 *
 * Adapted from FreeBSD port of drm_drawable.c
 */

int
drm_rb_compare(struct drm_rb_info *a, struct drm_rb_info *b)
{
	if (a->handle > b->handle)
		return 1;
	if (a->handle < b->handle)
		return -1;
	return 0;
}

RB_GENERATE(drm_rb_tree, drm_rb_info, tree, drm_rb_compare);

void
idr_init(struct idr *pidr) {
	RB_INIT(&pidr->tree);
	spin_lock_init(&pidr->idr_lock);
	pidr->filled_below = 0;
}

void *
idr_find(struct idr *pidr, int id) {
	struct drm_rb_info find;
        struct drm_rb_info *result;

	find.handle = id;
        result = RB_FIND(drm_rb_tree, &pidr->tree, &find);
	if (result == NULL) {
		return (NULL);
	}
	return result->data;
}

int
idr_pre_get(struct idr *pidr, unsigned int flags) {
	struct drm_rb_info *allocate;
	int already = 0;
	allocate = malloc(sizeof(struct drm_rb_info), DRM_MEM_IDR, M_WAITOK);
	if (allocate == NULL) {
		return 0;
	}
	spin_lock(&pidr->idr_lock);
	if (pidr->available != NULL) {
		already = 1;
	}
	else {
		pidr->available = allocate;
	}
	spin_unlock(&pidr->idr_lock);
	if (already) {
		free(allocate, DRM_MEM_IDR);
	}
	return 1;
}

/* Brute force implementation */
int
idr_get_new_above(struct idr *pidr, void *data, int floor, int *id) {
	struct drm_rb_info find;
	struct drm_rb_info *sofar;
	struct drm_rb_info *info;
	int candidate = floor;
	if (candidate < pidr->filled_below) {
		candidate = pidr->filled_below;
	}
	find.handle = candidate;
	sofar = RB_FIND(drm_rb_tree, &pidr->tree, &find);
        while ((sofar != NULL) && (candidate == sofar->handle)) {
		candidate = sofar->handle + 1;
		sofar = RB_NEXT(drm_rb_tree, &pidr->tree, sofar);
        }
	spin_lock(&pidr->idr_lock);
	info = pidr->available;
	if (info == NULL) {
		spin_unlock(&pidr->idr_lock);
		return -EAGAIN;
	}
	pidr->available = NULL;
	spin_unlock(&pidr->idr_lock);
	info->handle = candidate;
	info->data = data;
	RB_INSERT(drm_rb_tree, &pidr->tree, info);
	*id = info->handle;
	if (floor <= pidr->filled_below) {
		pidr->filled_below = info->handle + 1;
	}
	return 0;
}

int
idr_get_new(struct idr *pidr, void *data, int *id) {
	return idr_get_new_above(pidr, data, 0, id);
}

/* drm.gem.c drm_gem_handle_delete()
 * call idr_find() first to deal with data
 * then call idr_remove() to change actual data structure.
 * In particular, do not free data.
 */
void
idr_remove(struct idr *pidr, int id) {
	struct drm_rb_info find;
	struct drm_rb_info *info;
	find.handle = id;
	info = RB_FIND(drm_rb_tree, &pidr->tree, &find);
	if (info != NULL) {
		RB_REMOVE(drm_rb_tree, &pidr->tree, info);
		free(info, DRM_MEM_IDR);
        }
	if (id < pidr->filled_below) {
		pidr->filled_below = id;
	}
}

void
idr_remove_all(struct idr *pidr) {
	struct drm_rb_info *var;
        struct drm_rb_info *nxt;
	for (var = RB_MIN(drm_rb_tree, &pidr->tree); var != NULL; var = nxt) {
		nxt = RB_NEXT(drm_rb_tree, &pidr->tree, var);
		RB_REMOVE(drm_rb_tree, &pidr->tree, var);
		free(var, DRM_MEM_IDR);
	}
	var = NULL;
	spin_lock(&pidr->idr_lock);
	var = pidr->available;
	pidr->available = NULL;
	spin_unlock(&pidr->idr_lock);
	if (var != NULL) {
		free(var, DRM_MEM_IDR);
	}
	pidr->filled_below = 0;
}

/* from drm_info.c function drm_gem_name_info */
void
idr_for_each(struct idr *pidr, int (*func)(int id, void *ptr, void *data), void *data) {
	struct drm_rb_info *var;
        struct drm_rb_info *nxt;
	for (var = RB_MIN(drm_rb_tree, &pidr->tree); var != NULL; var = nxt) {
		nxt = RB_NEXT(drm_rb_tree, &pidr->tree, var);
		(*func)(var->handle, var->data, data);
	}
}

void *
idr_replace(struct idr *pidr, void *newData, int id) {
	struct drm_rb_info find;
        struct drm_rb_info *result;
	void *oldData;

	find.handle = id;
        result = RB_FIND(drm_rb_tree, &pidr->tree, &find);
	if (result == NULL) {
		return (void *)(-ENOENT);
	}
	oldData = result->data;
	result->data = newData;
	return oldData;
}

/* Using API from drm_gem.c function drm_gem_release() */
void
idr_destroy(struct idr *pidr) {
	struct drm_rb_info *var = NULL;
	spin_lock(&pidr->idr_lock);
	var = pidr->available;
	pidr->available = NULL;
	spin_unlock(&pidr->idr_lock);
	if (var != NULL) {
		free(var, DRM_MEM_IDR);
	}
}

/**********************************************************
 * ida                                                    *
 **********************************************************/

/* Brute force implementation of ida API
 * using current red-black tree backing
 *
 * Adapted from FreeBSD port of drm_drawable.c
 */

int
drm_ida_compare(struct drm_ida_info *a, struct drm_ida_info *b) {
	if (a->handle > b->handle)
		return 1;
	if (a->handle < b->handle)
		return -1;
	return 0;
}

RB_GENERATE(drm_ida_tree, drm_ida_info, tree, drm_ida_compare);

void
ida_init(struct ida *pida) {
	RB_INIT(&pida->tree);
	spin_lock_init(&pida->ida_lock);
	pida->filled_below = 0;
}

int
ida_pre_get(struct ida *pida, unsigned int flags) {
	struct drm_ida_info *allocate;
	int already = 0;
	allocate = malloc(sizeof(struct drm_ida_info), DRM_MEM_IDR, M_WAITOK);
	if (allocate == NULL) {
		return 0;
	}
	spin_lock(&pida->ida_lock);
	if (pida->available != NULL) {
		already = 1;
	}
	else {
		pida->available = allocate;
	}
	spin_unlock(&pida->ida_lock);
	if (already) {
		free(allocate, DRM_MEM_IDR);
	}
	return 1;
}

/* Brute force implementation */
int
ida_get_new_above(struct ida *pida, int floor, int *id) {
	struct drm_ida_info find;
	struct drm_ida_info *sofar;
	struct drm_ida_info *info;
	int candidate = floor;
	if (candidate < pida->filled_below) {
		candidate = pida->filled_below;
	}
	find.handle = candidate;
	sofar = RB_FIND(drm_ida_tree, &pida->tree, &find);
        while ((sofar != NULL) && (candidate == sofar->handle)) {
		candidate = sofar->handle + 1;
		sofar = RB_NEXT(drm_ida_tree, &pida->tree, sofar);
        }
	spin_lock(&pida->ida_lock);
	info = pida->available;
	if (info == NULL) {
		spin_unlock(&pida->ida_lock);
		return -EAGAIN;
	}
	pida->available = NULL;
	spin_unlock(&pida->ida_lock);
	info->handle = candidate;
	RB_INSERT(drm_ida_tree, &pida->tree, info);
	*id = info->handle;
	if (floor <= pida->filled_below) {
		pida->filled_below = info->handle + 1;
	}
	return 0;
}

int
ida_get_new(struct ida *pida, int *id) {
	return ida_get_new_above(pida, 0, id);
}

void
ida_remove(struct ida *pida, int id) {
	struct drm_ida_info find;
	struct drm_ida_info *info;
	find.handle = id;
	info = RB_FIND(drm_ida_tree, &pida->tree, &find);
	if (info != NULL) {
		RB_REMOVE(drm_ida_tree, &pida->tree, info);
		free(info, DRM_MEM_IDR);
        }
	if (id < pida->filled_below) {
		pida->filled_below = id;
	}
}

void
ida_destroy(struct ida *pida) {
	struct drm_ida_info *var = NULL;
	spin_lock(&pida->ida_lock);
	var = pida->available;
	pida->available = NULL;
	spin_unlock(&pida->ida_lock);
	if (var != NULL) {
		free(var, DRM_MEM_IDR);
	}
}

/********************************************************************
 * MEMORY MAPPED IO                                                 *
 ********************************************************************/

void *
ioremap(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

void *
ioremap_wc(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

void *
ioremap_nocache(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

void drm_iounmap(void *handle, unsigned long size)
{
	pmap_unmapdev((vm_offset_t)handle, size);
}

/********************************************************************
 * PCI                                                              *
 ********************************************************************/

struct resource *
drm_pci_map_rom(device_t ddev, size_t *psize)
{
	uint32_t addr;
	uint32_t mask;
	uint32_t romsize = 1;
	uint32_t rstart;
	uint32_t rend;
	struct resource *res;
	int rid = PCIR_BIOS;

	rstart = pci_read_config(ddev, PCIR_BIOS, 4);
	pci_write_config(ddev, PCIR_BIOS, ~PCIM_BIOS_ENABLE, 4);
	mask = pci_read_config(ddev, PCIR_BIOS, 4);
	addr = rstart | PCIM_BIOS_ENABLE;
	pci_write_config(ddev, PCIR_BIOS, addr, 4);
	while ((romsize & mask) == 0) {
		romsize >>= 1;
	}
	rend = rstart + romsize;
	res = bus_alloc_resource(ddev, SYS_RES_MEMORY, &rid, rstart, rend, 1, RF_ACTIVE);
	*psize = romsize;
	return res;
}

void
drm_pci_unmap_rom(device_t ddev, struct resource *res)
{
	bus_release_resource(ddev, SYS_RES_MEMORY, PCIR_BIOS, res);
}

/**********************************************************
 * KREF and KOBJECT                                       *
 **********************************************************/

void default_kref_release(struct kref *kref) {
	;
}

/**********************************************************
 * WORKQUEUE                                              *
 **********************************************************/

void convert_work(void *context, int pending) {
	struct work_struct *work = (struct work_struct *)context;
	(work->work_fn)(work);
}

void call_delayed(void *arg) {
	struct delayed_work *work = (struct delayed_work *)arg;
	taskqueue_enqueue(work->tq, &work->work.task);
}

/**********************************************************
 * GLOBAL VARIABLES                                       *
 **********************************************************/

int sysctl_vfs_cache_pressure = 0;

struct atomic_notifier_head panic_notifier_list;

/**********************************************************
 * FRAMEBUFFER                                            *
 **********************************************************/

const char *fb_mode_option = DEFAULT_FB_MODE_OPTION;
