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

#include "dev/drm/porting/drm_porting_layer.h"

#include <sys/tree.h>

MALLOC_DECLARE(DRM_MEM_DEFAULT);

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

/*
 * idr
 */

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
	pidr->tree = malloc(sizeof(struct drm_rb_tree),
		DRM_MEM_DEFAULT, M_NOWAIT | M_ZERO);
	RB_INIT(pidr->tree);
}

void *
idr_find(struct idr *pidr, int id) {
	struct drm_rb_info find;
        struct drm_rb_info *result;

	find.handle = id;
        result = RB_FIND(drm_rb_tree, pidr->tree, &find);
	if (result == NULL) {
		return (NULL);
	}
	return result->data;
}

/* Using red-black tree hopefully never run out of memory */
int
idr_pre_get(struct idr *pidr, unsigned int flags) {
	return 1;
}

/* Brute force implementation */
int
idr_get_new_above(struct idr *pidr, void *data, int floor, int *id) {
	struct drm_rb_info find;
	struct drm_rb_info *sofar;
	struct drm_rb_info *info;
	int try = floor + 1;
	find.handle = try;
	sofar = RB_FIND(drm_rb_tree, pidr->tree, &find);
        while ((sofar != NULL) && (try == sofar->handle)) {
		try = sofar->handle + 1;
		sofar = RB_NEXT(drm_rb_tree, pidr->tree, sofar);
        }
	info = malloc(sizeof(struct drm_rb_info),
		DRM_MEM_DEFAULT, M_NOWAIT | M_ZERO);
	if (info == NULL) {
		return -EAGAIN;
	}
	info->handle = try;
	info->data = data;
	RB_INSERT(drm_rb_tree, pidr->tree, info);
	*id = try;
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
	info = RB_FIND(drm_rb_tree, pidr->tree, &find);
	if (info != NULL) {
		RB_REMOVE(drm_rb_tree, pidr->tree, info);
		free(info, DRM_MEM_DEFAULT);
        }
}

void
idr_remove_all(struct idr *pidr) {
	struct drm_rb_info *var;
        struct drm_rb_info *nxt;
	for (var = RB_MIN(drm_rb_tree, pidr->tree); var != NULL; var = nxt) {
		nxt = RB_NEXT(drm_rb_tree, pidr->tree, var);
		RB_REMOVE(drm_rb_tree, pidr->tree, var);
		free(var, DRM_MEM_DEFAULT);
	}
}

/* from drm_info.c function drm_gem_name_info */
void
idr_for_each(struct idr *pidr, int (*func)(int id, void *ptr, void *data), void * data) {
	struct drm_rb_info *var;
        struct drm_rb_info *nxt;
	for (var = RB_MIN(drm_rb_tree, pidr->tree); var != NULL; var = nxt) {
		nxt = RB_NEXT(drm_rb_tree, pidr->tree, var);
		(*func)(var->handle, var->data, data);
	}
}

void *
idr_replace(struct idr *pidr, void *newData, int id) {
	struct drm_rb_info find;
        struct drm_rb_info *result;
	void *oldData;

	find.handle = id;
        result = RB_FIND(drm_rb_tree, pidr->tree, &find);
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
   free(pidr, DRM_MEM_DEFAULT);
}

/**********************************************************
 * PROCESSES AND THREADS                                  *
 **********************************************************/

/*
 * Tasks
 */

/* file ttm_memory.c, function ttm_mem_global_init() */
/* UNIMPLEMENTED */
struct workqueue *
create_singlethread_workqueue(char *name) {
	return (struct workqueue *)NULL;
}

/* file ttm_memory.c, function ttm_check_swapping() */
/* UNIMPLEMENTED */
void
queue_work(struct workqueue * wq, struct work *work) {
	;
}

/* file ttm_memory.c, function ttm_mem_global_release() */
/* UNIMPLEMENTED */
void
flush_workqueue(struct workqueue *wq) {
	;
}

/* UNIMPLEMENTED */
void
destroy_workqueue(struct workqueue *wq) {
	;
}

/* file ttm_bo_c, function ttm_vm_fault() */
/* UNIMPLEMENTED */
void
set_need_resched(void) {
	;
}

/* file ttm_bo_c, function ttm_bo_lock_delayed_workqueue() */
/* UNIMPLEMENTED */
void
cancel_delayed_work_sync(struct delayed_work *wq) {
	;
}

/* file ttm_bo_c, function ttm_bo_device_release() */
/* UNIMPLEMENTED */
void
cancel_delayed_work(struct delayed_work *wq) {
	;
}

/* file ttm_bo_c, function ttm_bo_device_release() */
/* UNIMPLEMENTED */
void
flush_scheduled_work(void) {
	;
}

/**********************************************************
 * VIRTUAL MEMORY                                         *
 **********************************************************/

/*
 * pages
 */

/* file ttm/ttm_page_alloc.c, function ttm_handle_caching_state() */
/* UNIMPLEMENTED */
void
__free_page(struct page *page) {
	;
}

/* file ttm/ttm_page_alloc.c, function ttm_alloc_new_pages() */
/* UNIMPLEMENTED */
struct page *
alloc_page(int gfp_flags) {
	return (struct page *)NULL;
}

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
/* UNIMPLEMENTED */
unsigned long
page_address(struct page *page) {
	return 0;
}

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
/* UNIMPLEMENTED */
void
clear_page(unsigned long handle) {
	;
}

/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
/* UNIMPLEMENTED */
bool
PageHighMem(struct page *page) {
	return (bool)1;
}

/* file ttm/ttm_tt.c, function ttm_tt_free_user_pages() */
/* UNIMPLEMENTED */
bool
PageReserved(struct page *page) {
	return (bool)1;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
void
set_page_dirty(struct page *to_page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
void
mark_page_accessed(struct page *to_page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
void
page_cache_release(struct page *to_page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_free_user_pages() */
void
set_page_dirty_lock(struct page *page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_page_caching() */
int
set_pages_wb(struct page *p, uint32_t val) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_page_caching() */
int
set_memory_wc(unsigned long page_address, uint32_t val) {
	return 0;
}

/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
bool
page_to_pfn(struct page *page) {
	return (bool)1;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapin() */
/* Fourth argument NULL all calls in drm */
struct page *
read_mapping_page(struct address_space *swap_space, int i, void *ptr) {
	return (struct page *)NULL;
}
