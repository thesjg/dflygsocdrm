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

#include "dev/drm/drm_porting_layer.h"

#include <sys/tree.h>

/**********************************************************
 * GLOBAL VARIABLES                                       *
 **********************************************************/
int sysctl_vfs_cache_pressure = 0;

struct atomic_notifier_head panic_notifier_list;

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

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

/**********************************************************
 * FRAMEBUFFER                                            *
 **********************************************************/

const char *fb_mode_option = DEFAULT_FB_MODE_OPTION;
