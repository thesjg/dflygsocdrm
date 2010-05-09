/* drm_priv_other.c -- Implementation Direct Rendering Manager other OS -*- linux-c -*-
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/sysctl.h>
#include <sys/bus.h>
#include <sys/signalvar.h>
#include <sys/poll.h>
#include <sys/tree.h>
#include <sys/taskqueue.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <machine/param.h>
#include <machine/pmap.h>
#include <sys/bus.h>
#include <sys/resource.h>
#include <machine/specialreg.h>
#include <machine/sysarch.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/rman.h>
#include <sys/memrange.h>
#include <dev/agp/agpvar.h>
#include <sys/device.h>
#include <sys/agpio.h>
#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include <sys/selinfo.h>
#include <sys/bus.h>

#include "dev/drm/drm_priv_other.h"

#include <sys/tree.h>

MALLOC_DECLARE(DRM_MEM_DEFAULT);

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

static int
drm_rb_compare(struct drm_rb_info *a,
    struct drm_rb_info *b)
{
	if (a->handle > b->handle)
		return 1;
	if (a->handle < b->handle)
		return -1;
	return 0;
}

RB_HEAD(drm_rb_tree, drm_rb_info);

RB_PROTOTYPE_STATIC(drm_rb_tree, drm_rb_info, tree, drm_rb_compare);
RB_GENERATE_STATIC(drm_rb_tree, drm_rb_info, tree, drm_rb_compare);

struct idr {
	struct drm_rb_tree *tree;
};

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
