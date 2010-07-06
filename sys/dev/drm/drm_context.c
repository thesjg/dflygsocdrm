/*-
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
 *
 * Authors:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/*
 * ChangeLog:
 *  2001-11-16	Torsten Duwe <duwe@caldera.de>
 *		added context constructor/destructor hooks,
 *		needed by SiS driver's memory management.
 */

/** @file drm_context.c
 * Implementation of the context management ioctls.
 */

#include "drmP.h"

/******************************************************************/
/** \name Context bitmap support */
/*@{*/

/**
 * Free a handle from the context bitmap.
 *
 * \param dev DRM device.
 * \param ctx_handle context handle.
 *
 * Clears the bit specified by \p ctx_handle in drm_device::ctx_bitmap and the entry
 * in drm_device::ctx_idr, while holding the drm_device::struct_mutex
 * lock.
 */
void drm_ctxbitmap_free(struct drm_device *dev, int ctx_handle)
{
	if (ctx_handle < 0 || ctx_handle >= DRM_MAX_CTXBITMAP || 
	    dev->ctx_bitmap == NULL) {
		DRM_ERROR("Attempt to free invalid context handle: %d\n",
		   ctx_handle);
		return;
	}

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif

	clear_bit(ctx_handle, dev->ctx_bitmap);
	dev->context_sareas[ctx_handle] = NULL;

#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
	return;
}

/**
 * Context bitmap allocation.
 *
 * \param dev DRM device.
 * \return (non-negative) context handle on success or a negative number on failure.
 *
 * Allocate a new idr from drm_device::ctx_idr while holding the
 * drm_device::struct_mutex lock.
 */
int drm_ctxbitmap_next(struct drm_device *dev)
{
	int bit;

	if (dev->ctx_bitmap == NULL)
		return -1;

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif

	bit = find_first_zero_bit(dev->ctx_bitmap, DRM_MAX_CTXBITMAP);
	if (bit >= DRM_MAX_CTXBITMAP) {
#ifdef DRM_NEWER_LOCK
		mutex_unlock(&dev->struct_mutex);
#else
		DRM_UNLOCK();
#endif
		return -1;
	}

	set_bit(bit, dev->ctx_bitmap);
	DRM_DEBUG("bit : %d\n", bit);
	if ((bit+1) > dev->max_context) {
		drm_local_map_t **ctx_sareas;
		int max_ctx = (bit+1);

#ifdef DRM_NEWER_LOCK
		ctx_sareas = realloc(dev->context_sareas,
		    max_ctx * sizeof(*dev->context_sareas),
		    DRM_MEM_SAREA, M_WAITOK);
#else
		ctx_sareas = realloc(dev->context_sareas,
		    max_ctx * sizeof(*dev->context_sareas),
		    DRM_MEM_SAREA, M_NOWAIT);
#endif

		if (ctx_sareas == NULL) {
			clear_bit(bit, dev->ctx_bitmap);
			DRM_DEBUG("failed to allocate bit : %d\n", bit);
#ifdef DRM_NEWER_LOCK
			mutex_unlock(&dev->struct_mutex);
#else
			DRM_UNLOCK();
#endif
			return -1;
		}
		dev->max_context = max_ctx;
		dev->context_sareas = ctx_sareas;
		dev->context_sareas[bit] = NULL;
	}
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
	return bit;
}

/**
 * Context bitmap initialization.
 *
 * \param dev DRM device.
 *
 * Initialise the drm_device::ctx_idr
 */
int drm_ctxbitmap_init(struct drm_device *dev)
{
	int i;
   	int temp;

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif

#ifdef DRM_NEWER_LOCK
	dev->ctx_bitmap = malloc(PAGE_SIZE, DRM_MEM_CTXBITMAP,
	    M_WAITOK | M_ZERO);
#else
	dev->ctx_bitmap = malloc(PAGE_SIZE, DRM_MEM_CTXBITMAP,
	    M_NOWAIT | M_ZERO);
#endif

	if (dev->ctx_bitmap == NULL) {
#ifdef DRM_NEWER_LOCK
		mutex_unlock(&dev->struct_mutex);
#else
		DRM_UNLOCK();
#endif
		return ENOMEM;
	}
	dev->context_sareas = NULL;
	dev->max_context = -1;

#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif

	for (i = 0; i < DRM_RESERVED_CONTEXTS; i++) {
		temp = drm_ctxbitmap_next(dev);
		DRM_DEBUG("drm_ctxbitmap_init : %d\n", temp);
	}

	return 0;
}

/**
 * Context bitmap cleanup.
 *
 * \param dev DRM device.
 *
 * Free all idr members using drm_ctx_sarea_free helper function
 * while holding the drm_device::struct_mutex lock.
 */
void drm_ctxbitmap_cleanup(struct drm_device *dev)
{
#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif
	if (dev->context_sareas != NULL)
		free(dev->context_sareas, DRM_MEM_SAREA);
	free(dev->ctx_bitmap, DRM_MEM_CTXBITMAP);
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
}

/******************************************************************/
/** \name Per Context SAREA Support */
/*@{*/

/**
 * Get per-context SAREA.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx_priv_map structure.
 * \return zero on success or a negative number on failure.
 *
 * Gets the map from drm_device::ctx_idr with the handle specified and
 * returns its handle.
 */
int drm_getsareactx(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct drm_ctx_priv_map *request = data;
	drm_local_map_t *map;
#ifdef __linux__
	struct drm_map_list *_entry;
#endif /* __linux__ */

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif
	if (dev->max_context < 0 ||
	    request->ctx_id >= (unsigned) dev->max_context) {
#ifdef DRM_NEWER_LOCK
		mutex_unlock(&dev->struct_mutex);
#else
		DRM_UNLOCK();
#endif
		return EINVAL;
	}

	map = dev->context_sareas[request->ctx_id];
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif

#ifdef __linux__
	request->handle = NULL;
	list_for_each_entry(_entry, &dev->maplist, head) {
		if (_entry->map == map) {
			request->handle =
			    (void *)(unsigned long)_entry->user_token;
			break;
		}
	}
	if (request->handle == NULL)
		return EINVAL;
#endif /* __linux__ */

	request->handle = map->handle;

	return 0;
}

/**
 * Set per-context SAREA.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx_priv_map structure.
 * \return zero on success or a negative number on failure.
 *
 * Searches the mapping specified in \p arg and update the entry in
 * drm_device::ctx_idr with it.
 */
int drm_setsareactx(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct drm_ctx_priv_map *request = data;
	drm_local_map_t *map = NULL;
#ifdef DRM_NEWER_MAPLIST
	struct drm_map_list *r_list = NULL;
#endif

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif

#ifdef DRM_NEWER_MAPLIST

	list_for_each_entry(r_list, &dev->maplist, head) {
		if (r_list->map
		    && (r_list->map->handle == request->handle)) {
			if (dev->max_context < 0)
				goto bad;
			if (request->ctx_id >= (unsigned) dev->max_context)
				goto bad;
			goto found;
		}
	}

#else /* DRM_NEWER_MAPLIST */

	TAILQ_FOREACH(map, &dev->maplist_legacy, link) {
		if (map->handle == request->handle) {
			if (dev->max_context < 0)
				goto bad;
			if (request->ctx_id >= (unsigned) dev->max_context)
				goto bad;
			dev->context_sareas[request->ctx_id] = map;
#ifdef DRM_NEWER_LOCK
			mutex_unlock(&dev->struct_mutex);
#else
			DRM_UNLOCK();
#endif
			return 0;
		}
	}

#endif /* DRM_NEWER_MAPLIST */

bad:
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
	return EINVAL;

#ifdef DRM_NEWER_MAPLIST

found:
	map = r_list->map;
	if (!map)
		goto bad;

	dev->context_sareas[request->ctx_id] = map;
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
	return 0;

#endif /* DRM_NEWER_MAPLIST */
}

/*@}*/

/******************************************************************/
/** \name The actual DRM context handling routines */
/*@{*/

/**
 * Switch context.
 *
 * \param dev DRM device.
 * \param old old context handle.
 * \param new new context handle.
 * \return zero on success or a negative number on failure.
 *
 * Attempt to set drm_device::context_flag.
 */
int drm_context_switch(struct drm_device *dev, int old, int new)
{
	if (test_and_set_bit(0, &dev->context_flag)) {
		DRM_ERROR("Reentering -- FIXME\n");
		return EBUSY;
	}

	DRM_DEBUG("Context switch from %d to %d\n", old, new);

	if (new == dev->last_context) {
		clear_bit(0, &dev->context_flag);
		return 0;
	}

	return 0;
}

/**
 * Complete context switch.
 *
 * \param dev DRM device.
 * \param new new context handle.
 * \return zero on success or a negative number on failure.
 *
 * Updates drm_device::last_context and drm_device::last_switch. Verifies the
 * hardware lock is held, clears the drm_device::context_flag and wakes up
 * drm_device::context_wait.
 */
#ifdef __linux__
static int drm_context_switch_complete(struct drm_device *dev,
				       struct drm_file *file_priv, int new)
#else
int drm_context_switch_complete(struct drm_device *dev, int new)
#endif /* __linux__ */
{
	dev->last_context = new;  /* PRE/POST: This is the _only_ writer. */

#ifdef __linux__ /* no code seems to use dev->last_switch */
	dev->last_switch = jiffies;

	if (!_DRM_LOCK_IS_HELD(file_priv->master->lock.hw_lock->lock)) {
		DRM_ERROR("Lock isn't held after context switch\n");
	}
#else
	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock)) {
		DRM_ERROR("Lock isn't held after context switch\n");
	}
#endif /* __linux__ */

	/* If a context switch is ever initiated
	   when the kernel holds the lock, release
	   that lock here. */
	clear_bit(0, &dev->context_flag);
#ifdef __linux__ /* no code seems to put any processes on wait queue */
	wake_up(&dev->context_wait);
#endif

	return 0;
}

/**
 * Reserve contexts.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx_res structure.
 * \return zero on success or a negative number on failure.
 */
int drm_resctx(struct drm_device *dev, void *data,
	struct drm_file *file_priv)
{
	struct drm_ctx_res *res = data;
	struct drm_ctx ctx;
	int i;

	if (res->count >= DRM_RESERVED_CONTEXTS) {
		bzero(&ctx, sizeof(ctx));
		for (i = 0; i < DRM_RESERVED_CONTEXTS; i++) {
			ctx.handle = i;
			if (DRM_COPY_TO_USER(&res->contexts[i], &ctx, sizeof(ctx)))
				return EFAULT;
		}
	}
	res->count = DRM_RESERVED_CONTEXTS;

	return 0;
}

/**
 * Add context.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx structure.
 * \return zero on success or a negative number on failure.
 *
 * Get a new handle for the context and copy to userspace.
 */
int drm_addctx(struct drm_device *dev, void *data,
		struct drm_file *file_priv)
{
	struct drm_ctx *ctx = data;

	ctx->handle = drm_ctxbitmap_next(dev);
	if (ctx->handle == DRM_KERNEL_CONTEXT) {
		/* Skip kernel's context and get a new one. */
		ctx->handle = drm_ctxbitmap_next(dev);
	}
	DRM_DEBUG("%d\n", ctx->handle);
	if (ctx->handle == -1) {
		DRM_DEBUG("Not enough free contexts.\n");
		/* Should this return -EBUSY instead? */
		return ENOMEM;
	}

	if (dev->driver->context_ctor && ctx->handle != DRM_KERNEL_CONTEXT) {
#ifndef DRM_NEWER_LOCK
		DRM_LOCK();
#endif
		dev->driver->context_ctor(dev, ctx->handle);
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif
	}

#ifdef __linux__
	ctx_entry = malloc(sizeof(*ctx_entry), DRM_MEM_CTXBITMAP, M_WAITOK);
	if (!ctx_entry) {
		DRM_DEBUG("out of memory\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ctx_entry->head);
	ctx_entry->handle = ctx->handle;
	ctx_entry->tag = file_priv;

	mutex_lock(&dev->ctxlist_mutex);
	list_add(&ctx_entry->head, &dev->ctxlist);
	++dev->ctx_count;
	mutex_unlock(&dev->ctxlist_mutex);
#endif /* __linux__ */

	return 0;
}

int drm_modctx(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	/* This does nothing */
	return 0;
}

/**
 * Get context.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx structure.
 * \return zero on success or a negative number on failure.
 */
int drm_getctx(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_ctx *ctx = data;

	/* This is 0, because we don't handle any context flags */
	ctx->flags = 0;

	return 0;
}

/**
 * Switch context.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx structure.
 * \return zero on success or a negative number on failure.
 *
 * Calls context_switch().
 */
int drm_switchctx(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	struct drm_ctx *ctx = data;

	DRM_DEBUG("%d\n", ctx->handle);
	return drm_context_switch(dev, dev->last_context, ctx->handle);
}

/**
 * New context.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx structure.
 * \return zero on success or a negative number on failure.
 *
 * Calls context_switch_complete().
 */
int drm_newctx(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_ctx *ctx = data;

	DRM_DEBUG("%d\n", ctx->handle);
#ifdef __linux__
	drm_context_switch_complete(dev, file_priv, ctx->handle);
#else
	drm_context_switch_complete(dev, ctx->handle);
#endif /* __linux__ */

	return 0;
}

/**
 * Remove context.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument pointing to a drm_ctx structure.
 * \return zero on success or a negative number on failure.
 *
 * If not the special kernel context, calls ctxbitmap_free() to free the specified context.
 */
int drm_rmctx(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_ctx *ctx = data;

	DRM_DEBUG("%d\n", ctx->handle);
	if (ctx->handle != DRM_KERNEL_CONTEXT) {
		if (dev->driver->context_dtor) {
#ifndef DRM_NEWER_LOCK
			DRM_LOCK();
#endif
			dev->driver->context_dtor(dev, ctx->handle);
#ifndef DRM_NEWER_LOCK
			DRM_UNLOCK();
#endif
		}

		drm_ctxbitmap_free(dev, ctx->handle);
	}

#ifdef __linux__
	mutex_lock(&dev->ctxlist_mutex);
	if (!list_empty(&dev->ctxlist)) {
		struct drm_ctx_list *pos, *n;

		list_for_each_entry_safe(pos, n, &dev->ctxlist, head) {
			if (pos->handle == ctx->handle) {
				list_del(&pos->head);
				free(pos, DRM_MEM_CTXBITMAP);
				--dev->ctx_count;
			}
		}
	}
	mutex_unlock(&dev->ctxlist_mutex);
#endif /* __linux__ */

	return 0;
}
