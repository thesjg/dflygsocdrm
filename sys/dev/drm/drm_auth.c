/**
 * \file drm_auth.c
 * IOCTLs for authentication
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Tue Feb  2 08:37:54 1999 by faith@valinux.com
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
 *
 * Authors:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/** @file drm_auth.c
 * Implementation of the get/authmagic ioctls implementing the authentication
 * scheme between the master and clients.
 */

#include "drmP.h"

static int drm_hash_magic(drm_magic_t magic)
{
	return magic & (DRM_HASH_SIZE-1);
}

/**
 * Find the file with the given magic number.
 *
 * \param dev DRM device.
 * \param magic magic number.
 *
 * Searches in drm_device::magiclist within all files with the same hash key
 * the one with matching magic number, while holding the drm_device::struct_mutex
 * lock.
 */
static struct drm_file *drm_find_file(struct drm_device *dev, drm_magic_t magic)
{
	struct drm_magic_entry *pt;
	int hash = drm_hash_magic(magic);

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
#endif

	for (pt = dev->magiclist[hash].head; pt; pt = pt->next) {
		if (pt->magic == magic) {
#ifdef DRM_NEWER_LOCK
			mutex_unlock(&dev->struct_mutex);
#endif
			return pt->priv;
		}
	}

#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#endif
	return NULL;
}

/**
 * Adds a magic number.
 *
 * \param dev DRM device.
 * \param priv file private data.
 * \param magic magic number.
 *
 * Creates a drm_magic_entry structure and appends to the linked list
 * associated the magic number hash key in drm_device::magiclist, while holding
 * the drm_device::struct_mutex lock.
 */
static int drm_add_magic(struct drm_device *dev, struct drm_file *priv,
			 drm_magic_t magic)
{
	int		  hash;
	struct drm_magic_entry *entry;

	DRM_DEBUG("%d\n", magic);

#ifndef DRM_NEWER_LOCK
	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
#endif

	hash = drm_hash_magic(magic);
#ifdef DRM_NEWER_LOCK
	entry = malloc(sizeof(*entry), DRM_MEM_MAGIC, M_ZERO | M_WAITOK);
#else
	entry = malloc(sizeof(*entry), DRM_MEM_MAGIC, M_ZERO | M_NOWAIT);
#endif
	if (!entry)
		return ENOMEM;
	entry->magic = magic;
	entry->priv  = priv;
	entry->next  = NULL;

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#endif
	if (dev->magiclist[hash].tail) {
		dev->magiclist[hash].tail->next = entry;
		dev->magiclist[hash].tail	= entry;
	} else {
		dev->magiclist[hash].head	= entry;
		dev->magiclist[hash].tail	= entry;
	}
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#endif

	return 0;
}

/**
 * Removes the given magic number from the hash table of used magic number
 * lists.
 */
static int drm_remove_magic(struct drm_device *dev, drm_magic_t magic)
{
	struct drm_magic_entry *prev = NULL;
	struct drm_magic_entry *pt;
	int		  hash;

#ifndef DRM_NEWER_LOCK
	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
#endif

	DRM_DEBUG("%d\n", magic);
	hash = drm_hash_magic(magic);

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#endif
	for (pt = dev->magiclist[hash].head; pt; prev = pt, pt = pt->next) {
		if (pt->magic == magic) {
			if (dev->magiclist[hash].head == pt) {
				dev->magiclist[hash].head = pt->next;
			}
			if (dev->magiclist[hash].tail == pt) {
				dev->magiclist[hash].tail = prev;
			}
			if (prev) {
				prev->next = pt->next;
			}
#ifdef DRM_NEWER_LOCK
			mutex_unlock(&dev->struct_mutex);
#endif
			free(pt, DRM_MEM_MAGIC);
			return 0;
		}
	}
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#endif
	return EINVAL;
}

/**
 * Called by the client, this returns a unique magic number to be authorized
 * by the master.
 *
 * The master may use its own knowledge of the client (such as the X
 * connection that the magic is passed over) to determine if the magic number
 * should be authenticated.
 */
/**
 * Get a unique magic number (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a resulting drm_auth structure.
 * \return zero on success, or a negative number on failure.
 *
 * If there is a magic number in drm_file::magic then use it, otherwise
 * searches an unique non-zero magic number and add it associating it with \p
 * file_priv.
 */
int drm_getmagic(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	static drm_magic_t sequence = 0;
	struct drm_auth *auth = data;

	/* Find unique magic */
	if (file_priv->magic) {
		auth->magic = file_priv->magic;
	} else {
#ifdef __linux__
		do {
			spin_lock(&lock);
			if (!sequence)
				++sequence;	/* reserve 0 */
			auth->magic = sequence++;
			spin_unlock(&lock);
		} while (drm_find_file(file_priv->master, auth->magic));
		file_priv->magic = auth->magic;
		drm_add_magic(file_priv->master, file_priv, auth->magic);
#else /* __linux__ */

#ifndef DRM_NEWER_LOCK
		DRM_LOCK();
#endif
		do {
			int old = sequence;

			auth->magic = old+1;

			if (!atomic_cmpset_int(&sequence, old, auth->magic))
				continue;
		} while (drm_find_file(dev, auth->magic));
		file_priv->magic = auth->magic;
		drm_add_magic(dev, file_priv, auth->magic);
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif

#endif /* __linux__ */
	}

	DRM_DEBUG("%u\n", auth->magic);

	return 0;
}

/**
 * Marks the client associated with the given magic number as authenticated.
 */
/**
 * Authenticate with a magic.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_auth structure.
 * \return zero if authentication successed, or a negative number otherwise.
 *
 * Checks if \p file_priv is associated with the magic number passed in \arg.
 */
int drm_authmagic(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	struct drm_auth *auth = data;
	struct drm_file *priv;

	DRM_DEBUG("%u\n", auth->magic);

#ifndef DRM_NEWER_LOCK
	DRM_LOCK();
#endif
	priv = drm_find_file(dev, auth->magic);
	if (priv != NULL) {
		priv->authenticated = 1;
		drm_remove_magic(dev, auth->magic);
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif
		return 0;
	} else {
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif
		return EINVAL;
	}
}
