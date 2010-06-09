/*-
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

/** @file drm_lock.c
 * Implementation of the ioctls and other support code for dealing with the
 * hardware lock.
 *
 * The DRM hardware lock is a shared structure between the kernel and userland.
 *
 * On uncontended access where the new context was the last context, the
 * client may take the lock without dropping down into the kernel, using atomic
 * compare-and-set.
 *
 * If the client finds during compare-and-set that it was not the last owner
 * of the lock, it calls the DRM lock ioctl, which may sleep waiting for the
 * lock, and may have side-effects of kernel-managed context switching.
 *
 * When the client releases the lock, if the lock is marked as being contended
 * by another client, then the DRM unlock ioctl is called so that the
 * contending client may be woken up.
 */

#include "dev/drm/drmP.h"

int drm_lock(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_lock *lock = data;
	int ret = 0;

	if (lock->context == DRM_KERNEL_CONTEXT) {
		DRM_ERROR("Process %d using kernel context %d\n",
		    DRM_CURRENTPID, lock->context);
		return EINVAL;
	}

	DRM_DEBUG("%d (pid %d) requests lock (0x%08x), flags = 0x%08x\n",
	    lock->context, DRM_CURRENTPID, dev->lock.hw_lock->lock,
	    lock->flags);

	if (drm_core_check_feature(dev, DRIVER_DMA_QUEUE) &&
	    lock->context < 0)
		return EINVAL;

	DRM_LOCK();
	for (;;) {
		if (drm_lock_take(&dev->lock, lock->context)) {
			dev->lock.file_priv = file_priv;
			dev->lock.lock_time = jiffies;
			atomic_inc(&dev->counts[_DRM_STAT_LOCKS]);
			break;  /* Got lock */
		}

		/* Contention */
		tsleep_interlock((void *)&dev->lock.lock_queue, PCATCH);
		DRM_UNLOCK();
		ret = tsleep((void *)&dev->lock.lock_queue,
			     PCATCH | PINTERLOCKED, "drmlk2", 0);
		DRM_LOCK();
		if (ret != 0)
			break;
	}
	DRM_UNLOCK();

	if (ret == ERESTART)
		DRM_DEBUG("restarting syscall\n");
	else
		DRM_DEBUG("%d %s\n", lock->context,
		    ret ? "interrupted" : "has lock");

	if (ret != 0)
		return ret;

	/* XXX: Add signal blocking here */

	if (dev->driver->dma_quiescent != NULL &&
	    (lock->flags & _DRM_LOCK_QUIESCENT))
		dev->driver->dma_quiescent(dev);

	return 0;
}

int drm_unlock(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_lock *lock = data;

	DRM_DEBUG("%d (pid %d) requests unlock (0x%08x), flags = 0x%08x\n",
	    lock->context, DRM_CURRENTPID, dev->lock.hw_lock->lock,
	    lock->flags);

	if (lock->context == DRM_KERNEL_CONTEXT) {
		DRM_ERROR("Process %d using kernel context %d\n",
		    DRM_CURRENTPID, lock->context);
		return EINVAL;
	}

	atomic_inc(&dev->counts[_DRM_STAT_UNLOCKS]);

	DRM_LOCK();
	drm_lock_transfer(&dev->lock, DRM_KERNEL_CONTEXT);

	if (drm_lock_free(&dev->lock, DRM_KERNEL_CONTEXT)) {
		DRM_ERROR("\n");
	}
	DRM_UNLOCK();

	return 0;
}

int drm_lock_take(struct drm_lock_data *lock_data, unsigned int context)
{
	volatile unsigned int *lock = &lock_data->hw_lock->lock;
	unsigned int old, new;

	do {
		old = *lock;
		if (old & _DRM_LOCK_HELD)
			new = old | _DRM_LOCK_CONT;
		else
			new = context | _DRM_LOCK_HELD;
	} while (!atomic_cmpset_int(lock, old, new));

	if (_DRM_LOCKING_CONTEXT(old) == context) {
		if (old & _DRM_LOCK_HELD) {
			if (context != DRM_KERNEL_CONTEXT) {
				DRM_ERROR("%d holds heavyweight lock\n",
				    context);
			}
			return 0;
		}
	}
	if (new == (context | _DRM_LOCK_HELD)) {
		/* Have lock */
		return 1;
	}
	return 0;
}

/* This takes a lock forcibly and hands it to context.	Should ONLY be used
   inside *_unlock to give lock to kernel before calling *_dma_schedule. */
int drm_lock_transfer(struct drm_lock_data *lock_data, unsigned int context)
{
	volatile unsigned int *lock = &lock_data->hw_lock->lock;
	unsigned int old, new;

	lock_data->file_priv = NULL;
	do {
		old = *lock;
		new = context | _DRM_LOCK_HELD;
	} while (!atomic_cmpset_int(lock, old, new));

	return 1;
}

int drm_lock_free(struct drm_lock_data *lock_data, unsigned int context)
{
	volatile unsigned int *lock = &lock_data->hw_lock->lock;
	unsigned int old, new;

	lock_data->file_priv = NULL;
	do {
		old = *lock;
		new = 0;
	} while (!atomic_cmpset_int(lock, old, new));

	if (_DRM_LOCK_IS_HELD(old) && _DRM_LOCKING_CONTEXT(old) != context) {
		DRM_ERROR("%d freed heavyweight lock held by %d\n",
		    context, _DRM_LOCKING_CONTEXT(old));
		return 1;
	}
	DRM_WAKEUP_INT((void *)&lock_data->lock_queue);
	return 0;
}

/* newer UNIMPLEMENTED */

#ifdef __linux__

/**
 * If we get here, it means that the process has called DRM_IOCTL_LOCK
 * without calling DRM_IOCTL_UNLOCK.
 *
 * If the lock is not held, then let the signal proceed as usual.  If the lock
 * is held, then set the contended flag and keep the signal blocked.
 *
 * \param priv pointer to a drm_sigdata structure.
 * \return one if the signal should be delivered normally, or zero if the
 * signal should be blocked.
 */
static int drm_notifier(void *priv)
{
	struct drm_sigdata *s = (struct drm_sigdata *) priv;
#ifdef __linux__
	unsigned int old, new, prev;
#else
	unsigned int old, new;
#endif

	/* Allow signal delivery if lock isn't held */
	if (!s->lock || !_DRM_LOCK_IS_HELD(s->lock->lock)
	    || _DRM_LOCKING_CONTEXT(s->lock->lock) != s->context)
		return 1;

	/* Otherwise, set flag to force call to
	   drmUnlock */
	do {
		old = s->lock->lock;
		new = old | _DRM_LOCK_CONT;
#ifdef __linux__
		prev = cmpxchg(&s->lock->lock, old, new);
	} while (prev != old);
#else
	} while (atomic_cmpset_int(&s->lock->lock, old, new));
#endif
	return 0;
}

#endif /* __linux__ */

/**
 * This function returns immediately and takes the hw lock
 * with the kernel context if it is free, otherwise it gets the highest priority when and if
 * it is eventually released.
 *
 * This guarantees that the kernel will _eventually_ have the lock _unless_ it is held
 * by a blocked process. (In the latter case an explicit wait for the hardware lock would cause
 * a deadlock, which is why the "idlelock" was invented).
 *
 * This should be sufficient to wait for GPU idle without
 * having to worry about starvation.
 */

void drm_idlelock_take(struct drm_lock_data *lock_data)
{
	int ret = 0;

	spin_lock_bh(&lock_data->spinlock);
	lock_data->kernel_waiters++;
	if (!lock_data->idle_has_lock) {

		spin_unlock_bh(&lock_data->spinlock);
		ret = drm_lock_take(lock_data, DRM_KERNEL_CONTEXT);
		spin_lock_bh(&lock_data->spinlock);

		if (ret == 1)
			lock_data->idle_has_lock = 1;
	}
	spin_unlock_bh(&lock_data->spinlock);
}
EXPORT_SYMBOL(drm_idlelock_take);

void drm_idlelock_release(struct drm_lock_data *lock_data)
{
#ifdef __linux__
	unsigned int old, prev;
#else
	unsigned int old;
#endif
	volatile unsigned int *lock = &lock_data->hw_lock->lock;

	spin_lock_bh(&lock_data->spinlock);
	if (--lock_data->kernel_waiters == 0) {
		if (lock_data->idle_has_lock) {
			do {
				old = *lock;
#ifdef __linux__
				prev = cmpxchg(lock, old, DRM_KERNEL_CONTEXT);
			} while (prev != old);
#else
			} while (atomic_cmpset_int(lock, old, DRM_KERNEL_CONTEXT));
#endif
			wake_up_interruptible(&lock_data->lock_queue);
			lock_data->idle_has_lock = 0;
		}
	}
	spin_unlock_bh(&lock_data->spinlock);
}
EXPORT_SYMBOL(drm_idlelock_release);


int drm_i_have_hw_lock(struct drm_device *dev, struct drm_file *file_priv)
{
	struct drm_master *master = file_priv->master;
	return (file_priv->lock_count && master->lock.hw_lock &&
		_DRM_LOCK_IS_HELD(master->lock.hw_lock->lock) &&
		master->lock.file_priv == file_priv);
}

EXPORT_SYMBOL(drm_i_have_hw_lock);
