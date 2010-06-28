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

#include "drmP.h"

/**
 * Lock ioctl.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_lock structure.
 * \return zero on success or negative number on failure.
 *
 * Add the current task to the lock wait queue, and attempt to take to lock.
 */
int drm_lock(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
#ifdef __linux__
	DECLARE_WAITQUEUE(entry, current);
#endif /* __linux__ */
	struct drm_lock *lock = data;
#ifdef __linux__
	struct drm_master *master = file_priv->master;
#endif /* __linux__ */
	int ret = 0;

#ifndef __linux__
	struct drm_lock_data *psystem_lock = &dev->lock;
#endif /* __linux__ */

	++file_priv->lock_count;

	if (lock->context == DRM_KERNEL_CONTEXT) {
		DRM_ERROR("Process %d using kernel context %d\n",
			DRM_CURRENTPID, lock->context);
		return EINVAL;
	}

	DRM_DEBUG("%d (pid %d) requests lock (0x%08x), flags = 0x%08x\n",
		lock->context, DRM_CURRENTPID,
		psystem_lock->hw_lock->lock, lock->flags);

	if (drm_core_check_feature(dev, DRIVER_DMA_QUEUE))
		if (lock->context < 0)
			return EINVAL;

#ifndef DRM_NEWER_LOCK
	DRM_LOCK();
#endif

#ifdef __linux__
	add_wait_queue(psystem_lock->lock_queue, &entry);
#endif /* __linux__ */

#ifdef DRM_NEWER_LOCK
	spin_lock_bh(psystem_lock->spinlock);
#endif

	psystem_lock->user_waiters++;

#ifdef DRM_NEWER_LOCK
	spin_unlock_bh(psystem_lock->spinlock);
#endif

	for (;;) {

#ifdef __linux__
		__set_current_state(TASK_INTERRUPTIBLE);
#endif /* __linux__ */

		if (!psystem_lock->hw_lock) {
			/* Device has been unregistered */
#ifdef __linux__
			send_sig(SIGTERM, current, 0);
			ret = -EINTR;
			break;
#else
			DRM_INFO("drm_lock() (pid %d) unregistered device needs SIGTERM\n",
				DRM_CURRENTPID);
#endif /* __linux__ */
		}

		if (drm_lock_take(psystem_lock, lock->context)) {
			psystem_lock->file_priv = file_priv;
			psystem_lock->lock_time = jiffies;
			atomic_inc(&dev->counts[_DRM_STAT_LOCKS]);
			break;  /* Got lock */
		}

		/* Contention */
		tsleep_interlock((void *)psystem_lock->lock_queue, PCATCH);
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif
		ret = tsleep((void *)psystem_lock->lock_queue,
			     PCATCH | PINTERLOCKED, "drmlk2", 0);
#ifndef DRM_NEWER_LOCK
		DRM_LOCK();
#endif
		if (ret != 0)
			break;
	}

#ifdef DRM_NEWER_LOCK
	spin_lock_bh(psystem_lock->spinlock);
#endif

	psystem_lock->user_waiters--;

#ifdef DRM_NEWER_LOCK
	spin_unlock_bh(psystem_lock->spinlock);
#endif

#ifdef __linux__
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(psystem_lock->lock_queue, &entry);
#endif /* __linux__ */

#ifndef DRM_NEWER_LOCK
	DRM_UNLOCK();
#endif

	if (ret == ERESTART)
		DRM_DEBUG("restarting syscall\n");
	else
		DRM_DEBUG("%d %s\n", lock->context,
		    ret ? "interrupted" : "has lock");

	if (ret) return ret;

	/* XXX: Add signal blocking here */
	/* don't set the block all signals on the master process for now
	 * really probably not the correct answer but lets us debug xkb
	 * xserver for now */
	if (!file_priv->is_master) {
#ifdef __linux__
		sigemptyset(&dev->sigmask);
		sigaddset(&dev->sigmask, SIGSTOP);
		sigaddset(&dev->sigmask, SIGTSTP);
		sigaddset(&dev->sigmask, SIGTTIN);
		sigaddset(&dev->sigmask, SIGTTOU);
		dev->sigdata.context = lock->context;
		dev->sigdata.lock = master->lock.hw_lock;
		block_all_signals(drm_notifier, &dev->sigdata, &dev->sigmask);
#else
		DRM_INFO("drm_lock() process (pid %d), file (pid %d) (uid %d) not master need signal block\n",
			DRM_CURRENTPID, file_priv->pid, file_priv->uid);
#endif
	}

	if (dev->driver->dma_ready && (lock->flags & _DRM_LOCK_READY))
		dev->driver->dma_ready(dev);

	if (dev->driver->dma_quiescent && (lock->flags & _DRM_LOCK_QUIESCENT))
	{
		if (dev->driver->dma_quiescent(dev)) {
			DRM_DEBUG("%d waiting for DMA quiescent\n",
				  lock->context);
			return EBUSY;
		}
	}

	if (dev->driver->kernel_context_switch &&
	    dev->last_context != lock->context) {
		dev->driver->kernel_context_switch(dev, dev->last_context,
						   lock->context);
	}

	return 0;
}

/**
 * Unlock ioctl.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_lock structure.
 * \return zero on success or negative number on failure.
 *
 * Transfer and free the lock.
 */
int drm_unlock(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_lock *lock = data;
#ifdef __linux__
	struct drm_master *master = file_priv->master;
#endif /* __linux__ */

#ifndef __linux__
	struct drm_lock_data *psystem_lock = &dev->lock;
#endif /* __linux__ */

#ifndef __linux__
	DRM_DEBUG("%d (pid %d) requests unlock (0x%08x), flags = 0x%08x\n",
	    lock->context, DRM_CURRENTPID, psystem_lock->hw_lock->lock,
	    lock->flags);
#endif /* __linux__ */

	if (lock->context == DRM_KERNEL_CONTEXT) {
		DRM_ERROR("Process %d using kernel context %d\n",
			DRM_CURRENTPID, lock->context);
		return EINVAL;
	}

	atomic_inc(&dev->counts[_DRM_STAT_UNLOCKS]);

#ifndef DRM_NEWER_LOCK
	DRM_LOCK();
#endif

#if 0
	drm_lock_transfer(psystem_lock, DRM_KERNEL_CONTEXT);
#endif /* __linux__ */

	/* kernel_context_switch isn't used by any of the x86 drm
	 * modules but is required by the Sparc driver.
	 */
	if (dev->driver->kernel_context_switch_unlock)
		dev->driver->kernel_context_switch_unlock(dev);
	else {
		if (drm_lock_free(psystem_lock, lock->context)) {
			/* FIXME: Should really bail out here. */
		}
#if 0
		if (drm_lock_free(psystem_lock, DRM_KERNEL_CONTEXT)) {
			DRM_ERROR("\n");
		}
#endif /* __linux__ */
	}

#ifdef __linux__
	unblock_all_signals();
#endif /* __linux__ */

#ifndef DRM_NEWER_LOCK
	DRM_UNLOCK();
#endif

	return 0;
}

/**
 * Take the heavyweight lock.
 *
 * \param lock lock pointer.
 * \param context locking context.
 * \return one if the lock is held, or zero otherwise.
 *
 * Attempt to mark the lock as held by the given context, via the \p cmpxchg instruction.
 */
int drm_lock_take(struct drm_lock_data *lock_data, unsigned int context)
{
	unsigned int old, new;
	volatile unsigned int *lock = &lock_data->hw_lock->lock;

#ifdef DRM_NEWER_LOCK
	spin_lock_bh(&lock_data->spinlock);
#endif

	do {
		old = *lock;
		if (old & _DRM_LOCK_HELD)
			new = old | _DRM_LOCK_CONT;
		else {
			new = context | _DRM_LOCK_HELD |
				((lock_data->user_waiters + lock_data->kernel_waiters > 1) ?
				 _DRM_LOCK_CONT : 0);
#if 0
			new = context | _DRM_LOCK_HELD;
#endif
		}
	} while (!atomic_cmpset_int(lock, old, new));

#ifdef DRM_NEWER_LOCK
	spin_unlock_bh(&lock_data->spinlock);
#endif

	if (_DRM_LOCKING_CONTEXT(old) == context) {
		if (old & _DRM_LOCK_HELD) {
			if (context != DRM_KERNEL_CONTEXT) {
				DRM_ERROR("%d holds heavyweight lock\n",
				    context);
			}
			return 0;
		}
	}
	if ((_DRM_LOCKING_CONTEXT(new)) == context && (new & _DRM_LOCK_HELD)) {
		/* Have lock */
		return 1;
	}
#if 0
	if (new == (context | _DRM_LOCK_HELD)) {
		/* Have lock */
		return 1;
	}
#endif
	return 0;
}

/* This takes a lock forcibly and hands it to context.	Should ONLY be used
   inside *_unlock to give lock to kernel before calling *_dma_schedule. */
/**
 * This takes a lock forcibly and hands it to context.	Should ONLY be used
 * inside *_unlock to give lock to kernel before calling *_dma_schedule.
 *
 * \param dev DRM device.
 * \param lock lock pointer.
 * \param context locking context.
 * \return always one.
 *
 * Resets the lock file pointer.
 * Marks the lock as held by the given context, via the \p cmpxchg instruction.
 */
int drm_lock_transfer(struct drm_lock_data *lock_data, unsigned int context)
{
	unsigned int old, new;
	volatile unsigned int *lock = &lock_data->hw_lock->lock;

	lock_data->file_priv = NULL;
	do {
		old = *lock;
		new = context | _DRM_LOCK_HELD;
	} while (!atomic_cmpset_int(lock, old, new));

	return 1;
}

/**
 * Free lock.
 *
 * \param dev DRM device.
 * \param lock lock.
 * \param context context.
 *
 * Resets the lock file pointer.
 * Marks the lock as not held, via the \p cmpxchg instruction. Wakes any task
 * waiting on the lock queue.
 */
int drm_lock_free(struct drm_lock_data *lock_data, unsigned int context)
{
	unsigned int old, new;
	volatile unsigned int *lock = &lock_data->hw_lock->lock;

#ifdef DRM_NEWER_LOCK
	spin_lock_bh(&lock_data->spinlock);
#endif

	if (lock_data->kernel_waiters != 0) {
		drm_lock_transfer(lock_data, 0);
		lock_data->idle_has_lock = 1;

#ifdef DRM_NEWER_LOCK
		spin_unlock_bh(&lock_data->spinlock);
#endif

		return 1;
	}

#ifdef DRM_NEWER_LOCK
	spin_unlock_bh(&lock_data->spinlock);
#endif

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

#ifdef __linux__
			wake_up_interruptible(&lock_data->lock_queue);
#else
			DRM_WAKEUP_INT((void *)&lock_data->lock_queue);
#endif /* __linux__ */

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
