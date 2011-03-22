/**
 * \file drm_fops.c
 * File operations for DRM
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Daryll Strauss <daryll@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Mon Jan  4 08:58:31 1999 by faith@valinux.com
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
 */

#include "drmP.h"
#ifdef __linux__
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#else /* !__linux__ */
/* #define DRM_NEWER_KQUEUE 1 */
#ifdef DRM_NEWER_KQUEUE
#include <sys/vnode.h>
#endif
extern devclass_t drm_devclass;

#define DRIVER_SOFTC(unit) \
	((struct drm_device *)devclass_get_softc(drm_devclass, unit))

struct drm_file *drm_find_file_by_proc(struct drm_device *dev, DRM_STRUCTPROC *p)
{
	uid_t uid = p->td_proc->p_ucred->cr_svuid;
	pid_t pid = p->td_proc->p_pid;
	struct drm_file *priv;

	list_for_each_entry(priv, &dev->filelist, lhead) {
		if (priv->pid == pid && priv->uid == uid)
			return priv;
	}
#if 0
	TAILQ_FOREACH(priv, &dev->files, link)
		if (priv->pid == pid && priv->uid == uid)
			return priv;
#endif
	return NULL;
}

static struct kqinfo drm_kqevent;
#endif /* !__linux__ */

#ifdef __linux__
static int drm_open_helper(struct inode *inode, struct file *filp,
			   struct drm_device * dev);
#else
static int drm_open_helper_legacy(struct cdev *kdev, int flags, int fmt, DRM_STRUCTPROC *p,
		    struct drm_device *dev);
#endif

static int drm_setup(struct drm_device * dev)
{
	int i;
	int ret;

	if (dev->driver->firstopen) {
		ret = dev->driver->firstopen(dev);
		if (ret != 0)
			return ret;
	}

	atomic_set(&dev->ioctl_count, 0);
	atomic_set(&dev->vma_count, 0);

#ifndef __linux__
/* Intel i915 only driver that appears to not DRIVER_HAVE_DMA */
	dev->buf_use = 0;
#endif /* __linux__ */
	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !drm_core_check_feature(dev, DRIVER_MODESET)) {
		dev->buf_use = 0;
		atomic_set(&dev->buf_alloc, 0);

		i = drm_dma_setup(dev);
#ifdef __linux__
		if (i < 0)
#else
		if (i != 0)
#endif
			return i;
	}

	for (i = 0; i < ARRAY_SIZE(dev->counts); i++)
		atomic_set(&dev->counts[i], 0);

	dev->sigdata.lock = NULL;

	dev->queue_count = 0;
	dev->queue_reserved = 0;
	dev->queue_slots = 0;
	dev->queuelist = NULL;
	dev->context_flag = 0;
	dev->interrupt_flag = 0;
	dev->dma_flag = 0;
	dev->last_context = 0;
	dev->last_switch = 0;
	dev->last_checked = 0;
	init_waitqueue_head(&dev->context_wait);
	dev->if_version = 0;

	dev->ctx_start = 0;
	dev->lck_start = 0;

	dev->buf_async = NULL;
	init_waitqueue_head(&dev->buf_readers);
	init_waitqueue_head(&dev->buf_writers);

#ifndef __linux__
	dev->irq_enabled = 0;
	dev->buf_sigio = NULL;
#endif /* __linux__ */

	DRM_DEBUG("\n");

	/*
	 * The kernel's context could be created here, but is now created
	 * in drm_dma_enqueue.  This is more resource-efficient for
	 * hardware that does not do DMA, but may mean that
	 * drm_select_queue fails between the time the interrupt is
	 * initialized and the time the queues are initialized.
	 */

	return 0;
}

/**
 * Open file.
 *
 * \param inode device inode
 * \param filp file pointer.
 * \return zero on success or a negative number on failure.
 *
 * Searches the DRM device with the same minor number, calls open_helper(), and
 * increments the device open count. If the open count was previous at zero,
 * i.e., it's the first that the device is open, then calls setup().
 */
#ifdef __linux__
int drm_open(struct inode *inode, struct file *filp)
#else
int drm_open_legacy(DRM_OPEN_ARGS)
#endif
{
#ifndef __linux__
	struct cdev *kdev = ap->a_head.a_dev;
	int flags = ap->a_oflags;
	int fmt = 0;
	struct thread *p = curthread;
#endif /* !__linux__ */
	struct drm_device *dev = NULL;
#ifdef __linux__
	int minor_id = iminor(inode);
#else
	int minor_id = minor(kdev);
#endif
	struct drm_minor *minor;
	int retcode = 0;

	minor = idr_find(&drm_minors_idr, minor_id);
	if (!minor) {
#ifdef __linux__
		return -ENODEV;
#else
		DRM_ERROR("No minor for %d\n", minor_id);
		return ENODEV;
#endif
	}

#ifdef __linux__
	if (!(dev = minor->dev))
		return -ENODEV;
#else
	if (minor && !minor->dev) {
		DRM_ERROR("No minor device for %d\n", minor_id);
		return ENODEV;
	}
	dev = DRIVER_SOFTC(minor_id);
	if (minor && (dev != minor->dev)) {
		DRM_ERROR("Minor device != softc device for %d\n", minor_id);
		return ENODEV;
	}
#endif

#ifdef __linux__
	retcode = drm_open_helper(inode, filp, dev);
#else
	retcode = drm_open_helper_legacy(kdev, flags, fmt, p, dev);
#endif
	if (!retcode) {
		atomic_inc(&dev->counts[_DRM_STAT_OPENS]);
		spin_lock(&dev->count_lock);

#ifndef __linux__ /* legacy change balanced in drm_close_legacy */
		device_busy(dev->device);
#endif

		if (!dev->open_count++) {
			spin_unlock(&dev->count_lock);
			retcode = drm_setup(dev);
			goto out;
		}
		spin_unlock(&dev->count_lock);
	}
out:
#ifdef __linux__ /* UNIMPLEMENTED */
	if (!retcode) {
		mutex_lock(&dev->struct_mutex);
		if (minor->type == DRM_MINOR_LEGACY) {
			if (dev->dev_mapping == NULL)
				dev->dev_mapping = inode->i_mapping;
			else if (dev->dev_mapping != inode->i_mapping)
				retcode = -ENODEV;
		}
		mutex_unlock(&dev->struct_mutex);
	}
#endif /* __linux__ */

	return retcode;
}
EXPORT_SYMBOL(drm_open);

/**
 * File \c open operation.
 *
 * \param inode device inode.
 * \param filp file pointer.
 *
 * Puts the dev->fops corresponding to the device minor number into
 * \p filp, call the \c open method, and restore the file operations.
 */
int drm_stub_open(struct inode *inode, struct file *filp)
{
	struct drm_device *dev = NULL;
	struct drm_minor *minor;
	int minor_id = iminor(inode);
	int err = -ENODEV;
#ifdef __linux__
	const struct file_operations *old_fops;
#else
	struct file_operations *old_fops;
#endif

	DRM_DEBUG("\n");

	/* BKL pushdown: note that nothing else serializes idr_find() */
	lock_kernel();
	minor = idr_find(&drm_minors_idr, minor_id);
	if (!minor)
		goto out;

	if (!(dev = minor->dev))
		goto out;

	old_fops = filp->f_op;
	filp->f_op = fops_get(&dev->driver->fops);
	if (filp->f_op == NULL) {
		filp->f_op = old_fops;
		goto out;
	}
	if (filp->f_op->open && (err = filp->f_op->open(inode, filp))) {
		fops_put(filp->f_op);
		filp->f_op = fops_get(old_fops);
	}
	fops_put(old_fops);

out:
	unlock_kernel();
	return err;
}

/**
 * Check whether DRI will run on this CPU.
 *
 * \return non-zero if the DRI will run on this CPU, or zero otherwise.
 */
static int drm_cpu_valid(void)
{
#ifdef __linux__ /* UNIMPLEMENTED */
#if defined(__i386__)
	if (boot_cpu_data.x86 == 3)
		return 0;	/* No cmpxchg on a 386 */
#endif
#if defined(__sparc__) && !defined(__sparc_v9__)
	return 0;		/* No cmpxchg before v9 sparc. */
#endif
#endif /* __linux __ */
	return 1;
}

/**
 * Called whenever a process opens /dev/drm.
 *
 * \param inode device inode.
 * \param filp file pointer.
 * \param dev device.
 * \return zero on success or a negative number on failure.
 *
 * Creates and initializes a drm_file structure for the file private data in \p
 * filp and add it into the double linked list in \p dev.
 */
#ifdef __linux__
static int drm_open_helper(struct inode *inode, struct file *filp,
			   struct drm_device * dev)
#else
static int drm_open_helper_legacy(struct cdev *kdev, int flags, int fmt, DRM_STRUCTPROC *p,
		    struct drm_device *dev)
#endif
{
	int minor_id = minor(kdev);
	struct drm_file *find_priv;
	struct drm_file *priv;
	int ret;

#ifdef __linux__
	if (filp->f_flags & O_EXCL)
		return -EBUSY;	/* No exclusive opens */
#else
	if (flags & O_EXCL)
		return EBUSY; /* No exclusive opens */
#endif
	if (!drm_cpu_valid())
		return EINVAL;

	dev->flags = flags;

	DRM_DEBUG("pid = %d, minor = %d\n", DRM_CURRENTPID, minor_id);

	priv = malloc(sizeof(*priv), DRM_MEM_FILES, M_WAITOK | M_ZERO);
	if (!priv) {
		return ENOMEM;
	}

	priv->refs = 1;
#if 0
	priv->minor_legacy = minor_id;
#endif

#ifdef __linux__
	priv->uid = current_euid();
	priv->pid = task_pid_nr(current);
#else
	priv->uid = p->td_proc->p_ucred->cr_svuid;
	priv->pid = p->td_proc->p_pid;
#endif
	priv->minor = idr_find(&drm_minors_idr, minor_id);
	priv->ioctl_count = 0;
	/* for compatibility root is always authenticated */
#ifdef __linux__
	priv->authenticated = capable(CAP_SYS_ADMIN);
#else
	priv->authenticated = DRM_SUSER(p);
#endif
	priv->lock_count = 0;

	INIT_LIST_HEAD(&priv->lhead);
	INIT_LIST_HEAD(&priv->fbs);
	INIT_LIST_HEAD(&priv->event_list);
	init_waitqueue_head(&priv->event_wait);
	priv->event_space = 4096; /* set aside 4k for event buffer */

#ifndef __linux__ /* legacy required because no file open state */
	spin_lock(&dev->file_priv_lock);
        find_priv = drm_find_file_by_proc(dev, p);
        if (find_priv) {
                find_priv->refs++;
		DRM_INFO("open %d by pid (%d), uid (%d), on minor_id (%d), authenticated (%d)\n",
			find_priv->refs,
			find_priv->pid,
			find_priv->uid,
			find_priv->minor->index,
			find_priv->authenticated
			);
		if (kdev->si_drv1 != dev)
			DRM_ERROR("kdev->si_drv1 != dev\n");
		kdev->si_drv1 = dev;
		ret = 0;
		goto out_free_found;
	}
#endif /* !__linux__ */

	if (dev->driver->driver_features & DRIVER_GEM)
		drm_gem_open(dev, priv);

	if (dev->driver->open) {
		ret = dev->driver->open(dev, priv);
		if (ret != 0) {
			goto out_free;
		}
	}

	/* if there is no current master make this fd it */
	mutex_lock(&dev->struct_mutex);
#ifndef __linux__ /* legacy BSD needed for other */
	kdev->si_drv1 = dev;
#if 0
	priv->master_legacy = TAILQ_EMPTY(&dev->files);
#endif
#endif
	if (!priv->minor->master) {
		/* create a new master */
		priv->minor->master = drm_master_create(priv->minor);
		if (!priv->minor->master) {
			mutex_unlock(&dev->struct_mutex);
			ret = ENOMEM;
			goto out_free;
		}
#ifndef __linux__
		DRM_INFO("master created on minor_id (%d) by pid (%d), uid (%d)\n",
			minor_id, priv->pid, priv->uid);
#endif

		priv->is_master = 1;
		/* take another reference for the copy in the local file priv */
		priv->master = drm_master_get(priv->minor->master);

		priv->authenticated = 1;

		mutex_unlock(&dev->struct_mutex);
		if (dev->driver->master_create) {
			ret = dev->driver->master_create(dev, priv->master);
			if (ret) {
				mutex_lock(&dev->struct_mutex);
				/* drop both references if this fails */
				drm_master_put(&priv->minor->master);
				drm_master_put(&priv->master);
				mutex_unlock(&dev->struct_mutex);
				goto out_free;
			}
		}

		mutex_lock(&dev->struct_mutex);
		if (dev->driver->master_set) {
			ret = dev->driver->master_set(dev, priv, true);
			if (ret) {
				/* drop both references if this fails */
				drm_master_put(&priv->minor->master);
				drm_master_put(&priv->master);
				mutex_unlock(&dev->struct_mutex);
				goto out_free;
			}
		}
		mutex_unlock(&dev->struct_mutex);
	} else {
		/* get a reference to the master */
		priv->master = drm_master_get(priv->minor->master);
		mutex_unlock(&dev->struct_mutex);
	}

	mutex_lock(&dev->struct_mutex);
#if 0
	TAILQ_INSERT_TAIL(&dev->files, priv, link);
#endif
	list_add(&priv->lhead, &dev->filelist);
	mutex_unlock(&dev->struct_mutex);

#ifdef __linux__
#ifdef __alpha__
	/*
	 * Default the hose
	 */
	if (!dev->hose) {
		struct pci_dev *pci_dev;
		pci_dev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, NULL);
		if (pci_dev) {
			dev->hose = pci_dev->sysdata;
			pci_dev_put(pci_dev);
		}
		if (!dev->hose) {
			struct pci_bus *b = pci_bus_b(pci_root_buses.next);
			if (b)
				dev->hose = b->sysdata;
		}
	}
#endif
#endif
#ifndef __linux__
	kdev->si_drv1 = dev;
	DRM_INFO("success open #(%d) by pid (%d), uid (%d), on minor_id (%d), authenticated (%d)\n",
		priv->refs,
		priv->pid,
		priv->uid,
		priv->minor->index,
		priv->authenticated
	);
	spin_unlock(&dev->file_priv_lock);
#endif /* !__linux__ */
	return 0;
      out_free:
#ifndef __linux__
	spin_unlock(&dev->file_priv_lock);
#endif
	free(priv, DRM_MEM_FILES);
#ifdef __linux__
	filp->private_data = NULL;
#endif
#if 0
	kdev->si_drv1 = NULL;
#endif
	return ret;
#ifndef __linux__
      out_free_found:
	spin_unlock(&dev->file_priv_lock);
	free(priv, DRM_MEM_FILES);
	return ret;
#endif
}

/** No-op. */
int drm_fasync(int fd, struct file *filp, int on)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;

	DRM_DEBUG("fd = %d, device = 0x%lx\n", fd,
		  (long)old_encode_dev(priv->minor->device));
	return fasync_helper(fd, filp, on, &dev->buf_async);
}
EXPORT_SYMBOL(drm_fasync);

/*
 * Reclaim locked buffers; note that this may be a bad idea if the current
 * context doesn't have the hw lock...
 */
#ifdef __linux__
static void drm_reclaim_locked_buffers(struct drm_device *dev, struct file *f)
#else
static void drm_reclaim_locked_buffers(struct drm_device *dev, struct drm_file *file_priv)
#endif
{
#ifdef __linux__
	struct drm_file *file_priv = f->private_data;
#endif

	if (drm_i_have_hw_lock(dev, file_priv)) {
		dev->driver->reclaim_buffers_locked(dev, file_priv);
	} else {
		unsigned long _end = jiffies + 3 * DRM_HZ;
		int locked = 0;

		drm_idlelock_take(&file_priv->master->lock);

		/*
		 * Wait for a while.
		 */
		do {
			spin_lock_bh(&file_priv->master->lock.spinlock);
			locked = file_priv->master->lock.idle_has_lock;
			spin_unlock_bh(&file_priv->master->lock.spinlock);
			if (locked)
				break;
#ifdef __linux__
			schedule();
#else
			tsleep_interlock((void *)&file_priv->master->lock.lock_queue, PCATCH);
			spin_unlock(&dev->file_priv_lock);
			tsleep((void *)&file_priv->master->lock.lock_queue,
					 PCATCH | PINTERLOCKED, "drmlk2", _end);
			spin_lock(&dev->file_priv_lock);
#endif
		} while (!time_after_eq(jiffies, _end));

		if (!locked) {
			DRM_ERROR("reclaim_buffers_locked() deadlock. Please rework this\n"
				  "\tdriver to use reclaim_buffers_idlelocked() instead.\n"
				  "\tI will go on reclaiming the buffers anyway.\n");
		}

		dev->driver->reclaim_buffers_locked(dev, file_priv);
		drm_idlelock_release(&file_priv->master->lock);
	}
}

#ifdef __linux__
static void drm_master_release(struct drm_device *dev, struct file *filp)
#else
static void drm_master_release(struct drm_device *dev, struct drm_file *file_priv)
#endif
{
#ifdef __linux__
	struct drm_file *file_priv = filp->private_data;
#endif

	if (dev->driver->reclaim_buffers_locked &&
	    file_priv->master->lock.hw_lock)
#ifdef __linux__
		drm_reclaim_locked_buffers(dev, filp);
#else
		drm_reclaim_locked_buffers(dev, file_priv);
#endif

	if (dev->driver->reclaim_buffers_idlelocked &&
	    file_priv->master->lock.hw_lock) {
		drm_idlelock_take(&file_priv->master->lock);
		dev->driver->reclaim_buffers_idlelocked(dev, file_priv);
		drm_idlelock_release(&file_priv->master->lock);
	}


	if (drm_i_have_hw_lock(dev, file_priv)) {
#ifdef __linux__
		DRM_DEBUG("File %p released, freeing lock for context %d\n",
			  filp, _DRM_LOCKING_CONTEXT(file_priv->master->lock.hw_lock->lock));
#endif /* __linux__ */
		drm_lock_free(&file_priv->master->lock,
			      _DRM_LOCKING_CONTEXT(file_priv->master->lock.hw_lock->lock));
	}

#if 1
	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !dev->driver->reclaim_buffers_locked) {
		dev->driver->reclaim_buffers(dev, file_priv);
	}
#endif
}

static void drm_events_release(struct drm_file *file_priv)
{
	struct drm_device *dev = file_priv->minor->dev;
	struct drm_pending_event *e, *et;
	struct drm_pending_vblank_event *v, *vt;
	unsigned long flags;

	spin_lock_irqsave(&dev->event_lock, flags);

	/* Remove pending flips */
	list_for_each_entry_safe(v, vt, &dev->vblank_event_list, base.link)
		if (v->base.file_priv == file_priv) {
			list_del(&v->base.link);
			drm_vblank_put(dev, v->pipe);
			v->base.destroy(&v->base);
		}

	/* Remove unconsumed events */
	list_for_each_entry_safe(e, et, &file_priv->event_list, link)
		e->destroy(e);

	spin_unlock_irqrestore(&dev->event_lock, flags);
}

/**
 * Release file.
 *
 * \param inode device inode
 * \param file_priv DRM file private.
 * \return zero on success or a negative number on failure.
 *
 * If the hardware lock is held then free it, and take it again for the kernel
 * context since it's necessary to reclaim buffers. Unlink the file private
 * data from its list and free it. Decreases the open count and if it reaches
 * zero calls drm_lastclose().
 */
#ifdef __linux__
int drm_release(struct inode *inode, struct file *filp)
#else
int drm_close_legacy(struct dev_close_args *ap)
#endif
{
#ifdef __linux__
	struct drm_file *file_priv = filp->private_data;
	struct drm_device *dev = file_priv->minor->dev;
#else
	struct cdev *kdev = ap->a_head.a_dev;
	struct drm_file *file_priv;
	struct drm_device *dev = DRIVER_SOFTC(minor(kdev));
#endif /* __linux__ */
	int retcode = 0;

	lock_kernel();

	DRM_DEBUG("open_count = %d\n", dev->open_count);

#ifndef __linux__ /* legacy change no per thread file state */
	spin_lock(&dev->file_priv_lock);
	file_priv = drm_find_file_by_proc(dev, curthread);
	if (!file_priv->minor) {
		DRM_ERROR("drm_close() no minor for file!\n");
	}
	if (file_priv->minor && (dev != file_priv->minor->dev)) {
		DRM_ERROR("drm_close() softc device != minor device!\n");
	}

	DRM_INFO("close %d by pid (%d), uid (%d), on minor_id (%d)\n",
		file_priv->refs,
		file_priv->pid,
		file_priv->uid,
		file_priv->minor->index);

	if (--file_priv->refs != 0) {
		goto done;
	}
#endif /* !__linux__ */

	if (dev->driver->preclose != NULL)
		dev->driver->preclose(dev, file_priv);

	/* ========================================================
	 * Begin inline drm_release
	 */

	DRM_DEBUG("pid = %d, device = 0x%lx, open_count = %d\n",
		DRM_CURRENTPID,
		(long)dev->device,
		dev->open_count);

	/* if the master has gone away we can't do anything with the lock */
	if (file_priv->minor->master)
		drm_master_release(dev, file_priv);

#ifndef __linux__
/* There apparently is a savage_reclaim_buffers */
	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !dev->driver->reclaim_buffers_locked)
		drm_core_reclaim_buffers(dev, file_priv);
#endif /* !__linux__ */

#ifndef __linux__
	funsetown(&dev->buf_sigio);
#endif /* !__linux__ */

	drm_events_release(file_priv);

	if (dev->driver->driver_features & DRIVER_GEM)
		drm_gem_release(dev, file_priv);

	if (dev->driver->driver_features & DRIVER_MODESET)
		drm_fb_release(file_priv);

	mutex_lock(&dev->ctxlist_mutex);
	if (!list_empty(&dev->ctxlist)) {
		struct drm_ctx_list *pos, *n;

		list_for_each_entry_safe(pos, n, &dev->ctxlist, head) {
			if (pos->tag == file_priv &&
			    pos->handle != DRM_KERNEL_CONTEXT) {
				if (dev->driver->context_dtor)
					dev->driver->context_dtor(dev,
								  pos->handle);

				drm_ctxbitmap_free(dev, pos->handle);

				list_del(&pos->head);
				free(pos, DRM_MEM_CTXBITMAP);
				--dev->ctx_count;
			}
		}
	}
	mutex_unlock(&dev->ctxlist_mutex);

	mutex_lock(&dev->struct_mutex);

	if (file_priv->is_master) {
		struct drm_master *master = file_priv->master;
		struct drm_file *temp;
		list_for_each_entry(temp, &dev->filelist, lhead) {
			if ((temp->master == file_priv->master) &&
			    (temp != file_priv))
				temp->authenticated = 0;
		}

		/**
		 * Since the master is disappearing, so is the
		 * possibility to lock.
		 */

		if (master->lock.hw_lock) {
			if (dev->sigdata.lock == master->lock.hw_lock)
				dev->sigdata.lock = NULL;
			master->lock.hw_lock = NULL;
			master->lock.file_priv = NULL;
			DRM_WAKEUP_INT(&master->lock.lock_queue);
		}

		if (file_priv->minor->master == file_priv->master) {
			/* drop the reference held my the minor */
			if (dev->driver->master_drop)
				dev->driver->master_drop(dev, file_priv, true);
			drm_master_put(&file_priv->minor->master);
		}
	}

	/* drop the reference held my the file priv */
	drm_master_put(&file_priv->master);
	file_priv->is_master = 0;
	list_del(&file_priv->lhead);
#if 0
	TAILQ_REMOVE(&dev->files, file_priv, link);
#endif
	mutex_unlock(&dev->struct_mutex);

	if (dev->driver->postclose)
		dev->driver->postclose(dev, file_priv);
	free(file_priv, DRM_MEM_FILES);

	/* ========================================================
	 * End inline drm_release
	 */
done:
#ifndef __linux__ /* legacy release file_priv change lock */
	spin_unlock(&dev->file_priv_lock);
#endif
	atomic_inc(&dev->counts[_DRM_STAT_CLOSES]);
	spin_lock(&dev->count_lock);
#ifndef __linux__
	device_unbusy(dev->device);
#endif
	if (!--dev->open_count) {
		if (atomic_read(&dev->ioctl_count)) {
			DRM_ERROR("Device busy: %d\n",
				  atomic_read(&dev->ioctl_count));
			spin_unlock(&dev->count_lock);
			unlock_kernel();
			return EBUSY;
		}
		spin_unlock(&dev->count_lock);
		unlock_kernel();
		return drm_lastclose(dev);
	}
	spin_unlock(&dev->count_lock);

	unlock_kernel();

	return (0);
}
EXPORT_SYMBOL(drm_release);

static bool
drm_dequeue_event(struct drm_file *file_priv,
		  size_t total, size_t max, struct drm_pending_event **out)
{
	struct drm_device *dev = file_priv->minor->dev;
	struct drm_pending_event *e;
	unsigned long flags;
	bool ret = false;

	spin_lock_irqsave(&dev->event_lock, flags);

	*out = NULL;
	if (list_empty(&file_priv->event_list))
		goto out;
	e = list_first_entry(&file_priv->event_list,
			     struct drm_pending_event, link);
	if (e->event->length + total > max)
		goto out;

	file_priv->event_space += e->event->length;
	list_del(&e->link);
	*out = e;
	ret = true;

out:
	spin_unlock_irqrestore(&dev->event_lock, flags);
	return ret;
}

ssize_t drm_read(struct file *filp, char __user *buffer,
		 size_t count, loff_t *offset)
{
	struct drm_file *file_priv = filp->private_data;
	struct drm_pending_event *e;
	size_t total;
	ssize_t ret;

	ret = wait_event_interruptible(file_priv->event_wait,
				       !list_empty(&file_priv->event_list));
	if (ret < 0)
		return ret;

	total = 0;
	while (drm_dequeue_event(file_priv, total, count, &e)) {
		if (copy_to_user(buffer + total,
				 e->event, e->event->length)) {
			total = -EFAULT;
			break;
		}

		total += e->event->length;
		e->destroy(e);
	}

	return total;
}
EXPORT_SYMBOL(drm_read);

unsigned int drm_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct drm_file *file_priv = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &file_priv->event_wait, wait);

	if (!list_empty(&file_priv->event_list))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}
EXPORT_SYMBOL(drm_poll);

/* The drm_read_legacy and drm_poll_legacy are stubs to prevent spurious errors
 * on older X Servers (4.3.0 and earlier) */
int drm_read_legacy(struct dev_read_args *ap)
{
#ifdef DRM_NEWER_KQUEUE
	struct cdev *kdev = ap->a_head.a_dev;
	struct uio *uio = ap->a_uio;
	struct drm_device *dev = kdev->si_drv1;
	struct drm_file *file_priv;
	struct drm_pending_event *e;
	size_t total;
	ssize_t ret;
	size_t count = uio->uio_resid;
	int error;
	spin_lock(&dev->file_priv_lock);
	file_priv = drm_find_file_by_proc(dev, curthread);
	spin_unlock(&dev->file_priv_lock);

	DRM_INFO("drm_read_legacy(): by pid (%d), uid (%d)\n",
		DRM_CURRENTPID,
		DRM_CURRENTUID);

	error = 0;
	crit_enter();
	for (;;) {
		if (!list_empty(&file_priv->event_list))
			break;
		if (ap->a_ioflag & IO_NDELAY) {
			error = EWOULDBLOCK;
			break;
		}
		error = tsleep(&file_priv->event_wait, PCATCH, "drmrek", 0);
		if (error)
			break;
	}
	crit_exit();
	if (error)
		return (error);

	total = 0;
	while (drm_dequeue_event(file_priv, total, count, &e)) {
		if ((error = uiomove(e->event, e->event->length, uio)) != 0) {
			break;
		}

		total += e->event->length;
		e->destroy(e);
	}

	return (error);
#else
	return (0);
#endif
}

static int
drmfilt(struct knote *kn, long hint)
{
	return (0);
}

static void
drmfilt_detach(struct knote *kn) {}

static struct filterops drmfiltops =
        { FILTEROP_ISFD, NULL, drmfilt_detach, drmfilt };

static void
drmreadfilt_detach(struct knote *kn)
{
#ifdef DRM_NEWER_KQUEUE
	struct klist *klist;

	klist = &drm_kqevent.ki_note;
	knote_remove(klist, kn);
#endif
}

static int
drmreadfilt(struct knote *kn, long hint)
{
	int ready = 0;
#ifdef DRM_NEWER_KQUEUE
	cdev_t kdev = (cdev_t)kn->kn_hook;
	struct drm_device *dev = kdev->si_drv1;
	struct drm_file *file_priv;
	spin_lock(&dev->file_priv_lock);
	file_priv = drm_find_file_by_proc(dev, curthread);
	spin_unlock(&dev->file_priv_lock);

	crit_enter();
	if (!list_empty(&file_priv->event_list))
		ready = 1;
	crit_exit();
#endif

	return (ready);
}

static struct filterops drmreadops =
        { FILTEROP_ISFD, NULL, drmreadfilt_detach, drmreadfilt };

int
drm_kqfilter(struct dev_kqfilter_args *ap)
{
#ifdef DRM_NEWER_KQUEUE
	cdev_t kdev = ap->a_head.a_dev;
	struct knote *kn = ap->a_kn;
	struct klist *klist;
#else
	struct knote *kn = ap->a_kn;
#endif

	ap->a_result = 0;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &drmreadops;
#ifdef DRM_NEWER_KQUEUE
		kn->kn_hook = (caddr_t)kdev;
#endif
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &drmfiltops;
		break;
	default:
		ap->a_result = EOPNOTSUPP;
		return (0);
	}

#ifdef DRM_NEWER_KQUEUE
	klist = &drm_kqevent.ki_note;
	knote_insert(klist, kn);
#endif

	return (0);
}
