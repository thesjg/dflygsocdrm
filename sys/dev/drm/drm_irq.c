/*-
 * Copyright 2003 Eric Anholt
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
 * ERIC ANHOLT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <anholt@FreeBSD.org>
 *
 */

/** @file drm_irq.c
 * Support code for handling setup/teardown of interrupt handlers and
 * handing interrupt handlers off to the drivers.
 */

#ifdef __linux__
#include "drmP.h"

#include <linux/interrupt.h>	/* For task queue support */
#include <linux/slab.h>

#include <linux/vgaarb.h>
#else
#include "drmP.h"
#endif /* __linux__ */

/**
 * Get interrupt from bus id.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_irq_busid structure.
 * \return zero on success or a negative number on failure.
 *
 * Finds the PCI device with the specified bus id and gets its IRQ number.
 * This IOCTL is deprecated, and will now return EINVAL for any busid not equal
 * to that of the device that this DRM instance attached to.
 */
int drm_irq_by_busid(struct drm_device *dev, void *data,
		     struct drm_file *file_priv)
{
	struct drm_irq_busid *irq = data;

	if ((irq->busnum >> 8) != dev->pci_domain ||
	    (irq->busnum & 0xff) != dev->pci_bus ||
	    irq->devnum != dev->pci_slot ||
	    irq->funcnum != dev->pci_func)
		return EINVAL;

	irq->irq = dev->irq;

	DRM_DEBUG("%d:%d:%d => IRQ %d\n",
	    irq->busnum, irq->devnum, irq->funcnum, irq->irq);

	return 0;
}

static void vblank_disable_fn(void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	int i;

	DRM_SPINLOCK(&dev->vbl_lock);
	
	if (callout_pending(&dev->vblank_disable_timer)) {
		/* callout was reset */
		DRM_SPINUNLOCK(&dev->vbl_lock);
		return;
	}
	if (!callout_active(&dev->vblank_disable_timer)) {
		/* callout was stopped */
		DRM_SPINUNLOCK(&dev->vbl_lock);
		return;
	}
	callout_deactivate(&dev->vblank_disable_timer);

	DRM_DEBUG("vblank_disable: %s\n", dev->vblank_disable_allowed ?
		"allowed" : "denied");
	if (!dev->vblank_disable_allowed) {
		DRM_SPINUNLOCK(&dev->vbl_lock);
		return;
	}

	for (i = 0; i < dev->num_crtcs; i++) {
		if (dev->vblank[i].refcount == 0 &&
		    dev->vblank[i].enabled && !dev->vblank[i].inmodeset) {
			DRM_DEBUG("disabling vblank on crtc %d\n", i);
			dev->vblank[i].last =
			    dev->driver->get_vblank_counter(dev, i);
			dev->driver->disable_vblank(dev, i);
			dev->vblank[i].enabled = 0;
		}
	}
	DRM_SPINUNLOCK(&dev->vbl_lock);
}

void drm_vblank_cleanup(struct drm_device *dev)
{
	/* Bail if the driver didn't call drm_vblank_init() */
	if (dev->num_crtcs == 0)
		return;

	DRM_SPINLOCK(&dev->vbl_lock);
	callout_stop(&dev->vblank_disable_timer);
	DRM_SPINUNLOCK(&dev->vbl_lock);

	vblank_disable_fn((void *)dev);

	free(dev->vblank, DRM_MEM_DRIVER);

	dev->num_crtcs = 0;
}

int drm_vblank_init(struct drm_device *dev, int num_crtcs)
{
	int i, ret = ENOMEM;

	callout_init(&dev->vblank_disable_timer);
	dev->num_crtcs = num_crtcs;

#ifdef DRM_NEWER_LOCK
	dev->vblank = malloc(sizeof(struct drm_vblank_info) * num_crtcs,
	    DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
#else
	dev->vblank = malloc(sizeof(struct drm_vblank_info) * num_crtcs,
	    DRM_MEM_DRIVER, M_NOWAIT | M_ZERO);
#endif
	if (!dev->vblank)
	    goto err;

	DRM_DEBUG("\n");

	/* Zero per-crtc vblank stuff */
	DRM_SPINLOCK(&dev->vbl_lock);
	for (i = 0; i < num_crtcs; i++) {
		DRM_INIT_WAITQUEUE(&dev->vblank[i].queue);
		dev->vblank[i].refcount = 0;
		atomic_set_rel_32(&dev->vblank[i].count, 0);
	}
	dev->vblank_disable_allowed = 0;
	DRM_SPINUNLOCK(&dev->vbl_lock);

	return 0;

err:
	drm_vblank_cleanup(dev);
	return ret;
}

/**
 * Install IRQ handler.
 *
 * \param dev DRM device.
 *
 * Initializes the IRQ related data. Installs the handler, calling the driver
 * \c drm_driver_irq_preinstall() and \c drm_driver_irq_postinstall() functions
 * before and after the installation.
 */
int drm_irq_install(struct drm_device *dev)
{
	int crtc, retcode;

	if (dev->irq == 0 || dev->dev_private == NULL)
		return EINVAL;

	DRM_DEBUG("irq=%d\n", dev->irq);

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif
	if (dev->irq_enabled) {
#ifdef DRM_NEWER_LOCK
		mutex_unlock(&dev->struct_mutex);
#else
		DRM_UNLOCK();
#endif
		return EBUSY;
	}
	dev->irq_enabled = 1;

	dev->context_flag = 0;

	/* Before installing handler */
	dev->driver->irq_preinstall(dev);
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif

	/* Install handler */
	retcode = bus_setup_intr(dev->device, dev->irqr, INTR_MPSAFE,
				 dev->driver->irq_handler, dev, &dev->irqh,
				 &dev->irq_lock);
	if (retcode != 0)
		goto err;

	/* After installing handler */
#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif
	dev->driver->irq_postinstall(dev);
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif
	if (dev->driver->enable_vblank) {
		DRM_SPINLOCK(&dev->vbl_lock);
		for( crtc = 0 ; crtc < dev->num_crtcs ; crtc++) {
			if (dev->driver->enable_vblank(dev, crtc) == 0) {
				dev->vblank[crtc].enabled = 1;
			}
		}
		callout_reset(&dev->vblank_disable_timer, 5 * DRM_HZ,
		    (timeout_t *)vblank_disable_fn, (void *)dev);
		DRM_SPINUNLOCK(&dev->vbl_lock);
	}

	return 0;
err:
#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#else
	DRM_LOCK();
#endif
	dev->irq_enabled = 0;
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#else
	DRM_UNLOCK();
#endif

	return retcode;
}

/**
 * Uninstall the IRQ handler.
 *
 * \param dev DRM device.
 *
 * Calls the driver's \c drm_driver_irq_uninstall() function, and stops the irq.
 */
int drm_irq_uninstall(struct drm_device * dev)
{
	int irq_enabled, crtc;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
		return EINVAL;

#ifdef DRM_NEWER_LOCK
	mutex_lock(&dev->struct_mutex);
#endif
	irq_enabled = dev->irq_enabled;
	dev->irq_enabled = 0;
#ifdef DRM_NEWER_LOCK
	mutex_unlock(&dev->struct_mutex);
#endif

	/*
	* Wake up any waiters so they don't hang.
	*/
	DRM_SPINLOCK(&dev->vbl_lock);
	for (crtc = 0; crtc < dev->num_crtcs; crtc++) {
		if (dev->vblank[crtc].enabled) {
			DRM_WAKEUP(&dev->vblank[crtc].queue);
			dev->vblank[crtc].last =
			    dev->driver->get_vblank_counter(dev, crtc);
			dev->vblank[crtc].enabled = 0;
		}
	}
	DRM_SPINUNLOCK(&dev->vbl_lock);

	if (!irq_enabled)
		return EINVAL;

	DRM_DEBUG("irq=%d\n", dev->irq);

#ifdef __linux__
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		vga_client_register(dev->pdev, NULL, NULL, NULL);
#endif /* __linux__ */

	dev->driver->irq_uninstall(dev);

#ifndef DRM_NEWER_LOCK
	DRM_UNLOCK();
#endif

#ifdef __linux__
	free_irq(dev->pdev->irq, dev);
#else
	bus_teardown_intr(dev->device, dev->irqr, dev->irqh);
#endif /* __linux__ */

#ifndef DRM_NEWER_LOCK
	DRM_LOCK();
#endif

	return 0;
}

/**
 * IRQ control ioctl.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_control structure.
 * \return zero on success or a negative number on failure.
 *
 * Calls irq_install() or irq_uninstall() according to \p arg.
 */
int drm_control(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_control *ctl = data;
	int err;

	switch (ctl->func) {
	case DRM_INST_HANDLER:
		/* Handle drivers whose DRM used to require IRQ setup but the
		 * no longer does.
		 */
		if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
			return 0;
#ifdef DRM_NEWER_LOCK
		if (drm_core_check_feature(dev, DRIVER_MODESET))
			return 0;
#endif
		if (dev->if_version < DRM_IF_VERSION(1, 2) &&
		    ctl->irq != dev->irq)
			return EINVAL;
		return drm_irq_install(dev);
	case DRM_UNINST_HANDLER:
		if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
			return 0;
#ifdef DRM_NEWER_LOCK
		if (drm_core_check_feature(dev, DRIVER_MODESET))
			return 0;
#endif

#ifndef DRM_NEWER_LOCK
		DRM_LOCK();
#endif
		err = drm_irq_uninstall(dev);
#ifndef DRM_NEWER_LOCK
		DRM_UNLOCK();
#endif
		return err;
	default:
		return EINVAL;
	}
}

/**
 * drm_vblank_count - retrieve "cooked" vblank counter value
 * @dev: DRM device
 * @crtc: which counter to retrieve
 *
 * Fetches the "cooked" vblank count value that represents the number of
 * vblank events since the system was booted, including lost events due to
 * modesetting activity.
 */
u32 drm_vblank_count(struct drm_device *dev, int crtc)
{
	return atomic_load_acq_32(&dev->vblank[crtc].count);
}

/**
 * drm_update_vblank_count - update the master vblank counter
 * @dev: DRM device
 * @crtc: counter to update
 *
 * Call back into the driver to update the appropriate vblank counter
 * (specified by @crtc).  Deal with wraparound, if it occurred, and
 * update the last read value so we can deal with wraparound on the next
 * call if necessary.
 *
 * Only necessary when going from off->on, to account for frames we
 * didn't get an interrupt for.
 *
 * Note: caller must hold dev->vbl_lock since this reads & writes
 * device vblank fields.
 */
static void drm_update_vblank_count(struct drm_device *dev, int crtc)
{
	u32 cur_vblank, diff;

	/*
	 * Interrupts were disabled prior to this call, so deal with counter
	 * wrap if needed.
	 * NOTE!  It's possible we lost a full dev->max_vblank_count events
	 * here if the register is small or we had vblank interrupts off for
	 * a long time.
	 */
	cur_vblank = dev->driver->get_vblank_counter(dev, crtc);
	diff = cur_vblank - dev->vblank[crtc].last;
	if (cur_vblank < dev->vblank[crtc].last) {
		diff += dev->max_vblank_count;

		DRM_DEBUG("vblank[%d].last=0x%x, cur_vblank=0x%x => diff=0x%x\n",
		    crtc, dev->vblank[crtc].last, cur_vblank, diff);
	}

	DRM_DEBUG("enabling vblank interrupts on crtc %d, missed %d\n",
	    crtc, diff);

	atomic_add_rel_32(&dev->vblank[crtc].count, diff);
}

/**
 * drm_vblank_get - get a reference count on vblank events
 * @dev: DRM device
 * @crtc: which CRTC to own
 *
 * Acquire a reference count on vblank events to avoid having them disabled
 * while in use.
 *
 * RETURNS
 * Zero on success, nonzero on failure.
 */
int drm_vblank_get(struct drm_device *dev, int crtc)
{
	int ret = 0;

	/* Make sure that we are called with the lock held */
	KKASSERT(lockstatus(&dev->vbl_lock, curthread) != 0);

#ifdef DRM_NEWER_LOCK
	DRM_SPINLOCK(&dev->vbl_lock);
#endif
	/* Going from 0->1 means we have to enable interrupts again */
	if (++dev->vblank[crtc].refcount == 1 &&
	    !dev->vblank[crtc].enabled) {
		ret = dev->driver->enable_vblank(dev, crtc);
		DRM_DEBUG("enabling vblank on crtc %d, ret: %d\n", crtc, ret);
		if (ret)
			--dev->vblank[crtc].refcount;
		else {
			dev->vblank[crtc].enabled = 1;
			drm_update_vblank_count(dev, crtc);
		}
	}

	if (dev->vblank[crtc].enabled)
		dev->vblank[crtc].last =
		    dev->driver->get_vblank_counter(dev, crtc);

#ifdef DRM_NEWER_LOCK
	DRM_SPINUNLOCK(&dev->vbl_lock);
#endif
	return ret;
}

/**
 * drm_vblank_put - give up ownership of vblank events
 * @dev: DRM device
 * @crtc: which counter to give up
 *
 * Release ownership of a given vblank counter, turning off interrupts
 * if possible.
 */
void drm_vblank_put(struct drm_device *dev, int crtc)
{
	/* Make sure that we are called with the lock held */
	KKASSERT(lockstatus(&dev->vbl_lock, curthread) != 0);

	KASSERT(dev->vblank[crtc].refcount > 0,
	    ("invalid refcount"));

#ifdef DRM_NEWER_LOCK
	DRM_SPINLOCK(&dev->vbl_lock);
#endif

	/* Last user schedules interrupt disable */
	if (--dev->vblank[crtc].refcount == 0)
	    callout_reset(&dev->vblank_disable_timer, 5 * DRM_HZ,
		(timeout_t *)vblank_disable_fn, (void *)dev);

#ifdef DRM_NEWER_LOCK
	DRM_SPINUNLOCK(&dev->vbl_lock);
#endif
}

/**
 * drm_modeset_ctl - handle vblank event counter changes across mode switch
 * @DRM_IOCTL_ARGS: standard ioctl arguments
 *
 * Applications should call the %_DRM_PRE_MODESET and %_DRM_POST_MODESET
 * ioctls around modesetting so that any lost vblank events are accounted for.
 *
 * Generally the counter will reset across mode sets.  If interrupts are
 * enabled around this call, we don't have to do anything since the counter
 * will have already been incremented.
 */
int drm_modeset_ctl(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct drm_modeset_ctl *modeset = data;
	int crtc, ret = 0;

	/* If drm_vblank_init() hasn't been called yet, just no-op */
	if (!dev->num_crtcs)
		goto out;

	crtc = modeset->crtc;
	if (crtc >= dev->num_crtcs) {
		ret = EINVAL;
		goto out;
	}

	/*
	 * To avoid all the problems that might happen if interrupts
	 * were enabled/disabled around or between these calls, we just
	 * have the kernel take a reference on the CRTC (just once though
	 * to avoid corrupting the count if multiple, mismatch calls occur),
	 * so that interrupts remain enabled in the interim.
	 */
	switch (modeset->cmd) {
/**
 * drm_vblank_pre_modeset - account for vblanks across mode sets
 * @dev: DRM device
 * @crtc: CRTC in question
 * @post: post or pre mode set?
 *
 * Account for vblank events across mode setting events, which will likely
 * reset the hardware frame counter.
 */
	case _DRM_PRE_MODESET:
		DRM_DEBUG("pre-modeset, crtc %d\n", crtc);
#ifndef DRM_NEWER_LOCK
		DRM_SPINLOCK(&dev->vbl_lock);
#endif
	/*
	 * To avoid all the problems that might happen if interrupts
	 * were enabled/disabled around or between these calls, we just
	 * have the kernel take a reference on the CRTC (just once though
	 * to avoid corrupting the count if multiple, mismatch calls occur),
	 * so that interrupts remain enabled in the interim.
	 */
		if (!dev->vblank[crtc].inmodeset) {
			dev->vblank[crtc].inmodeset = 0x1;
			if (drm_vblank_get(dev, crtc) == 0)
				dev->vblank[crtc].inmodeset |= 0x2;
		}
#ifndef DRM_NEWER_LOCK
		DRM_SPINUNLOCK(&dev->vbl_lock);
#endif
		break;
	case _DRM_POST_MODESET:
		DRM_DEBUG("post-modeset, crtc %d\n", crtc);
		DRM_SPINLOCK(&dev->vbl_lock);
		if (dev->vblank[crtc].inmodeset) {
			if (dev->vblank[crtc].inmodeset & 0x2)
				drm_vblank_put(dev, crtc);
			dev->vblank[crtc].inmodeset = 0;
		}
		dev->vblank_disable_allowed = 1;
		DRM_SPINUNLOCK(&dev->vbl_lock);
		break;
	default:
		ret = EINVAL;
		break;
	}

out:
	return ret;
}

/**
 * Wait for VBLANK.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param data user argument, pointing to a drm_wait_vblank structure.
 * \return zero on success or a negative number on failure.
 *
 * This function enables the vblank interrupt on the pipe requested, then
 * sleeps waiting for the requested sequence number to occur, and drops
 * the vblank interrupt refcount afterwards. (vblank irq disable follows that
 * after a timeout with no further vblank waits scheduled).
 */
int drm_wait_vblank(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	union drm_wait_vblank *vblwait = data;
	unsigned int flags, seq, crtc;
	int ret = 0;

	if (!dev->irq_enabled)
		return EINVAL;

	if (vblwait->request.type &
	    ~(_DRM_VBLANK_TYPES_MASK | _DRM_VBLANK_FLAGS_MASK)) {
		DRM_ERROR("Unsupported type value 0x%x, supported mask 0x%x\n",
		    vblwait->request.type,
		    (_DRM_VBLANK_TYPES_MASK | _DRM_VBLANK_FLAGS_MASK));
		return EINVAL;
	}

	flags = vblwait->request.type & _DRM_VBLANK_FLAGS_MASK;
	crtc = flags & _DRM_VBLANK_SECONDARY ? 1 : 0;

	if (crtc >= dev->num_crtcs)
		return EINVAL;

#ifndef DRM_NEWER_LOCK
	DRM_SPINLOCK(&dev->vbl_lock);
#endif
	ret = drm_vblank_get(dev, crtc);
#ifndef DRM_NEWER_LOCK
	DRM_SPINUNLOCK(&dev->vbl_lock);
#endif
	if (ret) {
		DRM_ERROR("failed to acquire vblank counter, %d\n", ret);
		return ret;
	}
	seq = drm_vblank_count(dev, crtc);

	switch (vblwait->request.type & _DRM_VBLANK_TYPES_MASK) {
	case _DRM_VBLANK_RELATIVE:
		vblwait->request.sequence += seq;
		vblwait->request.type &= ~_DRM_VBLANK_RELATIVE;
	case _DRM_VBLANK_ABSOLUTE:
		break;
	default:
		ret = EINVAL;
		goto done;
	}

	if ((flags & _DRM_VBLANK_NEXTONMISS) &&
	    (seq - vblwait->request.sequence) <= (1<<23)) {
		vblwait->request.sequence = seq + 1;
	}

	if (flags & _DRM_VBLANK_SIGNAL) {
		/* There have never been any consumers */
		ret = EINVAL;
	} else {
		DRM_DEBUG("waiting on vblank count %d, crtc %d\n",
		    vblwait->request.sequence, crtc);
		for ( ret = 0 ; !ret && !(((drm_vblank_count(dev, crtc) -
		    vblwait->request.sequence) <= (1 << 23)) ||
		    !dev->irq_enabled) ; ) {
			lwkt_serialize_enter(&dev->irq_lock);
			if (!(((drm_vblank_count(dev, crtc) -
			    vblwait->request.sequence) <= (1 << 23)) ||
			    !dev->irq_enabled))
				ret = zsleep(&dev->vblank[crtc].queue,
				    &dev->irq_lock, PCATCH, "vblwtq",
				    DRM_HZ);
			lwkt_serialize_exit(&dev->irq_lock);
		}

		if (ret != EINTR && ret != ERESTART) {
			struct timeval now;

			microtime(&now);
			vblwait->reply.tval_sec = now.tv_sec;
			vblwait->reply.tval_usec = now.tv_usec;
			vblwait->reply.sequence = drm_vblank_count(dev, crtc);
			DRM_DEBUG("returning %d to client, irq_enabled %d\n",
			    vblwait->reply.sequence, dev->irq_enabled);
		} else {
			DRM_DEBUG("vblank wait interrupted by signal\n");
		}
	}

done:
#ifndef DRM_NEWER_LOCK
	DRM_SPINLOCK(&dev->vbl_lock);
#endif
	drm_vblank_put(dev, crtc);
#ifndef DRM_NEWER_LOCK
	DRM_SPINUNLOCK(&dev->vbl_lock);
#endif

	return ret;
}

void drm_handle_vblank(struct drm_device *dev, int crtc)
{
	atomic_add_rel_32(&dev->vblank[crtc].count, 1);
	DRM_WAKEUP(&dev->vblank[crtc].queue);
}

/* newer UNIMPLEMENTED */
void drm_vblank_off(struct drm_device *dev, int crtc)
{
	unsigned long irqflags;

	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	dev->driver->disable_vblank(dev, crtc);
	DRM_WAKEUP(&dev->vbl_queue[crtc]);
	dev->vblank_enabled[crtc] = 0;
	dev->last_vblank[crtc] = dev->driver->get_vblank_counter(dev, crtc);
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
}
EXPORT_SYMBOL(drm_vblank_off);

/**
 * drm_vblank_pre_modeset - account for vblanks across mode sets
 * @dev: DRM device
 * @crtc: CRTC in question
 * @post: post or pre mode set?
 *
 * Account for vblank events across mode setting events, which will likely
 * reset the hardware frame counter.
 */
void drm_vblank_pre_modeset(struct drm_device *dev, int crtc)
{
	/* vblank is not initialized (IRQ not installed ?) */
	if (!dev->num_crtcs)
		return;
	/*
	 * To avoid all the problems that might happen if interrupts
	 * were enabled/disabled around or between these calls, we just
	 * have the kernel take a reference on the CRTC (just once though
	 * to avoid corrupting the count if multiple, mismatch calls occur),
	 * so that interrupts remain enabled in the interim.
	 */
	if (!dev->vblank_inmodeset[crtc]) {
		dev->vblank_inmodeset[crtc] = 0x1;
		if (drm_vblank_get(dev, crtc) == 0)
			dev->vblank_inmodeset[crtc] |= 0x2;
	}
}
EXPORT_SYMBOL(drm_vblank_pre_modeset);

void drm_vblank_post_modeset(struct drm_device *dev, int crtc)
{
	unsigned long irqflags;

	if (dev->vblank_inmodeset[crtc]) {
		spin_lock_irqsave(&dev->vbl_lock, irqflags);
		dev->vblank_disable_allowed = 1;
		spin_unlock_irqrestore(&dev->vbl_lock, irqflags);

		if (dev->vblank_inmodeset[crtc] & 0x2)
			drm_vblank_put(dev, crtc);

		dev->vblank_inmodeset[crtc] = 0;
	}
}
EXPORT_SYMBOL(drm_vblank_post_modeset);

#ifdef __linux__ /* enable when update drm_handle_vblank */
void drm_handle_vblank_events(struct drm_device *dev, int crtc)
{
	struct drm_pending_vblank_event *e, *t;
	struct timeval now;
	unsigned long flags;
	unsigned int seq;

#ifdef __linux__
	do_gettimeofday(&now);
#else
	microtime(&now);
#endif
	seq = drm_vblank_count(dev, crtc);

	spin_lock_irqsave(&dev->event_lock, flags);

	list_for_each_entry_safe(e, t, &dev->vblank_event_list, base.link) {
		if (e->pipe != crtc)
			continue;
		if ((seq - e->event.sequence) > (1<<23))
			continue;

		DRM_DEBUG("vblank event on %d, current %d\n",
			  e->event.sequence, seq);

		e->event.sequence = seq;
#ifdef __linux__
		e->event.tv_sec = now.tv_sec;
		e->event.tv_usec = now.tv_usec;
#else
		e->event.tv_sec = (uint32_t)now.tv_sec;
		e->event.tv_usec = (uint32_t)now.tv_usec;
#endif
		drm_vblank_put(dev, e->pipe);
		list_move_tail(&e->base.link, &e->base.file_priv->event_list);
		wake_up_interruptible(&e->base.file_priv->event_wait);
	}

	spin_unlock_irqrestore(&dev->event_lock, flags);
}
#endif /* __linux__ */
