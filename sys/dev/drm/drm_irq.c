/**
 * \file drm_irq.c
 * IRQ support
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Fri Mar 19 14:30:16 1999 by faith@valinux.com
 *
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
 */

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

#include "drmP.h"

#ifdef __linux__
#include <linux/interrupt.h>	/* For task queue support */
#include <linux/slab.h>

#include <linux/vgaarb.h>
#endif /* __linux__ */

#define DRM_NEWER_IRQRISK 1
#define DRM_NEWER_IRQSYNCH 1

#ifdef DRM_NEWER_IRQSYNCH
static int drm_msi = 1;	/* Enable by default. */
TUNABLE_INT("hw.drm.msi", &drm_msi);

static struct drm_msi_blacklist_entry drm_msi_blacklist[] = {
	{0x8086, 0x2772}, /* Intel i945G	*/ \
	{0x8086, 0x27A2}, /* Intel i945GM	*/ \
	{0x8086, 0x27AE}, /* Intel i945GME	*/ \
	{0, 0}
};

static int drm_msi_is_blacklisted(int vendor, int device)
{
	int i = 0;

	for (i = 0; drm_msi_blacklist[i].vendor != 0; i++) {
		if ((drm_msi_blacklist[i].vendor == vendor) &&
		    (drm_msi_blacklist[i].device == device)) {
			return 1;
		}
	}

	return 0;
}
#endif /* DRM_NEWER_IRQSYNCH */

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
	struct drm_irq_busid *p = data;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
		return -EINVAL;

#ifdef __linux__
	if ((p->busnum >> 8) != drm_get_pci_domain(dev) ||
	    (p->busnum & 0xff) != dev->pdev->bus->number ||
	    p->devnum != PCI_SLOT(dev->pdev->devfn) || p->funcnum != PCI_FUNC(dev->pdev->devfn))
#else
	if ((p->busnum >> 8) != dev->pci_domain ||
	    (p->busnum & 0xff) != dev->pci_bus ||
	    p->devnum != dev->pci_slot || p->funcnum != dev->pci_func)
#endif
		return -EINVAL;

#ifdef __linux__
	p->irq = dev->pdev->irq;
#else
	p->irq = dev->irq;
#endif

	DRM_DEBUG("%d:%d:%d => IRQ %d\n", p->busnum, p->devnum, p->funcnum,
		  p->irq);

	return 0;
}

#ifdef __linux__
static void vblank_disable_fn(unsigned long arg)
#else
static void vblank_disable_fn(void *arg)
#endif
{
	struct drm_device *dev = (struct drm_device *)arg;
	unsigned long irqflags;
	int i;

#ifndef __linux__
	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	
	if (callout_pending(&dev->vblank_disable_timer)) {
		/* callout was reset */
		spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
		return;
	}
	if (!callout_active(&dev->vblank_disable_timer)) {
		/* callout was stopped */
		spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
		return;
	}
	callout_deactivate(&dev->vblank_disable_timer);
#endif

	if (!dev->vblank_disable_allowed) {
		spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
		return;
	}

	for (i = 0; i < dev->num_crtcs; i++) {
		if (atomic_read(&dev->vblank_refcount[i]) == 0 &&
		    dev->vblank_enabled[i]) {
			DRM_DEBUG("disabling vblank on crtc %d\n", i);
			dev->last_vblank[i] =
				dev->driver->get_vblank_counter(dev, i);
			dev->driver->disable_vblank(dev, i);
			dev->vblank_enabled[i] = 0;
		}
	}
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);
}

void drm_vblank_cleanup(struct drm_device *dev)
{
	/* Bail if the driver didn't call drm_vblank_init() */
	if (dev->num_crtcs == 0)
		return;

#ifdef __linux__
	del_timer(&dev->vblank_disable_timer);
#else
	DRM_SPINLOCK(&dev->vbl_lock);
	callout_stop(&dev->vblank_disable_timer);
	DRM_SPINUNLOCK(&dev->vbl_lock);
#endif

#ifdef __linux__
	vblank_disable_fn((unsigned long)dev);
#else
	vblank_disable_fn((void *)dev);
#endif

	free(dev->vbl_queue, DRM_MEM_DRIVER);
	free(dev->_vblank_count, DRM_MEM_DRIVER);
	free(dev->vblank_refcount, DRM_MEM_DRIVER);
	free(dev->vblank_enabled, DRM_MEM_DRIVER);
	free(dev->last_vblank, DRM_MEM_DRIVER);
	free(dev->last_vblank_wait, DRM_MEM_DRIVER);
	free(dev->vblank_inmodeset, DRM_MEM_DRIVER);

	dev->num_crtcs = 0;
}
EXPORT_SYMBOL(drm_vblank_cleanup);

int drm_vblank_init(struct drm_device *dev, int num_crtcs)
{
	int i, ret = -ENOMEM;

#ifdef __linux__
	setup_timer(&dev->vblank_disable_timer, vblank_disable_fn,
		    (unsigned long)dev);
#else
	callout_init(&dev->vblank_disable_timer);
#endif
	DRM_SPININIT(&dev->vbl_lock, "drmvbl");
	dev->num_crtcs = num_crtcs;

	dev->vbl_queue = malloc(sizeof(wait_queue_head_t) * num_crtcs,
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->vbl_queue)
		goto err;

	dev->_vblank_count = malloc(sizeof(atomic_t) * num_crtcs,
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->_vblank_count)
		goto err;

	dev->vblank_refcount = malloc(sizeof(atomic_t) * num_crtcs,
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->vblank_refcount)
		goto err;

	dev->vblank_enabled = malloc(num_crtcs * sizeof(int),
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->vblank_enabled)
		goto err;

	dev->last_vblank = malloc(num_crtcs * sizeof(u32),
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->last_vblank)
		goto err;

	dev->last_vblank_wait = malloc(num_crtcs * sizeof(u32),
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->last_vblank_wait)
		goto err;

	dev->vblank_inmodeset = malloc(num_crtcs * sizeof(int),
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!dev->vblank_inmodeset)
		goto err;

	/* Zero per-crtc vblank stuff */
	DRM_SPINLOCK(&dev->vbl_lock);
	for (i = 0; i < num_crtcs; i++) {
		DRM_INIT_WAITQUEUE(&dev->vbl_queue[i]);
		atomic_set_rel_32(&dev->vblank_refcount[i], 0);
		atomic_set_rel_32(&dev->_vblank_count[i], 0);
	}

	dev->vblank_disable_allowed = 0;
	DRM_SPINUNLOCK(&dev->vbl_lock);
	return 0;

err:
	drm_vblank_cleanup(dev);
	return ret;
}
EXPORT_SYMBOL(drm_vblank_init);

static void drm_irq_vgaarb_nokms(void *cookie, bool state)
{
	struct drm_device *dev = cookie;

	if (dev->driver->vgaarb_irq) {
		dev->driver->vgaarb_irq(dev, state);
		return;
	}

	if (!dev->irq_enabled)
		return;

	if (state)
		dev->driver->irq_uninstall(dev);
	else {
		dev->driver->irq_preinstall(dev);
		dev->driver->irq_postinstall(dev);
	}
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
	int ret = 0;
#ifdef __linux__
	unsigned long sh_flags = 0;
	char *irqname;
#else /* !__linux__ */
#ifdef DRM_NEWER_IRQSYNCH
	int sh_flags = 0;
#if 0
	int msicount;
#endif
#endif /* DRM_NEWER_IRQSYNCH */
#endif /* __linux__ */

	if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
		return -EINVAL;

	if (dev->irq == 0)
		return -EINVAL;

	mutex_lock(&dev->struct_mutex);

	/* Driver must have been initialized */
	if (!dev->dev_private) {
		mutex_unlock(&dev->struct_mutex);
		return -EINVAL;
	}

	if (dev->irq_enabled) {
		mutex_unlock(&dev->struct_mutex);
		return -EBUSY;
	}
	dev->irq_enabled = 1;
	mutex_unlock(&dev->struct_mutex);

	DRM_DEBUG("irq=%d\n", dev->irq);

	/* Before installing handler */
	dev->driver->irq_preinstall(dev);

	/* Install handler */
#ifdef __linux__
	if (drm_core_check_feature(dev, DRIVER_IRQ_SHARED))
		sh_flags = IRQF_SHARED;

	if (dev->devname)
		irqname = dev->devname;
	else
		irqname = dev->driver->name;
#else
#ifdef DRM_NEWER_IRQSYNCH
	if (drm_core_check_feature(dev, DRIVER_IRQ_SHARED))
		sh_flags = RF_SHAREABLE | RF_ACTIVE;
#endif
#endif /* __linux__ */

#ifdef __linux__
	ret = request_irq(drm_dev_to_irq(dev), dev->driver->irq_handler,
			  sh_flags, irqname, dev);
#else
#ifdef DRM_NEWER_IRQSYNCH
	if (drm_msi &&
		!drm_msi_is_blacklisted(dev->pci_vendor, dev->pci_device)) {
#if 0
		msicount = pci_msi_count(dev->device);
		DRM_DEBUG("MSI count = %d\n", msicount);
		if (msicount > 1)
			msicount = 1;

		if (pci_alloc_msi(dev->device, &msicount) == 0) {
			DRM_INFO("MSI enabled %d message(s)\n",
			    msicount);
			dev->msi_enabled = 1;
			dev->irqrid = 1;
		}
#endif
	}

	dev->irqr = bus_alloc_resource_any(dev->device, SYS_RES_IRQ,
		&dev->irqrid, sh_flags);
	if (!dev->irqr) {
		return -ENOENT;
	}

	dev->irq = (int) rman_get_start(dev->irqr);
#endif /* DRM_NEWER_IRQSYNCH */
	ret = bus_setup_intr(dev->device, dev->irqr, INTR_MPSAFE,
				 dev->driver->irq_handler, dev, &dev->irqh,
				 &dev->irq_lock);
#endif /* __linux__ */

	if (ret != 0) {
		mutex_lock(&dev->struct_mutex);
		dev->irq_enabled = 0;
		mutex_unlock(&dev->struct_mutex);
		return ret;
	}

#ifdef __linux__
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		vga_client_register(dev->pdev, (void *)dev, drm_irq_vgaarb_nokms, NULL);
#endif /* __linux__ */

	/* After installing handler */
	ret = dev->driver->irq_postinstall(dev);
	if (ret != 0) {
		mutex_lock(&dev->struct_mutex);
		dev->irq_enabled = 0;
		mutex_unlock(&dev->struct_mutex);
	}

	return ret;
}
EXPORT_SYMBOL(drm_irq_install);

/**
 * Uninstall the IRQ handler.
 *
 * \param dev DRM device.
 *
 * Calls the driver's \c drm_driver_irq_uninstall() function, and stops the irq.
 */
int drm_irq_uninstall(struct drm_device * dev)
{
	unsigned long irqflags;
	int irq_enabled, i;

	if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
		return -EINVAL;

	mutex_lock(&dev->struct_mutex);
	irq_enabled = dev->irq_enabled;
	dev->irq_enabled = 0;
	mutex_unlock(&dev->struct_mutex);

	/*
	* Wake up any waiters so they don't hang.
	*/
	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	for (i = 0; i < dev->num_crtcs; i++) {
		DRM_WAKEUP(&dev->vbl_queue[i]);
		dev->vblank_enabled[i] = 0;
		dev->last_vblank[i] = dev->driver->get_vblank_counter(dev, i);
#if 0
		if (dev->vblank_enabled[i]) {
			DRM_WAKEUP(&dev->vbl_queue[i]);
			dev->vblank_enabled[i] = 0;
			dev->last_vblank[i] = dev->driver->get_vblank_counter(dev, i);
		}
		else {
			DRM_ERROR("vblank_enabled[%d] == 0\n", i);
		}
#endif
	}
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);

	if (!irq_enabled)
		return -EINVAL;

	DRM_DEBUG("irq=%d\n", dev->irq);

#ifdef __linux__
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		vga_client_register(dev->pdev, NULL, NULL, NULL);
#endif /* __linux__ */

	dev->driver->irq_uninstall(dev);

#ifdef __linux__
	free_irq(dev->pdev->irq, dev);
#else
	bus_teardown_intr(dev->device, dev->irqr, dev->irqh);
#endif

	return 0;
}
EXPORT_SYMBOL(drm_irq_uninstall);

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
int drm_control(struct drm_device *dev, void *data,
		struct drm_file *file_priv)
{
	struct drm_control *ctl = data;

	/* if we haven't irq we fallback for compatibility reasons - this used to be a separate function in drm_dma.h */


	switch (ctl->func) {
	case DRM_INST_HANDLER:
		if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
			return 0;
		if (drm_core_check_feature(dev, DRIVER_MODESET))
			return 0;
		if (dev->if_version < DRM_IF_VERSION(1, 2) &&
		    ctl->irq != dev->irq)
			return -EINVAL;
		return drm_irq_install(dev);
	case DRM_UNINST_HANDLER:
		if (!drm_core_check_feature(dev, DRIVER_HAVE_IRQ))
			return 0;
		if (drm_core_check_feature(dev, DRIVER_MODESET))
			return 0;
		return drm_irq_uninstall(dev);
	default:
		return -EINVAL;
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
#ifdef __linux__
	return atomic_read(&dev->_vblank_count[crtc]);
#else
	return atomic_load_acq_32(&dev->_vblank_count[crtc]);
#endif
}
EXPORT_SYMBOL(drm_vblank_count);

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
	diff = cur_vblank - dev->last_vblank[crtc];
	if (cur_vblank < dev->last_vblank[crtc]) {
		diff += dev->max_vblank_count;

		DRM_DEBUG("last_vblank[%d]=0x%x, cur_vblank=0x%x => diff=0x%x\n",
			  crtc, dev->last_vblank[crtc], cur_vblank, diff);
	}

	DRM_DEBUG("enabling vblank interrupts on crtc %d, missed %d\n",
		  crtc, diff);

#ifdef __linux__
	atomic_add(diff, &dev->_vblank_count[crtc]);
#else
	atomic_add_rel_32(&dev->_vblank_count[crtc], diff);
#endif
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
	unsigned long irqflags;
	int ret = 0;

	spin_lock_irqsave(&dev->vbl_lock, irqflags);
	/* Going from 0->1 means we have to enable interrupts again */
	if (atomic_fetchadd_int(&dev->vblank_refcount[crtc], 1) == 0) {
		if (!dev->vblank_enabled[crtc]) {
			ret = dev->driver->enable_vblank(dev, crtc);
			DRM_DEBUG("enabling vblank on crtc %d, ret: %d\n", crtc, ret);
			if (ret)
				atomic_dec(&dev->vblank_refcount[crtc]);
			else {
				dev->vblank_enabled[crtc] = 1;
				drm_update_vblank_count(dev, crtc);
			}
		}
	} else {
		if (!dev->vblank_enabled[crtc]) {
			atomic_dec(&dev->vblank_refcount[crtc]);
			ret = -EINVAL;
		}
	}
	spin_unlock_irqrestore(&dev->vbl_lock, irqflags);

	return ret;
}
EXPORT_SYMBOL(drm_vblank_get);

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
#ifdef __linux__
	BUG_ON (atomic_read (&dev->vblank_refcount[crtc]) == 0);
#else
	KASSERT(dev->vblank_refcount[crtc] > 0, ("invalid refcount"));
#endif

	DRM_SPINLOCK(&dev->vbl_lock);

	/* Last user schedules interrupt disable */
#ifdef __linux__
	if (atomic_dec_and_test(&dev->vblank_refcount[crtc]))
		mod_timer(&dev->vblank_disable_timer, jiffies + 5*DRM_HZ);
#else
	if (atomic_fetchadd_int(&dev->vblank_refcount[crtc], -1) == 1)
		callout_reset(&dev->vblank_disable_timer, 5 * DRM_HZ,
			(timeout_t *)vblank_disable_fn, (void *)dev);
#endif

	DRM_SPINUNLOCK(&dev->vbl_lock);
}
EXPORT_SYMBOL(drm_vblank_put);

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
		ret = -EINVAL;
		goto out;
	}

	switch (modeset->cmd) {
	case _DRM_PRE_MODESET:
		drm_vblank_pre_modeset(dev, crtc);
		break;
	case _DRM_POST_MODESET:
		drm_vblank_post_modeset(dev, crtc);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	return ret;
}

#ifndef __linux__
static void destroy_event(struct drm_pending_event *e) {
	free(e, DRM_MEM_DRIVER);
}
#endif

static int drm_queue_vblank_event(struct drm_device *dev, int pipe,
				  union drm_wait_vblank *vblwait,
				  struct drm_file *file_priv)
{
	struct drm_pending_vblank_event *e;
	struct timeval now;
	unsigned long flags;
	unsigned int seq;

	e = malloc(sizeof *e, DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (e == NULL)
		return -ENOMEM;

	e->pipe = pipe;
	e->event.base.type = DRM_EVENT_VBLANK;
	e->event.base.length = sizeof e->event;
	e->event.user_data = vblwait->request.signal;
	e->base.event = &e->event.base;
	e->base.file_priv = file_priv;
#ifdef __linux__
	e->base.destroy = (void (*) (struct drm_pending_event *)) kfree;
#else
	e->base.destroy = (void (*) (struct drm_pending_event *)) destroy_event;
#endif

#ifdef __linux__
	do_gettimeofday(&now);
#else
	microtime(&now);
#endif
	spin_lock_irqsave(&dev->event_lock, flags);

	if (file_priv->event_space < sizeof e->event) {
		spin_unlock_irqrestore(&dev->event_lock, flags);
		free(e, DRM_MEM_DRIVER);
		return -ENOMEM;
	}

	file_priv->event_space -= sizeof e->event;
	seq = drm_vblank_count(dev, pipe);
	if ((vblwait->request.type & _DRM_VBLANK_NEXTONMISS) &&
	    (seq - vblwait->request.sequence) <= (1 << 23)) {
		vblwait->request.sequence = seq + 1;
		vblwait->reply.sequence = vblwait->request.sequence;
	}

#ifdef __linux__
	DRM_DEBUG("event on vblank count %d, current %d, crtc %d\n",
		  vblwait->request.sequence, seq, pipe);
#else
	DRM_INFO("drm_queue_vblank_event(): event on vblank count %d, current %d, crtc %d\n",
		  vblwait->request.sequence, seq, pipe);
#endif

	e->event.sequence = vblwait->request.sequence;
	if ((seq - vblwait->request.sequence) <= (1 << 23)) {
		e->event.tv_sec = now.tv_sec;
		e->event.tv_usec = now.tv_usec;
		drm_vblank_put(dev, e->pipe);
		list_add_tail(&e->base.link, &e->base.file_priv->event_list);
		wake_up_interruptible(&e->base.file_priv->event_wait);
	} else {
		list_add_tail(&e->base.link, &dev->vblank_event_list);
	}

	spin_unlock_irqrestore(&dev->event_lock, flags);

	return 0;
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
int drm_wait_vblank(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	union drm_wait_vblank *vblwait = data;
	int ret = 0;
	unsigned int flags, seq, crtc;

	if (!dev->irq || !dev->irq_enabled)
		return -EINVAL;

	if (vblwait->request.type & _DRM_VBLANK_SIGNAL)
		return -EINVAL;

	if (vblwait->request.type &
	    ~(_DRM_VBLANK_TYPES_MASK | _DRM_VBLANK_FLAGS_MASK)) {
		DRM_ERROR("Unsupported type value 0x%x, supported mask 0x%x\n",
			  vblwait->request.type,
			  (_DRM_VBLANK_TYPES_MASK | _DRM_VBLANK_FLAGS_MASK));
		return -EINVAL;
	}

	flags = vblwait->request.type & _DRM_VBLANK_FLAGS_MASK;
	crtc = flags & _DRM_VBLANK_SECONDARY ? 1 : 0;

	if (crtc >= dev->num_crtcs)
		return -EINVAL;

	ret = drm_vblank_get(dev, crtc);
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
		ret = -EINVAL;
		goto done;
	}

#ifdef DRM_NEWER_IRQRISK
	if (flags & _DRM_VBLANK_EVENT)
		return drm_queue_vblank_event(dev, crtc, vblwait, file_priv);
#endif

	if ((flags & _DRM_VBLANK_NEXTONMISS) &&
	    (seq - vblwait->request.sequence) <= (1<<23)) {
		vblwait->request.sequence = seq + 1;
	}

	DRM_DEBUG("waiting on vblank count %d, crtc %d\n",
		  vblwait->request.sequence, crtc);
	dev->last_vblank_wait[crtc] = vblwait->request.sequence;

#ifdef __linux__
	DRM_WAIT_ON(ret, dev->vbl_queue[crtc], 3 * DRM_HZ,
		    (((drm_vblank_count(dev, crtc) -
		       vblwait->request.sequence) <= (1 << 23)) ||
		     !dev->irq_enabled));
#else
	for ( ret = 0 ; !ret && !(((drm_vblank_count(dev, crtc) -
	    vblwait->request.sequence) <= (1 << 23)) ||
	    !dev->irq_enabled) ; ) {
		lwkt_serialize_enter(&dev->irq_lock);
		if (!(((drm_vblank_count(dev, crtc) -
		    vblwait->request.sequence) <= (1 << 23)) ||
		    !dev->irq_enabled))
			ret = zsleep(&dev->vbl_queue[crtc],
			    &dev->irq_lock, PCATCH, "vblwtq",
			    3 * DRM_HZ);
		lwkt_serialize_exit(&dev->irq_lock);
	}
#endif

	if ((ret != EINTR) && (ret != ERESTART)) {
		struct timeval now;

		microtime(&now);
		vblwait->reply.tval_sec = now.tv_sec;
		vblwait->reply.tval_usec = now.tv_usec;
		vblwait->reply.sequence = drm_vblank_count(dev, crtc);
		DRM_DEBUG("returning %d to client\n",
			  vblwait->reply.sequence);
	} else {
#ifdef __linux__
		DRM_DEBUG("vblank wait interrupted by signal\n");
#else
		DRM_ERROR("vblank wait interrupted by signal (%d)\n", ret);
#endif
	}

done:
	drm_vblank_put(dev, crtc);
	return ret;
}

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

/**
 * drm_handle_vblank - handle a vblank event
 * @dev: DRM device
 * @crtc: where this event occurred
 *
 * Drivers should call this routine in their vblank interrupt handlers to
 * update the vblank counter and send any signals that may be pending.
 */
void drm_handle_vblank(struct drm_device *dev, int crtc)
{
	if (!dev->num_crtcs)
		return;

#ifdef __linux__
	atomic_inc(&dev->_vblank_count[crtc]);
#else
	atomic_add_rel_32(&dev->_vblank_count[crtc], 1);
#endif
	DRM_WAKEUP(&dev->vbl_queue[crtc]);
#if DRM_NEWER_IRQRISK
	drm_handle_vblank_events(dev, crtc);
#endif /* __linux__ */
}
EXPORT_SYMBOL(drm_handle_vblank);
