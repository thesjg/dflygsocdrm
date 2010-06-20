/* i915_drv.c -- Intel i915 driver -*- linux-c -*-
 * Created: Wed Feb 14 17:10:04 2001 by gareth@valinux.com
 */
/*-
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
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

#ifdef __linux__
#include <linux/device.h>
#endif /* __linux */
#include "drmP.h"
#include "drm.h"
#ifndef __linux__
#include "drm_mm.h"
#endif /* __linux__ */
#include "i915_drm.h"
#include "i915_drv.h"

#ifdef __linux__
#include <linux/console.h>
#include "drm_crtc_helper.h"
#else /* __linux__ */
#include "drm_pciids.h"
#endif /* __linux__ */

static int i915_modeset = -1;

static struct drm_driver driver;

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static drm_pci_id_list_t i915_pciidlist[] = {
	i915_PCI_IDS
};

static int i915_suspend(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	if (!dev || !dev->dev_private) {
		DRM_ERROR("DRM not initialized, aborting suspend.\n");
		return -ENODEV;
	}

	DRM_LOCK();
	DRM_DEBUG("starting suspend\n");
	i915_save_state(dev);
	DRM_UNLOCK();

	return (bus_generic_suspend(kdev));
}

static int i915_resume(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	DRM_LOCK();
	i915_restore_state(dev);
	DRM_DEBUG("finished resume\n");
	DRM_UNLOCK();

	return (bus_generic_resume(kdev));
}

static void i915_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	   DRIVER_USE_AGP | DRIVER_REQUIRE_AGP | DRIVER_USE_MTRR |
	   DRIVER_HAVE_IRQ;
/* newer */
	dev->driver->dev_priv_size 	= sizeof(drm_i915_private_t);
	dev->driver->buf_priv_size	= sizeof(drm_i915_private_t);
	dev->driver->load		= i915_driver_load;
	dev->driver->unload		= i915_driver_unload;
	dev->driver->preclose		= i915_driver_preclose;
	dev->driver->lastclose		= i915_driver_lastclose;
	dev->driver->device_is_agp	= i915_driver_device_is_agp;
	dev->driver->enable_vblank	= i915_enable_vblank;
	dev->driver->disable_vblank	= i915_disable_vblank;
	dev->driver->irq_preinstall	= i915_driver_irq_preinstall;
	dev->driver->irq_postinstall	= i915_driver_irq_postinstall;
	dev->driver->irq_uninstall	= i915_driver_irq_uninstall;
	dev->driver->irq_handler	= i915_driver_irq_handler;

	dev->driver->ioctls		= i915_ioctls;
	dev->driver->max_ioctl		= i915_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;

/* newer */
	dev->driver->num_ioctls = i915_max_ioctl;
}

static struct drm_driver driver = {
	/* don't use mtrr's here, the Xserver or user space app should
	 * deal with them for intel hardware.
	 */
	.driver_features =
	    DRIVER_USE_AGP | DRIVER_REQUIRE_AGP | /* DRIVER_USE_MTRR |*/
	    DRIVER_HAVE_IRQ,
	.load = i915_driver_load,
	.unload = i915_driver_unload,
	.lastclose = i915_driver_lastclose,
	.preclose = i915_driver_preclose,
	.postclose = i915_driver_postclose,
#ifdef __linux__
	/* Used in place of i915_pm_ops for non-DRIVER_MODESET */
	.suspend = i915_suspend,
	.resume = i915_resume,
#endif /* __linux__ */

	.device_is_agp = i915_driver_device_is_agp,
	.enable_vblank = i915_enable_vblank,
	.disable_vblank = i915_disable_vblank,
	.irq_preinstall = i915_driver_irq_preinstall,
	.irq_postinstall = i915_driver_irq_postinstall,
	.irq_uninstall = i915_driver_irq_uninstall,
	.irq_handler = i915_driver_irq_handler,
#ifdef __linux__
	.reclaim_buffers = drm_core_reclaim_buffers,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
	.master_create = i915_master_create,
	.master_destroy = i915_master_destroy,
#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = i915_debugfs_init,
	.debugfs_cleanup = i915_debugfs_cleanup,
#endif
	.gem_init_object = i915_gem_init_object,
	.gem_free_object = i915_gem_free_object,
	.gem_vm_ops = &i915_gem_vm_ops,
#endif /* __linux__ */
	.ioctls = i915_ioctls,
#ifdef __linux__
	.fops = {
		 .owner = THIS_MODULE,
		 .open = drm_open,
		 .release = drm_release,
		 .unlocked_ioctl = drm_ioctl,
		 .mmap = drm_gem_mmap,
		 .poll = drm_poll,
		 .fasync = drm_fasync,
		 .read = drm_read,
#ifdef CONFIG_COMPAT
		 .compat_ioctl = i915_compat_ioctl,
#endif
	},

	.pci_driver = {
		 .name = DRIVER_NAME,
		 .id_table = pciidlist,
		 .probe = i915_pci_probe,
		 .remove = i915_pci_remove,
		 .driver.pm = &i915_pm_ops,
	},
#endif /* __linux__ */

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static int
i915_probe(device_t kdev)
{
	return drm_probe(kdev, i915_pciidlist);
}

static int
i915_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	i915_configure(dev);

	return drm_attach(kdev, i915_pciidlist);
}

static int
i915_detach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int ret;

	ret = drm_detach(kdev);

	free(dev->driver, DRM_MEM_DRIVER);

	return ret;
}

static device_method_t i915_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		i915_probe),
	DEVMETHOD(device_attach,	i915_attach),
	DEVMETHOD(device_suspend,	i915_suspend),
	DEVMETHOD(device_resume,	i915_resume),
	DEVMETHOD(device_detach,	i915_detach),

	{ 0, 0 }
};

static driver_t i915_driver = {
	"drm",
	i915_methods,
	sizeof(struct drm_device)
};

extern devclass_t drm_devclass;

static int __init i915_init(void)
{
#ifdef __linux__
	if (!intel_agp_enabled) {
		DRM_ERROR("drm/i915 can't work without intel_agp module!\n");
		return -ENODEV;
	}
#endif /* __linux */

	driver.dev_priv_size = sizeof(drm_i915_private_t);
	driver.buf_priv_size = sizeof(drm_i915_private_t);
	driver.max_ioctl = i915_max_ioctl;
	driver.num_ioctls = i915_max_ioctl;

#ifdef __linux__
	i915_gem_shrinker_init();
#endif /* __linux__ */

	/*
	 * If CONFIG_DRM_I915_KMS is set, default to KMS unless
	 * explicitly disabled with the module pararmeter.
	 *
	 * Otherwise, just follow the parameter (defaulting to off).
	 *
	 * Allow optional vga_text_mode_force boot option to override
	 * the default behavior.
	 */
#if defined(CONFIG_DRM_I915_KMS)
	if (i915_modeset != 0)
		driver.driver_features |= DRIVER_MODESET;
#endif
	if (i915_modeset == 1)
		driver.driver_features |= DRIVER_MODESET;

#ifdef CONFIG_VGA_CONSOLE
	if (vgacon_text_force() && i915_modeset == -1)
		driver.driver_features &= ~DRIVER_MODESET;
#endif

#ifdef __linux__
	if (!(driver.driver_features & DRIVER_MODESET)) {
		driver.suspend = i915_suspend;
		driver.resume = i915_resume;
	}

	return drm_init(&driver);
#else
	kprintf("Called i915_init() and loaded i915 driver\n");
	return 0;
#endif /* __linux__ */
}

static void __exit i915_exit(void)
{
#ifdef __linux__
	i915_gem_shrinker_exit();
	drm_exit(&driver);
#endif /* __linux__ */
	kprintf("Called i915_exit() and unloaded i915 driver\n");
}

static int i915_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		i915_init();
		break;
	case MOD_UNLOAD:
		i915_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

DRIVER_MODULE(i915, vgapci, i915_driver, drm_devclass, i915_handler, 0);
MODULE_DEPEND(i915, drm, 1, 1, 1);
