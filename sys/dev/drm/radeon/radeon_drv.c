/* radeon_drv.c -- ATI Radeon driver -*- linux-c -*-
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

#include "drmP.h"
#include "drm.h"
#include "radeon_drm.h"
#include "radeon_drv.h"
#include "drm_pciids.h"

int radeon_no_wb;
int radeon_modeset = -1;

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static drm_pci_id_list_t radeon_pciidlist[] = {
	radeon_PCI_IDS
};

static void radeon_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA |
	    DRIVER_SG | DRIVER_HAVE_DMA | DRIVER_HAVE_IRQ;

/* newer */
	dev->driver->dev_priv_size = sizeof(drm_radeon_buf_priv_t);
	dev->driver->buf_priv_size	= sizeof(drm_radeon_buf_priv_t);
	dev->driver->load		= radeon_driver_load;
	dev->driver->unload		= radeon_driver_unload;
	dev->driver->firstopen		= radeon_driver_firstopen;
	dev->driver->open		= radeon_driver_open;
	dev->driver->preclose		= radeon_driver_preclose;
	dev->driver->postclose		= radeon_driver_postclose;
	dev->driver->lastclose		= radeon_driver_lastclose;
	dev->driver->get_vblank_counter	= radeon_get_vblank_counter;
	dev->driver->enable_vblank	= radeon_enable_vblank;
	dev->driver->disable_vblank	= radeon_disable_vblank;
	dev->driver->irq_preinstall	= radeon_driver_irq_preinstall;
	dev->driver->irq_postinstall	= radeon_driver_irq_postinstall;
	dev->driver->irq_uninstall	= radeon_driver_irq_uninstall;
	dev->driver->irq_handler	= radeon_driver_irq_handler;
	dev->driver->dma_ioctl		= radeon_cp_buffers;

	dev->driver->ioctls		= radeon_ioctls;
	dev->driver->max_ioctl		= radeon_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;
/* newer */
	dev->driver->num_ioctls = radeon_max_ioctl;
}

static struct drm_driver driver_old = {
	.driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA | DRIVER_SG |
	    DRIVER_HAVE_IRQ | DRIVER_HAVE_DMA,
	.dev_priv_size = sizeof(drm_radeon_buf_priv_t),
	.buf_priv_size	= sizeof(drm_radeon_buf_priv_t),
	.load = radeon_driver_load,
	.firstopen = radeon_driver_firstopen,
	.open = radeon_driver_open,
	.preclose = radeon_driver_preclose,
	.postclose = radeon_driver_postclose,
	.lastclose = radeon_driver_lastclose,
	.unload = radeon_driver_unload,
	.get_vblank_counter = radeon_get_vblank_counter,
	.enable_vblank = radeon_enable_vblank,
	.disable_vblank = radeon_disable_vblank,
	.irq_preinstall = radeon_driver_irq_preinstall,
	.irq_postinstall = radeon_driver_irq_postinstall,
	.irq_uninstall = radeon_driver_irq_uninstall,
	.irq_handler = radeon_driver_irq_handler,
	.ioctls = radeon_ioctls,
	.dma_ioctl = radeon_cp_buffers,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static struct drm_driver *driver;

static int
radeon_probe(device_t kdev)
{
	return drm_probe(kdev, radeon_pciidlist);
}

static int
radeon_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	radeon_configure(dev);

	return drm_attach(kdev, radeon_pciidlist);
}

static int
radeon_detach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int ret;

	ret = drm_detach(kdev);

	free(dev->driver, DRM_MEM_DRIVER);

	return ret;
}

static device_method_t radeon_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		radeon_probe),
	DEVMETHOD(device_attach,	radeon_attach),
	DEVMETHOD(device_detach,	radeon_detach),

	{ 0, 0 }
};

static driver_t radeon_driver = {
	"drm",
	radeon_methods,
	sizeof(struct drm_device)
};

extern devclass_t drm_devclass;

static int __init radeon_init(void)
{
	driver = &driver_old;
	driver->max_ioctl = radeon_max_ioctl;
	driver->num_ioctls = radeon_max_ioctl;
#ifdef CONFIG_VGA_CONSOLE
	if (vgacon_text_force() && radeon_modeset == -1) {
		DRM_INFO("VGACON disable radeon kernel modesetting.\n");
		driver = &driver_old;
		driver->driver_features &= ~DRIVER_MODESET;
		radeon_modeset = 0;
	}
#endif
	/* if enabled by default */
	if (radeon_modeset == -1) {
#ifdef CONFIG_DRM_RADEON_KMS
		DRM_INFO("radeon defaulting to kernel modesetting.\n");
		radeon_modeset = 1;
#else
		DRM_INFO("radeon defaulting to userspace modesetting.\n");
		radeon_modeset = 0;
#endif
	}
#ifdef __linux__
	if (radeon_modeset == 1) {
		DRM_INFO("radeon kernel modesetting enabled.\n");
		driver = &kms_driver;
		driver->driver_features |= DRIVER_MODESET;
		driver->num_ioctls = radeon_max_kms_ioctl;
		radeon_register_atpx_handler();
	}
	/* if the vga console setting is enabled still
	 * let modprobe override it */
	return drm_init(driver);
#else
	kprintf("Called radeon_init() and loaded radeon driver\n");
	return 0;
#endif /* __linux__ */
}

static void __exit radeon_exit(void)
{
#ifdef __linux__
	drm_exit(driver);
	radeon_unregister_atpx_handler();
#endif /* __linux__ */
	kprintf("Called radeon_exit() and unloaded radeon driver\n");
}

static int radeon_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		radeon_init();
		break;
	case MOD_UNLOAD:
		radeon_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

DRIVER_MODULE(radeon, vgapci, radeon_driver, drm_devclass, radeon_handler, 0);
MODULE_DEPEND(radeon, drm, 1, 1, 1);
