/* mach64_drv.c -- ATI Rage 128 driver -*- linux-c -*-
 * Created: Mon Dec 13 09:47:27 1999 by faith@precisioninsight.com
 */
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
 */

#include <sys/types.h>

#include "drmP.h"
#include "drm.h"
#include "mach64_drm.h"
#include "mach64_drv.h"
#include "drm_pciids.h"

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static DRM_PCI_DEVICE_ID mach64_pciidlist[] = {
	mach64_PCI_IDS
};

static void mach64_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA |
	    DRIVER_HAVE_DMA | DRIVER_HAVE_IRQ;

	dev->driver->buf_priv_size	= 1; /* No dev_priv */
	dev->driver->dev_priv_size	= 1; /* No dev_priv */
	dev->driver->load		= mach64_driver_load;
	dev->driver->lastclose		= mach64_driver_lastclose;
	dev->driver->get_vblank_counter	= mach64_get_vblank_counter;
	dev->driver->enable_vblank	= mach64_enable_vblank;
	dev->driver->disable_vblank	= mach64_disable_vblank;
	dev->driver->irq_preinstall	= mach64_driver_irq_preinstall;
	dev->driver->irq_postinstall	= mach64_driver_irq_postinstall;
	dev->driver->irq_uninstall	= mach64_driver_irq_uninstall;
	dev->driver->irq_handler	= mach64_driver_irq_handler;
	dev->driver->reclaim_buffers = drm_core_reclaim_buffers;
	dev->driver->get_map_ofs = drm_core_get_map_ofs;
	dev->driver->get_reg_ofs = drm_core_get_reg_ofs;
	dev->driver->dma_ioctl		= mach64_dma_buffers;

	dev->driver->ioctls		= mach64_ioctls;
	dev->driver->max_ioctl		= mach64_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;
	dev->driver->num_ioctls		= mach64_max_ioctl;
}

static struct drm_driver driver = {
	.driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA |
	    DRIVER_HAVE_DMA | DRIVER_HAVE_IRQ,

	.buf_priv_size = 1, /* No dev_priv */
	.dev_priv_size = 1, /* No dev_priv */
	.load = mach64_driver_load,
	.lastclose = mach64_driver_lastclose,
	.get_vblank_counter = mach64_get_vblank_counter,
	.enable_vblank = mach64_enable_vblank,
	.disable_vblank = mach64_disable_vblank,
	.irq_preinstall = mach64_driver_irq_preinstall,
	.irq_postinstall = mach64_driver_irq_postinstall,
	.irq_uninstall = mach64_driver_irq_uninstall,
	.irq_handler = mach64_driver_irq_handler,
	.reclaim_buffers = drm_core_reclaim_buffers,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
	.ioctls = mach64_ioctls,
	.dma_ioctl = mach64_dma_buffers,
#ifdef __linux__
	.fops = {
		.owner = THIS_MODULE,
		.open = drm_open,
		.release = drm_release,
		.unlocked_ioctl = drm_ioctl,
		.mmap = drm_mmap,
		.poll = drm_poll,
		.fasync = drm_fasync,
#ifdef CONFIG_COMPAT
		.compat_ioctl = mach64_compat_ioctl,
#endif
	},
	.pci_driver = {
		.name = DRIVER_NAME,
		.id_table = pciidlist,
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
mach64_probe(device_t kdev)
{
	return drm_probe(kdev, mach64_pciidlist);
}

static int
mach64_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	mach64_configure(dev);

	return drm_attach(kdev, mach64_pciidlist);
}

int
mach64_driver_load(struct drm_device * dev, unsigned long flags)
{
        return drm_vblank_init(dev, 1);
}

static int
mach64_detach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int ret;

	ret = drm_detach(kdev);

	free(dev->driver, DRM_MEM_DRIVER);

	return ret;
}

static device_method_t mach64_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		mach64_probe),
	DEVMETHOD(device_attach,	mach64_attach),
	DEVMETHOD(device_detach,	mach64_detach),

	{ 0, 0 }
};

static driver_t mach64_driver = {
	"drm",
	mach64_methods,
	sizeof(struct drm_device)
};

extern devclass_t drm_devclass;

static int __init mach64_init(void)
{
	driver.max_ioctl = mach64_max_ioctl;
	driver.num_ioctls = mach64_max_ioctl;
#ifdef __linux__
	return drm_init(&driver);
#else
	kprintf("Called mach64_init() and loaded mach64 driver\n");
	return 0;
#endif /* __linux__ */
}

static void __exit mach64_exit(void)
{
#ifdef __linux__
	drm_exit(&driver);
#else
	kprintf("Called mach64_exit() and unloaded mach64 driver\n");
#endif /* __linux__ */
}

static int mach64_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		mach64_init();
		break;
	case MOD_UNLOAD:
		mach64_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

DRIVER_MODULE(mach64, vgapci, mach64_driver, drm_devclass, mach64_handler, NULL);
MODULE_DEPEND(mach64, drm, 1, 1, 1);
