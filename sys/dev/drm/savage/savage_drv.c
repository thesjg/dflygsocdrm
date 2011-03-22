/* savage_drv.c -- Savage DRI driver
 */
/*-
 * Copyright 2005 Eric Anholt
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
 */

#include "drmP.h"
#include "drm.h"
#include "savage_drm.h"
#include "savage_drv.h"
#include "drm_pciids.h"

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static DRM_PCI_DEVICE_ID savage_pciidlist[] = {
	savage_PCI_IDS
};

static void savage_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA |
	    DRIVER_HAVE_DMA;

	dev->driver->buf_priv_size	= sizeof(drm_savage_buf_priv_t);
	dev->driver->dev_priv_size	= sizeof(drm_savage_buf_priv_t);
	dev->driver->load		= savage_driver_load;
	dev->driver->firstopen		= savage_driver_firstopen;
	dev->driver->lastclose		= savage_driver_lastclose;
	dev->driver->unload		= savage_driver_unload;
	dev->driver->reclaim_buffers = savage_reclaim_buffers;
	dev->driver->get_map_ofs = drm_core_get_map_ofs;
	dev->driver->get_reg_ofs = drm_core_get_reg_ofs;
	dev->driver->dma_ioctl		= savage_bci_buffers;

	dev->driver->ioctls		= savage_ioctls;
	dev->driver->max_ioctl		= savage_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;
	dev->driver->num_ioctls		= savage_max_ioctl;
}

static struct drm_driver driver = {
	.driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_HAVE_DMA | DRIVER_PCI_DMA,
	.dev_priv_size = sizeof(drm_savage_buf_priv_t),
	.load = savage_driver_load,
	.firstopen = savage_driver_firstopen,
	.lastclose = savage_driver_lastclose,
	.unload = savage_driver_unload,
	.reclaim_buffers = savage_reclaim_buffers,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
	.ioctls = savage_ioctls,
	.dma_ioctl = savage_bci_buffers,
#ifdef __linux__
	.fops = {
		 .owner = THIS_MODULE,
		 .open = drm_open,
		 .release = drm_release,
		 .unlocked_ioctl = drm_ioctl,
		 .mmap = drm_mmap,
		 .poll = drm_poll,
		 .fasync = drm_fasync,
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
savage_probe(device_t kdev)
{
	return drm_probe(kdev, savage_pciidlist);
}

static int
savage_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	savage_configure(dev);

	return drm_attach(kdev, savage_pciidlist);
}

static int
savage_detach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int ret;

	ret = drm_detach(kdev);

	free(dev->driver, DRM_MEM_DRIVER);

	return ret;
}

static device_method_t savage_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		savage_probe),
	DEVMETHOD(device_attach,	savage_attach),
	DEVMETHOD(device_detach,	savage_detach),

	{ 0, 0 }
};

static driver_t savage_driver = {
	"drm",
	savage_methods,
	sizeof(struct drm_device)
};

extern devclass_t drm_devclass;

static int __init savage_init(void)
{
	driver.max_ioctl = savage_max_ioctl;
	driver.num_ioctls = savage_max_ioctl;
#ifdef __linux__
	return drm_init(&driver);
#else
	kprintf("Called savage_init() and loaded savage driver\n");
	return 0;
#endif /* __linux__ */
}

static void __exit savage_exit(void)
{
#ifdef __linux__
	drm_exit(&driver);
#else
	kprintf("Called savage_exit() and unloaded savage driver\n");
#endif /* __linux__ */
}

static int savage_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		savage_init();
		break;
	case MOD_UNLOAD:
		savage_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

DRIVER_MODULE(savage, vgapci, savage_driver, drm_devclass, savage_handler, 0);
MODULE_DEPEND(savage, drm, 1, 1, 1);
#ifdef __linux__
module_init(savage_init);
module_exit(savage_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
#endif /* __linux__ */
