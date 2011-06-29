/* sis.c -- sis driver -*- linux-c -*-
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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "drmP.h"
#include "sis_drm.h"
#include "sis_drv.h"

#include "drm_pciids.h"

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static DRM_PCI_DEVICE_ID sis_pciidlist[] = {
#ifdef DRM_NEWER_PCIID
	sisdrv_PCI_IDS
#else
	sis_PCI_IDS
#endif /* DRM_NEWER_PCIID */
};

#ifdef SIS_HAVE_CORE_MM
static int sis_driver_load(struct drm_device *dev, unsigned long chipset)
{
	drm_sis_private_t *dev_priv;
	int ret;

#ifdef __linux__
	dev_priv = kzalloc(sizeof(drm_sis_private_t), GFP_KERNEL);
#else
	dev_priv = malloc(sizeof(drm_sis_private_t), DRM_MEM_MM, M_WAITOK | M_ZERO);
#endif /* __linux__ */
	if (dev_priv == NULL)
		return -ENOMEM;

	dev->dev_private = (void *)dev_priv;
	dev_priv->chipset = chipset;
	ret = drm_sman_init(&dev_priv->sman, 2, 12, 8);
	if (ret) {
#ifdef __linux__
		kfree(dev_priv);
#else
		free(dev_priv, DRM_MEM_MM);
#endif /* __linux__ */
	}

	return ret;
}

static int sis_driver_unload(struct drm_device *dev)
{
	drm_sis_private_t *dev_priv = dev->dev_private;

	drm_sman_takedown(&dev_priv->sman);
#ifdef __linux__
	kfree(dev_priv);
#else
	free(dev_priv, DRM_MEM_MM);
#endif /* __linux__ */

	return 0;
}
#endif /* SIS_HAVE_CORE_MM */

static void sis_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR;

	dev->driver->buf_priv_size	= 1; /* No dev_priv */
	dev->driver->dev_priv_size	= 1; /* No dev_priv */
	dev->driver->context_ctor	= sis_init_context;
	dev->driver->context_dtor	= sis_final_context;

	dev->driver->ioctls		= sis_ioctls;
	dev->driver->max_ioctl		= sis_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;
	dev->driver->num_ioctls		= sis_max_ioctl;
}

static struct drm_driver driver = {
	.driver_features = DRIVER_USE_AGP | DRIVER_USE_MTRR,
	.buf_priv_size	= 1, /* No dev_priv */
	.dev_priv_size	= 1, /* No dev_priv */
#ifdef SIS_HAVE_CORE_MM
	.load = sis_driver_load,
	.unload = sis_driver_unload,
#endif /* SIS_HAVE_CORE_MM */
#ifdef __linux__
	.context_dtor = NULL,
#else
	.context_ctor	= sis_init_context,
	.context_dtor	= sis_final_context,
#endif /* __linux__ */
#ifdef __linux__
	.dma_quiescent = sis_idle,
	.reclaim_buffers = NULL,
	.reclaim_buffers_idlelocked = sis_reclaim_buffers_locked,
	.lastclose = sis_lastclose,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
#endif /* __linux__ */
	.ioctls = sis_ioctls,
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
sis_probe(device_t kdev)
{
	return drm_probe(kdev, sis_pciidlist);
}

static int
sis_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	sis_configure(dev);

	return drm_attach(kdev, sis_pciidlist);
}

static int
sis_detach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int ret;

	ret = drm_detach(kdev);

	free(dev->driver, DRM_MEM_DRIVER);

	return ret;
}

static device_method_t sis_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		sis_probe),
	DEVMETHOD(device_attach,	sis_attach),
	DEVMETHOD(device_detach,	sis_detach),

	{ 0, 0 }
};

static driver_t sis_driver = {
	"drm",
	sis_methods,
	sizeof(struct drm_device)
};

extern devclass_t drm_devclass;

static int __init sis_init(void)
{
	driver.max_ioctl = sis_max_ioctl;
	driver.num_ioctls = sis_max_ioctl;
#ifdef __linux__
	return drm_init(&driver);
#else
	kprintf("Called sis_init() and loaded sis driver\n");
	return 0;
#endif /* __linux__ */
}

static void __exit sis_exit(void)
{
#ifdef __linux__
	drm_exit(&driver);
#else
	kprintf("Called sis_exit() and unloaded sis driver\n");
#endif /* __linux__ */
}

static int sis_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		sis_init();
		break;
	case MOD_UNLOAD:
		sis_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

DRIVER_MODULE(sisdrm, vgapci, sis_driver, drm_devclass, sis_handler, NULL);
MODULE_DEPEND(sisdrm, drm, 1, 1, 1);
#ifdef __linux__
module_init(sis_init);
module_exit(sis_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
#endif /* __linux__ */
