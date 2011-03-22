/**
 * \file radeon_drv.c
 * ATI Radeon driver
 *
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
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
#include "drm.h"
#include "radeon_drm.h"
#include "radeon_drv.h"

#include "drm_pciids.h"
#ifdef __linux__
#include <linux/console.h>
#endif /* __linux__ */

#define DRM_NEWER_MASTER 1

/*
 * KMS wrapper.
 * - 2.0.0 - initial interface
 * - 2.1.0 - add square tiling interface
 * - 2.2.0 - add r6xx/r7xx const buffer support
 * - 2.3.0 - add MSPOS + 3D texture + r500 VAP regs
 */
#define KMS_DRIVER_MAJOR	2
#define KMS_DRIVER_MINOR	3
#define KMS_DRIVER_PATCHLEVEL	0
int radeon_driver_load_kms(struct drm_device *dev, unsigned long flags);
int radeon_driver_unload_kms(struct drm_device *dev);
int radeon_driver_firstopen_kms(struct drm_device *dev);
void radeon_driver_lastclose_kms(struct drm_device *dev);
int radeon_driver_open_kms(struct drm_device *dev, struct drm_file *file_priv);
void radeon_driver_postclose_kms(struct drm_device *dev,
				 struct drm_file *file_priv);
void radeon_driver_preclose_kms(struct drm_device *dev,
				struct drm_file *file_priv);
int radeon_suspend_kms(struct drm_device *dev, pm_message_t state);
int radeon_resume_kms(struct drm_device *dev);
u32 radeon_get_vblank_counter_kms(struct drm_device *dev, int crtc);
int radeon_enable_vblank_kms(struct drm_device *dev, int crtc);
void radeon_disable_vblank_kms(struct drm_device *dev, int crtc);
void radeon_driver_irq_preinstall_kms(struct drm_device *dev);
int radeon_driver_irq_postinstall_kms(struct drm_device *dev);
void radeon_driver_irq_uninstall_kms(struct drm_device *dev);
irqreturn_t radeon_driver_irq_handler_kms(DRM_IRQ_ARGS);
int radeon_dma_ioctl_kms(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int radeon_gem_object_init(struct drm_gem_object *obj);
void radeon_gem_object_free(struct drm_gem_object *obj);
extern struct drm_ioctl_desc radeon_ioctls_kms[];
extern int radeon_max_kms_ioctl;
int radeon_mmap(struct file *filp, struct vm_area_struct *vma);
#if defined(CONFIG_DEBUG_FS)
int radeon_debugfs_init(struct drm_minor *minor);
void radeon_debugfs_cleanup(struct drm_minor *minor);
#endif


int radeon_no_wb;
int radeon_modeset = -1;
#ifdef __linux__
int radeon_dynclks = -1;
int radeon_r4xx_atom = 0;
int radeon_agpmode = 0;
int radeon_vram_limit = 0;
int radeon_gart_size = 512; /* default gart size */
int radeon_benchmarking = 0;
int radeon_testing = 0;
int radeon_connector_table = 0;
int radeon_tv = 1;
int radeon_new_pll = -1;
int radeon_dynpm = -1;
int radeon_audio = 1;
int radeon_disp_priority = 0;
int radeon_hw_i2c = 0;

MODULE_PARM_DESC(no_wb, "Disable AGP writeback for scratch registers");
module_param_named(no_wb, radeon_no_wb, int, 0444);

MODULE_PARM_DESC(modeset, "Disable/Enable modesetting");
module_param_named(modeset, radeon_modeset, int, 0400);

MODULE_PARM_DESC(dynclks, "Disable/Enable dynamic clocks");
module_param_named(dynclks, radeon_dynclks, int, 0444);

MODULE_PARM_DESC(r4xx_atom, "Enable ATOMBIOS modesetting for R4xx");
module_param_named(r4xx_atom, radeon_r4xx_atom, int, 0444);

MODULE_PARM_DESC(vramlimit, "Restrict VRAM for testing");
module_param_named(vramlimit, radeon_vram_limit, int, 0600);

MODULE_PARM_DESC(agpmode, "AGP Mode (-1 == PCI)");
module_param_named(agpmode, radeon_agpmode, int, 0444);

MODULE_PARM_DESC(gartsize, "Size of PCIE/IGP gart to setup in megabytes (32,64, etc)\n");
module_param_named(gartsize, radeon_gart_size, int, 0600);

MODULE_PARM_DESC(benchmark, "Run benchmark");
module_param_named(benchmark, radeon_benchmarking, int, 0444);

MODULE_PARM_DESC(test, "Run tests");
module_param_named(test, radeon_testing, int, 0444);

MODULE_PARM_DESC(connector_table, "Force connector table");
module_param_named(connector_table, radeon_connector_table, int, 0444);

MODULE_PARM_DESC(tv, "TV enable (0 = disable)");
module_param_named(tv, radeon_tv, int, 0444);

MODULE_PARM_DESC(new_pll, "Select new PLL code");
module_param_named(new_pll, radeon_new_pll, int, 0444);

MODULE_PARM_DESC(dynpm, "Disable/Enable dynamic power management (1 = enable)");
module_param_named(dynpm, radeon_dynpm, int, 0444);

MODULE_PARM_DESC(audio, "Audio enable (0 = disable)");
module_param_named(audio, radeon_audio, int, 0444);

MODULE_PARM_DESC(disp_priority, "Display Priority (0 = auto, 1 = normal, 2 = high)");
module_param_named(disp_priority, radeon_disp_priority, int, 0444);

MODULE_PARM_DESC(hw_i2c, "hw i2c engine enable (0 = disable)");
module_param_named(hw_i2c, radeon_hw_i2c, int, 0444);

static int radeon_suspend(struct drm_device *dev, pm_message_t state)
{
	drm_radeon_private_t *dev_priv = dev->dev_private;

	if ((dev_priv->flags & RADEON_FAMILY_MASK) >= CHIP_R600)
		return 0;

	/* Disable *all* interrupts */
	if ((dev_priv->flags & RADEON_FAMILY_MASK) >= CHIP_RS600)
		RADEON_WRITE(R500_DxMODE_INT_MASK, 0);
	RADEON_WRITE(RADEON_GEN_INT_CNTL, 0);
	return 0;
}

static int radeon_resume(struct drm_device *dev)
{
	drm_radeon_private_t *dev_priv = dev->dev_private;

	if ((dev_priv->flags & RADEON_FAMILY_MASK) >= CHIP_R600)
		return 0;

	/* Restore interrupt registers */
	if ((dev_priv->flags & RADEON_FAMILY_MASK) >= CHIP_RS600)
		RADEON_WRITE(R500_DxMODE_INT_MASK, dev_priv->r500_disp_irq_reg);
	RADEON_WRITE(RADEON_GEN_INT_CNTL, dev_priv->irq_enable_reg);
	return 0;
}
#endif /* __linux__ */

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static DRM_PCI_DEVICE_ID radeon_pciidlist[] = {
	radeon_PCI_IDS
};

#if defined(CONFIG_DRM_RADEON_KMS)
MODULE_DEVICE_TABLE(pci, pciidlist);
#endif

static void radeon_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA |
	    DRIVER_SG | DRIVER_HAVE_DMA | DRIVER_HAVE_IRQ;

/* newer */
	dev->driver->dev_priv_size 	= sizeof(drm_radeon_buf_priv_t);
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
	dev->driver->master_create      = radeon_master_create,
	dev->driver->master_destroy     = radeon_master_destroy,
	dev->driver->irq_preinstall	= radeon_driver_irq_preinstall;
	dev->driver->irq_postinstall	= radeon_driver_irq_postinstall;
	dev->driver->irq_uninstall	= radeon_driver_irq_uninstall;
	dev->driver->irq_handler	= radeon_driver_irq_handler;
#if 1
	dev->driver->reclaim_buffers = drm_core_reclaim_buffers;
	dev->driver->get_map_ofs = drm_core_get_map_ofs;
	dev->driver->get_reg_ofs = drm_core_get_reg_ofs;
#endif
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
#ifdef __linux__
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA | DRIVER_SG |
	    DRIVER_HAVE_IRQ | DRIVER_HAVE_DMA | DRIVER_IRQ_SHARED,
#else
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA | DRIVER_SG |
	    DRIVER_HAVE_IRQ | DRIVER_HAVE_DMA,
#endif /* __linux__ */
	.dev_priv_size = sizeof(drm_radeon_buf_priv_t),
	.buf_priv_size	= sizeof(drm_radeon_buf_priv_t),
	.load = radeon_driver_load,
	.firstopen = radeon_driver_firstopen,
	.open = radeon_driver_open,
	.preclose = radeon_driver_preclose,
	.postclose = radeon_driver_postclose,
	.lastclose = radeon_driver_lastclose,
	.unload = radeon_driver_unload,
#ifdef __linux__
	.suspend = radeon_suspend,
	.resume = radeon_resume,
#endif /* __linux__ */
	.get_vblank_counter = radeon_get_vblank_counter,
	.enable_vblank = radeon_enable_vblank,
	.disable_vblank = radeon_disable_vblank,
#ifdef DRM_NEWER_MASTER
	.master_create = radeon_master_create,
	.master_destroy = radeon_master_destroy,
#endif
	.irq_preinstall = radeon_driver_irq_preinstall,
	.irq_postinstall = radeon_driver_irq_postinstall,
	.irq_uninstall = radeon_driver_irq_uninstall,
	.irq_handler = radeon_driver_irq_handler,
#ifdef DRM_NEWER_MASTER
	.reclaim_buffers = drm_core_reclaim_buffers,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
#endif
	.ioctls = radeon_ioctls,
	.dma_ioctl = radeon_cp_buffers,
#ifdef __linux__
	.fops = {
		 .owner = THIS_MODULE,
		 .open = drm_open,
		 .release = drm_release,
		 .unlocked_ioctl = drm_ioctl,
		 .mmap = drm_mmap,
		 .poll = drm_poll,
		 .fasync = drm_fasync,
		 .read = drm_read,
#ifdef CONFIG_COMPAT
		 .compat_ioctl = radeon_compat_ioctl,
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

#ifdef __linux__
static struct drm_driver kms_driver;

static int __devinit
radeon_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	return drm_get_dev(pdev, ent, &kms_driver);
}

static void
radeon_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
}

static int
radeon_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	return radeon_suspend_kms(dev, state);
}

static int
radeon_pci_resume(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	return radeon_resume_kms(dev);
}

static struct drm_driver kms_driver = {
	.driver_features =
	    DRIVER_USE_AGP | DRIVER_USE_MTRR | DRIVER_PCI_DMA | DRIVER_SG |
	    DRIVER_HAVE_IRQ | DRIVER_HAVE_DMA | DRIVER_IRQ_SHARED | DRIVER_GEM,
	.dev_priv_size = 0,
	.load = radeon_driver_load_kms,
	.firstopen = radeon_driver_firstopen_kms,
	.open = radeon_driver_open_kms,
	.preclose = radeon_driver_preclose_kms,
	.postclose = radeon_driver_postclose_kms,
	.lastclose = radeon_driver_lastclose_kms,
	.unload = radeon_driver_unload_kms,
	.suspend = radeon_suspend_kms,
	.resume = radeon_resume_kms,
	.get_vblank_counter = radeon_get_vblank_counter_kms,
	.enable_vblank = radeon_enable_vblank_kms,
	.disable_vblank = radeon_disable_vblank_kms,
#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = radeon_debugfs_init,
	.debugfs_cleanup = radeon_debugfs_cleanup,
#endif
	.irq_preinstall = radeon_driver_irq_preinstall_kms,
	.irq_postinstall = radeon_driver_irq_postinstall_kms,
	.irq_uninstall = radeon_driver_irq_uninstall_kms,
	.irq_handler = radeon_driver_irq_handler_kms,
	.reclaim_buffers = drm_core_reclaim_buffers,
	.get_map_ofs = drm_core_get_map_ofs,
	.get_reg_ofs = drm_core_get_reg_ofs,
	.ioctls = radeon_ioctls_kms,
	.gem_init_object = radeon_gem_object_init,
	.gem_free_object = radeon_gem_object_free,
	.dma_ioctl = radeon_dma_ioctl_kms,
	.fops = {
		 .owner = THIS_MODULE,
		 .open = drm_open,
		 .release = drm_release,
		 .unlocked_ioctl = drm_ioctl,
		 .mmap = radeon_mmap,
		 .poll = drm_poll,
		 .fasync = drm_fasync,
		 .read = drm_read,
#ifdef CONFIG_COMPAT
		 .compat_ioctl = radeon_kms_compat_ioctl,
#endif
	},

	.pci_driver = {
		 .name = DRIVER_NAME,
		 .id_table = pciidlist,
		 .probe = radeon_pci_probe,
		 .remove = radeon_pci_remove,
		 .suspend = radeon_pci_suspend,
		 .resume = radeon_pci_resume,
	},

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = KMS_DRIVER_MAJOR,
	.minor = KMS_DRIVER_MINOR,
	.patchlevel = KMS_DRIVER_PATCHLEVEL,
};
#endif /* __linux__ */

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
	"radeon",
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
#ifdef __linux__
module_init(radeon_init);
module_exit(radeon_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
#endif /* __linux__ */
