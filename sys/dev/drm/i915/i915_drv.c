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

unsigned int i915_fbpercrtc = 0;

unsigned int i915_powersave = 1;

unsigned int i915_lvds_downclock = 0;

static struct drm_driver driver;

#ifdef __linux__ /* not defined in drm */
extern int intel_agp_enabled;
#endif /* __linux__ */

#ifdef DRM_NEWER_PCIID

#define INTEL_VGA_DEVICE(id, info) {		\
	.class = PCI_CLASS_DISPLAY_VGA << 8,	\
	.class_mask = 0xffff00,			\
	.vendor = 0x8086,			\
	.device = id,				\
	.subvendor = PCI_ANY_ID,		\
	.subdevice = PCI_ANY_ID,		\
	.driver_data = (unsigned long) info }

const static struct intel_device_info intel_i830_info = {
	.is_i8xx = 1, .is_mobile = 1, .cursor_needs_physical = 1,
};

const static struct intel_device_info intel_845g_info = {
	.is_i8xx = 1,
};

const static struct intel_device_info intel_i85x_info = {
	.is_i8xx = 1, .is_i85x = 1, .is_mobile = 1,
	.cursor_needs_physical = 1,
};

const static struct intel_device_info intel_i865g_info = {
	.is_i8xx = 1,
};

const static struct intel_device_info intel_i915g_info = {
	.is_i915g = 1, .is_i9xx = 1, .cursor_needs_physical = 1,
};
const static struct intel_device_info intel_i915gm_info = {
	.is_i9xx = 1,  .is_mobile = 1,
	.cursor_needs_physical = 1,
};
const static struct intel_device_info intel_i945g_info = {
	.is_i9xx = 1, .has_hotplug = 1, .cursor_needs_physical = 1,
};
const static struct intel_device_info intel_i945gm_info = {
	.is_i945gm = 1, .is_i9xx = 1, .is_mobile = 1,
	.has_hotplug = 1, .cursor_needs_physical = 1,
};

const static struct intel_device_info intel_i965g_info = {
	.is_i965g = 1, .is_i9xx = 1, .has_hotplug = 1,
};

const static struct intel_device_info intel_i965gm_info = {
	.is_i965g = 1, .is_mobile = 1, .is_i965gm = 1, .is_i9xx = 1,
	.is_mobile = 1, .has_fbc = 1, .has_rc6 = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_g33_info = {
	.is_g33 = 1, .is_i9xx = 1, .need_gfx_hws = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_g45_info = {
	.is_i965g = 1, .is_g4x = 1, .is_i9xx = 1, .need_gfx_hws = 1,
	.has_pipe_cxsr = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_gm45_info = {
	.is_i965g = 1, .is_mobile = 1, .is_g4x = 1, .is_i9xx = 1,
	.is_mobile = 1, .need_gfx_hws = 1, .has_fbc = 1, .has_rc6 = 1,
	.has_pipe_cxsr = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_pineview_info = {
	.is_g33 = 1, .is_pineview = 1, .is_mobile = 1, .is_i9xx = 1,
	.need_gfx_hws = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_ironlake_d_info = {
	.is_ironlake = 1, .is_i965g = 1, .is_i9xx = 1, .need_gfx_hws = 1,
	.has_pipe_cxsr = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_ironlake_m_info = {
	.is_ironlake = 1, .is_mobile = 1, .is_i965g = 1, .is_i9xx = 1,
	.need_gfx_hws = 1, .has_rc6 = 1,
	.has_hotplug = 1,
};

const static struct intel_device_info intel_sandybridge_d_info = {
	.is_i965g = 1, .is_i9xx = 1, .need_gfx_hws = 1,
	.has_hotplug = 1, .is_gen6 = 1,
};

const static struct intel_device_info intel_sandybridge_m_info = {
	.is_i965g = 1, .is_mobile = 1, .is_i9xx = 1, .need_gfx_hws = 1,
	.has_hotplug = 1, .is_gen6 = 1,
};

const static struct pci_device_id pciidlist[] = {
	INTEL_VGA_DEVICE(0x3577, &intel_i830_info),
	INTEL_VGA_DEVICE(0x2562, &intel_845g_info),
	INTEL_VGA_DEVICE(0x3582, &intel_i85x_info),
	INTEL_VGA_DEVICE(0x358e, &intel_i85x_info),
	INTEL_VGA_DEVICE(0x2572, &intel_i865g_info),
	INTEL_VGA_DEVICE(0x2582, &intel_i915g_info),
	INTEL_VGA_DEVICE(0x258a, &intel_i915g_info),
	INTEL_VGA_DEVICE(0x2592, &intel_i915gm_info),
	INTEL_VGA_DEVICE(0x2772, &intel_i945g_info),
	INTEL_VGA_DEVICE(0x27a2, &intel_i945gm_info),
	INTEL_VGA_DEVICE(0x27ae, &intel_i945gm_info),
	INTEL_VGA_DEVICE(0x2972, &intel_i965g_info),
	INTEL_VGA_DEVICE(0x2982, &intel_i965g_info),
	INTEL_VGA_DEVICE(0x2992, &intel_i965g_info),
	INTEL_VGA_DEVICE(0x29a2, &intel_i965g_info),
	INTEL_VGA_DEVICE(0x29b2, &intel_g33_info),
	INTEL_VGA_DEVICE(0x29c2, &intel_g33_info),
	INTEL_VGA_DEVICE(0x29d2, &intel_g33_info),
	INTEL_VGA_DEVICE(0x2a02, &intel_i965gm_info),
	INTEL_VGA_DEVICE(0x2a12, &intel_i965gm_info),
	INTEL_VGA_DEVICE(0x2a42, &intel_gm45_info),
	INTEL_VGA_DEVICE(0x2e02, &intel_g45_info),
	INTEL_VGA_DEVICE(0x2e12, &intel_g45_info),
	INTEL_VGA_DEVICE(0x2e22, &intel_g45_info),
	INTEL_VGA_DEVICE(0x2e32, &intel_g45_info),
	INTEL_VGA_DEVICE(0x2e42, &intel_g45_info),
	INTEL_VGA_DEVICE(0xa001, &intel_pineview_info),
	INTEL_VGA_DEVICE(0xa011, &intel_pineview_info),
	INTEL_VGA_DEVICE(0x0042, &intel_ironlake_d_info),
	INTEL_VGA_DEVICE(0x0046, &intel_ironlake_m_info),
	INTEL_VGA_DEVICE(0x0102, &intel_sandybridge_d_info),
	INTEL_VGA_DEVICE(0x0106, &intel_sandybridge_m_info),
	{0, 0, 0}
};
#else
/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static DRM_PCI_DEVICE_ID pciidlist[] = {
	i915_PCI_IDS
};
#endif /* DRM_NEWER_PCIID */

#ifdef __linux__
#if defined(CONFIG_DRM_I915_KMS)
MODULE_DEVICE_TABLE(pci, pciidlist);
#endif

#define INTEL_PCH_DEVICE_ID_MASK	0xff00
#define INTEL_PCH_CPT_DEVICE_ID_TYPE	0x1c00

void intel_detect_pch (struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct pci_dev *pch;

	/*
	 * The reason to probe ISA bridge instead of Dev31:Fun0 is to
	 * make graphics device passthrough work easy for VMM, that only
	 * need to expose ISA bridge to let driver know the real hardware
	 * underneath. This is a requirement from virtualization team.
	 */
	pch = pci_get_class(PCI_CLASS_BRIDGE_ISA << 8, NULL);
	if (pch) {
		if (pch->vendor == PCI_VENDOR_ID_INTEL) {
			int id;
			id = pch->device & INTEL_PCH_DEVICE_ID_MASK;

			if (id == INTEL_PCH_CPT_DEVICE_ID_TYPE) {
				dev_priv->pch_type = PCH_CPT;
				DRM_DEBUG_KMS("Found CougarPoint PCH\n");
			}
		}
		pci_dev_put(pch);
	}
}

static int i915_drm_freeze(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

	pci_save_state(dev->pdev);

	/* If KMS is active, we do the leavevt stuff here */
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		int error = i915_gem_idle(dev);
		if (error) {
			dev_err(&dev->pdev->dev,
				"GEM idle failed, resume might fail\n");
			return error;
		}
		drm_irq_uninstall(dev);
	}

	i915_save_state(dev);

	intel_opregion_free(dev, 1);

	/* Modeset on resume, not lid events */
	dev_priv->modeset_on_lid = 0;

	return 0;
}

int i915_suspend(struct drm_device *dev, pm_message_t state)
{
	int error;

	if (!dev || !dev->dev_private) {
		DRM_ERROR("dev: %p\n", dev);
		DRM_ERROR("DRM not initialized, aborting suspend.\n");
		return -ENODEV;
	}

	if (state.event == PM_EVENT_PRETHAW)
		return 0;

	error = i915_drm_freeze(dev);
	if (error)
		return error;

	if (state.event == PM_EVENT_SUSPEND) {
		/* Shut down the device */
		pci_disable_device(dev->pdev);
		pci_set_power_state(dev->pdev, PCI_D3hot);
	}

	return 0;
}

static int i915_drm_thaw(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	int error = 0;

	i915_restore_state(dev);

	intel_opregion_init(dev, 1);

	/* KMS EnterVT equivalent */
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		mutex_lock(&dev->struct_mutex);
		dev_priv->mm.suspended = 0;

		error = i915_gem_init_ringbuffer(dev);
		mutex_unlock(&dev->struct_mutex);

		drm_irq_install(dev);

		/* Resume the modeset for every activated CRTC */
		drm_helper_resume_force_mode(dev);
	}

	dev_priv->modeset_on_lid = 0;

	return error;
}

int i915_resume(struct drm_device *dev)
{
	if (pci_enable_device(dev->pdev))
		return -EIO;

	pci_set_master(dev->pdev);

	return i915_drm_thaw(dev);
}

/**
 * i965_reset - reset chip after a hang
 * @dev: drm device to reset
 * @flags: reset domains
 *
 * Reset the chip.  Useful if a hang is detected. Returns zero on successful
 * reset or otherwise an error code.
 *
 * Procedure is fairly simple:
 *   - reset the chip using the reset reg
 *   - re-init context state
 *   - re-init hardware status page
 *   - re-init ring buffer
 *   - re-init interrupt state
 *   - re-init display
 */
int i965_reset(struct drm_device *dev, u8 flags)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	unsigned long timeout;
	u8 gdrst;
	/*
	 * We really should only reset the display subsystem if we actually
	 * need to
	 */
	bool need_display = true;

	mutex_lock(&dev->struct_mutex);

	/*
	 * Clear request list
	 */
	i915_gem_retire_requests(dev);

	if (need_display)
		i915_save_display(dev);

	if (IS_I965G(dev) || IS_G4X(dev)) {
		/*
		 * Set the domains we want to reset, then the reset bit (bit 0).
		 * Clear the reset bit after a while and wait for hardware status
		 * bit (bit 1) to be set
		 */
		pci_read_config_byte(dev->pdev, GDRST, &gdrst);
		pci_write_config_byte(dev->pdev, GDRST, gdrst | flags | ((flags == GDRST_FULL) ? 0x1 : 0x0));
		udelay(50);
		pci_write_config_byte(dev->pdev, GDRST, gdrst & 0xfe);

		/* ...we don't want to loop forever though, 500ms should be plenty */
	       timeout = jiffies + msecs_to_jiffies(500);
		do {
			udelay(100);
			pci_read_config_byte(dev->pdev, GDRST, &gdrst);
		} while ((gdrst & 0x1) && time_after(timeout, jiffies));

		if (gdrst & 0x1) {
			WARN(true, "i915: Failed to reset chip\n");
			mutex_unlock(&dev->struct_mutex);
			return -EIO;
		}
	} else {
		DRM_ERROR("Error occurred. Don't know how to reset this chip.\n");
		return -ENODEV;
	}

	/* Ok, now get things going again... */

	/*
	 * Everything depends on having the GTT running, so we need to start
	 * there.  Fortunately we don't need to do this unless we reset the
	 * chip at a PCI level.
	 *
	 * Next we need to restore the context, but we don't use those
	 * yet either...
	 *
	 * Ring buffer needs to be re-initialized in the KMS case, or if X
	 * was running at the time of the reset (i.e. we weren't VT
	 * switched away).
	 */
	if (drm_core_check_feature(dev, DRIVER_MODESET) ||
	    !dev_priv->mm.suspended) {
		drm_i915_ring_buffer_t *ring = &dev_priv->ring;
		struct drm_gem_object *obj = ring->ring_obj;
		struct drm_i915_gem_object *obj_priv = to_intel_bo(obj);
		dev_priv->mm.suspended = 0;

		/* Stop the ring if it's running. */
		I915_WRITE(PRB0_CTL, 0);
		I915_WRITE(PRB0_TAIL, 0);
		I915_WRITE(PRB0_HEAD, 0);

		/* Initialize the ring. */
		I915_WRITE(PRB0_START, obj_priv->gtt_offset);
		I915_WRITE(PRB0_CTL,
			   ((obj->size - 4096) & RING_NR_PAGES) |
			   RING_NO_REPORT |
			   RING_VALID);
		if (!drm_core_check_feature(dev, DRIVER_MODESET))
			i915_kernel_lost_context(dev);
		else {
			ring->head = I915_READ(PRB0_HEAD) & HEAD_ADDR;
			ring->tail = I915_READ(PRB0_TAIL) & TAIL_ADDR;
			ring->space = ring->head - (ring->tail + 8);
			if (ring->space < 0)
				ring->space += ring->Size;
		}

		mutex_unlock(&dev->struct_mutex);
		drm_irq_uninstall(dev);
		drm_irq_install(dev);
		mutex_lock(&dev->struct_mutex);
	}

	/*
	 * Display needs restore too...
	 */
	if (need_display)
		i915_restore_display(dev);

	mutex_unlock(&dev->struct_mutex);
	return 0;
}

#ifdef __linux__
static int __devinit
i915_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	return drm_get_dev(pdev, ent, &driver);
}

static void
i915_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
}
#endif /* __linux__ */

static int i915_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	int error;

	if (!drm_dev || !drm_dev->dev_private) {
		dev_err(dev, "DRM not initialized, aborting suspend.\n");
		return -ENODEV;
	}

	error = i915_drm_freeze(drm_dev);
	if (error)
		return error;

	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);

	return 0;
}

static int i915_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	return i915_resume(drm_dev);
}

static int i915_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	if (!drm_dev || !drm_dev->dev_private) {
		dev_err(dev, "DRM not initialized, aborting suspend.\n");
		return -ENODEV;
	}

	return i915_drm_freeze(drm_dev);
}

static int i915_pm_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	return i915_drm_thaw(drm_dev);
}

static int i915_pm_poweroff(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	return i915_drm_freeze(drm_dev);
}

const struct dev_pm_ops i915_pm_ops = {
     .suspend = i915_pm_suspend,
     .resume = i915_pm_resume,
     .freeze = i915_pm_freeze,
     .thaw = i915_pm_thaw,
     .poweroff = i915_pm_poweroff,
     .restore = i915_pm_resume,
};

static struct vm_operations_struct i915_gem_vm_ops = {
	.fault = i915_gem_fault,
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};
#endif /* __linux__ */

static int i915_suspend_legacy(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	if (!dev || !dev->dev_private) {
		DRM_ERROR("DRM not initialized, aborting suspend.\n");
		return -ENODEV;
	}

	DRM_DEBUG("starting suspend\n");
	i915_save_state(dev);

	return (bus_generic_suspend(kdev));
}

static int i915_resume_legacy(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);

	i915_restore_state(dev);
	DRM_DEBUG("finished resume\n");

	return (bus_generic_resume(kdev));
}

static void i915_configure(struct drm_device *dev)
{
	dev->driver->driver_features =
	   DRIVER_USE_AGP | DRIVER_REQUIRE_AGP | DRIVER_USE_MTRR |
	   DRIVER_HAVE_IRQ | DRIVER_GEM;
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
	dev->driver->master_create = i915_master_create;
	dev->driver->master_destroy = i915_master_destroy;

	dev->driver->ioctls		= i915_ioctls;
	dev->driver->max_ioctl		= i915_max_ioctl;

	dev->driver->name		= DRIVER_NAME;
	dev->driver->desc		= DRIVER_DESC;
	dev->driver->date		= DRIVER_DATE;
	dev->driver->major		= DRIVER_MAJOR;
	dev->driver->minor		= DRIVER_MINOR;
	dev->driver->patchlevel		= DRIVER_PATCHLEVEL;

#ifdef DRM_NEWER_IGEM
	dev->driver->gem_init_object = i915_gem_init_object,
	dev->driver->gem_free_object = i915_gem_free_object,
#endif

/* newer */
	dev->driver->num_ioctls = i915_max_ioctl;
}

static struct drm_driver driver = {
	/* don't use mtrr's here, the Xserver or user space app should
	 * deal with them for intel hardware.
	 */
	.driver_features =
#ifdef __linux__
	    DRIVER_USE_AGP | DRIVER_REQUIRE_AGP | /* DRIVER_USE_MTRR |*/
	    DRIVER_HAVE_IRQ | DRIVER_IRQ_SHARED | DRIVER_GEM,
#else
	    DRIVER_USE_AGP | DRIVER_REQUIRE_AGP | DRIVER_USE_MTRR |
	    DRIVER_HAVE_IRQ | DRIVER_GEM,
#endif /* __linux__ */
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
	return drm_probe(kdev, pciidlist);
}

static int
i915_attach(device_t kdev)
{
	struct drm_device *dev = device_get_softc(kdev);
	int unit = device_get_unit(kdev);
	int error;

	dev->driver = malloc(sizeof(struct drm_driver), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	i915_configure(dev);

	int retcode = drm_attach(kdev, pciidlist);

	/* add bit-banging i915_iic */
	dev->iic = device_add_child(kdev, "i915_iic", unit);
	printk("i915_attach after device_add_child\n");
	if (!dev->iic) {
		device_printf(kdev, "could not add i915_iic\n");
		goto theend;
	}
	printk("after the check for non-null dev->iic must not be null\n");
	/* probed and attached the bit-banging code */
	error = device_probe_and_attach(dev->iic);

	if (error) {
		device_printf(kdev, "could not attach i915_iic\n");
		goto theend;
	}

theend:
	return retcode;
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
	DEVMETHOD(device_suspend,	i915_suspend_legacy),
	DEVMETHOD(device_resume,	i915_resume_legacy),
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
MODULE_DEPEND(i915, i915_iic, 1, 1, 1);
#ifdef __linux__
module_init(i915_init);
module_exit(i915_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
#endif /* __linux__ */
