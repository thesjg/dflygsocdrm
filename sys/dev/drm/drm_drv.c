/**
 * \file drm_drv.c
 * Generic driver template
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 *
 * To use this template, you must at least define the following (samples
 * given for the MGA driver):
 *
 * \code
 * #define DRIVER_AUTHOR	"VA Linux Systems, Inc."
 *
 * #define DRIVER_NAME		"mga"
 * #define DRIVER_DESC		"Matrox G200/G400"
 * #define DRIVER_DATE		"20001127"
 *
 * #define drm_x		mga_##x
 * \endcode
 */

/*
 * Created: Thu Nov 23 03:10:50 2000 by gareth@valinux.com
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

#ifdef __linux__
#include <linux/debugfs.h>
#include <linux/slab.h>
#else
#include <machine/limits.h>
#endif
#include "drmP.h"
#include "drm_sarea.h"
#include "drm_core.h"


#define DRM_NEWER_IOCTL 1

#ifdef DRM_DEBUG_DEFAULT_ON
int drm_debug_flag = 1;
#else
int drm_debug_flag = 0;
#endif

#ifndef DRM_DEV_NAME
#define DRM_DEV_NAME "drm"
#endif

devclass_t drm_devclass;

DRM_PCI_DEVICE_ID *drm_find_description(int vendor, int device,
	DRM_PCI_DEVICE_ID *idlist)
{
	int i = 0;

	for (i = 0; idlist[i].vendor != 0; i++) {
		if ((idlist[i].vendor == vendor) &&
		    ((idlist[i].device == device) ||
		    (idlist[i].device == 0))) {
			return &idlist[i];
		}
	}
	return NULL;
}

#define DRIVER_SOFTC(unit) \
	((struct drm_device *)devclass_get_softc(drm_devclass, unit))

static int drm_version(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);

/** Ioctl table */
static struct drm_ioctl_desc drm_ioctls[] = {
	DRM_IOCTL_DEF(DRM_IOCTL_VERSION, drm_version, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_UNIQUE, drm_getunique, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAGIC, drm_getmagic, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_IRQ_BUSID, drm_irq_by_busid, DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAP, drm_getmap, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_CLIENT, drm_getclient, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_STATS, drm_getstats, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_SET_VERSION, drm_setversion, DRM_MASTER),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_UNIQUE, drm_setunique, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_BLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_UNBLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AUTH_MAGIC, drm_authmagic, DRM_AUTH|DRM_MASTER),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_MAP, drm_addmap_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RM_MAP, drm_rmmap_ioctl, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_SAREA_CTX, drm_setsareactx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_SAREA_CTX, drm_getsareactx, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_MASTER, drm_setmaster_ioctl, DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_DROP_MASTER, drm_dropmaster_ioctl, DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_CTX, drm_addctx, DRM_AUTH|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RM_CTX, drm_rmctx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_MOD_CTX, drm_modctx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_CTX, drm_getctx, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_SWITCH_CTX, drm_switchctx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_NEW_CTX, drm_newctx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RES_CTX, drm_resctx, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_DRAW, drm_adddraw, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RM_DRAW, drm_rmdraw, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_LOCK, drm_lock, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_UNLOCK, drm_unlock, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_FINISH, drm_noop, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_BUFS, drm_addbufs, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_MARK_BUFS, drm_markbufs, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_INFO_BUFS, drm_infobufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_MAP_BUFS, drm_mapbufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_FREE_BUFS, drm_freebufs, DRM_AUTH),
	/* The DRM_IOCTL_DMA ioctl should be defined by the driver. */
	DRM_IOCTL_DEF(DRM_IOCTL_DMA, NULL, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_CONTROL, drm_control, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

#if __OS_HAS_AGP
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ACQUIRE, drm_agp_acquire_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_RELEASE, drm_agp_release_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ENABLE, drm_agp_enable_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_INFO, drm_agp_info_ioctl, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ALLOC, drm_agp_alloc_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_FREE, drm_agp_free_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_BIND, drm_agp_bind_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_UNBIND, drm_agp_unbind_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#endif

	DRM_IOCTL_DEF(DRM_IOCTL_SG_ALLOC, drm_sg_alloc_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_SG_FREE, drm_sg_free, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_WAIT_VBLANK, drm_wait_vblank, 0),

	DRM_IOCTL_DEF(DRM_IOCTL_MODESET_CTL, drm_modeset_ctl, 0),

	DRM_IOCTL_DEF(DRM_IOCTL_UPDATE_DRAW, drm_update_drawable_info, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

#ifdef DRM_NEWER_IGEM
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_CLOSE, drm_gem_close_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_FLINK, drm_gem_flink_ioctl, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_OPEN, drm_gem_open_ioctl, DRM_AUTH|DRM_UNLOCKED),
#endif

#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETRESOURCES, drm_mode_getresources, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETCRTC, drm_mode_getcrtc, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_SETCRTC, drm_mode_setcrtc, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_CURSOR, drm_mode_cursor_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETGAMMA, drm_mode_gamma_get_ioctl, DRM_MASTER|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_SETGAMMA, drm_mode_gamma_set_ioctl, DRM_MASTER|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETENCODER, drm_mode_getencoder, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETCONNECTOR, drm_mode_getconnector, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_ATTACHMODE, drm_mode_attachmode_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_DETACHMODE, drm_mode_detachmode_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETPROPERTY, drm_mode_getproperty_ioctl, DRM_MASTER | DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_SETPROPERTY, drm_mode_connector_property_set_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETPROPBLOB, drm_mode_getblob_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_GETFB, drm_mode_getfb, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_ADDFB, drm_mode_addfb, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_RMFB, drm_mode_rmfb, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_PAGE_FLIP, drm_mode_page_flip_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_MODE_DIRTYFB, drm_mode_dirtyfb_ioctl, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED)
#endif
};

#define DRM_CORE_IOCTL_COUNT	ARRAY_SIZE( drm_ioctls )

/**
 * Take down the DRM device.
 *
 * \param dev DRM device structure.
 *
 * Frees every resource in \p dev.
 *
 * \sa drm_device
 */
int drm_lastclose(struct drm_device * dev)
{
#ifdef __linux__
	struct drm_vma_entry *vma, *vma_temp;
#endif /* __linux__ */
	int i;

	DRM_DEBUG("\n");

	if (dev->driver->lastclose)
		dev->driver->lastclose(dev);
	DRM_DEBUG("driver lastclose completed\n");

	if (dev->irq_enabled && !drm_core_check_feature(dev, DRIVER_MODESET))
		drm_irq_uninstall(dev);

	mutex_lock(&dev->struct_mutex);

	/* Free drawable information memory */
	drm_drawable_free_all(dev);
#if 0 /* UNUSED? */
	del_timer(&dev->timer);
#endif

	/* Clear AGP information */
	if (drm_core_has_AGP(dev) && dev->agp &&
			!drm_core_check_feature(dev, DRIVER_MODESET)) {
		struct drm_agp_mem *entry, *tempe;

		/* Remove AGP resources, but leave dev->agp
		   intact until drv_cleanup is called. */
		list_for_each_entry_safe(entry, tempe, &dev->agp->memory, head) {
			if (entry->bound)
				drm_unbind_agp(entry->memory);
#if 0

				drm_agp_unbind_memory(entry->memory);
#endif
#ifdef __linux__
			drm_free_agp(entry->memory, entry->pages);
			kfree(entry);
#else
			drm_agp_free_memory(entry->memory);
			free(entry, DRM_MEM_AGPLISTS);
#endif
		}
		INIT_LIST_HEAD(&dev->agp->memory);

		if (dev->agp->acquired)
			drm_agp_release(dev);

		dev->agp->acquired = 0;
		dev->agp->enabled = 0;
	}
	if (drm_core_check_feature(dev, DRIVER_SG) && dev->sg &&
	    !drm_core_check_feature(dev, DRIVER_MODESET)) {
		drm_sg_cleanup(dev->sg);
		dev->sg = NULL;
	}

#ifdef __linux__ /* UNIMPLEMENTED */
	/* Clear vma list (only built for debugging) */
	list_for_each_entry_safe(vma, vma_temp, &dev->vmalist, head) {
		list_del(&vma->head);
		kfree(vma);
	}
#endif

	if (drm_core_check_feature(dev, DRIVER_DMA_QUEUE) && dev->queuelist) {
		for (i = 0; i < dev->queue_count; i++) {
#ifdef __linux__ /* UNIMPLEMENTED */
			kfree(dev->queuelist[i]);
#endif /* __linux__ */
			dev->queuelist[i] = NULL;
		}
#ifdef __linux__
		kfree(dev->queuelist);
#endif /* __linux__ */
		dev->queuelist = NULL;
	}
	dev->queue_count = 0;

	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !drm_core_check_feature(dev, DRIVER_MODESET))
		drm_dma_takedown(dev);

	dev->dev_mapping = NULL;
	mutex_unlock(&dev->struct_mutex);

	DRM_DEBUG("lastclose completed\n");
	return 0;
}

/**
 * Module initialization. Called via init_module at module load time, or via
 * linux/init/main.c (this is not currently supported).
 *
 * \return zero on success or a negative number on failure.
 *
 * Initializes an array of drm_device structures, and attempts to
 * initialize all available devices, using consecutive minors, registering the
 * stubs and initializing the AGP device.
 *
 * Expands the \c DRIVER_PREINIT and \c DRIVER_POST_INIT macros before and
 * after the initialization for driver customization.
 */
int drm_init(struct drm_driver *driver)
{
#ifdef __linux__
	struct pci_dev *pdev = NULL;
	const struct pci_device_id *pid;
	int i;
#endif /* __linux__ */

	DRM_DEBUG("\n");

	INIT_LIST_HEAD(&driver->device_list);

#ifdef __linux__ /* UNIMPLEMENTED */
	if (driver->driver_features & DRIVER_MODESET)
		return pci_register_driver(&driver->pci_driver);

	/* If not using KMS, fall back to stealth mode manual scanning. */
	for (i = 0; driver->pci_driver.id_table[i].vendor != 0; i++) {
		pid = &driver->pci_driver.id_table[i];

		/* Loop around setting up a DRM device for each PCI device
		 * matching our ID and device class.  If we had the internal
		 * function that pci_get_subsys and pci_get_class used, we'd
		 * be able to just pass pid in instead of doing a two-stage
		 * thing.
		 */
		pdev = NULL;
		while ((pdev =
			pci_get_subsys(pid->vendor, pid->device, pid->subvendor,
				       pid->subdevice, pdev)) != NULL) {
			if ((pdev->class & pid->class_mask) != pid->class)
				continue;

			/* stealth mode requires a manual probe */
			pci_dev_get(pdev);
			drm_get_dev(pdev, pid, driver);
		}
	}
#endif /* __linux__ */
	return 0;
}

EXPORT_SYMBOL(drm_init);

void drm_exit(struct drm_driver *driver)
{
#ifdef __linux__ /* UNIMPLEMENTED */
	struct drm_device *dev, *tmp;
	DRM_DEBUG("\n");

	if (driver->driver_features & DRIVER_MODESET) {
		pci_unregister_driver(&driver->pci_driver);
	} else {
		list_for_each_entry_safe(dev, tmp, &driver->device_list, driver_item)
			drm_put_dev(dev);
	}
#endif /* __linux__ */

	DRM_INFO("Module unloaded\n");
}

EXPORT_SYMBOL(drm_exit);

#ifdef __linux__ /* UNIMPLEMENTED */
/** File operations structure */
static const struct file_operations drm_stub_fops = {
	.owner = THIS_MODULE,
	.open = drm_stub_open
};
#endif

static int __init drm_core_init(void)
{
	int ret = -ENOMEM;

	idr_init(&drm_minors_idr);

#ifdef __linux__
	if (register_chrdev(DRM_MAJOR, "drm", &drm_stub_fops))
		goto err_p1;

	drm_class = drm_sysfs_create(THIS_MODULE, "drm");
	if (IS_ERR(drm_class)) {
		printk(KERN_ERR "DRM: Error creating drm class.\n");
		ret = PTR_ERR(drm_class);
		goto err_p2;
	}

	drm_proc_root = proc_mkdir("dri", NULL);
	if (!drm_proc_root) {
		DRM_ERROR("Cannot create /proc/dri\n");
		ret = -1;
		goto err_p3;
	}

	drm_debugfs_root = debugfs_create_dir("dri", NULL);
	if (!drm_debugfs_root) {
		DRM_ERROR("Cannot create /sys/kernel/debug/dri\n");
		ret = -1;
		goto err_p3;
	}
#else /* !__linux__ */
	drm_sysctl_root = drm_sysctl_mkroot("dri");
	if (!drm_sysctl_root) {
		DRM_ERROR("Cannot create sysctl hw.dri\n");
		ret = -1;
		goto err_p2;
	}
#endif /* !__linux__ */

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
		 CORE_NAME, CORE_MAJOR, CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
	return 0;
#ifdef __linux__
err_p3:
	drm_sysfs_destroy();
#endif
err_p2:
#ifdef __linux__
	unregister_chrdev(DRM_MAJOR, "drm");

#endif
	idr_destroy(&drm_minors_idr);
#ifdef __linux__
err_p1:
#endif
	return ret;
}

static void __exit drm_core_exit(void)
{
#ifdef __linux__
	remove_proc_entry("dri", NULL);
	debugfs_remove(drm_debugfs_root);
	drm_sysfs_destroy();

	unregister_chrdev(DRM_MAJOR, "drm");
#else
	DRM_INFO("Exiting drm module %s %d.%d.%d %s\n",
		 CORE_NAME, CORE_MAJOR, CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
	drm_sysctl_rmroot(drm_sysctl_root);
	drm_sysctl_root = NULL;
#endif

	idr_destroy(&drm_minors_idr);
}

#ifdef __linux__
module_init(drm_core_init);
module_exit(drm_core_exit);
#endif /* __linux__ */

/**
 * Copy and IOCTL return string to user space
 */
static int drm_copy_field(char *buf, size_t *buf_len, const char *value)
{
	int len;

	/* don't overflow userbuf */
	len = strlen(value);
	if (len > *buf_len)
		len = *buf_len;

	/* let userspace know exact length of driver value (which could be
	 * larger than the userspace-supplied buffer) */
	*buf_len = strlen(value);

	/* finally, try filling in the userbuf */
	if (len && buf)
		if (copy_to_user(buf, value, len))
			return -EFAULT;
	return 0;
}

/**
 * Get version information
 *
 * \param inode device inode.
 * \param filp file pointer.
 * \param cmd command.
 * \param arg user argument, pointing to a drm_version structure.
 * \return zero on success or negative number on failure.
 *
 * Fills in the version information in \p arg.
 */
static int drm_version(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct drm_version *version = data;
	int err;

	version->version_major = dev->driver->major;
	version->version_minor = dev->driver->minor;
	version->version_patchlevel = dev->driver->patchlevel;
	err = drm_copy_field(version->name, &version->name_len,
			dev->driver->name);
	if (!err)
		err = drm_copy_field(version->date, &version->date_len,
				dev->driver->date);
	if (!err)
		err = drm_copy_field(version->desc, &version->desc_len,
				dev->driver->desc);

	return err;
#if 0
	int len;

#define DRM_COPY( name, value )						\
	len = strlen( value );						\
	if ( len > name##_len ) len = name##_len;			\
	name##_len = strlen( value );					\
	if ( len && name ) {						\
		if ( DRM_COPY_TO_USER( name, value, len ) )		\
			return EFAULT;				\
	}

	version->version_major		= dev->driver->major;
	version->version_minor		= dev->driver->minor;
	version->version_patchlevel	= dev->driver->patchlevel;

	DRM_COPY(version->name, dev->driver->name);
	DRM_COPY(version->date, dev->driver->date);
	DRM_COPY(version->desc, dev->driver->desc);

	return 0;
#endif
}

/**
 * Called whenever a process performs an ioctl on /dev/drm.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg user argument.
 * \return zero on success or negative number on failure.
 *
 * Looks up the ioctl function in the ::ioctls table, checking for root
 * previleges if so required, and dispatches to the respective function.
 */
#ifdef __linux__
long drm_ioctl(struct file *filp,
	      unsigned int cmd, unsigned long arg)
#else
int drm_ioctl_legacy(struct dev_ioctl_args *ap)
#endif
{
#ifdef __linux__
	struct drm_file *file_priv = filp->private_data;
	struct drm_device *dev;
#else /* !__linux__ */
	struct cdev *kdev = ap->a_head.a_dev;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;
	struct thread *p = curthread;

	struct drm_device *dev = drm_get_device_from_kdev(kdev);
	struct drm_file *file_priv;

	spin_lock(&dev->file_priv_lock);
	file_priv = drm_find_file_by_proc(dev, p);
	spin_unlock(&dev->file_priv_lock);

	if (!file_priv) {
		DRM_ERROR("file_priv null\n");
		return EINVAL;
	}
	if (!file_priv->minor) {
		DRM_ERROR("file_priv has no minor\n");
	}
	if (file_priv->minor && (dev != file_priv->minor->dev)) {
		DRM_ERROR("drm_get_device_from_kdev dev != file_priv->minor->dev\n");
	}
#endif /* !__linux__ */
	struct drm_ioctl_desc *ioctl;
	drm_ioctl_t *func;
	unsigned int nr = DRM_IOCTL_NR(cmd);
#ifdef __linux__
	int retcode = -EINVAL;
#else /* !__linux__ */
	int retcode = EINVAL;
#endif /* !__linux__ */
#ifdef __linux__
	char stack_kdata[128];
	char *kdata = NULL;
#endif
#if 0 /* !__linux__ */
	int is_driver_ioctl = 0;
#endif /* __linux__ */

	dev = file_priv->minor->dev;
#ifdef __linux__
	atomic_inc(&dev->ioctl_count);
#endif
	atomic_inc(&dev->counts[_DRM_STAT_IOCTLS]);
	++file_priv->ioctl_count;

#ifdef __linux__
	DRM_DEBUG("pid=%d, cmd=0x%02x, nr=0x%02x, dev 0x%lx, auth=%d\n",
		  task_pid_nr(current), cmd, nr,
		  (long)old_encode_dev(file_priv->minor->device),
		  file_priv->authenticated);
#else
	DRM_DEBUG("pid=%d, cmd=0x%02lx, nr=0x%02x, dev 0x%lx, auth=%d\n",
		  task_pid_nr(current), cmd, nr,
		  (long)dev->device,
		  file_priv->authenticated);
#endif

#ifndef __linux__ /* legacy BSD */
	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		return 0;

	case FIOSETOWN:
		return fsetown(*(int *)data, &dev->buf_sigio);

	case FIOGETOWN:
		*(int *) data = fgetown(&dev->buf_sigio);
		return 0;
	}

	if (IOCGROUP(cmd) != DRM_IOCTL_BASE) {
		DRM_INFO("Bad ioctl group 0x%x\n", (int)IOCGROUP(cmd));
		return EINVAL;
	}

	atomic_inc(&dev->ioctl_count);
#endif /* !__linux__ */

/* DRM_NEWER_IOCTL */
	if ((nr >= DRM_CORE_IOCTL_COUNT) &&
	    ((nr < DRM_COMMAND_BASE) || (nr >= DRM_COMMAND_END)))
		goto err_i1;
#if 1 /* __linux__ */
	if ((nr >= DRM_COMMAND_BASE) && (nr < DRM_COMMAND_END) &&
	    (nr < DRM_COMMAND_BASE + dev->driver->num_ioctls))
		ioctl = &dev->driver->ioctls[nr - DRM_COMMAND_BASE];
#endif
#if 0 /* !__linux__ */
	if ((nr >= DRM_COMMAND_BASE) && (nr < DRM_COMMAND_END) &&
	    (nr < DRM_COMMAND_BASE + dev->driver->num_ioctls)) {
		ioctl = &dev->driver->ioctls[nr - DRM_COMMAND_BASE];
		is_driver_ioctl = 1;
	}
#endif
	else if ((nr >= DRM_COMMAND_END) || (nr < DRM_COMMAND_BASE)) {
		ioctl = &drm_ioctls[nr];
#ifndef __linux__
		if ((unsigned int)cmd != (unsigned int)ioctl->cmd) {
			DRM_ERROR("cmd (%d) != ioctrl->cmd (%d)\n",
				(unsigned int)cmd,
				(unsigned int)ioctl->cmd);
		}
#endif /* !__linux__ */
#if 1 /* __linux__  */
		cmd = ioctl->cmd;
#endif
	} else
		goto err_i1;
#if 0 /* !DRM_NEWER_IOCTL */
	ioctl = &drm_ioctls[nr];
	/* It's not a core DRM ioctl, try driver-specific. */
	if (ioctl->func == NULL && nr >= DRM_COMMAND_BASE) {
		/* The array entries begin at DRM_COMMAND_BASE ioctl nr */
		nr -= DRM_COMMAND_BASE;
		if (nr > dev->driver->num_ioctls) {
			DRM_DEBUG("Bad driver ioctl number, 0x%x (of 0x%x)\n",
			    nr, dev->driver->num_ioctls);
			goto err_i1;
		}
		ioctl = &dev->driver->ioctls[nr];
		is_driver_ioctl = 1;
	}
#endif /* DRM_NEWER_IOCTL */

	/* Do not trust userspace, use our own definition */
	func = ioctl->func;
	/* is there a local override? */
	if ((nr == DRM_IOCTL_NR(DRM_IOCTL_DMA)) && dev->driver->dma_ioctl)
		func = dev->driver->dma_ioctl;

	if (!func) {
		DRM_DEBUG("no function\n");
		retcode = EINVAL;
	} else
#ifdef __linux__
	        if (((ioctl->flags & DRM_ROOT_ONLY) && !capable(CAP_SYS_ADMIN)) ||
		   ((ioctl->flags & DRM_AUTH) && !file_priv->authenticated) ||
		   ((ioctl->flags & DRM_MASTER) && !file_priv->is_master) ||
		   (!(ioctl->flags & DRM_CONTROL_ALLOW) && (file_priv->minor->type == DRM_MINOR_CONTROL))) {
		retcode = -EACCES;
	}
#else
	        if (((ioctl->flags & DRM_ROOT_ONLY) && !capable(CAP_SYS_ADMIN)) ||
	 	   ((ioctl->flags & DRM_AUTH) && !file_priv->authenticated) ||
	 	   ((ioctl->flags & DRM_MASTER) && !file_priv->is_master)) {
		retcode = EACCES;
	}
#endif
	  else {
#ifndef __linux__
		if (!(ioctl->flags & DRM_CONTROL_ALLOW) && (file_priv->minor->type == DRM_MINOR_CONTROL)) {
			DRM_ERROR("!DRM_CONTROL_ALLOW yet minor->type == DRM_MINOR_CONTROL!\n");
		}
#endif

#ifdef __linux__
		if (cmd & (IOC_IN | IOC_OUT)) {
			if (_IOC_SIZE(cmd) <= sizeof(stack_kdata)) {
				kdata = stack_kdata;
			} else {
				kdata = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
				if (!kdata) {
					retcode = -ENOMEM;
					goto err_i1;
				}
			}
		}

		if (cmd & IOC_IN) {
			if (copy_from_user(kdata, (void __user *)arg,
					   _IOC_SIZE(cmd)) != 0) {
				retcode = -EFAULT;
				goto err_i1;
			}
		} else
			memset(kdata, 0, _IOC_SIZE(cmd));
#endif /* __linux__ */

#if 0
	if (is_driver_ioctl) {
		if (!(ioctl->flags & DRM_UNLOCKED))
/* DRM_NEWER_RATLOCK */
			mutex_lock(&drm_global_mutex);
#if 0 /* !DRM_NEWER_RATLOCK */
			lock_kernel();
#endif /* DRM_NEWER_RATLOCK */
/* legacy drm BSD: this lock seems essential for stability */
#if 0 /* !DRM_NEWER_RATLOCK */
		DRM_LOCK();
#endif
		retcode = -func(dev, data, file_priv);
#if 0 /* !DRM_NEWER_RATLOCK */
		DRM_UNLOCK();
#endif

		if (!(ioctl->flags & DRM_UNLOCKED))
/* DRM_NEWER_RATLOCK */
			mutex_unlock(&drm_global_mutex);
#if 0 /* !DRM_NEWER_RATLOCK */
			unlock_kernel();
#endif /* DRM_NEWER_RATLOCK */
	} else {
		if (!(ioctl->flags & DRM_UNLOCKED))
/* DRM_NEWER_RATLOCK */
			mutex_lock(&drm_global_mutex);
#if 0 /* !DRM_NEWER_RATLOCK */
			lock_kernel();
#endif /* DRM_NEWER_RATLOCK */
		retcode = -func(dev, data, file_priv);

		if (!(ioctl->flags & DRM_UNLOCKED))
/* DRM_NEWER_RATLOCK */
			mutex_unlock(&drm_global_mutex);
#if 0 /* !DRM_NEWER_RATLOCK */
			unlock_kernel();
#endif /* DRM_NEWER_RATLOCK */
	}
#endif

#ifdef __linux__
		if (ioctl->flags & DRM_UNLOCKED)
			retcode = func(dev, kdata, file_priv);
		else {
			lock_kernel();
			retcode = func(dev, kdata, file_priv);
			unlock_kernel();
		}
#else
		if (ioctl->flags & DRM_UNLOCKED)
			retcode = -func(dev, data, file_priv);
		else {
			mutex_lock(&drm_global_mutex);
			retcode = -func(dev, data, file_priv);
			mutex_unlock(&drm_global_mutex);
		}
#endif

#ifdef __linux__
		if (cmd & IOC_OUT) {
			if (copy_to_user((void __user *)arg, kdata,
					 _IOC_SIZE(cmd)) != 0)
				retcode = -EFAULT;
		}
#endif
	}

      err_i1:
#ifdef __linux__
	if (kdata != stack_kdata)
		kfree(kdata);
#endif
	atomic_dec(&dev->ioctl_count);
	if (retcode)
		DRM_DEBUG("ret = %x\n", retcode);
	return retcode;
}

EXPORT_SYMBOL(drm_ioctl);

struct drm_local_map *drm_getsarea(struct drm_device *dev)
{
	struct drm_map_list *entry;

	list_for_each_entry(entry, &dev->maplist, head) {
		if (entry->map && entry->map->type == _DRM_SHM &&
		    (entry->map->flags & _DRM_CONTAINS_LOCK)) {
			return entry->map;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(drm_getsarea);

static int drm_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		drm_core_init();
		break;
	case MOD_UNLOAD:
		drm_core_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

int drm_probe(device_t kdev, DRM_PCI_DEVICE_ID *idlist)
{
	DRM_PCI_DEVICE_ID *id_entry;
	int vendor, device;

	vendor = pci_get_vendor(kdev);
	device = pci_get_device(kdev);

	if (pci_get_class(kdev) != PCIC_DISPLAY
	    || pci_get_subclass(kdev) != PCIS_DISPLAY_VGA)
		return ENXIO;

	id_entry = drm_find_description(vendor, device, idlist);
	if (id_entry != NULL) {
		DRM_INFO("drm_probe: vendor 0x%4x, device 0x%4x, class 0x%4x, subclass 0x%4x, device_get_desc %s\n",
			pci_get_vendor(kdev), pci_get_device(kdev),
			pci_get_class(kdev), pci_get_subclass(kdev), device_get_desc(kdev));
		if (!device_get_desc(kdev)) {
			DRM_DEBUG("desc : %s\n", device_get_desc(kdev));
			device_set_desc(kdev, "UNKNOWN");
#if 0
			device_set_desc(kdev, id_entry->name);
#endif
		}
		return 0;
	}

	return ENXIO;
}

int drm_attach(device_t kdev, DRM_PCI_DEVICE_ID *idlist)
{
	return drm_get_dev(kdev, idlist);
}

int drm_detach(device_t kdev)
{
	struct drm_device *dev;
	int i;

	dev = device_get_softc(kdev);

	drm_put_dev(dev);

	/* Clean up PCI resources allocated by drm_bufs.c.  We're not really
	 * worried about resource consumption while the DRM is inactive (between
	 * lastclose and firstopen or unload) because these aren't actually
	 * taking up KVA, just keeping the PCI resource allocated.
	 */
	for (i = 0; i < DRM_MAX_PCI_RESOURCE; i++) {
		if (dev->pcir[i] == NULL)
			continue;
		bus_release_resource(dev->device, SYS_RES_MEMORY,
		    dev->pcirid[i], dev->pcir[i]);
		dev->pcir[i] = NULL;
	}

	pci_disable_busmaster(dev->device);

	DRM_SPINUNINIT(&dev->drw_lock);
	DRM_SPINUNINIT(&dev->dev_lock);
	
	if (dev->irqr) {
		bus_release_resource(dev->device, SYS_RES_IRQ, dev->irqrid,
		    dev->irqr);

#if 0
		if (dev->msi_enabled) {
			pci_release_msi(dev->device);
			DRM_INFO("MSI released\n");
		}
#endif
	}

	return 0;
}

static moduledata_t drm_data= {
	"drm",
	drm_handler,
	0
};

MODULE_VERSION(drm, 1);
DECLARE_MODULE(drm, drm_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(drm, agp, 1, 1, 1);
MODULE_DEPEND(drm, pci, 1, 1, 1);
