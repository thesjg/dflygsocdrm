/**
 * \file drm_stub.h
 * Stub support
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 */

/*
 * Created: Fri Jan 19 10:48:35 2001 by faith@acm.org
 *
 * Copyright 2001 VA Linux Systems, Inc., Sunnyvale, California.
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
 */

#ifdef __linux__
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#endif /* __linux__ */
#include "drmP.h"
#include "drm_core.h"

unsigned int drm_debug = 0;	/* 1 to enable debug output */
EXPORT_SYMBOL(drm_debug);

MODULE_AUTHOR(CORE_AUTHOR);
MODULE_DESCRIPTION(CORE_DESC);
MODULE_LICENSE("GPL and additional rights");
MODULE_PARM_DESC(debug, "Enable debug output");

module_param_named(debug, drm_debug, int, 0600);

static struct dev_ops drm_cdevsw = {
/*	{ "drm", 145, D_TRACKCLOSE | D_KQFILTER }, */
	{ "drm", 145, D_TRACKCLOSE },
	.d_open =       drm_open_legacy,
	.d_close =	drm_close_legacy,
	.d_read =       drm_read_legacy,
	.d_ioctl =      drm_ioctl_legacy,
	.d_kqfilter =   drm_kqfilter,
	.d_mmap =       drm_mmap_legacy
};

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

struct idr drm_minors_idr;

struct class *drm_class;
struct proc_dir_entry *drm_proc_root;
struct dentry *drm_debugfs_root;
void drm_ut_debug_printk(unsigned int request_level,
			 const char *prefix,
			 const char *function_name,
			 const char *format, ...)
{
	va_list args;

	if (drm_debug & request_level) {
		if (function_name)
			printk(KERN_DEBUG "[%s:%s], ", prefix, function_name);
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
	}
}
EXPORT_SYMBOL(drm_ut_debug_printk);
static int drm_minor_get_id(struct drm_device *dev, int type)
{
	int new_id;
	int ret;
/* if (type == DRM_MINOR_LEGACY) */
#ifdef __linux__
	int base = 0, limit = 63;
#else /* unit == 0 most common case */
	int base = dev->unit - 1, limit = 63;
#endif

	if (type == DRM_MINOR_CONTROL) {
                base += 64;
                limit = base + 127;
        } else if (type == DRM_MINOR_RENDER) {
                base += 128;
                limit = base + 255;
        }

again:
	if (idr_pre_get(&drm_minors_idr, GFP_KERNEL) == 0) {
		DRM_ERROR("Out of memory expanding drawable idr\n");
		return -ENOMEM;
	}
	mutex_lock(&dev->struct_mutex);
	ret = idr_get_new_above(&drm_minors_idr, NULL,
				base, &new_id);
	mutex_unlock(&dev->struct_mutex);
	if (ret == -EAGAIN) {
		goto again;
	} else if (ret) {
		return ret;
	}

	if (new_id >= limit) {
		idr_remove(&drm_minors_idr, new_id);
		return -EINVAL;
	}
#ifndef __linux__
	if ((type == DRM_MINOR_LEGACY) && (new_id != dev->unit))
		DRM_ERROR("Invalid minor id %d not unit %d\n", new_id, dev->unit);
#endif /* __linux__ */
	return new_id;
}

struct drm_master *drm_master_create(struct drm_minor *minor)
{
	struct drm_master *master;

	master = malloc(sizeof(*master), DRM_MEM_STUB, M_WAITOK | M_ZERO);
	if (!master)
		return NULL;

	kref_init(&master->refcount);
	spin_lock_init(&master->lock.spinlock);
	init_waitqueue_head(&master->lock.lock_queue);
	drm_ht_create(&master->magiclist, DRM_MAGIC_HASH_ORDER);
	INIT_LIST_HEAD(&master->magicfree);
	master->minor = minor;

	list_add_tail(&master->head, &minor->master_list);

	return master;
}

struct drm_master *drm_master_get(struct drm_master *master)
{
	kref_get(&master->refcount);
	return master;
}
EXPORT_SYMBOL(drm_master_get);

static void drm_master_destroy(struct kref *kref)
{
	struct drm_master *master = container_of(kref, struct drm_master, refcount);
	struct drm_magic_entry *pt, *next;
	struct drm_device *dev = master->minor->dev;
	struct drm_map_list *r_list, *list_temp;

	list_del(&master->head);

	if (dev->driver->master_destroy)
		dev->driver->master_destroy(dev, master);

	list_for_each_entry_safe(r_list, list_temp, &dev->maplist, head) {
		if (r_list->master == master) {
			drm_rmmap_locked(dev, r_list->map);
			r_list = NULL;
		}
	}

	if (master->unique) {
		free(master->unique, DRM_MEM_DRIVER);
		master->unique = NULL;
		master->unique_len = 0;
	}

	list_for_each_entry_safe(pt, next, &master->magicfree, head) {
		list_del(&pt->head);
		drm_ht_remove_item(&master->magiclist, &pt->hash_item);
		free(pt, DRM_MEM_MAGIC);
	}

	drm_ht_remove(&master->magiclist);

#ifndef __linux__
	DRM_INFO("master destroyed by pid (%d), minor_id (%d)\n",
		DRM_CURRENTPID, master->minor->index);
#endif /* !__linux__ */
	free(master, DRM_MEM_STUB);
}

void drm_master_put(struct drm_master **master)
{
	kref_put(&(*master)->refcount, drm_master_destroy);
	*master = NULL;
}
EXPORT_SYMBOL(drm_master_put);

int drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	int ret = 0;

	if (file_priv->is_master)
		return 0;

	if (file_priv->minor->master && file_priv->minor->master != file_priv->master)
		return -EINVAL;

	if (!file_priv->master)
		return -EINVAL;

	if (!file_priv->minor->master &&
	    file_priv->minor->master != file_priv->master) {
		mutex_lock(&dev->struct_mutex);
		file_priv->minor->master = drm_master_get(file_priv->master);
		file_priv->is_master = 1;
		if (dev->driver->master_set) {
			ret = dev->driver->master_set(dev, file_priv, false);
			if (unlikely(ret != 0)) {
				file_priv->is_master = 0;
				drm_master_put(&file_priv->minor->master);
			}
		}
		mutex_unlock(&dev->struct_mutex);
	}

	return 0;
}

int drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	if (!file_priv->is_master)
		return -EINVAL;

	if (!file_priv->minor->master)
		return -EINVAL;

	mutex_lock(&dev->struct_mutex);
	if (dev->driver->master_drop)
		dev->driver->master_drop(dev, file_priv, false);
	drm_master_put(&file_priv->minor->master);
	file_priv->is_master = 0;
	mutex_unlock(&dev->struct_mutex);
	return 0;
}

static int drm_fill_in_dev(struct drm_device *dev, device_t kdev,
			   DRM_PCI_DEVICE_ID *idlist,
			   struct drm_driver *driver)
{
	int i;
	DRM_PCI_DEVICE_ID *id_entry;

	int retcode;

	INIT_LIST_HEAD(&dev->filelist);
	INIT_LIST_HEAD(&dev->ctxlist);
	INIT_LIST_HEAD(&dev->vmalist);
	INIT_LIST_HEAD(&dev->maplist);
	INIT_LIST_HEAD(&dev->vblank_event_list);

	spin_lock_init(&dev->count_lock);
	DRM_SPININIT(&dev->drw_lock, "drmdrw");
	spin_lock_init(&dev->event_lock);
	init_timer(&dev->timer);
	mutex_init(&dev->struct_mutex);
	mutex_init(&dev->ctxlist_mutex);

	idr_init(&dev->drw_idr);

#ifndef __linux__
	DRM_SPININIT(&dev->dev_lock, "drmdev");
	lwkt_serialize_init(&dev->irq_lock);
	DRM_SPININIT(&dev->static_lock, "drmsta");
	DRM_SPININIT(&dev->file_priv_lock, "drmsta");
#endif /* __linux__ */

	dev->device = kdev;
	dev->unit = device_get_unit(kdev);
	dev->pci_device = pci_get_device(dev->device);
	dev->pci_vendor = pci_get_vendor(dev->device);

#ifndef __linux__
	dev->pci_domain = 0;
	dev->pci_bus = pci_get_bus(dev->device);
	dev->pci_slot = pci_get_slot(dev->device);
	dev->pci_func = pci_get_function(dev->device);

	id_entry = drm_find_description(dev->pci_vendor,
	    dev->pci_device, idlist);
	dev->id_entry = id_entry;

	TAILQ_INIT(&dev->maplist_legacy);
	TAILQ_INIT(&dev->files);

/* also done in drm_fops.c */
	for (i = 0; i < DRM_ARRAY_SIZE(dev->counts); i++)
		atomic_set(&dev->counts[i], 0);

#endif /* __linux__ */

	if (drm_ht_create(&dev->map_hash, 12)) {
		return -ENOMEM;
	}

	/* the DRM has 6 basic counters */
	dev->counters = 6;
	dev->types[0] = _DRM_STAT_LOCK;
	dev->types[1] = _DRM_STAT_OPENS;
	dev->types[2] = _DRM_STAT_CLOSES;
	dev->types[3] = _DRM_STAT_IOCTLS;
	dev->types[4] = _DRM_STAT_LOCKS;
	dev->types[5] = _DRM_STAT_UNLOCKS;

#ifdef __linux /* driver already set otherwise */
	dev->driver = driver;
#endif /* __linux__ */

	if (drm_core_has_AGP(dev)) {
		if (drm_device_is_agp(dev))
			dev->agp = drm_agp_init(dev);
		if (drm_core_check_feature(dev, DRIVER_REQUIRE_AGP)
		    && (dev->agp == NULL)) {
			DRM_ERROR("Cannot initialize the agpgart module.\n");
			retcode = -EINVAL;
			goto error_out_unreg;
		}
#ifdef __linux__
		if (drm_core_has_MTRR(dev)) {
			if (dev->agp)
				dev->agp->agp_mtrr =
				    mtrr_add(dev->agp->agp_info.aper_base,
					     dev->agp->agp_info.aper_size *
					     1024 * 1024, MTRR_TYPE_WRCOMB, 1);
		}
#else
#ifdef DRM_NEWER_MTRR
		if (drm_core_has_MTRR(dev)) {
			if (dev->agp) {
				if (drm_mtrr_add(dev->agp->info.ai_aperture_base,
				    dev->agp->info.ai_aperture_size, DRM_MTRR_WC) == 0)
					dev->agp->mtrr = 1;
			}
		}
#else
		if (dev->agp != NULL) {
			if (drm_mtrr_add(dev->agp->info.ai_aperture_base,
			    dev->agp->info.ai_aperture_size, DRM_MTRR_WC) == 0)
				dev->agp->mtrr = 1;
		}
#endif
#endif /* __linux__ */
	}

	retcode = drm_ctxbitmap_init(dev);
	if (retcode) {
		DRM_ERROR("Cannot allocate memory for context bitmap.\n");
		goto error_out_unreg;
	}

	if (driver->driver_features & DRIVER_GEM) {
		retcode = drm_gem_init(dev);
#if 0
	if (dev->driver->driver_features & DRIVER_GEM) {
		retcode = 0;
#endif
		if (retcode) {
			DRM_ERROR("Cannot initialize graphics execution "
				  "manager (GEM)\n");
			goto error_out_unreg;
		}
	}

	return 0;

      error_out_unreg:
	drm_lastclose(dev);
	return retcode;
}

/**
 * Get a secondary minor number.
 *
 * \param dev device data structure
 * \param sec-minor structure to hold the assigned minor
 * \return negative number on failure.
 *
 * Search an empty entry and initialize it to the given parameters, and
 * create the proc init entry via proc_init(). This routines assigns
 * minor numbers to secondary heads of multi-headed cards
 */
static int drm_get_minor(struct drm_device *dev, struct drm_minor **minor, int type)
{
	struct drm_minor *new_minor;
	int ret;
	int minor_id;

	DRM_DEBUG("\n");

	minor_id = drm_minor_get_id(dev, type);
	if (minor_id < 0)
		return minor_id;

	new_minor = malloc(sizeof(struct drm_minor), DRM_MEM_STUB, M_WAITOK | M_ZERO);
	if (!new_minor) {
		ret = -ENOMEM;
		goto err_idr;
	}

	new_minor->type = type;
	new_minor->device = MKDEV(DRM_MAJOR, minor_id);
	new_minor->dev = dev;
	new_minor->index = minor_id;
	INIT_LIST_HEAD(&new_minor->master_list);

	idr_replace(&drm_minors_idr, new_minor, minor_id);

	if (type == DRM_MINOR_LEGACY) {
#ifdef __linux__
		ret = drm_proc_init(new_minor, minor_id, drm_proc_root);
#else /* to compile maybe should initialize drm_sysctl here */
		ret = drm_sysctl_init(new_minor, minor_id, drm_sysctl_root);
		ret = 0;
#endif
		if (ret) {
			DRM_ERROR("DRM: Failed to initialize /proc/dri.\n");
			goto err_mem;
		}
	} else
		new_minor->proc_root = NULL;

#if defined(CONFIG_DEBUG_FS)
#ifdef __linux__
	ret = drm_debugfs_init(new_minor, minor_id, drm_debugfs_root);
#else /* to compile */
	ret = 0;
#endif /* __linux__ */
	if (ret) {
		DRM_ERROR("DRM: Failed to initialize /sys/kernel/debug/dri.\n");
		goto err_g2;
	}
#endif

#ifdef __linux__
	ret = drm_sysfs_device_add(new_minor);
#else /* to compile */
	ret = 0;
#endif
	if (ret) {
		printk(KERN_ERR
		       "DRM: Error sysfs_device_add.\n");
		goto err_g2;
	}
	*minor = new_minor;

	DRM_DEBUG("new minor assigned %d\n", minor_id);
#ifndef __linux__
	DRM_INFO("new minor %d assigned of type %d\n", minor_id, type);
#endif /* !__linux__ */
	return 0;


err_g2:
#ifdef __linux__
	if (new_minor->type == DRM_MINOR_LEGACY)
		drm_proc_cleanup(new_minor, drm_proc_root);
#endif /* __linux__ */
err_mem:
	free(new_minor, DRM_MEM_STUB);
err_idr:
	idr_remove(&drm_minors_idr, minor_id);
	*minor = NULL;
	return ret;
}

/**
 * Register.
 *
 * \param pdev - PCI device structure
 * \param ent entry from the PCI ID table with device type flags
 * \return zero on success or a negative number on failure.
 *
 * Attempt to gets inter module "drm" information. If we are first
 * then register the character device and inter module information.
 * Try and register, if we fail to register, backout previous work.
 */
int drm_get_dev(DRM_GET_DEV_ARGS)
{
	int unit;

	struct drm_device *dev;
	int ret;

#if 0
	int msicount;
#endif

	unit = device_get_unit(kdev);
	dev = device_get_softc(kdev);
	dev->device = kdev;

	if (!dev)
		return -ENOMEM;

	pci_enable_busmaster(dev->device);

	if (drm_core_check_feature(dev, DRIVER_HAVE_IRQ)) {
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
		    &dev->irqrid, RF_SHAREABLE);
		if (!dev->irqr) {
			return ENOENT;
		}

		dev->irq = (int) rman_get_start(dev->irqr);
	}

	if ((ret = drm_fill_in_dev(dev, kdev, idlist, dev->driver))) {
		printk(KERN_ERR "DRM: Fill_in_dev failed.\n");
		goto err_g2;
	}

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		ret = drm_get_minor(dev, &dev->control, DRM_MINOR_CONTROL);
		if (ret)
			goto err_g2;
	}

	if ((ret = drm_get_minor(dev, &dev->primary, DRM_MINOR_LEGACY)))
		goto err_g3;

	if (dev->driver->load) {
		/* Shared code returns -errno. */
		ret = -dev->driver->load(dev, dev->id_entry->driver_data);
		if (ret)
			goto err_g4;
	}

        /* setup the grouping for the legacy output */
	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
#ifdef __linux__ /* enable when import drm_crtc.c */
		ret = drm_mode_group_init_legacy_group(dev, &dev->primary->mode_group);
#else
		ret = 0;
#endif
		if (ret)
			goto err_g4;
	}

#ifdef __linux__
	list_add_tail(&dev->driver_item, &driver->device_list);
#endif /* __linux__ */

#ifndef __linux__
	dev->devnode = make_dev(&drm_cdevsw, unit, DRM_DEV_UID, DRM_DEV_GID,
				DRM_DEV_MODE, "dri/card%d", unit);
#endif /* __linux__ */

	DRM_INFO("Initialized %s %d.%d.%d %s for %s on minor %d\n",
		dev->driver->name, dev->driver->major,
		dev->driver->minor, dev->driver->patchlevel,
		dev->driver->date, device_get_desc(kdev), dev->unit);

	return 0;

err_g4:
	drm_put_minor(&dev->primary);
err_g3:
	if (drm_core_check_feature(dev, DRIVER_MODESET))
		drm_put_minor(&dev->control);
err_g2:
	return ret;
}
EXPORT_SYMBOL(drm_get_dev);

/**
 * Put a secondary minor number.
 *
 * \param sec_minor - structure to be released
 * \return always zero
 *
 * Cleans up the proc resources. Not legal for this to be the
 * last minor released.
 *
 */
int drm_put_minor(struct drm_minor **minor_p)
{
	struct drm_minor *minor = *minor_p;

	DRM_INFO("release secondary minor %d\n", minor->index);

	if (minor->type == DRM_MINOR_LEGACY)
		drm_sysctl_cleanup(minor);

#ifdef __linux__
#if defined(CONFIG_DEBUG_FS)
	drm_debugfs_cleanup(minor);
#endif

	drm_sysfs_device_remove(minor);
#endif /* __linux__ */

	idr_remove(&drm_minors_idr, minor->index);

#ifdef __linux__
	kfree(minor);
#else
	free(minor, DRM_MEM_STUB);
#endif
	*minor_p = NULL;
	return 0;
}

/**
 * Called via drm_exit() at module unload time or when pci device is
 * unplugged.
 *
 * Cleans up all DRM device, calling drm_lastclose().
 *
 * \sa drm_init
 */
void drm_put_dev(struct drm_device *dev)
{
	struct drm_driver *driver;
	struct drm_map_list *r_list, *list_temp;

	DRM_DEBUG("\n");

	if (!dev) {
		DRM_ERROR("cleanup called no dev\n");
		return;
	}
	driver = dev->driver;

	drm_lastclose(dev);

#ifdef __linux__
	if (drm_core_has_MTRR(dev) && drm_core_has_AGP(dev) &&
	    dev->agp && dev->agp->agp_mtrr >= 0) {
		int retval;
		retval = mtrr_del(dev->agp->agp_mtrr,
				  dev->agp->agp_info.aper_base,
				  dev->agp->agp_info.aper_size * 1024 * 1024);
		DRM_DEBUG("mtrr_del=%d\n", retval);
	}
#else /* __linux__ */
#ifdef DRM_NEWER_MTRR
	if (drm_core_has_MTRR(dev) && drm_core_has_AGP(dev) &&
	    dev->agp && dev->agp->agp_mtrr > 0) {
		int retval;
		retval = drm_mtrr_del(0,
			dev->agp->info.ai_aperture_base,
			dev->agp->info.ai_aperture_size, DRM_MTRR_WC);
		DRM_DEBUG("mtrr_del=%d\n", retval);
	}
#else
	if (dev->agp && dev->agp->mtrr) {
		int __unused retcode;

		retcode = drm_mtrr_del(0,
			dev->agp->info.ai_aperture_base,
			dev->agp->info.ai_aperture_size, DRM_MTRR_WC);
		DRM_DEBUG("mtrr_del = %d", retcode);
	}
#endif
#endif /* __linux__ */

	if (dev->driver->unload) {
		dev->driver->unload(dev);
	}

	if (drm_core_has_AGP(dev) && dev->agp) {
		free(dev->agp, DRM_MEM_AGPLISTS);
		dev->agp = NULL;
	}

	drm_vblank_cleanup(dev);

	list_for_each_entry_safe(r_list, list_temp, &dev->maplist, head)
		drm_rmmap(dev, r_list->map);
	drm_ht_remove(&dev->map_hash);

	drm_ctxbitmap_cleanup(dev);

	if (drm_core_check_feature(dev, DRIVER_MODESET))
		drm_put_minor(&dev->control);

	if (driver->driver_features & DRIVER_GEM)
		drm_gem_destroy(dev);

	destroy_dev(dev->devnode);
	drm_put_minor(&dev->primary);

	if (dev->devname) {
#ifdef __linux__
		kfree(dev->devname);
#endif /* __linux__ */
		dev->devname = NULL;
	}
#ifdef __linux__
	kfree(dev);
#endif /* __linux__ */
}
EXPORT_SYMBOL(drm_put_dev);
