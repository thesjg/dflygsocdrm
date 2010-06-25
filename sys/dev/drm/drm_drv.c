/*-
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
 *
 * Authors:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/** @file drm_drv.c
 * The catch-all file for DRM device support, including module setup/teardown,
 * open/close, and ioctl dispatch.
 */

#include <machine/limits.h>
#include "dev/drm/drmP.h"
#include "dev/drm/drm.h"
#include "dev/drm/drm_sarea.h"
#include "drm_core.h"

#ifdef DRM_DEBUG_DEFAULT_ON
int drm_debug_flag = 1;
#else
int drm_debug_flag = 0;
#endif

static int drm_load(struct drm_device *dev);
static void drm_unload(struct drm_device *dev);
static drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist);

#define DRIVER_SOFTC(unit) \
	((struct drm_device *)devclass_get_softc(drm_devclass, unit))

static struct drm_ioctl_desc drm_ioctls[256] = {
	DRM_IOCTL_DEF(DRM_IOCTL_VERSION, drm_version, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_UNIQUE, drm_getunique, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAGIC, drm_getmagic, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_IRQ_BUSID, drm_irq_by_busid, DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAP, drm_getmap, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_CLIENT, drm_getclient, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_STATS, drm_getstats, 0),
#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_SET_VERSION, drm_setversion, DRM_MASTER),
#else
	DRM_IOCTL_DEF(DRM_IOCTL_SET_VERSION, drm_setversion, DRM_MASTER|DRM_ROOT_ONLY),
#endif
	DRM_IOCTL_DEF(DRM_IOCTL_SET_UNIQUE, drm_setunique, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_BLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_UNBLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_AUTH_MAGIC, drm_authmagic, DRM_AUTH|DRM_MASTER),
#else
	DRM_IOCTL_DEF(DRM_IOCTL_AUTH_MAGIC, drm_authmagic, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#endif
	DRM_IOCTL_DEF(DRM_IOCTL_ADD_MAP, drm_addmap_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RM_MAP, drm_rmmap_ioctl, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_SAREA_CTX, drm_setsareactx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_SAREA_CTX, drm_getsareactx, DRM_AUTH),
#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_SET_MASTER, drm_setmaster_ioctl, DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_DROP_MASTER, drm_dropmaster_ioctl, DRM_ROOT_ONLY),
#endif
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
	DRM_IOCTL_DEF(DRM_IOCTL_DMA, drm_dma, DRM_AUTH),

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
#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_UPDATE_DRAW, drm_update_drawable_info, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#else
	DRM_IOCTL_DEF(DRM_IOCTL_UPDATE_DRAW, drm_update_draw, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#endif
#ifdef __linux__
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_CLOSE, drm_gem_close_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_FLINK, drm_gem_flink_ioctl, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_IOCTL_GEM_OPEN, drm_gem_open_ioctl, DRM_AUTH|DRM_UNLOCKED),

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

static struct dev_ops drm_cdevsw = {
	{ "drm", 145, D_TRACKCLOSE },
	.d_open =       drm_open_legacy,
	.d_close =	drm_close_legacy,
	.d_read =       drm_read_legacy,
	.d_ioctl =      drm_ioctl_legacy,
	.d_poll =       drm_poll_legacy,
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

#ifdef __linux__
static int drm_fill_in_dev(struct drm_device * dev, struct pci_dev *pdev,
			   const struct pci_device_id *ent,
			   struct drm_driver *driver)
#else
static int drm_fill_in_dev(struct drm_device *dev,
	device_t kdev, drm_pci_id_list_t *idlist)
#endif /* __linux__ */
{
	int retcode;
#ifndef __linux__
	int i;
	drm_pci_id_list_t *id_entry;
#endif /* __linux__ */

	INIT_LIST_HEAD(&dev->filelist);
	INIT_LIST_HEAD(&dev->ctxlist);
	INIT_LIST_HEAD(&dev->vmalist);
	INIT_LIST_HEAD(&dev->maplist);
	INIT_LIST_HEAD(&dev->vblank_event_list);

	spin_lock_init(&dev->count_lock);
/* both newer and legacy */
	DRM_SPININIT(&dev->drw_lock, "drmdrw");
/* end both newer and legacy */
	spin_lock_init(&dev->event_lock);
	init_timer(&dev->timer);
	mutex_init(&dev->struct_mutex);
	mutex_init(&dev->ctxlist_mutex);

	idr_init(&dev->drw_idr);

#ifndef __linux__
	DRM_SPININIT(&dev->dev_lock, "drmdev");
	lwkt_serialize_init(&dev->irq_lock);
/* Should perhaps be initialized in drm_irq.c as in linux drm */
	DRM_SPININIT(&dev->vbl_lock, "drmvbl");
#endif /* __linux__ */

#ifdef __linux__
	dev->pdev = pdev;
	dev->pci_device = pdev->device;
	dev->pci_vendor = pdev->vendor;
#else
	dev->device = kdev;
	dev->unit = device_get_unit(kdev);
	dev->pci_device = pci_get_device(dev->device);
	dev->pci_vendor = pci_get_vendor(dev->device);
#endif /* __linux__ */

#ifndef __linux__
	dev->pci_domain = 0;
	dev->pci_bus = pci_get_bus(dev->device);
	dev->pci_slot = pci_get_slot(dev->device);
	dev->pci_func = pci_get_function(dev->device);

	id_entry = drm_find_description(dev->pci_vendor,
	    dev->pci_device, idlist);
	dev->id_entry = id_entry;

	TAILQ_INIT(&dev->maplist_legacy);
	drm_sysctl_init(dev);
	TAILQ_INIT(&dev->files);

/* also done in drm_fops.c */
	for (i = 0; i < DRM_ARRAY_SIZE(dev->counts); i++)
		atomic_set(&dev->counts[i], 0);

#endif /* __linux__ */

#ifdef __alpha__
	dev->hose = pdev->sysdata;
#endif

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
		if (dev->agp != NULL) {
			if (drm_mtrr_add(dev->agp->info.ai_aperture_base,
			    dev->agp->info.ai_aperture_size, DRM_MTRR_WC) == 0)
				dev->agp->mtrr = 1;
		}
#endif /* __linux__ */
	}

	retcode = drm_ctxbitmap_init(dev);
	if (retcode) {
		DRM_ERROR("Cannot allocate memory for context bitmap.\n");
		goto error_out_unreg;
	}

#ifdef __linux__
	if (driver->driver_features & DRIVER_GEM) {
		retcode = drm_gem_init(dev);
#else /* inserted just to compile */
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

int drm_probe(device_t kdev, drm_pci_id_list_t *idlist)
{
	drm_pci_id_list_t *id_entry;
	int vendor, device;

	vendor = pci_get_vendor(kdev);
	device = pci_get_device(kdev);

	if (pci_get_class(kdev) != PCIC_DISPLAY
	    || pci_get_subclass(kdev) != PCIS_DISPLAY_VGA)
		return ENXIO;

	id_entry = drm_find_description(vendor, device, idlist);
	if (id_entry != NULL) {
		DRM_INFO("drm_probe: vendor 0x%4x, device 0x%4x, name %s, get_desc %s\n",
			vendor, device, id_entry->name, device_get_desc(kdev));
		if (!device_get_desc(kdev)) {
			DRM_DEBUG("desc : %s\n", device_get_desc(kdev));
			device_set_desc(kdev, id_entry->name);
		}
		return 0;
	}

	return ENXIO;
}

int drm_attach(device_t kdev, drm_pci_id_list_t *idlist)
{
	struct drm_device *dev;
	int ret;

#ifndef __linux__
#if 0
	drm_pci_id_list_t *id_entry;
#endif
	int unit;
#endif /* __linux__ */

#if 0
	int msicount;
#endif

#ifdef __linux__
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
#else /* already allocated in driver _drv.c */
	unit = device_get_unit(kdev);
	dev = device_get_softc(kdev);
#if 0
/* drmsub appears nowhere, relic of sub to drm rejected by linux */
	if (!strcmp(device_get_name(kdev), "drmsub"))
		dev->device = device_get_parent(kdev);
	else
#endif
	dev->device = kdev;
#endif /* __linux__ */
	if (!dev)
		return -ENOMEM;

#ifdef __linux__
	ret = pci_enable_device(pdev);
	if (ret)
		goto err_g1;

	pci_set_master(pdev);
#else
	pci_enable_busmaster(dev->device);
#endif /* __linux__ */

#if 0
	dev->devnode = make_dev(&drm_cdevsw, unit, DRM_DEV_UID, DRM_DEV_GID,
				DRM_DEV_MODE, "dri/card%d", unit);
#endif

#if 0
	dev->pci_domain = 0;
	dev->pci_bus = pci_get_bus(dev->device);
	dev->pci_slot = pci_get_slot(dev->device);
	dev->pci_func = pci_get_function(dev->device);

	dev->pci_vendor = pci_get_vendor(dev->device);
	dev->pci_device = pci_get_device(dev->device);
#endif

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

#if 0
	DRM_SPININIT(&dev->dev_lock, "drmdev");
	lwkt_serialize_init(&dev->irq_lock);
	DRM_SPININIT(&dev->vbl_lock, "drmvbl");
	DRM_SPININIT(&dev->drw_lock, "drmdrw");

	id_entry = drm_find_description(dev->pci_vendor,
	    dev->pci_device, idlist);
	dev->id_entry = id_entry;

	return drm_load(dev);
#endif

#ifdef __linux__
	if ((ret = drm_fill_in_dev(dev, pdev, ent, driver))) {
#else
	if ((ret = drm_fill_in_dev(dev, kdev, idlist))) {
#endif /* __linux__ */
		printk(KERN_ERR "DRM: Fill_in_dev failed.\n");
		goto err_g2;
	}

	if (dev->driver->load) {
#ifdef __linux__
		ret = dev->driver->load(dev, ent->driver_data);
#else
		DRM_LOCK();
		/* Shared code returns -errno. */
		ret = -dev->driver->load(dev, dev->id_entry->driver_private);
#if 0
		pci_enable_busmaster(dev->device);
#endif
		DRM_UNLOCK();
#endif /* __linux__ */
		if (ret)
			goto err_g4;
	}

#ifndef __linux__
	dev->devnode = make_dev(&drm_cdevsw, unit, DRM_DEV_UID, DRM_DEV_GID,
				DRM_DEV_MODE, "dri/card%d", unit);
#endif /* __linux__ */

#ifdef __linux__
	list_add_tail(&dev->driver_item, &driver->device_list);
#endif /* __linux__ */

	DRM_INFO("Initialized %s %d.%d.%d %s for %s on minor %d\n",
#ifdef __linux__
		 driver->name, driver->major, driver->minor, driver->patchlevel,
		 driver->date, pci_name(pdev), dev->primary->index);
#else
		dev->driver->name, dev->driver->major, dev->driver->minor, dev->driver->patchlevel,
		dev->driver->date, device_get_desc(kdev), dev->unit);
#endif /* __linux__ */

	return 0;

err_g4:

err_g2:
	return ret;
}

int drm_detach(device_t kdev)
{
	struct drm_device *dev;

	dev = device_get_softc(kdev);

	drm_unload(dev);
	
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

#ifndef DRM_DEV_NAME
#define DRM_DEV_NAME "drm"
#endif

devclass_t drm_devclass;

drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist)
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

static int drm_firstopen(struct drm_device *dev)
{
	drm_local_map_t *map;
	int i;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	/* prebuild the SAREA */
	i = drm_addmap(dev, 0, SAREA_MAX, _DRM_SHM,
	    _DRM_CONTAINS_LOCK, &map);
	if (i != 0)
		return i;

	if (dev->driver->firstopen)
		dev->driver->firstopen(dev);

	dev->buf_use = 0;

	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA)) {
		i = drm_dma_setup(dev);
		if (i != 0)
			return i;
	}

	for (i = 0; i < DRM_HASH_SIZE; i++) {
		dev->magiclist[i].head = NULL;
		dev->magiclist[i].tail = NULL;
	}

	dev->lock.lock_queue = 0;
	dev->irq_enabled = 0;
	dev->context_flag = 0;
	dev->last_context = 0;
	dev->if_version = 0;

	dev->buf_sigio = NULL;

	DRM_DEBUG("\n");

	return 0;
}

int drm_lastclose(struct drm_device *dev)
{
	struct drm_magic_entry *pt, *next;
	drm_local_map_t *map, *mapsave;
	int i;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	DRM_DEBUG("\n");

	if (dev->driver->lastclose != NULL)
		dev->driver->lastclose(dev);

	if (dev->irq_enabled)
		drm_irq_uninstall(dev);

	if (dev->unique) {
		free(dev->unique, DRM_MEM_DRIVER);
		dev->unique = NULL;
		dev->unique_len = 0;
	}
	/* Clear pid list */
	for (i = 0; i < DRM_HASH_SIZE; i++) {
		for (pt = dev->magiclist[i].head; pt; pt = next) {
			next = pt->next;
			free(pt, DRM_MEM_MAGIC);
		}
		dev->magiclist[i].head = dev->magiclist[i].tail = NULL;
	}

	DRM_UNLOCK();
	drm_drawable_free_all(dev);
	DRM_LOCK();

	/* Clear AGP information */
	if (dev->agp) {
#if 0
		struct drm_agp_mem *entry;
		struct drm_agp_mem *nexte;
#endif
		struct drm_agp_mem *entry, *tempe;

		/* Remove AGP resources, but leave dev->agp intact until
		 * drm_unload is called.
		 */
#if 0
		for (entry = dev->agp->memory_legacy; entry; entry = nexte) {
			nexte = entry->next;
			if (entry->bound)
				drm_agp_unbind_memory(entry->handle);
			drm_agp_free_memory(entry->handle);
			free(entry, DRM_MEM_AGPLISTS);
		}
		dev->agp->memory_legacy = NULL;
#endif
		list_for_each_entry_safe(entry, tempe, &dev->agp->memory, head) {
			if (entry->bound)
				drm_agp_unbind_memory(entry->memory);
			drm_agp_free_memory(entry->memory);
			free(entry, DRM_MEM_AGPLISTS);
		}
		INIT_LIST_HEAD(&dev->agp->memory);

		if (dev->agp->acquired)
			drm_agp_release(dev);

		dev->agp->acquired = 0;
		dev->agp->enabled  = 0;
	}
	if (dev->sg != NULL) {
		drm_sg_cleanup(dev->sg);
		dev->sg = NULL;
	}

	TAILQ_FOREACH_MUTABLE(map, &dev->maplist_legacy, link, mapsave) {
		if (!(map->flags & _DRM_DRIVER))
			drm_rmmap(dev, map);
	}

	drm_dma_takedown(dev);
	if (dev->lock.hw_lock) {
		dev->lock.hw_lock = NULL; /* SHM removed */
		dev->lock.file_priv = NULL;
		DRM_WAKEUP_INT((void *)&dev->lock.lock_queue);
	}

	return 0;
}

static int drm_load(struct drm_device *dev)
{
	int i, retcode;

	int unit;

	DRM_DEBUG("\n");

	TAILQ_INIT(&dev->maplist_legacy);

	drm_mem_init();
	drm_sysctl_init(dev);
	TAILQ_INIT(&dev->files);

	dev->counters  = 6;
	dev->types[0]  = _DRM_STAT_LOCK;
	dev->types[1]  = _DRM_STAT_OPENS;
	dev->types[2]  = _DRM_STAT_CLOSES;
	dev->types[3]  = _DRM_STAT_IOCTLS;
	dev->types[4]  = _DRM_STAT_LOCKS;
	dev->types[5]  = _DRM_STAT_UNLOCKS;

	for (i = 0; i < DRM_ARRAY_SIZE(dev->counts); i++)
		atomic_set(&dev->counts[i], 0);

	if (dev->driver->load != NULL) {
		DRM_LOCK();
		/* Shared code returns -errno. */
		retcode = -dev->driver->load(dev,
		    dev->id_entry->driver_private);
#if 0
		pci_enable_busmaster(dev->device);
#endif
		DRM_UNLOCK();
		if (retcode != 0)
			goto error;
	}

	if (drm_core_has_AGP(dev)) {
		if (drm_device_is_agp(dev))
			dev->agp = drm_agp_init((struct drm_device *)NULL);
		if (drm_core_check_feature(dev, DRIVER_REQUIRE_AGP) &&
		    dev->agp == NULL) {
			DRM_ERROR("Card isn't AGP, or couldn't initialize "
			    "AGP.\n");
			retcode = ENOMEM;
			goto error;
		}
		if (dev->agp != NULL) {
			if (drm_mtrr_add(dev->agp->info.ai_aperture_base,
			    dev->agp->info.ai_aperture_size, DRM_MTRR_WC) == 0)
				dev->agp->mtrr = 1;
		}
	}

	retcode = drm_ctxbitmap_init(dev);
	if (retcode != 0) {
		DRM_ERROR("Cannot allocate memory for context bitmap.\n");
		goto error;
	}

	unit = device_get_unit(dev->device);
	dev->devnode = make_dev(&drm_cdevsw, unit, DRM_DEV_UID, DRM_DEV_GID,
				DRM_DEV_MODE, "dri/card%d", unit);

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
	    dev->driver->name,
	    dev->driver->major,
	    dev->driver->minor,
	    dev->driver->patchlevel,
	    dev->driver->date);

	return 0;

error:
	drm_sysctl_cleanup(dev);
	DRM_LOCK();
	drm_lastclose(dev);
	DRM_UNLOCK();
	destroy_dev(dev->devnode);

	DRM_SPINUNINIT(&dev->drw_lock);
	DRM_SPINUNINIT(&dev->vbl_lock);
	DRM_SPINUNINIT(&dev->dev_lock);

	return retcode;
}

static void drm_unload(struct drm_device *dev)
{
	int i;

	DRM_DEBUG("\n");

	drm_sysctl_cleanup(dev);
	destroy_dev(dev->devnode);

	drm_ctxbitmap_cleanup(dev);

	if (dev->agp && dev->agp->mtrr) {
		int __unused retcode;

		retcode = drm_mtrr_del(0, dev->agp->info.ai_aperture_base,
		    dev->agp->info.ai_aperture_size, DRM_MTRR_WC);
		DRM_DEBUG("mtrr_del = %d", retcode);
	}

	drm_vblank_cleanup(dev);

	DRM_LOCK();
	drm_lastclose(dev);
	DRM_UNLOCK();

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

	if (dev->agp) {
		free(dev->agp, DRM_MEM_AGPLISTS);
		dev->agp = NULL;
	}

	if (dev->driver->unload != NULL) {
		DRM_LOCK();
		dev->driver->unload(dev);
		DRM_UNLOCK();
	}

	drm_mem_uninit();

	pci_disable_busmaster(dev->device);

	DRM_SPINUNINIT(&dev->drw_lock);
	DRM_SPINUNINIT(&dev->vbl_lock);
	DRM_SPINUNINIT(&dev->dev_lock);
}

int drm_version(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_version *version = data;
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
}

int drm_open_legacy(struct dev_open_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	int flags = ap->a_oflags;
	int fmt = 0;
	struct thread *p = curthread;
	struct drm_device *dev = NULL;
	int retcode = 0;

	dev = DRIVER_SOFTC(minor(kdev));

	DRM_DEBUG("open_count = %d\n", dev->open_count);

	retcode = drm_open_helper_legacy(kdev, flags, fmt, p, dev);

	if (!retcode) {
		atomic_inc(&dev->counts[_DRM_STAT_OPENS]);
		DRM_LOCK();
		device_busy(dev->device);
		if (!dev->open_count++)
			retcode = drm_firstopen(dev);
		DRM_UNLOCK();
	}

	return retcode;
}

int drm_close_legacy(struct dev_close_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	struct drm_file *file_priv;
	struct drm_device *dev;
	int retcode = 0;

	dev = DRIVER_SOFTC(minor(kdev));
	file_priv = drm_find_file_by_proc(dev, curthread);

	DRM_DEBUG("open_count = %d\n", dev->open_count);

	DRM_LOCK();

	if (--file_priv->refs != 0)
		goto done;

	if (dev->driver->preclose != NULL)
		dev->driver->preclose(dev, file_priv);

	/* ========================================================
	 * Begin inline drm_release
	 */

	DRM_DEBUG("pid = %d, device = 0x%lx, open_count = %d\n",
	    DRM_CURRENTPID, (long)dev->device, dev->open_count);

	if (dev->lock.hw_lock && _DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock)
	    && dev->lock.file_priv == file_priv) {
		DRM_DEBUG("Process %d dead, freeing lock for context %d\n",
			  DRM_CURRENTPID,
			  _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		if (dev->driver->reclaim_buffers_locked != NULL)
			dev->driver->reclaim_buffers_locked(dev, file_priv);

		drm_lock_free(&dev->lock,
		    _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		
				/* FIXME: may require heavy-handed reset of
                                   hardware at this point, possibly
                                   processed via a callback to the X
                                   server. */
	} else if (dev->driver->reclaim_buffers_locked != NULL &&
	    dev->lock.hw_lock != NULL) {
		/* The lock is required to reclaim buffers */
		for (;;) {
			if (!dev->lock.hw_lock) {
				/* Device has been unregistered */
				retcode = EINTR;
				break;
			}
			if (drm_lock_take(&dev->lock, DRM_KERNEL_CONTEXT)) {
				dev->lock.file_priv = file_priv;
				dev->lock.lock_time = jiffies;
				atomic_inc(&dev->counts[_DRM_STAT_LOCKS]);
				break;	/* Got lock */
			}
			/* Contention */
			tsleep_interlock((void *)&dev->lock.lock_queue, PCATCH);
			DRM_UNLOCK();
			retcode = tsleep((void *)&dev->lock.lock_queue,
					 PCATCH | PINTERLOCKED, "drmlk2", 0);
			DRM_LOCK();
			if (retcode)
				break;
		}
		if (retcode == 0) {
			dev->driver->reclaim_buffers_locked(dev, file_priv);
			drm_lock_free(&dev->lock, DRM_KERNEL_CONTEXT);
		}
	}

	if (drm_core_check_feature(dev, DRIVER_HAVE_DMA) &&
	    !dev->driver->reclaim_buffers_locked)
		drm_core_reclaim_buffers(dev, file_priv);

	funsetown(dev->buf_sigio);

	if (dev->driver->postclose != NULL)
		dev->driver->postclose(dev, file_priv);
	TAILQ_REMOVE(&dev->files, file_priv, link);
	free(file_priv, DRM_MEM_FILES);

	/* ========================================================
	 * End inline drm_release
	 */
done:
	atomic_inc(&dev->counts[_DRM_STAT_CLOSES]);
	device_unbusy(dev->device);
	if (--dev->open_count == 0) {
		retcode = drm_lastclose(dev);
	}

	DRM_UNLOCK();

	return (0);
}

/* drm_ioctl_legacy is called whenever a process performs an ioctl on /dev/drm.
 */
int drm_ioctl_legacy(struct dev_ioctl_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;
	struct thread *p = curthread;
	struct drm_device *dev = drm_get_device_from_kdev(kdev);
	int retcode = 0;
	struct drm_ioctl_desc *ioctl;
	int (*func)(struct drm_device *dev, void *data, struct drm_file *file_priv);
	int nr = DRM_IOCTL_NR(cmd);
	int is_driver_ioctl = 0;
	struct drm_file *file_priv;

	file_priv = drm_find_file_by_proc(dev, p);
	if (!file_priv) {
		DRM_ERROR("can't find authenticator\n");
		return EINVAL;
	}

	atomic_inc(&dev->counts[_DRM_STAT_IOCTLS]);
	++file_priv->ioctl_count;

	DRM_DEBUG("pid=%d, cmd=0x%02lx, nr=0x%02x, dev 0x%lx, auth=%d\n",
	    DRM_CURRENTPID, cmd, nr, (long)dev->device,
	    file_priv->authenticated);

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		return 0;

	case FIOSETOWN:
		return fsetown(*(int *)data, &dev->buf_sigio);

	case FIOGETOWN:
		*(int *) data = fgetown(dev->buf_sigio);
		return 0;
	}

	if (IOCGROUP(cmd) != DRM_IOCTL_BASE) {
		DRM_DEBUG("Bad ioctl group 0x%x\n", (int)IOCGROUP(cmd));
		return EINVAL;
	}

	ioctl = &drm_ioctls[nr];
	/* It's not a core DRM ioctl, try driver-specific. */
	if (ioctl->func == NULL && nr >= DRM_COMMAND_BASE) {
		/* The array entries begin at DRM_COMMAND_BASE ioctl nr */
		nr -= DRM_COMMAND_BASE;
		if (nr > dev->driver->max_ioctl) {
			DRM_DEBUG("Bad driver ioctl number, 0x%x (of 0x%x)\n",
			    nr, dev->driver->max_ioctl);
			return EINVAL;
		}
		ioctl = &dev->driver->ioctls[nr];
		is_driver_ioctl = 1;
	}
	func = ioctl->func;

	if (func == NULL) {
		DRM_DEBUG("no function\n");
		return EINVAL;
	}

	if (((ioctl->flags & DRM_ROOT_ONLY) && !DRM_SUSER(p)) ||
	    ((ioctl->flags & DRM_AUTH) && !file_priv->authenticated) ||
	    ((ioctl->flags & DRM_MASTER) && !file_priv->master_legacy))
		return EACCES;

	if (is_driver_ioctl) {
		DRM_LOCK();
		/* shared code returns -errno */
		retcode = -func(dev, data, file_priv);
		DRM_UNLOCK();
	} else {
		retcode = func(dev, data, file_priv);
	}

	if (retcode != 0)
		DRM_DEBUG("    returning %d\n", retcode);

	return retcode;
}

drm_local_map_t *drm_getsarea(struct drm_device *dev)
{
	drm_local_map_t *map;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
	TAILQ_FOREACH(map, &dev->maplist_legacy, link) {
		if (map->type == _DRM_SHM && (map->flags & _DRM_CONTAINS_LOCK))
			return map;
	}

	return NULL;
}

static int __init drm_core_init(void)
{
#ifdef __linux__
	int ret = -ENOMEM;
#endif /* __linux__ */

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
#endif /* __linux__ */

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
		 CORE_NAME, CORE_MAJOR, CORE_MINOR, CORE_PATCHLEVEL, CORE_DATE);
	return 0;
#ifdef __linux__
err_p3:
	drm_sysfs_destroy();
err_p2:
	unregister_chrdev(DRM_MAJOR, "drm");

	idr_destroy(&drm_minors_idr);
err_p1:
	return ret;
#endif /* __linux */
}

static void __exit drm_core_exit(void)
{
#ifdef __linux__
	remove_proc_entry("dri", NULL);
	debugfs_remove(drm_debugfs_root);
	drm_sysfs_destroy();

	unregister_chrdev(DRM_MAJOR, "drm");
#endif /* __linux__ */

	idr_destroy(&drm_minors_idr);
}

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

static moduledata_t drm_data= {
	"drm",
	drm_handler,
	0
};

MODULE_VERSION(drm, 1);
DECLARE_MODULE(drm, drm_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(drm, agp, 1, 1, 1);
MODULE_DEPEND(drm, pci, 1, 1, 1);

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

#ifdef __linux__
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
#ifdef __linux__
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

#if DRM_LINUX

#include <sys/sysproto.h>

MODULE_DEPEND(DRIVER_NAME, linux, 1, 1, 1);

#define LINUX_IOCTL_DRM_MIN		0x6400
#define LINUX_IOCTL_DRM_MAX		0x64ff

static linux_ioctl_function_t drm_linux_ioctl;
static struct linux_ioctl_handler drm_handler = {drm_linux_ioctl,
    LINUX_IOCTL_DRM_MIN, LINUX_IOCTL_DRM_MAX};

SYSINIT(drm_register, SI_SUB_KLD, SI_ORDER_MIDDLE,
    linux_ioctl_register_handler, &drm_handler);
SYSUNINIT(drm_unregister, SI_SUB_KLD, SI_ORDER_MIDDLE,
    linux_ioctl_unregister_handler, &drm_handler);

/* The bits for in/out are switched on Linux */
#define LINUX_IOC_IN	IOC_OUT
#define LINUX_IOC_OUT	IOC_IN

static int
drm_linux_ioctl(DRM_STRUCTPROC *p, struct linux_ioctl_args* args)
{
	int error;
	int cmd = args->cmd;

	args->cmd &= ~(LINUX_IOC_IN | LINUX_IOC_OUT);
	if (cmd & LINUX_IOC_IN)
		args->cmd |= IOC_IN;
	if (cmd & LINUX_IOC_OUT)
		args->cmd |= IOC_OUT;

	error = ioctl(p, (struct ioctl_args *)args);

	return error;
}

/* newer UNIMPLEMENTED */

/** File operations structure */
static const struct file_operations drm_stub_fops = {
	.owner = THIS_MODULE,
	.open = drm_stub_open
};

module_init(drm_core_init);
module_exit(drm_core_exit);

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
long drm_ioctl(struct file *filp,
	      unsigned int cmd, unsigned long arg)
{
	struct drm_file *file_priv = filp->private_data;
	struct drm_device *dev;
	struct drm_ioctl_desc *ioctl;
	drm_ioctl_t *func;
	unsigned int nr = DRM_IOCTL_NR(cmd);
	int retcode = -EINVAL;
	char stack_kdata[128];
	char *kdata = NULL;

	dev = file_priv->minor->dev;
	atomic_inc(&dev->ioctl_count);
	atomic_inc(&dev->counts[_DRM_STAT_IOCTLS]);
	++file_priv->ioctl_count;

	DRM_DEBUG("pid=%d, cmd=0x%02x, nr=0x%02x, dev 0x%lx, auth=%d\n",
		  task_pid_nr(current), cmd, nr,
		  (long)old_encode_dev(file_priv->minor->device),
		  file_priv->authenticated);

	if ((nr >= DRM_CORE_IOCTL_COUNT) &&
	    ((nr < DRM_COMMAND_BASE) || (nr >= DRM_COMMAND_END)))
		goto err_i1;
	if ((nr >= DRM_COMMAND_BASE) && (nr < DRM_COMMAND_END) &&
	    (nr < DRM_COMMAND_BASE + dev->driver->num_ioctls))
		ioctl = &dev->driver->ioctls[nr - DRM_COMMAND_BASE];
	else if ((nr >= DRM_COMMAND_END) || (nr < DRM_COMMAND_BASE)) {
		ioctl = &drm_ioctls[nr];
		cmd = ioctl->cmd;
	} else
		goto err_i1;

	/* Do not trust userspace, use our own definition */
	func = ioctl->func;
	/* is there a local override? */
	if ((nr == DRM_IOCTL_NR(DRM_IOCTL_DMA)) && dev->driver->dma_ioctl)
		func = dev->driver->dma_ioctl;

	if (!func) {
		DRM_DEBUG("no function\n");
		retcode = -EINVAL;
	} else if (((ioctl->flags & DRM_ROOT_ONLY) && !capable(CAP_SYS_ADMIN)) ||
		   ((ioctl->flags & DRM_AUTH) && !file_priv->authenticated) ||
		   ((ioctl->flags & DRM_MASTER) && !file_priv->is_master) ||
		   (!(ioctl->flags & DRM_CONTROL_ALLOW) && (file_priv->minor->type == DRM_MINOR_CONTROL))) {
		retcode = -EACCES;
	} else {
		if (cmd & (IOC_IN | IOC_OUT)) {
			if (_IOC_SIZE(cmd) <= sizeof(stack_kdata)) {
				kdata = stack_kdata;
			} else {
#ifdef __linux__
				kdata = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
#else
				kdata = malloc(_IOC_SIZE(cmd), DRM_MEM_IOCTLS, M_WAITOK);
#endif
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
		}
		if (ioctl->flags & DRM_UNLOCKED)
			retcode = func(dev, kdata, file_priv);
		else {
			lock_kernel();
			retcode = func(dev, kdata, file_priv);
			unlock_kernel();
		}

		if (cmd & IOC_OUT) {
			if (copy_to_user((void __user *)arg, kdata,
					 _IOC_SIZE(cmd)) != 0)
				retcode = -EFAULT;
		}
	}

      err_i1:
	if (kdata != stack_kdata)
#ifdef __linux__
		kfree(kdata);
#else
		free(kdata, DRM_MEM_IOCTLS);
#endif
	atomic_dec(&dev->ioctl_count);
	if (retcode)
		DRM_DEBUG("ret = %x\n", retcode);
	return retcode;
}

EXPORT_SYMBOL(drm_ioctl);

#endif /* DRM_LINUX */
