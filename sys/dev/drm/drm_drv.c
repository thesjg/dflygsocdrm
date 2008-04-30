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
 * $DragonFly: src/sys/dev/drm/drm_drv.c,v 1.1 2008/04/05 18:12:29 hasso Exp $
 */

/** @file drm_drv.c
 * The catch-all file for DRM device support, including module setup/teardown,
 * open/close, and ioctl dispatch.
 */

#ifdef __DragonFly__
#include <machine/limits.h>
#else
#include <sys/limits.h>
#endif
#include "drmP.h"
#include "drm.h"
#include "drm_sarea.h"

#ifdef DRM_DEBUG_DEFAULT_ON
int drm_debug_flag = 1;
#else
int drm_debug_flag = 0;
#endif

static int drm_load(drm_device_t *dev);
static void drm_unload(drm_device_t *dev);
static drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist);

#if defined(__FreeBSD__) || defined(__DragonFly__)
#define DRIVER_SOFTC(unit) \
	((drm_device_t *)devclass_get_softc(drm_devclass, unit))

MODULE_VERSION(drm, 1);
MODULE_DEPEND(drm, agp, 1, 1, 1);
MODULE_DEPEND(drm, pci, 1, 1, 1);
#if __FreeBSD_version > 502127
MODULE_DEPEND(drm, mem, 1, 1, 1);
#endif
#endif /* __FreeBSD__ || __DragonFly__ */

#if defined(__NetBSD__) || defined(__OpenBSD__)
#define DRIVER_SOFTC(unit) \
	((drm_device_t *)device_lookup(&drm_cd, unit))
#endif /* __NetBSD__ || __OpenBSD__ */

static drm_ioctl_desc_t		  drm_ioctls[256] = {
	DRM_IOCTL_DEF(DRM_IOCTL_VERSION, drm_version, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_UNIQUE, drm_getunique, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAGIC, drm_getmagic, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_IRQ_BUSID, drm_irq_by_busid, DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_MAP, drm_getmap, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_CLIENT, drm_getclient, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_STATS, drm_getstats, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_SET_VERSION, drm_setversion, DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_UNIQUE, drm_setunique, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_BLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_UNBLOCK, drm_noop, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AUTH_MAGIC, drm_authmagic, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_MAP, drm_addmap_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_RM_MAP, drm_rmmap_ioctl, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_SET_SAREA_CTX, drm_setsareactx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_GET_SAREA_CTX, drm_getsareactx, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_CTX, drm_addctx, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
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

	DRM_IOCTL_DEF(DRM_IOCTL_ADD_BUFS, drm_addbufs_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_MARK_BUFS, drm_markbufs, DRM_AUTH|DRM_MASTER),
	DRM_IOCTL_DEF(DRM_IOCTL_INFO_BUFS, drm_infobufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_MAP_BUFS, drm_mapbufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_FREE_BUFS, drm_freebufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_DMA, drm_dma, DRM_AUTH),

	DRM_IOCTL_DEF(DRM_IOCTL_CONTROL, drm_control, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ACQUIRE, drm_agp_acquire_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_RELEASE, drm_agp_release_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ENABLE, drm_agp_enable_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_INFO, drm_agp_info_ioctl, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_ALLOC, drm_agp_alloc_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_FREE, drm_agp_free_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_BIND, drm_agp_bind_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_AGP_UNBIND, drm_agp_unbind_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_SG_ALLOC, drm_sg_alloc_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_IOCTL_SG_FREE, drm_sg_free, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),

	DRM_IOCTL_DEF(DRM_IOCTL_WAIT_VBLANK, drm_wait_vblank, 0),
	DRM_IOCTL_DEF(DRM_IOCTL_UPDATE_DRAW, drm_update_draw, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
};

#if defined(__FreeBSD__) || defined(__DragonFly__)
#ifdef __FreeBSD__
static struct cdevsw drm_cdevsw = {
#if __FreeBSD_version >= 502103
	.d_version =	D_VERSION,
#endif
	.d_open =	drm_open,
	.d_close =	drm_close,
	.d_read =	drm_read,
	.d_ioctl =	drm_ioctl,
	.d_poll =	drm_poll,
	.d_mmap =	drm_mmap,
	.d_name =	"drm",
#if __FreeBSD_version >= 502103
	.d_flags =	D_TRACKCLOSE | D_NEEDGIANT,
#else
	.d_maj =	145,
	.d_flags =	D_TRACKCLOSE,
#endif
#if __FreeBSD_version < 500000
	.d_bmaj =	-1
#endif
};
#else	/* __FreeBSD__ */
static struct dev_ops drm_cdevsw = {
	{ "drm", 145, D_TRACKCLOSE },
	.d_open =	drm_open,
	.d_close =	drm_close,
	.d_read =	drm_read,
	.d_ioctl =	drm_ioctl,
	.d_poll =	drm_poll,
	.d_mmap =	drm_mmap
};
#endif	/* !__FreeBSD__ */

int drm_probe(device_t dev, drm_pci_id_list_t *idlist)
{
	drm_pci_id_list_t *id_entry;
	int vendor, device;
#if __FreeBSD_version < 700010
	device_t realdev;

	if (!strcmp(device_get_name(dev), "drmsub"))
		realdev = device_get_parent(dev);
	else
		realdev = dev;
	vendor = pci_get_vendor(realdev);
	device = pci_get_device(realdev);
#else
	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);
#endif

	id_entry = drm_find_description(vendor, device, idlist);
	if (id_entry != NULL) {
		device_set_desc(dev, id_entry->name);
		return 0;
	}

	return ENXIO;
}

int drm_attach(device_t nbdev, drm_pci_id_list_t *idlist)
{
	drm_device_t *dev;
	drm_pci_id_list_t *id_entry;
	int unit;

	unit = device_get_unit(nbdev);
	dev = device_get_softc(nbdev);

#if __FreeBSD_version < 700010
	if (!strcmp(device_get_name(nbdev), "drmsub"))
		dev->device = device_get_parent(nbdev);
	else
		dev->device = nbdev;
#else
	dev->device = nbdev;
#endif
#ifdef __DragonFly__
	dev_ops_add(&drm_cdevsw, -1, unit);
#endif
	dev->devnode = make_dev(&drm_cdevsw,
			unit,
			DRM_DEV_UID,
			DRM_DEV_GID,
			DRM_DEV_MODE,
			"dri/card%d", unit);
#if __FreeBSD_version >= 500000
	mtx_init(&dev->dev_lock, "drm device", NULL, MTX_DEF);
	mtx_init(&dev->drw_lock, "drmdrw", NULL, MTX_DEF);
#elif defined(__DragonFly__)
	DRM_SPININIT(&dev->dev_lock, "drm device");
	DRM_SPININIT(&dev->drw_lock, "drmdrw");
#endif

	id_entry = drm_find_description(pci_get_vendor(dev->device),
	    pci_get_device(dev->device), idlist);
	dev->id_entry = id_entry;

	return drm_load(dev);
}

int drm_detach(device_t dev)
{
	drm_unload(device_get_softc(dev));
	return 0;
}

#ifndef DRM_DEV_NAME
#define DRM_DEV_NAME "drm"
#endif

devclass_t drm_devclass;

#elif defined(__NetBSD__) || defined(__OpenBSD__)

static struct cdevsw drm_cdevsw = {
	drm_open,
	drm_close,
	drm_read,
	nowrite,
	drm_ioctl,
	nostop,
	notty,
	drm_poll,
	drm_mmap,
	nokqfilter,
	D_TTY
};

int drm_refcnt = 0;

#if defined(__NetBSD__) && __NetBSD_Version__ >= 106080000
MOD_DEV("drm", DRIVER_NAME, NULL, -1, &drm_cdevsw, CDEV_MAJOR);
#else
MOD_DEV("drm", LM_DT_CHAR, CDEV_MAJOR, &drm_cdevsw);
#endif

int drm_lkmentry(struct lkm_table *lkmtp, int cmd, int ver);
static int drm_lkmhandle(struct lkm_table *lkmtp, int cmd);

int drm_modprobe(void);
int drm_probe(struct pci_attach_args *pa);
void drm_attach(struct pci_attach_args *pa, dev_t kdev);

int drm_lkmentry(struct lkm_table *lkmtp, int cmd, int ver) {
	DISPATCH(lkmtp, cmd, ver, drm_lkmhandle, drm_lkmhandle, drm_lkmhandle);
}

static int drm_lkmhandle(struct lkm_table *lkmtp, int cmd)
{
	int error = 0;

	switch(cmd) {
	case LKM_E_LOAD:
		if (lkmexists(lkmtp))
			return EEXIST;

		if(drm_modprobe())
			return 0;

		return 1;

	case LKM_E_UNLOAD:
		if (drm_refcnt > 0)
			return (EBUSY);
		break;
	case LKM_E_STAT:
		break;

	default:
		error = EIO;
		break;
	}
	
	return error;
}

int drm_modprobe(void)
{
	struct pci_attach_args pa;
	int error;

	error = pci_find_device(&pa, drm_probe, idlist);
	if (error != 0)
		drm_attach(&pa, 0);

	return error;
}

int drm_probe(struct pci_attach_args *pa, drm_pci_id_list_t idlist)
{
	const char *desc;
	drm_pci_id_list_t *id_entry;

	id_entry = drm_find_description(PCI_VENDOR(pa->pa_id),
	    PCI_PRODUCT(pa->pa_id), idlist);
	if (id_entry != NULL) {
		return 1;
	}

	return 0;
}

void drm_attach(struct pci_attach_args *pa, dev_t kdev, 
    drm_pci_id_list_t *idlist)
{
	int i;
	drm_device_t *dev;
	drm_pci_id_list_t *id_entry;

	config_makeroom(kdev, &drm_cd);
	drm_cd.cd_devs[(kdev)] = malloc(sizeof(drm_device_t), M_DRM, M_WAITOK);
	dev = DRIVER_SOFTC(kdev);

	memset(dev, 0, sizeof(drm_device_t));
	memcpy(&dev->pa, pa, sizeof(dev->pa));

	dev->irq = pa->pa_intrline;
	dev->pci_domain = 0;
	dev->pci_bus = pa->pa_bus;
	dev->pci_slot = pa->pa_device;
	dev->pci_func = pa->pa_function;
	dev->dma_tag = pa->pa_dmat;

	id_entry = drm_find_description(PCI_VENDOR(pa->pa_id),
	    PCI_PRODUCT(pa->pa_id), idlist);
	dev->driver.pci_id_entry = id_entry;

	DRM_INFO("%s", id_entry->name);
	drm_load(dev);
}

int drm_detach(struct device *self, int flags)
{
	drm_unload((drm_device_t *)self);
	return 0;
}

int drm_activate(struct device *self, enum devact act)
{
	switch (act) {
	case DVACT_ACTIVATE:
		return (EOPNOTSUPP);
		break;

	case DVACT_DEACTIVATE:
		/* FIXME */
		break;
	}
	return (0);
}
#endif /* __NetBSD__ || __OpenBSD__ */

drm_pci_id_list_t *drm_find_description(int vendor, int device,
    drm_pci_id_list_t *idlist)
{
	int i = 0;
	
	for (i = 0; idlist[i].vendor != 0; i++) {
		if ((idlist[i].vendor == vendor) &&
		    (idlist[i].device == device)) {
			return &idlist[i];
		}
	}
	return NULL;
}

static int drm_firstopen(drm_device_t *dev)
{
	drm_local_map_t *map;
	int i;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	/* prebuild the SAREA */
	i = drm_addmap(dev, 0, SAREA_MAX, _DRM_SHM,
		       _DRM_CONTAINS_LOCK, &map);
	if (i != 0)
		return i;

	if (dev->driver.firstopen)
		dev->driver.firstopen(dev);

	dev->buf_use = 0;

	if (dev->driver.use_dma) {
		i = drm_dma_setup(dev);
		if (i != 0)
			return i;
	}

	for ( i = 0 ; i < DRM_HASH_SIZE ; i++ ) {
		dev->magiclist[i].head = NULL;
		dev->magiclist[i].tail = NULL;
	}

	dev->lock.lock_queue = 0;
	dev->irq_enabled = 0;
	dev->context_flag = 0;
	dev->last_context = 0;
	dev->if_version = 0;

#if defined(__FreeBSD__) || defined(__DragonFly__)
	dev->buf_sigio = NULL;
#elif defined(__NetBSD__) || defined(__OpenBSD__)
	dev->buf_pgid = 0;
#endif

	DRM_DEBUG( "\n" );

	return 0;
}

static int drm_lastclose(drm_device_t *dev)
{
	drm_magic_entry_t *pt, *next;
	drm_local_map_t *map, *mapsave;
	int i;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	DRM_DEBUG( "\n" );

	if (dev->driver.lastclose != NULL)
		dev->driver.lastclose(dev);

	if (dev->irq_enabled)
		drm_irq_uninstall(dev);

	if ( dev->unique ) {
		free(dev->unique, M_DRM);
		dev->unique = NULL;
		dev->unique_len = 0;
	}
				/* Clear pid list */
	for ( i = 0 ; i < DRM_HASH_SIZE ; i++ ) {
		for ( pt = dev->magiclist[i].head ; pt ; pt = next ) {
			next = pt->next;
			free(pt, M_DRM);
		}
		dev->magiclist[i].head = dev->magiclist[i].tail = NULL;
	}

				/* Clear AGP information */
	if ( dev->agp ) {
		drm_agp_mem_t *entry;
		drm_agp_mem_t *nexte;

		/* Remove AGP resources, but leave dev->agp intact until
		 * drm_unload is called.
		 */
		for ( entry = dev->agp->memory ; entry ; entry = nexte ) {
			nexte = entry->next;
			if ( entry->bound )
				drm_agp_unbind_memory(entry->handle);
			drm_agp_free_memory(entry->handle);
			free(entry, M_DRM);
		}
		dev->agp->memory = NULL;

		if (dev->agp->acquired)
			drm_agp_release(dev);

		dev->agp->acquired = 0;
		dev->agp->enabled  = 0;
	}
	if (dev->sg != NULL) {
		drm_sg_cleanup(dev->sg);
		dev->sg = NULL;
	}

	TAILQ_FOREACH_SAFE(map, &dev->maplist, link, mapsave) {
		if (!(map->flags & _DRM_DRIVER))
			drm_rmmap(dev, map);
	}

	drm_dma_takedown(dev);
	if ( dev->lock.hw_lock ) {
		dev->lock.hw_lock = NULL; /* SHM removed */
		dev->lock.file_priv = NULL;
		DRM_WAKEUP_INT((void *)&dev->lock.lock_queue);
	}

	return 0;
}

static int drm_load(drm_device_t *dev)
{
	int i, retcode;

	DRM_DEBUG( "\n" );

	dev->irq = pci_get_irq(dev->device);
#if defined(__FreeBSD__) && __FreeBSD_version >= 700053
	dev->pci_domain = pci_get_domain(dev->device);
#else
	dev->pci_domain = 0;
#endif
	dev->pci_bus = pci_get_bus(dev->device);
	dev->pci_slot = pci_get_slot(dev->device);
	dev->pci_func = pci_get_function(dev->device);

	dev->pci_vendor = pci_get_vendor(dev->device);
	dev->pci_device = pci_get_device(dev->device);

	TAILQ_INIT(&dev->maplist);

	drm_mem_init();
#if defined(__FreeBSD__) || defined(__DragonFly__)
	drm_sysctl_init(dev);
#endif
	TAILQ_INIT(&dev->files);

	dev->counters  = 6;
	dev->types[0]  = _DRM_STAT_LOCK;
	dev->types[1]  = _DRM_STAT_OPENS;
	dev->types[2]  = _DRM_STAT_CLOSES;
	dev->types[3]  = _DRM_STAT_IOCTLS;
	dev->types[4]  = _DRM_STAT_LOCKS;
	dev->types[5]  = _DRM_STAT_UNLOCKS;

	for ( i = 0 ; i < DRM_ARRAY_SIZE(dev->counts) ; i++ )
		atomic_set( &dev->counts[i], 0 );

	if (dev->driver.load != NULL) {
		DRM_LOCK();
		/* Shared code returns -errno. */
		retcode = -dev->driver.load(dev,
		    dev->id_entry->driver_private);
		DRM_UNLOCK();
		if (retcode != 0)
			goto error;
	}

	if (dev->driver.use_agp) {
		if (drm_device_is_agp(dev))
			dev->agp = drm_agp_init();
		if (dev->driver.require_agp && dev->agp == NULL) {
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

#ifdef __FreeBSD__
	dev->drw_unrhdr = new_unrhdr(1, INT_MAX, NULL);
	if (dev->drw_unrhdr == NULL) {
		DRM_ERROR("Couldn't allocate drawable number allocator\n");
		goto error;
	}
#endif

	DRM_INFO("Initialized %s %d.%d.%d %s\n",
	  	dev->driver.name,
	  	dev->driver.major,
	  	dev->driver.minor,
	  	dev->driver.patchlevel,
	  	dev->driver.date);

	return 0;

error:
#if defined(__FreeBSD__) || defined(__DragonFly__)
	drm_sysctl_cleanup(dev);
#endif
	DRM_LOCK();
	drm_lastclose(dev);
	DRM_UNLOCK();
#if defined(__FreeBSD__) || defined(__DragonFly__)
	destroy_dev(dev->devnode);
#if __FreeBSD_version >= 500000
	mtx_destroy(&dev->dev_lock);
#elif defined(__DragonFly__)
	DRM_SPINUNINIT(&dev->dev_lock);
#endif
#endif
	return retcode;
}

static void drm_unload(drm_device_t *dev)
{
	int i;

	DRM_DEBUG( "\n" );

#if defined(__FreeBSD__) || defined(__DragonFly__)
	drm_sysctl_cleanup(dev);
	destroy_dev(dev->devnode);
#endif

	drm_ctxbitmap_cleanup(dev);

	if (dev->agp && dev->agp->mtrr) {
		int __unused retcode;

		retcode = drm_mtrr_del(0, dev->agp->info.ai_aperture_base,
		    dev->agp->info.ai_aperture_size, DRM_MTRR_WC);
		DRM_DEBUG("mtrr_del = %d", retcode);
	}

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

	if ( dev->agp ) {
		free(dev->agp, M_DRM);
		dev->agp = NULL;
	}

	if (dev->driver.unload != NULL)
		dev->driver.unload(dev);

#ifdef __FreeBSD__
	delete_unrhdr(dev->drw_unrhdr);
#endif

	drm_mem_uninit();
#if defined(__FreeBSD__) &&  __FreeBSD_version >= 500000
	mtx_destroy(&dev->dev_lock);
#elif defined(__DragonFly__)
	DRM_SPINUNINIT(&dev->dev_lock);
#endif
}


int drm_version(drm_device_t *dev, void *data, struct drm_file *file_priv)
{
	drm_version_t *version = data;
	int len;

#define DRM_COPY( name, value )						\
	len = strlen( value );						\
	if ( len > name##_len ) len = name##_len;			\
	name##_len = strlen( value );					\
	if ( len && name ) {						\
		if ( DRM_COPY_TO_USER( name, value, len ) )		\
			return EFAULT;				\
	}

	version->version_major		= dev->driver.major;
	version->version_minor		= dev->driver.minor;
	version->version_patchlevel	= dev->driver.patchlevel;

	DRM_COPY(version->name, dev->driver.name);
	DRM_COPY(version->date, dev->driver.date);
	DRM_COPY(version->desc, dev->driver.desc);

	return 0;
}

#ifndef __DragonFly__
int drm_open(struct cdev *kdev, int flags, int fmt, DRM_STRUCTPROC *p)
{
#else
int drm_open(struct dev_open_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	int flags = ap->a_oflags;
	int fmt = 0;
	struct thread *p = curthread;
#endif
	drm_device_t *dev = NULL;
	int retcode = 0;

	dev = DRIVER_SOFTC(minor(kdev));

	DRM_DEBUG( "open_count = %d\n", dev->open_count );

	retcode = drm_open_helper(kdev, flags, fmt, p, dev);

	if ( !retcode ) {
		atomic_inc( &dev->counts[_DRM_STAT_OPENS] );
		DRM_LOCK();
#if defined(__FreeBSD__) || defined(__DragonFly__)
		device_busy(dev->device);
#endif
		if ( !dev->open_count++ )
			retcode = drm_firstopen(dev);
		DRM_UNLOCK();
	}

	return retcode;
}

#ifndef __DragonFly__
int drm_close(struct cdev *kdev, int flags, int fmt, DRM_STRUCTPROC *p)
{
#else
int drm_close(struct dev_close_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	struct thread *p = curthread;
#endif
	drm_device_t *dev = drm_get_device_from_kdev(kdev);
	drm_file_t *file_priv;
	int retcode = 0;

	DRM_DEBUG( "open_count = %d\n", dev->open_count );

	DRM_LOCK();

	file_priv = drm_find_file_by_proc(dev, p);
	if (!file_priv) {
		DRM_UNLOCK();
		DRM_ERROR("can't find authenticator\n");
		return EINVAL;
	}

	if (--file_priv->refs != 0)
		goto done;

	if (dev->driver.preclose != NULL)
		dev->driver.preclose(dev, file_priv);

	/* ========================================================
	 * Begin inline drm_release
	 */

#if defined(__FreeBSD__) || defined(__DragonFly__)
	DRM_DEBUG( "pid = %d, device = 0x%lx, open_count = %d\n",
		   DRM_CURRENTPID, (long)dev->device, dev->open_count );
#elif defined(__NetBSD__) || defined(__OpenBSD__)
	DRM_DEBUG( "pid = %d, device = 0x%lx, open_count = %d\n",
		   DRM_CURRENTPID, (long)&dev->device, dev->open_count);
#endif

	if (dev->lock.hw_lock && _DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock)
	    && dev->lock.file_priv == file_priv) {
		DRM_DEBUG("Process %d dead, freeing lock for context %d\n",
			  DRM_CURRENTPID,
			  _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		if (dev->driver.reclaim_buffers_locked != NULL)
			dev->driver.reclaim_buffers_locked(dev, file_priv);

		drm_lock_free(dev, &dev->lock.hw_lock->lock,
		    _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		
				/* FIXME: may require heavy-handed reset of
                                   hardware at this point, possibly
                                   processed via a callback to the X
                                   server. */
	} else if (dev->driver.reclaim_buffers_locked != NULL &&
	    dev->lock.hw_lock != NULL) {
		/* The lock is required to reclaim buffers */
		for (;;) {
			if ( !dev->lock.hw_lock ) {
				/* Device has been unregistered */
				retcode = EINTR;
				break;
			}
			if (drm_lock_take(&dev->lock.hw_lock->lock,
			    DRM_KERNEL_CONTEXT)) {
				dev->lock.file_priv = file_priv;
				dev->lock.lock_time = jiffies;
                                atomic_inc( &dev->counts[_DRM_STAT_LOCKS] );
				break;	/* Got lock */
			}
				/* Contention */
#if defined(__FreeBSD__) && __FreeBSD_version > 500000
			retcode = mtx_sleep((void *)&dev->lock.lock_queue,
			    &dev->dev_lock, PZERO | PCATCH, "drmlk2", 0);
#elif defined(__DragonFly__)
			crit_enter();
			tsleep_interlock((void *)&dev->lock.lock_queue);
			DRM_UNLOCK();
			retcode = tsleep((void *)&dev->lock.lock_queue,
			    PCATCH, "drmlk2", 0);
			crit_exit();
			DRM_LOCK();
#else
			retcode = tsleep((void *)&dev->lock.lock_queue,
			    PZERO | PCATCH, "drmlk2", 0);
#endif
			if (retcode)
				break;
		}
		if (retcode == 0) {
			dev->driver.reclaim_buffers_locked(dev, file_priv);
			drm_lock_free(dev, &dev->lock.hw_lock->lock,
			    DRM_KERNEL_CONTEXT);
		}
	}

	if (dev->driver.use_dma && !dev->driver.reclaim_buffers_locked)
		drm_reclaim_buffers(dev, file_priv);

#if defined (__FreeBSD__) && (__FreeBSD_version >= 500000)
	funsetown(&dev->buf_sigio);
#elif defined(__FreeBSD__) || defined(__DragonFly__)
	funsetown(dev->buf_sigio);
#elif defined(__NetBSD__) || defined(__OpenBSD__)
	dev->buf_pgid = 0;
#endif /* __NetBSD__  || __OpenBSD__ */

	if (dev->driver.postclose != NULL)
		dev->driver.postclose(dev, file_priv);
	TAILQ_REMOVE(&dev->files, file_priv, link);
	free(file_priv, M_DRM);

	/* ========================================================
	 * End inline drm_release
	 */

done:
	atomic_inc( &dev->counts[_DRM_STAT_CLOSES] );
#if defined(__FreeBSD__) || defined(__DragonFly__)
	device_unbusy(dev->device);
#endif
	if (--dev->open_count == 0) {
		retcode = drm_lastclose(dev);
	}

	DRM_UNLOCK();
	
	return retcode;
}

/* drm_ioctl is called whenever a process performs an ioctl on /dev/drm.
 */
#ifndef __DragonFly__
int drm_ioctl(struct cdev *kdev, u_long cmd, caddr_t data, int flags, 
    DRM_STRUCTPROC *p)
{
#else
int drm_ioctl(struct dev_ioctl_args *ap)
{
	struct cdev *kdev = ap->a_head.a_dev;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;
	struct thread *p = curthread;
#endif
	drm_device_t *dev = drm_get_device_from_kdev(kdev);
	int retcode = 0;
	drm_ioctl_desc_t *ioctl;
	int (*func)(drm_device_t *dev, void *data, struct drm_file *file_priv);
	int nr = DRM_IOCTL_NR(cmd);
	int is_driver_ioctl = 0;
	drm_file_t *file_priv;

	DRM_LOCK();
	file_priv = drm_find_file_by_proc(dev, p);
	DRM_UNLOCK();
	if (file_priv == NULL) {
		DRM_ERROR("can't find authenticator\n");
		return EINVAL;
	}

	atomic_inc( &dev->counts[_DRM_STAT_IOCTLS] );
	++file_priv->ioctl_count;

#if defined(__FreeBSD__) || defined(__DragonFly__)
	DRM_DEBUG( "pid=%d, cmd=0x%02lx, nr=0x%02x, dev 0x%lx, auth=%d\n",
	    DRM_CURRENTPID, cmd, nr, (long)dev->device,
	    file_priv->authenticated );
#elif defined(__NetBSD__) || defined(__OpenBSD__)
	DRM_DEBUG( "pid=%d, cmd=0x%02lx, nr=0x%02x, dev 0x%lx, auth=%d\n",
	    DRM_CURRENTPID, cmd, nr, (long)&dev->device,
	    file_priv->authenticated );
#endif

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		return 0;

#if defined(__FreeBSD__) || defined(__DragonFly__)
	case FIOSETOWN:
		return fsetown(*(int *)data, &dev->buf_sigio);

	case FIOGETOWN:
#if (__FreeBSD_version >= 500000)
		*(int *) data = fgetown(&dev->buf_sigio);
#else
		*(int *) data = fgetown(dev->buf_sigio);
#endif
		return 0;
#endif /* __FreeBSD__ || __DragonFly__ */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	case TIOCSPGRP:
		dev->buf_pgid = *(int *)data;
		return 0;

	case TIOCGPGRP:
		*(int *)data = dev->buf_pgid;
		return 0;
#endif /* __NetBSD__ */
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
		if (nr > dev->driver.max_ioctl) {
			DRM_DEBUG("Bad driver ioctl number, 0x%x (of 0x%x)\n",
			    nr, dev->driver.max_ioctl);
			return EINVAL;
		}
		ioctl = &dev->driver.ioctls[nr];
		is_driver_ioctl = 1;
	}
	func = ioctl->func;

	if (func == NULL) {
		DRM_DEBUG( "no function\n" );
		return EINVAL;
	}

	if (((ioctl->flags & DRM_ROOT_ONLY) && !DRM_SUSER(p)) ||
	    ((ioctl->flags & DRM_AUTH) && !file_priv->authenticated) ||
	    ((ioctl->flags & DRM_MASTER) && !file_priv->master))
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

drm_local_map_t *drm_getsarea(drm_device_t *dev)
{
	drm_local_map_t *map;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if (map->type == _DRM_SHM && (map->flags & _DRM_CONTAINS_LOCK))
			return map;
	}

	return NULL;
}

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
#endif /* DRM_LINUX */