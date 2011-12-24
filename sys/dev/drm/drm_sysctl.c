/*-
 * Copyright 2003 Eric Anholt
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
 */

/** @file drm_sysctl.c
 * Implementation of various sysctls for controlling DRM behavior and reporting
 * debug information.
 */

#include "drmP.h"

#include <sys/sysctl.h>

static int	   drm_name_info_legacy DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_vm_info_legacy DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_clients_info_legacy DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_bufs_info_legacy DRM_SYSCTL_HANDLER_ARGS;
static int	   drm_vblank_info_legacy DRM_SYSCTL_HANDLER_ARGS;

struct drm_sysctl_list {
	const char *name;
	int	   (*f) DRM_SYSCTL_HANDLER_ARGS;
} drm_sysctl_list[] = {
	{"name",    drm_name_info_legacy},
	{"vm",	    drm_vm_info_legacy},
	{"clients", drm_clients_info_legacy},
	{"bufs",    drm_bufs_info_legacy},
	{"vblank",    drm_vblank_info_legacy},
};
#define DRM_SYSCTL_ENTRIES NELEM(drm_sysctl_list)

DRM_PROC_DIR_ENTRY drm_sysctl_root;

DRM_PROC_DIR_ENTRY drm_sysctl_mkroot(const char *name) {
	struct sysctl_oid *drioid;

	/* Add the sysctl node for DRI if it doesn't already exist */
	drioid = SYSCTL_ADD_NODE(NULL, &sysctl__hw_children, OID_AUTO, name, CTLFLAG_RW, NULL, "DRI Graphics");
	if (!drioid)
		return NULL;

	return drioid;
}

void drm_sysctl_rmroot(DRM_PROC_DIR_ENTRY root) {
/* 1 == delete but 0 == do not recurse */
	sysctl_remove_oid(root, 1, 0);
}

int drm_sysctl_init(struct drm_minor *minor, int minor_id,
	DRM_PROC_DIR_ENTRY root)
{
	struct drm_device *dev = minor->dev;
	struct sysctl_oid *drioid = root;
	struct drm_sysctl_info *info;
	struct sysctl_oid *oid;
	struct sysctl_oid *top;
	int i;

	info = malloc(sizeof *info, DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!info)
		return ENOMEM;

	dev->sysctl = info;

	if ((minor_id < 0) || (minor_id > 9999))
		return EINVAL;

	info->name[0] = 0;
	info->name[1] = 0;
	info->name[2] = 0;
	info->name[3] = 0;
	snprintf(info->name, 5, "%d", minor_id);
	info->name[4] = 0;
	
	/* Add the hw.dri.x for our device */
	top = SYSCTL_ADD_NODE(&info->ctx, SYSCTL_CHILDREN(drioid), OID_AUTO, info->name, CTLFLAG_RW, NULL, NULL);
	if (!top)
		return EINVAL;
	
	for (i = 0; i < DRM_SYSCTL_ENTRIES; i++) {
		oid = SYSCTL_ADD_OID(&info->ctx, 
			SYSCTL_CHILDREN(top), 
			OID_AUTO, 
			drm_sysctl_list[i].name, 
			CTLTYPE_INT | CTLFLAG_RD, 
			minor,
			0, 
			drm_sysctl_list[i].f, 
			"A", 
			NULL);
		if (!oid)
			return 1;
	}
	SYSCTL_ADD_INT(&info->ctx, SYSCTL_CHILDREN(top), OID_AUTO, "debug",
	    CTLFLAG_RW, &drm_debug_flag, sizeof(drm_debug_flag),
	    "Enable debugging output");

	return 0;
}

int drm_sysctl_cleanup(struct drm_minor *minor)
{
	struct drm_device *dev = minor->dev;
	int error;
	error = sysctl_ctx_free( &dev->sysctl->ctx );

	free(dev->sysctl, DRM_MEM_DRIVER);
	dev->sysctl = NULL;

	return error;
}

#define DRM_SYSCTL_PRINT(fmt, arg...)				\
do {								\
	snprintf(buf, sizeof(buf), fmt, ##arg);			\
	retcode = SYSCTL_OUT(req, buf, strlen(buf));		\
	if (retcode)						\
		goto done;					\
} while (0)

/**
 * Called when "/proc/dri/.../name" is read.
 *
 * Prints the device name together with the bus id if available.
 */
static int drm_name_info_legacy DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev = minor->dev;
	struct drm_master *master = minor->master;

	if (!master)
		return 0;

	char buf[128];
	int retcode;
	int hasunique = 0;

	DRM_SYSCTL_PRINT("%s 0x%x", dev->driver->name, dev2udev(dev->devnode));

	mutex_lock(&dev->struct_mutex);
	if (master->unique) {
		snprintf(buf, sizeof(buf), " %s", master->unique);
		hasunique = 1;
	}
	mutex_unlock(&dev->struct_mutex);
	
	if (hasunique)
		SYSCTL_OUT(req, buf, strlen(buf));

	SYSCTL_OUT(req, "", 1);

done:
	return retcode;
}

static int drm_vm_info_legacy DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev = minor->dev;
	drm_local_map_t *map, *tempmaps;
	struct drm_map_list *r_list;
	const char   *types[] = { "FB", "REG", "SHM", "AGP", "SG" };
	const char *type, *yesno;
	int i, mapcount;
	char buf[128];
	int retcode;

	unsigned long *user_token;

	struct mem_range_desc *md = NULL;
	struct mem_range_desc *cand = NULL;
	int error;
	int nd = 0;
	int ndesc;

	/* We can't hold the lock while doing SYSCTL_OUTs, so allocate a
	 * temporary copy of all the map entries and then SYSCTL_OUT that.
	 */
	mutex_lock(&dev->struct_mutex);
	mapcount = 0;
	list_for_each_entry(r_list, &dev->maplist, head) {
		mapcount++;
	}

	tempmaps = malloc(sizeof(drm_local_map_t) * mapcount,
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!tempmaps) {
		mutex_unlock(&dev->struct_mutex);
		return ENOMEM;
	}

	user_token = malloc(sizeof(unsigned long) * mapcount,
		DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (user_token == NULL) {
		free(tempmaps, DRM_MEM_DRIVER);
		mutex_unlock(&dev->struct_mutex);
		return ENOMEM;
	}

	i = 0;
	list_for_each_entry(r_list, &dev->maplist, head) {
		map = r_list->map;
		user_token[i] = r_list->user_token;
		tempmaps[i++] = *map;
	}

	error = mem_range_attr_get(md, &nd);
	if (error) {
		ndesc = 0;
	} else {
		ndesc = nd;
	}
	if (ndesc > 0) {
		md = malloc(ndesc * sizeof(struct mem_range_desc), DRM_MEM_DRIVER, M_WAITOK);
		if (!md) {
			return ENOMEM;
		}
		error = mem_range_attr_get(md, &nd);
		if (error) {
			ndesc = 0;
			free(md, DRM_MEM_DRIVER);
		}
	}	

	mutex_unlock(&dev->struct_mutex);

	cand = md;
	DRM_SYSCTL_PRINT("\nmtrr reg|mtrr base       |mtrr length     |flag    |owner\n");
	for (i = 0; i < ndesc; i++, cand++) {
		if (cand->mr_flags & MDF_ACTIVE) {
			DRM_SYSCTL_PRINT(
				"%8d %016lx %016lx %08x %.8s\n",
				i, cand->mr_base, cand->mr_len, cand->mr_flags, cand->mr_owner[0] ? cand->mr_owner : "-------");
		}
	}
	if (ndesc > 0) {
		free(md, DRM_MEM_DRIVER);
	}

	DRM_SYSCTL_PRINT("\nslot             offset       size type flags"
	    "            address         user_token mtrr\n");

	for (i = 0; i < mapcount; i++) {
		map = &tempmaps[i];

		if (map->type < 0 || map->type > 4)
			type = "??";
		else
			type = types[map->type];

		if (map->mtrr <= 0)
			yesno = "no";
		else
			yesno = "yes";

		DRM_SYSCTL_PRINT(
			"%4d 0x%016lx 0x%08lx %4.4s  0x%02x 0x%016lx 0x%016lx %s %d\n",
			i,
			map->offset,
			map->size, type, map->flags,
			(unsigned long)map->handle,
			(unsigned long)user_token[i],
			yesno,
			map->mtrr);
	}
	SYSCTL_OUT(req, "", 1);

done:
	free(tempmaps, DRM_MEM_DRIVER);
	free(user_token, DRM_MEM_DRIVER);
	return retcode;
}

/**
 * Called when "/proc/dri/.../bufs" is read.
 */
static int drm_bufs_info_legacy DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev = minor->dev;
	struct drm_device_dma *dma = dev->dma;
	struct drm_device_dma tempdma;
	int *templists;
	int i;
	char buf[128];
	int retcode;

	/* We can't hold the locks around DRM_SYSCTL_PRINT, so make a temporary
	 * copy of the whole structure and the relevant data from buflist.
	 */
	mutex_lock(&dev->struct_mutex);
	if (dma == NULL) {
		mutex_unlock(&dev->struct_mutex);
		return 0;
	}
	tempdma = *dma;
	templists = malloc(sizeof(int) * dma->buf_count,
		DRM_MEM_DRIVER, M_WAITOK);
	if (!templists) {
		mutex_unlock(&dev->struct_mutex);
		return ENOMEM;
	}
	for (i = 0; i < dma->buf_count; i++)
		templists[i] = dma->buflist[i]->list;
	dma = &tempdma;

	mutex_unlock(&dev->struct_mutex);

	DRM_SYSCTL_PRINT("\n o     size count  free	 segs pages    kB\n");
	for (i = 0; i <= DRM_MAX_ORDER; i++) {
		if (dma->bufs[i].buf_count)
			DRM_SYSCTL_PRINT("%2d %8d %5d %5d %5d %5d %5d\n",
				       i,
				       dma->bufs[i].buf_size,
				       dma->bufs[i].buf_count,
				       atomic_read(&dma->bufs[i]
						   .freelist.count),
				       dma->bufs[i].seg_count,
				       dma->bufs[i].seg_count
				       *(1 << dma->bufs[i].page_order),
				       (dma->bufs[i].seg_count
					* (1 << dma->bufs[i].page_order))
				       * PAGE_SIZE / 1024);
	}
	DRM_SYSCTL_PRINT("\n");
	for (i = 0; i < dma->buf_count; i++) {
		if (i && !(i%32)) DRM_SYSCTL_PRINT("\n");
		DRM_SYSCTL_PRINT(" %d", templists[i]);
	}
	DRM_SYSCTL_PRINT("\n");

	SYSCTL_OUT(req, "", 1);
done:
	free(templists, DRM_MEM_DRIVER);
	return retcode;
}

/**
 * Called when "/proc/dri/.../vblank" is read.
 */
static int drm_vblank_info_legacy DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev = minor->dev;
	char buf[128];
	int retcode;
	int i;

	DRM_SYSCTL_PRINT("\ncrtc ref count    last     enabled inmodeset\n");
	for(i = 0 ; i < dev->num_crtcs ; i++) {
		DRM_SYSCTL_PRINT("  %02d  %02d %08d %08d %02d      %02d\n",
			i,
			atomic_read(&dev->vblank_refcount[i]),
			atomic_read(&dev->_vblank_count[i]),
			atomic_read(&dev->last_vblank[i]),
			atomic_read(&dev->vblank_enabled[i]),
			atomic_read(&dev->vblank_inmodeset[i]));
	}

	SYSCTL_OUT(req, "", -1);
done:
	return retcode;
}

/**
 * Called when "/proc/dri/.../clients" is read.
 *
 */
static int drm_clients_info_legacy DRM_SYSCTL_HANDLER_ARGS
{
	struct drm_minor *minor = arg1;
	struct drm_device *dev = minor->dev;
	struct drm_file *priv, *tempprivs;
	char buf[128];
	int retcode;
	int privcount, i;

	mutex_lock(&dev->struct_mutex);

	privcount = 0;
	list_for_each_entry(priv, &dev->filelist, lhead) {
		privcount++;
	}

	tempprivs = malloc(sizeof(struct drm_file) * privcount,
		DRM_MEM_DRIVER, M_WAITOK);
	if (!tempprivs) {
		mutex_unlock(&dev->struct_mutex);
		return ENOMEM;
	}
	i = 0;
	list_for_each_entry(priv, &dev->filelist, lhead) {
		tempprivs[i++] = *priv;
	}
	mutex_unlock(&dev->struct_mutex);

	DRM_SYSCTL_PRINT("\na dev	pid    uid	magic	  ioctls\n");
	for (i = 0; i < privcount; i++) {
		priv = &tempprivs[i];
		DRM_SYSCTL_PRINT("%c %3d %5d %5d %10u %10lu\n",
			       priv->authenticated ? 'y' : 'n',
			       priv->minor->index,
			       priv->pid,
			       priv->uid, priv->magic, priv->ioctl_count);
	}

	SYSCTL_OUT(req, "", 1);
done:
	free(tempprivs, DRM_MEM_DRIVER);
	return retcode;
}
