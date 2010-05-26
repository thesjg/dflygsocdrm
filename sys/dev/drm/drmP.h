/* drmP.h -- Private header for Direct Rendering Manager -*- linux-c -*-
 * Created: Mon Jan  4 10:05:05 1999 by faith@precisioninsight.com
 */
/*-
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All rights reserved.
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

#ifndef _DRM_P_H_
#define _DRM_P_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#ifdef __linux__
#ifdef __alpha__
/* add include of current.h so that "current" is defined
 * before static inline funcs in wait.h. Doing this so we
 * can build the DRM (part of PI DRI). 4/21/2000 S + B */
#include <asm/current.h>
#endif				/* __alpha__ */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/jiffies.h>
#include <linux/smp_lock.h>	/* For (un)lock_kernel */
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#if defined(__alpha__) || defined(__powerpc__)
#include <asm/pgtable.h>	/* For pte_wrprotect */
#endif
#include <asm/io.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#ifdef CONFIG_MTRR
#include <asm/mtrr.h>
#endif
#if defined(CONFIG_AGP) || defined(CONFIG_AGP_MODULE)
#include <linux/types.h>
#include <linux/agp_backend.h>
#endif
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <asm/pgalloc.h>
#else /* Other OS implementations */
#include "dev/drm/drm_port_layer.h"
#endif

#include "dev/drm/drm.h"

#ifdef __linux__
#include <linux/idr.h>

#define __OS_HAS_AGP (defined(CONFIG_AGP) || (defined(CONFIG_AGP_MODULE) && defined(MODULE)))
#else
#define __OS_HAS_AGP	1
#endif

#define __OS_HAS_MTRR (defined(CONFIG_MTRR))

struct drm_file;
struct drm_device;

#ifdef __linux__
#include "drm_os_linux.h"
#else
#include "dev/drm/drm_port_transition.h"
#include "dev/drm/drm_port_other.h"
#endif

#include "dev/drm/drm_hashtab.h"
#include "dev/drm/drm_mm.h"

#define DRM_UT_CORE 		0x01
#define DRM_UT_DRIVER		0x02
#define DRM_UT_KMS		0x04

/*
 * Three debug levels are defined.
 * drm_core, drm_driver, drm_kms
 * drm_core level can be used in the generic drm code. For example:
 * 	drm_ioctl, drm_mm, drm_memory
 * The macro definiton of DRM_DEBUG is used.
 * 	DRM_DEBUG(fmt, args...)
 * 	The debug info by using the DRM_DEBUG can be obtained by adding
 * 	the boot option of "drm.debug=1".
 *
 * drm_driver level can be used in the specific drm driver. It is used
 * to add the debug info related with the drm driver. For example:
 * i915_drv, i915_dma, i915_gem, radeon_drv,
 * 	The macro definition of DRM_DEBUG_DRIVER can be used.
 * 	DRM_DEBUG_DRIVER(fmt, args...)
 * 	The debug info by using the DRM_DEBUG_DRIVER can be obtained by
 * 	adding the boot option of "drm.debug=0x02"
 *
 * drm_kms level can be used in the KMS code related with specific drm driver.
 * It is used to add the debug info related with KMS mode. For example:
 * the connector/crtc ,
 * 	The macro definition of DRM_DEBUG_KMS can be used.
 * 	DRM_DEBUG_KMS(fmt, args...)
 * 	The debug info by using the DRM_DEBUG_KMS can be obtained by
 * 	adding the boot option of "drm.debug=0x04"
 *
 * If we add the boot option of "drm.debug=0x06", we can get the debug info by
 * using the DRM_DEBUG_KMS and DRM_DEBUG_DRIVER.
 * If we add the boot option of "drm.debug=0x05", we can get the debug info by
 * using the DRM_DEBUG_KMS and DRM_DEBUG.
 */

extern void drm_ut_debug_printk(unsigned int request_level,
				const char *prefix,
				const char *function_name,
				const char *format, ...);
/***********************************************************************/
/** \name DRM template customization defaults */
/*@{*/

/* driver capabilities and requirements mask */
#define DRIVER_USE_AGP     0x1
#define DRIVER_REQUIRE_AGP 0x2
#define DRIVER_USE_MTRR    0x4
#define DRIVER_PCI_DMA     0x8
#define DRIVER_SG          0x10
#define DRIVER_HAVE_DMA    0x20
#define DRIVER_HAVE_IRQ    0x40
#define DRIVER_IRQ_SHARED  0x80
#define DRIVER_IRQ_VBL     0x100
#define DRIVER_DMA_QUEUE   0x200
#define DRIVER_FB_DMA      0x400
#define DRIVER_IRQ_VBL2    0x800
#define DRIVER_GEM         0x1000
#define DRIVER_MODESET     0x2000

/* DRIVER_DMA_QUEUE formerly 0x100 but not actually set anywhere */

/***********************************************************************/
/** \name Begin the DRM... */
/*@{*/

#define DRM_DEBUG_CODE 2	  /**< Include debugging code if > 1, then
				     also include looping detection. */

#define DRM_MAGIC_HASH_ORDER  4  /**< Size of key hash table. Must be power of 2. */
#define DRM_KERNEL_CONTEXT    0	 /**< Change drm_resctx if changed */
#define DRM_RESERVED_CONTEXTS 1	 /**< Change drm_resctx if changed */
#define DRM_LOOPING_LIMIT     5000000

#ifdef __linux__
#define DRM_TIME_SLICE	      (HZ/20)  /**< Time slice for GLXContexts */
#else
#define DRM_TIME_SLICE		(hz/20)  /* Time slice for GLXContexts	  */
#endif

#define DRM_LOCK_SLICE	      1	/**< Time slice for lock, in jiffies */

#define DRM_FLAG_DEBUG	  0x01

#define DRM_MAX_CTXBITMAP (PAGE_SIZE * 8)
#define DRM_MAP_HASH_OFFSET 0x10000000

/*@}*/

/***********************************************************************/
/** \name Macros to make printk easier */
/*@{*/

/**
 * Error output.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#define DRM_ERROR(fmt, arg...) \
	printk(KERN_ERR "[" DRM_NAME ":%s] *ERROR* " fmt , __func__ , ##arg)

/**
 * Memory error output.
 *
 * \param area memory area where the error occurred.
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#define DRM_MEM_ERROR(area, fmt, arg...) \
	printk(KERN_ERR "[" DRM_NAME ":%s:%s] *ERROR* " fmt , __func__, \
	       drm_mem_stats[area].name , ##arg)

#define DRM_INFO(fmt, arg...)  printk(KERN_INFO "[" DRM_NAME "] " fmt , ##arg)

/**
 * Debug output.
 *
 * \param fmt printf() like format string.
 * \param arg arguments
 */
#if DRM_DEBUG_CODE
#define DRM_DEBUG(fmt, args...)						\
	do {								\
		drm_ut_debug_printk(DRM_UT_CORE, DRM_NAME, 		\
					__func__, fmt, ##args);		\
	} while (0)

#define DRM_DEBUG_DRIVER(fmt, args...)					\
	do {								\
		drm_ut_debug_printk(DRM_UT_DRIVER, DRM_NAME,		\
					__func__, fmt, ##args);		\
	} while (0)
#define DRM_DEBUG_KMS(fmt, args...)				\
	do {								\
		drm_ut_debug_printk(DRM_UT_KMS, DRM_NAME, 		\
					 __func__, fmt, ##args);	\
	} while (0)
#define DRM_LOG(fmt, args...)						\
	do {								\
		drm_ut_debug_printk(DRM_UT_CORE, NULL,			\
					NULL, fmt, ##args);		\
	} while (0)
#define DRM_LOG_KMS(fmt, args...)					\
	do {								\
		drm_ut_debug_printk(DRM_UT_KMS, NULL,			\
					NULL, fmt, ##args);		\
	} while (0)
#define DRM_LOG_MODE(fmt, args...)					\
	do {								\
		drm_ut_debug_printk(DRM_UT_MODE, NULL,			\
					NULL, fmt, ##args);		\
	} while (0)
#define DRM_LOG_DRIVER(fmt, args...)					\
	do {								\
		drm_ut_debug_printk(DRM_UT_DRIVER, NULL,		\
					NULL, fmt, ##args);		\
	} while (0)
#else
#define DRM_DEBUG_DRIVER(fmt, args...) do { } while (0)
#define DRM_DEBUG_KMS(fmt, args...)	do { } while (0)
#define DRM_DEBUG(fmt, arg...)		 do { } while (0)
#define DRM_LOG(fmt, arg...)		do { } while (0)
#define DRM_LOG_KMS(fmt, args...) do { } while (0)
#define DRM_LOG_MODE(fmt, arg...) do { } while (0)
#define DRM_LOG_DRIVER(fmt, arg...) do { } while (0)

#endif

/*@}*/

/***********************************************************************/
/** \name Internal types and structures */
/*@{*/

/* Define manually rather than refer to ARRAY_SIZE(x) */
#define DRM_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define DRM_LEFTCOUNT(x) (((x)->rp + (x)->count - (x)->wp) % ((x)->count + 1))
#define DRM_BUFCOUNT(x) ((x)->count - DRM_LEFTCOUNT(x))

#define DRM_IF_VERSION(maj, min) (maj << 16 | min)

/* Defined below */
#define DRM_MTRR_WC		MDF_WRITECOMBINE

/**
 * Test that the hardware lock is held by the caller, returning otherwise.
 *
 * \param dev DRM device.
 * \param filp file pointer of the caller.
 */
#ifdef __linux__

#define LOCK_TEST_WITH_RETURN( dev, _file_priv )				\
do {										\
	if (!_DRM_LOCK_IS_HELD(_file_priv->master->lock.hw_lock->lock) ||	\
	    _file_priv->master->lock.file_priv != _file_priv)	{		\
		DRM_ERROR( "%s called without lock held, held  %d owner %p %p\n",\
			   __func__, _DRM_LOCK_IS_HELD(_file_priv->master->lock.hw_lock->lock),\
			   _file_priv->master->lock.file_priv, _file_priv);	\
		return -EINVAL;							\
	}									\
} while (0)

#else /* Other OS */

#define LOCK_TEST_WITH_RETURN(dev, file_priv)				\
do {									\
	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock) ||		\
	     dev->lock.file_priv != file_priv) {			\
		DRM_ERROR("%s called without lock held\n",		\
			   __FUNCTION__);				\
		return EINVAL;						\
	}								\
} while (0)

#endif /* LOCK_TEST_WITH_RETURN */

/* Returns -errno to shared code */
#define DRM_WAIT_ON( ret, queue, timeout, condition )		\
for ( ret = 0 ; !ret && !(condition) ; ) {			\
	DRM_UNLOCK();						\
	lwkt_serialize_enter(&dev->irq_lock);			\
	if (!(condition)) {					\
            tsleep_interlock(&(queue), PCATCH);			\
            lwkt_serialize_exit(&dev->irq_lock);		\
            ret = -tsleep(&(queue), PCATCH | PINTERLOCKED,	\
			  "drmwtq", (timeout));			\
	} else {						\
		lwkt_serialize_exit(&dev->irq_lock);		\
	}							\
	DRM_LOCK();						\
}

#if 0
#define DRM_ERROR(fmt, ...) \
	printf("error: [" DRM_NAME ":pid%d:%s] *ERROR* " fmt,		\
	    DRM_CURRENTPID, __func__ , ##__VA_ARGS__)

#define DRM_INFO(fmt, ...)  printf("info: [" DRM_NAME "] " fmt , ##__VA_ARGS__)
	
#define DRM_DEBUG(fmt, ...) do {					\
	if (drm_debug_flag)						\
		printf("[" DRM_NAME ":pid%d:%s] " fmt, DRM_CURRENTPID,	\
			__func__ , ##__VA_ARGS__);			\
} while (0)
#endif

/* Used only in this file? */
typedef struct drm_pci_id_list
{
	int vendor;
	int device;
	long driver_private;
	char *name;
} drm_pci_id_list_t;

struct drm_msi_blacklist_entry
{
	int vendor;
	int device;
};

/**
 * Ioctl function type.
 *
 * \param inode device inode.
 * \param file_priv DRM file private pointer.
 * \param cmd command.
 * \param arg argument.
 */
typedef int drm_ioctl_t(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

typedef int drm_ioctl_compat_t(struct file *filp, unsigned int cmd,
			       unsigned long arg);

#ifdef __linux__
#define DRM_IOCTL_NR(n)                _IOC_NR(n)
#else
#define DRM_IOCTL_NR(n)		((n) & 0xff)
#endif

#ifdef __OpenBSD__
#define DRM_MAJOR       81
#endif
#if defined(__linux__) || defined(__NetBSD__) || defined(__DragonFly__)
#define DRM_MAJOR       226
#endif

#define DRM_AUTH	0x1
#define DRM_MASTER	0x2
#define DRM_ROOT_ONLY	0x4
#define DRM_CONTROL_ALLOW 0x8
#define DRM_UNLOCKED	0x10

typedef struct drm_ioctl_desc {
	unsigned long cmd;
	int (*func)(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
	int flags;
} drm_ioctl_desc_t;
/**
 * Creates a driver or general drm_ioctl_desc array entry for the given
 * ioctl, for use by drm_ioctl().
 */
#define DRM_IOCTL_DEF(ioctl, func, flags) \
	[DRM_IOCTL_NR(ioctl)] = {ioctl, func, flags}

typedef struct drm_magic_entry {
	drm_magic_t	       magic;
	struct drm_file	       *priv;
	struct drm_magic_entry *next;
} drm_magic_entry_t;

typedef struct drm_magic_head {
	struct drm_magic_entry *head;
	struct drm_magic_entry *tail;
} drm_magic_head_t;

typedef struct drm_buf {
	int		  idx;	       /* Index into master buflist	     */
	int		  total;       /* Buffer size			     */
	int		  order;       /* log-base-2(total)		     */
	int		  used;	       /* Amount of buffer in use (for DMA)  */
	unsigned long	  offset;      /* Byte offset (used internally)	     */
	void		  *address;    /* Address of buffer		     */
	unsigned long	  bus_address; /* Bus address of buffer		     */
	struct drm_buf	  *next;       /* Kernel-only: used for free list    */
	__volatile__ int  pending;     /* On hardware DMA queue		     */
	struct drm_file   *file_priv;  /* Unique identifier of holding process */
	int		  context;     /* Kernel queue for this buffer	     */
	enum {
		DRM_LIST_NONE	 = 0,
		DRM_LIST_FREE	 = 1,
		DRM_LIST_WAIT	 = 2,
		DRM_LIST_PEND	 = 3,
		DRM_LIST_PRIO	 = 4,
		DRM_LIST_RECLAIM = 5
	}		  list;	       /* Which list we're on		     */

	int		  dev_priv_size; /* Size of buffer private stoarge   */
	void		  *dev_private;  /* Per-buffer private storage       */
} drm_buf_t;

typedef struct drm_freelist {
	int		  initialized; /* Freelist in use		   */
	atomic_t	  count;       /* Number of free buffers	   */
	drm_buf_t	  *next;       /* End pointer			   */

	int		  low_mark;    /* Low water mark		   */
	int		  high_mark;   /* High water mark		   */
} drm_freelist_t;

typedef struct drm_dma_handle {
	void *vaddr;
	bus_addr_t busaddr;
	bus_dma_tag_t tag;
	bus_dmamap_t map;
} drm_dma_handle_t;

typedef struct drm_buf_entry {
	int		  buf_size;
	int		  buf_count;
	drm_buf_t	  *buflist;
	int		  seg_count;
	drm_dma_handle_t  **seglist;
	int		  page_order;

	drm_freelist_t	  freelist;
} drm_buf_entry_t;

typedef TAILQ_HEAD(drm_file_list, drm_file) drm_file_list_t;
struct drm_file {
	TAILQ_ENTRY(drm_file) link;
	struct drm_device *dev;
	int		  authenticated;
	int		  master;
	int		  minor;
	pid_t		  pid;
	uid_t		  uid;
	int		  refs;
	drm_magic_t	  magic;
	unsigned long	  ioctl_count;
	void		 *driver_priv;
};

typedef struct drm_lock_data {
	struct drm_hw_lock	*hw_lock;	/* Hardware lock		   */
	struct drm_file   *file_priv;   /* Unique identifier of holding process (NULL is kernel)*/
	int		  lock_queue;	/* Queue of blocked processes	   */
	unsigned long	  lock_time;	/* Time of last lock in jiffies	   */
} drm_lock_data_t;

/* This structure, in the struct drm_device, is always initialized while the
 * device
 * is open.  dev->dma_lock protects the incrementing of dev->buf_use, which
 * when set marks that no further bufs may be allocated until device teardown
 * occurs (when the last open of the device has closed).  The high/low
 * watermarks of bufs are only touched by the X Server, and thus not
 * concurrently accessed, so no locking is needed.
 */
typedef struct drm_device_dma {
	drm_buf_entry_t	  bufs[DRM_MAX_ORDER+1];
	int		  buf_count;
	drm_buf_t	  **buflist;	/* Vector of pointers info bufs	   */
	int		  seg_count;
	int		  page_count;
	unsigned long	  *pagelist;
	unsigned long	  byte_count;
	enum {
		_DRM_DMA_USE_AGP = 0x01,
		_DRM_DMA_USE_SG  = 0x02
	} flags;
} drm_device_dma_t;

typedef struct drm_agp_mem {
	void               *handle;
	unsigned long      bound; /* address */
	int                pages;
	struct drm_agp_mem *prev;
	struct drm_agp_mem *next;
} drm_agp_mem_t;

typedef struct drm_agp_head {
	device_t	   agpdev;
	struct agp_info    info;
	const char         *chipset;
	drm_agp_mem_t      *memory;
	unsigned long      mode;
	int                enabled;
	int                acquired;
	unsigned long      base;
   	int 		   mtrr;
	int		   cant_use_aperture;
	unsigned long	   page_mask;
} drm_agp_head_t;

typedef struct drm_sg_mem {
	unsigned long		  handle;
	void			 *virtual;
	int			  pages;
	dma_addr_t		 *busaddr;
	struct drm_dma_handle	 *dmah;		/* Handle to PCI memory  */
} drm_sg_mem_t;

typedef TAILQ_HEAD(drm_map_list, drm_local_map) drm_map_list_t;

typedef struct drm_local_map {
	unsigned long	offset;	 /* Physical address (0 for SAREA)*/
	unsigned long	size;	 /* Physical size (bytes)	    */
	enum drm_map_type	type;	 /* Type of memory mapped		    */
	enum drm_map_flags	flags;	 /* Flags				    */
	void		*handle; /* User-space: "Handle" to pass to mmap    */
				 /* Kernel-space: kernel-virtual address    */
	int		mtrr;	 /* Boolean: MTRR used */
				 /* Private data			    */
	int		rid;	 /* PCI resource ID for bus_space */
	struct resource *bsr;
	bus_space_tag_t bst;
	bus_space_handle_t bsh;
	drm_dma_handle_t *dmah;
	TAILQ_ENTRY(drm_local_map) link;
} drm_local_map_t;

struct drm_vblank_info {
	wait_queue_head_t queue;	/* vblank wait queue */
	atomic_t count;			/* number of VBLANK interrupts */
					/* (driver must alloc the right number of counters) */
	atomic_t refcount;		/* number of users of vblank interrupts */
	u32 last;			/* protected by dev->vbl_lock, used */
					/* for wraparound handling */
	int enabled;			/* so we don't call enable more than */
					/* once per disable */
	int inmodeset;			/* Display driver is setting mode */
};

/* location of GART table */
#define DRM_ATI_GART_MAIN 1
#define DRM_ATI_GART_FB   2

#define DRM_ATI_GART_PCI  1
#define DRM_ATI_GART_PCIE 2
#define DRM_ATI_GART_IGP  3

struct drm_ati_pcigart_info {
	int gart_table_location;
	int gart_reg_if;
	void *addr;
	dma_addr_t bus_addr;
	dma_addr_t table_mask;
	dma_addr_t member_mask;
	struct drm_dma_handle *table_handle;
	drm_local_map_t mapping;
	int table_size;
	struct drm_dma_handle *dmah; /* handle for ATI PCIGART table */
};

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : (1ULL<<(n)) - 1)
#endif

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

struct drm_driver_info {
	int	(*load)(struct drm_device *, unsigned long flags);
	int	(*firstopen)(struct drm_device *);
	int	(*open)(struct drm_device *, struct drm_file *);
	void	(*preclose)(struct drm_device *, struct drm_file *file_priv);
	void	(*postclose)(struct drm_device *, struct drm_file *);
	void	(*lastclose)(struct drm_device *);
	int	(*unload)(struct drm_device *);
	void	(*reclaim_buffers_locked)(struct drm_device *,
					  struct drm_file *file_priv);
	int	(*dma_ioctl)(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
	void	(*dma_ready)(struct drm_device *);
	int	(*dma_quiescent)(struct drm_device *);
	int	(*dma_flush_block_and_flush)(struct drm_device *, int context,
					     enum drm_lock_flags flags);
	int	(*dma_flush_unblock)(struct drm_device *, int context,
				     enum drm_lock_flags flags);
	int	(*context_ctor)(struct drm_device *dev, int context);
	int	(*context_dtor)(struct drm_device *dev, int context);
	int	(*kernel_context_switch)(struct drm_device *dev, int old,
					 int new);
	int	(*kernel_context_switch_unlock)(struct drm_device *dev);
	void	(*irq_preinstall)(struct drm_device *dev);
	int	(*irq_postinstall)(struct drm_device *dev);
	void	(*irq_uninstall)(struct drm_device *dev);
	void	(*irq_handler)(DRM_IRQ_ARGS);
	u32	(*get_vblank_counter)(struct drm_device *dev, int crtc);
	int	(*enable_vblank)(struct drm_device *dev, int crtc);
	void	(*disable_vblank)(struct drm_device *dev, int crtc);

	drm_pci_id_list_t *id_entry;	/* PCI ID, name, and chipset private */

	/**
	 * Called by \c drm_device_is_agp.  Typically used to determine if a
	 * card is really attached to AGP or not.
	 *
	 * \param dev  DRM device handle
	 *
	 * \returns 
	 * One of three values is returned depending on whether or not the
	 * card is absolutely \b not AGP (return of 0), absolutely \b is AGP
	 * (return of 1), or may or may not be AGP (return of 2).
	 */
	int	(*device_is_agp) (struct drm_device * dev);

	drm_ioctl_desc_t *ioctls;
	int	max_ioctl;

	int	buf_priv_size;

	int	major;
	int	minor;
	int	patchlevel;
	const char *name;		/* Simple driver name		   */
	const char *desc;		/* Longer driver name		   */
	const char *date;		/* Date of last major changes.	   */

	u32 driver_features;
};

/* Length for the array of resource pointers for drm_get_resource_*. */
#define DRM_MAX_PCI_RESOURCE	6

/** 
 * DRM device functions structure
 */
struct drm_device {
	struct drm_driver_info *driver;
	drm_pci_id_list_t *id_entry;	/* PCI ID, name, and chipset private */

	u_int16_t pci_device;		/* PCI device id */
	u_int16_t pci_vendor;		/* PCI vendor id */

	char		  *unique;	/* Unique identifier: e.g., busid  */
	int		  unique_len;	/* Length of unique field	   */
	device_t	  device;	/* Device instance from newbus     */
	struct cdev	  *devnode;	/* Device number for mknod	   */
	int		  if_version;	/* Highest interface version set */

	int		  flags;	/* Flags to open(2)		   */

				/* Locks */
	DRM_SPINTYPE	  vbl_lock;	/* protects vblank operations */
	DRM_SPINTYPE	  dma_lock;	/* protects dev->dma */
	struct lwkt_serialize irq_lock;	/* protects irq condition checks */
	DRM_SPINTYPE	  dev_lock;	/* protects everything else */
	DRM_SPINTYPE	  drw_lock;

				/* Usage Counters */
	int		  open_count;	/* Outstanding files open	   */
	int		  buf_use;	/* Buffers in use -- cannot alloc  */

				/* Performance counters */
	unsigned long     counters;
	enum drm_stat_type	types[15];
	atomic_t          counts[15];

				/* Authentication */
	drm_file_list_t   files;
	drm_magic_head_t  magiclist[DRM_HASH_SIZE];

	/* Linked list of mappable regions. Protected by dev_lock */
	drm_map_list_t	  maplist;

	drm_local_map_t	  **context_sareas;
	int		  max_context;

	drm_lock_data_t	  lock;		/* Information on hardware lock	   */

				/* DMA queues (contexts) */
	drm_device_dma_t  *dma;		/* Optional pointer for DMA support */

				/* Context support */
	int		  irq;		/* Interrupt used by board	   */
	int		  irq_enabled;	/* True if the irq handler is enabled */
	int		  msi_enabled;	/* MSI enabled */
	int		  irqrid;	/* Interrupt used by board */
	struct resource   *irqr;	/* Resource for interrupt used by board	   */
	void		  *irqh;	/* Handle from bus_setup_intr      */

	/* Storage of resource pointers for drm_get_resource_* */
	struct resource   *pcir[DRM_MAX_PCI_RESOURCE];
	int		  pcirid[DRM_MAX_PCI_RESOURCE];

	int		  pci_domain;
	int		  pci_bus;
	int		  pci_slot;
	int		  pci_func;

	atomic_t	  context_flag;	/* Context swapping flag	   */
	int		  last_context;	/* Last current context		   */

	int		  vblank_disable_allowed;
	struct callout	  vblank_disable_timer;
	u32		  max_vblank_count;	/* size of vblank counter register */
	struct drm_vblank_info *vblank;		/* per crtc vblank info */
	int		  num_crtcs;

	struct sigio      *buf_sigio;	/* Processes waiting for SIGIO     */

				/* Sysctl support */
	struct drm_sysctl_info *sysctl;

	drm_agp_head_t    *agp;
	drm_sg_mem_t      *sg;  /* Scatter gather memory */
	atomic_t          *ctx_bitmap;
	void		  *dev_private;
	unsigned int	  agp_buffer_token;
	drm_local_map_t   *agp_buffer_map;

	/* RB tree of drawable infos */
	RB_HEAD(drawable_tree, bsd_drm_drawable_info) drw_head;
};

static __inline__ int drm_core_check_feature(struct drm_device *dev,
					     int feature)
{
	return ((dev->driver->driver_features & feature) ? 1 : 0);
}

#if __OS_HAS_AGP
static inline int drm_core_has_AGP(struct drm_device *dev)
{
	return drm_core_check_feature(dev, DRIVER_USE_AGP);
}
#else
#define drm_core_has_AGP(dev) (0)
#endif

extern int	drm_debug_flag;

/* Device setup support (drm_drv.c) */
int	drm_probe(device_t kdev, drm_pci_id_list_t *idlist);
int	drm_attach(device_t kdev, drm_pci_id_list_t *idlist);
int	drm_detach(device_t kdev);
d_ioctl_t drm_ioctl;
d_open_t drm_open;
d_close_t drm_close;
d_read_t drm_read;
d_poll_t drm_poll;
d_mmap_t drm_mmap;
extern drm_local_map_t	*drm_getsarea(struct drm_device *dev);

/* File operations helpers (drm_fops.c) */
extern int		drm_open_helper(struct cdev *kdev, int flags, int fmt,
					 DRM_STRUCTPROC *p,
					struct drm_device *dev);
extern struct drm_file	*drm_find_file_by_proc(struct drm_device *dev,
					DRM_STRUCTPROC *p);

/* Memory management support (drm_memory.c) */
void	drm_mem_init(void);
void	drm_mem_uninit(void);
void	*drm_ioremap_wc(struct drm_device *dev, drm_local_map_t *map);
void	*drm_ioremap(struct drm_device *dev, drm_local_map_t *map);
void	drm_ioremapfree(drm_local_map_t *map);
int	drm_mtrr_add(unsigned long offset, size_t size, int flags);
int	drm_mtrr_del(int handle, unsigned long offset, size_t size, int flags);

int	drm_context_switch(struct drm_device *dev, int old, int new);
int	drm_context_switch_complete(struct drm_device *dev, int new);

int	drm_ctxbitmap_init(struct drm_device *dev);
void	drm_ctxbitmap_cleanup(struct drm_device *dev);
void	drm_ctxbitmap_free(struct drm_device *dev, int ctx_handle);
int	drm_ctxbitmap_next(struct drm_device *dev);

/* Locking IOCTL support (drm_lock.c) */
int	drm_lock_take(struct drm_lock_data *lock_data,
		      unsigned int context);
int	drm_lock_transfer(struct drm_lock_data *lock_data,
			  unsigned int context);
int	drm_lock_free(struct drm_lock_data *lock_data,
		      unsigned int context);

/* Buffer management support (drm_bufs.c) */
unsigned long drm_get_resource_start(struct drm_device *dev,
				     unsigned int resource);
unsigned long drm_get_resource_len(struct drm_device *dev,
				   unsigned int resource);
void	drm_rmmap(struct drm_device *dev, drm_local_map_t *map);
int	drm_order(unsigned long size);
int	drm_addmap(struct drm_device *dev, unsigned long offset,
		   unsigned long size,
		   enum drm_map_type type, enum drm_map_flags flags,
		   drm_local_map_t **map_ptr);
int	drm_addbufs_pci(struct drm_device *dev, struct drm_buf_desc *request);
int	drm_addbufs_sg(struct drm_device *dev, struct drm_buf_desc *request);
int	drm_addbufs_agp(struct drm_device *dev, struct drm_buf_desc *request);

/* DMA support (drm_dma.c) */
int	drm_dma_setup(struct drm_device *dev);
void	drm_dma_takedown(struct drm_device *dev);
void	drm_free_buffer(struct drm_device *dev, drm_buf_t *buf);
void	drm_reclaim_buffers(struct drm_device *dev, struct drm_file *file_priv);
#define drm_core_reclaim_buffers drm_reclaim_buffers

/* IRQ support (drm_irq.c) */
int	drm_irq_install(struct drm_device *dev);
int	drm_irq_uninstall(struct drm_device *dev);
irqreturn_t drm_irq_handler(DRM_IRQ_ARGS);
void	drm_driver_irq_preinstall(struct drm_device *dev);
void	drm_driver_irq_postinstall(struct drm_device *dev);
void	drm_driver_irq_uninstall(struct drm_device *dev);
void	drm_handle_vblank(struct drm_device *dev, int crtc);
u32	drm_vblank_count(struct drm_device *dev, int crtc);
int	drm_vblank_get(struct drm_device *dev, int crtc);
void	drm_vblank_put(struct drm_device *dev, int crtc);
void	drm_vblank_cleanup(struct drm_device *dev);
int	drm_vblank_wait(struct drm_device *dev, unsigned int *vbl_seq);
int	drm_vblank_init(struct drm_device *dev, int num_crtcs);
int 	drm_modeset_ctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

/* AGP/PCI Express/GART support (drm_agpsupport.c) */
int	drm_device_is_agp(struct drm_device *dev);
int	drm_device_is_pcie(struct drm_device *dev);
drm_agp_head_t *drm_agp_init(void);
int	drm_agp_acquire(struct drm_device *dev);
int	drm_agp_release(struct drm_device *dev);
int	drm_agp_info(struct drm_device * dev, struct drm_agp_info *info);
int	drm_agp_enable(struct drm_device *dev, struct drm_agp_mode mode);
void	*drm_agp_allocate_memory(size_t pages, u32 type);
int	drm_agp_free_memory(void *handle);
int	drm_agp_bind_memory(void *handle, off_t start);
int	drm_agp_unbind_memory(void *handle);
int	drm_agp_alloc(struct drm_device *dev, struct drm_agp_buffer *request);
int	drm_agp_free(struct drm_device *dev, struct drm_agp_buffer *request);
int	drm_agp_bind(struct drm_device *dev, struct drm_agp_binding *request);
int	drm_agp_unbind(struct drm_device *dev, struct drm_agp_binding *request);

/* Scatter Gather Support (drm_scatter.c) */
void	drm_sg_cleanup(drm_sg_mem_t *entry);
int	drm_sg_alloc(struct drm_device *dev, struct drm_scatter_gather * request);

/* sysctl support (drm_sysctl.h) */
extern int		drm_sysctl_init(struct drm_device *dev);
extern int		drm_sysctl_cleanup(struct drm_device *dev);

/* ATI PCIGART support (ati_pcigart.c) */
int	drm_ati_pcigart_init(struct drm_device *dev,
				struct drm_ati_pcigart_info *gart_info);
int	drm_ati_pcigart_cleanup(struct drm_device *dev,
				struct drm_ati_pcigart_info *gart_info);

/* Locking IOCTL support (drm_drv.c) */
int	drm_lock(struct drm_device *dev, void *data,
		 struct drm_file *file_priv);
int	drm_unlock(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_version(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_setversion(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);

/* Misc. IOCTL support (drm_ioctl.c) */
int	drm_irq_by_busid(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int	drm_getunique(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_setunique(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_getmap(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_getclient(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_getstats(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_noop(struct drm_device *dev, void *data,
		 struct drm_file *file_priv);

/* Context IOCTL support (drm_context.c) */
int	drm_resctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_addctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_modctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_getctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_switchctx(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int	drm_newctx(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_rmctx(struct drm_device *dev, void *data,
		  struct drm_file *file_priv);
int	drm_setsareactx(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int	drm_getsareactx(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

/* Drawable IOCTL support (drm_drawable.c) */
int	drm_adddraw(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_rmdraw(struct drm_device *dev, void *data,
		   struct drm_file *file_priv);
int	drm_update_draw(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
struct drm_drawable_info *drm_get_drawable_info(struct drm_device *dev,
						int handle);

/* Drawable support (drm_drawable.c) */
void drm_drawable_free_all(struct drm_device *dev);

/* Authentication IOCTL support (drm_auth.c) */
int	drm_getmagic(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_authmagic(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);

/* Buffer management support (drm_bufs.c) */
int	drm_addmap_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);
int	drm_rmmap_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int	drm_addbufs(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_infobufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_markbufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_freebufs(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int	drm_mapbufs(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);

/* DMA support (drm_dma.c) */
int	drm_dma(struct drm_device *dev, void *data, struct drm_file *file_priv);

/* IRQ support (drm_irq.c) */
int	drm_control(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);
int	drm_wait_vblank(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

/* AGP/GART support (drm_agpsupport.c) */
int	drm_agp_acquire_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int	drm_agp_release_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);
int	drm_agp_enable_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
int	drm_agp_info_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_agp_alloc_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file_priv);
int	drm_agp_free_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_agp_unbind_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);
int	drm_agp_bind_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);

/* Scatter Gather Support (drm_scatter.c) */
int	drm_sg_alloc_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);
int	drm_sg_free(struct drm_device *dev, void *data,
		    struct drm_file *file_priv);

/* consistent PCI memory functions (drm_pci.c) */
drm_dma_handle_t *drm_pci_alloc(struct drm_device *dev, size_t size,
				size_t align, dma_addr_t maxaddr);
void	drm_pci_free(struct drm_device *dev, drm_dma_handle_t *dmah);

/* Inline replacements for drm_alloc and friends */
static __inline__ void *
drm_alloc(size_t size, struct malloc_type *area)
{
	return malloc(size, area, M_NOWAIT);
}

static __inline__ void *
drm_calloc(size_t nmemb, size_t size, struct malloc_type *area)
{
	return malloc(size * nmemb, area, M_NOWAIT | M_ZERO);
}

static __inline__ void *
drm_realloc(void *oldpt, size_t oldsize, size_t size,
    struct malloc_type *area)
{
	return reallocf(oldpt, size, area, M_NOWAIT);
}

static __inline__ void
drm_free(void *pt, size_t size, struct malloc_type *area)
{
	free(pt, area);
}

/* Inline replacements for DRM_IOREMAP macros */
static __inline__ void
drm_core_ioremap_wc(struct drm_local_map *map, struct drm_device *dev)
{
	map->handle = drm_ioremap_wc(dev, map);
}
static __inline__ void
drm_core_ioremap(struct drm_local_map *map, struct drm_device *dev)
{
	map->handle = drm_ioremap(dev, map);
}
static __inline__ void
drm_core_ioremapfree(struct drm_local_map *map, struct drm_device *dev)
{
	if ( map->handle && map->size )
		drm_ioremapfree(map);
}

static __inline__ struct drm_local_map *
drm_core_findmap(struct drm_device *dev, unsigned long offset)
{
	drm_local_map_t *map;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if (map->offset == offset)
			return map;
	}
	return NULL;
}

static __inline__ void drm_core_dropmap(struct drm_map *map)
{
}

#endif /* __KERNEL__ */
#endif /* _DRM_P_H_ */
