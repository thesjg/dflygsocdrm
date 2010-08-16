/**
 * \file drm_porting_other.h
 * Declarations in previous BSD version of drmP.h
 * not in current Linux drmP.h
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
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
 */

#ifndef _DRM_PORTING_OTHER_H_
#define _DRM_PORTING_OTHER_H_

/* #include "dev/drm/drm_internal.h" */

/************************************************
 * Old version of drmP.h
 ************************************************/

#include <opt_drm.h>
#ifdef DRM_DEBUG
#undef DRM_DEBUG
#define DRM_DEBUG_DEFAULT_ON 1
#endif /* DRM_DEBUG */

#if defined(DRM_LINUX) && DRM_LINUX && !defined(__x86_64__) && !defined(__DragonFly__) /* XXX */
#include <sys/file.h>
#include <sys/proc.h>
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#else
/* Either it was defined when it shouldn't be (FreeBSD amd64) or it isn't
 * supported on this OS yet.
 */
#undef DRM_LINUX
#define DRM_LINUX 0
#endif

/* What is for now actually used in BSD code */
#define DRM_HASH_SIZE	      16 /* Size of key hash table		  */

/** Internal types and structures */

#define DRM_MIN(a,b) ((a)<(b)?(a):(b))
#define DRM_MAX(a,b) ((a)>(b)?(a):(b))

#define DRM_DEV_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define DRM_DEV_UID	0
#define DRM_DEV_GID	0

#define DRM_WAKEUP(w)		wakeup((void *)w)

/* Not in Linux drm */
#define DRM_WAKEUP_INT(w)	wakeup(w)

#define DRM_INIT_WAITQUEUE(queue) do {(void)(queue);} while (0)

#define DRM_CURPROC		curthread
#define DRM_STRUCTPROC		struct thread

#define DRM_CURRENTPID		curthread->td_proc->p_pid

/* Specific to BSD port of drm */
/* drm_drv.c drm_ioctl() and drm_vm.c drm_mmap() */
#define drm_get_device_from_kdev(_kdev) (_kdev->si_drv1)

/* DRM_SUSER returns true if the user is superuser */
#define DRM_SUSER(p)		(priv_check(p, PRIV_DRIVER) == 0)

/*
 * AGP
 */

/* Specific to BSD port of drm */
/* DRM_MIGHT_BE_AGP used in drm_agpsupport.c and mga_drv.c */
enum {
	DRM_IS_NOT_AGP,
	DRM_IS_AGP,
	DRM_MIGHT_BE_AGP
};

/* Specific to BSD port of drm */
/* drm_agpsupport.c */
#define DRM_AGP_FIND_DEVICE()	agp_find_device()

/* DRM_READMEMORYBARRIER() prevents reordering of reads.
 * DRM_WRITEMEMORYBARRIER() prevents reordering of writes.
 * DRM_MEMORYBARRIER() prevents reordering of reads and writes.
 */
#if defined(__i386__)
#define DRM_READMEMORYBARRIER()		__asm __volatile( \
					"lock; addl $0,0(%%esp)" : : : "memory");
#define DRM_WRITEMEMORYBARRIER()	__asm __volatile("" : : : "memory");
#define DRM_MEMORYBARRIER()		__asm __volatile( \
					"lock; addl $0,0(%%esp)" : : : "memory");
#elif defined(__alpha__)
#define DRM_READMEMORYBARRIER()		alpha_mb();
#define DRM_WRITEMEMORYBARRIER()	alpha_wmb();
#define DRM_MEMORYBARRIER()		alpha_mb();
#elif defined(__x86_64__)
#define DRM_READMEMORYBARRIER()		__asm __volatile( \
					"lock; addl $0,0(%%rsp)" : : : "memory");
#define DRM_WRITEMEMORYBARRIER()	__asm __volatile("" : : : "memory");
#define DRM_MEMORYBARRIER()		__asm __volatile( \
					"lock; addl $0,0(%%rsp)" : : : "memory");
#endif

#define DRM_READ8(map, offset)						\
	*(volatile u_int8_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset))
#define DRM_READ16(map, offset)						\
	*(volatile u_int16_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset))
#define DRM_READ32(map, offset)						\
	*(volatile u_int32_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset))
/* extension for i915/i915_drv.h */
#define DRM_READ64(map, offset)						\
	*(volatile u_int64_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset))

#define DRM_WRITE8(map, offset, val)					\
	*(volatile u_int8_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset)) = val
#define DRM_WRITE16(map, offset, val)					\
	*(volatile u_int16_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset)) = val
#define DRM_WRITE32(map, offset, val)					\
	*(volatile u_int32_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset)) = val
/* extension for i915/i915_drv.h */
#define DRM_WRITE64(map, offset, val)					\
	*(volatile u_int64_t *)(((vm_offset_t)(map)->handle) +		\
	    (vm_offset_t)(offset)) = val

#define DRM_VERIFYAREA_READ( uaddr, size )		\
	(!useracc(__DECONST(caddr_t, uaddr), size, VM_PROT_READ))

#define DRM_COPY_TO_USER(user, kern, size) \
	copyout(kern, user, size)
#define DRM_COPY_FROM_USER(kern, user, size) \
	copyin(user, kern, size)
#define DRM_COPY_FROM_USER_UNCHECKED(arg1, arg2, arg3) 	\
	copyin(arg2, arg1, arg3)
#define DRM_COPY_TO_USER_UNCHECKED(arg1, arg2, arg3)	\
	copyout(arg2, arg1, arg3)
#define DRM_GET_USER_UNCHECKED(val, uaddr)		\
	((val) = fuword32(uaddr), 0)

#define DRM_HZ			hz
#define DRM_UDELAY(udelay)	DELAY(udelay)

/* Does not appear to be used either BSD or Linux drm */
#define DRM_GET_PRIV_SAREA(_dev, _ctx, _map) do {	\
	(_map) = (_dev)->context_sareas[_ctx];		\
} while(0)


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

/* Legacy drm used only in this file? */
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

/* Length for the array of resource pointers for drm_get_resource_*. */
#define DRM_MAX_PCI_RESOURCE	6

/* Legacy drm defined in drm_drv.c */
extern int	drm_debug_flag;

#if 0
/* Deduced from drm_agpsupport function drm_agp_info() */
typedef struct drm_agp_info	DRM_AGP_KERN;
#endif

/* legacy drm */
d_ioctl_t drm_ioctl_legacy;
d_open_t drm_open_legacy;
d_close_t drm_close_legacy;
d_read_t drm_read_legacy;
d_poll_t drm_poll_legacy;
d_mmap_t drm_mmap_legacy;

/* Inline replacements for drm_alloc and friends */
static __inline__ void *
drm_alloc(size_t size, struct malloc_type *area)
{
	return malloc(size, area, M_WAITOK | M_ZERO);
}

static __inline__ void *
drm_calloc(size_t nmemb, size_t size, struct malloc_type *area)
{
	return malloc(size * nmemb, area, M_WAITOK | M_ZERO);
}

static __inline__ void
drm_free(void *pt, size_t size, struct malloc_type *area)
{
	free(pt, area);
}

struct drm_sysctl_info {
	struct sysctl_ctx_list ctx;
	char name[5];
};

typedef struct sysctl_oid *DRM_PROC_DIR_ENTRY;

extern DRM_PROC_DIR_ENTRY drm_sysctl_mkroot(const char *name);

extern void drm_sysctl_rmroot(DRM_PROC_DIR_ENTRY root);

extern DRM_PROC_DIR_ENTRY drm_sysctl_root;

/* Switching to Linux drm drm_pciids.h format */
#define DRM_NEWER_PCIID 1
#ifdef DRM_NEWER_PCIID
#define DRM_PCI_DEVICE_ID  struct pci_device_id
#else
#define DRM_PCI_DEVICE_ID  drm_pci_id_list_t
#endif

#endif

#define DRM_NEWER_MAPLIST 1
#define DRM_NEWER_HWLOCK 1
#define DRM_NEWER_SAREA 1
#define DRM_NEWER_MTRR 1

#define DRM_OPEN_ARGS  struct dev_open_args *ap
#define DRM_GET_DEV_ARGS  device_t kdev, DRM_PCI_DEVICE_ID *idlist
