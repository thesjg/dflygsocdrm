/* drm_porting_include.h derived from drmP.h
 * drmP.h -- Private header for Direct Rendering Manager -*- linux-c -*-
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

#ifndef _DRM_PORTING_INCLUDE_H_
#define _DRM_PORTING_INCLUDE_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/sysctl.h>
#include <sys/bus.h>
#include <sys/signalvar.h>
#include <sys/poll.h>
#include <sys/tree.h>

#include <sys/taskqueue.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <machine/param.h>
#include <machine/pmap.h>
#include <sys/bus.h>
#include <sys/resource.h>
#include <machine/specialreg.h>
#include <machine/sysarch.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/rman.h>
#include <sys/memrange.h>
#include <dev/agp/agpvar.h>
#include <sys/device.h>
#include <sys/agpio.h>
#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include <sys/bus.h>

/* For struct mtx, mtx_init, mtx_lock, mtx_unlock */
#include <sys/mutex.h>
#include <sys/mutex2.h>

/* For dev_t which is apparently uint32_t on DragonFly */
#include <sys/types.h>

/* For atomic operations for kref */
#include <machine/atomic.h>

#ifdef __DragonFly__
/* For va_start, va_end etc.
 * Note this header on DragonFly only includes machine/stdarg.h
 * then defines blah to be internal __blah.
 */
#include <stdarg.h>
#endif

/* for curthread */
#ifdef __DragonFly__
#include <sys/globaldata.h>
#include <machine/globaldata.h>
#endif

/* for gettimeofday */
#ifdef __DragonFly__
#include <sys/time.h>
#endif

/* for giant lock get_mplock() and rel_mplock() */
#ifdef __DragonFly__
#include <sys/mplock2.h>
#endif

/* for kern_kill */
#ifdef __DragonFly__
#include <sys/kern_syscall.h>
#endif

/* for lwbuf_alloc */
#ifdef __DragonFly__
#include <cpu/lwbuf.h>
#endif

#endif /* __KERNEL__ */
#endif
