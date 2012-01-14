/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/netgraph7/dragonfly.h,v 1.1 2008/06/26 23:05:35 dillon Exp $
 */

#include <sys/globaldata.h>	/* curthread in mtx_assert() */
#include <sys/lock.h>
#include <sys/objcache.h>

#ifndef _VA_LIST_DECLARED
#define _VA_LIST_DECLARED
typedef __va_list	va_list;
#endif
#define va_start(ap,last)	__va_start(ap,last)
#define va_end(ap)	__va_end(ap)

/*
#define mtx_assert(mtx, MA_OWNED) 		\
			KKASSERT(mtx_owned(&(mtx)->lock))

#define mtx_assert(mtx, MA_NOTOWNED) 		\
			KKASSERT(mtx_notowned(&(mtx)->lock))
*/

#define IFNET_RLOCK()	crit_enter()
#define IFNET_RUNLOCK()	crit_exit()

#define IFQ_LOCK(ifp)	lwkt_serialize_enter(&(ifp)->altq_lock)
#define IFQ_UNLOCK(ifp)	lwkt_serialize_exit(&(ifp)->altq_lock)

#define printf		kprintf
#define sprintf		ksprintf
#define snprintf	ksnprintf
#define vsnprintf	kvsnprintf

typedef struct objcache	*objcache_t;
#define uma_zone_t	objcache_t
typedef void *		uma_ctor;
typedef void *		uma_dtor;
typedef void *		uma_init;
typedef void *		uma_fini;

#define UMA_ALIGN_CACHE	0

#define uma_zcreate(name, size, ctor, dtor, uminit, fini, align, flags)	\
			objcache_create_mbacked(M_NETGRAPH, size,	\
					NULL, 0,			\
					bzero_ctor, NULL,		\
					NULL)
#define uma_zalloc(zone, flags)			\
			objcache_get(zone, flags)
#define uma_zfree(zone, item)			\
			objcache_put(zone, item)
#define uma_zone_set_max(zone, nitems)

#define CTR1(ktr_line, ...)
#define CTR2(ktr_line, ...)
#define CTR3(ktr_line, ...)
#define CTR4(ktr_line, ...)
#define CTR5(ktr_line, ...)
#define CTR6(ktr_line, ...)
#define cpu_spinwait()	cpu_pause()

#define splnet()	0
#define splx(v)

#define CTLFLAG_RDTUN	CTLFLAG_RD

#define SI_SUB_NETGRAPH	SI_SUB_DRIVERS
