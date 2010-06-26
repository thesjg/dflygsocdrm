/*
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/compat/ndis/kern_ndis.c,v 1.57 2004/07/11 00:19:30 wpaul Exp $
 * $DragonFly: src/sys/emulation/ndis/kern_ndis.c,v 1.14 2006/12/20 18:14:41 dillon Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/callout.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/conf.h>

#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/kthread.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netproto/802_11/ieee80211_var.h>
#include <netproto/802_11/ieee80211_ioctl.h>

#include "regcall.h"
#include "pe_var.h"
#include "resource_var.h"
#include "ntoskrnl_var.h"
#include "ndis_var.h"
#include "hal_var.h"
#include "cfg_var.h"
#include <dev/netif/ndis/if_ndisvar.h>

#define NDIS_DUMMY_PATH "\\\\some\\bogus\\path"

__stdcall static void ndis_status_func(ndis_handle, ndis_status,
	void *, uint32_t);
__stdcall static void ndis_statusdone_func(ndis_handle);
__stdcall static void ndis_setdone_func(ndis_handle, ndis_status);
__stdcall static void ndis_getdone_func(ndis_handle, ndis_status);
__stdcall static void ndis_resetdone_func(ndis_handle, ndis_status, uint8_t);
__stdcall static void ndis_sendrsrcavail_func(ndis_handle);

struct nd_head ndis_devhead;

struct ndis_req {
	void			(*nr_func)(void *);
	void			*nr_arg;
	int			nr_exit;
	STAILQ_ENTRY(ndis_req)	link;
};

struct ndisproc {
	struct ndisqhead	*np_q;
	struct thread		*np_td;
	int			np_state;
};

static void ndis_return(void *);
static int ndis_create_kthreads(void);
static void ndis_destroy_kthreads(void);
static void ndis_stop_thread(int);
static int ndis_enlarge_thrqueue(int);
static int ndis_shrink_thrqueue(int);
static void ndis_runq(void *);

static MALLOC_DEFINE(M_NDIS_PACKET, "ndis_packet", "ndis packet slosh");
static MALLOC_DEFINE(M_NDIS_BUFFER, "ndis_buffer", "ndis buffer slosh");
struct lwkt_token ndis_thr_token;
static STAILQ_HEAD(ndisqhead, ndis_req) ndis_ttodo;
struct ndisqhead ndis_itodo;
struct ndisqhead ndis_free;
static int ndis_jobs = 32;

static struct ndisproc ndis_tproc;
static struct ndisproc ndis_iproc;

/*
 * This allows us to export our symbols to other modules.
 * Note that we call ourselves 'ndisapi' to avoid a namespace
 * collision with if_ndis.ko, which internally calls itself
 * 'ndis.'
 */
static int
ndis_modevent(module_t mod, int cmd, void *arg)
{
	int			error = 0;

	switch (cmd) {
	case MOD_LOAD:
		/* Initialize subsystems */
		ndis_libinit();
		ntoskrnl_libinit();

		/* Initialize TX buffer UMA zone. */
		ndis_create_kthreads();

		TAILQ_INIT(&ndis_devhead);

		break;
	case MOD_SHUTDOWN:
		/* stop kthreads */
		ndis_destroy_kthreads();
		if (TAILQ_FIRST(&ndis_devhead) == NULL) {
			/* Shut down subsystems */
			ndis_libfini();
			ntoskrnl_libfini();

			/* Remove zones */
#if 0	/* YYY */
			malloc_uninit(M_NDIS_PACKET);
			malloc_uninit(M_NDIS_BUFFER);
#endif
		}
		break;
	case MOD_UNLOAD:
		/* stop kthreads */
		ndis_destroy_kthreads();

		/* Shut down subsystems */
		ndis_libfini();
		ntoskrnl_libfini();

		/* Remove zones */
#if 0	/* YYY */
		malloc_uninit(M_NDIS_PACKET);
		malloc_uninit(M_NDIS_BUFFER);
#endif
		break;
	default:
		error = EINVAL;
		break;
	}

	return(error);
}
DEV_MODULE(ndisapi, ndis_modevent, NULL);
MODULE_VERSION(ndisapi, 1);

/*
 * We create two kthreads for the NDIS subsystem. One of them is a task
 * queue for performing various odd jobs. The other is an swi thread
 * reserved exclusively for running interrupt handlers. The reason we
 * have our own task queue is that there are some cases where we may
 * need to sleep for a significant amount of time, and if we were to
 * use one of the taskqueue threads, we might delay the processing
 * of other pending tasks which might need to run right away. We have
 * a separate swi thread because we don't want our interrupt handling
 * to be delayed either.
 *
 * By default there are 32 jobs available to start, and another 8
 * are added to the free list each time a new device is created.
 */

static void
ndis_runq(void *arg)
{
	struct ndis_req		*r = NULL, *die = NULL;
	struct ndisproc		*p;

	p = arg;

	while (1) {

		/* Sleep, but preserve our original priority. */
		ndis_thsuspend(p->np_td, 0);

		/* Look for any jobs on the work queue. */

		lwkt_gettoken(&ndis_thr_token);
		p->np_state = NDIS_PSTATE_RUNNING;
		while(STAILQ_FIRST(p->np_q) != NULL) {
			r = STAILQ_FIRST(p->np_q);
			STAILQ_REMOVE_HEAD(p->np_q, link);
			lwkt_reltoken(&ndis_thr_token);

			/* Do the work. */

			if (r->nr_func != NULL)
				(*r->nr_func)(r->nr_arg);

			lwkt_gettoken(&ndis_thr_token);
			STAILQ_INSERT_HEAD(&ndis_free, r, link);

			/* Check for a shutdown request */

			if (r->nr_exit == TRUE)
				die = r;
		}
		p->np_state = NDIS_PSTATE_SLEEPING;
		lwkt_reltoken(&ndis_thr_token);

		/* Bail if we were told to shut down. */

		if (die != NULL)
			break;
	}

	wakeup(die);
	kthread_exit();
}

static int
ndis_create_kthreads(void)
{
	struct ndis_req		*r;
	int			i, error = 0;

	lwkt_token_init(&ndis_thr_token, 1);

	STAILQ_INIT(&ndis_ttodo);
	STAILQ_INIT(&ndis_itodo);
	STAILQ_INIT(&ndis_free);

	for (i = 0; i < ndis_jobs; i++) {
		r = kmalloc(sizeof(struct ndis_req), M_DEVBUF, M_WAITOK);
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
	}

	if (error == 0) {
		ndis_tproc.np_q = &ndis_ttodo;
		ndis_tproc.np_state = NDIS_PSTATE_SLEEPING;
		error = kthread_create_stk(ndis_runq, &ndis_tproc,
		    &ndis_tproc.np_td, NDIS_KSTACK_PAGES * PAGE_SIZE,
		    "ndis taskqueue");
	}

	if (error == 0) {
		ndis_iproc.np_q = &ndis_itodo;
		ndis_iproc.np_state = NDIS_PSTATE_SLEEPING;
		error = kthread_create_stk(ndis_runq, &ndis_iproc,
		    &ndis_iproc.np_td, NDIS_KSTACK_PAGES * PAGE_SIZE,
		    "ndis swi");
	}

	if (error) {
		while ((r = STAILQ_FIRST(&ndis_free)) != NULL) {
			STAILQ_REMOVE_HEAD(&ndis_free, link);
			kfree(r, M_DEVBUF);
		}
		return(error);
	}

	return(0);
}

static void
ndis_destroy_kthreads(void)
{
	struct ndis_req		*r;

	/* Stop the threads. */

	ndis_stop_thread(NDIS_TASKQUEUE);
	ndis_stop_thread(NDIS_SWI);

	/* Destroy request structures. */

	while ((r = STAILQ_FIRST(&ndis_free)) != NULL) {
		STAILQ_REMOVE_HEAD(&ndis_free, link);
		kfree(r, M_DEVBUF);
	}

	lwkt_token_uninit(&ndis_thr_token);

	return;
}

static void
ndis_stop_thread(int t)
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	thread_t		td;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		td = ndis_tproc.np_td;
	} else {
		q = &ndis_itodo;
		td = ndis_iproc.np_td;
	}

	/* Create and post a special 'exit' job. */

	lwkt_gettoken(&ndis_thr_token);
	r = STAILQ_FIRST(&ndis_free);
	STAILQ_REMOVE_HEAD(&ndis_free, link);
	r->nr_func = NULL;
	r->nr_arg = NULL;
	r->nr_exit = TRUE;
	STAILQ_INSERT_TAIL(q, r, link);
	lwkt_reltoken(&ndis_thr_token);

	ndis_thresume(td);

	/* wait for thread exit */

	tsleep(r, PCATCH, "ndisthexit", hz * 60);

	/* Now empty the job list. */

	lwkt_gettoken(&ndis_thr_token);
	while ((r = STAILQ_FIRST(q)) != NULL) {
		STAILQ_REMOVE_HEAD(q, link);
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
	}
	lwkt_reltoken(&ndis_thr_token);
}

static int
ndis_enlarge_thrqueue(int cnt)
{
	struct ndis_req		*r;
	int			i;

	for (i = 0; i < cnt; i++) {
		r = kmalloc(sizeof(struct ndis_req), M_DEVBUF, M_WAITOK);
		lwkt_gettoken(&ndis_thr_token);
		STAILQ_INSERT_HEAD(&ndis_free, r, link);
		ndis_jobs++;
		lwkt_reltoken(&ndis_thr_token);
	}

	return(0);
}

static int
ndis_shrink_thrqueue(int cnt)
{
	struct ndis_req		*r;
	int			i;

	for (i = 0; i < cnt; i++) {
		lwkt_gettoken(&ndis_thr_token);
		r = STAILQ_FIRST(&ndis_free);
		if (r == NULL) {
			lwkt_reltoken(&ndis_thr_token);
			return(ENOMEM);
		}
		STAILQ_REMOVE_HEAD(&ndis_free, link);
		ndis_jobs--;
		lwkt_reltoken(&ndis_thr_token);
		kfree(r, M_DEVBUF);
	}

	return(0);
}

int
ndis_unsched(void (*func)(void *), void *arg, int t)
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	thread_t		td;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		td = ndis_tproc.np_td;
	} else {
		q = &ndis_itodo;
		td = ndis_iproc.np_td;
	}

	lwkt_gettoken(&ndis_thr_token);
	STAILQ_FOREACH(r, q, link) {
		if (r->nr_func == func && r->nr_arg == arg) {
			STAILQ_REMOVE(q, r, ndis_req, link);
			STAILQ_INSERT_HEAD(&ndis_free, r, link);
			lwkt_reltoken(&ndis_thr_token);
			return(0);
		}
	}

	lwkt_reltoken(&ndis_thr_token);

	return(ENOENT);
}

int
ndis_sched(void (*func)(void *), void *arg, int t)
{
	struct ndis_req		*r;
	struct ndisqhead	*q;
	thread_t		td;
	int			s;

	if (t == NDIS_TASKQUEUE) {
		q = &ndis_ttodo;
		td = ndis_tproc.np_td;
	} else {
		q = &ndis_itodo;
		td = ndis_iproc.np_td;
	}

	lwkt_gettoken(&ndis_thr_token);
	/*
	 * Check to see if an instance of this job is already
	 * pending. If so, don't bother queuing it again.
	 */
	STAILQ_FOREACH(r, q, link) {
		if (r->nr_func == func && r->nr_arg == arg) {
			lwkt_reltoken(&ndis_thr_token);
			return(0);
		}
	}
	r = STAILQ_FIRST(&ndis_free);
	if (r == NULL) {
		lwkt_reltoken(&ndis_thr_token);
		return(EAGAIN);
	}
	STAILQ_REMOVE_HEAD(&ndis_free, link);
	r->nr_func = func;
	r->nr_arg = arg;
	r->nr_exit = FALSE;
	STAILQ_INSERT_TAIL(q, r, link);
	if (t == NDIS_TASKQUEUE)
		s = ndis_tproc.np_state;
	else
		s = ndis_iproc.np_state;
	lwkt_reltoken(&ndis_thr_token);

	/*
	 * Post the job, but only if the thread is actually blocked
	 * on its own suspend call. If a driver queues up a job with
	 * NdisScheduleWorkItem() which happens to do a KeWaitForObject(),
	 * it may suspend there, and in that case we don't want to wake
	 * it up until KeWaitForObject() gets woken up on its own.
	 */
	if (s == NDIS_PSTATE_SLEEPING)
		ndis_thresume(td);

	return(0);
}

int
ndis_thsuspend(thread_t td, int timo)
{
	int			error;

	error = tsleep(td, 0, "ndissp", timo);
	return(error);
}

void
ndis_thresume(struct thread *td)
{
	wakeup(td);
}

__stdcall static void
ndis_sendrsrcavail_func(ndis_handle adapter)
{
	return;
}

__stdcall static void
ndis_status_func(ndis_handle adapter, ndis_status status, void *sbuf,
		 uint32_t slen)
{
	ndis_miniport_block	*block;
	block = adapter;

	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "status: %x\n", status);
	return;
}

__stdcall static void
ndis_statusdone_func(ndis_handle adapter)
{
	ndis_miniport_block	*block;
	block = adapter;
	
	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "status complete\n");
	return;
}

__stdcall static void
ndis_setdone_func(ndis_handle adapter, ndis_status status)
{
	ndis_miniport_block	*block;
	block = adapter;

	block->nmb_setstat = status;
	wakeup(&block->nmb_wkupdpctimer);
	return;
}

__stdcall static void
ndis_getdone_func(ndis_handle adapter, ndis_status status)
{
	ndis_miniport_block	*block;
	block = adapter;

	block->nmb_getstat = status;
	wakeup(&block->nmb_wkupdpctimer);
	return;
}

__stdcall static void
ndis_resetdone_func(ndis_handle adapter, ndis_status status,
		    uint8_t addressingreset)
{
	ndis_miniport_block	*block;
	block = adapter;

	if (block->nmb_ifp->if_flags & IFF_DEBUG)
		device_printf (block->nmb_dev, "reset done...\n");
	wakeup(block->nmb_ifp);
	return;
}

int
ndis_create_sysctls(void *arg)
{
	struct ndis_softc	*sc;
	ndis_cfg		*vals;
	char			buf[256];

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	vals = sc->ndis_regvals;

	TAILQ_INIT(&sc->ndis_cfglist_head);

#if __FreeBSD_version < 502113
	/* Create the sysctl tree. */

	sc->ndis_tree = SYSCTL_ADD_NODE(&sc->ndis_ctx,
	    SYSCTL_STATIC_CHILDREN(_hw), OID_AUTO,
	    device_get_nameunit(sc->ndis_dev), CTLFLAG_RD, 0,
	    device_get_desc(sc->ndis_dev));

#endif
	/* Add the driver-specific registry keys. */

	vals = sc->ndis_regvals;
	while(1) {
		if (vals->nc_cfgkey == NULL)
			break;
		if (vals->nc_idx != sc->ndis_devidx) {
			vals++;
			continue;
		}
#if 1
		SYSCTL_ADD_STRING(&sc->ndis_ctx,
		    SYSCTL_CHILDREN(sc->ndis_tree),
		    OID_AUTO, vals->nc_cfgkey,
		    CTLFLAG_RW, vals->nc_val,
		    sizeof(vals->nc_val),
		    vals->nc_cfgdesc);
#else
		SYSCTL_ADD_STRING(device_get_sysctl_ctx(sc->ndis_dev),
		    SYSCTL_CHILDREN(device_get_sysctl_tree(sc->ndis_dev)),
		    OID_AUTO, vals->nc_cfgkey,
		    CTLFLAG_RW, vals->nc_val,
		    sizeof(vals->nc_val),
		    vals->nc_cfgdesc);
#endif
		vals++;
	}

	/* Now add a couple of builtin keys. */

	/*
	 * Environment can be either Windows (0) or WindowsNT (1).
	 * We qualify as the latter.
	 */
	ndis_add_sysctl(sc, "Environment",
	    "Windows environment", "1", CTLFLAG_RD);

	/* NDIS version should be 5.1. */
	ndis_add_sysctl(sc, "NdisVersion",
	    "NDIS API Version", "0x00050001", CTLFLAG_RD);

	/* Bus type (PCI, PCMCIA, etc...) */
	ksprintf(buf, "%d", (int)sc->ndis_iftype);
	ndis_add_sysctl(sc, "BusType", "Bus Type", buf, CTLFLAG_RD);

	if (sc->ndis_res_io != NULL) {
		ksprintf(buf, "0x%lx", rman_get_start(sc->ndis_res_io));
		ndis_add_sysctl(sc, "IOBaseAddress",
		    "Base I/O Address", buf, CTLFLAG_RD);
	}

	if (sc->ndis_irq != NULL) {
		ksprintf(buf, "%lu", rman_get_start(sc->ndis_irq));
		ndis_add_sysctl(sc, "InterruptNumber",
		    "Interrupt Number", buf, CTLFLAG_RD);
	}

	return(0);
}

int
ndis_add_sysctl(void *arg, char *key, char *desc, char *val, int flag)
{
	struct ndis_softc	*sc;
	struct ndis_cfglist	*cfg;
	char			descstr[256];

	sc = arg;

	cfg = kmalloc(sizeof(struct ndis_cfglist), M_DEVBUF, M_WAITOK|M_ZERO);
	cfg->ndis_cfg.nc_cfgkey = kstrdup(key, M_DEVBUF);
	if (desc == NULL) {
		ksnprintf(descstr, sizeof(descstr), "%s (dynamic)", key);
		cfg->ndis_cfg.nc_cfgdesc = kstrdup(descstr, M_DEVBUF);
	} else
		cfg->ndis_cfg.nc_cfgdesc = kstrdup(desc, M_DEVBUF);
	strcpy(cfg->ndis_cfg.nc_val, val);

	TAILQ_INSERT_TAIL(&sc->ndis_cfglist_head, cfg, link);

#if 1
	SYSCTL_ADD_STRING(&sc->ndis_ctx, SYSCTL_CHILDREN(sc->ndis_tree),
	    OID_AUTO, cfg->ndis_cfg.nc_cfgkey, flag,
	    cfg->ndis_cfg.nc_val, sizeof(cfg->ndis_cfg.nc_val),
	    cfg->ndis_cfg.nc_cfgdesc);
#else
	SYSCTL_ADD_STRING(device_get_sysctl_ctx(sc->ndis_dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(sc->ndis_dev)),
	    OID_AUTO, cfg->ndis_cfg.nc_cfgkey, flag,
	    cfg->ndis_cfg.nc_val, sizeof(cfg->ndis_cfg.nc_val),
	    cfg->ndis_cfg.nc_cfgdesc);
#endif

	return(0);
}

int
ndis_flush_sysctls(void *arg)
{
	struct ndis_softc	*sc;
	struct ndis_cfglist	*cfg;

	sc = arg;

	while (!TAILQ_EMPTY(&sc->ndis_cfglist_head)) {
		cfg = TAILQ_FIRST(&sc->ndis_cfglist_head);
		TAILQ_REMOVE(&sc->ndis_cfglist_head, cfg, link);
		kfree(cfg->ndis_cfg.nc_cfgkey, M_DEVBUF);
		kfree(cfg->ndis_cfg.nc_cfgdesc, M_DEVBUF);
		kfree(cfg, M_DEVBUF);
	}

	return(0);
}

static void
ndis_return(void *arg)
{
	struct ndis_softc	*sc;
	ndis_return_handler	returnfunc;
	ndis_handle		adapter;
	ndis_packet		*p;
	uint8_t			irql;

	p = arg;
	sc = p->np_softc;
	adapter = sc->ndis_block.nmb_miniportadapterctx;

	if (adapter == NULL)
		return;

	returnfunc = sc->ndis_chars.nmc_return_packet_func;
	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	returnfunc(adapter, p);
	FASTCALL1(hal_lower_irql, irql);

	return;
}

static void
ndis_extref_packet(void *arg)
{
	ndis_packet	*p = arg;

	++p->np_refcnt;
}

static void
ndis_extfree_packet(void *arg)
{
	ndis_packet	*p = arg;

	if (p == NULL)
		return;

	/* Decrement refcount. */
	p->np_refcnt--;

	/* Release packet when refcount hits zero, otherwise return. */
	if (p->np_refcnt)
		return;

	ndis_sched(ndis_return, p, NDIS_SWI);

	return;
}

void
ndis_return_packet(struct ndis_softc *sc, ndis_packet *p)
{
	ndis_extfree_packet(p);
}

void
ndis_free_bufs(ndis_buffer *b0)
{
	ndis_buffer		*next;

	if (b0 == NULL)
		return;

	while(b0 != NULL) {
		next = b0->nb_next;
		kfree(b0, M_NDIS_BUFFER);
		b0 = next;
	}

	return;
}

void
ndis_free_packet(ndis_packet *p)
{
	if (p == NULL)
		return;

	ndis_free_bufs(p->np_private.npp_head);
	kfree(p, M_NDIS_PACKET);

	return;
}

int
ndis_convert_res(void *arg)
{
	struct ndis_softc	*sc;
	ndis_resource_list	*rl = NULL;
	cm_partial_resource_desc	*prd = NULL;
	ndis_miniport_block	*block;
	device_t		dev;
	struct resource_list	*brl;
	struct resource_list	brl_rev;
	struct resource_list_entry	*brle, *n;
	int 			error = 0;

	sc = arg;
	block = &sc->ndis_block;
	dev = sc->ndis_dev;

	SLIST_INIT(&brl_rev);

	rl = kmalloc(sizeof(ndis_resource_list) +
	    (sizeof(cm_partial_resource_desc) * (sc->ndis_rescnt - 1)),
	    M_DEVBUF, M_WAITOK|M_NULLOK|M_ZERO);

	if (rl == NULL)
		return(ENOMEM);

	rl->cprl_version = 5;
	rl->cprl_version = 1;
	rl->cprl_count = sc->ndis_rescnt;
	prd = rl->cprl_partial_descs;

	brl = BUS_GET_RESOURCE_LIST(dev, dev);

	if (brl != NULL) {

		/*
		 * We have a small problem. Some PCI devices have
		 * multiple I/O ranges. Windows orders them starting
		 * from lowest numbered BAR to highest. We discover
		 * them in that order too, but insert them into a singly
		 * linked list head first, which means when time comes
		 * to traverse the list, we enumerate them in reverse
		 * order. This screws up some drivers which expect the
		 * BARs to be in ascending order so that they can choose
		 * the "first" one as their register space. Unfortunately,
		 * in order to fix this, we have to create our own
		 * temporary list with the entries in reverse order.
		 */
		SLIST_FOREACH(brle, brl, link) {
			n = kmalloc(sizeof(struct resource_list_entry),
			    M_TEMP, M_WAITOK|M_NULLOK);
			if (n == NULL) {
				error = ENOMEM;
				goto bad;
			}
			bcopy((char *)brle, (char *)n,
			    sizeof(struct resource_list_entry));
			SLIST_INSERT_HEAD(&brl_rev, n, link);
		}

		SLIST_FOREACH(brle, &brl_rev, link) {
			switch (brle->type) {
			case SYS_RES_IOPORT:
				prd->cprd_type = CmResourceTypePort;
				prd->cprd_flags = CM_RESOURCE_PORT_IO;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_port.cprd_start.np_quad =
				    brle->start;
				prd->u.cprd_port.cprd_len = brle->count;
				break;
			case SYS_RES_MEMORY:
				prd->cprd_type = CmResourceTypeMemory;
				prd->cprd_flags =
				    CM_RESOURCE_MEMORY_READ_WRITE;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_port.cprd_start.np_quad =
				    brle->start;
				prd->u.cprd_port.cprd_len = brle->count;
				break;
			case SYS_RES_IRQ:
				prd->cprd_type = CmResourceTypeInterrupt;
				prd->cprd_flags = 0;
				prd->cprd_sharedisp =
				    CmResourceShareDeviceExclusive;
				prd->u.cprd_intr.cprd_level = brle->start;
				prd->u.cprd_intr.cprd_vector = brle->start;
				prd->u.cprd_intr.cprd_affinity = 0;
				break;
			default:
				break;
			}
			prd++;
		}
	}

	block->nmb_rlist = rl;

bad:

	while (!SLIST_EMPTY(&brl_rev)) {
		n = SLIST_FIRST(&brl_rev);
		SLIST_REMOVE_HEAD(&brl_rev, link);
		kfree (n, M_TEMP);
	}

	return(error);
}

/*
 * Map an NDIS packet to an mbuf list. When an NDIS driver receives a
 * packet, it will hand it to us in the form of an ndis_packet,
 * which we need to convert to an mbuf that is then handed off
 * to the stack. Note: we configure the mbuf list so that it uses
 * the memory regions specified by the ndis_buffer structures in
 * the ndis_packet as external storage. In most cases, this will
 * point to a memory region allocated by the driver (either by
 * ndis_malloc_withtag() or ndis_alloc_sharedmem()). We expect
 * the driver to handle free()ing this region for is, so we set up
 * a dummy no-op free handler for it.
 */ 

int
ndis_ptom(struct mbuf **m0, ndis_packet *p)
{
	struct mbuf		*m, *prev = NULL;
	ndis_buffer		*buf;
	ndis_packet_private	*priv;
	uint32_t		totlen = 0;

	if (p == NULL || m0 == NULL)
		return(EINVAL);

	priv = &p->np_private;
	buf = priv->npp_head;
	p->np_refcnt = 0;

	for (buf = priv->npp_head; buf != NULL; buf = buf->nb_next) {
		if (buf == priv->npp_head)
			MGETHDR(m, MB_DONTWAIT, MT_HEADER);
		else
			MGET(m, MB_DONTWAIT, MT_DATA);
		if (m == NULL) {
			m_freem(*m0);
			*m0 = NULL;
			return(ENOBUFS);
		}
		m->m_len = buf->nb_bytecount;
		m->m_data = MDL_VA(buf);
		m->m_ext.ext_free = ndis_extfree_packet;
		m->m_ext.ext_ref = ndis_extref_packet;
		m->m_ext.ext_arg = p;
		m->m_ext.ext_buf = m->m_data;
		m->m_ext.ext_size = m->m_len;
		m->m_flags |= M_EXT;
#if 0
		MEXTADD(m, m->m_data, m->m_len, ndis_free_packet,
		    p, 0, EXT_NDIS);
#endif
		p->np_refcnt++;
		totlen += m->m_len;
		if (m->m_flags & M_PKTHDR)
			*m0 = m;
		else
			prev->m_next = m;
		prev = m;
	}

	(*m0)->m_pkthdr.len = totlen;

	return(0);
}

/*
 * Create an mbuf chain from an NDIS packet chain.
 * This is used mainly when transmitting packets, where we need
 * to turn an mbuf off an interface's send queue and transform it
 * into an NDIS packet which will be fed into the NDIS driver's
 * send routine.
 *
 * NDIS packets consist of two parts: an ndis_packet structure,
 * which is vaguely analagous to the pkthdr portion of an mbuf,
 * and one or more ndis_buffer structures, which define the
 * actual memory segments in which the packet data resides.
 * We need to allocate one ndis_buffer for each mbuf in a chain,
 * plus one ndis_packet as the header.
 */

int
ndis_mtop(struct mbuf *m0, ndis_packet **p)
{
	struct mbuf		*m;
	ndis_buffer		*buf = NULL, *prev = NULL;
	ndis_packet_private	*priv;

	if (p == NULL || m0 == NULL)
		return(EINVAL);

	/* If caller didn't supply a packet, make one. */
	if (*p == NULL) {
		*p = kmalloc(sizeof(ndis_packet), M_NDIS_PACKET, M_NOWAIT|M_ZERO);
		if (*p == NULL)
			return(ENOMEM);
	}
	
	priv = &(*p)->np_private;
	priv->npp_totlen = m0->m_pkthdr.len;
        priv->npp_packetooboffset = offsetof(ndis_packet, np_oob);
	priv->npp_ndispktflags = NDIS_PACKET_ALLOCATED_BY_NDIS;

	for (m = m0; m != NULL; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		buf = kmalloc(sizeof(ndis_buffer), M_NDIS_BUFFER, M_NOWAIT|M_ZERO);
		if (buf == NULL) {
			ndis_free_packet(*p);
			*p = NULL;
			return(ENOMEM);
		}

		MDL_INIT(buf, m->m_data, m->m_len);
		if (priv->npp_head == NULL)
			priv->npp_head = buf;
		else
			prev->nb_next = buf;
		prev = buf;
	}

	priv->npp_tail = buf;
	priv->npp_totlen = m0->m_pkthdr.len;

	return(0);
}

int
ndis_get_supported_oids(void *arg, ndis_oid **oids, int *oidcnt)
{
	int			len, rval;
	ndis_oid		*o;

	if (arg == NULL || oids == NULL || oidcnt == NULL)
		return(EINVAL);
	len = 0;
	ndis_get_info(arg, OID_GEN_SUPPORTED_LIST, NULL, &len);

	o = kmalloc(len, M_DEVBUF, M_WAITOK);

	rval = ndis_get_info(arg, OID_GEN_SUPPORTED_LIST, o, &len);

	if (rval) {
		kfree(o, M_DEVBUF);
		return(rval);
	}

	*oids = o;
	*oidcnt = len / 4;

	return(0);
}

int
ndis_set_info(void *arg, ndis_oid oid, void *buf, int *buflen)
{
	struct ndis_softc	*sc;
	ndis_status		rval;
	ndis_handle		adapter;
	ndis_setinfo_handler	setfunc;
	uint32_t		byteswritten = 0, bytesneeded = 0;
	int			error;
	uint8_t			irql;

	sc = arg;
	setfunc = sc->ndis_chars.nmc_setinfo_func;
	adapter = sc->ndis_block.nmb_miniportadapterctx;

	if (adapter == NULL || setfunc == NULL)
		return(ENXIO);

	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	rval = setfunc(adapter, oid, buf, *buflen,
	    &byteswritten, &bytesneeded);
	FASTCALL1(hal_lower_irql, irql);

	if (rval == NDIS_STATUS_PENDING) {
		error = tsleep(&sc->ndis_block.nmb_wkupdpctimer,
		    0, "ndisset", 5 * hz);
		rval = sc->ndis_block.nmb_setstat;
	}

	if (byteswritten)
		*buflen = byteswritten;
	if (bytesneeded)
		*buflen = bytesneeded;

	if (rval == NDIS_STATUS_INVALID_LENGTH)
		return(ENOSPC);

	if (rval == NDIS_STATUS_INVALID_OID)
		return(EINVAL);

	if (rval == NDIS_STATUS_NOT_SUPPORTED ||
	    rval == NDIS_STATUS_NOT_ACCEPTED)
		return(ENOTSUP);

	if (rval != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	return(0);
}

typedef __stdcall void (*ndis_senddone_func)(ndis_handle, ndis_packet *, ndis_status);

int
ndis_send_packets(void *arg, ndis_packet **packets, int cnt)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_sendmulti_handler	sendfunc;
	ndis_senddone_func	senddonefunc;
	int			i;
	ndis_packet		*p;
	uint8_t			irql;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL)
		return(ENXIO);
	sendfunc = sc->ndis_chars.nmc_sendmulti_func;
	senddonefunc = sc->ndis_block.nmb_senddone_func;
	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	sendfunc(adapter, packets, cnt);
	FASTCALL1(hal_lower_irql, irql);

	for (i = 0; i < cnt; i++) {
		p = packets[i];
		/*
		 * Either the driver already handed the packet to
		 * ndis_txeof() due to a failure, or it wants to keep
		 * it and release it asynchronously later. Skip to the
		 * next one.
		 */
		if (p == NULL || p->np_oob.npo_status == NDIS_STATUS_PENDING)
			continue;
		senddonefunc(&sc->ndis_block, p, p->np_oob.npo_status);
	}

	return(0);
}

int
ndis_send_packet(void *arg, ndis_packet *packet)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_status		status;
	ndis_sendsingle_handler	sendfunc;
	ndis_senddone_func	senddonefunc;
	uint8_t			irql;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL)
		return(ENXIO);
	sendfunc = sc->ndis_chars.nmc_sendsingle_func;
	senddonefunc = sc->ndis_block.nmb_senddone_func;

	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	status = sendfunc(adapter, packet, packet->np_private.npp_flags);
	FASTCALL1(hal_lower_irql, irql);

	if (status == NDIS_STATUS_PENDING)
		return(0);

	senddonefunc(&sc->ndis_block, packet, status);

	return(0);
}

int
ndis_init_dma(void *arg)
{
	struct ndis_softc	*sc;
	int			i, error;

	sc = arg;

	sc->ndis_tmaps = kmalloc(sizeof(bus_dmamap_t) * sc->ndis_maxpkts,
	    M_DEVBUF, M_WAITOK|M_ZERO);

	for (i = 0; i < sc->ndis_maxpkts; i++) {
		error = bus_dmamap_create(sc->ndis_ttag, 0,
		    &sc->ndis_tmaps[i]);
		if (error) {
			kfree(sc->ndis_tmaps, M_DEVBUF);
			return(ENODEV);
		}
	}

	return(0);
}

int
ndis_destroy_dma(void *arg)
{
	struct ndis_softc	*sc;
	struct mbuf		*m;
	ndis_packet		*p = NULL;
	int			i;

	sc = arg;

	for (i = 0; i < sc->ndis_maxpkts; i++) {
		if (sc->ndis_txarray[i] != NULL) {
			p = sc->ndis_txarray[i];
			m = (struct mbuf *)p->np_rsvd[1];
			if (m != NULL)
				m_freem(m);
			ndis_free_packet(sc->ndis_txarray[i]);
		}
		bus_dmamap_destroy(sc->ndis_ttag, sc->ndis_tmaps[i]);
	}
	if (sc->ndis_tmaps)
		kfree(sc->ndis_tmaps, M_DEVBUF);
	bus_dma_tag_destroy(sc->ndis_ttag);

	return(0);
}

int
ndis_reset_nic(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_reset_handler	resetfunc;
	uint8_t			addressing_reset;
	int			rval;
	uint8_t			irql;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	resetfunc = sc->ndis_chars.nmc_reset_func;
	if (adapter == NULL || resetfunc == NULL)
		return(EIO);

	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	rval = resetfunc(&addressing_reset, adapter);
	FASTCALL1(hal_lower_irql, irql);

	if (rval == NDIS_STATUS_PENDING) {
		tsleep(sc, 0, "ndisrst", 0);
	}

	return(0);
}

int
ndis_halt_nic(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_halt_handler	haltfunc;

	sc = arg;

	adapter = sc->ndis_block.nmb_miniportadapterctx;
	if (adapter == NULL) {
		return(EIO);
	}

	/*
	 * The adapter context is only valid after the init
	 * handler has been called, and is invalid once the
	 * halt handler has been called.
	 */

	haltfunc = sc->ndis_chars.nmc_halt_func;

	haltfunc(adapter);

	sc->ndis_block.nmb_miniportadapterctx = NULL;

	return(0);
}

int
ndis_shutdown_nic(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_shutdown_handler	shutdownfunc;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	shutdownfunc = sc->ndis_chars.nmc_shutdown_handler;
	if (adapter == NULL || shutdownfunc == NULL)
		return(EIO);

	if (sc->ndis_chars.nmc_rsvd0 == NULL)
		shutdownfunc(adapter);
	else
		shutdownfunc(sc->ndis_chars.nmc_rsvd0);

	ndis_shrink_thrqueue(8);
	TAILQ_REMOVE(&ndis_devhead, &sc->ndis_block, link);

	return(0);
}

int
ndis_init_nic(void *arg)
{
	struct ndis_softc	*sc;
	ndis_miniport_block	*block;
        ndis_init_handler	initfunc;
	ndis_status		status, openstatus = 0;
	ndis_medium		mediumarray[NdisMediumMax];
	uint32_t		chosenmedium, i;

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	block = &sc->ndis_block;
	initfunc = sc->ndis_chars.nmc_init_func;

	TAILQ_INIT(&block->nmb_timerlist);

	for (i = 0; i < NdisMediumMax; i++)
		mediumarray[i] = i;

        status = initfunc(&openstatus, &chosenmedium,
            mediumarray, NdisMediumMax, block, block);

	/*
	 * If the init fails, blow away the other exported routines
	 * we obtained from the driver so we can't call them later.
	 * If the init failed, none of these will work.
	 */
	if (status != NDIS_STATUS_SUCCESS) {
		sc->ndis_block.nmb_miniportadapterctx = NULL;
		return(ENXIO);
	}

	return(0);
}

void
ndis_enable_intr(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_enable_interrupts_handler	intrenbfunc;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrenbfunc = sc->ndis_chars.nmc_enable_interrupts_func;
	if (adapter == NULL || intrenbfunc == NULL)
		return;
	intrenbfunc(adapter);

	return;
}

void
ndis_disable_intr(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_disable_interrupts_handler	intrdisfunc;

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrdisfunc = sc->ndis_chars.nmc_disable_interrupts_func;
	if (adapter == NULL || intrdisfunc == NULL)
	    return;
	intrdisfunc(adapter);

	return;
}

int
ndis_isr(void *arg, int *ourintr, int *callhandler)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_isr_handler	isrfunc;
	uint8_t			accepted, queue;

	if (arg == NULL || ourintr == NULL || callhandler == NULL)
		return(EINVAL);

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	isrfunc = sc->ndis_chars.nmc_isr_func;
	if (adapter == NULL || isrfunc == NULL)
		return(ENXIO);

	isrfunc(&accepted, &queue, adapter);
	*ourintr = accepted;
	*callhandler = queue;

	return(0);
}

int
ndis_intrhand(void *arg)
{
	struct ndis_softc	*sc;
	ndis_handle		adapter;
	ndis_interrupt_handler	intrfunc;

	if (arg == NULL)
		return(EINVAL);

	sc = arg;
	adapter = sc->ndis_block.nmb_miniportadapterctx;
	intrfunc = sc->ndis_chars.nmc_interrupt_func;
	if (adapter == NULL || intrfunc == NULL)
		return(EINVAL);

	intrfunc(adapter);

	return(0);
}

int
ndis_get_info(void *arg, ndis_oid oid, void *buf, int *buflen)
{
	struct ndis_softc	*sc;
	ndis_status		rval;
	ndis_handle		adapter;
	ndis_queryinfo_handler	queryfunc;
	uint32_t		byteswritten = 0, bytesneeded = 0;
	int			error;
	uint8_t			irql;

	sc = arg;
	queryfunc = sc->ndis_chars.nmc_queryinfo_func;
	adapter = sc->ndis_block.nmb_miniportadapterctx;

	if (adapter == NULL || queryfunc == NULL)
		return(ENXIO);

	irql = FASTCALL1(hal_raise_irql, DISPATCH_LEVEL);
	rval = queryfunc(adapter, oid, buf, *buflen,
	    &byteswritten, &bytesneeded);
	FASTCALL1(hal_lower_irql, irql);

	/* Wait for requests that block. */

	if (rval == NDIS_STATUS_PENDING) {
		error = tsleep(&sc->ndis_block.nmb_wkupdpctimer,
		    0, "ndisget", 5 * hz);
		rval = sc->ndis_block.nmb_getstat;
	}

	if (byteswritten)
		*buflen = byteswritten;
	if (bytesneeded)
		*buflen = bytesneeded;

	if (rval == NDIS_STATUS_INVALID_LENGTH ||
	    rval == NDIS_STATUS_BUFFER_TOO_SHORT)
		return(ENOSPC);

	if (rval == NDIS_STATUS_INVALID_OID)
		return(EINVAL);

	if (rval == NDIS_STATUS_NOT_SUPPORTED ||
	    rval == NDIS_STATUS_NOT_ACCEPTED)
		return(ENOTSUP);

	if (rval != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	return(0);
}

int
ndis_unload_driver(void *arg)
{
	struct ndis_softc	*sc;

	sc = arg;

	kfree(sc->ndis_block.nmb_rlist, M_DEVBUF);

	ndis_flush_sysctls(sc);

	ndis_shrink_thrqueue(8);
	TAILQ_REMOVE(&ndis_devhead, &sc->ndis_block, link);

	return(0);
}

#define NDIS_LOADED		htonl(0x42534F44)

int
ndis_load_driver(vm_offset_t img, void *arg)
{
	driver_entry		entry;
	image_optional_header	opt_hdr;
	image_import_descriptor imp_desc;
	ndis_unicode_string	dummystr;
        ndis_miniport_block     *block;
	ndis_status		status;
	int			idx;
	uint32_t		*ptr;
	struct ndis_softc	*sc;

	sc = arg;

	/*
	 * Only perform the relocation/linking phase once
	 * since the binary image may be shared among multiple
	 * device instances.
	 */

	ptr = (uint32_t *)(img + 8);
	if (*ptr != NDIS_LOADED) {
		/* Perform text relocation */
		if (pe_relocate(img))
			return(ENOEXEC);

		/* Dynamically link the NDIS.SYS routines -- required. */
		if (pe_patch_imports(img, "NDIS", ndis_functbl))
			return(ENOEXEC);

		/* Dynamically link the HAL.dll routines -- also required. */
		if (pe_patch_imports(img, "HAL", hal_functbl))
			return(ENOEXEC);

		/* Dynamically link ntoskrnl.exe -- optional. */
		if (pe_get_import_descriptor(img,
		    &imp_desc, "ntoskrnl") == 0) {
			if (pe_patch_imports(img,
			    "ntoskrnl", ntoskrnl_functbl))
				return(ENOEXEC);
		}
		*ptr = NDIS_LOADED;
	}

        /* Locate the driver entry point */
	pe_get_optional_header(img, &opt_hdr);
	entry = (driver_entry)pe_translate_addr(img, opt_hdr.ioh_entryaddr);

	dummystr.nus_len = strlen(NDIS_DUMMY_PATH) * 2;
	dummystr.nus_maxlen = strlen(NDIS_DUMMY_PATH) * 2;
	dummystr.nus_buf = NULL;
	ndis_ascii_to_unicode(NDIS_DUMMY_PATH, &dummystr.nus_buf);

	/*
	 * Now that we have the miniport driver characteristics,
	 * create an NDIS block and call the init handler.
	 * This will cause the driver to try to probe for
	 * a device.
	 */

	block = &sc->ndis_block;

	ptr = (uint32_t *)block;
	for (idx = 0; idx < sizeof(ndis_miniport_block) / 4; idx++) {
		*ptr = idx | 0xdead0000;
		ptr++;
	}

	block->nmb_signature = (void *)0xcafebabe;
	block->nmb_setdone_func = ndis_setdone_func;
	block->nmb_querydone_func = ndis_getdone_func;
	block->nmb_status_func = ndis_status_func;
	block->nmb_statusdone_func = ndis_statusdone_func;
	block->nmb_resetdone_func = ndis_resetdone_func;
	block->nmb_sendrsrc_func = ndis_sendrsrcavail_func;

	block->nmb_ifp = &sc->arpcom.ac_if;
	block->nmb_dev = sc->ndis_dev;
	block->nmb_img = img;
	block->nmb_devobj.do_rsvd = block;

	/*
	 * Now call the DriverEntry() routine. This will cause
	 * a callout to the NdisInitializeWrapper() and
	 * NdisMRegisterMiniport() routines.
	 */
	status = entry(&block->nmb_devobj, &dummystr);

	kfree (dummystr.nus_buf, M_DEVBUF);

	if (status != NDIS_STATUS_SUCCESS)
		return(ENODEV);

	ndis_enlarge_thrqueue(8);

	TAILQ_INSERT_TAIL(&ndis_devhead, block, link);

	return(0);
}

