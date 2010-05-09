/*
 * Copyright (c) 2009, 2010 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Alex Hornung <ahornung@gmail.com>
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
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/diskslice.h>
#include <sys/disk.h>
#include <sys/malloc.h>
#include <machine/md_var.h>
#include <sys/ctype.h>
#include <sys/syslog.h>
#include <sys/device.h>
#include <sys/msgport.h>
#include <sys/msgport2.h>
#include <sys/buf2.h>
#include <sys/dsched.h>
#include <sys/fcntl.h>
#include <machine/varargs.h>

MALLOC_DEFINE(M_DSCHED, "dsched", "dsched allocs");

static dsched_prepare_t		default_prepare;
static dsched_teardown_t	default_teardown;
static dsched_cancel_t		default_cancel;
static dsched_queue_t		default_queue;

static d_open_t      dsched_dev_open;
static d_close_t     dsched_dev_close;
static d_ioctl_t     dsched_dev_ioctl;

static int dsched_dev_list_disks(struct dsched_ioctl *data);
static int dsched_dev_list_disk(struct dsched_ioctl *data);
static int dsched_dev_list_policies(struct dsched_ioctl *data);
static int dsched_dev_handle_switch(char *disk, char *policy);

static void dsched_sysctl_add_disk(struct dsched_disk_ctx *diskctx, char *name);

static int	dsched_inited = 0;

struct lock	dsched_lock;
static int	dsched_debug_enable = 0;
static cdev_t	dsched_dev;

struct dsched_stats	dsched_stats;

struct objcache_malloc_args dsched_disk_ctx_malloc_args = {
	DSCHED_DISK_CTX_MAX_SZ, M_DSCHED };
struct objcache_malloc_args dsched_thread_io_malloc_args = {
	DSCHED_THREAD_IO_MAX_SZ, M_DSCHED };
struct objcache_malloc_args dsched_thread_ctx_malloc_args = {
	DSCHED_THREAD_CTX_MAX_SZ, M_DSCHED };

static struct objcache	*dsched_diskctx_cache;
static struct objcache	*dsched_tdctx_cache;
static struct objcache	*dsched_tdio_cache;

TAILQ_HEAD(, dsched_thread_ctx)	dsched_tdctx_list =
		TAILQ_HEAD_INITIALIZER(dsched_tdctx_list);

struct lock	dsched_tdctx_lock;

static struct dsched_policy_head dsched_policy_list =
		TAILQ_HEAD_INITIALIZER(dsched_policy_list);

static struct dsched_policy dsched_default_policy = {
	.name = "noop",

	.prepare = default_prepare,
	.teardown = default_teardown,
	.cancel_all = default_cancel,
	.bio_queue = default_queue
};

static struct dev_ops dsched_dev_ops = {
	{ "dsched", 0, 0 },
	.d_open = dsched_dev_open,
	.d_close = dsched_dev_close,
	.d_ioctl = dsched_dev_ioctl
};

/*
 * dsched_debug() is a SYSCTL and TUNABLE controlled debug output function
 * using kvprintf
 */
int
dsched_debug(int level, char *fmt, ...)
{
	__va_list ap;

	__va_start(ap, fmt);
	if (level <= dsched_debug_enable)
		kvprintf(fmt, ap);
	__va_end(ap);

	return 0;
}

/*
 * Called on disk_create()
 * tries to read which policy to use from loader.conf, if there's
 * none specified, the default policy is used.
 */
void
dsched_disk_create_callback(struct disk *dp, const char *head_name, int unit)
{
	char tunable_key[SPECNAMELEN + 48];
	char sched_policy[DSCHED_POLICY_NAME_LENGTH];
	struct dsched_policy *policy = NULL;

	/* Also look for serno stuff? */
	/* kprintf("dsched_disk_create_callback() for disk %s%d\n", head_name, unit); */
	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	ksnprintf(tunable_key, sizeof(tunable_key), "dsched.policy.%s%d",
	    head_name, unit);
	if (TUNABLE_STR_FETCH(tunable_key, sched_policy,
	    sizeof(sched_policy)) != 0) {
		policy = dsched_find_policy(sched_policy);
	}

	ksnprintf(tunable_key, sizeof(tunable_key), "dsched.policy.%s",
	    head_name);
	if (!policy && (TUNABLE_STR_FETCH(tunable_key, sched_policy,
	    sizeof(sched_policy)) != 0)) {
		policy = dsched_find_policy(sched_policy);
	}

	ksnprintf(tunable_key, sizeof(tunable_key), "dsched.policy.default");
	if (!policy && (TUNABLE_STR_FETCH(tunable_key, sched_policy,
	    sizeof(sched_policy)) != 0)) {
		policy = dsched_find_policy(sched_policy);
	}

	if (!policy) {
		dsched_debug(0, "No policy for %s%d specified, "
		    "or policy not found\n", head_name, unit);
		dsched_set_policy(dp, &dsched_default_policy);
	} else {
		dsched_set_policy(dp, policy);
	}

	ksnprintf(tunable_key, sizeof(tunable_key), "%s%d", head_name, unit);
	dsched_sysctl_add_disk(
	    (struct dsched_disk_ctx *)dsched_get_disk_priv(dp),
	    tunable_key);

	lockmgr(&dsched_lock, LK_RELEASE);
}

/*
 * Called from disk_setdiskinfo (or rather _setdiskinfo). This will check if
 * there's any policy associated with the serial number of the device.
 */
void
dsched_disk_update_callback(struct disk *dp, struct disk_info *info)
{
	char tunable_key[SPECNAMELEN + 48];
	char sched_policy[DSCHED_POLICY_NAME_LENGTH];
	struct dsched_policy *policy = NULL;

	if (info->d_serialno == NULL)
		return;

	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	ksnprintf(tunable_key, sizeof(tunable_key), "dsched.policy.%s",
	    info->d_serialno);

	if((TUNABLE_STR_FETCH(tunable_key, sched_policy,
	    sizeof(sched_policy)) != 0)) {
		policy = dsched_find_policy(sched_policy);	
	}

	if (policy) {
		dsched_switch(dp, policy);	
	}

	dsched_sysctl_add_disk(
	    (struct dsched_disk_ctx *)dsched_get_disk_priv(dp),
	    info->d_serialno);

	lockmgr(&dsched_lock, LK_RELEASE);
}

/*
 * Called on disk_destroy()
 * shuts down the scheduler core and cancels all remaining bios
 */
void
dsched_disk_destroy_callback(struct disk *dp)
{
	struct dsched_policy *old_policy;
	struct dsched_disk_ctx *diskctx;

	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	diskctx = dsched_get_disk_priv(dp);

	old_policy = dp->d_sched_policy;
	dp->d_sched_policy = &dsched_default_policy;
	old_policy->cancel_all(dsched_get_disk_priv(dp));
	old_policy->teardown(dsched_get_disk_priv(dp));

	if (diskctx->flags & DSCHED_SYSCTL_CTX_INITED)
		sysctl_ctx_free(&diskctx->sysctl_ctx);

	policy_destroy(dp);
	atomic_subtract_int(&old_policy->ref_count, 1);
	KKASSERT(old_policy->ref_count >= 0);

	lockmgr(&dsched_lock, LK_RELEASE);
}


void
dsched_queue(struct disk *dp, struct bio *bio)
{
	struct dsched_thread_ctx	*tdctx;
	struct dsched_thread_io		*tdio;
	struct dsched_disk_ctx		*diskctx;

	int found = 0, error = 0;

	tdctx = dsched_get_buf_priv(bio->bio_buf);
	if (tdctx == NULL) {
		/* We don't handle this case, let dsched dispatch */
		atomic_add_int(&dsched_stats.no_tdctx, 1);
		dsched_strategy_raw(dp, bio);
		return;
	}

	DSCHED_THREAD_CTX_LOCK(tdctx);

	KKASSERT(!TAILQ_EMPTY(&tdctx->tdio_list));
	TAILQ_FOREACH(tdio, &tdctx->tdio_list, link) {
		if (tdio->dp == dp) {
			dsched_thread_io_ref(tdio);
			found = 1;
			break;
		}
	}

	DSCHED_THREAD_CTX_UNLOCK(tdctx);
	dsched_clr_buf_priv(bio->bio_buf);
	dsched_thread_ctx_unref(tdctx); /* acquired on new_buf */

	KKASSERT(found == 1);
	diskctx = dsched_get_disk_priv(dp);
	dsched_disk_ctx_ref(diskctx);
	error = dp->d_sched_policy->bio_queue(diskctx, tdio, bio);

	if (error) {
		dsched_strategy_raw(dp, bio);
	}
	dsched_disk_ctx_unref(diskctx);
	dsched_thread_io_unref(tdio);
}


/*
 * Called from each module_init or module_attach of each policy
 * registers the policy in the local policy list.
 */
int
dsched_register(struct dsched_policy *d_policy)
{
	struct dsched_policy *policy;
	int error = 0;

	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	policy = dsched_find_policy(d_policy->name);

	if (!policy) {
		TAILQ_INSERT_TAIL(&dsched_policy_list, d_policy, link);
		atomic_add_int(&d_policy->ref_count, 1);
	} else {
		dsched_debug(LOG_ERR, "Policy with name %s already registered!\n",
		    d_policy->name);
		error = EEXIST;
	}

	lockmgr(&dsched_lock, LK_RELEASE);
	return error;
}

/*
 * Called from each module_detach of each policy
 * unregisters the policy
 */
int
dsched_unregister(struct dsched_policy *d_policy)
{
	struct dsched_policy *policy;

	lockmgr(&dsched_lock, LK_EXCLUSIVE);
	policy = dsched_find_policy(d_policy->name);

	if (policy) {
		if (policy->ref_count > 1) {
			lockmgr(&dsched_lock, LK_RELEASE);
			return EBUSY;
		}
		TAILQ_REMOVE(&dsched_policy_list, policy, link);
		atomic_subtract_int(&policy->ref_count, 1);
		KKASSERT(policy->ref_count == 0);
	}
	lockmgr(&dsched_lock, LK_RELEASE);
	return 0;
}


/*
 * switches the policy by first removing the old one and then
 * enabling the new one.
 */
int
dsched_switch(struct disk *dp, struct dsched_policy *new_policy)
{
	struct dsched_policy *old_policy;

	/* If we are asked to set the same policy, do nothing */
	if (dp->d_sched_policy == new_policy)
		return 0;

	/* lock everything down, diskwise */
	lockmgr(&dsched_lock, LK_EXCLUSIVE);
	old_policy = dp->d_sched_policy;

	atomic_subtract_int(&old_policy->ref_count, 1);
	KKASSERT(old_policy->ref_count >= 0);

	dp->d_sched_policy = &dsched_default_policy;
	old_policy->teardown(dsched_get_disk_priv(dp));
	policy_destroy(dp);

	/* Bring everything back to life */
	dsched_set_policy(dp, new_policy);
	lockmgr(&dsched_lock, LK_RELEASE);
	return 0;
}


/*
 * Loads a given policy and attaches it to the specified disk.
 * Also initializes the core for the policy
 */
void
dsched_set_policy(struct disk *dp, struct dsched_policy *new_policy)
{
	int locked = 0;

	/* Check if it is locked already. if not, we acquire the devfs lock */
	if (!(lockstatus(&dsched_lock, curthread)) == LK_EXCLUSIVE) {
		lockmgr(&dsched_lock, LK_EXCLUSIVE);
		locked = 1;
	}

	policy_new(dp, new_policy);
	new_policy->prepare(dsched_get_disk_priv(dp));
	dp->d_sched_policy = new_policy;
	atomic_add_int(&new_policy->ref_count, 1);
	kprintf("disk scheduler: set policy of %s to %s\n", dp->d_cdev->si_name,
	    new_policy->name);

	/* If we acquired the lock, we also get rid of it */
	if (locked)
		lockmgr(&dsched_lock, LK_RELEASE);
}

struct dsched_policy*
dsched_find_policy(char *search)
{
	struct dsched_policy *policy;
	struct dsched_policy *policy_found = NULL;
	int locked = 0;

	/* Check if it is locked already. if not, we acquire the devfs lock */
	if (!(lockstatus(&dsched_lock, curthread)) == LK_EXCLUSIVE) {
		lockmgr(&dsched_lock, LK_EXCLUSIVE);
		locked = 1;
	}

	TAILQ_FOREACH(policy, &dsched_policy_list, link) {
		if (!strcmp(policy->name, search)) {
			policy_found = policy;
			break;
		}
	}

	/* If we acquired the lock, we also get rid of it */
	if (locked)
		lockmgr(&dsched_lock, LK_RELEASE);

	return policy_found;
}

struct disk*
dsched_find_disk(char *search)
{
	struct disk *dp_found = NULL;
	struct disk *dp = NULL;

	while((dp = disk_enumerate(dp))) {
		if (!strcmp(dp->d_cdev->si_name, search)) {
			dp_found = dp;
			break;
		}
	}

	return dp_found;
}

struct disk*
dsched_disk_enumerate(struct disk *dp, struct dsched_policy *policy)
{
	while ((dp = disk_enumerate(dp))) {
		if (dp->d_sched_policy == policy)
			return dp;
	}

	return NULL;
}

struct dsched_policy *
dsched_policy_enumerate(struct dsched_policy *pol)
{
	if (!pol)
		return (TAILQ_FIRST(&dsched_policy_list));
	else
		return (TAILQ_NEXT(pol, link));
}

void
dsched_cancel_bio(struct bio *bp)
{
	bp->bio_buf->b_error = ENXIO;
	bp->bio_buf->b_flags |= B_ERROR;
	bp->bio_buf->b_resid = bp->bio_buf->b_bcount;

	biodone(bp);
}

void
dsched_strategy_raw(struct disk *dp, struct bio *bp)
{
	/*
	 * Ideally, this stuff shouldn't be needed... but just in case, we leave it in
	 * to avoid panics
	 */
	KASSERT(dp->d_rawdev != NULL, ("dsched_strategy_raw sees NULL d_rawdev!!"));
	if(bp->bio_track != NULL) {
		dsched_debug(LOG_INFO,
		    "dsched_strategy_raw sees non-NULL bio_track!! "
		    "bio: %p\n", bp);
		bp->bio_track = NULL;
	}
	dev_dstrategy(dp->d_rawdev, bp);
}

void
dsched_strategy_sync(struct disk *dp, struct bio *bio)
{
	struct buf *bp, *nbp;
	struct bio *nbio;

	bp = bio->bio_buf;

	nbp = getpbuf(NULL);
	nbio = &nbp->b_bio1;

	nbp->b_cmd = bp->b_cmd;
	nbp->b_bufsize = bp->b_bufsize;
	nbp->b_runningbufspace = bp->b_runningbufspace;
	nbp->b_bcount = bp->b_bcount;
	nbp->b_resid = bp->b_resid;
	nbp->b_data = bp->b_data;
	nbp->b_kvabase = bp->b_kvabase;
	nbp->b_kvasize = bp->b_kvasize;
	nbp->b_dirtyend = bp->b_dirtyend;

	nbio->bio_done = biodone_sync;
	nbio->bio_flags |= BIO_SYNC;
	nbio->bio_track = NULL;

	nbio->bio_caller_info1.ptr = dp;
	nbio->bio_offset = bio->bio_offset;

	dev_dstrategy(dp->d_rawdev, nbio);
	biowait(nbio, "dschedsync");
	bp->b_resid = nbp->b_resid;
	bp->b_error = nbp->b_error;
	biodone(bio);
	relpbuf(nbp, NULL);
}

void
dsched_strategy_async(struct disk *dp, struct bio *bio, biodone_t *done, void *priv)
{
	struct bio *nbio;

	nbio = push_bio(bio);
	nbio->bio_done = done;
	nbio->bio_offset = bio->bio_offset;

	dsched_set_bio_dp(nbio, dp);
	dsched_set_bio_priv(nbio, priv);

	getmicrotime(&nbio->bio_caller_info3.tv);
	dev_dstrategy(dp->d_rawdev, nbio);
}

void
dsched_disk_ctx_ref(struct dsched_disk_ctx *diskctx)
{
	int refcount;

	refcount = atomic_fetchadd_int(&diskctx->refcount, 1);

	KKASSERT(refcount >= 0);
}

void
dsched_thread_io_ref(struct dsched_thread_io *tdio)
{
	int refcount;

	refcount = atomic_fetchadd_int(&tdio->refcount, 1);

	KKASSERT(refcount >= 0);
}

void
dsched_thread_ctx_ref(struct dsched_thread_ctx *tdctx)
{
	int refcount;

	refcount = atomic_fetchadd_int(&tdctx->refcount, 1);

	KKASSERT(refcount >= 0);
}

void
dsched_disk_ctx_unref(struct dsched_disk_ctx *diskctx)
{
	struct dsched_thread_io	*tdio, *tdio2;
	int refcount;

	refcount = atomic_fetchadd_int(&diskctx->refcount, -1);


	KKASSERT(refcount >= 0 || refcount <= -0x400);

	if (refcount == 1) {
		atomic_subtract_int(&diskctx->refcount, 0x400); /* mark as: in destruction */
#if 0
		kprintf("diskctx (%p) destruction started, trace:\n", diskctx);
		print_backtrace(4);
#endif
		lockmgr(&diskctx->lock, LK_EXCLUSIVE);
		TAILQ_FOREACH_MUTABLE(tdio, &diskctx->tdio_list, dlink, tdio2) {
			TAILQ_REMOVE(&diskctx->tdio_list, tdio, dlink);
			tdio->flags &= ~DSCHED_LINKED_DISK_CTX;
			dsched_thread_io_unref(tdio);
		}
		lockmgr(&diskctx->lock, LK_RELEASE);
		if (diskctx->dp->d_sched_policy->destroy_diskctx)
			diskctx->dp->d_sched_policy->destroy_diskctx(diskctx);
		objcache_put(dsched_diskctx_cache, diskctx);
		atomic_subtract_int(&dsched_stats.diskctx_allocations, 1);
	}
}

void
dsched_thread_io_unref(struct dsched_thread_io *tdio)
{
	struct dsched_thread_ctx	*tdctx;
	struct dsched_disk_ctx	*diskctx;
	int refcount;

	refcount = atomic_fetchadd_int(&tdio->refcount, -1);

	KKASSERT(refcount >= 0 || refcount <= -0x400);

	if (refcount == 1) {
		atomic_subtract_int(&tdio->refcount, 0x400); /* mark as: in destruction */
#if 0
		kprintf("tdio (%p) destruction started, trace:\n", tdio);
		print_backtrace(8);
#endif
		diskctx = tdio->diskctx;
		KKASSERT(diskctx != NULL);
		KKASSERT(tdio->qlength == 0);

		if (tdio->flags & DSCHED_LINKED_DISK_CTX) {
			lockmgr(&diskctx->lock, LK_EXCLUSIVE);

			TAILQ_REMOVE(&diskctx->tdio_list, tdio, dlink);
			tdio->flags &= ~DSCHED_LINKED_DISK_CTX;

			lockmgr(&diskctx->lock, LK_RELEASE);
		}

		if (tdio->flags & DSCHED_LINKED_THREAD_CTX) {
			tdctx = tdio->tdctx;
			KKASSERT(tdctx != NULL);

			lockmgr(&tdctx->lock, LK_EXCLUSIVE);

			TAILQ_REMOVE(&tdctx->tdio_list, tdio, link);
			tdio->flags &= ~DSCHED_LINKED_THREAD_CTX;

			lockmgr(&tdctx->lock, LK_RELEASE);
		}
		if (tdio->diskctx->dp->d_sched_policy->destroy_tdio)
			tdio->diskctx->dp->d_sched_policy->destroy_tdio(tdio);
		objcache_put(dsched_tdio_cache, tdio);
		atomic_subtract_int(&dsched_stats.tdio_allocations, 1);
#if 0
		dsched_disk_ctx_unref(diskctx);
#endif
	}
}

void
dsched_thread_ctx_unref(struct dsched_thread_ctx *tdctx)
{
	struct dsched_thread_io	*tdio, *tdio2;
	int refcount;

	refcount = atomic_fetchadd_int(&tdctx->refcount, -1);

	KKASSERT(refcount >= 0 || refcount <= -0x400);

	if (refcount == 1) {
		atomic_subtract_int(&tdctx->refcount, 0x400); /* mark as: in destruction */
#if 0
		kprintf("tdctx (%p) destruction started, trace:\n", tdctx);
		print_backtrace(8);
#endif
		DSCHED_GLOBAL_THREAD_CTX_LOCK();

		TAILQ_FOREACH_MUTABLE(tdio, &tdctx->tdio_list, link, tdio2) {
			TAILQ_REMOVE(&tdctx->tdio_list, tdio, link);
			tdio->flags &= ~DSCHED_LINKED_THREAD_CTX;
			dsched_thread_io_unref(tdio);
		}
		TAILQ_REMOVE(&dsched_tdctx_list, tdctx, link);

		DSCHED_GLOBAL_THREAD_CTX_UNLOCK();

		objcache_put(dsched_tdctx_cache, tdctx);
		atomic_subtract_int(&dsched_stats.tdctx_allocations, 1);
	}
}


struct dsched_thread_io *
dsched_thread_io_alloc(struct disk *dp, struct dsched_thread_ctx *tdctx,
    struct dsched_policy *pol)
{
	struct dsched_thread_io	*tdio;
#if 0
	dsched_disk_ctx_ref(dsched_get_disk_priv(dp));
#endif
	tdio = objcache_get(dsched_tdio_cache, M_WAITOK);
	bzero(tdio, DSCHED_THREAD_IO_MAX_SZ);

	/* XXX: maybe we do need another ref for the disk list for tdio */
	dsched_thread_io_ref(tdio);

	DSCHED_THREAD_IO_LOCKINIT(tdio);
	tdio->dp = dp;

	tdio->diskctx = dsched_get_disk_priv(dp);
	TAILQ_INIT(&tdio->queue);

	if (pol->new_tdio)
		pol->new_tdio(tdio);

	TAILQ_INSERT_TAIL(&tdio->diskctx->tdio_list, tdio, dlink);
	tdio->flags |= DSCHED_LINKED_DISK_CTX;

	if (tdctx) {
		tdio->tdctx = tdctx;
		tdio->p = tdctx->p;

		/* Put the tdio in the tdctx list */
		DSCHED_THREAD_CTX_LOCK(tdctx);
		TAILQ_INSERT_TAIL(&tdctx->tdio_list, tdio, link);
		DSCHED_THREAD_CTX_UNLOCK(tdctx);
		tdio->flags |= DSCHED_LINKED_THREAD_CTX;
	}

	atomic_add_int(&dsched_stats.tdio_allocations, 1);
	return tdio;
}


struct dsched_disk_ctx *
dsched_disk_ctx_alloc(struct disk *dp, struct dsched_policy *pol)
{
	struct dsched_disk_ctx *diskctx;

	diskctx = objcache_get(dsched_diskctx_cache, M_WAITOK);
	bzero(diskctx, DSCHED_DISK_CTX_MAX_SZ);
	dsched_disk_ctx_ref(diskctx);
	diskctx->dp = dp;
	DSCHED_DISK_CTX_LOCKINIT(diskctx);
	TAILQ_INIT(&diskctx->tdio_list);

	atomic_add_int(&dsched_stats.diskctx_allocations, 1);
	if (pol->new_diskctx)
		pol->new_diskctx(diskctx);
	return diskctx;
}


struct dsched_thread_ctx *
dsched_thread_ctx_alloc(struct proc *p)
{
	struct dsched_thread_ctx	*tdctx;
	struct dsched_thread_io	*tdio;
	struct disk	*dp = NULL;

	tdctx = objcache_get(dsched_tdctx_cache, M_WAITOK);
	bzero(tdctx, DSCHED_THREAD_CTX_MAX_SZ);
	dsched_thread_ctx_ref(tdctx);
#if 0
	kprintf("dsched_thread_ctx_alloc, new tdctx = %p\n", tdctx);
#endif
	DSCHED_THREAD_CTX_LOCKINIT(tdctx);
	TAILQ_INIT(&tdctx->tdio_list);
	tdctx->p = p;

	/* XXX */
	while ((dp = disk_enumerate(dp))) {
		tdio = dsched_thread_io_alloc(dp, tdctx, dp->d_sched_policy);
	}

	DSCHED_GLOBAL_THREAD_CTX_LOCK();
	TAILQ_INSERT_TAIL(&dsched_tdctx_list, tdctx, link);
	DSCHED_GLOBAL_THREAD_CTX_UNLOCK();

	atomic_add_int(&dsched_stats.tdctx_allocations, 1);
	/* XXX: no callback here */
	return tdctx;
}

void
policy_new(struct disk *dp, struct dsched_policy *pol) {
	struct dsched_thread_ctx *tdctx;
	struct dsched_disk_ctx *diskctx;
	struct dsched_thread_io *tdio;

	diskctx = dsched_disk_ctx_alloc(dp, pol);
	dsched_disk_ctx_ref(diskctx);
	dsched_set_disk_priv(dp, diskctx);

	DSCHED_GLOBAL_THREAD_CTX_LOCK();
	TAILQ_FOREACH(tdctx, &dsched_tdctx_list, link) {
		tdio = dsched_thread_io_alloc(dp, tdctx, pol);
	}
	DSCHED_GLOBAL_THREAD_CTX_UNLOCK();

}

void
policy_destroy(struct disk *dp) {
	struct dsched_disk_ctx *diskctx;

	diskctx = dsched_get_disk_priv(dp);
	KKASSERT(diskctx != NULL);

	dsched_disk_ctx_unref(diskctx); /* from prepare */
	dsched_disk_ctx_unref(diskctx); /* from alloc */

	dsched_set_disk_priv(dp, NULL);
}

void
dsched_new_buf(struct buf *bp)
{
	struct dsched_thread_ctx	*tdctx = NULL;

	if (dsched_inited == 0)
		return;

	if (curproc != NULL) {
		tdctx = dsched_get_proc_priv(curproc);
	} else {
		/* This is a kernel thread, so no proc info is available */
		tdctx = dsched_get_thread_priv(curthread);
	}

#if 0
	/*
	 * XXX: hack. we don't want this assert because we aren't catching all
	 *	threads. mi_startup() is still getting away without an tdctx.
	 */

	/* by now we should have an tdctx. if not, something bad is going on */
	KKASSERT(tdctx != NULL);
#endif

	if (tdctx) {
		dsched_thread_ctx_ref(tdctx);
	}
	dsched_set_buf_priv(bp, tdctx);
}

void
dsched_exit_buf(struct buf *bp)
{
	struct dsched_thread_ctx	*tdctx;

	tdctx = dsched_get_buf_priv(bp);
	if (tdctx != NULL) {
		dsched_clr_buf_priv(bp);
		dsched_thread_ctx_unref(tdctx);
	}
}

void
dsched_new_proc(struct proc *p)
{
	struct dsched_thread_ctx	*tdctx;

	if (dsched_inited == 0)
		return;

	KKASSERT(p != NULL);

	tdctx = dsched_thread_ctx_alloc(p);
	tdctx->p = p;
	dsched_thread_ctx_ref(tdctx);

	dsched_set_proc_priv(p, tdctx);
	atomic_add_int(&dsched_stats.nprocs, 1);
}


void
dsched_new_thread(struct thread *td)
{
	struct dsched_thread_ctx	*tdctx;

	if (dsched_inited == 0)
		return;

	KKASSERT(td != NULL);

	tdctx = dsched_thread_ctx_alloc(NULL);
	tdctx->td = td;
	dsched_thread_ctx_ref(tdctx);

	dsched_set_thread_priv(td, tdctx);
	atomic_add_int(&dsched_stats.nthreads, 1);
}

void
dsched_exit_proc(struct proc *p)
{
	struct dsched_thread_ctx	*tdctx;

	if (dsched_inited == 0)
		return;

	KKASSERT(p != NULL);

	tdctx = dsched_get_proc_priv(p);
	KKASSERT(tdctx != NULL);

	tdctx->dead = 0xDEAD;
	dsched_set_proc_priv(p, 0);

	dsched_thread_ctx_unref(tdctx); /* one for alloc, */
	dsched_thread_ctx_unref(tdctx); /* one for ref */
	atomic_subtract_int(&dsched_stats.nprocs, 1);
}


void
dsched_exit_thread(struct thread *td)
{
	struct dsched_thread_ctx	*tdctx;

	if (dsched_inited == 0)
		return;

	KKASSERT(td != NULL);

	tdctx = dsched_get_thread_priv(td);
	KKASSERT(tdctx != NULL);

	tdctx->dead = 0xDEAD;
	dsched_set_thread_priv(td, 0);

	dsched_thread_ctx_unref(tdctx); /* one for alloc, */
	dsched_thread_ctx_unref(tdctx); /* one for ref */
	atomic_subtract_int(&dsched_stats.nthreads, 1);
}

/* DEFAULT NOOP POLICY */

static int
default_prepare(struct dsched_disk_ctx *diskctx)
{
	return 0;
}

static void
default_teardown(struct dsched_disk_ctx *diskctx)
{

}

static void
default_cancel(struct dsched_disk_ctx *diskctx)
{

}

static int
default_queue(struct dsched_disk_ctx *diskctx, struct dsched_thread_io *tdio,
    struct bio *bio)
{
	dsched_strategy_raw(diskctx->dp, bio);
#if 0
	dsched_strategy_async(diskctx->dp, bio, default_completed, NULL);
#endif
	return 0;
}


/*
 * dsched device stuff
 */

static int
dsched_dev_list_disks(struct dsched_ioctl *data)
{
	struct disk *dp = NULL;
	uint32_t i;

	for (i = 0; (i <= data->num_elem) && (dp = disk_enumerate(dp)); i++);

	if (dp == NULL)
		return -1;

	strncpy(data->dev_name, dp->d_cdev->si_name, sizeof(data->dev_name));

	if (dp->d_sched_policy) {
		strncpy(data->pol_name, dp->d_sched_policy->name,
		    sizeof(data->pol_name));
	} else {
		strncpy(data->pol_name, "N/A (error)", 12);
	}

	return 0;
}

static int
dsched_dev_list_disk(struct dsched_ioctl *data)
{
	struct disk *dp = NULL;
	int found = 0;

	while ((dp = disk_enumerate(dp))) {
		if (!strncmp(dp->d_cdev->si_name, data->dev_name,
		    sizeof(data->dev_name))) {
			KKASSERT(dp->d_sched_policy != NULL);

			found = 1;
			strncpy(data->pol_name, dp->d_sched_policy->name,
			    sizeof(data->pol_name));
			break;
		}
	}
	if (!found)
		return -1;

	return 0;
}

static int
dsched_dev_list_policies(struct dsched_ioctl *data)
{
	struct dsched_policy *pol = NULL;
	uint32_t i;

	for (i = 0; (i <= data->num_elem) && (pol = dsched_policy_enumerate(pol)); i++);

	if (pol == NULL)
		return -1;

	strncpy(data->pol_name, pol->name, sizeof(data->pol_name));
	return 0;
}

static int
dsched_dev_handle_switch(char *disk, char *policy)
{
	struct disk *dp;
	struct dsched_policy *pol;

	dp = dsched_find_disk(disk);
	pol = dsched_find_policy(policy);

	if ((dp == NULL) || (pol == NULL))
		return -1;

	return (dsched_switch(dp, pol));
}

static int
dsched_dev_open(struct dev_open_args *ap)
{
	/*
	 * Only allow read-write access.
	 */
	if (((ap->a_oflags & FWRITE) == 0) || ((ap->a_oflags & FREAD) == 0))
		return(EPERM);

	/*
	 * We don't allow nonblocking access.
	 */
	if ((ap->a_oflags & O_NONBLOCK) != 0) {
		kprintf("dsched_dev: can't do nonblocking access\n");
		return(ENODEV);
	}

	return 0;
}

static int
dsched_dev_close(struct dev_close_args *ap)
{
	return 0;
}

static int
dsched_dev_ioctl(struct dev_ioctl_args *ap)
{
	int error;
	struct dsched_ioctl *data;

	error = 0;
	data = (struct dsched_ioctl *)ap->a_data;

	switch(ap->a_cmd) {
	case DSCHED_SET_DEVICE_POLICY:
		if (dsched_dev_handle_switch(data->dev_name, data->pol_name))
			error = ENOENT; /* No such file or directory */
		break;

	case DSCHED_LIST_DISK:
		if (dsched_dev_list_disk(data) != 0) {
			error = EINVAL; /* Invalid argument */
		}
		break;

	case DSCHED_LIST_DISKS:
		if (dsched_dev_list_disks(data) != 0) {
			error = EINVAL; /* Invalid argument */
		}
		break;

	case DSCHED_LIST_POLICIES:
		if (dsched_dev_list_policies(data) != 0) {
			error = EINVAL; /* Invalid argument */
		}
		break;


	default:
		error = ENOTTY; /* Inappropriate ioctl for device */
		break;
	}

	return(error);
}






/*
 * SYSINIT stuff
 */


static void
dsched_init(void)
{
	dsched_tdio_cache = objcache_create("dsched-tdio-cache", 0, 0,
					   NULL, NULL, NULL,
					   objcache_malloc_alloc,
					   objcache_malloc_free,
					   &dsched_thread_io_malloc_args );

	dsched_tdctx_cache = objcache_create("dsched-tdctx-cache", 0, 0,
					   NULL, NULL, NULL,
					   objcache_malloc_alloc,
					   objcache_malloc_free,
					   &dsched_thread_ctx_malloc_args );

	dsched_diskctx_cache = objcache_create("dsched-diskctx-cache", 0, 0,
					   NULL, NULL, NULL,
					   objcache_malloc_alloc,
					   objcache_malloc_free,
					   &dsched_disk_ctx_malloc_args );

	bzero(&dsched_stats, sizeof(struct dsched_stats));

	lockinit(&dsched_lock, "dsched lock", 0, LK_CANRECURSE);
	DSCHED_GLOBAL_THREAD_CTX_LOCKINIT();

	dsched_register(&dsched_default_policy);

	dsched_inited = 1;
}

static void
dsched_uninit(void)
{
}

static void
dsched_dev_init(void)
{
	dsched_dev = make_dev(&dsched_dev_ops,
            0,
            UID_ROOT,
            GID_WHEEL,
            0600,
            "dsched");
}

static void
dsched_dev_uninit(void)
{
	destroy_dev(dsched_dev);
}

SYSINIT(subr_dsched_register, SI_SUB_CREATE_INIT-1, SI_ORDER_FIRST, dsched_init, NULL);
SYSUNINIT(subr_dsched_register, SI_SUB_CREATE_INIT-1, SI_ORDER_ANY, dsched_uninit, NULL);
SYSINIT(subr_dsched_dev_register, SI_SUB_DRIVERS, SI_ORDER_ANY, dsched_dev_init, NULL);
SYSUNINIT(subr_dsched_dev_register, SI_SUB_DRIVERS, SI_ORDER_ANY, dsched_dev_uninit, NULL);

/*
 * SYSCTL stuff
 */
static int
sysctl_dsched_stats(SYSCTL_HANDLER_ARGS)
{
	return (sysctl_handle_opaque(oidp, &dsched_stats, sizeof(struct dsched_stats), req));
}

static int
sysctl_dsched_list_policies(SYSCTL_HANDLER_ARGS)
{
	struct dsched_policy *pol = NULL;
	int error, first = 1;

	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	while ((pol = dsched_policy_enumerate(pol))) {
		if (!first) {
			error = SYSCTL_OUT(req, " ", 1);
			if (error)
				break;
		} else {
			first = 0;
		}
		error = SYSCTL_OUT(req, pol->name, strlen(pol->name));
		if (error)
			break;

	}

	lockmgr(&dsched_lock, LK_RELEASE);

	error = SYSCTL_OUT(req, "", 1);
	
	return error;
}

static int
sysctl_dsched_policy(SYSCTL_HANDLER_ARGS)
{
	char buf[DSCHED_POLICY_NAME_LENGTH];
	struct dsched_disk_ctx *diskctx = arg1;
	struct dsched_policy *pol = NULL;
	int error;

	if (diskctx == NULL) {
		return 0;
	}

	lockmgr(&dsched_lock, LK_EXCLUSIVE);

	pol = diskctx->dp->d_sched_policy;
	memcpy(buf, pol->name, DSCHED_POLICY_NAME_LENGTH);

	error = sysctl_handle_string(oidp, buf, DSCHED_POLICY_NAME_LENGTH, req);
	if (error || req->newptr == NULL) {
		lockmgr(&dsched_lock, LK_RELEASE);
		return (error);
	}

	pol = dsched_find_policy(buf);
	if (pol == NULL) {
		lockmgr(&dsched_lock, LK_RELEASE);
		return 0;
	}

	dsched_switch(diskctx->dp, pol);

	lockmgr(&dsched_lock, LK_RELEASE);

	return error;
}

SYSCTL_NODE(, OID_AUTO, dsched, CTLFLAG_RD, NULL,
    "Disk Scheduler Framework (dsched) magic");
SYSCTL_NODE(_dsched, OID_AUTO, policy, CTLFLAG_RW, NULL,
    "List of disks and their policies");
SYSCTL_INT(_dsched, OID_AUTO, debug, CTLFLAG_RW, &dsched_debug_enable,
    0, "Enable dsched debugging");
SYSCTL_PROC(_dsched, OID_AUTO, stats, CTLTYPE_OPAQUE|CTLFLAG_RD,
    0, sizeof(struct dsched_stats), sysctl_dsched_stats, "dsched_stats",
    "dsched statistics");
SYSCTL_PROC(_dsched, OID_AUTO, policies, CTLTYPE_STRING|CTLFLAG_RD,
    NULL, 0, sysctl_dsched_list_policies, "A", "names of available policies");

static void
dsched_sysctl_add_disk(struct dsched_disk_ctx *diskctx, char *name)
{
	if (!(diskctx->flags & DSCHED_SYSCTL_CTX_INITED)) {
		diskctx->flags |= DSCHED_SYSCTL_CTX_INITED;
		sysctl_ctx_init(&diskctx->sysctl_ctx);
	}

	SYSCTL_ADD_PROC(&diskctx->sysctl_ctx, SYSCTL_STATIC_CHILDREN(_dsched_policy),
	    OID_AUTO, name, CTLTYPE_STRING|CTLFLAG_RW,
	    diskctx, 0, sysctl_dsched_policy, "A", "policy");
}
