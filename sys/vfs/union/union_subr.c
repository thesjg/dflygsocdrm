/*
 * Copyright (c) 1994 Jan-Simon Pendry
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)union_subr.c	8.20 (Berkeley) 5/20/95
 * $FreeBSD: src/sys/miscfs/union/union_subr.c,v 1.43.2.2 2001/12/25 01:44:45 dillon Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>	/* for vnode_pager_setsize */
#include <vm/vm_zone.h>
#include <vm/vm_object.h>	/* for vm cache coherency */
#include "union.h"

extern int	union_init (void);

/* must be power of two, otherwise change UNION_HASH() */
#define NHASH 32

/* unsigned int ... */
#define UNION_HASH(u, l) \
	(((((uintptr_t) (u)) + ((uintptr_t) l)) >> 8) & (NHASH-1))

static LIST_HEAD(unhead, union_node) unhead[NHASH];
static int unvplock[NHASH];

static void	union_dircache_r (struct vnode *vp, struct vnode ***vppp,
				      int *cntp);
static int	union_list_lock (int ix);
static void	union_list_unlock (int ix);
static int	union_relookup (struct union_mount *um, struct vnode *dvp,
				    struct vnode **vpp,
				    struct componentname *cnp,
				    struct componentname *cn, char *path,
				    int pathlen);
static void	union_updatevp (struct union_node *un,
				    struct vnode *uppervp,
				    struct vnode *lowervp);
static void union_newlower (struct union_node *, struct vnode *);
static void union_newupper (struct union_node *, struct vnode *);
static int union_copyfile (struct vnode *, struct vnode *,
					struct ucred *, struct thread *);
static int union_vn_create (struct vnode **, struct union_node *,
				struct thread *);
static int union_vn_close (struct vnode *, int, struct ucred *);

int
union_init(void)
{
	int i;

	for (i = 0; i < NHASH; i++)
		LIST_INIT(&unhead[i]);
	bzero((caddr_t)unvplock, sizeof(unvplock));
	return (0);
}

static int
union_list_lock(int ix)
{
	if (unvplock[ix] & UNVP_LOCKED) {
		unvplock[ix] |= UNVP_WANT;
		(void) tsleep((caddr_t) &unvplock[ix], 0, "unllck", 0);
		return (1);
	}
	unvplock[ix] |= UNVP_LOCKED;
	return (0);
}

static void
union_list_unlock(int ix)
{
	unvplock[ix] &= ~UNVP_LOCKED;

	if (unvplock[ix] & UNVP_WANT) {
		unvplock[ix] &= ~UNVP_WANT;
		wakeup((caddr_t) &unvplock[ix]);
	}
}

/*
 *	union_updatevp:
 *
 *	The uppervp, if not NULL, must be referenced and not locked by us
 *	The lowervp, if not NULL, must be referenced.
 *
 *	if uppervp and lowervp match pointers already installed, nothing
 *	happens. The passed vp's (when matching) are not adjusted.  This
 *	routine may only be called by union_newupper() and union_newlower().
 */

static void
union_updatevp(struct union_node *un, struct vnode *uppervp,
	       struct vnode *lowervp)
{
	int ohash = UNION_HASH(un->un_uppervp, un->un_lowervp);
	int nhash = UNION_HASH(uppervp, lowervp);
	int docache = (lowervp != NULLVP || uppervp != NULLVP);
	int lhash, uhash;

	/*
	 * Ensure locking is ordered from lower to higher
	 * to avoid deadlocks.
	 */
	if (nhash < ohash) {
		lhash = nhash;
		uhash = ohash;
	} else {
		lhash = ohash;
		uhash = nhash;
	}

	if (lhash != uhash) {
		while (union_list_lock(lhash))
			continue;
	}

	while (union_list_lock(uhash))
		continue;

	if (ohash != nhash || !docache) {
		if (un->un_flags & UN_CACHED) {
			un->un_flags &= ~UN_CACHED;
			LIST_REMOVE(un, un_cache);
		}
	}

	if (ohash != nhash)
		union_list_unlock(ohash);

	if (un->un_lowervp != lowervp) {
		if (un->un_lowervp) {
			vrele(un->un_lowervp);
			if (un->un_path) {
				kfree(un->un_path, M_TEMP);
				un->un_path = 0;
			}
		}
		un->un_lowervp = lowervp;
		un->un_lowersz = VNOVAL;
	}

	if (un->un_uppervp != uppervp) {
		if (un->un_uppervp)
			vrele(un->un_uppervp);
		un->un_uppervp = uppervp;
		un->un_uppersz = VNOVAL;
	}

	if (docache && (ohash != nhash)) {
		LIST_INSERT_HEAD(&unhead[nhash], un, un_cache);
		un->un_flags |= UN_CACHED;
	}

	union_list_unlock(nhash);
}

/*
 * Set a new lowervp.  The passed lowervp must be referenced and will be
 * stored in the vp in a referenced state. 
 */

static void
union_newlower(struct union_node *un, struct vnode *lowervp)
{
	union_updatevp(un, un->un_uppervp, lowervp);
}

/*
 * Set a new uppervp.  The passed uppervp must be locked and will be 
 * stored in the vp in a locked state.  The caller should not unlock
 * uppervp.
 */

static void
union_newupper(struct union_node *un, struct vnode *uppervp)
{
	union_updatevp(un, uppervp, un->un_lowervp);
}

/*
 * Keep track of size changes in the underlying vnodes.
 * If the size changes, then callback to the vm layer
 * giving priority to the upper layer size.
 */
void
union_newsize(struct vnode *vp, off_t uppersz, off_t lowersz)
{
	struct union_node *un;
	off_t sz;

	/* only interested in regular files */
	if (vp->v_type != VREG)
		return;

	un = VTOUNION(vp);
	sz = VNOVAL;

	if ((uppersz != VNOVAL) && (un->un_uppersz != uppersz)) {
		un->un_uppersz = uppersz;
		if (sz == VNOVAL)
			sz = un->un_uppersz;
	}

	if ((lowersz != VNOVAL) && (un->un_lowersz != lowersz)) {
		un->un_lowersz = lowersz;
		if (sz == VNOVAL)
			sz = un->un_lowersz;
	}

	if (sz != VNOVAL) {
		UDEBUG(("union: %s size now %ld\n",
			(uppersz != VNOVAL ? "upper" : "lower"), (long)sz));
		vnode_pager_setsize(vp, sz);
	}
}

/*
 *	union_allocvp:	allocate a union_node and associate it with a
 *			parent union_node and one or two vnodes.
 *
 *	vpp	Holds the returned vnode locked and referenced if no 
 *		error occurs.
 *
 *	mp	Holds the mount point.  mp may or may not be busied. 
 *		allocvp makes no changes to mp.
 *
 *	dvp	Holds the parent union_node to the one we wish to create.
 *		XXX may only be used to traverse an uncopied lowervp-based
 *		tree?  XXX
 *
 *		dvp may or may not be locked.  allocvp makes no changes
 *		to dvp.
 *
 *	upperdvp Holds the parent vnode to uppervp, generally used along
 *		with path component information to create a shadow of
 *		lowervp when uppervp does not exist.
 *
 *		upperdvp is referenced but unlocked on entry, and will be
 *		dereferenced on return.
 *
 *	uppervp	Holds the new uppervp vnode to be stored in the 
 *		union_node we are allocating.  uppervp is referenced but
 *		not locked, and will be dereferenced on return.
 *
 *	lowervp	Holds the new lowervp vnode to be stored in the
 *		union_node we are allocating.  lowervp is referenced but
 *		not locked, and will be dereferenced on return.
 * 
 *	cnp	Holds path component information to be coupled with
 *		lowervp and upperdvp to allow unionfs to create an uppervp
 *		later on.  Only used if lowervp is valid.  The conents
 *		of cnp is only valid for the duration of the call.
 *
 *	docache	Determine whether this node should be entered in the
 *		cache or whether it should be destroyed as soon as possible.
 *
 * all union_nodes are maintained on a singly-linked
 * list.  new nodes are only allocated when they cannot
 * be found on this list.  entries on the list are
 * removed when the vfs reclaim entry is called.
 *
 * a single lock is kept for the entire list.  this is
 * needed because the getnewvnode() function can block
 * waiting for a vnode to become free, in which case there
 * may be more than one process trying to get the same
 * vnode.  this lock is only taken if we are going to
 * call getnewvnode, since the kernel itself is single-threaded.
 *
 * if an entry is found on the list, then call vget() to
 * take a reference.  this is done because there may be
 * zero references to it and so it needs to removed from
 * the vnode free list.
 */

int
union_allocvp(struct vnode **vpp,
	      struct mount *mp,
	      struct vnode *dvp,		/* parent union vnode */
	      struct vnode *upperdvp,		/* parent vnode of uppervp */
	      struct componentname *cnp,	/* may be null */
	      struct vnode *uppervp,		/* may be null */
	      struct vnode *lowervp,		/* may be null */
	      int docache)
{
	int error;
	struct union_node *un = 0;
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	struct thread *td = (cnp) ? cnp->cn_td : curthread; /* XXX */
	int hash = 0;
	int vflag;
	int try;

	if (uppervp == NULLVP && lowervp == NULLVP)
		panic("union: unidentifiable allocation");

	if (uppervp && lowervp && (uppervp->v_type != lowervp->v_type)) {
		vrele(lowervp);
		lowervp = NULLVP;
	}

	/* detect the root vnode (and aliases) */
	vflag = 0;
	if ((uppervp == um->um_uppervp) &&
	    ((lowervp == NULLVP) || lowervp == um->um_lowervp)) {
		if (lowervp == NULLVP) {
			lowervp = um->um_lowervp;
			if (lowervp != NULLVP)
				vref(lowervp);
		}
		vflag = VROOT;
	}

loop:
	if (!docache) {
		un = 0;
	} else for (try = 0; try < 3; try++) {
		switch (try) {
		case 0:
			if (lowervp == NULLVP)
				continue;
			hash = UNION_HASH(uppervp, lowervp);
			break;

		case 1:
			if (uppervp == NULLVP)
				continue;
			hash = UNION_HASH(uppervp, NULLVP);
			break;

		case 2:
			if (lowervp == NULLVP)
				continue;
			hash = UNION_HASH(NULLVP, lowervp);
			break;
		}

		while (union_list_lock(hash))
			continue;

		for (un = unhead[hash].lh_first; un != 0;
					un = un->un_cache.le_next) {
			if ((un->un_lowervp == lowervp ||
			     un->un_lowervp == NULLVP) &&
			    (un->un_uppervp == uppervp ||
			     un->un_uppervp == NULLVP) &&
			    (UNIONTOV(un)->v_mount == mp)) {
				if (vget(UNIONTOV(un), LK_EXCLUSIVE|LK_SLEEPFAIL)) {
					union_list_unlock(hash);
					goto loop;
				}
				break;
			}
		}

		union_list_unlock(hash);

		if (un)
			break;
	}

	if (un) {
		/*
		 * Obtain a lock on the union_node.  Everything is unlocked
		 * except for dvp, so check that case.  If they match, our
		 * new un is already locked.  Otherwise we have to lock our
		 * new un.
		 *
		 * A potential deadlock situation occurs when we are holding
		 * one lock while trying to get another.  We must follow 
		 * strict ordering rules to avoid it.  We try to locate dvp
		 * by scanning up from un_vnode, since the most likely 
		 * scenario is un being under dvp.
		 */

		if (dvp && un->un_vnode != dvp) {
			struct vnode *scan = un->un_vnode;

			do {
				scan = VTOUNION(scan)->un_pvp;
			} while (scan && scan->v_tag == VT_UNION && scan != dvp);
			if (scan != dvp) {
				/*
				 * our new un is above dvp (we never saw dvp
				 * while moving up the tree).
				 */
				vref(dvp);
				vn_unlock(dvp);
				error = vn_lock(un->un_vnode, LK_EXCLUSIVE);
				vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
				vrele(dvp);
			} else {
				/*
				 * our new un is under dvp
				 */
				error = vn_lock(un->un_vnode, LK_EXCLUSIVE);
			}
		} else if (dvp == NULLVP) {
			/*
			 * dvp is NULL, we need to lock un.
			 */
			error = vn_lock(un->un_vnode, LK_EXCLUSIVE);
		} else {
			/*
			 * dvp == un->un_vnode, we are already locked.
			 */
			error = 0;
		}

		if (error)
			goto loop;

		/*
		 * At this point, the union_node is locked and referenced.
		 *
		 * uppervp is locked and referenced or NULL, lowervp is
		 * referenced or NULL.
		 */
		UDEBUG(("Modify existing un %p vn %p upper %p(refs %d) -> %p(refs %d)\n",
			un, un->un_vnode, un->un_uppervp, 
			(un->un_uppervp ? un->un_uppervp->v_sysref.refcnt : -99),
			uppervp,
			(uppervp ? uppervp->v_sysref.refcnt : -99)
		));

		if (uppervp != un->un_uppervp) {
			KASSERT(uppervp == NULL || uppervp->v_sysref.refcnt > 0, ("union_allocvp: too few refs %d (at least 1 required) on uppervp", uppervp->v_sysref.refcnt));
			union_newupper(un, uppervp);
		} else if (uppervp) {
			KASSERT(uppervp->v_sysref.refcnt > 1, ("union_allocvp: too few refs %d (at least 2 required) on uppervp", uppervp->v_sysref.refcnt));
			vrele(uppervp);
		}

		/*
		 * Save information about the lower layer.
		 * This needs to keep track of pathname
		 * and directory information which union_vn_create
		 * might need.
		 */
		if (lowervp != un->un_lowervp) {
			union_newlower(un, lowervp);
			if (cnp && (lowervp != NULLVP)) {
				un->un_path = malloc(cnp->cn_namelen+1,
						M_TEMP, M_WAITOK);
				bcopy(cnp->cn_nameptr, un->un_path,
						cnp->cn_namelen);
				un->un_path[cnp->cn_namelen] = '\0';
			}
		} else if (lowervp) {
			vrele(lowervp);
		}

		/*
		 * and upperdvp
		 */
		if (upperdvp != un->un_dirvp) {
			if (un->un_dirvp)
				vrele(un->un_dirvp);
			un->un_dirvp = upperdvp;
		} else if (upperdvp) {
			vrele(upperdvp);
		}

		*vpp = UNIONTOV(un);
		return (0);
	}

	if (docache) {
		/*
		 * otherwise lock the vp list while we call getnewvnode
		 * since that can block.
		 */ 
		hash = UNION_HASH(uppervp, lowervp);

		if (union_list_lock(hash))
			goto loop;
	}

	/*
	 * Create new node rather then replace old node
	 */

	error = getnewvnode(VT_UNION, mp, vpp, 0, 0);
	if (error) {
		/*
		 * If an error occurs clear out vnodes.
		 */
		if (lowervp)
			vrele(lowervp);
		if (uppervp) 
			vrele(uppervp);
		if (upperdvp)
			vrele(upperdvp);
		*vpp = NULL;
		goto out;
	}

	(*vpp)->v_data = kmalloc(sizeof(struct union_node), M_TEMP, M_WAITOK);

	vsetflags(*vpp, vflag);
	if (uppervp)
		(*vpp)->v_type = uppervp->v_type;
	else
		(*vpp)->v_type = lowervp->v_type;

	un = VTOUNION(*vpp);
	bzero(un, sizeof(*un));

	un->un_vnode = *vpp;
	un->un_uppervp = uppervp;
	un->un_uppersz = VNOVAL;
	un->un_lowervp = lowervp;
	un->un_lowersz = VNOVAL;
	un->un_dirvp = upperdvp;
	un->un_pvp = dvp;		/* only parent dir in new allocation */
	if (dvp != NULLVP)
		vref(dvp);
	un->un_dircache = 0;
	un->un_openl = 0;

	if (cnp && (lowervp != NULLVP)) {
		un->un_path = kmalloc(cnp->cn_namelen+1, M_TEMP, M_WAITOK);
		bcopy(cnp->cn_nameptr, un->un_path, cnp->cn_namelen);
		un->un_path[cnp->cn_namelen] = '\0';
	} else {
		un->un_path = 0;
		un->un_dirvp = NULL;
	}

	if (docache) {
		LIST_INSERT_HEAD(&unhead[hash], un, un_cache);
		un->un_flags |= UN_CACHED;
	}

	/* 
	 * locked refd vpp is returned
	 */

out:
	if (docache)
		union_list_unlock(hash);

	return (error);
}

int
union_freevp(struct vnode *vp)
{
	struct union_node *un = VTOUNION(vp);

	vp->v_data = NULL;
	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}
	if (un->un_pvp != NULLVP) {
		vrele(un->un_pvp);
		un->un_pvp = NULL;
	}
	if (un->un_uppervp != NULLVP) {
		vrele(un->un_uppervp);
		un->un_uppervp = NULL;
	}
	if (un->un_lowervp != NULLVP) {
		vrele(un->un_lowervp);
		un->un_lowervp = NULL;
	}
	if (un->un_dirvp != NULLVP) {
		vrele(un->un_dirvp);
		un->un_dirvp = NULL;
	}
	if (un->un_path) {
		kfree(un->un_path, M_TEMP);
		un->un_path = NULL;
	}
	kfree(un, M_TEMP);
	return (0);
}

/*
 * copyfile.  copy the vnode (fvp) to the vnode (tvp)
 * using a sequence of reads and writes.  both (fvp)
 * and (tvp) are locked on entry and exit.
 *
 * fvp and tvp are both exclusive locked on call, but their refcount's
 * haven't been bumped at all.
 */
static int
union_copyfile(struct vnode *fvp, struct vnode *tvp, struct ucred *cred,
	       struct thread *td)
{
	char *buf;
	struct uio uio;
	struct iovec iov;
	int error = 0;

	/*
	 * strategy:
	 * allocate a buffer of size MAXBSIZE.
	 * loop doing reads and writes, keeping track
	 * of the current uio offset.
	 * give up at the first sign of trouble.
	 */

	bzero(&uio, sizeof(uio));

	uio.uio_td = td;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_offset = 0;

	buf = kmalloc(MAXBSIZE, M_TEMP, M_WAITOK);

	/* ugly loop follows... */
	do {
		off_t offset = uio.uio_offset;
		int count;
		int bufoffset;

		/*
		 * Setup for big read
		 */
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		iov.iov_base = buf;
		iov.iov_len = MAXBSIZE;
		uio.uio_resid = iov.iov_len;
		uio.uio_rw = UIO_READ;

		if ((error = VOP_READ(fvp, &uio, 0, cred)) != 0)
			break;

		/*
		 * Get bytes read, handle read eof case and setup for
		 * write loop
		 */
		if ((count = MAXBSIZE - uio.uio_resid) == 0)
			break;
		bufoffset = 0;

		/*
		 * Write until an error occurs or our buffer has been
		 * exhausted, then update the offset for the next read.
		 */
		while (bufoffset < count) {
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			iov.iov_base = buf + bufoffset;
			iov.iov_len = count - bufoffset;
			uio.uio_offset = offset + bufoffset;
			uio.uio_rw = UIO_WRITE;
			uio.uio_resid = iov.iov_len;

			if ((error = VOP_WRITE(tvp, &uio, 0, cred)) != 0)
				break;
			bufoffset += (count - bufoffset) - uio.uio_resid;
		}
		uio.uio_offset = offset + bufoffset;
	} while (error == 0);

	kfree(buf, M_TEMP);
	return (error);
}

/*
 *
 * un's vnode is assumed to be locked on entry and remains locked on exit.
 */

int
union_copyup(struct union_node *un, int docopy, struct ucred *cred,
	     struct thread *td)
{
	int error;
	struct vnode *lvp, *uvp;

	/*
	 * If the user does not have read permission, the vnode should not
	 * be copied to upper layer.
	 */
	vn_lock(un->un_lowervp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_EACCESS(un->un_lowervp, VREAD, cred);
	vn_unlock(un->un_lowervp);
	if (error)
		return (error);

	error = union_vn_create(&uvp, un, td);
	if (error)
		return (error);

	lvp = un->un_lowervp;

	KASSERT(uvp->v_sysref.refcnt > 0, ("copy: uvp refcount 0: %d", uvp->v_sysref.refcnt));
	if (docopy) {
		/*
		 * XX - should not ignore errors
		 * from VOP_CLOSE
		 */
		vn_lock(lvp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_OPEN(lvp, FREAD, cred, NULL);
		if (error == 0) {
			error = union_copyfile(lvp, uvp, cred, td);
			vn_unlock(lvp);
			(void) VOP_CLOSE(lvp, FREAD);
		}
		if (error == 0)
			UDEBUG(("union: copied up %s\n", un->un_path));

	}
	vn_unlock(uvp);
	union_newupper(un, uvp);
	KASSERT(uvp->v_sysref.refcnt > 0, ("copy: uvp refcount 0: %d", uvp->v_sysref.refcnt));
	union_vn_close(uvp, FWRITE, cred);
	KASSERT(uvp->v_sysref.refcnt > 0, ("copy: uvp refcount 0: %d", uvp->v_sysref.refcnt));
	/*
	 * Subsequent IOs will go to the top layer, so
	 * call close on the lower vnode and open on the
	 * upper vnode to ensure that the filesystem keeps
	 * its references counts right.  This doesn't do
	 * the right thing with (cred) and (FREAD) though.
	 * Ignoring error returns is not right, either.
	 */
	if (error == 0) {
		int i;

		for (i = 0; i < un->un_openl; i++) {
			VOP_CLOSE(lvp, FREAD);
			VOP_OPEN(uvp, FREAD, cred, NULL);
		}
		un->un_openl = 0;
	}

	return (error);

}

/*
 *	union_relookup:
 *
 *	dvp should be locked on entry and will be locked on return.  No
 *	net change in the ref count will occur.
 *
 *	If an error is returned, *vpp will be invalid, otherwise it
 *	will hold a locked, referenced vnode.  If *vpp == dvp then
 *	remember that only one exclusive lock is held.
 */

static int
union_relookup(struct union_mount *um, struct vnode *dvp, struct vnode **vpp,
	       struct componentname *cnp, struct componentname *cn, char *path,
	       int pathlen)
{
	int error;

	/*
	 * A new componentname structure must be faked up because
	 * there is no way to know where the upper level cnp came
	 * from or what it is being used for.  This must duplicate
	 * some of the work done by NDINIT, some of the work done
	 * by namei, some of the work done by lookup and some of
	 * the work done by VOP_LOOKUP when given a CREATE flag.
	 * Conclusion: Horrible.
	 */
	cn->cn_namelen = pathlen;
	cn->cn_nameptr = objcache_get(namei_oc, M_WAITOK);
	bcopy(path, cn->cn_nameptr, cn->cn_namelen);
	cn->cn_nameptr[cn->cn_namelen] = '\0';

	cn->cn_nameiop = NAMEI_CREATE;
	cn->cn_flags = CNP_LOCKPARENT;
	cn->cn_td = cnp->cn_td;
	if (um->um_op == UNMNT_ABOVE)
		cn->cn_cred = cnp->cn_cred;
	else
		cn->cn_cred = um->um_cred;
	cn->cn_consume = cnp->cn_consume;

	vref(dvp);
	vn_unlock(dvp);

	/*
	 * Pass dvp unlocked and referenced on call to relookup().
	 *
	 * If an error occurs, dvp will be returned unlocked and dereferenced.
	 */

	if ((error = relookup(dvp, vpp, cn)) != 0) {
		objcache_put(namei_oc, cn->cn_nameptr);
		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
		return(error);
	}
	objcache_put(namei_oc, cn->cn_nameptr);

	/*
	 * If no error occurs, dvp will be returned locked with the reference
	 * left as before, and vpp will be returned referenced and locked.
	 *
	 * We want to return with dvp as it was passed to us, so we get
	 * rid of our reference.
	 */
	vrele(dvp);
	return (0);
}

/*
 * Create a shadow directory in the upper layer.
 * The new vnode is returned locked.
 *
 * (um) points to the union mount structure for access to the
 * the mounting process's credentials.
 * (dvp) is the directory in which to create the shadow directory,
 * it is locked (but not ref'd) on entry and return.
 * (cnp) is the componentname to be created.
 * (vpp) is the returned newly created shadow directory, which
 * is returned locked and ref'd
 */
int
union_mkshadow(struct union_mount *um, struct vnode *dvp,
	       struct componentname *cnp, struct vnode **vpp)
{
	int error;
	struct vattr va;
	struct thread *td = cnp->cn_td;
	struct componentname cn;

	error = union_relookup(um, dvp, vpp, cnp, &cn,
			cnp->cn_nameptr, cnp->cn_namelen);
	if (error)
		return (error);

	if (*vpp) {
		if (dvp == *vpp)
			vrele(*vpp);
		else
			vput(*vpp);
		*vpp = NULLVP;
		return (EEXIST);
	}

	/*
	 * policy: when creating the shadow directory in the
	 * upper layer, create it owned by the user who did
	 * the mount, group from parent directory, and mode
	 * 777 modified by umask (ie mostly identical to the
	 * mkdir syscall).  (jsp, kb)
	 */

	VATTR_NULL(&va);
	va.va_type = VDIR;
	va.va_mode = um->um_cmode;

	error = VOP_MKDIR(dvp, vpp, &cn, &va);
	/*vput(dvp);*/
	return (error);
}

/*
 * Create a whiteout entry in the upper layer.
 *
 * (um) points to the union mount structure for access to the
 * the mounting process's credentials.
 * (dvp) is the directory in which to create the whiteout.
 * it is locked on entry and return.
 * (cnp) is the componentname to be created.
 */
int
union_mkwhiteout(struct union_mount *um, struct vnode *dvp,
		 struct componentname *cnp, char *path)
{
	int error;
	struct thread *td = cnp->cn_td;
	struct vnode *wvp;
	struct componentname cn;
	struct ucred *cred;

	KKASSERT(td->td_proc);
	cred = td->td_proc->p_ucred;

	error = union_relookup(um, dvp, &wvp, cnp, &cn, path, strlen(path));
	if (error)
		return (error);

	if (wvp) {
		if (wvp == dvp)
			vrele(wvp);
		else
			vput(wvp);
		return (EEXIST);
	}

	error = VOP_WHITEOUT(dvp, &cn, NAMEI_CREATE);
	return (error);
}

/*
 * union_vn_create: creates and opens a new shadow file
 * on the upper union layer.  this function is similar
 * in spirit to calling vn_open but it avoids calling namei().
 * the problem with calling namei is that a) it locks too many
 * things, and b) it doesn't start at the "right" directory,
 * whereas relookup is told where to start.
 *
 * On entry, the vnode associated with un is locked.  It remains locked
 * on return.
 *
 * If no error occurs, *vpp contains a locked referenced vnode for your
 * use.  If an error occurs *vpp iis undefined.
 */
static int
union_vn_create(struct vnode **vpp, struct union_node *un, struct thread *td)
{
	struct vnode *vp;
	struct ucred *cred;
	struct vattr vat;
	struct vattr *vap = &vat;
	int fmode = FFLAGS(O_WRONLY|O_CREAT|O_TRUNC|O_EXCL);
	int error;
	int cmode;
	struct componentname cn;

	KKASSERT(td->td_proc);
	cred = td->td_proc->p_ucred;
	cmode = UN_FILEMODE & ~td->td_proc->p_fd->fd_cmask;

	*vpp = NULLVP;

	/*
	 * Build a new componentname structure (for the same
	 * reasons outlines in union_mkshadow).
	 * The difference here is that the file is owned by
	 * the current user, rather than by the person who
	 * did the mount, since the current user needs to be
	 * able to write the file (that's why it is being
	 * copied in the first place).
	 */
	cn.cn_namelen = strlen(un->un_path);
	cn.cn_nameptr = objcache_get(namei_oc, M_WAITOK);
	bcopy(un->un_path, cn.cn_nameptr, cn.cn_namelen+1);
	cn.cn_nameiop = NAMEI_CREATE;
	cn.cn_flags = CNP_LOCKPARENT;
	cn.cn_td = td;
	cn.cn_cred = cred;
	cn.cn_consume = 0;

	/*
	 * Pass dvp unlocked and referenced on call to relookup().
	 *
	 * If an error occurs, dvp will be returned unlocked and dereferenced.
	 */
	vref(un->un_dirvp);
	error = relookup(un->un_dirvp, &vp, &cn);
	objcache_put(namei_oc, cn.cn_nameptr);
	if (error)
		return (error);

	/*
	 * If no error occurs, dvp will be returned locked with the reference
	 * left as before, and vpp will be returned referenced and locked.
	 */
	if (vp) {
		vput(un->un_dirvp);
		if (vp == un->un_dirvp)
			vrele(vp);
		else
			vput(vp);
		return (EEXIST);
	}

	/*
	 * Good - there was no race to create the file
	 * so go ahead and create it.  The permissions
	 * on the file will be 0666 modified by the
	 * current user's umask.  Access to the file, while
	 * it is unioned, will require access to the top *and*
	 * bottom files.  Access when not unioned will simply
	 * require access to the top-level file.
	 * TODO: confirm choice of access permissions.
	 */
	VATTR_NULL(vap);
	vap->va_type = VREG;
	vap->va_mode = cmode;
	error = VOP_CREATE(un->un_dirvp, &vp, &cn, vap);
	vput(un->un_dirvp);
	if (error)
		return (error);

	error = VOP_OPEN(vp, fmode, cred, NULL);
	if (error) {
		vput(vp);
		return (error);
	}
	*vpp = vp;
	return (0);
}

static int
union_vn_close(struct vnode *vp, int fmode, struct ucred *cred)
{
	return (VOP_CLOSE(vp, fmode));
}

#if 0

/*
 *	union_removed_upper:
 *
 *	called with union_node unlocked. XXX
 */

void
union_removed_upper(struct union_node *un)
{
	struct thread *td = curthread;	/* XXX */
	struct vnode **vpp;

	/*
	 * Do not set the uppervp to NULLVP.  If lowervp is NULLVP,
	 * union node will have neither uppervp nor lowervp.  We remove
	 * the union node from cache, so that it will not be referrenced.
	 */
	union_newupper(un, NULLVP);
	if (un->un_dircache != 0) {
		for (vpp = un->un_dircache; *vpp != NULLVP; vpp++)
			vrele(*vpp);
		kfree(un->un_dircache, M_TEMP);
		un->un_dircache = 0;
	}

	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}
}

#endif

/*
 * determine whether a whiteout is needed
 * during a remove/rmdir operation.
 */
int
union_dowhiteout(struct union_node *un, struct ucred *cred, struct thread *td)
{
	struct vattr va;

	if (un->un_lowervp != NULLVP)
		return (1);

	if (VOP_GETATTR(un->un_uppervp, &va) == 0 &&
	    (va.va_flags & OPAQUE))
		return (1);

	return (0);
}

static void
union_dircache_r(struct vnode *vp, struct vnode ***vppp, int *cntp)
{
	struct union_node *un;

	if (vp->v_tag != VT_UNION) {
		if (vppp) {
			vref(vp);
			*(*vppp)++ = vp;
			if (--(*cntp) == 0)
				panic("union: dircache table too small");
		} else {
			(*cntp)++;
		}

		return;
	}

	un = VTOUNION(vp);
	if (un->un_uppervp != NULLVP)
		union_dircache_r(un->un_uppervp, vppp, cntp);
	if (un->un_lowervp != NULLVP)
		union_dircache_r(un->un_lowervp, vppp, cntp);
}

struct vnode *
union_dircache(struct vnode *vp, struct thread *td)
{
	int cnt;
	struct vnode *nvp;
	struct vnode **vpp;
	struct vnode **dircache;
	struct union_node *un;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	dircache = VTOUNION(vp)->un_dircache;

	nvp = NULLVP;

	if (dircache == NULL) {
		cnt = 0;
		union_dircache_r(vp, 0, &cnt);
		cnt++;
		dircache = malloc(cnt * sizeof(struct vnode *),
				M_TEMP, M_WAITOK);
		vpp = dircache;
		union_dircache_r(vp, &vpp, &cnt);
		*vpp = NULLVP;
		vpp = dircache + 1;
	} else {
		vpp = dircache;
		do {
			if (*vpp++ == VTOUNION(vp)->un_uppervp)
				break;
		} while (*vpp != NULLVP);
	}

	if (*vpp == NULLVP)
		goto out;

	/*vn_lock(*vpp, LK_EXCLUSIVE | LK_RETRY);*/
	UDEBUG(("ALLOCVP-3 %p ref %d\n", *vpp, (*vpp ? (*vpp)->v_sysref.refcnt : -99)));
	vref(*vpp);
	error = union_allocvp(&nvp, vp->v_mount, NULLVP, NULLVP, NULL, *vpp, NULLVP, 0);
	UDEBUG(("ALLOCVP-3B %p ref %d\n", nvp, (*vpp ? (*vpp)->v_sysref.refcnt : -99)));
	if (error)
		goto out;

	VTOUNION(vp)->un_dircache = 0;
	un = VTOUNION(nvp);
	un->un_dircache = dircache;

out:
	vn_unlock(vp);
	return (nvp);
}

/*
 * Guarentee coherency with the VM cache by invalidating any clean VM pages
 * associated with this write and updating any dirty VM pages.  Since our
 * vnode is locked, other processes will not be able to read the pages in
 * again until after our write completes.
 *
 * We also have to be coherent with reads, by flushing any pending dirty
 * pages prior to issuing the read.
 *
 * XXX this is somewhat of a hack at the moment.  To support this properly
 * we would have to be able to run VOP_READ and VOP_WRITE through the VM
 * cache.  Then we wouldn't need to worry about coherency.
 */

void 
union_vm_coherency(struct vnode *vp, struct uio *uio, int cleanfls)
{
	vm_object_t object;
	vm_pindex_t pstart;
	vm_pindex_t pend;
	int pgoff;

	if ((object = vp->v_object) == NULL)
	    return;

	pgoff = uio->uio_offset & PAGE_MASK;
	pstart = uio->uio_offset / PAGE_SIZE;
	pend = pstart + (uio->uio_resid + pgoff + PAGE_MASK) / PAGE_SIZE;

	vm_object_page_clean(object, pstart, pend, OBJPC_SYNC);
	if (cleanfls)
		vm_object_page_remove(object, pstart, pend, TRUE);
}

/*
 * Module glue to remove #ifdef UNION from vfs_syscalls.c
 */
static int
union_dircheck(struct thread *td, struct vnode **vp, struct file *fp)
{
	int error = 0;

	if ((*vp)->v_tag == VT_UNION) {
		struct vnode *lvp;

		lvp = union_dircache(*vp, td);
		if (lvp != NULLVP) {
			struct vattr va;

			/*
			 * If the directory is opaque,
			 * then don't show lower entries
			 */
			error = VOP_GETATTR(*vp, &va);
			if (va.va_flags & OPAQUE) {
				vput(lvp);
				lvp = NULL;
			}
		}

		if (lvp != NULLVP) {
			error = VOP_OPEN(lvp, FREAD, fp->f_cred, NULL);
			if (error) {
				vput(lvp);
				return (error);
			}
			vn_unlock(lvp);
			fp->f_data = lvp;
			fp->f_offset = 0;
			error = vn_close(*vp, FREAD);
			if (error)
				return (error);
			*vp = lvp;
			return -1;	/* goto unionread */
		}
	}
	return error;
}

static int
union_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		union_dircheckp = union_dircheck;
		break;
	case MOD_UNLOAD:
		union_dircheckp = NULL;
		break;
	default:
		break;
	}
	return 0;
}

static moduledata_t union_mod = {
	"union_dircheck",
	union_modevent,
	NULL
};

DECLARE_MODULE(union_dircheck, union_mod, SI_SUB_VFS, SI_ORDER_ANY);
