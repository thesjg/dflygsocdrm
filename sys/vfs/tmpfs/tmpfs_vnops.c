/*-
 * Copyright (c) 2005, 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal, developed as part of Google's Summer of Code
 * 2005 program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $NetBSD: tmpfs_vnops.c,v 1.39 2007/07/23 15:41:01 jmmv Exp $
 */

/*
 * tmpfs vnode interface.
 */

#include <sys/kernel.h>
#include <sys/kern_syscall.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vfsops.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/swap_pager.h>

#include <vfs/fifofs/fifo.h>
#include <vfs/tmpfs/tmpfs_vnops.h>
#include <vfs/tmpfs/tmpfs.h>

MALLOC_DECLARE(M_TMPFS);

static __inline
void
tmpfs_knote(struct vnode *vp, int flags)
{
	if (flags)
		KNOTE(&vp->v_pollinfo.vpi_kqinfo.ki_note, flags);
}


/* --------------------------------------------------------------------- */

static int
tmpfs_nresolve(struct vop_nresolve_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode *vp = NULL;
	struct namecache *ncp = v->a_nch->ncp;
	struct tmpfs_node *tnode;

	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_node *dnode;

	dnode = VP_TO_TMPFS_DIR(dvp);

	de = tmpfs_dir_lookup(dnode, NULL, ncp);
	if (de == NULL) {
		error = ENOENT;
	} else {
		/*
		 * Allocate a vnode for the node we found.
		 */
		tnode = de->td_node;
		error = tmpfs_alloc_vp(dvp->v_mount, tnode,
				       LK_EXCLUSIVE | LK_RETRY, &vp);
		if (error)
			goto out;
		KKASSERT(vp);
	}

out:
	/*
	 * Store the result of this lookup in the cache.  Avoid this if the
	 * request was for creation, as it does not improve timings on
	 * emprical tests.
	 */
	if (vp) {
		vn_unlock(vp);
		cache_setvp(v->a_nch, vp);
		vrele(vp);
	} else if (error == ENOENT) {
		cache_setvp(v->a_nch, NULL);
	}
	return error;
}

static int
tmpfs_nlookupdotdot(struct vop_nlookupdotdot_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct tmpfs_node *dnode = VP_TO_TMPFS_NODE(dvp);
	struct ucred *cred = v->a_cred;
	int error;

	*vpp = NULL;
	/* Check accessibility of requested node as a first step. */
	error = VOP_ACCESS(dvp, VEXEC, cred);
	if (error != 0)
		return error;

	if (dnode->tn_dir.tn_parent != NULL) {
		/* Allocate a new vnode on the matching entry. */
		error = tmpfs_alloc_vp(dvp->v_mount, dnode->tn_dir.tn_parent,
		    LK_EXCLUSIVE | LK_RETRY, vpp);

		if (*vpp)
			vn_unlock(*vpp);
	}

	return (*vpp == NULL) ? ENOENT : 0;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_ncreate(struct vop_ncreate_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	int error;

	KKASSERT(vap->va_type == VREG || vap->va_type == VSOCK);

	error = tmpfs_alloc_file(dvp, vpp, vap, ncp, cred, NULL);
	if (error == 0) {
		cache_setunresolved(v->a_nch);
		cache_setvp(v->a_nch, *vpp);
		tmpfs_knote(dvp, NOTE_WRITE);
	}

	return error;
}
/* --------------------------------------------------------------------- */

static int
tmpfs_nmknod(struct vop_nmknod_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	int error;

	if (vap->va_type != VBLK && vap->va_type != VCHR &&
	    vap->va_type != VFIFO)
		return EINVAL;

	error = tmpfs_alloc_file(dvp, vpp, vap, ncp, cred, NULL);
	if (error == 0) {
		cache_setunresolved(v->a_nch);
		cache_setvp(v->a_nch, *vpp);
		tmpfs_knote(dvp, NOTE_WRITE);
	}

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_open(struct vop_open_args *v)
{
	struct vnode *vp = v->a_vp;
	int mode = v->a_mode;

	int error;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	/* The file is still active but all its names have been removed
	 * (e.g. by a "rmdir $(pwd)").  It cannot be opened any more as
	 * it is about to die. */
	if (node->tn_links < 1)
		return (ENOENT);

	/* If the file is marked append-only, deny write requests. */
	if ((node->tn_flags & APPEND) &&
	    (mode & (FWRITE | O_APPEND)) == FWRITE) {
		error = EPERM;
	} else {
		return (vop_stdopen(v));
	}
	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_close(struct vop_close_args *v)
{
	struct vnode *vp = v->a_vp;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	if (node->tn_links > 0) {
		/* Update node times.  No need to do it if the node has
		 * been deleted, because it will vanish after we return. */
		tmpfs_update(vp);
	}

	return vop_stdclose(v);
}

/* --------------------------------------------------------------------- */

int
tmpfs_access(struct vop_access_args *v)
{
	struct vnode *vp = v->a_vp;
	int error;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	switch (vp->v_type) {
	case VDIR:
		/* FALLTHROUGH */
	case VLNK:
		/* FALLTHROUGH */
	case VREG:
		if ((v->a_mode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY)) {
			error = EROFS;
			goto out;
		}
		break;

	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		/* FALLTHROUGH */
	case VSOCK:
		/* FALLTHROUGH */
	case VFIFO:
		break;

	default:
		error = EINVAL;
		goto out;
	}

	if ((v->a_mode & VWRITE) && (node->tn_flags & IMMUTABLE)) {
		error = EPERM;
		goto out;
	}

	error = vop_helper_access(v, node->tn_uid, node->tn_gid, node->tn_mode, 0);

out:

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_getattr(struct vop_getattr_args *v)
{
	struct vnode *vp = v->a_vp;
	struct vattr *vap = v->a_vap;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	lwkt_gettoken(&vp->v_mount->mnt_token);
	tmpfs_update(vp);

	vap->va_type = vp->v_type;
	vap->va_mode = node->tn_mode;
	vap->va_nlink = node->tn_links;
	vap->va_uid = node->tn_uid;
	vap->va_gid = node->tn_gid;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_fileid = node->tn_id;
	vap->va_size = node->tn_size;
	vap->va_blocksize = PAGE_SIZE;
	vap->va_atime.tv_sec = node->tn_atime;
	vap->va_atime.tv_nsec = node->tn_atimensec;
	vap->va_mtime.tv_sec = node->tn_mtime;
	vap->va_mtime.tv_nsec = node->tn_mtimensec;
	vap->va_ctime.tv_sec = node->tn_ctime;
	vap->va_ctime.tv_nsec = node->tn_ctimensec;
	vap->va_gen = node->tn_gen;
	vap->va_flags = node->tn_flags;
	if (vp->v_type == VBLK || vp->v_type == VCHR)
	{
		vap->va_rmajor = umajor(node->tn_rdev);
		vap->va_rminor = uminor(node->tn_rdev);
	}
	vap->va_bytes = round_page(node->tn_size);
	vap->va_filerev = 0;

	lwkt_reltoken(&vp->v_mount->mnt_token);

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_setattr(struct vop_setattr_args *v)
{
	struct vnode *vp = v->a_vp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	struct tmpfs_node *node = VP_TO_TMPFS_NODE(vp);
	int error = 0;
	int kflags = 0;

	if (error == 0 && (vap->va_flags != VNOVAL)) {
		error = tmpfs_chflags(vp, vap->va_flags, cred);
		kflags |= NOTE_ATTRIB;
	}

	if (error == 0 && (vap->va_size != VNOVAL)) {
		if (vap->va_size > node->tn_size)
			kflags |= NOTE_WRITE | NOTE_EXTEND;
		else
			kflags |= NOTE_WRITE;
		error = tmpfs_chsize(vp, vap->va_size, cred);
	}

	if (error == 0 && (vap->va_uid != (uid_t)VNOVAL ||
			   vap->va_gid != (gid_t)VNOVAL)) {
		error = tmpfs_chown(vp, vap->va_uid, vap->va_gid, cred);
		kflags |= NOTE_ATTRIB;
	}

	if (error == 0 && (vap->va_mode != (mode_t)VNOVAL)) {
		error = tmpfs_chmod(vp, vap->va_mode, cred);
		kflags |= NOTE_ATTRIB;
	}

	if (error == 0 && ((vap->va_atime.tv_sec != VNOVAL &&
	    vap->va_atime.tv_nsec != VNOVAL) ||
	    (vap->va_mtime.tv_sec != VNOVAL &&
	    vap->va_mtime.tv_nsec != VNOVAL) )) {
		error = tmpfs_chtimes(vp, &vap->va_atime, &vap->va_mtime,
				      vap->va_vaflags, cred);
		kflags |= NOTE_ATTRIB;
	}

	/* Update the node times.  We give preference to the error codes
	 * generated by this function rather than the ones that may arise
	 * from tmpfs_update. */
	tmpfs_update(vp);
	tmpfs_knote(vp, kflags);

	return error;
}

/* --------------------------------------------------------------------- */

/*
 * fsync is usually a NOP, but we must take action when unmounting or
 * when recycling.
 */
static int
tmpfs_fsync(struct vop_fsync_args *v)
{
	struct tmpfs_mount *tmp;
	struct tmpfs_node *node;
	struct vnode *vp = v->a_vp;

	tmp = VFS_TO_TMPFS(vp->v_mount);
	node = VP_TO_TMPFS_NODE(vp);

	tmpfs_update(vp);
	if (vp->v_type == VREG) {
		if (vp->v_flag & VRECLAIMED) {
			if (node->tn_links == 0)
				tmpfs_truncate(vp, 0);
			else
				vfsync(v->a_vp, v->a_waitfor, 1, NULL, NULL);
		}
	}
	return 0;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_read (struct vop_read_args *ap)
{
	struct buf *bp;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct tmpfs_node *node;
	off_t base_offset;
	size_t offset;
	size_t len;
	int error;

	error = 0;
	if (uio->uio_resid == 0) {
		return error;
	}

	node = VP_TO_TMPFS_NODE(vp);

	if (uio->uio_offset < 0)
		return (EINVAL);
	if (vp->v_type != VREG)
		return (EINVAL);

	while (uio->uio_resid > 0 && uio->uio_offset < node->tn_size) {
		/*
		 * Use buffer cache I/O (via tmpfs_strategy)
		 */
		offset = (size_t)uio->uio_offset & BMASK;
		base_offset = (off_t)uio->uio_offset - offset;
		bp = getcacheblk(vp, base_offset, BSIZE);
		if (bp == NULL)
		{
			lwkt_gettoken(&vp->v_mount->mnt_token);
			error = bread(vp, base_offset, BSIZE, &bp);
			if (error) {
				brelse(bp);
				lwkt_reltoken(&vp->v_mount->mnt_token);
				kprintf("tmpfs_read bread error %d\n", error);
				break;
			}
			lwkt_reltoken(&vp->v_mount->mnt_token);
		}

		/*
		 * Figure out how many bytes we can actually copy this loop.
		 */
		len = BSIZE - offset;
		if (len > uio->uio_resid)
			len = uio->uio_resid;
		if (len > node->tn_size - uio->uio_offset)
			len = (size_t)(node->tn_size - uio->uio_offset);

		error = uiomove((char *)bp->b_data + offset, len, uio);
		bqrelse(bp);
		if (error) {
			kprintf("tmpfs_read uiomove error %d\n", error);
			break;
		}
	}

	TMPFS_NODE_LOCK(node);
	node->tn_status |= TMPFS_NODE_ACCESSED;
	TMPFS_NODE_UNLOCK(node);

	return(error);
}

static int
tmpfs_write (struct vop_write_args *ap)
{
	struct buf *bp;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct thread *td = uio->uio_td;
	struct tmpfs_node *node;
	boolean_t extended;
	off_t oldsize;
	int error;
	off_t base_offset;
	size_t offset;
	size_t len;
	struct rlimit limit;
	int trivial = 0;
	int kflags = 0;

	error = 0;
	if (uio->uio_resid == 0) {
		return error;
	}

	node = VP_TO_TMPFS_NODE(vp);

	if (vp->v_type != VREG)
		return (EINVAL);

	lwkt_gettoken(&vp->v_mount->mnt_token);

	oldsize = node->tn_size;
	if (ap->a_ioflag & IO_APPEND)
		uio->uio_offset = node->tn_size;

	/*
	 * Check for illegal write offsets.
	 */
	if (uio->uio_offset + uio->uio_resid >
	  VFS_TO_TMPFS(vp->v_mount)->tm_maxfilesize) {
		lwkt_reltoken(&vp->v_mount->mnt_token);
		return (EFBIG);
	}

	if (vp->v_type == VREG && td != NULL) {
		error = kern_getrlimit(RLIMIT_FSIZE, &limit);
		if (error != 0) {
			lwkt_reltoken(&vp->v_mount->mnt_token);
			return error;
		}
		if (uio->uio_offset + uio->uio_resid > limit.rlim_cur) {
			ksignal(td->td_proc, SIGXFSZ);
			lwkt_reltoken(&vp->v_mount->mnt_token);
			return (EFBIG);
		}
	}


	/*
	 * Extend the file's size if necessary
	 */
	extended = ((uio->uio_offset + uio->uio_resid) > node->tn_size);

	while (uio->uio_resid > 0) {
		/*
		 * Use buffer cache I/O (via tmpfs_strategy)
		 */
		offset = (size_t)uio->uio_offset & BMASK;
		base_offset = (off_t)uio->uio_offset - offset;
		len = BSIZE - offset;
		if (len > uio->uio_resid)
			len = uio->uio_resid;

		if ((uio->uio_offset + len) > node->tn_size) {
			trivial = (uio->uio_offset <= node->tn_size);
			error = tmpfs_reg_resize(vp, uio->uio_offset + len,  trivial);
			if (error)
				break;
		}

		/*
		 * Read to fill in any gaps.  Theoretically we could
		 * optimize this if the write covers the entire buffer
		 * and is not a UIO_NOCOPY write, however this can lead
		 * to a security violation exposing random kernel memory
		 * (whatever junk was in the backing VM pages before).
		 *
		 * So just use bread() to do the right thing.
		 */
		error = bread(vp, base_offset, BSIZE, &bp);
		error = uiomove((char *)bp->b_data + offset, len, uio);
		if (error) {
			kprintf("tmpfs_write uiomove error %d\n", error);
			brelse(bp);
			break;
		}

		if (uio->uio_offset > node->tn_size) {
			node->tn_size = uio->uio_offset;
			kflags |= NOTE_EXTEND;
		}
		kflags |= NOTE_WRITE;

		/*
		 * The data has been loaded into the buffer, write it out.
		 *
		 * We want tmpfs to be able to use all available ram, not
		 * just the buffer cache, so if not explicitly paging we
		 * use buwrite() to leave the buffer clean but mark all the
		 * VM pages valid+dirty.
		 *
		 * When the kernel is paging, either via normal pageout
		 * operation or when cleaning the object during a recycle,
		 * the underlying VM pages are going to get thrown away
		 * so we MUST write them to swap.
		 *
		 * XXX unfortunately this catches msync() system calls too
		 * for the moment.
		 */
		if (vm_swap_size == 0) {
			/*
			 * if swap isn't configured yet, force a buwrite() to
			 * avoid problems further down the line, due to flushing
			 * to swap.
			 */
			buwrite(bp);
		} else {
			if (ap->a_ioflag & IO_SYNC) {
				bwrite(bp);
			} else if ((ap->a_ioflag & IO_ASYNC) ||
				 (uio->uio_segflg == UIO_NOCOPY)) {
				bawrite(bp);
			} else {
				buwrite(bp);
			}
		}

		if (bp->b_error) {
			kprintf("tmpfs_write bwrite error %d\n", bp->b_error);
			break;
		}
	}

	if (error) {
		if (extended) {
			(void)tmpfs_reg_resize(vp, oldsize, trivial);
			kflags &= ~NOTE_EXTEND;
		}
		goto done;
	}

	TMPFS_NODE_LOCK(node);
	node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_MODIFIED |
	    (extended? TMPFS_NODE_CHANGED : 0);

	if (node->tn_mode & (S_ISUID | S_ISGID)) {
		if (priv_check_cred(ap->a_cred, PRIV_VFS_RETAINSUGID, 0))
			node->tn_mode &= ~(S_ISUID | S_ISGID);
	}
	TMPFS_NODE_UNLOCK(node);
done:

	tmpfs_knote(vp, kflags);


	lwkt_reltoken(&vp->v_mount->mnt_token);
	return(error);
}

static int
tmpfs_advlock (struct vop_advlock_args *ap)
{
	struct tmpfs_node *node;
	struct vnode *vp = ap->a_vp;

	node = VP_TO_TMPFS_NODE(vp);

	return (lf_advlock(ap, &node->tn_advlock, node->tn_size));
}

static int
tmpfs_strategy(struct vop_strategy_args *ap)
{
	struct bio *bio = ap->a_bio;
	struct buf *bp = bio->bio_buf;
	struct vnode *vp = ap->a_vp;
	struct tmpfs_node *node;
	vm_object_t uobj;

	if (vp->v_type != VREG) {
		bp->b_resid = bp->b_bcount;
		bp->b_flags |= B_ERROR | B_INVAL;
		bp->b_error = EINVAL;
		biodone(bio);
		return(0);
	}

	lwkt_gettoken(&vp->v_mount->mnt_token);
	node = VP_TO_TMPFS_NODE(vp);

	uobj = node->tn_reg.tn_aobj;

	/*
	 * Call swap_pager_strategy to read or write between the VM
	 * object and the buffer cache.
	 */
	swap_pager_strategy(uobj, bio);

	lwkt_reltoken(&vp->v_mount->mnt_token);
	return 0;
}

static int
tmpfs_bmap(struct vop_bmap_args *ap)
{
	if (ap->a_doffsetp != NULL)
		*ap->a_doffsetp = ap->a_loffset;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;

	return 0;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nremove(struct vop_nremove_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vnode *vp;
	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;

	/*
	 * We have to acquire the vp from v->a_nch because
	 * we will likely unresolve the namecache entry, and
	 * a vrele is needed to trigger the tmpfs_inactive/tmpfs_reclaim
	 * sequence to recover space from the file.
	 */
	error = cache_vref(v->a_nch, v->a_cred, &vp);
	KKASSERT(error == 0);

	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	dnode = VP_TO_TMPFS_DIR(dvp);
	node = VP_TO_TMPFS_NODE(vp);
	tmp = VFS_TO_TMPFS(vp->v_mount);
	de = tmpfs_dir_lookup(dnode, node, ncp);
	if (de == NULL) {
		error = ENOENT;
		goto out;
	}

	/* Files marked as immutable or append-only cannot be deleted. */
	if ((node->tn_flags & (IMMUTABLE | APPEND | NOUNLINK)) ||
	    (dnode->tn_flags & APPEND)) {
		error = EPERM;
		goto out;
	}

	/* Remove the entry from the directory; as it is a file, we do not
	 * have to change the number of hard links of the directory. */
	tmpfs_dir_detach(dnode, de);

	/* Free the directory entry we just deleted.  Note that the node
	 * referred by it will not be removed until the vnode is really
	 * reclaimed. */
	tmpfs_free_dirent(tmp, de);

	if (node->tn_links > 0) {
	        TMPFS_NODE_LOCK(node);
		node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	                TMPFS_NODE_MODIFIED;
	        TMPFS_NODE_UNLOCK(node);
	}

	cache_setunresolved(v->a_nch);
	cache_setvp(v->a_nch, NULL);
	tmpfs_knote(vp, NOTE_DELETE);
	/*cache_inval_vp(vp, CINV_DESTROY);*/
	tmpfs_knote(dvp, NOTE_WRITE);
	error = 0;

out:
	vrele(vp);

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nlink(struct vop_nlink_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode *vp = v->a_vp;
	struct namecache *ncp = v->a_nch->ncp;
	struct tmpfs_dirent *de;
	struct tmpfs_node *node;
	struct tmpfs_node *dnode;
	int error;

	KKASSERT(dvp != vp); /* XXX When can this be false? */

	node = VP_TO_TMPFS_NODE(vp);
	dnode = VP_TO_TMPFS_NODE(dvp);

	/* XXX: Why aren't the following two tests done by the caller? */

	/* Hard links of directories are forbidden. */
	if (vp->v_type == VDIR) {
		error = EPERM;
		goto out;
	}

	/* Cannot create cross-device links. */
	if (dvp->v_mount != vp->v_mount) {
		error = EXDEV;
		goto out;
	}

	/* Ensure that we do not overflow the maximum number of links imposed
	 * by the system. */
	KKASSERT(node->tn_links <= LINK_MAX);
	if (node->tn_links == LINK_MAX) {
		error = EMLINK;
		goto out;
	}

	/* We cannot create links of files marked immutable or append-only. */
	if (node->tn_flags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}

	/* Allocate a new directory entry to represent the node. */
	error = tmpfs_alloc_dirent(VFS_TO_TMPFS(vp->v_mount), node,
	    ncp->nc_name, ncp->nc_nlen, &de);
	if (error != 0)
		goto out;

	/* Insert the new directory entry into the appropriate directory. */
	tmpfs_dir_attach(dnode, de);

	/* vp link count has changed, so update node times. */

	TMPFS_NODE_LOCK(node);
	node->tn_status |= TMPFS_NODE_CHANGED;
	TMPFS_NODE_UNLOCK(node);
	tmpfs_update(vp);

	tmpfs_knote(vp, NOTE_LINK);
	cache_setunresolved(v->a_nch);
	cache_setvp(v->a_nch, vp);
	tmpfs_knote(dvp, NOTE_WRITE);
	error = 0;

out:
	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nrename(struct vop_nrename_args *v)
{
	struct vnode *fdvp = v->a_fdvp;
	struct namecache *fncp = v->a_fnch->ncp;
	struct vnode *fvp = fncp->nc_vp;
	struct vnode *tdvp = v->a_tdvp;
	struct namecache *tncp = v->a_tnch->ncp;
	struct vnode *tvp = tncp->nc_vp;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *fdnode;
	struct tmpfs_node *fnode;
	struct tmpfs_node *tnode;
	struct tmpfs_node *tdnode;
	char *newname;
	char *oldname;
	int error;

	tnode = (tvp == NULL) ? NULL : VP_TO_TMPFS_NODE(tvp);

	/* Disallow cross-device renames.
	 * XXX Why isn't this done by the caller? */
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp != NULL && fvp->v_mount != tvp->v_mount)) {
		error = EXDEV;
		goto out;
	}

	tmp = VFS_TO_TMPFS(tdvp->v_mount);
	tdnode = VP_TO_TMPFS_DIR(tdvp);

	/* If source and target are the same file, there is nothing to do. */
	if (fvp == tvp) {
		error = 0;
		goto out;
	}

	fdnode = VP_TO_TMPFS_DIR(fdvp);
	fnode = VP_TO_TMPFS_NODE(fvp);
	de = tmpfs_dir_lookup(fdnode, fnode, fncp);

	/* Avoid manipulating '.' and '..' entries. */
	if (de == NULL) {
		error = ENOENT;
		goto out_locked;
	}
	KKASSERT(de->td_node == fnode);

	/*
	 * If replacing an entry in the target directory and that entry
	 * is a directory, it must be empty.
	 *
	 * Kern_rename gurantees the destination to be a directory
	 * if the source is one (it does?).
	 */
	if (tvp != NULL) {
		KKASSERT(tnode != NULL);

		if ((tnode->tn_flags & (NOUNLINK | IMMUTABLE | APPEND)) ||
		    (tdnode->tn_flags & (APPEND | IMMUTABLE))) {
			error = EPERM;
			goto out_locked;
		}

		if (fnode->tn_type == VDIR && tnode->tn_type == VDIR) {
			if (tnode->tn_size > 0) {
				error = ENOTEMPTY;
				goto out_locked;
			}
		} else if (fnode->tn_type == VDIR && tnode->tn_type != VDIR) {
			error = ENOTDIR;
			goto out_locked;
		} else if (fnode->tn_type != VDIR && tnode->tn_type == VDIR) {
			error = EISDIR;
			goto out_locked;
		} else {
			KKASSERT(fnode->tn_type != VDIR &&
				tnode->tn_type != VDIR);
		}
	}

	if ((fnode->tn_flags & (NOUNLINK | IMMUTABLE | APPEND)) ||
	    (fdnode->tn_flags & (APPEND | IMMUTABLE))) {
		error = EPERM;
		goto out_locked;
	}

	/*
	 * Ensure that we have enough memory to hold the new name, if it
	 * has to be changed.
	 */
	if (fncp->nc_nlen != tncp->nc_nlen ||
	    bcmp(fncp->nc_name, tncp->nc_name, fncp->nc_nlen) != 0) {
		newname = kmalloc(tncp->nc_nlen + 1, tmp->tm_name_zone, 
				  M_WAITOK | M_NULLOK);
		if (newname == NULL) {
			error = ENOSPC;
			goto out_locked;
		}
		bcopy(tncp->nc_name, newname, tncp->nc_nlen);
		newname[tncp->nc_nlen] = '\0';
	} else {
		newname = NULL;
	}

	/*
	 * Unlink entry from source directory.  Note that the kernel has
	 * already checked for illegal recursion cases (renaming a directory
	 * into a subdirectory of itself).
	 */
	if (fdnode != tdnode)
		tmpfs_dir_detach(fdnode, de);

	/*
	 * Handle any name change.  Swap with newname, we will
	 * deallocate it at the end.
	 */
	if (newname != NULL) {
#if 0
		TMPFS_NODE_LOCK(fnode);
		fnode->tn_status |= TMPFS_NODE_CHANGED;
		TMPFS_NODE_UNLOCK(fnode);
#endif
		oldname = de->td_name;
		de->td_name = newname;
		de->td_namelen = (uint16_t)tncp->nc_nlen;
		newname = oldname;
	}

	/*
	 * Link entry to target directory.  If the entry
	 * represents a directory move the parent linkage
	 * as well.
	 */
	if (fdnode != tdnode) {
		if (de->td_node->tn_type == VDIR) {
			TMPFS_VALIDATE_DIR(fnode);

			TMPFS_NODE_LOCK(tdnode);
			tdnode->tn_links++;
			tdnode->tn_status |= TMPFS_NODE_MODIFIED;
			TMPFS_NODE_UNLOCK(tdnode);

			TMPFS_NODE_LOCK(fnode);
			fnode->tn_dir.tn_parent = tdnode;
			fnode->tn_status |= TMPFS_NODE_CHANGED;
			TMPFS_NODE_UNLOCK(fnode);

			TMPFS_NODE_LOCK(fdnode);
			fdnode->tn_links--;
			fdnode->tn_status |= TMPFS_NODE_MODIFIED;
			TMPFS_NODE_UNLOCK(fdnode);
		}
		tmpfs_dir_attach(tdnode, de);
	} else {
		TMPFS_NODE_LOCK(tdnode);
		tdnode->tn_status |= TMPFS_NODE_MODIFIED;
		TMPFS_NODE_UNLOCK(tdnode);
	}

	/*
	 * If we are overwriting an entry, we have to remove the old one
	 * from the target directory.
	 */
	if (tvp != NULL) {
		/* Remove the old entry from the target directory. */
		de = tmpfs_dir_lookup(tdnode, tnode, tncp);
		tmpfs_dir_detach(tdnode, de);
		tmpfs_knote(tdnode->tn_vnode, NOTE_DELETE);

		/*
		 * Free the directory entry we just deleted.  Note that the
		 * node referred by it will not be removed until the vnode is
		 * really reclaimed.
		 */
		tmpfs_free_dirent(VFS_TO_TMPFS(tvp->v_mount), de);
		/*cache_inval_vp(tvp, CINV_DESTROY);*/
	}

	/*
	 * Finish up
	 */
	if (newname) {
		kfree(newname, tmp->tm_name_zone);
		newname = NULL;
	}
	cache_rename(v->a_fnch, v->a_tnch);
	tmpfs_knote(v->a_fdvp, NOTE_WRITE);
	tmpfs_knote(v->a_tdvp, NOTE_WRITE);
	if (fnode->tn_vnode)
		tmpfs_knote(fnode->tn_vnode, NOTE_RENAME);
	error = 0;

out_locked:
	;

out:
	/* Release target nodes. */
	/* XXX: I don't understand when tdvp can be the same as tvp, but
	 * other code takes care of this... */
	if (tdvp == tvp)
		vrele(tdvp);

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nmkdir(struct vop_nmkdir_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	int error;

	KKASSERT(vap->va_type == VDIR);

	error = tmpfs_alloc_file(dvp, vpp, vap, ncp, cred, NULL);
	if (error == 0) {
		cache_setunresolved(v->a_nch);
		cache_setvp(v->a_nch, *vpp);
		tmpfs_knote(dvp, NOTE_WRITE | NOTE_LINK);
	}

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nrmdir(struct vop_nrmdir_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vnode *vp;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;
	int error;

	/*
	 * We have to acquire the vp from v->a_nch because
	 * we will likely unresolve the namecache entry, and
	 * a vrele is needed to trigger the tmpfs_inactive/tmpfs_reclaim
	 * sequence.
	 */
	error = cache_vref(v->a_nch, v->a_cred, &vp);
	KKASSERT(error == 0);

	/*
	 * Prevalidate so we don't hit an assertion later
	 */
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	tmp = VFS_TO_TMPFS(dvp->v_mount);
	dnode = VP_TO_TMPFS_DIR(dvp);
	node = VP_TO_TMPFS_DIR(vp);

	/* Directories with more than two entries ('.' and '..') cannot be
	 * removed. */
	 if (node->tn_size > 0) {
		 error = ENOTEMPTY;
		 goto out;
	 }

	if ((dnode->tn_flags & APPEND)
	    || (node->tn_flags & (NOUNLINK | IMMUTABLE | APPEND))) {
		error = EPERM;
		goto out;
	}

	/* This invariant holds only if we are not trying to remove "..".
	  * We checked for that above so this is safe now. */
	KKASSERT(node->tn_dir.tn_parent == dnode);

	/* Get the directory entry associated with node (vp).  This was
	 * filled by tmpfs_lookup while looking up the entry. */
	de = tmpfs_dir_lookup(dnode, node, ncp);
	KKASSERT(TMPFS_DIRENT_MATCHES(de,
	    ncp->nc_name,
	    ncp->nc_nlen));

	/* Check flags to see if we are allowed to remove the directory. */
	if ((dnode->tn_flags & APPEND) ||
	    node->tn_flags & (NOUNLINK | IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}


	/* Detach the directory entry from the directory (dnode). */
	tmpfs_dir_detach(dnode, de);

	/* No vnode should be allocated for this entry from this point */
	TMPFS_NODE_LOCK(node);
	TMPFS_ASSERT_ELOCKED(node);
	TMPFS_NODE_LOCK(dnode);
	TMPFS_ASSERT_ELOCKED(dnode);

#if 0
	/* handled by tmpfs_free_node */
	KKASSERT(node->tn_links > 0);
	node->tn_links--;
	node->tn_dir.tn_parent = NULL;
#endif
	node->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	    TMPFS_NODE_MODIFIED;

#if 0
	/* handled by tmpfs_free_node */
	KKASSERT(dnode->tn_links > 0);
	dnode->tn_links--;
#endif
	dnode->tn_status |= TMPFS_NODE_ACCESSED | \
	    TMPFS_NODE_CHANGED | TMPFS_NODE_MODIFIED;

	TMPFS_NODE_UNLOCK(dnode);
	TMPFS_NODE_UNLOCK(node);

	/* Free the directory entry we just deleted.  Note that the node
	 * referred by it will not be removed until the vnode is really
	 * reclaimed. */
	tmpfs_free_dirent(tmp, de);

	/* Release the deleted vnode (will destroy the node, notify
	 * interested parties and clean it from the cache). */

	TMPFS_NODE_LOCK(dnode);
	dnode->tn_status |= TMPFS_NODE_CHANGED;
	TMPFS_NODE_UNLOCK(dnode);
	tmpfs_update(dvp);

	cache_setunresolved(v->a_nch);
	cache_setvp(v->a_nch, NULL);
	/*cache_inval_vp(vp, CINV_DESTROY);*/
	tmpfs_knote(dvp, NOTE_WRITE | NOTE_LINK);
	error = 0;

out:
	vrele(vp);

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_nsymlink(struct vop_nsymlink_args *v)
{
	struct vnode *dvp = v->a_dvp;
	struct vnode **vpp = v->a_vpp;
	struct namecache *ncp = v->a_nch->ncp;
	struct vattr *vap = v->a_vap;
	struct ucred *cred = v->a_cred;
	char *target = v->a_target;
	int error;

	vap->va_type = VLNK;
	error = tmpfs_alloc_file(dvp, vpp, vap, ncp, cred, target);
	if (error == 0) {
		tmpfs_knote(*vpp, NOTE_WRITE);
		cache_setunresolved(v->a_nch);
		cache_setvp(v->a_nch, *vpp);
	}

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_readdir(struct vop_readdir_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;
	int *eofflag = v->a_eofflag;
	off_t **cookies = v->a_cookies;
	int *ncookies = v->a_ncookies;
	struct tmpfs_mount *tmp;
	int error;
	off_t startoff;
	off_t cnt = 0;
	struct tmpfs_node *node;

	/* This operation only makes sense on directory nodes. */
	if (vp->v_type != VDIR)
		return ENOTDIR;

	tmp = VFS_TO_TMPFS(vp->v_mount);
	node = VP_TO_TMPFS_DIR(vp);
	startoff = uio->uio_offset;

	if (uio->uio_offset == TMPFS_DIRCOOKIE_DOT) {
		error = tmpfs_dir_getdotdent(node, uio);
		if (error != 0)
			goto outok;
		cnt++;
	}

	if (uio->uio_offset == TMPFS_DIRCOOKIE_DOTDOT) {
		error = tmpfs_dir_getdotdotdent(tmp, node, uio);
		if (error != 0)
			goto outok;
		cnt++;
	}

	error = tmpfs_dir_getdents(node, uio, &cnt);

outok:
	KKASSERT(error >= -1);

	if (error == -1)
		error = 0;

	if (eofflag != NULL)
		*eofflag =
		    (error == 0 && uio->uio_offset == TMPFS_DIRCOOKIE_EOF);

	/* Update NFS-related variables. */
	if (error == 0 && cookies != NULL && ncookies != NULL) {
		off_t i;
		off_t off = startoff;
		struct tmpfs_dirent *de = NULL;

		*ncookies = cnt;
		*cookies = kmalloc(cnt * sizeof(off_t), M_TEMP, M_WAITOK);

		for (i = 0; i < cnt; i++) {
			KKASSERT(off != TMPFS_DIRCOOKIE_EOF);
			if (off == TMPFS_DIRCOOKIE_DOT) {
				off = TMPFS_DIRCOOKIE_DOTDOT;
			} else {
				if (off == TMPFS_DIRCOOKIE_DOTDOT) {
					de = TAILQ_FIRST(&node->tn_dir.tn_dirhead);
				} else if (de != NULL) {
					de = TAILQ_NEXT(de, td_entries);
				} else {
					de = tmpfs_dir_lookupbycookie(node,
					    off);
					KKASSERT(de != NULL);
					de = TAILQ_NEXT(de, td_entries);
				}
				if (de == NULL)
					off = TMPFS_DIRCOOKIE_EOF;
				else
					off = tmpfs_dircookie(de);
			}

			(*cookies)[i] = off;
		}
		KKASSERT(uio->uio_offset == off);
	}

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_readlink(struct vop_readlink_args *v)
{
	struct vnode *vp = v->a_vp;
	struct uio *uio = v->a_uio;

	int error;
	struct tmpfs_node *node;

	KKASSERT(uio->uio_offset == 0);
	KKASSERT(vp->v_type == VLNK);

	node = VP_TO_TMPFS_NODE(vp);

	error = uiomove(node->tn_link, MIN(node->tn_size, uio->uio_resid),
	    uio);
	TMPFS_NODE_LOCK(node);
	node->tn_status |= TMPFS_NODE_ACCESSED;
	TMPFS_NODE_UNLOCK(node);

	return error;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_inactive(struct vop_inactive_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	/*
	 * Get rid of unreferenced deleted vnodes sooner rather than
	 * later so the data memory can be recovered immediately.
	 *
	 * We must truncate the vnode to prevent the normal reclamation
	 * path from flushing the data for the removed file to disk.
	 */
	TMPFS_NODE_LOCK(node);
	if ((node->tn_vpstate & TMPFS_VNODE_ALLOCATING) == 0 &&
	    (node->tn_links == 0 ||
	     (node->tn_links == 1 && node->tn_type == VDIR &&
	      node->tn_dir.tn_parent)))
	{
		node->tn_vpstate = TMPFS_VNODE_DOOMED;
		TMPFS_NODE_UNLOCK(node);
		if (node->tn_type == VREG)
			tmpfs_truncate(vp, 0);
		vrecycle(vp);
	} else {
		TMPFS_NODE_UNLOCK(node);
	}

	return 0;
}

/* --------------------------------------------------------------------- */

int
tmpfs_reclaim(struct vop_reclaim_args *v)
{
	struct vnode *vp = v->a_vp;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);
	tmp = VFS_TO_TMPFS(vp->v_mount);

	tmpfs_free_vp(vp);

	/*
	 * If the node referenced by this vnode was deleted by the
	 * user, we must free its associated data structures now that
	 * the vnode is being reclaimed.
	 *
	 * Directories have an extra link ref.
	 */
	TMPFS_NODE_LOCK(node);
	if ((node->tn_vpstate & TMPFS_VNODE_ALLOCATING) == 0 &&
	    (node->tn_links == 0 ||
	     (node->tn_links == 1 && node->tn_type == VDIR &&
	      node->tn_dir.tn_parent)))
	{
		node->tn_vpstate = TMPFS_VNODE_DOOMED;
		tmpfs_free_node(tmp, node);
		/* eats the lock */
	} else {
		TMPFS_NODE_UNLOCK(node);
	}

	KKASSERT(vp->v_data == NULL);
	return 0;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_print(struct vop_print_args *v)
{
	struct vnode *vp = v->a_vp;

	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	kprintf("tag VT_TMPFS, tmpfs_node %p, flags 0x%x, links %d\n",
	    node, node->tn_flags, node->tn_links);
	kprintf("\tmode 0%o, owner %d, group %d, size %ju, status 0x%x\n",
	    node->tn_mode, node->tn_uid, node->tn_gid,
	    (uintmax_t)node->tn_size, node->tn_status);

	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);

	kprintf("\n");

	return 0;
}

/* --------------------------------------------------------------------- */

static int
tmpfs_pathconf(struct vop_pathconf_args *v)
{
	int name = v->a_name;
	register_t *retval = v->a_retval;

	int error;

	error = 0;

	switch (name) {
	case _PC_LINK_MAX:
		*retval = LINK_MAX;
		break;

	case _PC_NAME_MAX:
		*retval = NAME_MAX;
		break;

	case _PC_PATH_MAX:
		*retval = PATH_MAX;
		break;

	case _PC_PIPE_BUF:
		*retval = PIPE_BUF;
		break;

	case _PC_CHOWN_RESTRICTED:
		*retval = 1;
		break;

	case _PC_NO_TRUNC:
		*retval = 1;
		break;

	case _PC_SYNC_IO:
		*retval = 1;
		break;

	case _PC_FILESIZEBITS:
		*retval = 0; /* XXX Don't know which value should I return. */
		break;

	default:
		error = EINVAL;
	}

	return error;
}

/************************************************************************
 *                          KQFILTER OPS                                *
 ************************************************************************/

static void filt_tmpfsdetach(struct knote *kn);
static int filt_tmpfsread(struct knote *kn, long hint);
static int filt_tmpfswrite(struct knote *kn, long hint);
static int filt_tmpfsvnode(struct knote *kn, long hint);

static struct filterops tmpfsread_filtops =
	{ FILTEROP_ISFD, NULL, filt_tmpfsdetach, filt_tmpfsread };
static struct filterops tmpfswrite_filtops =
	{ FILTEROP_ISFD, NULL, filt_tmpfsdetach, filt_tmpfswrite };
static struct filterops tmpfsvnode_filtops =
	{ FILTEROP_ISFD, NULL, filt_tmpfsdetach, filt_tmpfsvnode };

static int
tmpfs_kqfilter (struct vop_kqfilter_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct knote *kn = ap->a_kn;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &tmpfsread_filtops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &tmpfswrite_filtops;
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &tmpfsvnode_filtops;
		break;
	default:
		return (EOPNOTSUPP);
	}

	kn->kn_hook = (caddr_t)vp;

	knote_insert(&vp->v_pollinfo.vpi_kqinfo.ki_note, kn);

	return(0);
}

static void
filt_tmpfsdetach(struct knote *kn)
{
	struct vnode *vp = (void *)kn->kn_hook;

	knote_remove(&vp->v_pollinfo.vpi_kqinfo.ki_note, kn);
}

static int
filt_tmpfsread(struct knote *kn, long hint)
{
	struct vnode *vp = (void *)kn->kn_hook;
	struct tmpfs_node *node = VP_TO_TMPFS_NODE(vp);
	off_t off;

	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return(1);
	}

	/*
	 * Interlock against MP races when performing this function.
	 */
	lwkt_gettoken(&vp->v_mount->mnt_token);
	off = node->tn_size - kn->kn_fp->f_offset;
	kn->kn_data = (off < INTPTR_MAX) ? off : INTPTR_MAX;
	if (kn->kn_sfflags & NOTE_OLDAPI) {
		lwkt_reltoken(&vp->v_mount->mnt_token);
		return(1);
	}

	if (kn->kn_data == 0) {
		kn->kn_data = (off < INTPTR_MAX) ? off : INTPTR_MAX;
	}
	lwkt_reltoken(&vp->v_mount->mnt_token);
	return (kn->kn_data != 0);
}

static int
filt_tmpfswrite(struct knote *kn, long hint)
{
	if (hint == NOTE_REVOKE)
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
	kn->kn_data = 0;
	return (1);
}

static int
filt_tmpfsvnode(struct knote *kn, long hint)
{
	if (kn->kn_sfflags & hint)
		kn->kn_fflags |= hint;
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (kn->kn_fflags != 0);
}


/* --------------------------------------------------------------------- */

/*
 * vnode operations vector used for files stored in a tmpfs file system.
 */
struct vop_ops tmpfs_vnode_vops = {
	.vop_default =			vop_defaultop,
	.vop_getpages = 		vop_stdgetpages,
	.vop_putpages = 		vop_stdputpages,
	.vop_ncreate =			tmpfs_ncreate,
	.vop_nresolve =			tmpfs_nresolve,
	.vop_nlookupdotdot =		tmpfs_nlookupdotdot,
	.vop_nmknod =			tmpfs_nmknod,
	.vop_open =			tmpfs_open,
	.vop_close =			tmpfs_close,
	.vop_access =			tmpfs_access,
	.vop_getattr =			tmpfs_getattr,
	.vop_setattr =			tmpfs_setattr,
	.vop_read =			tmpfs_read,
	.vop_write =			tmpfs_write,
	.vop_fsync =			tmpfs_fsync,
	.vop_nremove =			tmpfs_nremove,
	.vop_nlink =			tmpfs_nlink,
	.vop_nrename =			tmpfs_nrename,
	.vop_nmkdir =			tmpfs_nmkdir,
	.vop_nrmdir =			tmpfs_nrmdir,
	.vop_nsymlink =			tmpfs_nsymlink,
	.vop_readdir =			tmpfs_readdir,
	.vop_readlink =			tmpfs_readlink,
	.vop_inactive =			tmpfs_inactive,
	.vop_reclaim =			tmpfs_reclaim,
	.vop_print =			tmpfs_print,
	.vop_pathconf =			tmpfs_pathconf,
	.vop_bmap =			tmpfs_bmap,
	.vop_strategy =			tmpfs_strategy,
	.vop_advlock =			tmpfs_advlock,
	.vop_kqfilter =			tmpfs_kqfilter
};
