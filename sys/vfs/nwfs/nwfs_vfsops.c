/*
 * Copyright (c) 1999, 2000 Boris Popov
 * All rights reserved.
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
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/nwfs/nwfs_vfsops.c,v 1.6.2.6 2001/10/25 19:18:54 dillon Exp $
 */

#ifndef KLD_MODULE
#include "opt_ncp.h"
#ifndef NCP
#error "NWFS requires NCP protocol"
#endif
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/buf.h>

#include <netproto/ncp/ncp.h>
#include <netproto/ncp/ncp_conn.h>
#include <netproto/ncp/ncp_subr.h>
#include <netproto/ncp/ncp_ncp.h>
#include <netproto/ncp/ncp_nls.h>

#include "nwfs.h"
#include "nwfs_node.h"
#include "nwfs_subr.h"

extern struct vop_ops nwfs_vnode_vops;

int nwfs_debuglevel = 0;

static int nwfs_version = NWFS_VERSION;

SYSCTL_DECL(_vfs_nwfs);
SYSCTL_NODE(_vfs, OID_AUTO, nwfs, CTLFLAG_RW, 0, "Netware file system");
SYSCTL_INT(_vfs_nwfs, OID_AUTO, version, CTLFLAG_RD, &nwfs_version, 0, "");
SYSCTL_INT(_vfs_nwfs, OID_AUTO, debuglevel, CTLFLAG_RW, &nwfs_debuglevel, 0, "");

static int nwfs_mount(struct mount *, char *, caddr_t, struct ucred *);
static int nwfs_root(struct mount *, struct vnode **);
static int nwfs_statfs(struct mount *, struct statfs *, struct ucred *);
static int nwfs_sync(struct mount *, int);
static int nwfs_unmount(struct mount *, int);
static int nwfs_init(struct vfsconf *vfsp);
static int nwfs_uninit(struct vfsconf *vfsp);

static struct vfsops nwfs_vfsops = {
	.vfs_mount =    	nwfs_mount,
	.vfs_unmount =   	nwfs_unmount,
	.vfs_root =     	nwfs_root,
	.vfs_statfs =    	nwfs_statfs,
	.vfs_sync =    		nwfs_sync,
	.vfs_init =    		nwfs_init,
	.vfs_uninit =    	nwfs_uninit
};


VFS_SET(nwfs_vfsops, nwfs, VFCF_NETWORK);
MODULE_VERSION(nwfs, 1);
MODULE_DEPEND(nwfs, ncp, 1, 1, 1);

int nwfs_pbuf_freecnt = -1;	/* start out unlimited */
static int nwfsid = 1;

static int
nwfs_initnls(struct nwmount *nmp) {
	char	*pc, *pe;
	int	error = 0;
#define COPY_TABLE(t,d)	{ \
		if (t) { \
			error = copyin((t), pc, 256); \
			if (error) break; \
		} else \
			bcopy(d, pc, 256); \
		(t) = pc; pc += 256; \
	}

	nmp->m.nls.opt |= NWHP_NLS | NWHP_DOS;
	if ((nmp->m.flags & NWFS_MOUNT_HAVE_NLS) == 0) {
		nmp->m.nls.to_lower = ncp_defnls.to_lower;
		nmp->m.nls.to_upper = ncp_defnls.to_upper;
		nmp->m.nls.n2u = ncp_defnls.n2u;
		nmp->m.nls.u2n = ncp_defnls.u2n;
		return 0;
	}
	pe = kmalloc(256 * 4, M_NWFSDATA, M_WAITOK);
	pc = pe;
	do {
		COPY_TABLE(nmp->m.nls.to_lower, ncp_defnls.to_lower);
		COPY_TABLE(nmp->m.nls.to_upper, ncp_defnls.to_upper);
		COPY_TABLE(nmp->m.nls.n2u, ncp_defnls.n2u);
		COPY_TABLE(nmp->m.nls.u2n, ncp_defnls.u2n);
	} while(0);
	if (error) {
		kfree(pe, M_NWFSDATA);
		return error;
	}
	return 0;
}
/*
 * mp - path - addr in user space of mount point (ie /usr or whatever)
 * data - addr in user space of mount params 
 */
static int
nwfs_mount(struct mount *mp, char *path, caddr_t data, struct ucred *cred)
{
	struct nwfs_args args; 	  /* will hold data from mount request */
	int error;
	struct nwmount *nmp = NULL;
	struct ncp_conn *conn = NULL;
	struct ncp_handle *handle = NULL;
	struct vnode *vp;
	char *pc,*pe;

	if (data == NULL) {
		nwfs_printf("missing data argument\n");
		return 1;
	}
	if (mp->mnt_flag & MNT_UPDATE) {
		nwfs_printf("MNT_UPDATE not implemented");
		return (EOPNOTSUPP);
	}
	error = copyin(data, (caddr_t)&args, sizeof(struct nwfs_args));
	if (error)
		return (error);
	if (args.version != NWFS_VERSION) {
		nwfs_printf("mount version mismatch: kernel=%d, mount=%d\n",NWFS_VERSION,args.version);
		return (1);
	}
	error = ncp_conn_getbyref(args.connRef,curthread,cred,NCPM_EXECUTE,&conn);
	if (error) {
		nwfs_printf("invalid connection reference %d\n",args.connRef);
		return (error);
	}
	error = ncp_conn_gethandle(conn, NULL, &handle);
	if (error) {
		nwfs_printf("can't get connection handle\n");
		return (error);
	}
	ncp_conn_unlock(conn,curthread);	/* we keep the ref */
	mp->mnt_stat.f_iosize = conn->buffer_size;
        /* We must malloc our own mount info */
        nmp = kmalloc(sizeof(struct nwmount), M_NWFSDATA,
		      M_WAITOK | M_USE_RESERVE | M_ZERO);
        mp->mnt_data = (qaddr_t)nmp;
	nmp->connh = handle;
	nmp->n_root = NULL;
	nmp->n_id = nwfsid++;
        nmp->m = args;
	nmp->m.file_mode = (nmp->m.file_mode &
			    (S_IRWXU|S_IRWXG|S_IRWXO)) | S_IFREG;
	nmp->m.dir_mode  = (nmp->m.dir_mode &
			    (S_IRWXU|S_IRWXG|S_IRWXO)) | S_IFDIR;
	if ((error = nwfs_initnls(nmp)) != 0) goto bad;
	pc = mp->mnt_stat.f_mntfromname;
	pe = pc+sizeof(mp->mnt_stat.f_mntfromname);
	bzero(pc, MNAMELEN);
	*(pc++) = '/';
	pc = index(strncpy(pc, conn->li.server, pe-pc-2),0);
	if (pc < pe-1) {
		*(pc++) = ':';
		pc=index(strncpy(pc, conn->li.user, pe-pc-2),0);
		if (pc < pe-1) {
			*(pc++) = '/';
			strncpy(pc, nmp->m.mounted_vol, pe-pc-2);
		}
	}
	/* protect against invalid mount points */
	nmp->m.mount_point[sizeof(nmp->m.mount_point)-1] = '\0';

	vfs_add_vnodeops(mp, &nwfs_vnode_vops, &mp->mnt_vn_norm_ops);

	vfs_getnewfsid(mp);
	error = nwfs_root(mp, &vp);
	if (error)
		goto bad;
	/*
	 * Lose the lock but keep the ref.
	 */
	vn_unlock(vp);
	NCPVODEBUG("rootvp.vrefcnt=%d\n",vp->v_sysref.refcnt);
	return error;
bad:
        if (nmp)
		kfree(nmp, M_NWFSDATA);
	if (handle)
		ncp_conn_puthandle(handle, NULL, 0);
        return error;
}

/* Unmount the filesystem described by mp. */
static int
nwfs_unmount(struct mount *mp, int mntflags)
{
	struct nwmount *nmp = VFSTONWFS(mp);
	struct ncp_conn *conn;
	int error, flags;

	NCPVODEBUG("nwfs_unmount: flags=%04x\n",mntflags);
	flags = 0;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	/* There is 1 extra root vnode reference from nwfs_mount(). */
	error = vflush(mp, 1, flags);
	if (error)
		return (error);
	conn = NWFSTOCONN(nmp);
	ncp_conn_puthandle(nmp->connh,NULL,0);
	if (ncp_conn_lock(conn, curthread, proc0.p_ucred, NCPM_WRITE | NCPM_EXECUTE) == 0) {
		if(ncp_disconnect(conn))
			ncp_conn_unlock(conn, curthread);
	}
	mp->mnt_data = (qaddr_t)0;
	if (nmp->m.flags & NWFS_MOUNT_HAVE_NLS)
		kfree(nmp->m.nls.to_lower, M_NWFSDATA);
	kfree(nmp, M_NWFSDATA);
	mp->mnt_flag &= ~MNT_LOCAL;
	return (error);
}

/*  Return locked vnode to root of a filesystem */
static int
nwfs_root(struct mount *mp, struct vnode **vpp)
{
	struct vnode *vp;
	struct nwmount *nmp;
	struct nwnode *np;
	struct ncp_conn *conn;
	struct nw_entry_info fattr;
	struct thread *td = curthread;	/* XXX */
	struct ucred *cred;
	int error, nsf, opt;
	u_char vol;

	KKASSERT(td->td_proc);
	cred = td->td_proc->p_ucred;

	nmp = VFSTONWFS(mp);
	conn = NWFSTOCONN(nmp);
	if (nmp->n_root) {
		*vpp = NWTOV(nmp->n_root);
		while (vget(*vpp, LK_EXCLUSIVE) != 0) /* XXX */
			;
		return 0;
	}
	error = ncp_lookup_volume(conn, nmp->m.mounted_vol, &vol, 
		&nmp->n_rootent.f_id, td, cred);
	if (error)
		return ENOENT;
	nmp->n_volume = vol;
	error = ncp_get_namespaces(conn, vol, &nsf, td, cred);
	if (error)
		return ENOENT;
	if (nsf & NW_NSB_OS2) {
		NCPVODEBUG("volume %s has os2 namespace\n",nmp->m.mounted_vol);
		if ((nmp->m.flags & NWFS_MOUNT_NO_OS2) == 0) {
			nmp->name_space = NW_NS_OS2;
			nmp->m.nls.opt &= ~NWHP_DOS;
		}
	}
	opt = nmp->m.nls.opt;
	nsf = opt & (NWHP_UPPER | NWHP_LOWER);
	if (opt & NWHP_DOS) {
		if (nsf == (NWHP_UPPER | NWHP_LOWER)) {
			nmp->m.nls.opt &= ~(NWHP_LOWER | NWHP_UPPER);
		} else if (nsf == 0) {
			nmp->m.nls.opt |= NWHP_LOWER;
		}
	} else {
		if (nsf == (NWHP_UPPER | NWHP_LOWER)) {
			nmp->m.nls.opt &= ~(NWHP_LOWER | NWHP_UPPER);
		}
	}
	if (nmp->m.root_path[0]) {
		nmp->m.root_path[0]--;
		error = ncp_obtain_info(nmp, nmp->n_rootent.f_id,
		    -nmp->m.root_path[0], nmp->m.root_path, &fattr, td, cred);
		if (error) {
			NCPFATAL("Invalid root path specified\n");
			return ENOENT;
		}
		nmp->n_rootent.f_parent = fattr.dirEntNum;
		nmp->m.root_path[0]++;
		error = ncp_obtain_info(nmp, nmp->n_rootent.f_id,
		    -nmp->m.root_path[0], nmp->m.root_path, &fattr, td, cred);
		if (error) {
			NCPFATAL("Invalid root path specified\n");
			return ENOENT;
		}
		nmp->n_rootent.f_id = fattr.dirEntNum;
	} else {
		error = ncp_obtain_info(nmp, nmp->n_rootent.f_id,
		    0, NULL, &fattr, td, cred);
		if (error) {
			NCPFATAL("Can't obtain volume info\n");
			return ENOENT;
		}
		fattr.nameLen = strlen(strcpy(fattr.entryName, NWFS_ROOTVOL));
		nmp->n_rootent.f_parent = nmp->n_rootent.f_id;
	}
	error = nwfs_nget(mp, nmp->n_rootent, &fattr, NULL, &vp);
	if (error)
		return (error);
	vsetflags(vp, VROOT);
	np = VTONW(vp);
	if (nmp->m.root_path[0] == 0)
		np->n_flag |= NVOLUME;
	nmp->n_root = np;
/*	error = VOP_GETATTR(vp, &vattr);
	if (error) {
		vput(vp);
		NCPFATAL("Can't get root directory entry\n");
		return error;
	}*/
	*vpp = vp;
	return (0);
}

/*ARGSUSED*/
int
nwfs_init(struct vfsconf *vfsp)
{
#ifndef SMP
	if (ncpus > 1)
		kprintf("warning: nwfs module compiled without SMP support.");
#endif
	nwfs_hash_init();
	nwfs_pbuf_freecnt = nswbuf / 2 + 1;
	NCPVODEBUG("always happy to load!\n");
	return (0);
}

/*ARGSUSED*/
int
nwfs_uninit(struct vfsconf *vfsp)
{

	nwfs_hash_free();
	NCPVODEBUG("unloaded\n");
	return (0);
}

/*
 * nwfs_statfs call
 */
int
nwfs_statfs(struct mount *mp, struct statfs *sbp, struct ucred *cred)
{
	struct nwmount *nmp = VFSTONWFS(mp);
	int error = 0, secsize;
	struct nwnode *np = nmp->n_root;
	struct ncp_volume_info vi;

	if (np == NULL) return EINVAL;
	error = ncp_get_volume_info_with_number(NWFSTOCONN(nmp), nmp->n_volume,
						&vi, curthread, cred);
	if (error) return error;
	secsize = 512;			/* XXX how to get real value ??? */
	sbp->f_spare2=0;		/* placeholder */
	/* fundamental file system block size */
	sbp->f_bsize = vi.sectors_per_block*secsize;
	/* optimal transfer block size */
	sbp->f_iosize = NWFSTOCONN(nmp)->buffer_size;
	/* total data blocks in file system */
	sbp->f_blocks= vi.total_blocks;
	/* free blocks in fs */
	sbp->f_bfree = vi.free_blocks + vi.purgeable_blocks;
	/* free blocks avail to non-superuser */
	sbp->f_bavail= vi.free_blocks+vi.purgeable_blocks;
	/* total file nodes in file system */
	sbp->f_files = vi.total_dir_entries;
	/* free file nodes in fs */
	sbp->f_ffree = vi.available_dir_entries;
	sbp->f_flags = 0;		/* copy of mount exported flags */
	if (sbp != &mp->mnt_stat) {
		sbp->f_fsid = mp->mnt_stat.f_fsid;	/* file system id */
		sbp->f_owner = mp->mnt_stat.f_owner;	/* user that mounted the filesystem */
		sbp->f_type = mp->mnt_vfc->vfc_typenum;	/* type of filesystem */
		bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
	}
	strncpy(sbp->f_fstypename, mp->mnt_vfc->vfc_name, MFSNAMELEN);
	return 0;
}

/*
 * Flush out the buffer cache
 */
/* ARGSUSED */
static int
nwfs_sync(struct mount *mp, int waitfor)
{
	struct vnode *vp;
	int error, allerror = 0;
	/*
	 * Force stale buffer cache information to be flushed.
	 */
loop:
	for (vp = TAILQ_FIRST(&mp->mnt_nvnodelist);
	     vp != NULL;
	     vp = TAILQ_NEXT(vp, v_nmntvnodes)) {
		/*
		 * If the vnode that we are about to sync is no longer
		 * associated with this mount point, start over.
		 */
		if (vp->v_mount != mp)
			goto loop;
		if (vn_islocked(vp) || RB_EMPTY(&vp->v_rbdirty_tree) ||
		    (waitfor & MNT_LAZY))
			continue;
		if (vget(vp, LK_EXCLUSIVE))
			goto loop;
		/* XXX vp may not be retained */
		error = VOP_FSYNC(vp, waitfor, 0);
		if (error)
			allerror = error;
		vput(vp);
	}
	return (allerror);
}
