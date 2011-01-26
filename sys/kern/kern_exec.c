/*
 * Copyright (c) 1993, David Greenman
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
 * $FreeBSD: src/sys/kern/kern_exec.c,v 1.107.2.15 2002/07/30 15:40:46 nectar Exp $
 * $DragonFly: src/sys/kern/kern_exec.c,v 1.64 2008/10/26 04:29:19 sephe Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/acct.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kern_syscall.h>
#include <sys/wait.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/ktrace.h>
#include <sys/signalvar.h>
#include <sys/pioctl.h>
#include <sys/nlookup.h>
#include <sys/sysent.h>
#include <sys/shm.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vmmeter.h>
#include <sys/aio.h>
#include <sys/libkern.h>

#include <cpu/lwbuf.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vnode_pager.h>
#include <vm/vm_pager.h>

#include <sys/user.h>
#include <sys/reg.h>

#include <sys/thread2.h>
#include <sys/mplock2.h>

MALLOC_DEFINE(M_PARGS, "proc-args", "Process arguments");
MALLOC_DEFINE(M_EXECARGS, "exec-args", "Exec arguments");

static register_t *exec_copyout_strings (struct image_params *);

/* XXX This should be vm_size_t. */
static u_long ps_strings = PS_STRINGS;
SYSCTL_ULONG(_kern, KERN_PS_STRINGS, ps_strings, CTLFLAG_RD, &ps_strings, 0, "");

/* XXX This should be vm_size_t. */
static u_long usrstack = USRSTACK;
SYSCTL_ULONG(_kern, KERN_USRSTACK, usrstack, CTLFLAG_RD, &usrstack, 0, "");

u_long ps_arg_cache_limit = PAGE_SIZE / 16;
SYSCTL_LONG(_kern, OID_AUTO, ps_arg_cache_limit, CTLFLAG_RW, 
    &ps_arg_cache_limit, 0, "");

int ps_argsopen = 1;
SYSCTL_INT(_kern, OID_AUTO, ps_argsopen, CTLFLAG_RW, &ps_argsopen, 0, "");

static int ktrace_suid = 0;
SYSCTL_INT(_kern, OID_AUTO, ktrace_suid, CTLFLAG_RW, &ktrace_suid, 0, "");

void print_execve_args(struct image_args *args);
int debug_execve_args = 0;
SYSCTL_INT(_kern, OID_AUTO, debug_execve_args, CTLFLAG_RW, &debug_execve_args,
    0, "");

/*
 * Exec arguments object cache
 */
static struct objcache *exec_objcache;

static
void
exec_objcache_init(void *arg __unused)
{
	int cluster_limit;

	cluster_limit = 16;	/* up to this many objects */
	exec_objcache = objcache_create_mbacked(
					M_EXECARGS, PATH_MAX + ARG_MAX,
					&cluster_limit,
					2,	/* minimal magazine capacity */
					NULL, NULL, NULL);
}
SYSINIT(exec_objcache, SI_BOOT2_MACHDEP, SI_ORDER_ANY, exec_objcache_init, 0);

/*
 * stackgap_random specifies if the stackgap should have a random size added
 * to it.  It must be a power of 2.  If non-zero, the stack gap will be 
 * calculated as: ALIGN(karc4random() & (stackgap_random - 1)).
 */
static int stackgap_random = 1024;
static int
sysctl_kern_stackgap(SYSCTL_HANDLER_ARGS)
{
	int error, new_val;
	new_val = stackgap_random;
	error = sysctl_handle_int(oidp, &new_val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if ((new_val < 0) || (new_val > 16 * PAGE_SIZE) || ! powerof2(new_val))
		return (EINVAL);
	stackgap_random = new_val;

	return(0);
}

SYSCTL_PROC(_kern, OID_AUTO, stackgap_random, CTLFLAG_RW|CTLTYPE_UINT, 
	0, 0, sysctl_kern_stackgap, "IU", "Max random stack gap (power of 2)");
	
void
print_execve_args(struct image_args *args)
{
	char *cp;
	int ndx;

	cp = args->begin_argv;
	for (ndx = 0; ndx < args->argc; ndx++) {
		kprintf("\targv[%d]: %s\n", ndx, cp);
		while (*cp++ != '\0');
	}
	for (ndx = 0; ndx < args->envc; ndx++) {
		kprintf("\tenvv[%d]: %s\n", ndx, cp);
		while (*cp++ != '\0');
	}
}

/*
 * Each of the items is a pointer to a `const struct execsw', hence the
 * double pointer here.
 */
static const struct execsw **execsw;

/*
 * Replace current vmspace with a new binary.
 * Returns 0 on success, > 0 on recoverable error (use as errno).
 * Returns -1 on lethal error which demands killing of the current
 * process!
 */
int
kern_execve(struct nlookupdata *nd, struct image_args *args)
{
	struct thread *td = curthread;
	struct lwp *lp = td->td_lwp;
	struct proc *p = td->td_proc;
	register_t *stack_base;
	int error, len, i;
	struct image_params image_params, *imgp;
	struct vattr attr;
	int (*img_first) (struct image_params *);

	if (debug_execve_args) {
		kprintf("%s()\n", __func__);
		print_execve_args(args);
	}

	KKASSERT(p);
	imgp = &image_params;

	/*
	 * NOTE: P_INEXEC is handled by exec_new_vmspace() now.  We make
	 * no modifications to the process at all until we get there.
	 *
	 * Note that multiple threads may be trying to exec at the same
	 * time.  exec_new_vmspace() handles that too.
	 */

	/*
	 * Initialize part of the common data
	 */
	imgp->proc = p;
	imgp->args = args;
	imgp->attr = &attr;
	imgp->entry_addr = 0;
	imgp->resident = 0;
	imgp->vmspace_destroyed = 0;
	imgp->interpreted = 0;
	imgp->interpreter_name[0] = 0;
	imgp->auxargs = NULL;
	imgp->vp = NULL;
	imgp->firstpage = NULL;
	imgp->ps_strings = 0;
	imgp->image_header = NULL;

interpret:

	/*
	 * Translate the file name to a vnode.  Unlock the cache entry to
	 * improve parallelism for programs exec'd in parallel.
	 */
	if ((error = nlookup(nd)) != 0)
		goto exec_fail;
	error = cache_vget(&nd->nl_nch, nd->nl_cred, LK_EXCLUSIVE, &imgp->vp);
	KKASSERT(nd->nl_flags & NLC_NCPISLOCKED);
	nd->nl_flags &= ~NLC_NCPISLOCKED;
	cache_unlock(&nd->nl_nch);
	if (error)
		goto exec_fail;

	/*
	 * Check file permissions (also 'opens' file).
	 * Include also the top level mount in the check.
	 */
	error = exec_check_permissions(imgp, nd->nl_nch.mount);
	if (error) {
		vn_unlock(imgp->vp);
		goto exec_fail_dealloc;
	}

	error = exec_map_first_page(imgp);
	vn_unlock(imgp->vp);
	if (error)
		goto exec_fail_dealloc;

	if (debug_execve_args && imgp->interpreted) {
		kprintf("    target is interpreted -- recursive pass\n");
		kprintf("    interpreter: %s\n", imgp->interpreter_name);
		print_execve_args(args);
	}

	/*
	 *	If the current process has a special image activator it
	 *	wants to try first, call it.   For example, emulating shell 
	 *	scripts differently.
	 */
	error = -1;
	if ((img_first = imgp->proc->p_sysent->sv_imgact_try) != NULL)
		error = img_first(imgp);

	/*
	 *	If the vnode has a registered vmspace, exec the vmspace
	 */
	if (error == -1 && imgp->vp->v_resident) {
		error = exec_resident_imgact(imgp);
	}

	/*
	 *	Loop through the list of image activators, calling each one.
	 *	An activator returns -1 if there is no match, 0 on success,
	 *	and an error otherwise.
	 */
	for (i = 0; error == -1 && execsw[i]; ++i) {
		if (execsw[i]->ex_imgact == NULL ||
		    execsw[i]->ex_imgact == img_first) {
			continue;
		}
		error = (*execsw[i]->ex_imgact)(imgp);
	}

	if (error) {
		if (error == -1)
			error = ENOEXEC;
		goto exec_fail_dealloc;
	}

	/*
	 * Special interpreter operation, cleanup and loop up to try to
	 * activate the interpreter.
	 */
	if (imgp->interpreted) {
		exec_unmap_first_page(imgp);
		nlookup_done(nd);
		vrele(imgp->vp);
		imgp->vp = NULL;
		error = nlookup_init(nd, imgp->interpreter_name, UIO_SYSSPACE,
					NLC_FOLLOW);
		if (error)
			goto exec_fail;
		goto interpret;
	}

	/*
	 * Copy out strings (args and env) and initialize stack base
	 */
	stack_base = exec_copyout_strings(imgp);
	p->p_vmspace->vm_minsaddr = (char *)stack_base;

	/*
	 * If custom stack fixup routine present for this process
	 * let it do the stack setup.  If we are running a resident
	 * image there is no auxinfo or other image activator context
	 * so don't try to add fixups to the stack.
	 *
	 * Else stuff argument count as first item on stack
	 */
	if (p->p_sysent->sv_fixup && imgp->resident == 0)
		(*p->p_sysent->sv_fixup)(&stack_base, imgp);
	else
		suword(--stack_base, imgp->args->argc);

	/*
	 * For security and other reasons, the file descriptor table cannot
	 * be shared after an exec.
	 */
	if (p->p_fd->fd_refcnt > 1) {
		struct filedesc *tmp;

		tmp = fdcopy(p);
		fdfree(p, tmp);
	}

	/*
	 * For security and other reasons, signal handlers cannot
	 * be shared after an exec. The new proces gets a copy of the old
	 * handlers. In execsigs(), the new process will have its signals
	 * reset.
	 */
	if (p->p_sigacts->ps_refcnt > 1) {
		struct sigacts *newsigacts;

		newsigacts = (struct sigacts *)kmalloc(sizeof(*newsigacts),
		       M_SUBPROC, M_WAITOK);
		bcopy(p->p_sigacts, newsigacts, sizeof(*newsigacts));
		p->p_sigacts->ps_refcnt--;
		p->p_sigacts = newsigacts;
		p->p_sigacts->ps_refcnt = 1;
	}

	/*
	 * For security and other reasons virtual kernels cannot be
	 * inherited by an exec.  This also allows a virtual kernel
	 * to fork/exec unrelated applications.
	 */
	if (p->p_vkernel)
		vkernel_exit(p);

	/* Stop profiling */
	stopprofclock(p);

	/* close files on exec */
	fdcloseexec(p);

	/* reset caught signals */
	execsigs(p);

	/* name this process - nameiexec(p, ndp) */
	len = min(nd->nl_nch.ncp->nc_nlen, MAXCOMLEN);
	bcopy(nd->nl_nch.ncp->nc_name, p->p_comm, len);
	p->p_comm[len] = 0;
	bcopy(p->p_comm, lp->lwp_thread->td_comm, MAXCOMLEN+1);

	/*
	 * mark as execed, wakeup the process that vforked (if any) and tell
	 * it that it now has its own resources back
	 */
	p->p_flag |= P_EXEC;
	if (p->p_pptr && (p->p_flag & P_PPWAIT)) {
		p->p_flag &= ~P_PPWAIT;
		wakeup((caddr_t)p->p_pptr);
	}

	/*
	 * Implement image setuid/setgid.
	 *
	 * Don't honor setuid/setgid if the filesystem prohibits it or if
	 * the process is being traced.
	 */
	if ((((attr.va_mode & VSUID) && p->p_ucred->cr_uid != attr.va_uid) ||
	     ((attr.va_mode & VSGID) && p->p_ucred->cr_gid != attr.va_gid)) &&
	    (imgp->vp->v_mount->mnt_flag & MNT_NOSUID) == 0 &&
	    (p->p_flag & P_TRACED) == 0) {
		/*
		 * Turn off syscall tracing for set-id programs, except for
		 * root.  Record any set-id flags first to make sure that
		 * we do not regain any tracing during a possible block.
		 */
		setsugid();
		if (p->p_tracenode && ktrace_suid == 0 &&
		    priv_check(td, PRIV_ROOT) != 0) {
			ktrdestroy(&p->p_tracenode);
			p->p_traceflag = 0;
		}
		/* Close any file descriptors 0..2 that reference procfs */
		setugidsafety(p);
		/* Make sure file descriptors 0..2 are in use. */
		error = fdcheckstd(lp);
		if (error != 0)
			goto exec_fail_dealloc;
		/*
		 * Set the new credentials.
		 */
		cratom(&p->p_ucred);
		if (attr.va_mode & VSUID)
			change_euid(attr.va_uid);
		if (attr.va_mode & VSGID)
			p->p_ucred->cr_gid = attr.va_gid;

		/*
		 * Clear local varsym variables
		 */
		varsymset_clean(&p->p_varsymset);
	} else {
		if (p->p_ucred->cr_uid == p->p_ucred->cr_ruid &&
		    p->p_ucred->cr_gid == p->p_ucred->cr_rgid)
			p->p_flag &= ~P_SUGID;
	}

	/*
	 * Implement correct POSIX saved-id behavior.
	 */
	if (p->p_ucred->cr_svuid != p->p_ucred->cr_uid ||
	    p->p_ucred->cr_svgid != p->p_ucred->cr_gid) {
		cratom(&p->p_ucred);
		p->p_ucred->cr_svuid = p->p_ucred->cr_uid;
		p->p_ucred->cr_svgid = p->p_ucred->cr_gid;
	}

	/*
	 * Store the vp for use in procfs
	 */
	if (p->p_textvp)		/* release old reference */
		vrele(p->p_textvp);
	p->p_textvp = imgp->vp;
	vref(p->p_textvp);

	/* Release old namecache handle to text file */
	if (p->p_textnch.ncp)
		cache_drop(&p->p_textnch);

	if (nd->nl_nch.mount)
		cache_copy(&nd->nl_nch, &p->p_textnch);

        /*
         * Notify others that we exec'd, and clear the P_INEXEC flag
         * as we're now a bona fide freshly-execed process.
         */
	KNOTE(&p->p_klist, NOTE_EXEC);
	p->p_flag &= ~P_INEXEC;

	/*
	 * If tracing the process, trap to debugger so breakpoints
	 * 	can be set before the program executes.
	 */
	STOPEVENT(p, S_EXEC, 0);

	if (p->p_flag & P_TRACED)
		ksignal(p, SIGTRAP);

	/* clear "fork but no exec" flag, as we _are_ execing */
	p->p_acflag &= ~AFORK;

	/* Set values passed into the program in registers. */
	exec_setregs(imgp->entry_addr, (u_long)(uintptr_t)stack_base,
	    imgp->ps_strings);

	/* Set the access time on the vnode */
	vn_mark_atime(imgp->vp, td);

	/* Free any previous argument cache */
	if (p->p_args && --p->p_args->ar_ref == 0)
		FREE(p->p_args, M_PARGS);
	p->p_args = NULL;

	/* Cache arguments if they fit inside our allowance */
	i = imgp->args->begin_envv - imgp->args->begin_argv;
	if (ps_arg_cache_limit >= i + sizeof(struct pargs)) {
		MALLOC(p->p_args, struct pargs *, sizeof(struct pargs) + i, 
		    M_PARGS, M_WAITOK);
		p->p_args->ar_ref = 1;
		p->p_args->ar_length = i;
		bcopy(imgp->args->begin_argv, p->p_args->ar_args, i);
	}

exec_fail_dealloc:

	/*
	 * free various allocated resources
	 */
	if (imgp->firstpage)
		exec_unmap_first_page(imgp);

	if (imgp->vp) {
		vrele(imgp->vp);
		imgp->vp = NULL;
	}

	if (error == 0) {
		++mycpu->gd_cnt.v_exec;
		return (0);
	}

exec_fail:
	/*
	 * we're done here, clear P_INEXEC if we were the ones that
	 * set it.  Otherwise if vmspace_destroyed is still set we
	 * raced another thread and that thread is responsible for
	 * clearing it.
	 */
	if (imgp->vmspace_destroyed & 2)
		p->p_flag &= ~P_INEXEC;
	if (imgp->vmspace_destroyed) {
		/*
		 * Sorry, no more process anymore. exit gracefully.
		 * However we can't die right here, because our
		 * caller might have to clean up, so indicate a
		 * lethal error by returning -1.
		 */
		return(-1);
	} else {
		return(error);
	}
}

/*
 * execve() system call.
 *
 * MPALMOSTSAFE
 */
int
sys_execve(struct execve_args *uap)
{
	struct nlookupdata nd;
	struct image_args args;
	int error;

	bzero(&args, sizeof(args));

	get_mplock();
	error = nlookup_init(&nd, uap->fname, UIO_USERSPACE, NLC_FOLLOW);
	if (error == 0) {
		error = exec_copyin_args(&args, uap->fname, PATH_USERSPACE,
					uap->argv, uap->envv);
	}
	if (error == 0)
		error = kern_execve(&nd, &args);
	nlookup_done(&nd);
	exec_free_args(&args);

	if (error < 0) {
		/* We hit a lethal error condition.  Let's die now. */
		exit1(W_EXITCODE(0, SIGABRT));
		/* NOTREACHED */
	}
	rel_mplock();

	/*
	 * The syscall result is returned in registers to the new program.
	 * Linux will register %edx as an atexit function and we must be
	 * sure to set it to 0.  XXX
	 */
	if (error == 0)
		uap->sysmsg_result64 = 0;

	return (error);
}

int
exec_map_page(struct image_params *imgp, vm_pindex_t pageno,
	      struct lwbuf **plwb, const char **pdata)
{
	int rv;
	vm_page_t ma;
	vm_page_t m;
	vm_object_t object;

	/*
	 * The file has to be mappable.
	 */
	if ((object = imgp->vp->v_object) == NULL)
		return (EIO);

	if (pageno >= object->size)
		return (EIO);

	m = vm_page_grab(object, pageno, VM_ALLOC_NORMAL | VM_ALLOC_RETRY);

	lwkt_gettoken(&vm_token);
	while ((m->valid & VM_PAGE_BITS_ALL) != VM_PAGE_BITS_ALL) {
		ma = m;

		/*
		 * get_pages unbusies all the requested pages except the
		 * primary page (at index 0 in this case).  The primary
		 * page may have been wired during the pagein (e.g. by
		 * the buffer cache) so vnode_pager_freepage() must be
		 * used to properly release it.
		 */
		rv = vm_pager_get_page(object, &ma, 1, -1);
		m = vm_page_lookup(object, pageno);

		if (rv != VM_PAGER_OK || m == NULL || m->valid == 0) {
			if (m) {
				vm_page_protect(m, VM_PROT_NONE);
				vnode_pager_freepage(m);
			}
			lwkt_reltoken(&vm_token);
			return EIO;
		}
	}
	vm_page_hold(m);	/* requires vm_token to be held */
	vm_page_wakeup(m);	/* unbusy the page */
	lwkt_reltoken(&vm_token);

	*plwb = lwbuf_alloc(m, *plwb);
	*pdata = (void *)lwbuf_kva(*plwb);

	return (0);
}

int
exec_map_first_page(struct image_params *imgp)
{
	int err;

	if (imgp->firstpage)
		exec_unmap_first_page(imgp);

	imgp->firstpage = &imgp->firstpage_cache;
	err = exec_map_page(imgp, 0, &imgp->firstpage, &imgp->image_header);

	if (err)
		return err;

	return 0;
}

void
exec_unmap_page(struct lwbuf *lwb)
{
	vm_page_t m;

	crit_enter();
	if (lwb != NULL) {
		m = lwbuf_page(lwb);
		lwbuf_free(lwb);
		vm_page_unhold(m);
	}
	crit_exit();
}

void
exec_unmap_first_page(struct image_params *imgp)
{
	exec_unmap_page(imgp->firstpage);
	imgp->firstpage = NULL;
	imgp->image_header = NULL;
}

/*
 * Destroy old address space, and allocate a new stack
 *	The new stack is only SGROWSIZ large because it is grown
 *	automatically in trap.c.
 *
 * This is the point of no return.
 */
int
exec_new_vmspace(struct image_params *imgp, struct vmspace *vmcopy)
{
	struct vmspace *vmspace = imgp->proc->p_vmspace;
	vm_offset_t stack_addr = USRSTACK - maxssiz;
	struct proc *p;
	vm_map_t map;
	int error;

	/*
	 * Indicate that we cannot gracefully error out any more, kill
	 * any other threads present, and set P_INEXEC to indicate that
	 * we are now messing with the process structure proper.
	 *
	 * If killalllwps() races return an error which coupled with
	 * vmspace_destroyed will cause us to exit.  This is what we
	 * want since another thread is patiently waiting for us to exit
	 * in that case.
	 */
	p = curproc;
	imgp->vmspace_destroyed = 1;

	if (curthread->td_proc->p_nthreads > 1) {
		error = killalllwps(1);
		if (error)
			return (error);
	}
	imgp->vmspace_destroyed |= 2;	/* we are responsible for P_INEXEC */
	p->p_flag |= P_INEXEC;

	/*
	 * Prevent a pending AIO from modifying the new address space.
	 */
	aio_proc_rundown(imgp->proc);

	/*
	 * Blow away entire process VM, if address space not shared,
	 * otherwise, create a new VM space so that other threads are
	 * not disrupted.  If we are execing a resident vmspace we
	 * create a duplicate of it and remap the stack.
	 *
	 * The exitingcnt test is not strictly necessary but has been
	 * included for code sanity (to make the code more deterministic).
	 */
	map = &vmspace->vm_map;
	if (vmcopy) {
		vmspace_exec(imgp->proc, vmcopy);
		vmspace = imgp->proc->p_vmspace;
		pmap_remove_pages(vmspace_pmap(vmspace), stack_addr, USRSTACK);
		map = &vmspace->vm_map;
	} else if (vmspace->vm_sysref.refcnt == 1 &&
		   vmspace->vm_exitingcnt == 0) {
		shmexit(vmspace);
		if (vmspace->vm_upcalls)
			upc_release(vmspace, ONLY_LWP_IN_PROC(imgp->proc));
		pmap_remove_pages(vmspace_pmap(vmspace),
			0, VM_MAX_USER_ADDRESS);
		vm_map_remove(map, 0, VM_MAX_USER_ADDRESS);
	} else {
		vmspace_exec(imgp->proc, NULL);
		vmspace = imgp->proc->p_vmspace;
		map = &vmspace->vm_map;
	}

	/* Allocate a new stack */
	error = vm_map_stack(&vmspace->vm_map, stack_addr, (vm_size_t)maxssiz,
			     0, VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error)
		return (error);

	/* vm_ssize and vm_maxsaddr are somewhat antiquated concepts in the
	 * VM_STACK case, but they are still used to monitor the size of the
	 * process stack so we can check the stack rlimit.
	 */
	vmspace->vm_ssize = sgrowsiz >> PAGE_SHIFT;
	vmspace->vm_maxsaddr = (char *)USRSTACK - maxssiz;

	return(0);
}

/*
 * Copy out argument and environment strings from the old process
 *	address space into the temporary string buffer.
 */
int
exec_copyin_args(struct image_args *args, char *fname,
		enum exec_path_segflg segflg, char **argv, char **envv)
{
	char	*argp, *envp;
	int	error = 0;
	size_t	length;

	args->buf = objcache_get(exec_objcache, M_WAITOK);
	if (args->buf == NULL)
		return (ENOMEM);
	args->begin_argv = args->buf;
	args->endp = args->begin_argv;
	args->space = ARG_MAX;

	args->fname = args->buf + ARG_MAX;

	/*
	 * Copy the file name.
	 */
	if (segflg == PATH_SYSSPACE) {
		error = copystr(fname, args->fname, PATH_MAX, &length);
	} else if (segflg == PATH_USERSPACE) {
		error = copyinstr(fname, args->fname, PATH_MAX, &length);
	}

	/*
	 * Extract argument strings.  argv may not be NULL.  The argv
	 * array is terminated by a NULL entry.  We special-case the
	 * situation where argv[0] is NULL by passing { filename, NULL }
	 * to the new program to guarentee that the interpreter knows what
	 * file to open in case we exec an interpreted file.   Note that
	 * a NULL argv[0] terminates the argv[] array.
	 *
	 * XXX the special-casing of argv[0] is historical and needs to be
	 * revisited.
	 */
	if (argv == NULL)
		error = EFAULT;
	if (error == 0) {
		while ((argp = (caddr_t)(intptr_t)fuword(argv++)) != NULL) {
			if (argp == (caddr_t)-1) {
				error = EFAULT;
				break;
			}
			error = copyinstr(argp, args->endp,
					    args->space, &length);
			if (error) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				break;
			}
			args->space -= length;
			args->endp += length;
			args->argc++;
		}
		if (args->argc == 0 && error == 0) {
			length = strlen(args->fname) + 1;
			if (length > args->space) {
				error = E2BIG;
			} else {
				bcopy(args->fname, args->endp, length);
				args->space -= length;
				args->endp += length;
				args->argc++;
			}
		}
	}	

	args->begin_envv = args->endp;

	/*
	 * extract environment strings.  envv may be NULL.
	 */
	if (envv && error == 0) {
		while ((envp = (caddr_t) (intptr_t) fuword(envv++))) {
			if (envp == (caddr_t) -1) {
				error = EFAULT;
				break;
			}
			error = copyinstr(envp, args->endp, args->space,
			    &length);
			if (error) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				break;
			}
			args->space -= length;
			args->endp += length;
			args->envc++;
		}
	}
	return (error);
}

void
exec_free_args(struct image_args *args)
{
	if (args->buf) {
		objcache_put(exec_objcache, args->buf);
		args->buf = NULL;
	}
}

/*
 * Copy strings out to the new process address space, constructing
 *	new arg and env vector tables. Return a pointer to the base
 *	so that it can be used as the initial stack pointer.
 */
register_t *
exec_copyout_strings(struct image_params *imgp)
{
	int argc, envc, sgap;
	char **vectp;
	char *stringp, *destp;
	register_t *stack_base;
	struct ps_strings *arginfo;
	int szsigcode;

	/*
	 * Calculate string base and vector table pointers.
	 * Also deal with signal trampoline code for this exec type.
	 */
	arginfo = (struct ps_strings *)PS_STRINGS;
	szsigcode = *(imgp->proc->p_sysent->sv_szsigcode);
	if (stackgap_random != 0)
		sgap = ALIGN(karc4random() & (stackgap_random - 1));
	else
		sgap = 0;
	destp =	(caddr_t)arginfo - szsigcode - SPARE_USRSPACE - sgap -
	    roundup((ARG_MAX - imgp->args->space), sizeof(char *));

	/*
	 * install sigcode
	 */
	if (szsigcode)
		copyout(imgp->proc->p_sysent->sv_sigcode,
		    ((caddr_t)arginfo - szsigcode), szsigcode);

	/*
	 * If we have a valid auxargs ptr, prepare some room
	 * on the stack.
	 *
	 * The '+ 2' is for the null pointers at the end of each of the
	 * arg and env vector sets, and 'AT_COUNT*2' is room for the
	 * ELF Auxargs data.
	 */
	if (imgp->auxargs) {
		vectp = (char **)(destp - (imgp->args->argc +
			imgp->args->envc + 2 + AT_COUNT * 2) * sizeof(char*));
	} else {
		vectp = (char **)(destp - (imgp->args->argc +
			imgp->args->envc + 2) * sizeof(char*));
	}

	/*
	 * NOTE: don't bother aligning the stack here for GCC 2.x, it will
	 * be done in crt1.o.  Note that GCC 3.x aligns the stack in main.
	 */

	/*
	 * vectp also becomes our initial stack base
	 */
	stack_base = (register_t *)vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;

	/*
	 * Copy out strings - arguments and environment.
	 */
	copyout(stringp, destp, ARG_MAX - imgp->args->space);

	/*
	 * Fill in "ps_strings" struct for ps, w, etc.
	 */
	suword(&arginfo->ps_argvstr, (long)(intptr_t)vectp);
	suword(&arginfo->ps_nargvstr, argc);

	/*
	 * Fill in argument portion of vector table.
	 */
	for (; argc > 0; --argc) {
		suword(vectp++, (long)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* a null vector table pointer separates the argp's from the envp's */
	suword(vectp++, 0);

	suword(&arginfo->ps_envstr, (long)(intptr_t)vectp);
	suword(&arginfo->ps_nenvstr, envc);

	/*
	 * Fill in environment portion of vector table.
	 */
	for (; envc > 0; --envc) {
		suword(vectp++, (long)(intptr_t)destp);
		while (*stringp++ != 0)
			destp++;
		destp++;
	}

	/* end of vector table is a null pointer */
	suword(vectp, 0);

	return (stack_base);
}

/*
 * Check permissions of file to execute.
 *	Return 0 for success or error code on failure.
 */
int
exec_check_permissions(struct image_params *imgp, struct mount *topmnt)
{
	struct proc *p = imgp->proc;
	struct vnode *vp = imgp->vp;
	struct vattr *attr = imgp->attr;
	int error;

	/* Get file attributes */
	error = VOP_GETATTR(vp, attr);
	if (error)
		return (error);

	/*
	 * 1) Check if file execution is disabled for the filesystem that this
	 *	file resides on.
	 * 2) Insure that at least one execute bit is on - otherwise root
	 *	will always succeed, and we don't want to happen unless the
	 *	file really is executable.
	 * 3) Insure that the file is a regular file.
	 */
	if ((vp->v_mount->mnt_flag & MNT_NOEXEC) ||
	    ((topmnt != NULL) && (topmnt->mnt_flag & MNT_NOEXEC)) ||
	    ((attr->va_mode & 0111) == 0) ||
	    (attr->va_type != VREG)) {
		return (EACCES);
	}

	/*
	 * Zero length files can't be exec'd
	 */
	if (attr->va_size == 0)
		return (ENOEXEC);

	/*
	 *  Check for execute permission to file based on current credentials.
	 */
	error = VOP_EACCESS(vp, VEXEC, p->p_ucred);
	if (error)
		return (error);

	/*
	 * Check number of open-for-writes on the file and deny execution
	 * if there are any.
	 */
	if (vp->v_writecount)
		return (ETXTBSY);

	/*
	 * Call filesystem specific open routine, which allows us to read,
	 * write, and mmap the file.  Without the VOP_OPEN we can only
	 * stat the file.
	 */
	error = VOP_OPEN(vp, FREAD, p->p_ucred, NULL);
	if (error)
		return (error);

	return (0);
}

/*
 * Exec handler registration
 */
int
exec_register(const struct execsw *execsw_arg)
{
	const struct execsw **es, **xs, **newexecsw;
	int count = 2;	/* New slot and trailing NULL */

	if (execsw)
		for (es = execsw; *es; es++)
			count++;
	newexecsw = kmalloc(count * sizeof(*es), M_TEMP, M_WAITOK);
	xs = newexecsw;
	if (execsw)
		for (es = execsw; *es; es++)
			*xs++ = *es;
	*xs++ = execsw_arg;
	*xs = NULL;
	if (execsw)
		kfree(execsw, M_TEMP);
	execsw = newexecsw;
	return 0;
}

int
exec_unregister(const struct execsw *execsw_arg)
{
	const struct execsw **es, **xs, **newexecsw;
	int count = 1;

	if (execsw == NULL)
		panic("unregister with no handlers left?");

	for (es = execsw; *es; es++) {
		if (*es == execsw_arg)
			break;
	}
	if (*es == NULL)
		return ENOENT;
	for (es = execsw; *es; es++)
		if (*es != execsw_arg)
			count++;
	newexecsw = kmalloc(count * sizeof(*es), M_TEMP, M_WAITOK);
	xs = newexecsw;
	for (es = execsw; *es; es++)
		if (*es != execsw_arg)
			*xs++ = *es;
	*xs = NULL;
	if (execsw)
		kfree(execsw, M_TEMP);
	execsw = newexecsw;
	return 0;
}
