/*-
 * Copyright (c) 1982, 1987, 1990 The Regents of the University of California.
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 2008 The DragonFly Project.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 * from: @(#)machdep.c	7.4 (Berkeley) 6/3/91
 * $FreeBSD: src/sys/i386/i386/machdep.c,v 1.385.2.30 2003/05/31 08:48:05 alc Exp $
 */

//#include "use_npx.h"
#include "use_isa.h"
#include "opt_atalk.h"
#include "opt_compat.h"
#include "opt_cpu.h"
#include "opt_ddb.h"
#include "opt_directio.h"
#include "opt_inet.h"
#include "opt_ipx.h"
#include "opt_msgbuf.h"
#include "opt_swap.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/buf.h>
#include <sys/reboot.h>
#include <sys/mbuf.h>
#include <sys/msgbuf.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/bus.h>
#include <sys/upcall.h>
#include <sys/usched.h>
#include <sys/reg.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

#include <sys/thread2.h>
#include <sys/mplock2.h>
#include <sys/mutex2.h>

#include <sys/user.h>
#include <sys/exec.h>
#include <sys/cons.h>

#include <ddb/ddb.h>

#include <machine/cpu.h>
#include <machine/clock.h>
#include <machine/specialreg.h>
#if JG
#include <machine/bootinfo.h>
#endif
#include <machine/md_var.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include <machine/pcb_ext.h>		/* pcb.h included via sys/user.h */
#include <machine/globaldata.h>		/* CPU_prvspace */
#include <machine/smp.h>
#ifdef PERFMON
#include <machine/perfmon.h>
#endif
#include <machine/cputypes.h>
#include <machine/intr_machdep.h>

#ifdef OLD_BUS_ARCH
#include <bus/isa/isa_device.h>
#endif
#include <machine_base/isa/isa_intr.h>
#include <bus/isa/rtc.h>
#include <sys/random.h>
#include <sys/ptrace.h>
#include <machine/sigframe.h>

#include <sys/machintr.h>
#include <machine_base/icu/icu_abi.h>
#include <machine_base/icu/elcr_var.h>
#include <machine_base/apic/lapic.h>
#include <machine_base/apic/ioapic.h>
#include <machine_base/apic/ioapic_abi.h>
#include <machine/mptable.h>

#define PHYSMAP_ENTRIES		10

extern u_int64_t hammer_time(u_int64_t, u_int64_t);

extern void printcpuinfo(void);	/* XXX header file */
extern void identify_cpu(void);
#if JG
extern void finishidentcpu(void);
#endif
extern void panicifcpuunsupported(void);

static void cpu_startup(void *);
static void pic_finish(void *);
static void cpu_finish(void *);

#ifndef CPU_DISABLE_SSE
static void set_fpregs_xmm(struct save87 *, struct savexmm *);
static void fill_fpregs_xmm(struct savexmm *, struct save87 *);
#endif /* CPU_DISABLE_SSE */
#ifdef DIRECTIO
extern void ffs_rawread_setup(void);
#endif /* DIRECTIO */
static void init_locks(void);

SYSINIT(cpu, SI_BOOT2_START_CPU, SI_ORDER_FIRST, cpu_startup, NULL)
SYSINIT(pic_finish, SI_BOOT2_FINISH_PIC, SI_ORDER_FIRST, pic_finish, NULL)
SYSINIT(cpu_finish, SI_BOOT2_FINISH_CPU, SI_ORDER_FIRST, cpu_finish, NULL)

#ifdef DDB
extern vm_offset_t ksym_start, ksym_end;
#endif

struct privatespace CPU_prvspace[MAXCPU] __aligned(4096); /* XXX */

int	_udatasel, _ucodesel, _ucode32sel;
u_long	atdevbase;
#ifdef SMP
int64_t tsc_offsets[MAXCPU];
#else
int64_t tsc_offsets[1];
#endif

#if defined(SWTCH_OPTIM_STATS)
extern int swtch_optim_stats;
SYSCTL_INT(_debug, OID_AUTO, swtch_optim_stats,
	CTLFLAG_RD, &swtch_optim_stats, 0, "");
SYSCTL_INT(_debug, OID_AUTO, tlb_flush_count,
	CTLFLAG_RD, &tlb_flush_count, 0, "");
#endif

long physmem = 0;

u_long ebda_addr = 0;

int imcr_present = 0;

int naps = 0; /* # of Applications processors */

u_int base_memory;
struct mtx dt_lock;		/* lock for GDT and LDT */

static int
sysctl_hw_physmem(SYSCTL_HANDLER_ARGS)
{
	u_long pmem = ctob(physmem);

	int error = sysctl_handle_long(oidp, &pmem, 0, req);
	return (error);
}

SYSCTL_PROC(_hw, HW_PHYSMEM, physmem, CTLTYPE_ULONG|CTLFLAG_RD,
	0, 0, sysctl_hw_physmem, "LU", "Total system memory in bytes (number of pages * page size)");

static int
sysctl_hw_usermem(SYSCTL_HANDLER_ARGS)
{
	int error = sysctl_handle_int(oidp, 0,
		ctob(physmem - vmstats.v_wire_count), req);
	return (error);
}

SYSCTL_PROC(_hw, HW_USERMEM, usermem, CTLTYPE_INT|CTLFLAG_RD,
	0, 0, sysctl_hw_usermem, "IU", "");

static int
sysctl_hw_availpages(SYSCTL_HANDLER_ARGS)
{
	int error = sysctl_handle_int(oidp, 0,
		x86_64_btop(avail_end - avail_start), req);
	return (error);
}

SYSCTL_PROC(_hw, OID_AUTO, availpages, CTLTYPE_INT|CTLFLAG_RD,
	0, 0, sysctl_hw_availpages, "I", "");

vm_paddr_t Maxmem;
vm_paddr_t Realmem;

/*
 * The number of PHYSMAP entries must be one less than the number of
 * PHYSSEG entries because the PHYSMAP entry that spans the largest
 * physical address that is accessible by ISA DMA is split into two
 * PHYSSEG entries.
 */
#define	PHYSMAP_SIZE	(2 * (VM_PHYSSEG_MAX - 1))

vm_paddr_t phys_avail[PHYSMAP_SIZE + 2];
vm_paddr_t dump_avail[PHYSMAP_SIZE + 2];

/* must be 2 less so 0 0 can signal end of chunks */
#define PHYS_AVAIL_ARRAY_END (NELEM(phys_avail) - 2)
#define DUMP_AVAIL_ARRAY_END (NELEM(dump_avail) - 2)

static vm_offset_t buffer_sva, buffer_eva;
vm_offset_t clean_sva, clean_eva;
static vm_offset_t pager_sva, pager_eva;
static struct trapframe proc0_tf;

static void
cpu_startup(void *dummy)
{
	caddr_t v;
	vm_size_t size = 0;
	vm_offset_t firstaddr;

	/*
	 * Good {morning,afternoon,evening,night}.
	 */
	kprintf("%s", version);
	startrtclock();
	printcpuinfo();
	panicifcpuunsupported();
#ifdef PERFMON
	perfmon_init();
#endif
	kprintf("real memory  = %ju (%ju MB)\n",
		(intmax_t)Realmem,
		(intmax_t)Realmem / 1024 / 1024);
	/*
	 * Display any holes after the first chunk of extended memory.
	 */
	if (bootverbose) {
		int indx;

		kprintf("Physical memory chunk(s):\n");
		for (indx = 0; phys_avail[indx + 1] != 0; indx += 2) {
			vm_paddr_t size1 = phys_avail[indx + 1] - phys_avail[indx];

			kprintf("0x%08jx - 0x%08jx, %ju bytes (%ju pages)\n",
				(intmax_t)phys_avail[indx],
				(intmax_t)phys_avail[indx + 1] - 1,
				(intmax_t)size1,
				(intmax_t)(size1 / PAGE_SIZE));
		}
	}

	/*
	 * Allocate space for system data structures.
	 * The first available kernel virtual address is in "v".
	 * As pages of kernel virtual memory are allocated, "v" is incremented.
	 * As pages of memory are allocated and cleared,
	 * "firstaddr" is incremented.
	 * An index into the kernel page table corresponding to the
	 * virtual memory address maintained in "v" is kept in "mapaddr".
	 */

	/*
	 * Make two passes.  The first pass calculates how much memory is
	 * needed and allocates it.  The second pass assigns virtual
	 * addresses to the various data structures.
	 */
	firstaddr = 0;
again:
	v = (caddr_t)firstaddr;

#define	valloc(name, type, num) \
	    (name) = (type *)v; v = (caddr_t)((name)+(num))
#define	valloclim(name, type, num, lim) \
	    (name) = (type *)v; v = (caddr_t)((lim) = ((name)+(num)))

	/*
	 * The nominal buffer size (and minimum KVA allocation) is BKVASIZE.
	 * For the first 64MB of ram nominally allocate sufficient buffers to
	 * cover 1/4 of our ram.  Beyond the first 64MB allocate additional
	 * buffers to cover 1/20 of our ram over 64MB.  When auto-sizing
	 * the buffer cache we limit the eventual kva reservation to
	 * maxbcache bytes.
	 *
	 * factor represents the 1/4 x ram conversion.
	 */
	if (nbuf == 0) {
		int factor = 4 * BKVASIZE / 1024;
		int kbytes = physmem * (PAGE_SIZE / 1024);

		nbuf = 50;
		if (kbytes > 4096)
			nbuf += min((kbytes - 4096) / factor, 65536 / factor);
		if (kbytes > 65536)
			nbuf += (kbytes - 65536) * 2 / (factor * 5);
		if (maxbcache && nbuf > maxbcache / BKVASIZE)
			nbuf = maxbcache / BKVASIZE;
	}

	/*
	 * Do not allow the buffer_map to be more then 1/2 the size of the
	 * kernel_map.
	 */
	if (nbuf > (virtual_end - virtual_start) / (BKVASIZE * 2)) {
		nbuf = (virtual_end - virtual_start) / (BKVASIZE * 2);
		kprintf("Warning: nbufs capped at %d\n", nbuf);
	}

	nswbuf = max(min(nbuf/4, 256), 16);
#ifdef NSWBUF_MIN
	if (nswbuf < NSWBUF_MIN)
		nswbuf = NSWBUF_MIN;
#endif
#ifdef DIRECTIO
	ffs_rawread_setup();
#endif

	valloc(swbuf, struct buf, nswbuf);
	valloc(buf, struct buf, nbuf);

	/*
	 * End of first pass, size has been calculated so allocate memory
	 */
	if (firstaddr == 0) {
		size = (vm_size_t)(v - firstaddr);
		firstaddr = kmem_alloc(&kernel_map, round_page(size));
		if (firstaddr == 0)
			panic("startup: no room for tables");
		goto again;
	}

	/*
	 * End of second pass, addresses have been assigned
	 */
	if ((vm_size_t)(v - firstaddr) != size)
		panic("startup: table size inconsistency");

	kmem_suballoc(&kernel_map, &clean_map, &clean_sva, &clean_eva,
		      (nbuf*BKVASIZE) + (nswbuf*MAXPHYS) + pager_map_size);
	kmem_suballoc(&clean_map, &buffer_map, &buffer_sva, &buffer_eva,
		      (nbuf*BKVASIZE));
	buffer_map.system_map = 1;
	kmem_suballoc(&clean_map, &pager_map, &pager_sva, &pager_eva,
		      (nswbuf*MAXPHYS) + pager_map_size);
	pager_map.system_map = 1;

#if defined(USERCONFIG)
	userconfig();
	cninit();		/* the preferred console may have changed */
#endif

	kprintf("avail memory = %ju (%ju MB)\n",
		(uintmax_t)ptoa(vmstats.v_free_count),
		(uintmax_t)ptoa(vmstats.v_free_count) / 1024 / 1024);

	/*
	 * Set up buffers, so they can be used to read disk labels.
	 */
	bufinit();
	vm_pager_bufferinit();
}

static void
cpu_finish(void *dummy __unused)
{
	cpu_setregs();
}

static void
pic_finish(void *dummy __unused)
{
	/* Log ELCR information */
	elcr_dump();

	/* Log MPTABLE information */
	mptable_pci_int_dump();

	/* Finalize PCI */
	MachIntrABI.finalize();
}

/*
 * Send an interrupt to process.
 *
 * Stack is set up to allow sigcode stored
 * at top to call routine, followed by kcall
 * to sigreturn routine below.  After sigreturn
 * resets the signal mask, the stack, and the
 * frame pointer, it returns to the user
 * specified pc, psl.
 */
void
sendsig(sig_t catcher, int sig, sigset_t *mask, u_long code)
{
	struct lwp *lp = curthread->td_lwp;
	struct proc *p = lp->lwp_proc;
	struct trapframe *regs;
	struct sigacts *psp = p->p_sigacts;
	struct sigframe sf, *sfp;
	int oonstack;
	char *sp;

	regs = lp->lwp_md.md_regs;
	oonstack = (lp->lwp_sigstk.ss_flags & SS_ONSTACK) ? 1 : 0;

	/* Save user context */
	bzero(&sf, sizeof(struct sigframe));
	sf.sf_uc.uc_sigmask = *mask;
	sf.sf_uc.uc_stack = lp->lwp_sigstk;
	sf.sf_uc.uc_mcontext.mc_onstack = oonstack;
	KKASSERT(__offsetof(struct trapframe, tf_rdi) == 0);
	bcopy(regs, &sf.sf_uc.uc_mcontext.mc_rdi, sizeof(struct trapframe));

	/* Make the size of the saved context visible to userland */
	sf.sf_uc.uc_mcontext.mc_len = sizeof(sf.sf_uc.uc_mcontext);

	/* Save mailbox pending state for syscall interlock semantics */
	if (p->p_flag & P_MAILBOX)
		sf.sf_uc.uc_mcontext.mc_xflags |= PGEX_MAILBOX;

	/* Allocate and validate space for the signal handler context. */
        if ((lp->lwp_flag & LWP_ALTSTACK) != 0 && !oonstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = (char *)(lp->lwp_sigstk.ss_sp + lp->lwp_sigstk.ss_size -
			      sizeof(struct sigframe));
		lp->lwp_sigstk.ss_flags |= SS_ONSTACK;
	} else {
		/* We take red zone into account */
		sp = (char *)regs->tf_rsp - sizeof(struct sigframe) - 128;
	}

	/* Align to 16 bytes */
	sfp = (struct sigframe *)((intptr_t)sp & ~(intptr_t)0xF);

	/* Translate the signal is appropriate */
	if (p->p_sysent->sv_sigtbl) {
		if (sig <= p->p_sysent->sv_sigsize)
			sig = p->p_sysent->sv_sigtbl[_SIG_IDX(sig)];
	}

	/*
	 * Build the argument list for the signal handler.
	 *
	 * Arguments are in registers (%rdi, %rsi, %rdx, %rcx)
	 */
	regs->tf_rdi = sig;				/* argument 1 */
	regs->tf_rdx = (register_t)&sfp->sf_uc;		/* argument 3 */

	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		/*
		 * Signal handler installed with SA_SIGINFO.
		 *
		 * action(signo, siginfo, ucontext)
		 */
		regs->tf_rsi = (register_t)&sfp->sf_si;	/* argument 2 */
		regs->tf_rcx = (register_t)regs->tf_addr; /* argument 4 */
		sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher;

		/* fill siginfo structure */
		sf.sf_si.si_signo = sig;
		sf.sf_si.si_code = code;
		sf.sf_si.si_addr = (void *)regs->tf_addr;
	} else {
		/*
		 * Old FreeBSD-style arguments.
		 *
		 * handler (signo, code, [uc], addr)
		 */
		regs->tf_rsi = (register_t)code;	/* argument 2 */
		regs->tf_rcx = (register_t)regs->tf_addr; /* argument 4 */
		sf.sf_ahu.sf_handler = catcher;
	}

	/*
	 * If we're a vm86 process, we want to save the segment registers.
	 * We also change eflags to be our emulated eflags, not the actual
	 * eflags.
	 */
#if JG
	if (regs->tf_eflags & PSL_VM) {
		struct trapframe_vm86 *tf = (struct trapframe_vm86 *)regs;
		struct vm86_kernel *vm86 = &lp->lwp_thread->td_pcb->pcb_ext->ext_vm86;

		sf.sf_uc.uc_mcontext.mc_gs = tf->tf_vm86_gs;
		sf.sf_uc.uc_mcontext.mc_fs = tf->tf_vm86_fs;
		sf.sf_uc.uc_mcontext.mc_es = tf->tf_vm86_es;
		sf.sf_uc.uc_mcontext.mc_ds = tf->tf_vm86_ds;

		if (vm86->vm86_has_vme == 0)
			sf.sf_uc.uc_mcontext.mc_eflags =
			    (tf->tf_eflags & ~(PSL_VIF | PSL_VIP)) |
			    (vm86->vm86_eflags & (PSL_VIF | PSL_VIP));

		/*
		 * Clear PSL_NT to inhibit T_TSSFLT faults on return from
		 * syscalls made by the signal handler.  This just avoids
		 * wasting time for our lazy fixup of such faults.  PSL_NT
		 * does nothing in vm86 mode, but vm86 programs can set it
		 * almost legitimately in probes for old cpu types.
		 */
		tf->tf_eflags &= ~(PSL_VM | PSL_NT | PSL_VIF | PSL_VIP);
	}
#endif

	/*
	 * Save the FPU state and reinit the FP unit
	 */
	npxpush(&sf.sf_uc.uc_mcontext);

	/*
	 * Copy the sigframe out to the user's stack.
	 */
	if (copyout(&sf, sfp, sizeof(struct sigframe)) != 0) {
		/*
		 * Something is wrong with the stack pointer.
		 * ...Kill the process.
		 */
		sigexit(lp, SIGILL);
	}

	regs->tf_rsp = (register_t)sfp;
	regs->tf_rip = PS_STRINGS - *(p->p_sysent->sv_szsigcode);

	/*
	 * i386 abi specifies that the direction flag must be cleared
	 * on function entry
	 */
	regs->tf_rflags &= ~(PSL_T|PSL_D);

	/*
	 * 64 bit mode has a code and stack selector but
	 * no data or extra selector.  %fs and %gs are not
	 * stored in-context.
	 */
	regs->tf_cs = _ucodesel;
	regs->tf_ss = _udatasel;
}

/*
 * Sanitize the trapframe for a virtual kernel passing control to a custom
 * VM context.  Remove any items that would otherwise create a privilage
 * issue.
 *
 * XXX at the moment we allow userland to set the resume flag.  Is this a
 * bad idea?
 */
int
cpu_sanitize_frame(struct trapframe *frame)
{
	frame->tf_cs = _ucodesel;
	frame->tf_ss = _udatasel;
	/* XXX VM (8086) mode not supported? */
	frame->tf_rflags &= (PSL_RF | PSL_USERCHANGE | PSL_VM_UNSUPP);
	frame->tf_rflags |= PSL_RESERVED_DEFAULT | PSL_I;

	return(0);
}

/*
 * Sanitize the tls so loading the descriptor does not blow up
 * on us.  For x86_64 we don't have to do anything.
 */
int
cpu_sanitize_tls(struct savetls *tls)
{
	return(0);
}

/*
 * sigreturn(ucontext_t *sigcntxp)
 *
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above).
 * Return to previous pc and psl as specified by
 * context left by sendsig. Check carefully to
 * make sure that the user has not modified the
 * state to gain improper privileges.
 *
 * MPSAFE
 */
#define	EFL_SECURE(ef, oef)	((((ef) ^ (oef)) & ~PSL_USERCHANGE) == 0)
#define	CS_SECURE(cs)		(ISPL(cs) == SEL_UPL)

int
sys_sigreturn(struct sigreturn_args *uap)
{
	struct lwp *lp = curthread->td_lwp;
	struct proc *p = lp->lwp_proc;
	struct trapframe *regs;
	ucontext_t uc;
	ucontext_t *ucp;
	register_t rflags;
	int cs;
	int error;

	/*
	 * We have to copy the information into kernel space so userland
	 * can't modify it while we are sniffing it.
	 */
	regs = lp->lwp_md.md_regs;
	error = copyin(uap->sigcntxp, &uc, sizeof(uc));
	if (error)
		return (error);
	ucp = &uc;
	rflags = ucp->uc_mcontext.mc_rflags;

	/* VM (8086) mode not supported */
	rflags &= ~PSL_VM_UNSUPP;

#if JG
	if (eflags & PSL_VM) {
		struct trapframe_vm86 *tf = (struct trapframe_vm86 *)regs;
		struct vm86_kernel *vm86;

		/*
		 * if pcb_ext == 0 or vm86_inited == 0, the user hasn't
		 * set up the vm86 area, and we can't enter vm86 mode.
		 */
		if (lp->lwp_thread->td_pcb->pcb_ext == 0)
			return (EINVAL);
		vm86 = &lp->lwp_thread->td_pcb->pcb_ext->ext_vm86;
		if (vm86->vm86_inited == 0)
			return (EINVAL);

		/* go back to user mode if both flags are set */
		if ((eflags & PSL_VIP) && (eflags & PSL_VIF))
			trapsignal(lp, SIGBUS, 0);

		if (vm86->vm86_has_vme) {
			eflags = (tf->tf_eflags & ~VME_USERCHANGE) |
			    (eflags & VME_USERCHANGE) | PSL_VM;
		} else {
			vm86->vm86_eflags = eflags;	/* save VIF, VIP */
			eflags = (tf->tf_eflags & ~VM_USERCHANGE) |
			    (eflags & VM_USERCHANGE) | PSL_VM;
		}
		bcopy(&ucp->uc_mcontext.mc_gs, tf, sizeof(struct trapframe));
		tf->tf_eflags = eflags;
		tf->tf_vm86_ds = tf->tf_ds;
		tf->tf_vm86_es = tf->tf_es;
		tf->tf_vm86_fs = tf->tf_fs;
		tf->tf_vm86_gs = tf->tf_gs;
		tf->tf_ds = _udatasel;
		tf->tf_es = _udatasel;
		tf->tf_fs = _udatasel;
		tf->tf_gs = _udatasel;
	} else
#endif
	{
		/*
		 * Don't allow users to change privileged or reserved flags.
		 */
		/*
		 * XXX do allow users to change the privileged flag PSL_RF.
		 * The cpu sets PSL_RF in tf_eflags for faults.  Debuggers
		 * should sometimes set it there too.  tf_eflags is kept in
		 * the signal context during signal handling and there is no
		 * other place to remember it, so the PSL_RF bit may be
		 * corrupted by the signal handler without us knowing.
		 * Corruption of the PSL_RF bit at worst causes one more or
		 * one less debugger trap, so allowing it is fairly harmless.
		 */
		if (!EFL_SECURE(rflags & ~PSL_RF, regs->tf_rflags & ~PSL_RF)) {
			kprintf("sigreturn: rflags = 0x%lx\n", (long)rflags);
	    		return(EINVAL);
		}

		/*
		 * Don't allow users to load a valid privileged %cs.  Let the
		 * hardware check for invalid selectors, excess privilege in
		 * other selectors, invalid %eip's and invalid %esp's.
		 */
		cs = ucp->uc_mcontext.mc_cs;
		if (!CS_SECURE(cs)) {
			kprintf("sigreturn: cs = 0x%x\n", cs);
			trapsignal(lp, SIGBUS, T_PROTFLT);
			return(EINVAL);
		}
		bcopy(&ucp->uc_mcontext.mc_rdi, regs, sizeof(struct trapframe));
	}

	/*
	 * Restore the FPU state from the frame
	 */
	crit_enter();
	npxpop(&ucp->uc_mcontext);

	/*
	 * Merge saved signal mailbox pending flag to maintain interlock
	 * semantics against system calls.
	 */
	if (ucp->uc_mcontext.mc_xflags & PGEX_MAILBOX)
		p->p_flag |= P_MAILBOX;

	if (ucp->uc_mcontext.mc_onstack & 1)
		lp->lwp_sigstk.ss_flags |= SS_ONSTACK;
	else
		lp->lwp_sigstk.ss_flags &= ~SS_ONSTACK;

	lp->lwp_sigmask = ucp->uc_sigmask;
	SIG_CANTMASK(lp->lwp_sigmask);
	crit_exit();
	return(EJUSTRETURN);
}

/*
 * Stack frame on entry to function.  %rax will contain the function vector,
 * %rcx will contain the function data.  flags, rcx, and rax will have
 * already been pushed on the stack.
 */
struct upc_frame {
	register_t	rax;
	register_t	rcx;
	register_t	rdx;
	register_t	flags;
	register_t	oldip;
};

void
sendupcall(struct vmupcall *vu, int morepending)
{
	struct lwp *lp = curthread->td_lwp;
	struct trapframe *regs;
	struct upcall upcall;
	struct upc_frame upc_frame;
	int	crit_count = 0;

	/*
	 * If we are a virtual kernel running an emulated user process
	 * context, switch back to the virtual kernel context before
	 * trying to post the signal.
	 */
	if (lp->lwp_vkernel && lp->lwp_vkernel->ve) {
		lp->lwp_md.md_regs->tf_trapno = 0;
		vkernel_trap(lp, lp->lwp_md.md_regs);
	}

	/*
	 * Get the upcall data structure
	 */
	if (copyin(lp->lwp_upcall, &upcall, sizeof(upcall)) ||
	    copyin((char *)upcall.upc_uthread + upcall.upc_critoff, &crit_count, sizeof(int))
	) {
		vu->vu_pending = 0;
		kprintf("bad upcall address\n");
		return;
	}

	/*
	 * If the data structure is already marked pending or has a critical
	 * section count, mark the data structure as pending and return 
	 * without doing an upcall.  vu_pending is left set.
	 */
	if (upcall.upc_pending || crit_count >= vu->vu_pending) {
		if (upcall.upc_pending < vu->vu_pending) {
			upcall.upc_pending = vu->vu_pending;
			copyout(&upcall.upc_pending, &lp->lwp_upcall->upc_pending,
				sizeof(upcall.upc_pending));
		}
		return;
	}

	/*
	 * We can run this upcall now, clear vu_pending.
	 *
	 * Bump our critical section count and set or clear the
	 * user pending flag depending on whether more upcalls are
	 * pending.  The user will be responsible for calling 
	 * upc_dispatch(-1) to process remaining upcalls.
	 */
	vu->vu_pending = 0;
	upcall.upc_pending = morepending;
	++crit_count;
	copyout(&upcall.upc_pending, &lp->lwp_upcall->upc_pending, 
		sizeof(upcall.upc_pending));
	copyout(&crit_count, (char *)upcall.upc_uthread + upcall.upc_critoff,
		sizeof(int));

	/*
	 * Construct a stack frame and issue the upcall
	 */
	regs = lp->lwp_md.md_regs;
	upc_frame.rax = regs->tf_rax;
	upc_frame.rcx = regs->tf_rcx;
	upc_frame.rdx = regs->tf_rdx;
	upc_frame.flags = regs->tf_rflags;
	upc_frame.oldip = regs->tf_rip;
	if (copyout(&upc_frame, (void *)(regs->tf_rsp - sizeof(upc_frame)),
	    sizeof(upc_frame)) != 0) {
		kprintf("bad stack on upcall\n");
	} else {
		regs->tf_rax = (register_t)vu->vu_func;
		regs->tf_rcx = (register_t)vu->vu_data;
		regs->tf_rdx = (register_t)lp->lwp_upcall;
		regs->tf_rip = (register_t)vu->vu_ctx;
		regs->tf_rsp -= sizeof(upc_frame);
	}
}

/*
 * fetchupcall occurs in the context of a system call, which means that
 * we have to return EJUSTRETURN in order to prevent eax and edx from
 * being overwritten by the syscall return value.
 *
 * if vu is not NULL we return the new context in %edx, the new data in %ecx,
 * and the function pointer in %eax.  
 */
int
fetchupcall(struct vmupcall *vu, int morepending, void *rsp)
{
	struct upc_frame upc_frame;
	struct lwp *lp = curthread->td_lwp;
	struct trapframe *regs;
	int error;
	struct upcall upcall;
	int crit_count;

	regs = lp->lwp_md.md_regs;

	error = copyout(&morepending, &lp->lwp_upcall->upc_pending, sizeof(int));
	if (error == 0) {
	    if (vu) {
		/*
		 * This jumps us to the next ready context.
		 */
		vu->vu_pending = 0;
		error = copyin(lp->lwp_upcall, &upcall, sizeof(upcall));
		crit_count = 0;
		if (error == 0)
			error = copyin((char *)upcall.upc_uthread + upcall.upc_critoff, &crit_count, sizeof(int));
		++crit_count;
		if (error == 0)
			error = copyout(&crit_count, (char *)upcall.upc_uthread + upcall.upc_critoff, sizeof(int));
		regs->tf_rax = (register_t)vu->vu_func;
		regs->tf_rcx = (register_t)vu->vu_data;
		regs->tf_rdx = (register_t)lp->lwp_upcall;
		regs->tf_rip = (register_t)vu->vu_ctx;
		regs->tf_rsp = (register_t)rsp;
	    } else {
		/*
		 * This returns us to the originally interrupted code.
		 */
		error = copyin(rsp, &upc_frame, sizeof(upc_frame));
		regs->tf_rax = upc_frame.rax;
		regs->tf_rcx = upc_frame.rcx;
		regs->tf_rdx = upc_frame.rdx;
		regs->tf_rflags = (regs->tf_rflags & ~PSL_USERCHANGE) |
				(upc_frame.flags & PSL_USERCHANGE);
		regs->tf_rip = upc_frame.oldip;
		regs->tf_rsp = (register_t)((char *)rsp + sizeof(upc_frame));
	    }
	}
	if (error == 0)
		error = EJUSTRETURN;
	return(error);
}

/*
 * Machine dependent boot() routine
 *
 * I haven't seen anything to put here yet
 * Possibly some stuff might be grafted back here from boot()
 */
void
cpu_boot(int howto)
{
}

/*
 * Shutdown the CPU as much as possible
 */
void
cpu_halt(void)
{
	for (;;)
		__asm__ __volatile("hlt");
}

/*
 * cpu_idle() represents the idle LWKT.  You cannot return from this function
 * (unless you want to blow things up!).  Instead we look for runnable threads
 * and loop or halt as appropriate.  Giant is not held on entry to the thread.
 *
 * The main loop is entered with a critical section held, we must release
 * the critical section before doing anything else.  lwkt_switch() will
 * check for pending interrupts due to entering and exiting its own 
 * critical section.
 *
 * NOTE: On an SMP system we rely on a scheduler IPI to wake a HLTed cpu up.
 *	 However, there are cases where the idlethread will be entered with
 *	 the possibility that no IPI will occur and in such cases
 *	 lwkt_switch() sets TDF_IDLE_NOHLT.
 *
 * NOTE: cpu_idle_hlt again defaults to 2 (use ACPI sleep states).  Set to
 *	 1 to just use hlt and for debugging purposes.
 *
 * NOTE: cpu_idle_repeat determines how many entries into the idle thread
 *	 must occur before it starts using ACPI halt.
 */
static int	cpu_idle_hlt = 2;
static int	cpu_idle_hltcnt;
static int	cpu_idle_spincnt;
static u_int	cpu_idle_repeat = 4;
SYSCTL_INT(_machdep, OID_AUTO, cpu_idle_hlt, CTLFLAG_RW,
    &cpu_idle_hlt, 0, "Idle loop HLT enable");
SYSCTL_INT(_machdep, OID_AUTO, cpu_idle_hltcnt, CTLFLAG_RW,
    &cpu_idle_hltcnt, 0, "Idle loop entry halts");
SYSCTL_INT(_machdep, OID_AUTO, cpu_idle_spincnt, CTLFLAG_RW,
    &cpu_idle_spincnt, 0, "Idle loop entry spins");
SYSCTL_INT(_machdep, OID_AUTO, cpu_idle_repeat, CTLFLAG_RW,
    &cpu_idle_repeat, 0, "Idle entries before acpi hlt");

static void
cpu_idle_default_hook(void)
{
	/*
	 * We must guarentee that hlt is exactly the instruction
	 * following the sti.
	 */
	__asm __volatile("sti; hlt");
}

/* Other subsystems (e.g., ACPI) can hook this later. */
void (*cpu_idle_hook)(void) = cpu_idle_default_hook;

void
cpu_idle(void)
{
	globaldata_t gd = mycpu;
	struct thread *td __debugvar = gd->gd_curthread;
	int reqflags;
	int quick;

	crit_exit();
	KKASSERT(td->td_critcount == 0);
	for (;;) {
		/*
		 * See if there are any LWKTs ready to go.
		 */
		lwkt_switch();

		/*
		 * When halting inside a cli we must check for reqflags
		 * races, particularly [re]schedule requests.  Running
		 * splz() does the job.
		 *
		 * cpu_idle_hlt:
		 *	0	Never halt, just spin
		 *
		 *	1	Always use HLT (or MONITOR/MWAIT if avail).
		 *		This typically eats more power than the
		 *		ACPI halt.
		 *
		 *	2	Use HLT/MONITOR/MWAIT up to a point and then
		 *		use the ACPI halt (default).  This is a hybrid
		 *		approach.  See machdep.cpu_idle_repeat.
		 *
		 *	3	Always use the ACPI halt.  This typically
		 *		eats the least amount of power but the cpu
		 *		will be slow waking up.  Slows down e.g.
		 *		compiles and other pipe/event oriented stuff.
		 *
		 * NOTE: Interrupts are enabled and we are not in a critical
		 *	 section.
		 *
		 * NOTE: Preemptions do not reset gd_idle_repeat.   Also we
		 *	 don't bother capping gd_idle_repeat, it is ok if
		 *	 it overflows.
		 */
		++gd->gd_idle_repeat;
		reqflags = gd->gd_reqflags;
		quick = (cpu_idle_hlt == 1) ||
			(cpu_idle_hlt < 3 &&
			 gd->gd_idle_repeat < cpu_idle_repeat);

		if (quick && (cpu_mi_feature & CPU_MI_MONITOR) &&
		    (reqflags & RQF_IDLECHECK_WK_MASK) == 0) {
			splz(); /* XXX */
			cpu_mmw_pause_int(&gd->gd_reqflags, reqflags);
			++cpu_idle_hltcnt;
		} else if (cpu_idle_hlt) {
			__asm __volatile("cli");
			splz();
			if ((gd->gd_reqflags & RQF_IDLECHECK_WK_MASK) == 0) {
				if (quick)
					cpu_idle_default_hook();
				else
					cpu_idle_hook();
			}
			__asm __volatile("sti");
			++cpu_idle_hltcnt;
		} else {
			splz();
			__asm __volatile("sti");
			++cpu_idle_spincnt;
		}
	}
}

#ifdef SMP

/*
 * This routine is called if a spinlock has been held through the
 * exponential backoff period and is seriously contested.  On a real cpu
 * we let it spin.
 */
void
cpu_spinlock_contested(void)
{
	cpu_pause();
}

#endif

/*
 * Clear registers on exec
 */
void
exec_setregs(u_long entry, u_long stack, u_long ps_strings)
{
	struct thread *td = curthread;
	struct lwp *lp = td->td_lwp;
	struct pcb *pcb = td->td_pcb;
	struct trapframe *regs = lp->lwp_md.md_regs;

	/* was i386_user_cleanup() in NetBSD */
	user_ldt_free(pcb);
  
	bzero((char *)regs, sizeof(struct trapframe));
	regs->tf_rip = entry;
	regs->tf_rsp = ((stack - 8) & ~0xFul) + 8; /* align the stack */
	regs->tf_rdi = stack;		/* argv */
	regs->tf_rflags = PSL_USER | (regs->tf_rflags & PSL_T);
	regs->tf_ss = _udatasel;
	regs->tf_cs = _ucodesel;
	regs->tf_rbx = ps_strings;

	/*
	 * Reset the hardware debug registers if they were in use.
	 * They won't have any meaning for the newly exec'd process.
	 */
	if (pcb->pcb_flags & PCB_DBREGS) {
		pcb->pcb_dr0 = 0;
		pcb->pcb_dr1 = 0;
		pcb->pcb_dr2 = 0;
		pcb->pcb_dr3 = 0;
		pcb->pcb_dr6 = 0;
		pcb->pcb_dr7 = 0; /* JG set bit 10? */
		if (pcb == td->td_pcb) {
			/*
			 * Clear the debug registers on the running
			 * CPU, otherwise they will end up affecting
			 * the next process we switch to.
			 */
			reset_dbregs();
		}
		pcb->pcb_flags &= ~PCB_DBREGS;
	}

	/*
	 * Initialize the math emulator (if any) for the current process.
	 * Actually, just clear the bit that says that the emulator has
	 * been initialized.  Initialization is delayed until the process
	 * traps to the emulator (if it is done at all) mainly because
	 * emulators don't provide an entry point for initialization.
	 */
	pcb->pcb_flags &= ~FP_SOFTFP;

	/*
	 * NOTE: do not set CR0_TS here.  npxinit() must do it after clearing
	 *	 gd_npxthread.  Otherwise a preemptive interrupt thread
	 *	 may panic in npxdna().
	 */
	crit_enter();
	load_cr0(rcr0() | CR0_MP);

	/*
	 * NOTE: The MSR values must be correct so we can return to
	 * 	 userland.  gd_user_fs/gs must be correct so the switch
	 *	 code knows what the current MSR values are.
	 */
	pcb->pcb_fsbase = 0;	/* Values loaded from PCB on switch */
	pcb->pcb_gsbase = 0;
	mdcpu->gd_user_fs = 0;	/* Cache of current MSR values */
	mdcpu->gd_user_gs = 0;
	wrmsr(MSR_FSBASE, 0);	/* Set MSR values for return to userland */
	wrmsr(MSR_KGSBASE, 0);

	/* Initialize the npx (if any) for the current process. */
	npxinit(__INITIAL_NPXCW__);
	crit_exit();

	pcb->pcb_ds = _udatasel;
	pcb->pcb_es = _udatasel;
	pcb->pcb_fs = _udatasel;
	pcb->pcb_gs = _udatasel;
}

void
cpu_setregs(void)
{
	register_t cr0;

	cr0 = rcr0();
	cr0 |= CR0_NE;			/* Done by npxinit() */
	cr0 |= CR0_MP | CR0_TS;		/* Done at every execve() too. */
	cr0 |= CR0_WP | CR0_AM;
	load_cr0(cr0);
	load_gs(_udatasel);
}

static int
sysctl_machdep_adjkerntz(SYSCTL_HANDLER_ARGS)
{
	int error;
	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2,
		req);
	if (!error && req->newptr)
		resettodr();
	return (error);
}

SYSCTL_PROC(_machdep, CPU_ADJKERNTZ, adjkerntz, CTLTYPE_INT|CTLFLAG_RW,
	&adjkerntz, 0, sysctl_machdep_adjkerntz, "I", "");

SYSCTL_INT(_machdep, CPU_DISRTCSET, disable_rtc_set,
	CTLFLAG_RW, &disable_rtc_set, 0, "");

#if JG
SYSCTL_STRUCT(_machdep, CPU_BOOTINFO, bootinfo, 
	CTLFLAG_RD, &bootinfo, bootinfo, "");
#endif

SYSCTL_INT(_machdep, CPU_WALLCLOCK, wall_cmos_clock,
	CTLFLAG_RW, &wall_cmos_clock, 0, "");

extern u_long bootdev;		/* not a cdev_t - encoding is different */
SYSCTL_ULONG(_machdep, OID_AUTO, guessed_bootdev,
	CTLFLAG_RD, &bootdev, 0, "Boot device (not in cdev_t format)");

/*
 * Initialize 386 and configure to run kernel
 */

/*
 * Initialize segments & interrupt table
 */

int _default_ldt;
struct user_segment_descriptor gdt[NGDT * MAXCPU];	/* global descriptor table */
static struct gate_descriptor idt0[NIDT];
struct gate_descriptor *idt = &idt0[0];	/* interrupt descriptor table */
#if JG
union descriptor ldt[NLDT];		/* local descriptor table */
#endif

/* table descriptors - used to load tables by cpu */
struct region_descriptor r_gdt, r_idt;

/* JG proc0paddr is a virtual address */
void *proc0paddr;
/* JG alignment? */
char proc0paddr_buff[LWKT_THREAD_STACK];


/* software prototypes -- in more palatable form */
struct soft_segment_descriptor gdt_segs[] = {
/* GNULL_SEL	0 Null Descriptor */
{	0x0,			/* segment base address  */
	0x0,			/* length */
	0,			/* segment type */
	0,			/* segment descriptor priority level */
	0,			/* segment descriptor present */
	0,			/* long */
	0,			/* default 32 vs 16 bit size */
	0  			/* limit granularity (byte/page units)*/ },
/* GCODE_SEL	1 Code Descriptor for kernel */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMERA,		/* segment type */
	SEL_KPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	1,			/* long */
	0,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
/* GDATA_SEL	2 Data Descriptor for kernel */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMRWA,		/* segment type */
	SEL_KPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	1,			/* long */
	0,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
/* GUCODE32_SEL	3 32 bit Code Descriptor for user */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMERA,		/* segment type */
	SEL_UPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	0,			/* long */
	1,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
/* GUDATA_SEL	4 32/64 bit Data Descriptor for user */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMRWA,		/* segment type */
	SEL_UPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	0,			/* long */
	1,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
/* GUCODE_SEL	5 64 bit Code Descriptor for user */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMERA,		/* segment type */
	SEL_UPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	1,			/* long */
	0,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
/* GPROC0_SEL	6 Proc 0 Tss Descriptor */
{
	0x0,			/* segment base address */
	sizeof(struct x86_64tss)-1,/* length - all address space */
	SDT_SYSTSS,		/* segment type */
	SEL_KPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	0,			/* long */
	0,			/* unused - default 32 vs 16 bit size */
	0  			/* limit granularity (byte/page units)*/ },
/* Actually, the TSS is a system descriptor which is double size */
{	0x0,			/* segment base address  */
	0x0,			/* length */
	0,			/* segment type */
	0,			/* segment descriptor priority level */
	0,			/* segment descriptor present */
	0,			/* long */
	0,			/* default 32 vs 16 bit size */
	0  			/* limit granularity (byte/page units)*/ },
/* GUGS32_SEL	8 32 bit GS Descriptor for user */
{	0x0,			/* segment base address  */
	0xfffff,		/* length - all address space */
	SDT_MEMRWA,		/* segment type */
	SEL_UPL,		/* segment descriptor priority level */
	1,			/* segment descriptor present */
	0,			/* long */
	1,			/* default 32 vs 16 bit size */
	1  			/* limit granularity (byte/page units)*/ },
};

void
setidt(int idx, inthand_t *func, int typ, int dpl, int ist)
{
	struct gate_descriptor *ip;

	ip = idt + idx;
	ip->gd_looffset = (uintptr_t)func;
	ip->gd_selector = GSEL(GCODE_SEL, SEL_KPL);
	ip->gd_ist = ist;
	ip->gd_xx = 0;
	ip->gd_type = typ;
	ip->gd_dpl = dpl;
	ip->gd_p = 1;
	ip->gd_hioffset = ((uintptr_t)func)>>16 ;
}

#define	IDTVEC(name)	__CONCAT(X,name)

extern inthand_t
	IDTVEC(div), IDTVEC(dbg), IDTVEC(nmi), IDTVEC(bpt), IDTVEC(ofl),
	IDTVEC(bnd), IDTVEC(ill), IDTVEC(dna), IDTVEC(fpusegm),
	IDTVEC(tss), IDTVEC(missing), IDTVEC(stk), IDTVEC(prot),
	IDTVEC(page), IDTVEC(mchk), IDTVEC(rsvd), IDTVEC(fpu), IDTVEC(align),
	IDTVEC(xmm), IDTVEC(dblfault),
	IDTVEC(fast_syscall), IDTVEC(fast_syscall32);

#ifdef DEBUG_INTERRUPTS
extern inthand_t *Xrsvdary[256];
#endif

void
sdtossd(struct user_segment_descriptor *sd, struct soft_segment_descriptor *ssd)
{
	ssd->ssd_base  = (sd->sd_hibase << 24) | sd->sd_lobase;
	ssd->ssd_limit = (sd->sd_hilimit << 16) | sd->sd_lolimit;
	ssd->ssd_type  = sd->sd_type;
	ssd->ssd_dpl   = sd->sd_dpl;
	ssd->ssd_p     = sd->sd_p;
	ssd->ssd_def32 = sd->sd_def32;
	ssd->ssd_gran  = sd->sd_gran;
}

void
ssdtosd(struct soft_segment_descriptor *ssd, struct user_segment_descriptor *sd)
{

	sd->sd_lobase = (ssd->ssd_base) & 0xffffff;
	sd->sd_hibase = (ssd->ssd_base >> 24) & 0xff;
	sd->sd_lolimit = (ssd->ssd_limit) & 0xffff;
	sd->sd_hilimit = (ssd->ssd_limit >> 16) & 0xf;
	sd->sd_type  = ssd->ssd_type;
	sd->sd_dpl   = ssd->ssd_dpl;
	sd->sd_p     = ssd->ssd_p;
	sd->sd_long  = ssd->ssd_long;
	sd->sd_def32 = ssd->ssd_def32;
	sd->sd_gran  = ssd->ssd_gran;
}

void
ssdtosyssd(struct soft_segment_descriptor *ssd,
    struct system_segment_descriptor *sd)
{

	sd->sd_lobase = (ssd->ssd_base) & 0xffffff;
	sd->sd_hibase = (ssd->ssd_base >> 24) & 0xfffffffffful;
	sd->sd_lolimit = (ssd->ssd_limit) & 0xffff;
	sd->sd_hilimit = (ssd->ssd_limit >> 16) & 0xf;
	sd->sd_type  = ssd->ssd_type;
	sd->sd_dpl   = ssd->ssd_dpl;
	sd->sd_p     = ssd->ssd_p;
	sd->sd_gran  = ssd->ssd_gran;
}

/*
 * Populate the (physmap) array with base/bound pairs describing the
 * available physical memory in the system, then test this memory and
 * build the phys_avail array describing the actually-available memory.
 *
 * If we cannot accurately determine the physical memory map, then use
 * value from the 0xE801 call, and failing that, the RTC.
 *
 * Total memory size may be set by the kernel environment variable
 * hw.physmem or the compile-time define MAXMEM.
 *
 * Memory is aligned to PHYSMAP_ALIGN which must be a multiple
 * of PAGE_SIZE.  This also greatly reduces the memory test time
 * which would otherwise be excessive on machines with > 8G of ram.
 *
 * XXX first should be vm_paddr_t.
 */

#define PHYSMAP_ALIGN		(vm_paddr_t)(128 * 1024)
#define PHYSMAP_ALIGN_MASK	(vm_paddr_t)(PHYSMAP_ALIGN - 1)

static void
getmemsize(caddr_t kmdp, u_int64_t first)
{
	int off, physmap_idx, pa_indx, da_indx;
	int i, j;
	vm_paddr_t physmap[PHYSMAP_SIZE];
	vm_paddr_t pa;
	vm_paddr_t msgbuf_size;
	u_long physmem_tunable;
	pt_entry_t *pte;
	struct bios_smap *smapbase, *smap, *smapend;
	u_int32_t smapsize;
	quad_t dcons_addr, dcons_size;

	bzero(physmap, sizeof(physmap));
	physmap_idx = 0;

	/*
	 * get memory map from INT 15:E820, kindly supplied by the loader.
	 *
	 * subr_module.c says:
	 * "Consumer may safely assume that size value precedes data."
	 * ie: an int32_t immediately precedes smap.
	 */
	smapbase = (struct bios_smap *)preload_search_info(kmdp,
	    MODINFO_METADATA | MODINFOMD_SMAP);
	if (smapbase == NULL)
		panic("No BIOS smap info from loader!");

	smapsize = *((u_int32_t *)smapbase - 1);
	smapend = (struct bios_smap *)((uintptr_t)smapbase + smapsize);

	for (smap = smapbase; smap < smapend; smap++) {
		if (boothowto & RB_VERBOSE)
			kprintf("SMAP type=%02x base=%016lx len=%016lx\n",
			    smap->type, smap->base, smap->length);

		if (smap->type != SMAP_TYPE_MEMORY)
			continue;

		if (smap->length == 0)
			continue;

		for (i = 0; i <= physmap_idx; i += 2) {
			if (smap->base < physmap[i + 1]) {
				if (boothowto & RB_VERBOSE) {
					kprintf("Overlapping or non-monotonic "
						"memory region, ignoring "
						"second region\n");
				}
				continue;
			}
		}
		Realmem += smap->length;

		if (smap->base == physmap[physmap_idx + 1]) {
			physmap[physmap_idx + 1] += smap->length;
			continue;
		}

		physmap_idx += 2;
		if (physmap_idx == PHYSMAP_SIZE) {
			kprintf("Too many segments in the physical "
				"address map, giving up\n");
			break;
		}
		physmap[physmap_idx] = smap->base;
		physmap[physmap_idx + 1] = smap->base + smap->length;
	}

	base_memory = physmap[1] / 1024;
#ifdef SMP
	/* make hole for AP bootstrap code */
	physmap[1] = mp_bootaddress(base_memory);
#endif

	/* Save EBDA address, if any */
	ebda_addr = (u_long)(*(u_short *)(KERNBASE + 0x40e));
	ebda_addr <<= 4;

	/*
	 * Maxmem isn't the "maximum memory", it's one larger than the
	 * highest page of the physical address space.  It should be
	 * called something like "Maxphyspage".  We may adjust this
	 * based on ``hw.physmem'' and the results of the memory test.
	 */
	Maxmem = atop(physmap[physmap_idx + 1]);

#ifdef MAXMEM
	Maxmem = MAXMEM / 4;
#endif

	if (TUNABLE_ULONG_FETCH("hw.physmem", &physmem_tunable))
		Maxmem = atop(physmem_tunable);

	/*
	 * Don't allow MAXMEM or hw.physmem to extend the amount of memory
	 * in the system.
	 */
	if (Maxmem > atop(physmap[physmap_idx + 1]))
		Maxmem = atop(physmap[physmap_idx + 1]);

	/*
	 * Blowing out the DMAP will blow up the system.
	 */
	if (Maxmem > atop(DMAP_MAX_ADDRESS - DMAP_MIN_ADDRESS)) {
		kprintf("Limiting Maxmem due to DMAP size\n");
		Maxmem = atop(DMAP_MAX_ADDRESS - DMAP_MIN_ADDRESS);
	}

	if (atop(physmap[physmap_idx + 1]) != Maxmem &&
	    (boothowto & RB_VERBOSE)) {
		kprintf("Physical memory use set to %ldK\n", Maxmem * 4);
	}

	/*
	 * Call pmap initialization to make new kernel address space
	 *
	 * Mask off page 0.
	 */
	pmap_bootstrap(&first);
	physmap[0] = PAGE_SIZE;

	/*
	 * Align the physmap to PHYSMAP_ALIGN and cut out anything
	 * exceeding Maxmem.
	 */
	for (i = j = 0; i <= physmap_idx; i += 2) {
		if (physmap[i+1] > ptoa((vm_paddr_t)Maxmem))
			physmap[i+1] = ptoa((vm_paddr_t)Maxmem);
		physmap[i] = (physmap[i] + PHYSMAP_ALIGN_MASK) &
			     ~PHYSMAP_ALIGN_MASK;
		physmap[i+1] = physmap[i+1] & ~PHYSMAP_ALIGN_MASK;

		physmap[j] = physmap[i];
		physmap[j+1] = physmap[i+1];

		if (physmap[i] < physmap[i+1])
			j += 2;
	}
	physmap_idx = j - 2;

	/*
	 * Align anything else used in the validation loop.
	 */
	first = (first + PHYSMAP_ALIGN_MASK) & ~PHYSMAP_ALIGN_MASK;

	/*
	 * Size up each available chunk of physical memory.
	 */
	pa_indx = 0;
	da_indx = 1;
	phys_avail[pa_indx++] = physmap[0];
	phys_avail[pa_indx] = physmap[0];
	dump_avail[da_indx] = physmap[0];
	pte = CMAP1;

	/*
	 * Get dcons buffer address
	 */
	if (kgetenv_quad("dcons.addr", &dcons_addr) == 0 ||
	    kgetenv_quad("dcons.size", &dcons_size) == 0)
		dcons_addr = 0;

	/*
	 * Validate the physical memory.  The physical memory segments
	 * have already been aligned to PHYSMAP_ALIGN which is a multiple
	 * of PAGE_SIZE.
	 */
	for (i = 0; i <= physmap_idx; i += 2) {
		vm_paddr_t end;

		end = physmap[i + 1];

		for (pa = physmap[i]; pa < end; pa += PHYSMAP_ALIGN) {
			int tmp, page_bad, full;
			int *ptr = (int *)CADDR1;

			full = FALSE;
			/*
			 * block out kernel memory as not available.
			 */
			if (pa >= 0x100000 && pa < first)
				goto do_dump_avail;

			/*
			 * block out dcons buffer
			 */
			if (dcons_addr > 0
			    && pa >= trunc_page(dcons_addr)
			    && pa < dcons_addr + dcons_size) {
				goto do_dump_avail;
			}

			page_bad = FALSE;

			/*
			 * map page into kernel: valid, read/write,non-cacheable
			 */
			*pte = pa | PG_V | PG_RW | PG_N;
			cpu_invltlb();

			tmp = *(int *)ptr;
			/*
			 * Test for alternating 1's and 0's
			 */
			*(volatile int *)ptr = 0xaaaaaaaa;
			cpu_mfence();
			if (*(volatile int *)ptr != 0xaaaaaaaa)
				page_bad = TRUE;
			/*
			 * Test for alternating 0's and 1's
			 */
			*(volatile int *)ptr = 0x55555555;
			cpu_mfence();
			if (*(volatile int *)ptr != 0x55555555)
				page_bad = TRUE;
			/*
			 * Test for all 1's
			 */
			*(volatile int *)ptr = 0xffffffff;
			cpu_mfence();
			if (*(volatile int *)ptr != 0xffffffff)
				page_bad = TRUE;
			/*
			 * Test for all 0's
			 */
			*(volatile int *)ptr = 0x0;
			cpu_mfence();
			if (*(volatile int *)ptr != 0x0)
				page_bad = TRUE;
			/*
			 * Restore original value.
			 */
			*(int *)ptr = tmp;

			/*
			 * Adjust array of valid/good pages.
			 */
			if (page_bad == TRUE)
				continue;
			/*
			 * If this good page is a continuation of the
			 * previous set of good pages, then just increase
			 * the end pointer. Otherwise start a new chunk.
			 * Note that "end" points one higher than end,
			 * making the range >= start and < end.
			 * If we're also doing a speculative memory
			 * test and we at or past the end, bump up Maxmem
			 * so that we keep going. The first bad page
			 * will terminate the loop.
			 */
			if (phys_avail[pa_indx] == pa) {
				phys_avail[pa_indx] += PHYSMAP_ALIGN;
			} else {
				pa_indx++;
				if (pa_indx == PHYS_AVAIL_ARRAY_END) {
					kprintf(
		"Too many holes in the physical address space, giving up\n");
					pa_indx--;
					full = TRUE;
					goto do_dump_avail;
				}
				phys_avail[pa_indx++] = pa;
				phys_avail[pa_indx] = pa + PHYSMAP_ALIGN;
			}
			physmem += PHYSMAP_ALIGN / PAGE_SIZE;
do_dump_avail:
			if (dump_avail[da_indx] == pa) {
				dump_avail[da_indx] += PHYSMAP_ALIGN;
			} else {
				da_indx++;
				if (da_indx == DUMP_AVAIL_ARRAY_END) {
					da_indx--;
					goto do_next;
				}
				dump_avail[da_indx++] = pa;
				dump_avail[da_indx] = pa + PHYSMAP_ALIGN;
			}
do_next:
			if (full)
				break;
		}
	}
	*pte = 0;
	cpu_invltlb();

	/*
	 * The last chunk must contain at least one page plus the message
	 * buffer to avoid complicating other code (message buffer address
	 * calculation, etc.).
	 */
	msgbuf_size = (MSGBUF_SIZE + PHYSMAP_ALIGN_MASK) & ~PHYSMAP_ALIGN_MASK;

	while (phys_avail[pa_indx - 1] + PHYSMAP_ALIGN +
	       msgbuf_size >= phys_avail[pa_indx]) {
		physmem -= atop(phys_avail[pa_indx] - phys_avail[pa_indx - 1]);
		phys_avail[pa_indx--] = 0;
		phys_avail[pa_indx--] = 0;
	}

	Maxmem = atop(phys_avail[pa_indx]);

	/* Trim off space for the message buffer. */
	phys_avail[pa_indx] -= msgbuf_size;

	avail_end = phys_avail[pa_indx];

	/* Map the message buffer. */
	for (off = 0; off < msgbuf_size; off += PAGE_SIZE) {
		pmap_kenter((vm_offset_t)msgbufp + off,
			    phys_avail[pa_indx] + off);
	}
}

struct machintr_abi MachIntrABI;

/*
 * IDT VECTORS:
 *	0	Divide by zero
 *	1	Debug
 *	2	NMI
 *	3	BreakPoint
 *	4	OverFlow
 *	5	Bound-Range
 *	6	Invalid OpCode
 *	7	Device Not Available (x87)
 *	8	Double-Fault
 *	9	Coprocessor Segment overrun (unsupported, reserved)
 *	10	Invalid-TSS
 *	11	Segment not present
 *	12	Stack
 *	13	General Protection
 *	14	Page Fault
 *	15	Reserved
 *	16	x87 FP Exception pending
 *	17	Alignment Check
 *	18	Machine Check
 *	19	SIMD floating point
 *	20-31	reserved
 *	32-255	INTn/external sources
 */
u_int64_t
hammer_time(u_int64_t modulep, u_int64_t physfree)
{
	caddr_t kmdp;
	int gsel_tss, x;
#if JG
	int metadata_missing, off;
#endif
	struct mdglobaldata *gd;
	u_int64_t msr;

	/*
	 * Prevent lowering of the ipl if we call tsleep() early.
	 */
	gd = &CPU_prvspace[0].mdglobaldata;
	bzero(gd, sizeof(*gd));

	/*
	 * Note: on both UP and SMP curthread must be set non-NULL
	 * early in the boot sequence because the system assumes
	 * that 'curthread' is never NULL.
	 */

	gd->mi.gd_curthread = &thread0;
	thread0.td_gd = &gd->mi;

	atdevbase = ISA_HOLE_START + PTOV_OFFSET;

#if JG
	metadata_missing = 0;
	if (bootinfo.bi_modulep) {
		preload_metadata = (caddr_t)bootinfo.bi_modulep + KERNBASE;
		preload_bootstrap_relocate(KERNBASE);
	} else {
		metadata_missing = 1;
	}
	if (bootinfo.bi_envp)
		kern_envp = (caddr_t)bootinfo.bi_envp + KERNBASE;
#endif

	preload_metadata = (caddr_t)(uintptr_t)(modulep + PTOV_OFFSET);
	preload_bootstrap_relocate(PTOV_OFFSET);
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	boothowto = MD_FETCH(kmdp, MODINFOMD_HOWTO, int);
	kern_envp = MD_FETCH(kmdp, MODINFOMD_ENVP, char *) + PTOV_OFFSET;
#ifdef DDB
	ksym_start = MD_FETCH(kmdp, MODINFOMD_SSYM, uintptr_t);
	ksym_end = MD_FETCH(kmdp, MODINFOMD_ESYM, uintptr_t);
#endif

	if (boothowto & RB_VERBOSE)
		bootverbose++;

	/*
	 * Default MachIntrABI to ICU
	 */
	MachIntrABI = MachIntrABI_ICU;

	TUNABLE_INT_FETCH("hw.apic_io_enable", &ioapic_enable); /* for compat */
	TUNABLE_INT_FETCH("hw.ioapic_enable", &ioapic_enable);
	TUNABLE_INT_FETCH("hw.lapic_enable", &lapic_enable);

	/*
	 * start with one cpu.  Note: with one cpu, ncpus2_shift, ncpus2_mask,
	 * and ncpus_fit_mask remain 0.
	 */
	ncpus = 1;
	ncpus2 = 1;
	ncpus_fit = 1;
	/* Init basic tunables, hz etc */
	init_param1();

	/*
	 * make gdt memory segments
	 */
	gdt_segs[GPROC0_SEL].ssd_base =
		(uintptr_t) &CPU_prvspace[0].mdglobaldata.gd_common_tss;

	gd->mi.gd_prvspace = &CPU_prvspace[0];

	for (x = 0; x < NGDT; x++) {
		if (x != GPROC0_SEL && x != (GPROC0_SEL + 1))
			ssdtosd(&gdt_segs[x], &gdt[x]);
	}
	ssdtosyssd(&gdt_segs[GPROC0_SEL],
	    (struct system_segment_descriptor *)&gdt[GPROC0_SEL]);

	r_gdt.rd_limit = NGDT * sizeof(gdt[0]) - 1;
	r_gdt.rd_base =  (long) gdt;
	lgdt(&r_gdt);

	wrmsr(MSR_FSBASE, 0);		/* User value */
	wrmsr(MSR_GSBASE, (u_int64_t)&gd->mi);
	wrmsr(MSR_KGSBASE, 0);		/* User value while in the kernel */

	mi_gdinit(&gd->mi, 0);
	cpu_gdinit(gd, 0);
	proc0paddr = proc0paddr_buff;
	mi_proc0init(&gd->mi, proc0paddr);
	safepri = TDPRI_MAX;

	/* spinlocks and the BGL */
	init_locks();

	/* exceptions */
	for (x = 0; x < NIDT; x++)
		setidt(x, &IDTVEC(rsvd), SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DE, &IDTVEC(div),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DB, &IDTVEC(dbg),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NMI, &IDTVEC(nmi),  SDT_SYSIGT, SEL_KPL, 1);
 	setidt(IDT_BP, &IDTVEC(bpt),  SDT_SYSIGT, SEL_UPL, 0);
	setidt(IDT_OF, &IDTVEC(ofl),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_BR, &IDTVEC(bnd),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_UD, &IDTVEC(ill),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NM, &IDTVEC(dna),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_DF, &IDTVEC(dblfault), SDT_SYSIGT, SEL_KPL, 1);
	setidt(IDT_FPUGP, &IDTVEC(fpusegm),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_TS, &IDTVEC(tss),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_NP, &IDTVEC(missing),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_SS, &IDTVEC(stk),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_GP, &IDTVEC(prot),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_PF, &IDTVEC(page),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_MF, &IDTVEC(fpu),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_AC, &IDTVEC(align), SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_MC, &IDTVEC(mchk),  SDT_SYSIGT, SEL_KPL, 0);
	setidt(IDT_XF, &IDTVEC(xmm), SDT_SYSIGT, SEL_KPL, 0);

	r_idt.rd_limit = sizeof(idt0) - 1;
	r_idt.rd_base = (long) idt;
	lidt(&r_idt);

	/*
	 * Initialize the console before we print anything out.
	 */
	cninit();

#if JG
	if (metadata_missing)
		kprintf("WARNING: loader(8) metadata is missing!\n");
#endif

#if	NISA >0
	elcr_probe();
	isa_defaultirq();
#endif
	rand_initialize();

	/*
	 * Initialize IRQ mapping
	 *
	 * NOTE:
	 * SHOULD be after elcr_probe()
	 */
	MachIntrABI_ICU.initmap();
#ifdef SMP
	MachIntrABI_IOAPIC.initmap();
#endif

#ifdef DDB
	kdb_init();
	if (boothowto & RB_KDB)
		Debugger("Boot flags requested debugger");
#endif

#if JG
	finishidentcpu();	/* Final stage of CPU initialization */
	setidt(6, &IDTVEC(ill),  SDT_SYS386IGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	setidt(13, &IDTVEC(prot),  SDT_SYS386IGT, SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
#endif
	identify_cpu();		/* Final stage of CPU initialization */
	initializecpu();	/* Initialize CPU registers */
	initializecpucache();

	/* make an initial tss so cpu can get interrupt stack on syscall! */
	gd->gd_common_tss.tss_rsp0 =
		(register_t)(thread0.td_kstack +
			     KSTACK_PAGES * PAGE_SIZE - sizeof(struct pcb));
	/* Ensure the stack is aligned to 16 bytes */
	gd->gd_common_tss.tss_rsp0 &= ~(register_t)0xF;

	/* double fault stack */
	gd->gd_common_tss.tss_ist1 =
		(long)&gd->mi.gd_prvspace->idlestack[
			sizeof(gd->mi.gd_prvspace->idlestack)];

	/* Set the IO permission bitmap (empty due to tss seg limit) */
	gd->gd_common_tss.tss_iobase = sizeof(struct x86_64tss);

	gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);
	gd->gd_tss_gdt = &gdt[GPROC0_SEL];
	gd->gd_common_tssd = *gd->gd_tss_gdt;
	ltr(gsel_tss);

	/* Set up the fast syscall stuff */
	msr = rdmsr(MSR_EFER) | EFER_SCE;
	wrmsr(MSR_EFER, msr);
	wrmsr(MSR_LSTAR, (u_int64_t)IDTVEC(fast_syscall));
	wrmsr(MSR_CSTAR, (u_int64_t)IDTVEC(fast_syscall32));
	msr = ((u_int64_t)GSEL(GCODE_SEL, SEL_KPL) << 32) |
	      ((u_int64_t)GSEL(GUCODE32_SEL, SEL_UPL) << 48);
	wrmsr(MSR_STAR, msr);
	wrmsr(MSR_SF_MASK, PSL_NT|PSL_T|PSL_I|PSL_C|PSL_D);

	getmemsize(kmdp, physfree);
	init_param2(physmem);

	/* now running on new page tables, configured,and u/iom is accessible */

	/* Map the message buffer. */
#if JG
	for (off = 0; off < round_page(MSGBUF_SIZE); off += PAGE_SIZE)
		pmap_kenter((vm_offset_t)msgbufp + off, avail_end + off);
#endif

	msgbufinit(msgbufp, MSGBUF_SIZE);


	/* transfer to user mode */

	_ucodesel = GSEL(GUCODE_SEL, SEL_UPL);
	_udatasel = GSEL(GUDATA_SEL, SEL_UPL);
	_ucode32sel = GSEL(GUCODE32_SEL, SEL_UPL);

	load_ds(_udatasel);
	load_es(_udatasel);
	load_fs(_udatasel);

	/* setup proc 0's pcb */
	thread0.td_pcb->pcb_flags = 0;
	thread0.td_pcb->pcb_cr3 = KPML4phys;
	thread0.td_pcb->pcb_ext = 0;
	lwp0.lwp_md.md_regs = &proc0_tf;	/* XXX needed? */

	/* Location of kernel stack for locore */
	return ((u_int64_t)thread0.td_pcb);
}

/*
 * Initialize machine-dependant portions of the global data structure.
 * Note that the global data area and cpu0's idlestack in the private
 * data space were allocated in locore.
 *
 * Note: the idlethread's cpl is 0
 *
 * WARNING!  Called from early boot, 'mycpu' may not work yet.
 */
void
cpu_gdinit(struct mdglobaldata *gd, int cpu)
{
	if (cpu)
		gd->mi.gd_curthread = &gd->mi.gd_idlethread;

	lwkt_init_thread(&gd->mi.gd_idlethread, 
			gd->mi.gd_prvspace->idlestack, 
			sizeof(gd->mi.gd_prvspace->idlestack), 
			0, &gd->mi);
	lwkt_set_comm(&gd->mi.gd_idlethread, "idle_%d", cpu);
	gd->mi.gd_idlethread.td_switch = cpu_lwkt_switch;
	gd->mi.gd_idlethread.td_sp -= sizeof(void *);
	*(void **)gd->mi.gd_idlethread.td_sp = cpu_idle_restore;
}

int
is_globaldata_space(vm_offset_t saddr, vm_offset_t eaddr)
{
	if (saddr >= (vm_offset_t)&CPU_prvspace[0] &&
	    eaddr <= (vm_offset_t)&CPU_prvspace[MAXCPU]) {
		return (TRUE);
	}
	return (FALSE);
}

struct globaldata *
globaldata_find(int cpu)
{
	KKASSERT(cpu >= 0 && cpu < ncpus);
	return(&CPU_prvspace[cpu].mdglobaldata.mi);
}

int
ptrace_set_pc(struct lwp *lp, unsigned long addr)
{
	lp->lwp_md.md_regs->tf_rip = addr;
	return (0);
}

int
ptrace_single_step(struct lwp *lp)
{
	lp->lwp_md.md_regs->tf_rflags |= PSL_T;
	return (0);
}

int
fill_regs(struct lwp *lp, struct reg *regs)
{
	struct trapframe *tp;

	tp = lp->lwp_md.md_regs;
	bcopy(&tp->tf_rdi, &regs->r_rdi, sizeof(*regs));
	return (0);
}

int
set_regs(struct lwp *lp, struct reg *regs)
{
	struct trapframe *tp;

	tp = lp->lwp_md.md_regs;
	if (!EFL_SECURE(regs->r_rflags, tp->tf_rflags) ||
	    !CS_SECURE(regs->r_cs))
		return (EINVAL);
	bcopy(&regs->r_rdi, &tp->tf_rdi, sizeof(*regs));
	return (0);
}

#ifndef CPU_DISABLE_SSE
static void
fill_fpregs_xmm(struct savexmm *sv_xmm, struct save87 *sv_87)
{
	struct env87 *penv_87 = &sv_87->sv_env;
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	int i;

	/* FPU control/status */
	penv_87->en_cw = penv_xmm->en_cw;
	penv_87->en_sw = penv_xmm->en_sw;
	penv_87->en_tw = penv_xmm->en_tw;
	penv_87->en_fip = penv_xmm->en_fip;
	penv_87->en_fcs = penv_xmm->en_fcs;
	penv_87->en_opcode = penv_xmm->en_opcode;
	penv_87->en_foo = penv_xmm->en_foo;
	penv_87->en_fos = penv_xmm->en_fos;

	/* FPU registers */
	for (i = 0; i < 8; ++i)
		sv_87->sv_ac[i] = sv_xmm->sv_fp[i].fp_acc;
}

static void
set_fpregs_xmm(struct save87 *sv_87, struct savexmm *sv_xmm)
{
	struct env87 *penv_87 = &sv_87->sv_env;
	struct envxmm *penv_xmm = &sv_xmm->sv_env;
	int i;

	/* FPU control/status */
	penv_xmm->en_cw = penv_87->en_cw;
	penv_xmm->en_sw = penv_87->en_sw;
	penv_xmm->en_tw = penv_87->en_tw;
	penv_xmm->en_fip = penv_87->en_fip;
	penv_xmm->en_fcs = penv_87->en_fcs;
	penv_xmm->en_opcode = penv_87->en_opcode;
	penv_xmm->en_foo = penv_87->en_foo;
	penv_xmm->en_fos = penv_87->en_fos;

	/* FPU registers */
	for (i = 0; i < 8; ++i)
		sv_xmm->sv_fp[i].fp_acc = sv_87->sv_ac[i];
}
#endif /* CPU_DISABLE_SSE */

int
fill_fpregs(struct lwp *lp, struct fpreg *fpregs)
{
#ifndef CPU_DISABLE_SSE
	if (cpu_fxsr) {
		fill_fpregs_xmm(&lp->lwp_thread->td_pcb->pcb_save.sv_xmm,
				(struct save87 *)fpregs);
		return (0);
	}
#endif /* CPU_DISABLE_SSE */
	bcopy(&lp->lwp_thread->td_pcb->pcb_save.sv_87, fpregs, sizeof *fpregs);
	return (0);
}

int
set_fpregs(struct lwp *lp, struct fpreg *fpregs)
{
#ifndef CPU_DISABLE_SSE
	if (cpu_fxsr) {
		set_fpregs_xmm((struct save87 *)fpregs,
			       &lp->lwp_thread->td_pcb->pcb_save.sv_xmm);
		return (0);
	}
#endif /* CPU_DISABLE_SSE */
	bcopy(fpregs, &lp->lwp_thread->td_pcb->pcb_save.sv_87, sizeof *fpregs);
	return (0);
}

int
fill_dbregs(struct lwp *lp, struct dbreg *dbregs)
{
        if (lp == NULL) {
                dbregs->dr[0] = rdr0();
                dbregs->dr[1] = rdr1();
                dbregs->dr[2] = rdr2();
                dbregs->dr[3] = rdr3();
                dbregs->dr[4] = rdr4();
                dbregs->dr[5] = rdr5();
                dbregs->dr[6] = rdr6();
                dbregs->dr[7] = rdr7();
        } else {
		struct pcb *pcb;

                pcb = lp->lwp_thread->td_pcb;
                dbregs->dr[0] = pcb->pcb_dr0;
                dbregs->dr[1] = pcb->pcb_dr1;
                dbregs->dr[2] = pcb->pcb_dr2;
                dbregs->dr[3] = pcb->pcb_dr3;
                dbregs->dr[4] = 0;
                dbregs->dr[5] = 0;
                dbregs->dr[6] = pcb->pcb_dr6;
                dbregs->dr[7] = pcb->pcb_dr7;
        }
	return (0);
}

int
set_dbregs(struct lwp *lp, struct dbreg *dbregs)
{
	if (lp == NULL) {
		load_dr0(dbregs->dr[0]);
		load_dr1(dbregs->dr[1]);
		load_dr2(dbregs->dr[2]);
		load_dr3(dbregs->dr[3]);
		load_dr4(dbregs->dr[4]);
		load_dr5(dbregs->dr[5]);
		load_dr6(dbregs->dr[6]);
		load_dr7(dbregs->dr[7]);
	} else {
		struct pcb *pcb;
		struct ucred *ucred;
		int i;
		uint64_t mask1, mask2;

		/*
		 * Don't let an illegal value for dr7 get set.	Specifically,
		 * check for undefined settings.  Setting these bit patterns
		 * result in undefined behaviour and can lead to an unexpected
		 * TRCTRAP.
		 */
		/* JG this loop looks unreadable */
		/* Check 4 2-bit fields for invalid patterns.
		 * These fields are R/Wi, for i = 0..3
		 */
		/* Is 10 in LENi allowed when running in compatibility mode? */
		/* Pattern 10 in R/Wi might be used to indicate
		 * breakpoint on I/O. Further analysis should be
		 * carried to decide if it is safe and useful to
		 * provide access to that capability
		 */
		for (i = 0, mask1 = 0x3<<16, mask2 = 0x2<<16; i < 4; 
		     i++, mask1 <<= 4, mask2 <<= 4)
			if ((dbregs->dr[7] & mask1) == mask2)
				return (EINVAL);
		
		pcb = lp->lwp_thread->td_pcb;
		ucred = lp->lwp_proc->p_ucred;

		/*
		 * Don't let a process set a breakpoint that is not within the
		 * process's address space.  If a process could do this, it
		 * could halt the system by setting a breakpoint in the kernel
		 * (if ddb was enabled).  Thus, we need to check to make sure
		 * that no breakpoints are being enabled for addresses outside
		 * process's address space, unless, perhaps, we were called by
		 * uid 0.
		 *
		 * XXX - what about when the watched area of the user's
		 * address space is written into from within the kernel
		 * ... wouldn't that still cause a breakpoint to be generated
		 * from within kernel mode?
		 */

		if (priv_check_cred(ucred, PRIV_ROOT, 0) != 0) {
			if (dbregs->dr[7] & 0x3) {
				/* dr0 is enabled */
				if (dbregs->dr[0] >= VM_MAX_USER_ADDRESS)
					return (EINVAL);
			}

			if (dbregs->dr[7] & (0x3<<2)) {
				/* dr1 is enabled */
				if (dbregs->dr[1] >= VM_MAX_USER_ADDRESS)
					return (EINVAL);
			}

			if (dbregs->dr[7] & (0x3<<4)) {
				/* dr2 is enabled */
				if (dbregs->dr[2] >= VM_MAX_USER_ADDRESS)
					return (EINVAL);
			}

			if (dbregs->dr[7] & (0x3<<6)) {
				/* dr3 is enabled */
				if (dbregs->dr[3] >= VM_MAX_USER_ADDRESS)
					return (EINVAL);
			}
		}

		pcb->pcb_dr0 = dbregs->dr[0];
		pcb->pcb_dr1 = dbregs->dr[1];
		pcb->pcb_dr2 = dbregs->dr[2];
		pcb->pcb_dr3 = dbregs->dr[3];
		pcb->pcb_dr6 = dbregs->dr[6];
		pcb->pcb_dr7 = dbregs->dr[7];

		pcb->pcb_flags |= PCB_DBREGS;
	}

	return (0);
}

/*
 * Return > 0 if a hardware breakpoint has been hit, and the
 * breakpoint was in user space.  Return 0, otherwise.
 */
int
user_dbreg_trap(void)
{
        u_int64_t dr7, dr6; /* debug registers dr6 and dr7 */
        u_int64_t bp;       /* breakpoint bits extracted from dr6 */
        int nbp;            /* number of breakpoints that triggered */
        caddr_t addr[4];    /* breakpoint addresses */
        int i;
        
        dr7 = rdr7();
        if ((dr7 & 0xff) == 0) {
                /*
                 * all GE and LE bits in the dr7 register are zero,
                 * thus the trap couldn't have been caused by the
                 * hardware debug registers
                 */
                return 0;
        }

        nbp = 0;
        dr6 = rdr6();
        bp = dr6 & 0xf;

        if (bp == 0) {
                /*
                 * None of the breakpoint bits are set meaning this
                 * trap was not caused by any of the debug registers
                 */
                return 0;
        }

        /*
         * at least one of the breakpoints were hit, check to see
         * which ones and if any of them are user space addresses
         */

        if (bp & 0x01) {
                addr[nbp++] = (caddr_t)rdr0();
        }
        if (bp & 0x02) {
                addr[nbp++] = (caddr_t)rdr1();
        }
        if (bp & 0x04) {
                addr[nbp++] = (caddr_t)rdr2();
        }
        if (bp & 0x08) {
                addr[nbp++] = (caddr_t)rdr3();
        }

        for (i=0; i<nbp; i++) {
                if (addr[i] <
                    (caddr_t)VM_MAX_USER_ADDRESS) {
                        /*
                         * addr[i] is in user space
                         */
                        return nbp;
                }
        }

        /*
         * None of the breakpoints are in user space.
         */
        return 0;
}


#ifndef DDB
void
Debugger(const char *msg)
{
	kprintf("Debugger(\"%s\") called.\n", msg);
}
#endif /* no DDB */

#ifdef DDB

/*
 * Provide inb() and outb() as functions.  They are normally only
 * available as macros calling inlined functions, thus cannot be
 * called inside DDB.
 *
 * The actual code is stolen from <machine/cpufunc.h>, and de-inlined.
 */

#undef inb
#undef outb

/* silence compiler warnings */
u_char inb(u_int);
void outb(u_int, u_char);

u_char
inb(u_int port)
{
	u_char	data;
	/*
	 * We use %%dx and not %1 here because i/o is done at %dx and not at
	 * %edx, while gcc generates inferior code (movw instead of movl)
	 * if we tell it to load (u_short) port.
	 */
	__asm __volatile("inb %%dx,%0" : "=a" (data) : "d" (port));
	return (data);
}

void
outb(u_int port, u_char data)
{
	u_char	al;
	/*
	 * Use an unnecessary assignment to help gcc's register allocator.
	 * This make a large difference for gcc-1.40 and a tiny difference
	 * for gcc-2.6.0.  For gcc-1.40, al had to be ``asm("ax")'' for
	 * best results.  gcc-2.6.0 can't handle this.
	 */
	al = data;
	__asm __volatile("outb %0,%%dx" : : "a" (al), "d" (port));
}

#endif /* DDB */



#include "opt_cpu.h"


/*
 * initialize all the SMP locks
 */

/* critical region when masking or unmasking interupts */
struct spinlock_deprecated imen_spinlock;

/* critical region for old style disable_intr/enable_intr */
struct spinlock_deprecated mpintr_spinlock;

/* critical region around INTR() routines */
struct spinlock_deprecated intr_spinlock;

/* lock region used by kernel profiling */
struct spinlock_deprecated mcount_spinlock;

/* locks com (tty) data/hardware accesses: a FASTINTR() */
struct spinlock_deprecated com_spinlock;

/* lock regions around the clock hardware */
struct spinlock_deprecated clock_spinlock;

static void
init_locks(void)
{
#ifdef SMP
	/*
	 * Get the initial mplock with a count of 1 for the BSP.
	 * This uses a LOGICAL cpu ID, ie BSP == 0.
	 */
	cpu_get_initial_mplock();
#endif
	/* DEPRECATED */
	spin_lock_init(&mcount_spinlock);
	spin_lock_init(&intr_spinlock);
	spin_lock_init(&mpintr_spinlock);
	spin_lock_init(&imen_spinlock);
	spin_lock_init(&com_spinlock);
	spin_lock_init(&clock_spinlock);

	/* our token pool needs to work early */
	lwkt_token_pool_init();
}

