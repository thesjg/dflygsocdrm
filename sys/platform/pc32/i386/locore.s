/*-
 * Copyright (c) 1990 The Regents of the University of California.
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
 *	from: @(#)locore.s	7.3 (Berkeley) 5/13/91
 * $FreeBSD: src/sys/i386/i386/locore.s,v 1.132.2.10 2003/02/03 20:54:49 jhb Exp $
 * $DragonFly: src/sys/platform/pc32/i386/locore.s,v 1.13 2007/01/08 03:33:42 dillon Exp $
 *
 *		originally from: locore.s, by William F. Jolitz
 *
 *		Substantially rewritten by David Greenman, Rod Grimes,
 *			Bruce Evans, Wolfgang Solfrank, Poul-Henning Kamp
 *			and many others.
 */

#include "opt_bootp.h"
#include "opt_nfsroot.h"

#include <sys/syscall.h>
#include <sys/reboot.h>

#include <machine/asmacros.h>
#include <machine/cputypes.h>
#include <machine/psl.h>
#include <machine/pmap.h>
#include <machine/specialreg.h>

#include "assym.s"

/*
 *	XXX
 *
 * Note: This version greatly munged to avoid various assembler errors
 * that may be fixed in newer versions of gas. Perhaps newer versions
 * will have more pleasant appearance.
 */

/*
 * PTmap is recursive pagemap at top of virtual address space.
 * Within PTmap, the page directory can be found (third indirection).
 */
	.globl	PTmap,PTD,PTDpde
	.set	PTmap,(PTDPTDI << PDRSHIFT)
	.set	PTD,PTmap + (PTDPTDI * PAGE_SIZE)
	.set	PTDpde,PTD + (PTDPTDI * PDESIZE)

/*
 * APTmap, APTD is the alternate recursive pagemap.
 * It's used when modifying another process's page tables.
 */
	.globl	APTmap,APTD,APTDpde
	.set	APTmap,APTDPTDI << PDRSHIFT
	.set	APTD,APTmap + (APTDPTDI * PAGE_SIZE)
	.set	APTDpde,PTD + (APTDPTDI * PDESIZE)

/*
 * Compiled KERNBASE location
 */
	.globl	kernbase
	.set	kernbase,KERNBASE

/*
 * Globals
 */
	.data
	ALIGN_DATA		/* just to be sure */

	.globl	.tmpstk
	.space	0x2000		/* space for tmpstk - temporary stack */
.tmpstk:

	.globl	boothowto,bootdev,bootinfo

bootinfo:	.space	BOOTINFO_SIZE		/* bootinfo buffer space */

KERNend:	.long	0			/* phys addr end of kernel (just after bss) */
physfree:	.long	0			/* phys addr of next free page */

#if 0
		.globl	cpu0prvpage
cpu0prvpage:	.long	0			/* relocated version */
#endif
cpu0pp:		.long	0			/* phys addr cpu0 private pg */
cpu0idlestk:	.long	0			/* stack for the idle thread */

		.globl	SMPpt
SMPptpa:	.long	0			/* phys addr SMP page table */
SMPpt:		.long	0			/* relocated version */

	.globl	IdlePTD
IdlePTD:	.long	0			/* phys addr of kernel PTD */

	.globl	KPTphys
KPTphys:	.long	0			/* PA of kernel page tables */

	.globl	proc0paddr
proc0paddr:	.long	0			/* VA of proc 0 address space */
p0upa:		.long	0			/* PA of proc0's UPAGES */

vm86phystk:	.long	0			/* PA of vm86/bios stack */

	.globl	vm86paddr, vm86pa
vm86paddr:	.long	0			/* address of vm86 region */
vm86pa:		.long	0			/* phys addr of vm86 region */

#ifdef BDE_DEBUGGER
	.globl	bdb_exists			/* BDE debugger is present */
bdb_exists:	.long	0
#endif

/**********************************************************************
 *
 * Some handy macros
 *
 */

#define R(foo) ((foo)-KERNBASE)

#define ALLOCPAGES(foo) 				\
	movl	R(physfree), %esi ; 			\
	movl	$((foo)*PAGE_SIZE), %eax ; 		\
	addl	%esi, %eax ; 				\
	movl	%eax, R(physfree) ; 			\
	movl	%esi, %edi ; 				\
	movl	$((foo)*PAGE_SIZE),%ecx ; 		\
	xorl	%eax,%eax ; 				\
	cld ; 						\
	rep ; 						\
	stosb

/*
 * fillkpt
 *	eax = page frame address
 *	ebx = index into page table
 *	ecx = how many pages to map
 * 	base = base address of page dir/table
 *	prot = protection bits
 */
#define	fillkpt(base, prot)		  \
	shll	$2,%ebx			; \
	addl	base,%ebx		; \
	orl	$PG_V,%eax		; \
	orl	prot,%eax		; \
1:	movl	%eax,(%ebx)		; \
	addl	$PAGE_SIZE,%eax		; /* increment physical address */ \
	addl	$4,%ebx			; /* next pte */ \
	loop	1b

/*
 * fillkptphys(prot)
 *	eax = physical address
 *	ecx = how many pages to map
 *	prot = protection bits
 */
#define	fillkptphys(prot)		  \
	movl	%eax, %ebx		; \
	shrl	$PAGE_SHIFT, %ebx	; \
	fillkpt(R(KPTphys), prot)

	.text
/**********************************************************************
 *
 * This is where the bootblocks start us, set the ball rolling...
 *
 */
NON_GPROF_ENTRY(btext)

#ifdef BDE_DEBUGGER
#ifdef BIOS_STEALS_3K
	cmpl	$0x0375c339,0x95504
#else
	cmpl	$0x0375c339,0x96104	/* XXX - debugger signature */
#endif
	jne	1f
	movb	$1,R(bdb_exists)
1:
#endif
/* Tell the bios to warmboot next time */
	movw	$0x1234,0x472

/* Set up a real frame in case the double return in newboot is executed. */
	pushl	%ebp
	movl	%esp, %ebp

/* Don't trust what the BIOS gives for eflags. */
	pushl	$PSL_KERNEL
	popfl

/*
 * Don't trust what the BIOS gives for %fs and %gs.  Trust the bootstrap
 * to set %cs, %ds, %es and %ss.
 */
	mov	%ds, %ax
	mov	%ax, %fs
	mov	%ax, %gs

/*
 * Clear the bss.  Not all boot programs do it, and it is our job anyway.
 * 
 * XXX we don't check that there is memory for our bss and page tables   
 * before using it.
 * 
 * Note: we must be careful to not overwrite an active gdt or idt.  They
 * inactive from now until we switch to new ones, since we don't load any
 * more segment registers or permit interrupts until after the switch.
 */
	movl	$R(_end),%ecx
	movl	$R(_edata),%edi
	subl	%edi,%ecx
	xorl	%eax,%eax
	cld
	rep
	stosb

	call	recover_bootinfo

/* Get onto a stack that we can trust. */
/*
 * XXX this step is delayed in case recover_bootinfo needs to return via
 * the old stack, but it need not be, since recover_bootinfo actually
 * returns via the old frame.
 */
	movl	$R(.tmpstk),%esp

	call	identify_cpu

	call	create_pagetables

/*
 * If the CPU has support for VME, turn it on.
 */ 
	testl	$CPUID_VME, R(cpu_feature)
	jz	1f
	movl	%cr4, %eax
	orl	$CR4_VME, %eax
	movl	%eax, %cr4
1:

#ifdef BDE_DEBUGGER
/*
 * Adjust as much as possible for paging before enabling paging so that the
 * adjustments can be traced.
 */
	call	bdb_prepare_paging
#endif

/* Now enable paging */
	movl	R(IdlePTD), %eax
	movl	%eax,%cr3			/* load ptd addr into mmu */
	movl	%cr0,%eax			/* get control word */
	orl	$CR0_PE|CR0_PG,%eax		/* enable paging */
	movl	%eax,%cr0			/* and let's page NOW! */


#ifdef BDE_DEBUGGER
/*
 * Complete the adjustments for paging so that we can keep tracing through
 * initi386() after the low (physical) addresses for the gdt and idt become
 * invalid.
 */
	call	bdb_commit_paging
#endif

	pushl	$begin				/* jump to high virtualized address */
	ret

/* now running relocated at KERNBASE where the system is linked to run */
begin:

	/*
	 * set up the bootstrap stack.  The pcb sits at the end of the
	 * bootstrap stack.
	 */
	/* set up bootstrap stack */
	movl	proc0paddr,%esp	/* location of in-kernel pages */
	addl	$UPAGES*PAGE_SIZE-PCB_SIZE,%esp	
	xorl	%eax,%eax		/* mark end of frames */
	movl	%eax,%ebp
	/*movl	proc0paddr,%eax*/
	movl	IdlePTD, %esi
	movl	%esi,PCB_CR3(%esp)

	testl	$CPUID_PGE, R(cpu_feature)
	jz	1f
	movl	%cr4, %eax
	orl	$CR4_PGE, %eax
	movl	%eax, %cr4
1:

	movl	physfree, %esi
	pushl	%esi			/* value of first for init386(first) */

	call	init386			/* wire 386 chip for unix operation */
	popl	%esi

	call	mi_startup		/* autoconfiguration, mountroot etc */

	hlt		/* never returns to here */

/*
 * Signal trampoline, copied to top of user stack
 */
NON_GPROF_ENTRY(sigcode)
	call	*SIGF_HANDLER(%esp)		/* call signal handler */
	lea	SIGF_UC(%esp),%eax		/* get ucontext_t */
	pushl	%eax
	testl	$PSL_VM,UC_EFLAGS(%eax)
	jne	9f
9:
	movl	$SYS_sigreturn,%eax
	pushl	%eax				/* junk to fake return addr. */
	int	$0x80				/* enter kernel with args */
0:	jmp	0b

	ALIGN_TEXT
esigcode:

	.data
	.globl	szsigcode
szsigcode:
	.long	esigcode - sigcode
	.text

/**********************************************************************
 *
 * Recover the bootinfo passed to us from the boot program
 *
 */
recover_bootinfo:
	/*
	 * This code is called in different ways depending on what loaded
	 * and started the kernel.  This is used to detect how we get the
	 * arguments from the other code and what we do with them.
	 *
	 * Old disk boot blocks:
	 *	(*btext)(howto, bootdev, cyloffset, esym);
	 *	[return address == 0, and can NOT be returned to]
	 *	[cyloffset was not supported by the FreeBSD boot code
	 *	 and always passed in as 0]
	 *	[esym is also known as total in the boot code, and
	 *	 was never properly supported by the FreeBSD boot code]
	 *
	 * Old diskless netboot code:
	 *	(*btext)(0,0,0,0,&nfsdiskless,0,0,0);
	 *	[return address != 0, and can NOT be returned to]
	 *	If we are being booted by this code it will NOT work,
	 *	so we are just going to halt if we find this case.
	 *
	 * New uniform boot code:
	 *	(*btext)(howto, bootdev, 0, 0, 0, &bootinfo)
	 *	[return address != 0, and can be returned to]
	 *
	 * There may seem to be a lot of wasted arguments in here, but
	 * that is so the newer boot code can still load very old kernels
	 * and old boot code can load new kernels.
	 */

	/*
	 * The old style disk boot blocks fake a frame on the stack and
	 * did an lret to get here.  The frame on the stack has a return
	 * address of 0.
	 */
	cmpl	$0,4(%ebp)
	je	olddiskboot

	/*
	 * We have some form of return address, so this is either the
	 * old diskless netboot code, or the new uniform code.  That can
	 * be detected by looking at the 5th argument, if it is 0
	 * we are being booted by the new uniform boot code.
	 */
	cmpl	$0,24(%ebp)
	je	newboot

	/*
	 * Seems we have been loaded by the old diskless boot code, we
	 * don't stand a chance of running as the diskless structure
	 * changed considerably between the two, so just halt.
	 */
	 hlt

	/*
	 * We have been loaded by the new uniform boot code.
	 * Let's check the bootinfo version, and if we do not understand
	 * it we return to the loader with a status of 1 to indicate this error
	 */
newboot:
	movl	28(%ebp),%ebx		/* &bootinfo.version */
	movl	BI_VERSION(%ebx),%eax
	cmpl	$1,%eax			/* We only understand version 1 */
	je	1f
	movl	$1,%eax			/* Return status */
	leave
	/*
	 * XXX this returns to our caller's caller (as is required) since
	 * we didn't set up a frame and our caller did.
	 */
	ret

1:
	/*
	 * If we have a kernelname copy it in
	 */
	movl	BI_KERNELNAME(%ebx),%esi
	cmpl	$0,%esi
	je	2f			/* No kernelname */
	movl	$MAXPATHLEN,%ecx	/* Brute force!!! */
	movl	$R(kernelname),%edi
	cmpb	$'/',(%esi)		/* Make sure it starts with a slash */
	je	1f
	movb	$'/',(%edi)
	incl	%edi
	decl	%ecx
1:
	cld
	rep
	movsb

2:
	/*
	 * Determine the size of the boot loader's copy of the bootinfo
	 * struct.  This is impossible to do properly because old versions
	 * of the struct don't contain a size field and there are 2 old
	 * versions with the same version number.
	 */
	movl	$BI_ENDCOMMON,%ecx	/* prepare for sizeless version */
	testl	$RB_BOOTINFO,8(%ebp)	/* bi_size (and bootinfo) valid? */
	je	got_bi_size		/* no, sizeless version */
	movl	BI_SIZE(%ebx),%ecx
got_bi_size:

	/*
	 * Copy the common part of the bootinfo struct
	 */
	movl	%ebx,%esi
	movl	$R(bootinfo),%edi
	cmpl	$BOOTINFO_SIZE,%ecx
	jbe	got_common_bi_size
	movl	$BOOTINFO_SIZE,%ecx
got_common_bi_size:
	cld
	rep
	movsb

#ifdef NFS_ROOT
#ifndef BOOTP_NFSV3
	/*
	 * If we have a nfs_diskless structure copy it in
	 */
	movl	BI_NFS_DISKLESS(%ebx),%esi
	cmpl	$0,%esi
	je	olddiskboot
	movl	$R(nfs_diskless),%edi
	movl	$NFSDISKLESS_SIZE,%ecx
	cld
	rep
	movsb
	movl	$R(nfs_diskless_valid),%edi
	movl	$1,(%edi)
#endif
#endif

	/*
	 * The old style disk boot.
	 *	(*btext)(howto, bootdev, cyloffset, esym);
	 * Note that the newer boot code just falls into here to pick
	 * up howto and bootdev, cyloffset and esym are no longer used
	 */
olddiskboot:
	movl	8(%ebp),%eax
	movl	%eax,R(boothowto)
	movl	12(%ebp),%eax
	movl	%eax,R(bootdev)

	ret


/**********************************************************************
 *
 * Identify the CPU and initialize anything special about it
 *
 */
identify_cpu:

	/* Try to toggle alignment check flag; does not exist on 386. */
	pushfl
	popl	%eax
	movl	%eax,%ecx
	orl	$PSL_AC,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	xorl	%ecx,%eax
	andl	$PSL_AC,%eax
	pushl	%ecx
	popfl

	testl	%eax,%eax
	jnz	try486

	/* NexGen CPU does not have aligment check flag. */
	pushfl
	movl	$0x5555, %eax
	xorl	%edx, %edx
	movl	$2, %ecx
	clc
	divl	%ecx
	jz	trynexgen
	popfl
	movl	$CPU_386,R(cpu)
	jmp	3f

trynexgen:
	popfl
	movl	$CPU_NX586,R(cpu)
	movl	$0x4778654e,R(cpu_vendor)	# store vendor string
	movl	$0x72446e65,R(cpu_vendor+4)
	movl	$0x6e657669,R(cpu_vendor+8)
	movl	$0,R(cpu_vendor+12)
	jmp	3f

try486:	/* Try to toggle identification flag; does not exist on early 486s. */
	pushfl
	popl	%eax
	movl	%eax,%ecx
	xorl	$PSL_ID,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	xorl	%ecx,%eax
	andl	$PSL_ID,%eax
	pushl	%ecx
	popfl

	testl	%eax,%eax
	jnz	trycpuid
	movl	$CPU_486,R(cpu)

	/*
	 * Check Cyrix CPU
	 * Cyrix CPUs do not change the undefined flags following
	 * execution of the divide instruction which divides 5 by 2.
	 *
	 * Note: CPUID is enabled on M2, so it passes another way.
	 */
	pushfl
	movl	$0x5555, %eax
	xorl	%edx, %edx
	movl	$2, %ecx
	clc
	divl	%ecx
	jnc	trycyrix
	popfl
	jmp	3f		/* You may use Intel CPU. */

trycyrix:
	popfl
	/*
	 * IBM Bluelighting CPU also doesn't change the undefined flags.
	 * Because IBM doesn't disclose the information for Bluelighting
	 * CPU, we couldn't distinguish it from Cyrix's (including IBM
	 * brand of Cyrix CPUs).
	 */
	movl	$0x69727943,R(cpu_vendor)	# store vendor string
	movl	$0x736e4978,R(cpu_vendor+4)
	movl	$0x64616574,R(cpu_vendor+8)
	jmp	3f

trycpuid:	/* Use the `cpuid' instruction. */
	xorl	%eax,%eax
	cpuid					# cpuid 0
	movl	%eax,R(cpu_high)		# highest capability
	movl	%ebx,R(cpu_vendor)		# store vendor string
	movl	%edx,R(cpu_vendor+4)
	movl	%ecx,R(cpu_vendor+8)
	movb	$0,R(cpu_vendor+12)

	movl	$1,%eax
	cpuid					# cpuid 1
	movl	%eax,R(cpu_id)			# store cpu_id
	movl	%ebx,R(cpu_procinfo)		# store cpu_procinfo
	movl	%edx,R(cpu_feature)		# store cpu_feature
	movl	%ecx,R(cpu_feature2)		# store cpu_feature2
	rorl	$8,%eax				# extract family type
	andl	$15,%eax
	cmpl	$5,%eax
	jae	1f

	/* less than Pentium; must be 486 */
	movl	$CPU_486,R(cpu)
	jmp	3f
1:
	/* a Pentium? */
	cmpl	$5,%eax
	jne	2f
	movl	$CPU_586,R(cpu)
	jmp	3f
2:
	/* Greater than Pentium...call it a Pentium Pro */
	movl	$CPU_686,R(cpu)
3:
	ret


/**********************************************************************
 *
 * Create the first page directory and its page tables.
 *
 */

create_pagetables:

/* Find end of kernel image (rounded up to a page boundary). */
	movl	$R(end),%esi

/* Include symbols, if any. */
	movl	R(bootinfo+BI_ESYMTAB),%edi
	testl	%edi,%edi
	je	over_symalloc
	movl	%edi,%esi
	movl	$KERNBASE,%edi
	addl	%edi,R(bootinfo+BI_SYMTAB)
	addl	%edi,R(bootinfo+BI_ESYMTAB)
over_symalloc:

/* If we are told where the end of the kernel space is, believe it. */
	movl	R(bootinfo+BI_KERNEND),%edi
	testl	%edi,%edi
	je	no_kernend
	movl	%edi,%esi
no_kernend:
	
	addl	$PAGE_MASK,%esi
	andl	$~PAGE_MASK,%esi
	movl	%esi,R(KERNend)		/* save end of kernel */
	movl	%esi,R(physfree)	/* next free page is at end of kernel */


/* Allocate Kernel Page Tables */
	ALLOCPAGES(NKPT)
	movl	%esi,R(KPTphys)

/* Allocate Page Table Directory */
	ALLOCPAGES(1)
	movl	%esi,R(IdlePTD)

/* Allocate UPAGES */
	ALLOCPAGES(UPAGES)
	movl	%esi,R(p0upa)
	addl	$KERNBASE, %esi
	movl	%esi, R(proc0paddr)

	ALLOCPAGES(1)			/* vm86/bios stack */
	movl	%esi,R(vm86phystk)

	ALLOCPAGES(3)			/* pgtable + ext + IOPAGES */
	movl	%esi,R(vm86pa)
	addl	$KERNBASE, %esi
	movl	%esi, R(vm86paddr)

/* Allocate cpu0's mdglobaldata */
	ALLOCPAGES(MDGLOBALDATA_BASEALLOC_PAGES)
	movl	%esi,R(cpu0pp)
#if 0
	addl	$KERNBASE, %esi
	movl	%esi, R(cpu0prvpage)	/* relocated to KVM space */
#endif

/* Allocate cpu0's idle stack */
	ALLOCPAGES(UPAGES)
	movl	%esi,R(cpu0idlestk)

/* Allocate SMP page table page */
	ALLOCPAGES(1)
	movl	%esi,R(SMPptpa)
	addl	$KERNBASE, %esi
	movl	%esi, R(SMPpt)		/* relocated to KVM space */

/* Map read-only from zero to the end of the kernel text section */
	xorl	%eax, %eax
#ifdef BDE_DEBUGGER
/* If the debugger is present, actually map everything read-write. */
	cmpl	$0,R(bdb_exists)
	jne	map_read_write
#endif
	xorl	%edx,%edx

#if !defined(SMP)
	testl	$CPUID_PGE, R(cpu_feature)
	jz	2f
	orl	$PG_G,%edx
#endif
	
2:	movl	$R(etext),%ecx
	addl	$PAGE_MASK,%ecx
	shrl	$PAGE_SHIFT,%ecx
	fillkptphys(%edx)

/* Map read-write, data, bss and symbols */
	movl	$R(etext),%eax
	addl	$PAGE_MASK, %eax
	andl	$~PAGE_MASK, %eax
map_read_write:
	movl	$PG_RW,%edx
#if !defined(SMP)
	testl	$CPUID_PGE, R(cpu_feature)
	jz	1f
	orl	$PG_G,%edx
#endif
	
1:	movl	R(KERNend),%ecx
	subl	%eax,%ecx
	shrl	$PAGE_SHIFT,%ecx
	fillkptphys(%edx)

/* Map page directory. */
	movl	R(IdlePTD), %eax
	movl	$1, %ecx
	fillkptphys($PG_RW)

/* Map proc0's UPAGES in the physical way ... */
	movl	R(p0upa), %eax
	movl	$UPAGES, %ecx
	fillkptphys($PG_RW)

/* Map ISA hole */
	movl	$ISA_HOLE_START, %eax
	movl	$ISA_HOLE_LENGTH>>PAGE_SHIFT, %ecx
	fillkptphys($PG_RW)

/* Map space for the vm86 region */
	movl	R(vm86phystk), %eax
	movl	$4, %ecx
	fillkptphys($PG_RW)

/* Map page 0 into the vm86 page table */
	movl	$0, %eax
	movl	$0, %ebx
	movl	$1, %ecx
	fillkpt(R(vm86pa), $PG_RW|PG_U)

/* ...likewise for the ISA hole */
	movl	$ISA_HOLE_START, %eax
	movl	$ISA_HOLE_START>>PAGE_SHIFT, %ebx
	movl	$ISA_HOLE_LENGTH>>PAGE_SHIFT, %ecx
	fillkpt(R(vm86pa), $PG_RW|PG_U)

#if 0
/* Map cpu0's mdglobaldata into global kmem (N pages @ cpu0pp) */
	movl	R(cpu0pp), %eax
	movl	$MDGLOBALDATA_BASEALLOC_PAGES, %ecx
	fillkptphys($PG_RW)
#endif

/* Map SMP page table page into global kmem FWIW */
	movl	R(SMPptpa), %eax
	movl	$1, %ecx
	fillkptphys($PG_RW)

/* Map the private page into the SMP page table */
	movl	R(cpu0pp), %eax
	movl	$0, %ebx		/* pte offset = 0 */
					/* N private pages coming right up */
	movl	$MDGLOBALDATA_BASEALLOC_PAGES, %ecx		
	fillkpt(R(SMPptpa), $PG_RW)

/* Map the cpu0's idle thread stack */
	movl	R(cpu0idlestk), %eax
	movl	$PS_IDLESTACK_PAGE, %ebx
	movl	$UPAGES, %ecx
	fillkpt(R(SMPptpa), $PG_RW)

/* ... and put the page table table in the pde. */
	movl	R(SMPptpa), %eax
	movl	$MPPTDI, %ebx
	movl	$1, %ecx
	fillkpt(R(IdlePTD), $PG_RW)

/* Fakeup VA for the local apic to allow early traps. */
	ALLOCPAGES(1)
	movl	%esi, %eax
	movl	$(NPTEPG-1), %ebx	/* pte offset = NTEPG-1 */
	movl	$1, %ecx		/* one private pt coming right up */
	fillkpt(R(SMPptpa), $PG_RW)

/* install a pde for temporary double map of bottom of VA */
	movl	R(KPTphys), %eax
	xorl	%ebx, %ebx
	movl	$NKPT, %ecx
	fillkpt(R(IdlePTD), $PG_RW)

/* install pde's for pt's */
	movl	R(KPTphys), %eax
	movl	$KPTDI, %ebx
	movl	$NKPT, %ecx
	fillkpt(R(IdlePTD), $PG_RW)

/* install a pde recursively mapping page directory as a page table */
	movl	R(IdlePTD), %eax
	movl	$PTDPTDI, %ebx
	movl	$1,%ecx
	fillkpt(R(IdlePTD), $PG_RW)

	ret

#ifdef BDE_DEBUGGER
bdb_prepare_paging:
	cmpl	$0,R(bdb_exists)
	je	bdb_prepare_paging_exit

	subl	$6,%esp

	/*
	 * Copy and convert debugger entries from the bootstrap gdt and idt
	 * to the kernel gdt and idt.  Everything is still in low memory.
	 * Tracing continues to work after paging is enabled because the
	 * low memory addresses remain valid until everything is relocated.
	 * However, tracing through the setidt() that initializes the trace
	 * trap will crash.
	 */
	sgdt	(%esp)
	movl	2(%esp),%esi		/* base address of bootstrap gdt */
	movl	$R(gdt),%edi
	movl	%edi,2(%esp)		/* prepare to load kernel gdt */
	movl	$8*18/4,%ecx
	cld
	rep				/* copy gdt */
	movsl
	movl	$R(gdt),-8+2(%edi)	/* adjust gdt self-ptr */
	movb	$0x92,-8+5(%edi)
	lgdt	(%esp)

	sidt	(%esp)
	movl	2(%esp),%esi		/* base address of current idt */
	movl	8+4(%esi),%eax		/* convert dbg descriptor to ... */
	movw	8(%esi),%ax
	movl	%eax,R(bdb_dbg_ljmp+1)	/* ... immediate offset ... */
	movl	8+2(%esi),%eax
	movw	%ax,R(bdb_dbg_ljmp+5)	/* ... and selector for ljmp */
	movl	24+4(%esi),%eax		/* same for bpt descriptor */
	movw	24(%esi),%ax
	movl	%eax,R(bdb_bpt_ljmp+1)
	movl	24+2(%esi),%eax
	movw	%ax,R(bdb_bpt_ljmp+5)
	movl	R(idt),%edi
	movl	%edi,2(%esp)		/* prepare to load kernel idt */
	movl	$8*4/4,%ecx
	cld
	rep				/* copy idt */
	movsl
	lidt	(%esp)

	addl	$6,%esp

bdb_prepare_paging_exit:
	ret

/* Relocate debugger gdt entries and gdt and idt pointers. */
bdb_commit_paging:
	cmpl	$0,_bdb_exists
	je	bdb_commit_paging_exit

	movl	$_gdt+8*9,%eax		/* adjust slots 9-17 */
	movl	$9,%ecx
reloc_gdt:
	movb	$KERNBASE>>24,7(%eax)	/* top byte of base addresses, was 0, */
	addl	$8,%eax			/* now KERNBASE>>24 */
	loop	reloc_gdt

	subl	$6,%esp
	sgdt	(%esp)
	addl	$KERNBASE,2(%esp)
	lgdt	(%esp)
	sidt	(%esp)
	addl	$KERNBASE,2(%esp)
	lidt	(%esp)
	addl	$6,%esp

	int	$3

bdb_commit_paging_exit:
	ret

#endif /* BDE_DEBUGGER */
