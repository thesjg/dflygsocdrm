/*-
 * Copyright (c) 1995 Bruce D. Evans.
 * Copyright (c) 2008 The DragonFly Project.
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
 * 3. Neither the name of the author nor the names of contributors
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
 * $FreeBSD: src/sys/amd64/include/md_var.h,v 1.71 2004/01/29 00:05:03 peter Exp $
 * $DragonFly: src/sys/platform/pc64/include/md_var.h,v 1.5 2008/08/29 17:07:17 dillon Exp $
 */

#ifndef _MACHINE_MD_VAR_H_
#define	_MACHINE_MD_VAR_H_

#include <machine/globaldata.h>

/*
 * Miscellaneous machine-dependent declarations.
 */

extern	u_long	atdevbase;	/* offset in virtual memory of ISA io mem */
extern	int	busdma_swi_pending;
extern	void	(*cpu_idle_hook)(void);
extern	void	cpu_idle(void);
extern	u_int	cpu_exthigh;
extern	u_int	via_feature_rng;
extern	u_int	via_feature_xcrypt;
extern	u_int	amd_feature;
extern	u_int	amd_feature2;
extern	u_int	cpu_clflush_line_size;
extern	u_int	cpu_fxsr;
extern	u_int	cpu_high;
extern	u_int	cpu_id;
extern	u_int	cpu_procinfo;
extern	u_int	cpu_procinfo2;
extern	char	cpu_vendor[];
extern	u_int	cpu_vendor_id;
extern	char	kstack[];
extern	char	sigcode[];
extern	int	szsigcode;
extern	uint64_t *vm_page_dump;
extern	int	vm_page_dump_size;


typedef void alias_for_inthand_t(u_int cs, u_int ef, u_int esp, u_int ss);
struct	thread;
struct	reg;
struct	fpreg;
struct  dbreg;
struct __mcontext;
struct dumperinfo;

void	busdma_swi(void);
void	cpu_gdinit (struct mdglobaldata *gd, int cpu);
void	cpu_idle_restore (void);	/* cannot be called from C */
void	cpu_setregs(void);
void	doreti_iret(void) __asm(__STRING(doreti_iret));
void	doreti_iret_fault(void) __asm(__STRING(doreti_iret_fault));
void	enable_sse(void);
void	fillw(int /*u_short*/ pat, void *base, size_t cnt);
void	pagezero(void *addr);
void	pagecopy(void *from, void *to);
void	setidt(int idx, alias_for_inthand_t *func, int typ, int dpl, int ist);
int	user_dbreg_trap(void);
void	fpstate_drop(struct thread *td);

int     npxdna(void);
void npxpush(struct __mcontext *mctx);
void npxpop(struct __mcontext *mctx);

void	cpu_heavy_restore (void);
void	cpu_kthread_restore (void);/* cannot be called from C */

thread_t cpu_exit_switch (struct thread *next);

void	syscall2 (struct trapframe *);
void    minidumpsys(struct dumperinfo *);
void	dump_add_page(vm_paddr_t);
void	dump_drop_page(vm_paddr_t);
#if 0
void	initializecpu(void);
#endif
void	initializecpucache(void);

#endif /* !_MACHINE_MD_VAR_H_ */
