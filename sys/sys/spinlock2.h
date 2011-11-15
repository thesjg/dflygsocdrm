/*
 * Copyright (c) 2005 Jeffrey M. Hsu.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Jeffrey M. Hsu.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#ifndef _SYS_SPINLOCK2_H_
#define _SYS_SPINLOCK2_H_

#ifndef _KERNEL

#error "This file should not be included by userland programs."

#else

#ifndef _SYS_SYSTM_H_
#include <sys/systm.h>
#endif
#ifndef _SYS_THREAD2_H_
#include <sys/thread2.h>
#endif
#ifndef _SYS_GLOBALDATA_H_
#include <sys/globaldata.h>
#endif
#include <machine/atomic.h>
#include <machine/cpufunc.h>

extern struct spinlock pmap_spin;

#ifdef SMP

int spin_trylock_contested(struct spinlock *spin);
void spin_lock_contested(struct spinlock *spin);
void _spin_pool_lock(void *chan);
void _spin_pool_unlock(void *chan);

#endif

#ifdef SMP

/*
 * Attempt to obtain an exclusive spinlock.  Returns FALSE on failure,
 * TRUE on success.
 */
static __inline boolean_t
spin_trylock(struct spinlock *spin)
{
	globaldata_t gd = mycpu;

	++gd->gd_curthread->td_critcount;
	cpu_ccfence();
	++gd->gd_spinlocks_wr;
	if (atomic_swap_int(&spin->counta, 1))
		return (spin_trylock_contested(spin));
#ifdef DEBUG_LOCKS
	int i;
	for (i = 0; i < SPINLOCK_DEBUG_ARRAY_SIZE; i++) {
		if (gd->gd_curthread->td_spinlock_stack_id[i] == 0) {
			gd->gd_curthread->td_spinlock_stack_id[i] = 1;
			gd->gd_curthread->td_spinlock_stack[i] = spin;
			gd->gd_curthread->td_spinlock_caller_pc[i] =
						__builtin_return_address(0);
			break;
		}
	}
#endif
	return (TRUE);
}

#else

static __inline boolean_t
spin_trylock(struct spinlock *spin)
{
	globaldata_t gd = mycpu;

	++gd->gd_curthread->td_critcount;
	cpu_ccfence();
	++gd->gd_spinlocks_wr;
	return (TRUE);
}

#endif

/*
 * Return TRUE if the spinlock is held (we can't tell by whom, though)
 */
static __inline int
spin_held(struct spinlock *spin)
{
	return(spin->counta != 0);
}

/*
 * Obtain an exclusive spinlock and return.
 */
static __inline void
spin_lock_quick(globaldata_t gd, struct spinlock *spin)
{
	++gd->gd_curthread->td_critcount;
	cpu_ccfence();
	++gd->gd_spinlocks_wr;
#ifdef SMP
	if (atomic_swap_int(&spin->counta, 1))
		spin_lock_contested(spin);
#ifdef DEBUG_LOCKS
	int i;
	for (i = 0; i < SPINLOCK_DEBUG_ARRAY_SIZE; i++) {
		if (gd->gd_curthread->td_spinlock_stack_id[i] == 0) {
			gd->gd_curthread->td_spinlock_stack_id[i] = 1;
			gd->gd_curthread->td_spinlock_stack[i] = spin;
			gd->gd_curthread->td_spinlock_caller_pc[i] =
				__builtin_return_address(0);
			break;
		}
	}
#endif
#endif
}

static __inline void
spin_lock(struct spinlock *spin)
{
	spin_lock_quick(mycpu, spin);
}

/*
 * Release an exclusive spinlock.  We can just do this passively, only
 * ensuring that our spinlock count is left intact until the mutex is
 * cleared.
 */
static __inline void
spin_unlock_quick(globaldata_t gd, struct spinlock *spin)
{
#ifdef SMP
#ifdef DEBUG_LOCKS
	int i;
	for (i = 0; i < SPINLOCK_DEBUG_ARRAY_SIZE; i++) {
		if ((gd->gd_curthread->td_spinlock_stack_id[i] == 1) &&
		    (gd->gd_curthread->td_spinlock_stack[i] == spin)) {
			gd->gd_curthread->td_spinlock_stack_id[i] = 0;
			gd->gd_curthread->td_spinlock_stack[i] = NULL;
			gd->gd_curthread->td_spinlock_caller_pc[i] = NULL;
			break;
		}
	}
#endif
	/*
	 * Don't use a locked instruction here.  To reduce latency we avoid
	 * reading spin->counta prior to writing to it.
	 */
#ifdef DEBUG_LOCKS
	KKASSERT(spin->counta != 0);
#endif
	cpu_sfence();
	spin->counta = 0;
	cpu_sfence();
#endif
#ifdef DEBUG_LOCKS
	KKASSERT(gd->gd_spinlocks_wr > 0);
#endif
	--gd->gd_spinlocks_wr;
	cpu_ccfence();
	--gd->gd_curthread->td_critcount;
#if 0
	/* FUTURE */
	if (__predict_false(gd->gd_reqflags & RQF_IDLECHECK_MASK))
		lwkt_maybe_splz(gd->gd_curthread);
#endif
}

static __inline void
spin_unlock(struct spinlock *spin)
{
	spin_unlock_quick(mycpu, spin);
}

static __inline void
spin_pool_lock(void *chan)
{
#ifdef SMP
	_spin_pool_lock(chan);
#else
	spin_lock(NULL);
#endif
}

static __inline void
spin_pool_unlock(void *chan)
{
#ifdef SMP
	_spin_pool_unlock(chan);
#else
	spin_unlock(NULL);
#endif
}

static __inline void
spin_init(struct spinlock *spin)
{
        spin->counta = 0;
        spin->countb = 0;
}

static __inline void
spin_uninit(struct spinlock *spin)
{
	/* unused */
}

#endif	/* _KERNEL */
#endif	/* _SYS_SPINLOCK2_H_ */

