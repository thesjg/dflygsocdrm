/*
 * Copyright (c) 2005 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
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
 * 
 * $DragonFly: src/sys/kern/lwkt_serialize.c,v 1.18 2008/10/04 14:22:44 swildner Exp $
 */
/*
 * This API provides a fast locked-bus-cycle-based serializer.  It's
 * basically a low level NON-RECURSIVE exclusive lock that can be held across
 * a blocking condition.  It is NOT a mutex.
 *
 * This serializer is primarily designed for low level situations and
 * interrupt/device interaction.  There are two primary facilities.  First,
 * the serializer facility itself.  Second, an integrated interrupt handler 
 * disablement facility.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/rtprio.h>
#include <sys/queue.h>
#include <sys/thread2.h>
#include <sys/serialize.h>
#include <sys/sysctl.h>
#include <sys/ktr.h>
#include <sys/kthread.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <sys/lock.h>
#include <sys/caps.h>

struct exp_backoff {
	int backoff;
	int round;
	lwkt_serialize_t s;
};

#define SLZ_KTR_STRING		"slz=%p"
#define SLZ_KTR_ARG_SIZE	(sizeof(void *))

#ifndef KTR_SERIALIZER
#define KTR_SERIALIZER	KTR_ALL
#endif

KTR_INFO_MASTER(slz);
KTR_INFO(KTR_SERIALIZER, slz, enter_beg, 0, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, sleep_beg, 1, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, sleep_end, 2, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, exit_end, 3, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, wakeup_beg, 4, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, wakeup_end, 5, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, try, 6, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, tryfail, 7, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, tryok, 8, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
#ifdef SMP
KTR_INFO(KTR_SERIALIZER, slz, spinbo, 9,
	 "slz=%p bo1=%d bo=%d", (sizeof(void *) + (2 * sizeof(int))));
#endif
KTR_INFO(KTR_SERIALIZER, slz, enter_end, 10, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);
KTR_INFO(KTR_SERIALIZER, slz, exit_beg, 11, SLZ_KTR_STRING, SLZ_KTR_ARG_SIZE);

#define logslz(name, slz)		KTR_LOG(slz_ ## name, slz)
#ifdef SMP
#define logslz_spinbo(slz, bo1, bo)	KTR_LOG(slz_spinbo, slz, bo1, bo)
#endif

static void lwkt_serialize_sleep(void *info);
static void lwkt_serialize_wakeup(void *info);

#ifdef SMP
static void lwkt_serialize_adaptive_sleep(void *bo);

static int slz_backoff_limit = 128;
SYSCTL_INT(_debug, OID_AUTO, serialize_bolimit, CTLFLAG_RW,
    &slz_backoff_limit, 0, "Backoff limit");

static int slz_backoff_shift = 1;
SYSCTL_INT(_debug, OID_AUTO, serialize_boshift, CTLFLAG_RW,
    &slz_backoff_shift, 0, "Backoff shift");

static int slz_backoff_round;
TUNABLE_INT("debug.serialize_boround", &slz_backoff_round);
SYSCTL_INT(_debug, OID_AUTO, serialize_boround, CTLFLAG_RW,
    &slz_backoff_round, 0,
    "Backoff rounding");
#endif	/* SMP */

void
lwkt_serialize_init(lwkt_serialize_t s)
{
    atomic_intr_init(&s->interlock);
#ifdef INVARIANTS
    s->last_td = (void *)-4;
#endif
}

#ifdef SMP
void
lwkt_serialize_adaptive_enter(lwkt_serialize_t s)
{
    struct exp_backoff bo;

    bo.backoff = 1;
    bo.round = 0;
    bo.s = s;

    ASSERT_NOT_SERIALIZED(s);

    logslz(enter_beg, s);
    atomic_intr_cond_enter(&s->interlock, lwkt_serialize_adaptive_sleep, &bo);
    logslz(enter_end, s);
#ifdef INVARIANTS
    s->last_td = curthread;
#endif
}
#endif	/* SMP */

void
lwkt_serialize_enter(lwkt_serialize_t s)
{
    ASSERT_NOT_SERIALIZED(s);

    logslz(enter_beg, s);
    atomic_intr_cond_enter(&s->interlock, lwkt_serialize_sleep, s);
    logslz(enter_end, s);
#ifdef INVARIANTS
    s->last_td = curthread;
#endif
}

/*
 * Returns non-zero on success
 */
int
lwkt_serialize_try(lwkt_serialize_t s)
{
    int error;

    ASSERT_NOT_SERIALIZED(s);

    logslz(try, s);
    if ((error = atomic_intr_cond_try(&s->interlock)) == 0) {
#ifdef INVARIANTS
	s->last_td = curthread;
#endif
	logslz(tryok, s);
	return(1);
    }
    logslz(tryfail, s);
    return (0);
}

void
lwkt_serialize_exit(lwkt_serialize_t s)
{
    ASSERT_SERIALIZED(s);
#ifdef INVARIANTS
    s->last_td = (void *)-2;
#endif
    logslz(exit_beg, s);
    atomic_intr_cond_exit(&s->interlock, lwkt_serialize_wakeup, s);
    logslz(exit_end, s);
}

/*
 * Interrupt handler disablement support, used by drivers.  Non-stackable
 * (uses bit 30).
 */
void
lwkt_serialize_handler_disable(lwkt_serialize_t s)
{
    atomic_intr_handler_disable(&s->interlock);
}

void
lwkt_serialize_handler_enable(lwkt_serialize_t s)
{
    atomic_intr_handler_enable(&s->interlock);
}

void
lwkt_serialize_handler_call(lwkt_serialize_t s, void (*func)(void *, void *), 
			    void *arg, void *frame)
{
    /*
     * note: a return value of 0 indicates that the interrupt handler is 
     * enabled.
     */
    if (atomic_intr_handler_is_enabled(&s->interlock) == 0) {
	logslz(enter_beg, s);
	atomic_intr_cond_enter(&s->interlock, lwkt_serialize_sleep, s);
	logslz(enter_end, s);
#ifdef INVARIANTS
	s->last_td = curthread;
#endif
	if (atomic_intr_handler_is_enabled(&s->interlock) == 0)
	    func(arg, frame);

	ASSERT_SERIALIZED(s);
#ifdef INVARIANTS
	s->last_td = (void *)-2;
#endif
	logslz(exit_beg, s);
	atomic_intr_cond_exit(&s->interlock, lwkt_serialize_wakeup, s);
	logslz(exit_end, s);
    }
}

/*
 * Similar to handler_call but does not block.  Returns 0 on success, 
 * and 1 on failure.
 */
int
lwkt_serialize_handler_try(lwkt_serialize_t s, void (*func)(void *, void *),
			   void *arg, void *frame)
{
    /*
     * note: a return value of 0 indicates that the interrupt handler is 
     * enabled.
     */
    if (atomic_intr_handler_is_enabled(&s->interlock) == 0) {
	logslz(try, s);
	if (atomic_intr_cond_try(&s->interlock) == 0) {
#ifdef INVARIANTS
	    s->last_td = curthread;
#endif
	    logslz(tryok, s);

	    func(arg, frame);

	    ASSERT_SERIALIZED(s);
#ifdef INVARIANTS
	    s->last_td = (void *)-2;
#endif
	    logslz(exit_beg, s);
	    atomic_intr_cond_exit(&s->interlock, lwkt_serialize_wakeup, s);
	    logslz(exit_end, s);
	    return(0);
	}
    }
    logslz(tryfail, s);
    return(1);
}


/*
 * Helper functions
 *
 * It is possible to race an interrupt which acquires and releases the
 * bit, then calls wakeup before we actually go to sleep, so we
 * need to check that the interlock is still acquired from within
 * a critical section prior to sleeping.
 */
static void
lwkt_serialize_sleep(void *info)
{
    lwkt_serialize_t s = info;

    tsleep_interlock(s, 0);
    if (atomic_intr_cond_test(&s->interlock) != 0) {
	logslz(sleep_beg, s);
	tsleep(s, PINTERLOCKED, "slize", 0);
	logslz(sleep_end, s);
    }
}

#ifdef SMP

static void
lwkt_serialize_adaptive_sleep(void *arg)
{
    struct exp_backoff *bo = arg;
    lwkt_serialize_t s = bo->s;
    int backoff;

    /*
     * Randomize backoff value
     */
#ifdef _RDTSC_SUPPORTED_
    if (cpu_feature & CPUID_TSC) {
	backoff =
	(((u_long)rdtsc() ^ (((u_long)curthread) >> 5)) &
	 (bo->backoff - 1)) + 1;
    } else
#endif
	backoff = bo->backoff;

    logslz_spinbo(s, bo->backoff, backoff);

    /*
     * Quick backoff
     */
    for (; backoff; --backoff)
	cpu_pause();
    if (bo->backoff < slz_backoff_limit) {
	bo->backoff <<= slz_backoff_shift;
	return;
    } else {
	bo->backoff = 1;
	bo->round++;
	if (bo->round >= slz_backoff_round)
	    bo->round = 0;
    	else
	    return;
    }

    tsleep_interlock(s, 0);
    if (atomic_intr_cond_test(&s->interlock) != 0) {
	logslz(sleep_beg, s);
	tsleep(s, PINTERLOCKED, "slize", 0);
	logslz(sleep_end, s);
    }
}

#endif	/* SMP */

static void
lwkt_serialize_wakeup(void *info)
{
    logslz(wakeup_beg, info);
    wakeup(info);
    logslz(wakeup_end, info);
}

#ifdef SMP
static void
lwkt_serialize_sysinit(void *dummy __unused)
{
	if (slz_backoff_round <= 0)
		slz_backoff_round = ncpus * 2;
}
SYSINIT(lwkt_serialize, SI_SUB_PRE_DRIVERS, SI_ORDER_SECOND,
	lwkt_serialize_sysinit, NULL);
#endif
