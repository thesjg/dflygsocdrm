/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD: src/sys/i386/include/smp.h,v 1.50.2.5 2001/02/13 22:32:45 tegge Exp $
 * $DragonFly: src/sys/platform/pc32/include/smp.h,v 1.20 2006/11/07 06:43:24 dillon Exp $
 *
 */

#ifndef _MACHINE_SMP_H_
#define _MACHINE_SMP_H_

#ifdef _KERNEL

#ifndef LOCORE

/* XXX wrong header */
void	initializecpu(void);

#endif	/* LOCORE */

/*
 * Size of APIC ID list.
 * Also used a MAX size of various other arrays.
 */
#define NAPICID		256

#if defined(SMP)

#ifndef LOCORE

/*
 * For sending values to POST displays.
 * XXX FIXME: where does this really belong, isa.h/isa.c perhaps?
 */
extern int current_postcode;  /** XXX currently in mp_machdep.c */
#define POSTCODE(X)	current_postcode = (X), \
			outb(0x80, current_postcode)
#define POSTCODE_LO(X)	current_postcode &= 0xf0, \
			current_postcode |= ((X) & 0x0f), \
			outb(0x80, current_postcode)
#define POSTCODE_HI(X)	current_postcode &= 0x0f, \
			current_postcode |= (((X) << 4) & 0xf0), \
			outb(0x80, current_postcode)


#include <machine_base/apic/apicreg.h>
#include <machine/pcb.h>

/* global symbols in mpboot.S */
extern char			mptramp_start[];
extern char			mptramp_end[];
extern u_int32_t		mptramp_pagetables;

/* functions in mpboot.s */
void	bootMP			(void);

/* global data in apic_vector.s */
extern volatile cpumask_t	stopped_cpus;
extern volatile cpumask_t	started_cpus;

extern volatile u_int		checkstate_probed_cpus;
extern void (*cpustop_restartfunc) (void);

/* global data in mp_machdep.c */
extern int			mp_naps;

#define APIC_INTMAPSIZE 192
/*
 * NOTE:
 * - Keep size of apic_intmapinfo power of 2
 * - Update IOAPIC_IM_SZSHIFT after changing apic_intmapinfo size
 */
struct apic_intmapinfo {
  	int ioapic;
	int int_pin;
	volatile void *apic_address;
	int redirindex;
	uint32_t flags;		/* IOAPIC_IM_FLAG_ */
	uint32_t pad[2];
};
#define IOAPIC_IM_SZSHIFT	5

#define IOAPIC_IM_FLAG_LEVEL	0x1	/* default to edge trigger */
#define IOAPIC_IM_FLAG_MASKED	0x2

extern struct apic_intmapinfo	int_to_apicintpin[];
extern struct pcb		stoppcbs[];

/* functions in mp_machdep.c */
u_int	mp_bootaddress		(u_int);
void	mp_start		(void);
void	mp_announce		(void);
void	init_secondary		(void);
int	stop_cpus		(cpumask_t);
void	ap_init			(void);
int	restart_cpus		(cpumask_t);
void	forward_signal		(struct proc *);

#if defined(READY)
void	clr_io_apic_mask24	(int, u_int32_t);
void	set_io_apic_mask24	(int, u_int32_t);
#endif /* READY */

void	cpu_send_ipiq		(int);
int	cpu_send_ipiq_passive	(int);

/* global data in init_smp.c */
extern cpumask_t		smp_active_mask;

#endif /* !LOCORE */
#else	/* !SMP */

#define	smp_active_mask	1	/* smp_active_mask always 1 on UP machines */

#endif

#endif /* _KERNEL */
#endif /* _MACHINE_SMP_H_ */
