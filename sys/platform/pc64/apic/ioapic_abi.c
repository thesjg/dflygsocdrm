/*
 * Copyright (c) 1991 The Regents of the University of California.
 * Copyright (c) 1996, by Steve Passe.  All rights reserved.
 * Copyright (c) 2005,2008 The DragonFly Project.  All rights reserved.
 * All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 * $DragonFly: src/sys/platform/pc64/apic/apic_abi.c,v 1.1 2008/08/29 17:07:12 dillon Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/machintr.h>
#include <sys/interrupt.h>
#include <sys/bus.h>

#include <machine/smp.h>
#include <machine/segments.h>
#include <machine/md_var.h>
#include <machine/intr_machdep.h>
#include <machine_base/icu/icu.h>
#include <machine/globaldata.h>

#include <sys/thread2.h>

#include <machine_base/apic/ioapic_ipl.h>

#ifdef SMP /* APIC-IO */

extern inthand_t
	IDTVEC(ioapic_intr0),
	IDTVEC(ioapic_intr1),
	IDTVEC(ioapic_intr2),
	IDTVEC(ioapic_intr3),
	IDTVEC(ioapic_intr4),
	IDTVEC(ioapic_intr5),
	IDTVEC(ioapic_intr6),
	IDTVEC(ioapic_intr7),
	IDTVEC(ioapic_intr8),
	IDTVEC(ioapic_intr9),
	IDTVEC(ioapic_intr10),
	IDTVEC(ioapic_intr11),
	IDTVEC(ioapic_intr12),
	IDTVEC(ioapic_intr13),
	IDTVEC(ioapic_intr14),
	IDTVEC(ioapic_intr15),
	IDTVEC(ioapic_intr16),
	IDTVEC(ioapic_intr17),
	IDTVEC(ioapic_intr18),
	IDTVEC(ioapic_intr19),
	IDTVEC(ioapic_intr20),
	IDTVEC(ioapic_intr21),
	IDTVEC(ioapic_intr22),
	IDTVEC(ioapic_intr23),
	IDTVEC(ioapic_intr24),
	IDTVEC(ioapic_intr25),
	IDTVEC(ioapic_intr26),
	IDTVEC(ioapic_intr27),
	IDTVEC(ioapic_intr28),
	IDTVEC(ioapic_intr29),
	IDTVEC(ioapic_intr30),
	IDTVEC(ioapic_intr31),
	IDTVEC(ioapic_intr32),
	IDTVEC(ioapic_intr33),
	IDTVEC(ioapic_intr34),
	IDTVEC(ioapic_intr35),
	IDTVEC(ioapic_intr36),
	IDTVEC(ioapic_intr37),
	IDTVEC(ioapic_intr38),
	IDTVEC(ioapic_intr39),
	IDTVEC(ioapic_intr40),
	IDTVEC(ioapic_intr41),
	IDTVEC(ioapic_intr42),
	IDTVEC(ioapic_intr43),
	IDTVEC(ioapic_intr44),
	IDTVEC(ioapic_intr45),
	IDTVEC(ioapic_intr46),
	IDTVEC(ioapic_intr47),
	IDTVEC(ioapic_intr48),
	IDTVEC(ioapic_intr49),
	IDTVEC(ioapic_intr50),
	IDTVEC(ioapic_intr51),
	IDTVEC(ioapic_intr52),
	IDTVEC(ioapic_intr53),
	IDTVEC(ioapic_intr54),
	IDTVEC(ioapic_intr55),
	IDTVEC(ioapic_intr56),
	IDTVEC(ioapic_intr57),
	IDTVEC(ioapic_intr58),
	IDTVEC(ioapic_intr59),
	IDTVEC(ioapic_intr60),
	IDTVEC(ioapic_intr61),
	IDTVEC(ioapic_intr62),
	IDTVEC(ioapic_intr63),
	IDTVEC(ioapic_intr64),
	IDTVEC(ioapic_intr65),
	IDTVEC(ioapic_intr66),
	IDTVEC(ioapic_intr67),
	IDTVEC(ioapic_intr68),
	IDTVEC(ioapic_intr69),
	IDTVEC(ioapic_intr70),
	IDTVEC(ioapic_intr71),
	IDTVEC(ioapic_intr72),
	IDTVEC(ioapic_intr73),
	IDTVEC(ioapic_intr74),
	IDTVEC(ioapic_intr75),
	IDTVEC(ioapic_intr76),
	IDTVEC(ioapic_intr77),
	IDTVEC(ioapic_intr78),
	IDTVEC(ioapic_intr79),
	IDTVEC(ioapic_intr80),
	IDTVEC(ioapic_intr81),
	IDTVEC(ioapic_intr82),
	IDTVEC(ioapic_intr83),
	IDTVEC(ioapic_intr84),
	IDTVEC(ioapic_intr85),
	IDTVEC(ioapic_intr86),
	IDTVEC(ioapic_intr87),
	IDTVEC(ioapic_intr88),
	IDTVEC(ioapic_intr89),
	IDTVEC(ioapic_intr90),
	IDTVEC(ioapic_intr91),
	IDTVEC(ioapic_intr92),
	IDTVEC(ioapic_intr93),
	IDTVEC(ioapic_intr94),
	IDTVEC(ioapic_intr95),
	IDTVEC(ioapic_intr96),
	IDTVEC(ioapic_intr97),
	IDTVEC(ioapic_intr98),
	IDTVEC(ioapic_intr99),
	IDTVEC(ioapic_intr100),
	IDTVEC(ioapic_intr101),
	IDTVEC(ioapic_intr102),
	IDTVEC(ioapic_intr103),
	IDTVEC(ioapic_intr104),
	IDTVEC(ioapic_intr105),
	IDTVEC(ioapic_intr106),
	IDTVEC(ioapic_intr107),
	IDTVEC(ioapic_intr108),
	IDTVEC(ioapic_intr109),
	IDTVEC(ioapic_intr110),
	IDTVEC(ioapic_intr111),
	IDTVEC(ioapic_intr112),
	IDTVEC(ioapic_intr113),
	IDTVEC(ioapic_intr114),
	IDTVEC(ioapic_intr115),
	IDTVEC(ioapic_intr116),
	IDTVEC(ioapic_intr117),
	IDTVEC(ioapic_intr118),
	IDTVEC(ioapic_intr119),
	IDTVEC(ioapic_intr120),
	IDTVEC(ioapic_intr121),
	IDTVEC(ioapic_intr122),
	IDTVEC(ioapic_intr123),
	IDTVEC(ioapic_intr124),
	IDTVEC(ioapic_intr125),
	IDTVEC(ioapic_intr126),
	IDTVEC(ioapic_intr127),
	IDTVEC(ioapic_intr128),
	IDTVEC(ioapic_intr129),
	IDTVEC(ioapic_intr130),
	IDTVEC(ioapic_intr131),
	IDTVEC(ioapic_intr132),
	IDTVEC(ioapic_intr133),
	IDTVEC(ioapic_intr134),
	IDTVEC(ioapic_intr135),
	IDTVEC(ioapic_intr136),
	IDTVEC(ioapic_intr137),
	IDTVEC(ioapic_intr138),
	IDTVEC(ioapic_intr139),
	IDTVEC(ioapic_intr140),
	IDTVEC(ioapic_intr141),
	IDTVEC(ioapic_intr142),
	IDTVEC(ioapic_intr143),
	IDTVEC(ioapic_intr144),
	IDTVEC(ioapic_intr145),
	IDTVEC(ioapic_intr146),
	IDTVEC(ioapic_intr147),
	IDTVEC(ioapic_intr148),
	IDTVEC(ioapic_intr149),
	IDTVEC(ioapic_intr150),
	IDTVEC(ioapic_intr151),
	IDTVEC(ioapic_intr152),
	IDTVEC(ioapic_intr153),
	IDTVEC(ioapic_intr154),
	IDTVEC(ioapic_intr155),
	IDTVEC(ioapic_intr156),
	IDTVEC(ioapic_intr157),
	IDTVEC(ioapic_intr158),
	IDTVEC(ioapic_intr159),
	IDTVEC(ioapic_intr160),
	IDTVEC(ioapic_intr161),
	IDTVEC(ioapic_intr162),
	IDTVEC(ioapic_intr163),
	IDTVEC(ioapic_intr164),
	IDTVEC(ioapic_intr165),
	IDTVEC(ioapic_intr166),
	IDTVEC(ioapic_intr167),
	IDTVEC(ioapic_intr168),
	IDTVEC(ioapic_intr169),
	IDTVEC(ioapic_intr170),
	IDTVEC(ioapic_intr171),
	IDTVEC(ioapic_intr172),
	IDTVEC(ioapic_intr173),
	IDTVEC(ioapic_intr174),
	IDTVEC(ioapic_intr175),
	IDTVEC(ioapic_intr176),
	IDTVEC(ioapic_intr177),
	IDTVEC(ioapic_intr178),
	IDTVEC(ioapic_intr179),
	IDTVEC(ioapic_intr180),
	IDTVEC(ioapic_intr181),
	IDTVEC(ioapic_intr182),
	IDTVEC(ioapic_intr183),
	IDTVEC(ioapic_intr184),
	IDTVEC(ioapic_intr185),
	IDTVEC(ioapic_intr186),
	IDTVEC(ioapic_intr187),
	IDTVEC(ioapic_intr188),
	IDTVEC(ioapic_intr189),
	IDTVEC(ioapic_intr190),
	IDTVEC(ioapic_intr191);

static inthand_t *ioapic_intr[IOAPIC_HWI_VECTORS] = {
	&IDTVEC(ioapic_intr0),
	&IDTVEC(ioapic_intr1),
	&IDTVEC(ioapic_intr2),
	&IDTVEC(ioapic_intr3),
	&IDTVEC(ioapic_intr4),
	&IDTVEC(ioapic_intr5),
	&IDTVEC(ioapic_intr6),
	&IDTVEC(ioapic_intr7),
	&IDTVEC(ioapic_intr8),
	&IDTVEC(ioapic_intr9),
	&IDTVEC(ioapic_intr10),
	&IDTVEC(ioapic_intr11),
	&IDTVEC(ioapic_intr12),
	&IDTVEC(ioapic_intr13),
	&IDTVEC(ioapic_intr14),
	&IDTVEC(ioapic_intr15),
	&IDTVEC(ioapic_intr16),
	&IDTVEC(ioapic_intr17),
	&IDTVEC(ioapic_intr18),
	&IDTVEC(ioapic_intr19),
	&IDTVEC(ioapic_intr20),
	&IDTVEC(ioapic_intr21),
	&IDTVEC(ioapic_intr22),
	&IDTVEC(ioapic_intr23),
	&IDTVEC(ioapic_intr24),
	&IDTVEC(ioapic_intr25),
	&IDTVEC(ioapic_intr26),
	&IDTVEC(ioapic_intr27),
	&IDTVEC(ioapic_intr28),
	&IDTVEC(ioapic_intr29),
	&IDTVEC(ioapic_intr30),
	&IDTVEC(ioapic_intr31),
	&IDTVEC(ioapic_intr32),
	&IDTVEC(ioapic_intr33),
	&IDTVEC(ioapic_intr34),
	&IDTVEC(ioapic_intr35),
	&IDTVEC(ioapic_intr36),
	&IDTVEC(ioapic_intr37),
	&IDTVEC(ioapic_intr38),
	&IDTVEC(ioapic_intr39),
	&IDTVEC(ioapic_intr40),
	&IDTVEC(ioapic_intr41),
	&IDTVEC(ioapic_intr42),
	&IDTVEC(ioapic_intr43),
	&IDTVEC(ioapic_intr44),
	&IDTVEC(ioapic_intr45),
	&IDTVEC(ioapic_intr46),
	&IDTVEC(ioapic_intr47),
	&IDTVEC(ioapic_intr48),
	&IDTVEC(ioapic_intr49),
	&IDTVEC(ioapic_intr50),
	&IDTVEC(ioapic_intr51),
	&IDTVEC(ioapic_intr52),
	&IDTVEC(ioapic_intr53),
	&IDTVEC(ioapic_intr54),
	&IDTVEC(ioapic_intr55),
	&IDTVEC(ioapic_intr56),
	&IDTVEC(ioapic_intr57),
	&IDTVEC(ioapic_intr58),
	&IDTVEC(ioapic_intr59),
	&IDTVEC(ioapic_intr60),
	&IDTVEC(ioapic_intr61),
	&IDTVEC(ioapic_intr62),
	&IDTVEC(ioapic_intr63),
	&IDTVEC(ioapic_intr64),
	&IDTVEC(ioapic_intr65),
	&IDTVEC(ioapic_intr66),
	&IDTVEC(ioapic_intr67),
	&IDTVEC(ioapic_intr68),
	&IDTVEC(ioapic_intr69),
	&IDTVEC(ioapic_intr70),
	&IDTVEC(ioapic_intr71),
	&IDTVEC(ioapic_intr72),
	&IDTVEC(ioapic_intr73),
	&IDTVEC(ioapic_intr74),
	&IDTVEC(ioapic_intr75),
	&IDTVEC(ioapic_intr76),
	&IDTVEC(ioapic_intr77),
	&IDTVEC(ioapic_intr78),
	&IDTVEC(ioapic_intr79),
	&IDTVEC(ioapic_intr80),
	&IDTVEC(ioapic_intr81),
	&IDTVEC(ioapic_intr82),
	&IDTVEC(ioapic_intr83),
	&IDTVEC(ioapic_intr84),
	&IDTVEC(ioapic_intr85),
	&IDTVEC(ioapic_intr86),
	&IDTVEC(ioapic_intr87),
	&IDTVEC(ioapic_intr88),
	&IDTVEC(ioapic_intr89),
	&IDTVEC(ioapic_intr90),
	&IDTVEC(ioapic_intr91),
	&IDTVEC(ioapic_intr92),
	&IDTVEC(ioapic_intr93),
	&IDTVEC(ioapic_intr94),
	&IDTVEC(ioapic_intr95),
	&IDTVEC(ioapic_intr96),
	&IDTVEC(ioapic_intr97),
	&IDTVEC(ioapic_intr98),
	&IDTVEC(ioapic_intr99),
	&IDTVEC(ioapic_intr100),
	&IDTVEC(ioapic_intr101),
	&IDTVEC(ioapic_intr102),
	&IDTVEC(ioapic_intr103),
	&IDTVEC(ioapic_intr104),
	&IDTVEC(ioapic_intr105),
	&IDTVEC(ioapic_intr106),
	&IDTVEC(ioapic_intr107),
	&IDTVEC(ioapic_intr108),
	&IDTVEC(ioapic_intr109),
	&IDTVEC(ioapic_intr110),
	&IDTVEC(ioapic_intr111),
	&IDTVEC(ioapic_intr112),
	&IDTVEC(ioapic_intr113),
	&IDTVEC(ioapic_intr114),
	&IDTVEC(ioapic_intr115),
	&IDTVEC(ioapic_intr116),
	&IDTVEC(ioapic_intr117),
	&IDTVEC(ioapic_intr118),
	&IDTVEC(ioapic_intr119),
	&IDTVEC(ioapic_intr120),
	&IDTVEC(ioapic_intr121),
	&IDTVEC(ioapic_intr122),
	&IDTVEC(ioapic_intr123),
	&IDTVEC(ioapic_intr124),
	&IDTVEC(ioapic_intr125),
	&IDTVEC(ioapic_intr126),
	&IDTVEC(ioapic_intr127),
	&IDTVEC(ioapic_intr128),
	&IDTVEC(ioapic_intr129),
	&IDTVEC(ioapic_intr130),
	&IDTVEC(ioapic_intr131),
	&IDTVEC(ioapic_intr132),
	&IDTVEC(ioapic_intr133),
	&IDTVEC(ioapic_intr134),
	&IDTVEC(ioapic_intr135),
	&IDTVEC(ioapic_intr136),
	&IDTVEC(ioapic_intr137),
	&IDTVEC(ioapic_intr138),
	&IDTVEC(ioapic_intr139),
	&IDTVEC(ioapic_intr140),
	&IDTVEC(ioapic_intr141),
	&IDTVEC(ioapic_intr142),
	&IDTVEC(ioapic_intr143),
	&IDTVEC(ioapic_intr144),
	&IDTVEC(ioapic_intr145),
	&IDTVEC(ioapic_intr146),
	&IDTVEC(ioapic_intr147),
	&IDTVEC(ioapic_intr148),
	&IDTVEC(ioapic_intr149),
	&IDTVEC(ioapic_intr150),
	&IDTVEC(ioapic_intr151),
	&IDTVEC(ioapic_intr152),
	&IDTVEC(ioapic_intr153),
	&IDTVEC(ioapic_intr154),
	&IDTVEC(ioapic_intr155),
	&IDTVEC(ioapic_intr156),
	&IDTVEC(ioapic_intr157),
	&IDTVEC(ioapic_intr158),
	&IDTVEC(ioapic_intr159),
	&IDTVEC(ioapic_intr160),
	&IDTVEC(ioapic_intr161),
	&IDTVEC(ioapic_intr162),
	&IDTVEC(ioapic_intr163),
	&IDTVEC(ioapic_intr164),
	&IDTVEC(ioapic_intr165),
	&IDTVEC(ioapic_intr166),
	&IDTVEC(ioapic_intr167),
	&IDTVEC(ioapic_intr168),
	&IDTVEC(ioapic_intr169),
	&IDTVEC(ioapic_intr170),
	&IDTVEC(ioapic_intr171),
	&IDTVEC(ioapic_intr172),
	&IDTVEC(ioapic_intr173),
	&IDTVEC(ioapic_intr174),
	&IDTVEC(ioapic_intr175),
	&IDTVEC(ioapic_intr176),
	&IDTVEC(ioapic_intr177),
	&IDTVEC(ioapic_intr178),
	&IDTVEC(ioapic_intr179),
	&IDTVEC(ioapic_intr180),
	&IDTVEC(ioapic_intr181),
	&IDTVEC(ioapic_intr182),
	&IDTVEC(ioapic_intr183),
	&IDTVEC(ioapic_intr184),
	&IDTVEC(ioapic_intr185),
	&IDTVEC(ioapic_intr186),
	&IDTVEC(ioapic_intr187),
	&IDTVEC(ioapic_intr188),
	&IDTVEC(ioapic_intr189),
	&IDTVEC(ioapic_intr190),
	&IDTVEC(ioapic_intr191)
};

static struct ioapic_irqmap {
	int			im_type;	/* IOAPIC_IMT_ */
	enum intr_trigger	im_trig;
	int			im_gsi;
} ioapic_irqmaps[MAX_HARDINTS];	/* XXX MAX_HARDINTS may not be correct */

#define IOAPIC_IMT_UNUSED	0
#define IOAPIC_IMT_RESERVED	1
#define IOAPIC_IMT_LINE		2

extern void	IOAPIC_INTREN(int);
extern void	IOAPIC_INTRDIS(int);

static int	ioapic_setvar(int, const void *);
static int	ioapic_getvar(int, void *);
static int	ioapic_vectorctl(int, int, int);
static void	ioapic_finalize(void);
static void	ioapic_cleanup(void);
static void	ioapic_setdefault(void);
static void	ioapic_stabilize(void);
static void	ioapic_initmap(void);

static int	ioapic_imcr_present;

struct machintr_abi MachIntrABI_IOAPIC = {
	MACHINTR_IOAPIC,
	.intrdis	= IOAPIC_INTRDIS,
	.intren		= IOAPIC_INTREN,
	.vectorctl	= ioapic_vectorctl,
	.setvar		= ioapic_setvar,
	.getvar		= ioapic_getvar,
	.finalize	= ioapic_finalize,
	.cleanup	= ioapic_cleanup,
	.setdefault	= ioapic_setdefault,
	.stabilize	= ioapic_stabilize,
	.initmap	= ioapic_initmap
};

static int
ioapic_setvar(int varid, const void *buf)
{
	int error = 0;

	switch(varid) {
	case MACHINTR_VAR_IMCR_PRESENT:
		ioapic_imcr_present = *(const int *)buf;
		break;

	default:
		error = ENOENT;
		break;
	}
	return error;
}

static int
ioapic_getvar(int varid, void *buf)
{
	int error = 0;

	switch(varid) {
	case MACHINTR_VAR_IMCR_PRESENT:
		*(int *)buf = ioapic_imcr_present;
		break;

	default:
		error = ENOENT;
		break;
	}
	return error;
}

/*
 * Called from ICU's finalize if I/O APIC is enabled, after BSP's LAPIC
 * is initialized; some of the BSP's LAPIC configuration are adjusted.
 *
 * - disable 'pic mode'.
 * - disable 'virtual wire mode'.
 * - switch MachIntrABI
 * - enable NMI.
 */
static void
ioapic_finalize(void)
{
	register_t ef;
	uint32_t temp;

	KKASSERT(MachIntrABI.type == MACHINTR_ICU);
	KKASSERT(apic_io_enable);

	/*
	 * If an IMCR is present, program bit 0 to disconnect the 8259
	 * from the BSP.  The 8259 may still be connected to LINT0 on
	 * the BSP's LAPIC.
	 */
	if (ioapic_imcr_present) {
		outb(0x22, 0x70);	/* select IMCR */
		outb(0x23, 0x01);	/* disconnect 8259 */
	}

	/*
	 * Setup LINT0 (the 8259 'virtual wire' connection).  We
	 * mask the interrupt, completing the disconnection of the
	 * 8259.
	 */
	temp = lapic->lvt_lint0;
	temp |= APIC_LVT_MASKED;
	lapic->lvt_lint0 = temp;

	crit_enter();

	ef = read_rflags();
	cpu_disable_intr();

	/*
	 * 8259 is completely disconnected; switch to IOAPIC MachIntrABI
	 * and reconfigure the default IDT entries.
	 */
	MachIntrABI = MachIntrABI_IOAPIC;
	MachIntrABI.setdefault();

	write_rflags(ef);

	MachIntrABI.cleanup();

	crit_exit();

	/*
	 * Setup LINT1 to handle an NMI 
	 */
	temp = lapic->lvt_lint1;
	temp &= ~APIC_LVT_MASKED;
	lapic->lvt_lint1 = temp;

	if (bootverbose)
		apic_dump("ioapic_finalize()");
}

/*
 * This routine is called after physical interrupts are enabled but before
 * the critical section is released.  We need to clean out any interrupts
 * that had already been posted to the cpu.
 */
static void
ioapic_cleanup(void)
{
	bzero(mdcpu->gd_ipending, sizeof(mdcpu->gd_ipending));
}

/* Must never be called */
static void
ioapic_stabilize(void)
{
	panic("ioapic_stabilize is called\n");
}

static int
ioapic_vectorctl(int op, int intr, int flags)
{
	int error;
	int vector;
	int select;
	uint32_t value;
	register_t ef;

	if (intr < 0 || intr >= IOAPIC_HWI_VECTORS ||
	    intr == IDT_OFFSET_SYSCALL - IDT_OFFSET)
		return EINVAL;

	ef = read_rflags();
	cpu_disable_intr();
	error = 0;

	switch(op) {
	case MACHINTR_VECTOR_SETUP:
		vector = IDT_OFFSET + intr;
		setidt(vector, ioapic_intr[intr], SDT_SYSIGT, SEL_KPL, 0);

		/*
		 * Now reprogram the vector in the IO APIC.  In order to avoid
		 * losing an EOI for a level interrupt, which is vector based,
		 * make sure that the IO APIC is programmed for edge-triggering
		 * first, then reprogrammed with the new vector.  This should
		 * clear the IRR bit.
		 */
		if (int_to_apicintpin[intr].ioapic >= 0) {
			imen_lock();

			select = int_to_apicintpin[intr].redirindex;
			value = ioapic_read(int_to_apicintpin[intr].ioapic,
					    select);
			value |= IOART_INTMSET;

			ioapic_write(int_to_apicintpin[intr].ioapic,
				     select, (value & ~APIC_TRIGMOD_MASK));
			ioapic_write(int_to_apicintpin[intr].ioapic,
				     select, (value & ~IOART_INTVEC) | vector);

			imen_unlock();
		}

		machintr_intren(intr);
		break;

	case MACHINTR_VECTOR_TEARDOWN:
		/*
		 * Teardown an interrupt vector.  The vector should already be
		 * installed in the cpu's IDT, but make sure.
		 */
		machintr_intrdis(intr);

		vector = IDT_OFFSET + intr;
		setidt(vector, ioapic_intr[intr], SDT_SYSIGT, SEL_KPL, 0);

		/*
		 * In order to avoid losing an EOI for a level interrupt, which
		 * is vector based, make sure that the IO APIC is programmed for
		 * edge-triggering first, then reprogrammed with the new vector.
		 * This should clear the IRR bit.
		 */
		if (int_to_apicintpin[intr].ioapic >= 0) {
			imen_lock();

			select = int_to_apicintpin[intr].redirindex;
			value = ioapic_read(int_to_apicintpin[intr].ioapic,
					    select);

			ioapic_write(int_to_apicintpin[intr].ioapic,
				     select, (value & ~APIC_TRIGMOD_MASK));
			ioapic_write(int_to_apicintpin[intr].ioapic,
				     select, (value & ~IOART_INTVEC) | vector);

			imen_unlock();
		}
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	write_rflags(ef);
	return error;
}

static void
ioapic_setdefault(void)
{
	int intr;

	for (intr = 0; intr < IOAPIC_HWI_VECTORS; ++intr) {
		if (intr == IDT_OFFSET_SYSCALL - IDT_OFFSET)
			continue;
		setidt(IDT_OFFSET + intr, ioapic_intr[intr], SDT_SYSIGT,
		       SEL_KPL, 0);
	}
}

/* XXX magic number */
static void
ioapic_initmap(void)
{
	int i;

	for (i = 0; i < 16; ++i) {
		struct ioapic_irqmap *map = &ioapic_irqmaps[i];

		map->im_type = IOAPIC_IMT_LINE;
		map->im_trig = INTR_TRIGGER_EDGE;
		map->im_gsi = i;
	}
}

#endif	/* SMP */
