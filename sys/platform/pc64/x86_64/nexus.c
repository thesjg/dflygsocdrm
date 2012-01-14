/*
 * Copyright 1998 Massachusetts Institute of Technology
 * Copyright (c) 2008 The DragonFly Project.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/i386/i386/nexus.c,v 1.26.2.10 2003/02/22 13:16:45 imp Exp $
 */

/*
 * This code implements a `root nexus' for Intel Architecture
 * machines.  The function of the root nexus is to serve as an
 * attachment point for both processors and buses, and to manage
 * resources which are common to all of them.  In particular,
 * this code implements the core resource managers for interrupt
 * requests, DMA requests (which rightfully should be a part of the
 * ISA code but it's easier to do it here for now), I/O port addresses,
 * and I/O memory address space.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/interrupt.h>
#include <sys/machintr.h>

#include <machine/vmparam.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/pmap.h>

#include <machine/nexusvar.h>
#include <machine/smp.h>
#include <machine/intr_machdep.h>
#include <machine_base/apic/lapic.h>
#include <machine_base/apic/ioapic.h>

#include "pcib_if.h"

#define I386_BUS_SPACE_IO       0       /* space is i/o space */
#define I386_BUS_SPACE_MEM      1       /* space is mem space */

static MALLOC_DEFINE(M_NEXUSDEV, "nexusdev", "Nexus device");
struct nexus_device {
	struct resource_list	nx_resources;
	int			nx_pcibus;
};

#define DEVTONX(dev)	((struct nexus_device *)device_get_ivars(dev))

static struct rman irq_rman[MAXCPU], drq_rman, port_rman, mem_rman;

static	int nexus_probe(device_t);
static	int nexus_attach(device_t);
static	int nexus_print_all_resources(device_t dev);
static	int nexus_print_child(device_t, device_t);
static device_t nexus_add_child(device_t bus, device_t parent, int order,
				const char *name, int unit);
static	struct resource *nexus_alloc_resource(device_t, device_t, int, int *,
    u_long, u_long, u_long, u_int, int);
static	int nexus_read_ivar(device_t, device_t, int, uintptr_t *);
static	int nexus_write_ivar(device_t, device_t, int, uintptr_t);
static	int nexus_activate_resource(device_t, device_t, int, int,
				    struct resource *);
static	int nexus_deactivate_resource(device_t, device_t, int, int,
				      struct resource *);
static	int nexus_release_resource(device_t, device_t, int, int,
				   struct resource *);
static	int nexus_config_intr(device_t, device_t, int, enum intr_trigger,
			      enum intr_polarity);
static	int nexus_setup_intr(device_t, device_t, struct resource *, int flags,
			     void (*)(void *), void *, 
			     void **, lwkt_serialize_t);
static	int nexus_teardown_intr(device_t, device_t, struct resource *,
				void *);
static	int nexus_set_resource(device_t, device_t, int, int, u_long, u_long,
			       int);
static	int nexus_get_resource(device_t, device_t, int, int, u_long *, u_long *);
static void nexus_delete_resource(device_t, device_t, int, int);

static	int nexus_alloc_msi(device_t, device_t, int, int, int *, int);
static	int nexus_release_msi(device_t, device_t, int, int *, int);
static	int nexus_map_msi(device_t, device_t, int, uint64_t *, uint32_t *, int);

/*
 * The device_identify method will cause nexus to automatically associate
 * and attach to the root bus.
 */
static device_method_t nexus_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	bus_generic_identify),
	DEVMETHOD(device_probe,		nexus_probe),
	DEVMETHOD(device_attach,	nexus_attach),
	DEVMETHOD(device_detach,	bus_generic_detach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	nexus_print_child),
	DEVMETHOD(bus_add_child,	nexus_add_child),
	DEVMETHOD(bus_read_ivar,	nexus_read_ivar),
	DEVMETHOD(bus_write_ivar,	nexus_write_ivar),
	DEVMETHOD(bus_alloc_resource,	nexus_alloc_resource),
	DEVMETHOD(bus_release_resource,	nexus_release_resource),
	DEVMETHOD(bus_activate_resource, nexus_activate_resource),
	DEVMETHOD(bus_deactivate_resource, nexus_deactivate_resource),
	DEVMETHOD(bus_config_intr,	nexus_config_intr),
	DEVMETHOD(bus_setup_intr,	nexus_setup_intr),
	DEVMETHOD(bus_teardown_intr,	nexus_teardown_intr),
	DEVMETHOD(bus_set_resource,	nexus_set_resource),
	DEVMETHOD(bus_get_resource,	nexus_get_resource),
	DEVMETHOD(bus_delete_resource,	nexus_delete_resource),

	DEVMETHOD(pcib_alloc_msi,	nexus_alloc_msi),
	DEVMETHOD(pcib_release_msi,	nexus_release_msi),
	DEVMETHOD(pcib_map_msi,		nexus_map_msi),

	{ 0, 0 }
};

static driver_t nexus_driver = {
	"nexus",
	nexus_methods,
	1,			/* no softc */
};
static devclass_t nexus_devclass;

DRIVER_MODULE(nexus, root, nexus_driver, nexus_devclass, NULL, NULL);

static int
nexus_probe(device_t dev)
{
	int cpuid;

	device_quiet(dev);	/* suppress attach message for neatness */

	for (cpuid = 0; cpuid < ncpus; ++cpuid) {
		struct rman *rm = &irq_rman[cpuid];

		rm->rm_start = 0;
		rm->rm_end = IDT_HWI_VECTORS - 1;
		rm->rm_type = RMAN_ARRAY;
		rm->rm_descr = "Interrupt request lines";

		if (rman_init(rm, cpuid))
			panic("nexus_probe rman_init");
		MachIntrABI.rman_setup(rm);
	}

	/*
	 * ISA DMA on PCI systems is implemented in the ISA part of each
	 * PCI->ISA bridge and the channels can be duplicated if there are
	 * multiple bridges.  (eg: laptops with docking stations)
	 */
	drq_rman.rm_start = 0;
	drq_rman.rm_end = 7;
	drq_rman.rm_type = RMAN_ARRAY;
	drq_rman.rm_descr = "DMA request lines";
	/* XXX drq 0 not available on some machines */
	if (rman_init(&drq_rman, -1)
	    || rman_manage_region(&drq_rman,
				  drq_rman.rm_start, drq_rman.rm_end))
		panic("nexus_probe drq_rman");

	/*
	 * However, IO ports and Memory truely are global at this level,
	 * as are APIC interrupts (however many IO APICS there turn out
	 * to be on large systems..)
	 */
	port_rman.rm_start = 0;
	port_rman.rm_end = 0xffff;
	port_rman.rm_type = RMAN_ARRAY;
	port_rman.rm_descr = "I/O ports";
	if (rman_init(&port_rman, -1)
	    || rman_manage_region(&port_rman, 0, 0xffff))
		panic("nexus_probe port_rman");

	mem_rman.rm_start = 0;
	mem_rman.rm_end = ~0u;
	mem_rman.rm_type = RMAN_ARRAY;
	mem_rman.rm_descr = "I/O memory addresses";
	if (rman_init(&mem_rman, -1)
	    || rman_manage_region(&mem_rman, 0, ~0))
		panic("nexus_probe mem_rman");

	return bus_generic_probe(dev);
}

static int
nexus_attach(device_t dev)
{
	device_t	child;

	/*
	 * First, let our child driver's identify any child devices that
	 * they can find.  Once that is done attach any devices that we
	 * found.
	 */
#if 0 /* FUTURE */
	bus_generic_probe(dev);
#endif
	bus_generic_attach(dev);

	/*
	 * And if we didn't see ISA on a pci bridge, create a
	 * connection point now so it shows up "on motherboard".
	 */
	if (!devclass_get_device(devclass_find("isa"), 0)) {
		child = BUS_ADD_CHILD(dev, dev, 0, "isa", 0);
		if (child == NULL)
			panic("nexus_attach isa");
		device_probe_and_attach(child);
	}

	return 0;
}

static int
nexus_print_all_resources(device_t dev)
{
	struct	nexus_device *ndev = DEVTONX(dev);
	struct resource_list *rl = &ndev->nx_resources;
	int retval = 0;

	if (SLIST_FIRST(rl) || ndev->nx_pcibus != -1)
		retval += kprintf(" at");
	
	retval += resource_list_print_type(rl, "port", SYS_RES_IOPORT, "%#lx");
	retval += resource_list_print_type(rl, "iomem", SYS_RES_MEMORY, "%#lx");
	retval += resource_list_print_type(rl, "irq", SYS_RES_IRQ, "%ld");

	return retval;
}

static int
nexus_print_child(device_t bus, device_t child)
{
	struct	nexus_device *ndev = DEVTONX(child);
	int retval = 0;

	retval += bus_print_child_header(bus, child);
	retval += nexus_print_all_resources(child);
	if (ndev->nx_pcibus != -1)
		retval += kprintf(" pcibus %d", ndev->nx_pcibus);
	retval += kprintf(" on motherboard\n");

	return (retval);
}

static device_t
nexus_add_child(device_t bus, device_t parent, int order,
		const char *name, int unit)
{
	device_t		child;
	struct nexus_device	*ndev;

	ndev = kmalloc(sizeof(struct nexus_device), M_NEXUSDEV, M_INTWAIT|M_ZERO);
	if (!ndev)
		return(0);
	resource_list_init(&ndev->nx_resources);
	ndev->nx_pcibus = -1;

	child = device_add_child_ordered(parent, order, name, unit); 

	/* should we free this in nexus_child_detached? */
	device_set_ivars(child, ndev);

	return(child);
}

static int
nexus_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{
	struct nexus_device *ndev = DEVTONX(child);
	
	switch (which) {
	case NEXUS_IVAR_PCIBUS:
		*result = ndev->nx_pcibus;
		break;
	default:
		return ENOENT;
	}
	return 0;
}

static int
nexus_write_ivar(device_t dev, device_t child, int which, uintptr_t value)
{
	struct nexus_device *ndev = DEVTONX(child);
	
	switch (which) {
	case NEXUS_IVAR_PCIBUS:
		ndev->nx_pcibus = value;
		break;
	default:
		return ENOENT;
	}
	return 0;
}

/*
 * Allocate a resource on behalf of child.  NB: child is usually going to be a
 * child of one of our descendants, not a direct child of nexus0.
 * (Exceptions include npx.)
 */
static struct resource *
nexus_alloc_resource(device_t bus, device_t child, int type, int *rid,
    u_long start, u_long end, u_long count, u_int flags, int cpuid)
{
	struct nexus_device *ndev = DEVTONX(child);
	struct	resource *rv;
	struct resource_list_entry *rle;
	struct	rman *rm;
	int needactivate = flags & RF_ACTIVE;

	/*
	 * If this is an allocation of the "default" range for a given RID, and
	 * we know what the resources for this device are (ie. they aren't maintained
	 * by a child bus), then work out the start/end values.
	 */
	if ((start == 0UL) && (end == ~0UL) && (count == 1)) {
		if (ndev == NULL)
			return(NULL);
		rle = resource_list_find(&ndev->nx_resources, type, *rid);
		if (rle == NULL)
			return(NULL);
		start = rle->start;
		end = rle->end;
		count = rle->count;
		cpuid = rle->cpuid;
	}

	flags &= ~RF_ACTIVE;

	switch (type) {
	case SYS_RES_IRQ:
		KASSERT(cpuid >= 0 && cpuid < ncpus,
		    ("nexus invalid cpuid %d:\n", cpuid));
		rm = &irq_rman[cpuid];
		break;

	case SYS_RES_DRQ:
		rm = &drq_rman;
		break;

	case SYS_RES_IOPORT:
		rm = &port_rman;
		break;

	case SYS_RES_MEMORY:
		rm = &mem_rman;
		break;

	default:
		return 0;
	}

	rv = rman_reserve_resource(rm, start, end, count, flags, child);
	if (rv == NULL)
		return 0;
	rman_set_rid(rv, *rid);

	if (type == SYS_RES_MEMORY) {
		rman_set_bustag(rv, I386_BUS_SPACE_MEM);
	} else if (type == SYS_RES_IOPORT) {
		rman_set_bustag(rv, I386_BUS_SPACE_IO);
		rman_set_bushandle(rv, rv->r_start);
	}

	if (needactivate) {
		if (bus_activate_resource(child, type, *rid, rv)) {
			rman_release_resource(rv);
			return 0;
		}
	}
	
	return rv;
}

static int
nexus_activate_resource(device_t bus, device_t child, int type, int rid,
			struct resource *r)
{
	/*
	 * If this is a memory resource, map it into the kernel.
	 */
	if (rman_get_bustag(r) == I386_BUS_SPACE_MEM) {
		caddr_t vaddr = 0;

		if (rman_get_end(r) < 1024 * 1024) {
			/*
			 * The first 1Mb is mapped at KERNBASE.
			 */
			vaddr = (caddr_t)(uintptr_t)(KERNBASE + rman_get_start(r));
		} else {
			u_int64_t paddr;
			u_int64_t psize;
			u_int32_t poffs;

			paddr = rman_get_start(r);
			psize = rman_get_size(r);

			poffs = paddr - trunc_page(paddr);
			vaddr = (caddr_t) pmap_mapdev(paddr-poffs, psize+poffs) + poffs;
		}
		rman_set_virtual(r, vaddr);
		/* IBM-PC: the type of bus_space_handle_t is u_int */
		rman_set_bushandle(r, (bus_space_handle_t) vaddr);
	}
	return (rman_activate_resource(r));
}

static int
nexus_deactivate_resource(device_t bus, device_t child, int type, int rid,
			  struct resource *r)
{
	/*
	 * If this is a memory resource, unmap it.
	 */
	if ((rman_get_bustag(r) == I386_BUS_SPACE_MEM) &&
	    (rman_get_end(r) >= 1024 * 1024)) {
		u_int32_t psize;

		psize = rman_get_size(r);
		pmap_unmapdev((vm_offset_t)rman_get_virtual(r), psize);
	}
		
	return (rman_deactivate_resource(r));
}

static int
nexus_release_resource(device_t bus, device_t child, int type, int rid,
		       struct resource *r)
{
	if (rman_get_flags(r) & RF_ACTIVE) {
		int error = bus_deactivate_resource(child, type, rid, r);
		if (error)
			return error;
	}
	return (rman_release_resource(r));
}

static int
nexus_config_intr(device_t bus, device_t chile, int irq,
    enum intr_trigger trig, enum intr_polarity pola)
{
	machintr_legacy_intr_config(irq, trig, pola);
	return 0;
}

/*
 * Currently this uses the really grody interface from kern/kern_intr.c
 * (which really doesn't belong in kern/anything.c).  Eventually, all of
 * the code in kern_intr.c and machdep_intr.c should get moved here, since
 * this is going to be the official interface.
 */
static int
nexus_setup_intr(device_t bus, device_t child, struct resource *irq,
		 int flags, void (*ihand)(void *), void *arg,
		 void **cookiep, lwkt_serialize_t serializer)
{
	int	error, icflags;

	/* somebody tried to setup an irq that failed to allocate! */
	if (irq == NULL)
		panic("nexus_setup_intr: NULL irq resource!");

	*cookiep = NULL;
	icflags = flags;
	if ((irq->r_flags & RF_SHAREABLE) == 0)
		icflags |= INTR_EXCL;

	/*
	 * We depend here on rman_activate_resource() being idempotent.
	 */
	error = rman_activate_resource(irq);
	if (error)
		return (error);

	/*
	 * XXX cast the interrupt handler function to an inthand2_t.  The
	 * difference is that an additional frame argument is passed which
	 * we do not currently want to expose the BUS subsystem to.
	 */
	*cookiep = register_int(irq->r_start, (inthand2_t *)ihand, arg,
				device_get_nameunit(child), serializer,
				icflags, rman_get_cpuid(irq));
	if (*cookiep == NULL)
		error = EINVAL;
	return (error);
}

static int
nexus_teardown_intr(device_t dev, device_t child, struct resource *r, void *ih)
{
	if (ih) {
		unregister_int(ih, rman_get_cpuid(r));
		return (0);
	}
	return(-1);
}

static int
nexus_set_resource(device_t dev, device_t child, int type, int rid,
    u_long start, u_long count, int cpuid)
{
	struct nexus_device	*ndev = DEVTONX(child);
	struct resource_list	*rl = &ndev->nx_resources;

	/* XXX this should return a success/failure indicator */
	resource_list_add(rl, type, rid, start, start + count - 1, count,
	    cpuid);
	return(0);
}

static int
nexus_get_resource(device_t dev, device_t child, int type, int rid, u_long *startp, u_long *countp)
{
	struct nexus_device	*ndev = DEVTONX(child);
	struct resource_list	*rl = &ndev->nx_resources;
	struct resource_list_entry *rle;

	rle = resource_list_find(rl, type, rid);
	device_printf(child, "type %d  rid %d  startp %p  countp %p - got %p\n",
		      type, rid, startp, countp, rle);
	if (!rle)
		return(ENOENT);
	if (startp)
		*startp = rle->start;
	if (countp)
		*countp = rle->count;
	return(0);
}

static void
nexus_delete_resource(device_t dev, device_t child, int type, int rid)
{
	struct nexus_device	*ndev = DEVTONX(child);
	struct resource_list	*rl = &ndev->nx_resources;

	resource_list_delete(rl, type, rid);
}

static int
nexus_alloc_msi(device_t dev, device_t child, int count, int maxcount,
    int *irqs, int cpuid)
{
	if (!lapic_enable)
		return ENODEV;

	return MachIntrABI.msi_alloc(irqs, count, cpuid);
}

static int
nexus_release_msi(device_t dev, device_t child, int count, int *irqs, int cpuid)
{
	KKASSERT(lapic_enable);
	MachIntrABI.msi_release(irqs, count, cpuid);
	return 0;
}

static int
nexus_map_msi(device_t dev, device_t child, int irq, uint64_t *addr,
    uint32_t *data, int cpuid)
{
	KKASSERT(lapic_enable);
	MachIntrABI.msi_map(irq, addr, data, cpuid);
	return 0;
}
