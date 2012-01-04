/*-
 * Copyright (c) 2000 Doug Rabson
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
 *	$FreeBSD: src/sys/dev/agp/agp.c,v 1.58 2007/11/12 21:51:36 jhb Exp $
 */

#include "opt_bus.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/agpio.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/rman.h>

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include "agppriv.h"
#include "agpvar.h"
#include "agpreg.h"

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/pmap.h>

#include <machine/md_var.h>

MODULE_VERSION(agp, 1);

MALLOC_DEFINE(M_AGP, "agp", "AGP data structures");

static d_open_t agp_open;
static d_close_t agp_close;
static d_ioctl_t agp_ioctl;
static d_mmap_t agp_mmap;

static struct dev_ops agp_ops = {
	{ "agp", 0, D_TTY },
	.d_open =	agp_open,
	.d_close =	agp_close,
	.d_ioctl =	agp_ioctl,
	.d_mmap =	agp_mmap,
};

static devclass_t agp_devclass;
#define KDEV2DEV(kdev)	devclass_get_device(agp_devclass, minor(kdev))

/* Helper functions for implementing chipset mini drivers. */

void
agp_flush_cache(void)
{
#if defined(__i386__) || defined(__x86_64__)
	wbinvd();
#endif
}

u_int8_t
agp_find_caps(device_t dev)
{
	int capreg;

	if (pci_find_extcap(dev, PCIY_AGP, &capreg) != 0)
		capreg = 0;
	return (capreg);
}

/*
 * Find an AGP display device (if any).
 */
static device_t
agp_find_display(void)
{
	devclass_t pci = devclass_find("pci");
	device_t bus, dev = 0;
	device_t *kids;
	int busnum, numkids, i;

	for (busnum = 0; busnum < devclass_get_maxunit(pci); busnum++) {
		bus = devclass_get_device(pci, busnum);
		if (!bus)
			continue;
		device_get_children(bus, &kids, &numkids);
		for (i = 0; i < numkids; i++) {
			dev = kids[i];
			if (pci_get_class(dev) == PCIC_DISPLAY
			    && pci_get_subclass(dev) == PCIS_DISPLAY_VGA)
				if (agp_find_caps(dev)) {
					kfree(kids, M_TEMP);
					return dev;
				}
					
		}
		kfree(kids, M_TEMP);
	}

	return 0;
}

struct agp_gatt *
agp_alloc_gatt(device_t dev)
{
	u_int32_t apsize = AGP_GET_APERTURE(dev);
	u_int32_t entries = apsize >> AGP_PAGE_SHIFT;
	struct agp_gatt *gatt;

	if (bootverbose)
		device_printf(dev,
			      "allocating GATT for aperture of size %dM\n",
			      apsize / (1024*1024));

	if (entries == 0) {
		device_printf(dev, "bad aperture size\n");
		return NULL;
	}

	gatt = kmalloc(sizeof(struct agp_gatt), M_AGP, M_INTWAIT);
	gatt->ag_entries = entries;
	gatt->ag_virtual = contigmalloc(entries * sizeof(u_int32_t), M_AGP,
					M_WAITOK|M_ZERO, 0, ~0, PAGE_SIZE, 0);
	if (!gatt->ag_virtual) {
		if (bootverbose)
			device_printf(dev, "contiguous allocation failed\n");
		kfree(gatt, M_AGP);
		return 0;
	}
	gatt->ag_physical = vtophys((vm_offset_t) gatt->ag_virtual);
	agp_flush_cache();

	return gatt;
}

void
agp_free_gatt(struct agp_gatt *gatt)
{
	contigfree(gatt->ag_virtual,
		   gatt->ag_entries * sizeof(u_int32_t), M_AGP);
	kfree(gatt, M_AGP);
}

static u_int agp_max[][2] = {
	{0,	0},
	{32,	4},
	{64,	28},
	{128,	96},
	{256,	204},
	{512,	440},
	{1024,	942},
	{2048,	1920},
	{4096,	3932}
};
#define agp_max_size	NELEM(agp_max)

/**
 * Sets the PCI resource which represents the AGP aperture.
 *
 * If not called, the default AGP aperture resource of AGP_APBASE will
 * be used.  Must be called before agp_generic_attach().
 */
void
agp_set_aperture_resource(device_t dev, int rid)
{
	struct agp_softc *sc = device_get_softc(dev);

	sc->as_aperture_rid = rid;
}

int
agp_generic_attach(device_t dev)
{
	struct agp_softc *sc = device_get_softc(dev);
	int i;
	u_int memsize;

	/*
	 * Find and map the aperture, RF_SHAREABLE for DRM but not RF_ACTIVE
	 * because the kernel doesn't need to map it.
	 */
	if (sc->as_aperture_rid == 0)
		sc->as_aperture_rid = AGP_APBASE;

	sc->as_aperture = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &sc->as_aperture_rid, RF_SHAREABLE);
	if (!sc->as_aperture)
		return ENOMEM;

	/*
	 * Work out an upper bound for agp memory allocation. This
	 * uses a heurisitc table from the Linux driver.
	 */
	memsize = ptoa(Maxmem) >> 20;
	for (i = 0; i < agp_max_size; i++) {
		if (memsize <= agp_max[i][0])
			break;
	}
	if (i == agp_max_size) i = agp_max_size - 1;
	sc->as_maxmem = agp_max[i][1] << 20U;

	/*
	 * The lock is used to prevent re-entry to
	 * agp_generic_bind_memory() since that function can sleep.
	 */
	lockinit(&sc->as_lock, "agplk", 0, 0);

	/*
	 * Initialise stuff for the userland device.
	 */
	agp_devclass = devclass_find("agp");
	TAILQ_INIT(&sc->as_memory);
	sc->as_nextid = 1;

	make_dev(&agp_ops, device_get_unit(dev), UID_ROOT, GID_WHEEL,
		 0600, "agpgart");

	return 0;
}

void
agp_free_cdev(device_t dev)
{
	dev_ops_remove_minor(&agp_ops, device_get_unit(dev));
}

void
agp_free_res(device_t dev)
{
	struct agp_softc *sc = device_get_softc(dev);

	bus_release_resource(dev, SYS_RES_MEMORY, sc->as_aperture_rid,
			     sc->as_aperture);
	agp_flush_cache();
}

int
agp_generic_detach(device_t dev)
{
	agp_free_cdev(dev);
	agp_free_res(dev);
	return 0;
}

/**
 * Default AGP aperture size detection which simply returns the size of
 * the aperture's PCI resource.
 */
int
agp_generic_get_aperture(device_t dev)
{
	struct agp_softc *sc = device_get_softc(dev);

	return rman_get_size(sc->as_aperture);
}

/**
 * Default AGP aperture size setting function, which simply doesn't allow
 * changes to resource size.
 */
int
agp_generic_set_aperture(device_t dev, u_int32_t aperture)
{
	u_int32_t current_aperture;

	current_aperture = AGP_GET_APERTURE(dev);
	if (current_aperture != aperture)
		return EINVAL;
	else
		return 0;
}

/*
 * This does the enable logic for v3, with the same topology
 * restrictions as in place for v2 -- one bus, one device on the bus.
 */
static int
agp_v3_enable(device_t dev, device_t mdev, u_int32_t mode)
{
	u_int32_t tstatus, mstatus;
	u_int32_t command;
	int rq, sba, fw, rate, arqsz, cal;

	tstatus = pci_read_config(dev, agp_find_caps(dev) + AGP_STATUS, 4);
	mstatus = pci_read_config(mdev, agp_find_caps(mdev) + AGP_STATUS, 4);

	/* Set RQ to the min of mode, tstatus and mstatus */
	rq = AGP_MODE_GET_RQ(mode);
	if (AGP_MODE_GET_RQ(tstatus) < rq)
		rq = AGP_MODE_GET_RQ(tstatus);
	if (AGP_MODE_GET_RQ(mstatus) < rq)
		rq = AGP_MODE_GET_RQ(mstatus);

	/*
	 * ARQSZ - Set the value to the maximum one.
	 * Don't allow the mode register to override values.
	 */
	arqsz = AGP_MODE_GET_ARQSZ(mode);
	if (AGP_MODE_GET_ARQSZ(tstatus) > rq)
		rq = AGP_MODE_GET_ARQSZ(tstatus);
	if (AGP_MODE_GET_ARQSZ(mstatus) > rq)
		rq = AGP_MODE_GET_ARQSZ(mstatus);

	/* Calibration cycle - don't allow override by mode register */
	cal = AGP_MODE_GET_CAL(tstatus);
	if (AGP_MODE_GET_CAL(mstatus) < cal)
		cal = AGP_MODE_GET_CAL(mstatus);

	/* SBA must be supported for AGP v3. */
	sba = 1;

	/* Set FW if all three support it. */
	fw = (AGP_MODE_GET_FW(tstatus)
	       & AGP_MODE_GET_FW(mstatus)
	       & AGP_MODE_GET_FW(mode));
	
	/* Figure out the max rate */
	rate = (AGP_MODE_GET_RATE(tstatus)
		& AGP_MODE_GET_RATE(mstatus)
		& AGP_MODE_GET_RATE(mode));
	if (rate & AGP_MODE_V3_RATE_8x)
		rate = AGP_MODE_V3_RATE_8x;
	else
		rate = AGP_MODE_V3_RATE_4x;
	if (bootverbose)
		device_printf(dev, "Setting AGP v3 mode %d\n", rate * 4);

	pci_write_config(dev, agp_find_caps(dev) + AGP_COMMAND, 0, 4);

	/* Construct the new mode word and tell the hardware */
	command = 0;
	command = AGP_MODE_SET_RQ(0, rq);
	command = AGP_MODE_SET_ARQSZ(command, arqsz);
	command = AGP_MODE_SET_CAL(command, cal);
	command = AGP_MODE_SET_SBA(command, sba);
	command = AGP_MODE_SET_FW(command, fw);
	command = AGP_MODE_SET_RATE(command, rate);
	command = AGP_MODE_SET_MODE_3(command, 1);
	command = AGP_MODE_SET_AGP(command, 1);
	pci_write_config(dev, agp_find_caps(dev) + AGP_COMMAND, command, 4);
	pci_write_config(mdev, agp_find_caps(mdev) + AGP_COMMAND, command, 4);

	return 0;
}

static int
agp_v2_enable(device_t dev, device_t mdev, u_int32_t mode)
{
	u_int32_t tstatus, mstatus;
	u_int32_t command;
	int rq, sba, fw, rate;

	tstatus = pci_read_config(dev, agp_find_caps(dev) + AGP_STATUS, 4);
	mstatus = pci_read_config(mdev, agp_find_caps(mdev) + AGP_STATUS, 4);

	/* Set RQ to the min of mode, tstatus and mstatus */
	rq = AGP_MODE_GET_RQ(mode);
	if (AGP_MODE_GET_RQ(tstatus) < rq)
		rq = AGP_MODE_GET_RQ(tstatus);
	if (AGP_MODE_GET_RQ(mstatus) < rq)
		rq = AGP_MODE_GET_RQ(mstatus);

	/* Set SBA if all three can deal with SBA */
	sba = (AGP_MODE_GET_SBA(tstatus)
	       & AGP_MODE_GET_SBA(mstatus)
	       & AGP_MODE_GET_SBA(mode));

	/* Similar for FW */
	fw = (AGP_MODE_GET_FW(tstatus)
	       & AGP_MODE_GET_FW(mstatus)
	       & AGP_MODE_GET_FW(mode));

	/* Figure out the max rate */
	rate = (AGP_MODE_GET_RATE(tstatus)
		& AGP_MODE_GET_RATE(mstatus)
		& AGP_MODE_GET_RATE(mode));
	if (rate & AGP_MODE_V2_RATE_4x)
		rate = AGP_MODE_V2_RATE_4x;
	else if (rate & AGP_MODE_V2_RATE_2x)
		rate = AGP_MODE_V2_RATE_2x;
	else
		rate = AGP_MODE_V2_RATE_1x;
	if (bootverbose)
		device_printf(dev, "Setting AGP v2 mode %d\n", rate);

	/* Construct the new mode word and tell the hardware */
	command = 0;
	command = AGP_MODE_SET_RQ(0, rq);
	command = AGP_MODE_SET_SBA(command, sba);
	command = AGP_MODE_SET_FW(command, fw);
	command = AGP_MODE_SET_RATE(command, rate);
	command = AGP_MODE_SET_AGP(command, 1);
	pci_write_config(dev, agp_find_caps(dev) + AGP_COMMAND, command, 4);
	pci_write_config(mdev, agp_find_caps(mdev) + AGP_COMMAND, command, 4);

	return 0;
}

int
agp_generic_enable(device_t dev, u_int32_t mode)
{
	device_t mdev = agp_find_display();
	u_int32_t tstatus, mstatus;

	if (!mdev) {
		AGP_DPF("can't find display\n");
		return ENXIO;
	}

	tstatus = pci_read_config(dev, agp_find_caps(dev) + AGP_STATUS, 4);
	mstatus = pci_read_config(mdev, agp_find_caps(mdev) + AGP_STATUS, 4);

	/*
	 * Check display and bridge for AGP v3 support.  AGP v3 allows
	 * more variety in topology than v2, e.g. multiple AGP devices
	 * attached to one bridge, or multiple AGP bridges in one
	 * system.  This doesn't attempt to address those situations,
	 * but should work fine for a classic single AGP slot system
	 * with AGP v3.
	 */
	if (AGP_MODE_GET_MODE_3(mode) &&
	    AGP_MODE_GET_MODE_3(tstatus) &&
	    AGP_MODE_GET_MODE_3(mstatus))
		return (agp_v3_enable(dev, mdev, mode));
	else
		return (agp_v2_enable(dev, mdev, mode));	    
}

struct agp_memory *
agp_generic_alloc_memory(device_t dev, int type, vm_size_t size)
{
	struct agp_softc *sc = device_get_softc(dev);
	struct agp_memory *mem;

	if ((size & (AGP_PAGE_SIZE - 1)) != 0)
		return 0;

	if (sc->as_allocated + size > sc->as_maxmem)
		return 0;

	if (type != 0) {
		kprintf("agp_generic_alloc_memory: unsupported type %d\n",
			type);
		return 0;
	}

	mem = kmalloc(sizeof *mem, M_AGP, M_INTWAIT);
	mem->am_id = sc->as_nextid++;
	mem->am_size = size;
	mem->am_type = 0;
	mem->am_obj = vm_object_allocate(OBJT_DEFAULT, atop(round_page(size)));
	mem->am_physical = 0;
	mem->am_offset = 0;
	mem->am_is_bound = 0;
	TAILQ_INSERT_TAIL(&sc->as_memory, mem, am_link);
	sc->as_allocated += size;

	return mem;
}

struct agp_memory *
agp_generic_alloc_given(device_t dev, int type, vm_size_t size, void *handle)
{
	struct agp_softc *sc = device_get_softc(dev);
	struct agp_memory *mem;

	if ((size & (AGP_PAGE_SIZE - 1)) != 0)
		return 0;

	if (sc->as_allocated + size > sc->as_maxmem)
		return 0;

	if (type != 0) {
		kprintf("agp_generic_alloc_memory: unsupported type %d\n",
			type);
		return 0;
	}

	mem = kmalloc(sizeof *mem, M_AGP, M_INTWAIT);
	mem->am_id = sc->as_nextid++;
	mem->am_size = size;
	mem->am_type = 0;
	mem->am_obj = (vm_object_t)handle;
	mem->am_physical = 0;
	mem->am_offset = 0;
	mem->am_is_bound = 0;
	TAILQ_INSERT_TAIL(&sc->as_memory, mem, am_link);
	sc->as_allocated += size;

	return mem;
}

int
agp_generic_free_memory(device_t dev, struct agp_memory *mem)
{
	struct agp_softc *sc = device_get_softc(dev);

	if (mem->am_is_bound)
		return EBUSY;

	sc->as_allocated -= mem->am_size;
	TAILQ_REMOVE(&sc->as_memory, mem, am_link);
	vm_object_deallocate(mem->am_obj);
	kfree(mem, M_AGP);
	return 0;
}

int
agp_generic_bind_memory(device_t dev, struct agp_memory *mem,
			vm_offset_t offset)
{
	struct agp_softc *sc = device_get_softc(dev);
	vm_offset_t i, j, k;
	vm_page_t m;
	int error;

	lockmgr(&sc->as_lock, LK_EXCLUSIVE);

	if (mem->am_is_bound) {
		device_printf(dev, "memory already bound\n");
		lockmgr(&sc->as_lock, LK_RELEASE);
		return EINVAL;
	}
	
	if (offset < 0
	    || (offset & (AGP_PAGE_SIZE - 1)) != 0
	    || offset + mem->am_size > AGP_GET_APERTURE(dev)) {
		device_printf(dev, "binding memory at bad offset %#x,%#x,%#x\n",
			      (int) offset, (int)mem->am_size,
			      (int)AGP_GET_APERTURE(dev));
		kprintf("Check BIOS's aperature size vs X\n");
		lockmgr(&sc->as_lock, LK_RELEASE);
		return EINVAL;
	}

	/*
	 * Bind the individual pages and flush the chipset's
	 * TLB.
	 */
	for (i = 0; i < mem->am_size; i += PAGE_SIZE) {
		/*
		 * Find a page from the object and wire it down. This page
		 * will be mapped using one or more entries in the GATT
		 * (assuming that PAGE_SIZE >= AGP_PAGE_SIZE. If this is
		 * the first call to bind, the pages will be allocated
		 * and zeroed.
		 */
		m = vm_page_grab(mem->am_obj, OFF_TO_IDX(i),
				 VM_ALLOC_NORMAL | VM_ALLOC_ZERO |
				 VM_ALLOC_RETRY);
		AGP_DPF("found page pa=%#x\n", VM_PAGE_TO_PHYS(m));
		vm_page_wire(m);

		/*
		 * Install entries in the GATT, making sure that if
		 * AGP_PAGE_SIZE < PAGE_SIZE and mem->am_size is not
		 * aligned to PAGE_SIZE, we don't modify too many GATT 
		 * entries.
		 */
		for (j = 0; j < PAGE_SIZE && i + j < mem->am_size;
		     j += AGP_PAGE_SIZE) {
			vm_offset_t pa = VM_PAGE_TO_PHYS(m) + j;
			AGP_DPF("binding offset %#x to pa %#x\n",
				offset + i + j, pa);
			error = AGP_BIND_PAGE(dev, offset + i + j, pa);
			if (error) {
				/*
				 * Bail out. Reverse all the mappings
				 * and unwire the pages.
				 */
				vm_page_wakeup(m);
				for (k = 0; k < i + j; k += AGP_PAGE_SIZE)
					AGP_UNBIND_PAGE(dev, offset + k);
				vm_object_hold(mem->am_obj);
				for (k = 0; k <= i; k += PAGE_SIZE) {
					m = vm_page_lookup_busy_wait(
						mem->am_obj, OFF_TO_IDX(k),
						FALSE, "agppg");
					vm_page_unwire(m, 0);
					vm_page_wakeup(m);
				}
				vm_object_drop(mem->am_obj);
				lockmgr(&sc->as_lock, LK_RELEASE);
				return error;
			}
		}
		vm_page_wakeup(m);
	}

	/*
	 * Flush the cpu cache since we are providing a new mapping
	 * for these pages.
	 */
	agp_flush_cache();

	/*
	 * Make sure the chipset gets the new mappings.
	 */
	AGP_FLUSH_TLB(dev);

	mem->am_offset = offset;
	mem->am_is_bound = 1;

	lockmgr(&sc->as_lock, LK_RELEASE);

	return 0;
}

int
agp_generic_unbind_memory(device_t dev, struct agp_memory *mem)
{
	struct agp_softc *sc = device_get_softc(dev);
	vm_page_t m;
	int i;

	lockmgr(&sc->as_lock, LK_EXCLUSIVE);

	if (!mem->am_is_bound) {
		device_printf(dev, "memory is not bound\n");
		lockmgr(&sc->as_lock, LK_RELEASE);
		return EINVAL;
	}


	/*
	 * Unbind the individual pages and flush the chipset's
	 * TLB. Unwire the pages so they can be swapped.
	 */
	for (i = 0; i < mem->am_size; i += AGP_PAGE_SIZE)
		AGP_UNBIND_PAGE(dev, mem->am_offset + i);
	vm_object_hold(mem->am_obj);
	for (i = 0; i < mem->am_size; i += PAGE_SIZE) {
		m = vm_page_lookup_busy_wait(mem->am_obj, atop(i),
					     FALSE, "agppg");
		vm_page_unwire(m, 0);
		vm_page_wakeup(m);
	}
	vm_object_drop(mem->am_obj);
		
	agp_flush_cache();
	AGP_FLUSH_TLB(dev);

	mem->am_offset = 0;
	mem->am_is_bound = 0;

	lockmgr(&sc->as_lock, LK_RELEASE);

	return 0;
}

/* Helper functions for implementing user/kernel api */

static int
agp_acquire_helper(device_t dev, enum agp_acquire_state state)
{
	struct agp_softc *sc = device_get_softc(dev);

	if (sc->as_state != AGP_ACQUIRE_FREE)
		return EBUSY;
	sc->as_state = state;

	return 0;
}

static int
agp_release_helper(device_t dev, enum agp_acquire_state state)
{
	struct agp_softc *sc = device_get_softc(dev);

	if (sc->as_state == AGP_ACQUIRE_FREE)
		return 0;

	if (sc->as_state != state)
		return EBUSY;

	sc->as_state = AGP_ACQUIRE_FREE;
	return 0;
}

static struct agp_memory *
agp_find_memory(device_t dev, int id)
{
	struct agp_softc *sc = device_get_softc(dev);
	struct agp_memory *mem;

	AGP_DPF("searching for memory block %d\n", id);
	TAILQ_FOREACH(mem, &sc->as_memory, am_link) {
		AGP_DPF("considering memory block %d\n", mem->am_id);
		if (mem->am_id == id)
			return mem;
	}
	return 0;
}

/* Implementation of the userland ioctl api */

static int
agp_info_user(device_t dev, agp_info *info)
{
	struct agp_softc *sc = device_get_softc(dev);

	bzero(info, sizeof *info);
	info->bridge_id = pci_get_devid(dev);
	info->agp_mode = 
	    pci_read_config(dev, agp_find_caps(dev) + AGP_STATUS, 4);
	info->aper_base = rman_get_start(sc->as_aperture);
	info->aper_size = AGP_GET_APERTURE(dev) >> 20;
	info->pg_total = info->pg_system = sc->as_maxmem >> AGP_PAGE_SHIFT;
	info->pg_used = sc->as_allocated >> AGP_PAGE_SHIFT;

	return 0;
}

static int
agp_setup_user(device_t dev, agp_setup *setup)
{
	return AGP_ENABLE(dev, setup->agp_mode);
}

static int
agp_allocate_user(device_t dev, agp_allocate *alloc)
{
	struct agp_memory *mem;

	mem = AGP_ALLOC_MEMORY(dev,
			       alloc->type,
			       alloc->pg_count << AGP_PAGE_SHIFT);
	if (mem) {
		alloc->key = mem->am_id;
		alloc->physical = mem->am_physical;
		return 0;
	} else {
		return ENOMEM;
	}
}

static int
agp_deallocate_user(device_t dev, int id)
{
	struct agp_memory *mem = agp_find_memory(dev, id);

	if (mem) {
		AGP_FREE_MEMORY(dev, mem);
		return 0;
	} else {
		return ENOENT;
	}
}

static int
agp_bind_user(device_t dev, agp_bind *bind)
{
	struct agp_memory *mem = agp_find_memory(dev, bind->key);

	if (!mem)
		return ENOENT;

	return AGP_BIND_MEMORY(dev, mem, bind->pg_start << AGP_PAGE_SHIFT);
}

static int
agp_unbind_user(device_t dev, agp_unbind *unbind)
{
	struct agp_memory *mem = agp_find_memory(dev, unbind->key);

	if (!mem)
		return ENOENT;

	return AGP_UNBIND_MEMORY(dev, mem);
}

static int
agp_open(struct dev_open_args *ap)
{
	cdev_t kdev = ap->a_head.a_dev;
	device_t dev = KDEV2DEV(kdev);
	struct agp_softc *sc = device_get_softc(dev);

	if (!sc->as_isopen) {
		sc->as_isopen = 1;
		device_busy(dev);
	}

	return 0;
}

static int
agp_close(struct dev_close_args *ap)
{
	cdev_t kdev = ap->a_head.a_dev;
	device_t dev = KDEV2DEV(kdev);
	struct agp_softc *sc = device_get_softc(dev);
	struct agp_memory *mem;

	/*
	 * Clear the GATT and force release on last close
	 */
	while ((mem = TAILQ_FIRST(&sc->as_memory)) != NULL) {
		if (mem->am_is_bound)
			AGP_UNBIND_MEMORY(dev, mem);
		AGP_FREE_MEMORY(dev, mem);
	}
	if (sc->as_state == AGP_ACQUIRE_USER)
		agp_release_helper(dev, AGP_ACQUIRE_USER);
	sc->as_isopen = 0;
	device_unbusy(dev);

	return 0;
}

static int
agp_ioctl(struct dev_ioctl_args *ap)
{
	cdev_t kdev = ap->a_head.a_dev;
	device_t dev = KDEV2DEV(kdev);

	switch (ap->a_cmd) {
	case AGPIOC_INFO:
		return agp_info_user(dev, (agp_info *)ap->a_data);

	case AGPIOC_ACQUIRE:
		return agp_acquire_helper(dev, AGP_ACQUIRE_USER);

	case AGPIOC_RELEASE:
		return agp_release_helper(dev, AGP_ACQUIRE_USER);

	case AGPIOC_SETUP:
		return agp_setup_user(dev, (agp_setup *)ap->a_data);

	case AGPIOC_ALLOCATE:
		return agp_allocate_user(dev, (agp_allocate *)ap->a_data);

	case AGPIOC_DEALLOCATE:
		return agp_deallocate_user(dev, *(int *)ap->a_data);

	case AGPIOC_BIND:
		return agp_bind_user(dev, (agp_bind *)ap->a_data);

	case AGPIOC_UNBIND:
		return agp_unbind_user(dev, (agp_unbind *)ap->a_data);

	}

	return EINVAL;
}

static int
agp_mmap(struct dev_mmap_args *ap)
{
	cdev_t kdev = ap->a_head.a_dev;
	device_t dev = KDEV2DEV(kdev);
	struct agp_softc *sc = device_get_softc(dev);

	if (ap->a_offset > AGP_GET_APERTURE(dev))
		return EINVAL;
	ap->a_result = atop(rman_get_start(sc->as_aperture) + ap->a_offset);
	return 0;
}

/* Implementation of the kernel api */

device_t
agp_find_device(void)
{
	device_t *children, child;
	int i, count;

	if (!agp_devclass)
		return NULL;
	if (devclass_get_devices(agp_devclass, &children, &count) != 0)
		return NULL;
	child = NULL;
	for (i = 0; i < count; i++) {
		if (device_is_attached(children[i])) {
			child = children[i];
			break;
		}
	}
	kfree(children, M_TEMP);
	return child;
}

enum agp_acquire_state
agp_state(device_t dev)
{
	struct agp_softc *sc = device_get_softc(dev);
	return sc->as_state;
}

void
agp_get_info(device_t dev, struct agp_info *info)
{
	struct agp_softc *sc = device_get_softc(dev);

	info->ai_mode =
		pci_read_config(dev, agp_find_caps(dev) + AGP_STATUS, 4);
	info->ai_aperture_base = rman_get_start(sc->as_aperture);
	info->ai_aperture_size = rman_get_size(sc->as_aperture);
	info->ai_memory_allowed = sc->as_maxmem;
	info->ai_memory_used = sc->as_allocated;
}

int
agp_acquire(device_t dev)
{
	return agp_acquire_helper(dev, AGP_ACQUIRE_KERNEL);
}

int
agp_release(device_t dev)
{
	return agp_release_helper(dev, AGP_ACQUIRE_KERNEL);
}

int
agp_enable(device_t dev, u_int32_t mode)
{
	return AGP_ENABLE(dev, mode);
}

void *agp_alloc_memory(device_t dev, int type, vm_size_t bytes)
{
	return  (void *) AGP_ALLOC_MEMORY(dev, type, bytes);
}

void *agp_alloc_given(device_t dev, int type, vm_size_t bytes, void *handle)
{
	return  (void *) AGP_ALLOC_GIVEN(dev, type, bytes, handle);
}

void agp_free_memory(device_t dev, void *handle)
{
	struct agp_memory *mem = (struct agp_memory *) handle;
	AGP_FREE_MEMORY(dev, mem);
}

int agp_bind_memory(device_t dev, void *handle, vm_offset_t offset)
{
	struct agp_memory *mem = (struct agp_memory *) handle;
	return AGP_BIND_MEMORY(dev, mem, offset);
}

int agp_unbind_memory(device_t dev, void *handle)
{
	struct agp_memory *mem = (struct agp_memory *) handle;
	return AGP_UNBIND_MEMORY(dev, mem);
}

void agp_memory_info(device_t dev, void *handle, struct
		     agp_memory_info *mi)
{
	struct agp_memory *mem = (struct agp_memory *) handle;

	mi->ami_size = mem->am_size;
	mi->ami_physical = mem->am_physical;
	mi->ami_offset = mem->am_offset;
	mi->ami_is_bound = mem->am_is_bound;
}
