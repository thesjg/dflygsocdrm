/*
 * Copyright (c) 2006 Dave Airlie <airlied@linux.ie>
 * Copyright © 2006-2008 Intel Corporation
 *   Jesse Barnes <jesse.barnes@intel.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *	Eric Anholt <eric@anholt.net>
 */

/*
 * Adapted from sys/dev/video/cxm/cxm_i2c.c
 */

/*
 * Copyright (c) 2003, 2004, 2005
 *	John Wehle <john@feith.com>.  All rights reserved.
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
 *	This product includes software developed by John Wehle.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * I2c routines for the Conexant MPEG-2 Codec driver.
 */

#ifdef __linux__
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/i2c-id.h>
#include <linux/i2c-algo-bit.h>
#endif /* __linux__ */

#include "drmP.h"
#include "drm.h"
#include "intel_drv.h"
#include "i915_drm.h"
#include "i915_drv.h"
#ifndef __linux__
#include <bus/iicbus/iiconf.h>
#include "iicbb_if.h"
#endif

static int	i915_iic_probe(device_t dev);
static int	i915_iic_attach(device_t dev);
static int	i915_iic_detach(device_t dev);
static void	i915_iic_child_detached(device_t dev, device_t child);

static int	i915_iic_callback(device_t, int, caddr_t *);
static int	i915_iic_reset(device_t, u_char, u_char, u_char *);
#if 0 /* specified in intel_drv.h */
int	i915_get_clock(device_t);
int	i915_get_data(device_t);
void	i915_set_clock(device_t, int);
void	i915_set_data(device_t, int);
#endif

static device_method_t i915_iic_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,         i915_iic_probe),
	DEVMETHOD(device_attach,        i915_iic_attach),
	DEVMETHOD(device_detach,        i915_iic_detach),

	/* bus interface */
	DEVMETHOD(bus_child_detached,   i915_iic_child_detached),
	DEVMETHOD(bus_print_child,      bus_generic_print_child),
	DEVMETHOD(bus_driver_added,     bus_generic_driver_added),

	/* iicbb interface */
	DEVMETHOD(iicbb_callback,       i915_iic_callback),
	DEVMETHOD(iicbb_reset,          i915_iic_reset),
	DEVMETHOD(iicbb_getscl,         i915_get_clock),
	DEVMETHOD(iicbb_getsda,         i915_get_data),
	DEVMETHOD(iicbb_setscl,         i915_set_clock),
	DEVMETHOD(iicbb_setsda,         i915_set_data),

	{ 0, 0 }
};

static driver_t i915_iic_driver = {
	"i915_iic",
	i915_iic_methods,
	sizeof(struct i915_iic_softc),
};

static devclass_t i915_iic_devclass;

MODULE_VERSION(i915_iic, 1);
DRIVER_MODULE(i915_iic, i915, i915_iic_driver, i915_iic_devclass, 0, 0);
MODULE_DEPEND(i915_iic, iicbb, IICBB_MINVER, IICBB_PREFVER, IICBB_MAXVER);

/*
 * the boot time probe routine.
 *
 * The i915_iic device is only probed after it has
 * been established that the i915 device is present
 * which means that the i915_iic device * must *
 * be present since it's built into the i915 hardware.
 */
static int
i915_iic_probe(device_t dev)
{
	printk("i915_iic_probe called\n");
	device_set_desc(dev, "i915 I2C controller");

	return 0;
}

/*
 * the attach routine.
 */
static int
i915_iic_attach(device_t dev)
{
	printk("i915_iic_attach called\n");
	device_t *kids;
	device_t iicbus;
	int error;
	int numkids;
	int i;
	int unit;
#if 0
	bus_space_handle_t *bhandlep;
	bus_space_tag_t *btagp;
#endif
	struct i915_iic_softc *sc;
	device_t child;

	/* Get the device data */
	sc = device_get_softc(dev);
	unit = device_get_unit(dev);

	sc->drm_dev = (struct drm_device *)device_get_softc(device_get_parent(dev));
	sc->iicdrm = dev;
	sc->drm_dev->iicdrm = dev;

#if 0
	/* retrieve the cxm btag and bhandle */
	if (BUS_READ_IVAR(device_get_parent(dev), dev,
			  CXM_IVAR_BTAG, (uintptr_t *)&btagp)
	    || BUS_READ_IVAR(device_get_parent(dev), dev,
			     CXM_IVAR_BHANDLE, (uintptr_t *)&bhandlep)) {
		device_printf(dev,
			      "could not retrieve bus space information\n");
		return ENXIO;
	}

	sc->btag = *btagp;
	sc->bhandle = *bhandlep;
#endif

	/* add bit-banging generic code onto i915_iic interface */
	sc->iicbb = device_add_child(dev, "iicbb", -1);

	if (!sc->iicbb) {
		device_printf(dev, "could not add iicbb\n");
		return ENXIO;
	}

	/* probed and attached the bit-banging code */
	error = device_probe_and_attach(sc->iicbb);

	if (error) {
		device_printf(dev, "could not attach iicbb\n");
		goto fail;
	}

	/* locate iicbus which was attached by the bit-banging code */
	iicbus = NULL;
	device_get_children(sc->iicbb, &kids, &numkids);
	for (i = 0; i < numkids; i++)
		if (strcmp(device_get_name(kids[i]), "iicbus") == 0) {
			iicbus = kids[i];
			break;
		}
	kfree(kids, M_TEMP);

	if (!iicbus) {
		device_printf(dev, "could not find iicbus\n");
		error = ENXIO;
		goto fail;
	}

	sc->drm_dev->iicbus = iicbus;

#if 0
	if (BUS_WRITE_IVAR(device_get_parent(dev), dev,
			   CXM_IVAR_IICBUS, (uintptr_t)&iicbus)) {
		device_printf(dev, "could not store iicbus information\n");
		error = ENXIO;
		goto fail;
	}
#endif

	return 0;

fail:
	/*
	 * Detach the children before recursively deleting
	 * in case a child has a pointer to a grandchild
	 * which is used by the child's detach routine.
	 *
	 * Remember the child before detaching so we can
	 * delete it (bus_generic_detach indirectly zeroes
	 * sc->child_dev).
	 */
	child = sc->iicbb;
	bus_generic_detach(dev);
	if (child)
		device_delete_child(dev, child);

	return error;
}

/*
 * the detach routine.
 */
static int
i915_iic_detach(device_t dev)
{
	struct i915_iic_softc *sc;
	device_t child;

	/* Get the device data */
	sc = device_get_softc(dev);

#if 0
	BUS_WRITE_IVAR(device_get_parent(dev), dev, CXM_IVAR_IICBUS, 0);
#endif

	/*
	 * Detach the children before recursively deleting
	 * in case a child has a pointer to a grandchild
	 * which is used by the child's detach routine.
	 *
	 * Remember the child before detaching so we can
	 * delete it (bus_generic_detach indirectly zeroes
	 * sc->child_dev).
	 */
	child = sc->iicbb;
	bus_generic_detach(dev);
	if (child)
		device_delete_child(dev, child);

	return 0;
}

/*
 * the child detached routine.
 */
static void
i915_iic_child_detached(device_t dev, device_t child)
{
	struct i915_iic_softc *sc;

	/* Get the device data */
	sc = device_get_softc(dev);

	if (child == sc->iicbb)
		sc->iicbb = NULL;
}

static int
i915_iic_callback(device_t dev, int index, caddr_t *data)
{
	return 0;
}

static int
i915_iic_reset(device_t dev, u_char speed, u_char addr, u_char * oldaddr)
{
	struct i915_iic_softc *sc;

	/* Get the device data */
	sc = device_get_softc(dev);

#ifdef DRM_NEWER_MODESET
	intel_i2c_reset_gmbus(sc->drm_dev);

	/* JJJ:  raise SCL and SDA? */
	intel_i2c_quirk_set(sc->drm_dev, true);
	i915_set_data(dev, 1);
	i915_set_clock(dev, 1);
	intel_i2c_quirk_set(sc->drm_dev, false);
	udelay(20);
#endif

	return IIC_ENOADDR;
}
