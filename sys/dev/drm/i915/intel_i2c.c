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

void intel_i2c_quirk_set(struct drm_device *dev, bool enable)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

	/* When using bit bashing for I2C, this bit needs to be set to 1 */
	if (!IS_PINEVIEW(dev))
		return;
	if (enable)
		I915_WRITE(DSPCLK_GATE_D,
			I915_READ(DSPCLK_GATE_D) | DPCUNIT_CLOCK_GATE_DISABLE);
	else
		I915_WRITE(DSPCLK_GATE_D,
			I915_READ(DSPCLK_GATE_D) & (~DPCUNIT_CLOCK_GATE_DISABLE));
}

/*
 * Intel GPIO access functions
 */

#define I2C_RISEFALL_TIME 20

#ifdef __linux__
static int get_clock(void *data)
#else
int i915_get_clock(device_t dev)
#endif
{
	struct i915_iic_softc *sc = (struct i915_iic_softc *)device_get_softc(dev);
	struct intel_i2c_chan *chan = (struct intel_i2c_chan *)sc->drm_dev->iic_private;

	struct drm_i915_private *dev_priv = chan->drm_dev->dev_private;
	u32 val;

	val = I915_READ(chan->reg);
	return ((val & GPIO_CLOCK_VAL_IN) != 0);
}

#ifdef __linux__
static int get_data(void *data)
#else
int i915_get_data(device_t dev)
#endif
{
	struct i915_iic_softc *sc = (struct i915_iic_softc *)device_get_softc(dev);
	struct intel_i2c_chan *chan = (struct intel_i2c_chan *)sc->drm_dev->iic_private;

	struct drm_i915_private *dev_priv = chan->drm_dev->dev_private;
	u32 val;

	val = I915_READ(chan->reg);
	return ((val & GPIO_DATA_VAL_IN) != 0);
}

#ifdef __linux__
static void set_clock(void *data, int state_high)
#else
void i915_set_clock(device_t dev, int state_high)
#endif
{
	struct i915_iic_softc *sc = (struct i915_iic_softc *)device_get_softc(dev);
	struct intel_i2c_chan *chan = (struct intel_i2c_chan *)sc->drm_dev->iic_private;

	struct drm_device *drm_dev = chan->drm_dev;
	struct drm_i915_private *dev_priv = chan->drm_dev->dev_private;
	u32 reserved = 0, clock_bits;

	/* On most chips, these bits must be preserved in software. */
	if (!IS_I830(drm_dev) && !IS_845G(drm_dev))
		reserved = I915_READ(chan->reg) & (GPIO_DATA_PULLUP_DISABLE |
						   GPIO_CLOCK_PULLUP_DISABLE);

	if (state_high)
		clock_bits = GPIO_CLOCK_DIR_IN | GPIO_CLOCK_DIR_MASK;
	else
		clock_bits = GPIO_CLOCK_DIR_OUT | GPIO_CLOCK_DIR_MASK |
			GPIO_CLOCK_VAL_MASK;
	I915_WRITE(chan->reg, reserved | clock_bits);
	udelay(I2C_RISEFALL_TIME); /* wait for the line to change state */
}

#ifdef __linux__
static void set_data(void *data, int state_high)
#else
void i915_set_data(device_t dev, int state_high)
#endif
{
	struct i915_iic_softc *sc = (struct i915_iic_softc *)device_get_softc(dev);
	struct intel_i2c_chan *chan = (struct intel_i2c_chan *)sc->drm_dev->iic_private;

	struct drm_device *drm_dev = chan->drm_dev;
	struct drm_i915_private *dev_priv = chan->drm_dev->dev_private;
	u32 reserved = 0, data_bits;

	/* On most chips, these bits must be preserved in software. */
	if (!IS_I830(drm_dev) && !IS_845G(drm_dev))
		reserved = I915_READ(chan->reg) & (GPIO_DATA_PULLUP_DISABLE |
						   GPIO_CLOCK_PULLUP_DISABLE);

	if (state_high)
		data_bits = GPIO_DATA_DIR_IN | GPIO_DATA_DIR_MASK;
	else
		data_bits = GPIO_DATA_DIR_OUT | GPIO_DATA_DIR_MASK |
			GPIO_DATA_VAL_MASK;

	I915_WRITE(chan->reg, reserved | data_bits);
	udelay(I2C_RISEFALL_TIME); /* wait for the line to change state */
}

/* Clears the GMBUS setup.  Our driver doesn't make use of the GMBUS I2C
 * engine, but if the BIOS leaves it enabled, then that can break our use
 * of the bit-banging I2C interfaces.  This is notably the case with the
 * Mac Mini in EFI mode.
 */
void
intel_i2c_reset_gmbus(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

	if (HAS_PCH_SPLIT(dev)) {
		I915_WRITE(PCH_GMBUS0, 0);
	} else {
		I915_WRITE(GMBUS0, 0);
	}
}

/**
 * intel_i2c_create - instantiate an Intel i2c bus using the specified GPIO reg
 * @dev: DRM device
 * @output: driver specific output device
 * @reg: GPIO reg to use
 * @name: name for this bus
 * @slave_addr: slave address (if fixed)
 *
 * Creates and registers a new i2c bus with the Linux i2c layer, for use
 * in output probing and control (e.g. DDC or SDVO control functions).
 *
 * Possible values for @reg include:
 *   %GPIOA
 *   %GPIOB
 *   %GPIOC
 *   %GPIOD
 *   %GPIOE
 *   %GPIOF
 *   %GPIOG
 *   %GPIOH
 * see PRM for details on how these different busses are used.
 */
struct i2c_adapter *intel_i2c_create(struct drm_device *dev, const u32 reg,
				     const char *name)
{
	struct intel_i2c_chan *chan;

	chan = malloc(sizeof(struct intel_i2c_chan), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!chan)
		goto out_free;

	chan->drm_dev = dev;
	chan->reg = reg;
	snprintf(chan->adapter.name, I2C_NAME_SIZE, "intel drm %s", name);
#ifdef __linux__ /* UNIMPLEMENTED */
	chan->adapter.owner = THIS_MODULE;
#endif
	chan->adapter.algo_data	= &chan->algo;
#ifdef __linux__
	chan->adapter.dev.parent = &dev->pdev->dev;
#else
	chan->adapter.iicbus = dev->iicbus;
#endif
#ifdef __linux__ /* UNIMPLEMENTED */
	chan->algo.setsda = set_data;
	chan->algo.setscl = set_clock;
	chan->algo.getsda = get_data;
	chan->algo.getscl = get_clock;
#endif
	chan->algo.udelay = 20;
	chan->algo.timeout = usecs_to_jiffies(2200);
	chan->algo.data = chan;

	i2c_set_adapdata(&chan->adapter, chan);

	if(i2c_bit_add_bus(&chan->adapter))
		goto out_free;

	intel_i2c_reset_gmbus(dev);

	/* JJJ:  raise SCL and SDA? */
	intel_i2c_quirk_set(dev, true);
	i915_set_data(dev->iicdrm, 1);
	i915_set_clock(dev->iicdrm, 1);
	intel_i2c_quirk_set(dev, false);
	udelay(20);

	return &chan->adapter;

out_free:
	free(chan, DRM_MEM_DRIVER);
	return NULL;
}

/**
 * intel_i2c_destroy - unregister and free i2c bus resources
 * @output: channel to free
 *
 * Unregister the adapter from the i2c layer, then free the structure.
 */
void intel_i2c_destroy(struct i2c_adapter *adapter)
{
	struct intel_i2c_chan *chan;

	if (!adapter)
		return;

	chan = container_of(adapter,
			    struct intel_i2c_chan,
			    adapter);
	i2c_del_adapter(&chan->adapter);
	free(chan, DRM_MEM_DRIVER);
}
