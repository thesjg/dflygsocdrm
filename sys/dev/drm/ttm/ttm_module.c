/**************************************************************************
 *
 * Copyright (c) 2006-2009 VMware, Inc., Palo Alto, CA., USA
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/
/*
 * Authors: Thomas Hellstrom <thellstrom-at-vmware-dot-com>
 * 	    Jerome Glisse
 */
#ifdef __linux__
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sched.h>
#else
#include "drm_porting_layer.h"
#endif
#include "ttm/ttm_module.h"
#ifdef __linux__
#include "drm_sysfs.h"
#endif

static DECLARE_WAIT_QUEUE_HEAD(exit_q);
atomic_t device_released;

static struct device_type ttm_drm_class_type = {
	.name = "ttm",
	/**
	 * Add pm ops here.
	 */
};

static void ttm_drm_class_device_release(struct device *dev)
{
	atomic_set(&device_released, 1);
	wake_up_all(&exit_q);
}

static struct device ttm_drm_class_device = {
	.type = &ttm_drm_class_type,
	.release = &ttm_drm_class_device_release
};

struct kobject *ttm_get_kobj(void)
{
	struct kobject *kobj = &ttm_drm_class_device.kobj;
	BUG_ON(kobj == NULL);
	return kobj;
}

static int __init ttm_init(void)
{
	int ret;

	ret = dev_set_name(&ttm_drm_class_device, "ttm");
	if (unlikely(ret != 0))
		return ret;

	ttm_global_init();

	atomic_set(&device_released, 0);
#ifdef __linux__ /* UNIMPLEMENTED */
	ret = drm_class_device_register(&ttm_drm_class_device);
#endif
	if (unlikely(ret != 0))
		goto out_no_dev_reg;

	return 0;
out_no_dev_reg:
	atomic_set(&device_released, 1);
	wake_up_all(&exit_q);
	ttm_global_release();
	return ret;
}

static void __exit ttm_exit(void)
{
#ifdef __linux__ /* UNIMPLEMENTED */
	drm_class_device_unregister(&ttm_drm_class_device);
#endif

	/**
	 * Refuse to unload until the TTM device is released.
	 * Not sure this is 100% needed.
	 */

	wait_event(exit_q, atomic_read(&device_released) == 1);
	ttm_global_release();
}

static int ttmdrm_handler(module_t mod, int what, void *arg) {
	int err = 0;
	switch(what) {
	case MOD_LOAD:
		ttm_init();
		break;
	case MOD_UNLOAD:
		ttm_exit();
		break;
	default:
		err = EINVAL;
		break;
	}
	return (err);
}

static moduledata_t ttmdrm_data= {
	"ttmdrm",
	ttmdrm_handler,
	0
};

MODULE_VERSION(ttmdrm, 1);
DECLARE_MODULE(ttmdrm, ttmdrm_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(ttmdrm, agp, 1, 1, 1);
MODULE_DEPEND(ttmdrm, pci, 1, 1, 1);
MODULE_DEPEND(ttmdrm, drm, 1, 1, 1);

#ifdef __linux__
module_init(ttm_init);
module_exit(ttm_exit);

MODULE_AUTHOR("Thomas Hellstrom, Jerome Glisse");
MODULE_DESCRIPTION("TTM memory manager subsystem (for DRM device)");
MODULE_LICENSE("GPL and additional rights");
#endif /* __linux__ */
