/* i915_dma.c -- DMA support for the I915 -*- linux-c -*-
 */
/*
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 * IN NO EVENT SHALL TUNGSTEN GRAPHICS AND/OR ITS SUPPLIERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "drmP.h"
#include "drm.h"
#include "drm_crtc_helper.h"
#include "drm_fb_helper.h"
#include "intel_drv.h"
#include "i915_drm.h"
#include "i915_drv.h"

#ifdef __linux__
#include "i915_trace.h"
#else
#include "i915_trace_porting.h"
#endif

#ifdef __linux__
#include <linux/vgaarb.h>
#include <linux/acpi.h>
#include <linux/pnp.h>
#include <linux/vga_switcheroo.h>
#include <linux/slab.h>
#endif /* __linux__ */

/* Really want an OS-independent resettable timer.  Would like to have
 * this loop run for (eg) 3 sec, but have the timer reset every time
 * the head pointer changes, so that EBUSY only happens if the ring
 * actually stalls for (eg) 3 seconds.
 */
int i915_wait_ring(struct drm_device * dev, int n, const char *caller)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_ring_buffer_t *ring = &(dev_priv->ring);
	u32 acthd_reg = IS_I965G(dev) ? ACTHD_I965 : ACTHD;
	u32 last_acthd = I915_READ(acthd_reg);
	u32 acthd;
	u32 last_head = I915_READ(PRB0_HEAD) & HEAD_ADDR;
	int i;

	trace_i915_ring_wait_begin (dev);

	for (i = 0; i < 100000; i++) {
		ring->head = I915_READ(PRB0_HEAD) & HEAD_ADDR;
		acthd = I915_READ(acthd_reg);
		ring->space = ring->head - (ring->tail + 8);
		if (ring->space < 0)
			ring->space += ring->Size;
		if (ring->space >= n) {
			trace_i915_ring_wait_end (dev);
			return 0;
		}

		if (dev->primary->master) {
			struct drm_i915_master_private *master_priv = dev->primary->master->driver_priv;
			if (master_priv->sarea_priv)
				master_priv->sarea_priv->perf_boxes |= I915_BOX_WAIT;
		}


		if (ring->head != last_head)
			i = 0;
		if (acthd != last_acthd)
			i = 0;

		last_head = ring->head;
		last_acthd = acthd;
		msleep_interruptible(10);

	}

	trace_i915_ring_wait_end (dev);
	return -EBUSY;
}

/* As a ringbuffer is only allowed to wrap between instructions, fill
 * the tail with NOOPs.
 */
int i915_wrap_ring(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	volatile unsigned int *virt;
	int rem;

	rem = dev_priv->ring.Size - dev_priv->ring.tail;
	if (dev_priv->ring.space < rem) {
		int ret = i915_wait_ring(dev, rem, __func__);
		if (ret)
			return ret;
	}
	dev_priv->ring.space -= rem;

	virt = (unsigned int *)
		(dev_priv->ring.virtual_start + dev_priv->ring.tail);
	rem /= 4;
	while (rem--)
		*virt++ = MI_NOOP;

	dev_priv->ring.tail = 0;

	return 0;
}

/**
 * Sets up the hardware status page for devices that need a physical address
 * in the register.
 */
static int i915_init_phys_hws(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	/* Program Hardware Status Page */
	dev_priv->status_page_dmah =
		drm_pci_alloc(dev, PAGE_SIZE, PAGE_SIZE);

	if (!dev_priv->status_page_dmah) {
		DRM_ERROR("Can not allocate hardware status page\n");
		return -ENOMEM;
	}
	dev_priv->hw_status_page = dev_priv->status_page_dmah->vaddr;
	dev_priv->dma_status_page = dev_priv->status_page_dmah->busaddr;

	memset(dev_priv->hw_status_page, 0, PAGE_SIZE);

	if (IS_I965G(dev))
		dev_priv->dma_status_page |= (dev_priv->dma_status_page >> 28) &
					     0xf0;

	I915_WRITE(HWS_PGA, dev_priv->dma_status_page);
	DRM_DEBUG_DRIVER("Enabled hardware status page\n");
	return 0;
}

/**
 * Frees the hardware status page, whether it's a physical address or a virtual
 * address set up by the X Server.
 */
static void i915_free_hws(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	if (dev_priv->status_page_dmah) {
		drm_pci_free(dev, dev_priv->status_page_dmah);
		dev_priv->status_page_dmah = NULL;
	}

	if (dev_priv->status_gfx_addr) {
		dev_priv->status_gfx_addr = 0;
		drm_core_ioremapfree(&dev_priv->hws_map, dev);
	}

	/* Need to rewrite hardware status page */
	I915_WRITE(HWS_PGA, 0x1ffff000);
}

void i915_kernel_lost_context(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	struct drm_i915_master_private *master_priv;
	drm_i915_ring_buffer_t *ring = &(dev_priv->ring);

	/*
	 * We should never lose context on the ring with modesetting
	 * as we don't expose it to userspace
	 */
	if (drm_core_check_feature(dev, DRIVER_MODESET))
		return;

	ring->head = I915_READ(PRB0_HEAD) & HEAD_ADDR;
	ring->tail = I915_READ(PRB0_TAIL) & TAIL_ADDR;
	ring->space = ring->head - (ring->tail + 8);
	if (ring->space < 0)
		ring->space += ring->Size;

	if (!dev->primary->master)
		return;

	master_priv = dev->primary->master->driver_priv;
	if (ring->head == ring->tail && master_priv->sarea_priv)
		master_priv->sarea_priv->perf_boxes |= I915_BOX_RING_EMPTY;
}

static int i915_dma_cleanup(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	/* Make sure interrupts are disabled here because the uninstall ioctl
	 * may not have been called from userspace and after dev_private
	 * is freed, it's too late.
	 */
	if (dev->irq_enabled)
		drm_irq_uninstall(dev);

	if (dev_priv->ring.virtual_start) {
		drm_core_ioremapfree(&dev_priv->ring.map, dev);
		dev_priv->ring.virtual_start = NULL;
		dev_priv->ring.map.handle = NULL;
		dev_priv->ring.map.size = 0;
	}

	/* Clear the HWS virtual address at teardown */
	if (I915_NEED_GFX_HWS(dev))
		i915_free_hws(dev);

	return 0;
}

static int i915_initialize(struct drm_device * dev, drm_i915_init_t * init)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	struct drm_i915_master_private *master_priv = dev->primary->master->driver_priv;

	master_priv->sarea = drm_getsarea(dev);
	if (master_priv->sarea) {
		master_priv->sarea_priv = (drm_i915_sarea_t *)
			((u8 *)master_priv->sarea->handle + init->sarea_priv_offset);
	} else {
		DRM_DEBUG_DRIVER("sarea not found assuming DRI2 userspace\n");
	}

	if (init->ring_size != 0) {
		if (dev_priv->ring.ring_obj != NULL) {
			i915_dma_cleanup(dev);
			DRM_ERROR("Client tried to initialize ringbuffer in "
				  "GEM mode\n");
			return -EINVAL;
		}

		dev_priv->ring.Size = init->ring_size;

		dev_priv->ring.map.offset = init->ring_start;
		dev_priv->ring.map.size = init->ring_size;
		dev_priv->ring.map.type = 0;
		dev_priv->ring.map.flags = 0;
		dev_priv->ring.map.mtrr = 0;

		drm_core_ioremap_wc(&dev_priv->ring.map, dev);

		if (dev_priv->ring.map.handle == NULL) {
			i915_dma_cleanup(dev);
			DRM_ERROR("can not ioremap virtual address for"
				  " ring buffer\n");
			return -ENOMEM;
		}
	}

	dev_priv->ring.virtual_start = dev_priv->ring.map.handle;

	dev_priv->cpp = init->cpp;
	dev_priv->back_offset = init->back_offset;
	dev_priv->front_offset = init->front_offset;
	dev_priv->current_page = 0;
	if (master_priv->sarea_priv)
		master_priv->sarea_priv->pf_current_page = 0;

	/* Allow hardware batchbuffers unless told otherwise.
	 */
	dev_priv->allow_batchbuffer = 1;

	return 0;
}

static int i915_dma_resume(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	DRM_DEBUG_DRIVER("%s\n", __func__);

	if (dev_priv->ring.map.handle == NULL) {
		DRM_ERROR("can not ioremap virtual address for"
			  " ring buffer\n");
		return -ENOMEM;
	}

	/* Program Hardware Status Page */
	if (!dev_priv->hw_status_page) {
		DRM_ERROR("Can not find hardware status page\n");
		return -EINVAL;
	}
	DRM_DEBUG_DRIVER("hw status page @ %p\n",
				dev_priv->hw_status_page);

	if (dev_priv->status_gfx_addr != 0)
		I915_WRITE(HWS_PGA, dev_priv->status_gfx_addr);
	else
		I915_WRITE(HWS_PGA, dev_priv->dma_status_page);
	DRM_DEBUG_DRIVER("Enabled hardware status page\n");

	return 0;
}

static int i915_dma_init(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	drm_i915_init_t *init = data;
	int retcode = 0;

	switch (init->func) {
	case I915_INIT_DMA:
		retcode = i915_initialize(dev, init);
		break;
	case I915_CLEANUP_DMA:
		retcode = i915_dma_cleanup(dev);
		break;
	case I915_RESUME_DMA:
		retcode = i915_dma_resume(dev);
		break;
	default:
		retcode = -EINVAL;
		break;
	}

	return retcode;
}

/* Implement basically the same security restrictions as hardware does
 * for MI_BATCH_NON_SECURE.  These can be made stricter at any time.
 *
 * Most of the calculations below involve calculating the size of a
 * particular instruction.  It's important to get the size right as
 * that tells us where the next instruction to check is.  Any illegal
 * instruction detected will be given a size of zero, which is a
 * signal to abort the rest of the buffer.
 */
static int do_validate_cmd(int cmd)
{
	switch (((cmd >> 29) & 0x7)) {
	case 0x0:
		switch ((cmd >> 23) & 0x3f) {
		case 0x0:
			return 1;	/* MI_NOOP */
		case 0x4:
			return 1;	/* MI_FLUSH */
		default:
			return 0;	/* disallow everything else */
		}
		break;
	case 0x1:
		return 0;	/* reserved */
	case 0x2:
		return (cmd & 0xff) + 2;	/* 2d commands */
	case 0x3:
		if (((cmd >> 24) & 0x1f) <= 0x18)
			return 1;

		switch ((cmd >> 24) & 0x1f) {
		case 0x1c:
			return 1;
		case 0x1d:
			switch ((cmd >> 16) & 0xff) {
			case 0x3:
				return (cmd & 0x1f) + 2;
			case 0x4:
				return (cmd & 0xf) + 2;
			default:
				return (cmd & 0xffff) + 2;
			}
		case 0x1e:
			if (cmd & (1 << 23))
				return (cmd & 0xffff) + 1;
			else
				return 1;
		case 0x1f:
			if ((cmd & (1 << 23)) == 0)	/* inline vertices */
				return (cmd & 0x1ffff) + 2;
			else if (cmd & (1 << 17))	/* indirect random */
				if ((cmd & 0xffff) == 0)
					return 0;	/* unknown length, too hard */
				else
					return (((cmd & 0xffff) + 1) / 2) + 1;
			else
				return 2;	/* indirect sequential */
		default:
			return 0;
		}
	default:
		return 0;
	}

	return 0;
}

static int validate_cmd(int cmd)
{
	int ret = do_validate_cmd(cmd);

/*	printk("validate_cmd( %x ): %d\n", cmd, ret); */

	return ret;
}

static int i915_emit_cmds(struct drm_device * dev, int *buffer, int dwords)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	int i;
	RING_LOCALS;

	if ((dwords+1) * sizeof(int) >= dev_priv->ring.Size - 8)
		return -EINVAL;

	BEGIN_LP_RING((dwords+1)&~1);

	for (i = 0; i < dwords;) {
		int cmd, sz;

		cmd = buffer[i];

		if ((sz = validate_cmd(cmd)) == 0 || i + sz > dwords)
			return -EINVAL;

		OUT_RING(cmd);

		while (++i, --sz) {
			OUT_RING(buffer[i]);
		}
	}

	if (dwords & 1)
		OUT_RING(0);

	ADVANCE_LP_RING();

	return 0;
}

int
i915_emit_box(struct drm_device *dev,
	      struct drm_clip_rect *boxes,
	      int i, int DR1, int DR4)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	struct drm_clip_rect box = boxes[i];
	RING_LOCALS;

	if (box.y2 <= box.y1 || box.x2 <= box.x1 || box.y2 <= 0 || box.x2 <= 0) {
		DRM_ERROR("Bad box %d,%d..%d,%d\n",
			  box.x1, box.y1, box.x2, box.y2);
		return -EINVAL;
	}

	if (IS_I965G(dev)) {
		BEGIN_LP_RING(4);
		OUT_RING(GFX_OP_DRAWRECT_INFO_I965);
		OUT_RING((box.x1 & 0xffff) | (box.y1 << 16));
		OUT_RING(((box.x2 - 1) & 0xffff) | ((box.y2 - 1) << 16));
		OUT_RING(DR4);
		ADVANCE_LP_RING();
	} else {
		BEGIN_LP_RING(6);
		OUT_RING(GFX_OP_DRAWRECT_INFO);
		OUT_RING(DR1);
		OUT_RING((box.x1 & 0xffff) | (box.y1 << 16));
		OUT_RING(((box.x2 - 1) & 0xffff) | ((box.y2 - 1) << 16));
		OUT_RING(DR4);
		OUT_RING(0);
		ADVANCE_LP_RING();
	}

	return 0;
}

/* XXX: Emitting the counter should really be moved to part of the IRQ
 * emit. For now, do it in both places:
 */

static void i915_emit_breadcrumb(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	struct drm_i915_master_private *master_priv = dev->primary->master->driver_priv;
	RING_LOCALS;

	dev_priv->counter++;
	if (dev_priv->counter > 0x7FFFFFFFUL)
		dev_priv->counter = 0;
	if (master_priv->sarea_priv)
		master_priv->sarea_priv->last_enqueue = dev_priv->counter;

	BEGIN_LP_RING(4);
	OUT_RING(MI_STORE_DWORD_INDEX);
	OUT_RING(I915_BREADCRUMB_INDEX << MI_STORE_DWORD_INDEX_SHIFT);
	OUT_RING(dev_priv->counter);
	OUT_RING(0);
	ADVANCE_LP_RING();
}

static int i915_dispatch_cmdbuffer(struct drm_device * dev,
				   drm_i915_cmdbuffer_t *cmd,
				   struct drm_clip_rect *cliprects,
				   void *cmdbuf)
{
	int nbox = cmd->num_cliprects;
	int i = 0, count, ret;

	if (cmd->sz & 0x3) {
		DRM_ERROR("alignment");
		return -EINVAL;
	}

	i915_kernel_lost_context(dev);

	count = nbox ? nbox : 1;

	for (i = 0; i < count; i++) {
		if (i < nbox) {
			ret = i915_emit_box(dev, cliprects, i,
					    cmd->DR1, cmd->DR4);
			if (ret)
				return ret;
		}

		ret = i915_emit_cmds(dev, cmdbuf, cmd->sz / 4);
		if (ret)
			return ret;
	}

	i915_emit_breadcrumb(dev);
	return 0;
}

static int i915_dispatch_batchbuffer(struct drm_device * dev,
				     drm_i915_batchbuffer_t * batch,
				     struct drm_clip_rect *cliprects)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	int nbox = batch->num_cliprects;
	int i = 0, count;
	RING_LOCALS;

	if ((batch->start | batch->used) & 0x7) {
		DRM_ERROR("alignment");
		return -EINVAL;
	}

	i915_kernel_lost_context(dev);

	count = nbox ? nbox : 1;

	for (i = 0; i < count; i++) {
		if (i < nbox) {
			int ret = i915_emit_box(dev, cliprects, i,
						batch->DR1, batch->DR4);
			if (ret)
				return ret;
		}

		if (!IS_I830(dev) && !IS_845G(dev)) {
			BEGIN_LP_RING(2);
			if (IS_I965G(dev)) {
				OUT_RING(MI_BATCH_BUFFER_START | (2 << 6) | MI_BATCH_NON_SECURE_I965);
				OUT_RING(batch->start);
			} else {
				OUT_RING(MI_BATCH_BUFFER_START | (2 << 6));
				OUT_RING(batch->start | MI_BATCH_NON_SECURE);
			}
			ADVANCE_LP_RING();
		} else {
			BEGIN_LP_RING(4);
			OUT_RING(MI_BATCH_BUFFER);
			OUT_RING(batch->start | MI_BATCH_NON_SECURE);
			OUT_RING(batch->start + batch->used - 4);
			OUT_RING(0);
			ADVANCE_LP_RING();
		}
	}

	i915_emit_breadcrumb(dev);

	return 0;
}

static int i915_dispatch_flip(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	struct drm_i915_master_private *master_priv =
		dev->primary->master->driver_priv;
	RING_LOCALS;

	if (!master_priv->sarea_priv)
		return -EINVAL;

	DRM_DEBUG_DRIVER("%s: page=%d pfCurrentPage=%d\n",
			  __func__,
			 dev_priv->current_page,
			 master_priv->sarea_priv->pf_current_page);

	i915_kernel_lost_context(dev);

	BEGIN_LP_RING(2);
	OUT_RING(MI_FLUSH | MI_READ_FLUSH);
	OUT_RING(0);
	ADVANCE_LP_RING();

	BEGIN_LP_RING(6);
	OUT_RING(CMD_OP_DISPLAYBUFFER_INFO | ASYNC_FLIP);
	OUT_RING(0);
	if (dev_priv->current_page == 0) {
		OUT_RING(dev_priv->back_offset);
		dev_priv->current_page = 1;
	} else {
		OUT_RING(dev_priv->front_offset);
		dev_priv->current_page = 0;
	}
	OUT_RING(0);
	ADVANCE_LP_RING();

	BEGIN_LP_RING(2);
	OUT_RING(MI_WAIT_FOR_EVENT | MI_WAIT_FOR_PLANE_A_FLIP);
	OUT_RING(0);
	ADVANCE_LP_RING();

	master_priv->sarea_priv->last_enqueue = dev_priv->counter++;

	BEGIN_LP_RING(4);
	OUT_RING(MI_STORE_DWORD_INDEX);
	OUT_RING(I915_BREADCRUMB_INDEX << MI_STORE_DWORD_INDEX_SHIFT);
	OUT_RING(dev_priv->counter);
	OUT_RING(0);
	ADVANCE_LP_RING();

	master_priv->sarea_priv->pf_current_page = dev_priv->current_page;
	return 0;
}

static int i915_quiescent(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;

	i915_kernel_lost_context(dev);
	return i915_wait_ring(dev, dev_priv->ring.Size - 8, __func__);
}

static int i915_flush_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *file_priv)
{
	int ret;

	RING_LOCK_TEST_WITH_RETURN(dev, file_priv);

	mutex_lock(&dev->struct_mutex);
	ret = i915_quiescent(dev);
	mutex_unlock(&dev->struct_mutex);

	return ret;
}

static int i915_batchbuffer(struct drm_device *dev, void *data,
			    struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	struct drm_i915_master_private *master_priv = dev->primary->master->driver_priv;
	drm_i915_sarea_t *sarea_priv = (drm_i915_sarea_t *)
	    master_priv->sarea_priv;
	drm_i915_batchbuffer_t *batch = data;
	int ret;
	struct drm_clip_rect *cliprects = NULL;

	if (!dev_priv->allow_batchbuffer) {
		DRM_ERROR("Batchbuffer ioctl disabled\n");
		return -EINVAL;
	}

	DRM_DEBUG_DRIVER("i915 batchbuffer, start %x used %d cliprects %d\n",
			batch->start, batch->used, batch->num_cliprects);

	RING_LOCK_TEST_WITH_RETURN(dev, file_priv);

	if (batch->num_cliprects < 0)
		return -EINVAL;

	if (batch->num_cliprects) {
		cliprects = malloc(batch->num_cliprects *
				    sizeof(struct drm_clip_rect),
				    DRM_MEM_DRAWABLE, M_WAITOK | M_ZERO);
		if (cliprects == NULL)
			return -ENOMEM;

		ret = copy_from_user(cliprects, batch->cliprects,
				     batch->num_cliprects *
				     sizeof(struct drm_clip_rect));
		if (ret != 0)
			goto fail_free;
	}

	mutex_lock(&dev->struct_mutex);
	ret = i915_dispatch_batchbuffer(dev, batch, cliprects);
	mutex_unlock(&dev->struct_mutex);

	if (sarea_priv)
		sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);

fail_free:
	free(cliprects, DRM_MEM_DRAWABLE);

	return ret;
}

static int i915_cmdbuffer(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	struct drm_i915_master_private *master_priv = dev->primary->master->driver_priv;
	drm_i915_sarea_t *sarea_priv = (drm_i915_sarea_t *)
	    master_priv->sarea_priv;
	drm_i915_cmdbuffer_t *cmdbuf = data;
	struct drm_clip_rect *cliprects = NULL;
	void *batch_data;
	int ret;

	DRM_DEBUG_DRIVER("i915 cmdbuffer, buf %p sz %d cliprects %d\n",
			cmdbuf->buf, cmdbuf->sz, cmdbuf->num_cliprects);

	RING_LOCK_TEST_WITH_RETURN(dev, file_priv);

	if (cmdbuf->num_cliprects < 0)
		return -EINVAL;

	batch_data = malloc(cmdbuf->sz, DRM_MEM_DRAWABLE, M_WAITOK);
	if (batch_data == NULL)
		return -ENOMEM;

	ret = copy_from_user(batch_data, cmdbuf->buf, cmdbuf->sz);
	if (ret != 0)
		goto fail_batch_free;

	if (cmdbuf->num_cliprects) {
		cliprects = malloc(cmdbuf->num_cliprects *
				   sizeof(struct drm_clip_rect),
				   DRM_MEM_DRAWABLE, M_WAITOK | M_ZERO);
		if (cliprects == NULL) {
			ret = -ENOMEM;
			goto fail_batch_free;
		}

		ret = copy_from_user(cliprects, cmdbuf->cliprects,
				     cmdbuf->num_cliprects *
				     sizeof(struct drm_clip_rect));
		if (ret != 0)
			goto fail_clip_free;
	}

	mutex_lock(&dev->struct_mutex);
	ret = i915_dispatch_cmdbuffer(dev, cmdbuf, cliprects, batch_data);
	mutex_unlock(&dev->struct_mutex);
	if (ret) {
		DRM_ERROR("i915_dispatch_cmdbuffer failed\n");
		goto fail_clip_free;
	}

	if (sarea_priv)
		sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);

fail_clip_free:
	free(cliprects, DRM_MEM_DRAWABLE);
fail_batch_free:
	free(batch_data, DRM_MEM_DRAWABLE);

	return ret;
}

static int i915_flip_bufs(struct drm_device *dev, void *data,
			  struct drm_file *file_priv)
{
	int ret;

	DRM_DEBUG_DRIVER("%s\n", __func__);

	RING_LOCK_TEST_WITH_RETURN(dev, file_priv);

	mutex_lock(&dev->struct_mutex);
	ret = i915_dispatch_flip(dev);
	mutex_unlock(&dev->struct_mutex);

	return ret;
}

static int i915_getparam(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_getparam_t *param = data;
	int value;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return -EINVAL;
	}

	switch (param->param) {
	case I915_PARAM_IRQ_ACTIVE:
#ifdef __linux__
		value = dev->pdev->irq ? 1 : 0;
#else
		value = dev->irq_enabled ? 1 : 0;
#endif
		break;
	case I915_PARAM_ALLOW_BATCHBUFFER:
		value = dev_priv->allow_batchbuffer ? 1 : 0;
		break;
	case I915_PARAM_LAST_DISPATCH:
		value = READ_BREADCRUMB(dev_priv);
		break;
	case I915_PARAM_CHIPSET_ID:
		value = dev->pci_device;
		break;
	case I915_PARAM_HAS_GEM:
#ifdef DRM_NEWER_IGEM
		value = dev_priv->has_gem;
#else
		/* We need to reset this to 1 once we have GEM */
		value = 0;
#endif
		break;
#ifdef DRM_NEWER_IGEM
	case I915_PARAM_NUM_FENCES_AVAIL:
		value = dev_priv->num_fence_regs - dev_priv->fence_reg_start;
		break;
	case I915_PARAM_HAS_OVERLAY:
		value = dev_priv->overlay ? 1 : 0;
		break;
	case I915_PARAM_HAS_PAGEFLIPPING:
		value = 1;
		break;
	case I915_PARAM_HAS_EXECBUF2:
		/* depends on GEM */
		value = dev_priv->has_gem;
		break;
#endif
	default:
		DRM_DEBUG_DRIVER("Unknown parameter %d\n",
				 param->param);
		return -EINVAL;
	}

	if (DRM_COPY_TO_USER(param->value, &value, sizeof(int))) {
		DRM_ERROR("DRM_COPY_TO_USER failed\n");
		return -EFAULT;
	}

	return 0;
}

static int i915_setparam(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_setparam_t *param = data;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return -EINVAL;
	}

	switch (param->param) {
	case I915_SETPARAM_USE_MI_BATCHBUFFER_START:
		break;
	case I915_SETPARAM_TEX_LRU_LOG_GRANULARITY:
		dev_priv->tex_lru_log_granularity = param->value;
		break;
	case I915_SETPARAM_ALLOW_BATCHBUFFER:
		dev_priv->allow_batchbuffer = param->value;
		break;
#ifdef DRM_NEWER_IGEM
	case I915_SETPARAM_NUM_USED_FENCES:
		if (param->value > dev_priv->num_fence_regs ||
		    param->value < 0)
			return -EINVAL;
		/* Userspace can use first N regs */
		dev_priv->fence_reg_start = param->value;
		break;
#endif
	default:
		DRM_DEBUG_DRIVER("unknown parameter %d\n",
					param->param);
		return -EINVAL;
	}

	return 0;
}

static int i915_set_status_page(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_hws_addr_t *hws = data;

	if (!I915_NEED_GFX_HWS(dev))
		return -EINVAL;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return -EINVAL;
	}

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		WARN(1, "tried to set status page when mode setting active\n");
		return 0;
	}

	DRM_DEBUG_DRIVER("set status page addr 0x%08x\n", (u32)hws->addr);

	dev_priv->status_gfx_addr = hws->addr & (0x1ffff<<12);

	dev_priv->hws_map.offset = dev->agp->base + hws->addr;
	dev_priv->hws_map.size = 4*1024;
	dev_priv->hws_map.type = 0;
	dev_priv->hws_map.flags = 0;
	dev_priv->hws_map.mtrr = 0;

	drm_core_ioremap_wc(&dev_priv->hws_map, dev);
	if (dev_priv->hws_map.handle == NULL) {
		i915_dma_cleanup(dev);
		dev_priv->status_gfx_addr = 0;
		DRM_ERROR("can not ioremap virtual address for"
				" G33 hw status page\n");
		return -ENOMEM;
	}
	dev_priv->hw_status_page = dev_priv->hws_map.handle;

	memset(dev_priv->hw_status_page, 0, PAGE_SIZE);
	I915_WRITE(HWS_PGA, dev_priv->status_gfx_addr);
	DRM_DEBUG_DRIVER("load hws HWS_PGA with gfx mem 0x%x\n",
				dev_priv->status_gfx_addr);
	DRM_DEBUG_DRIVER("load hws at %p\n",
				dev_priv->hw_status_page);
	return 0;
}

static int i915_get_bridge_dev(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

#ifdef __linux__
	dev_priv->bridge_dev = pci_get_bus_and_slot(0, PCI_DEVFN(0,0));
#else
	dev_priv->bridge_dev = drm_agp_find_bridge(dev);
#endif
	if (!dev_priv->bridge_dev) {
		DRM_ERROR("bridge device not found\n");
		return -1;
	}
	return 0;
}

#define MCHBAR_I915 0x44
#define MCHBAR_I965 0x48
#define MCHBAR_SIZE (4*4096)

#define DEVEN_REG 0x54
#define   DEVEN_MCHBAR_EN (1 << 28)

/* Allocate space for the MCH regs if needed, return nonzero on error */
static int
intel_alloc_mchbar_resource(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	int reg = IS_I965G(dev) ? MCHBAR_I965 : MCHBAR_I915;
	u32 temp_lo, temp_hi = 0;
	u64 mchbar_addr;
	int ret = 0;

	if (IS_I965G(dev))
		temp_hi = pci_read_config(dev_priv->bridge_dev, reg + 4, 4);
	temp_lo = pci_read_config(dev_priv->bridge_dev, reg, 4);
	mchbar_addr = ((u64)temp_hi << 32) | temp_lo;

#ifdef __linux__
	/* If ACPI doesn't have it, assume we need to allocate it ourselves */
#ifdef CONFIG_PNP
	if (mchbar_addr &&
	    pnp_range_reserved(mchbar_addr, mchbar_addr + MCHBAR_SIZE)) {
		ret = 0;
		goto out;
	}
#endif

	/* Get some space for it */
	ret = pci_bus_alloc_resource(dev_priv->bridge_dev->bus, &dev_priv->mch_res,
				     MCHBAR_SIZE, MCHBAR_SIZE,
				     PCIBIOS_MIN_MEM,
				     0,   pcibios_align_resource,
				     dev_priv->bridge_dev);
	if (ret) {
		DRM_DEBUG_DRIVER("failed bus alloc: %d\n", ret);
		dev_priv->mch_res.start = 0;
		goto out;
	}

	if (IS_I965G(dev))
		pci_write_config_dword(dev_priv->bridge_dev, reg + 4,
				       upper_32_bits(dev_priv->mch_res.start));

	pci_write_config_dword(dev_priv->bridge_dev, reg,
			       lower_32_bits(dev_priv->mch_res.start));
#else /* __linux__ */
	if (mchbar_addr) { /* assume acpi is working */
		DRM_INFO("registers returned MCHBAR address\n");
		ret = 0;
		goto out;
	}
#endif /* __linux__ */
out:
	return ret;
}

/* Setup MCHBAR if possible, return true if we should disable it again */
static void
intel_setup_mchbar(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	int mchbar_reg = IS_I965G(dev) ? MCHBAR_I965 : MCHBAR_I915;
	u32 temp;
	bool enabled;

	dev_priv->mchbar_need_disable = false;

	if (IS_I915G(dev) || IS_I915GM(dev)) {
		temp = pci_read_config(dev_priv->bridge_dev, DEVEN_REG, 4);
		enabled = !!(temp & DEVEN_MCHBAR_EN);
	} else {
		temp = pci_read_config(dev_priv->bridge_dev, mchbar_reg, 4);
		enabled = temp & 1;
	}

	/* If it's already enabled, don't have to do anything */
	if (enabled) {
		DRM_INFO("MCHBAR already enabled\n");
		return;
	}

	if (intel_alloc_mchbar_resource(dev))
		return;

#ifdef __linux__
	dev_priv->mchbar_need_disable = true;

	/* Space is allocated or reserved, so enable it. */
	if (IS_I915G(dev) || IS_I915GM(dev)) {
		pci_write_config_dword(dev_priv->bridge_dev, DEVEN_REG,
				       temp | DEVEN_MCHBAR_EN);
	} else {
		pci_read_config_dword(dev_priv->bridge_dev, mchbar_reg, &temp);
		pci_write_config_dword(dev_priv->bridge_dev, mchbar_reg, temp | 1);
	}
#endif /* __linux__ */
}

static void
intel_teardown_mchbar(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	int mchbar_reg = IS_I965G(dev) ? MCHBAR_I965 : MCHBAR_I915;
	u32 temp;

	if (dev_priv->mchbar_need_disable) {
		if (IS_I915G(dev) || IS_I915GM(dev)) {
			temp = pci_read_config(dev_priv->bridge_dev, DEVEN_REG, 4);
			temp &= ~DEVEN_MCHBAR_EN;
			pci_write_config(dev_priv->bridge_dev, DEVEN_REG, temp, 4);
		} else {
			temp = pci_read_config(dev_priv->bridge_dev, mchbar_reg, 4);
			temp &= ~1;
			pci_write_config(dev_priv->bridge_dev, mchbar_reg, temp, 4);
		}
	}
#ifdef __linux__
	if (dev_priv->mch_res.start)
		release_resource(&dev_priv->mch_res);
#endif /* __linux__ */
}

/**
 * i915_probe_agp - get AGP bootup configuration
 * @pdev: PCI device
 * @aperture_size: returns AGP aperture configured size
 * @preallocated_size: returns size of BIOS preallocated AGP space
 *
 * Since Intel integrated graphics are UMA, the BIOS has to set aside
 * some RAM for the framebuffer at early boot.  This code figures out
 * how much was set aside so we can use it for our own purposes.
 */
static int i915_probe_agp(struct drm_device *dev, uint32_t *aperture_size,
			  uint32_t *preallocated_size,
			  uint32_t *start)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	u16 tmp = 0;
	unsigned long overhead;
	unsigned long stolen;

	/* Get the fb aperture size and "stolen" memory amount. */
	tmp = (u16)pci_read_config(dev_priv->bridge_dev, INTEL_GMCH_CTRL, 2);

	*aperture_size = 1024 * 1024;
	*preallocated_size = 1024 * 1024;

	switch (dev->pci_device) {
/* pci_ids from http://pciids.sourceforge.net */
	case 0x3577 /* PCI_DEVICE_ID_INTEL_82830_CGC */:
	case 0x2562 /* PCI_DEVICE_ID_INTEL_82845G_IG */:
	case 0x3582 /* PCI_DEVICE_ID_INTEL_82855GM_IG */:
	case 0x2572 /* PCI_DEVICE_ID_INTEL_82865_IG */:
		if ((tmp & INTEL_GMCH_MEM_MASK) == INTEL_GMCH_MEM_64M)
			*aperture_size *= 64;
		else
			*aperture_size *= 128;
		break;
	default:
		/* 9xx supports large sizes, just look at the length */
		*aperture_size = (uint32_t)drm_get_resource_len(dev, 2);
		DRM_INFO("drm_get_resource(2) aperture_size = (%d)\n", *aperture_size);
		break;
	}

	/*
	 * Some of the preallocated space is taken by the GTT
	 * and popup.  GTT is 1K per MB of aperture size, and popup is 4K.
	 */
	if (IS_G4X(dev) || IS_PINEVIEW(dev) || IS_IRONLAKE(dev) || IS_GEN6(dev))
		overhead = 4096;
	else
		overhead = (*aperture_size / 1024) + 4096;

	if (IS_GEN6(dev)) {
		/* SNB has memory control reg at 0x50.w */
		tmp = pci_read_config(dev->device, SNB_GMCH_CTRL, 2);

		switch (tmp & SNB_GMCH_GMS_STOLEN_MASK) {
		case INTEL_855_GMCH_GMS_DISABLED:
			DRM_ERROR("video memory is disabled\n");
			return -1;
		case SNB_GMCH_GMS_STOLEN_32M:
			stolen = 32 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_64M:
			stolen = 64 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_96M:
			stolen = 96 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_128M:
			stolen = 128 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_160M:
			stolen = 160 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_192M:
			stolen = 192 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_224M:
			stolen = 224 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_256M:
			stolen = 256 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_288M:
			stolen = 288 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_320M:
			stolen = 320 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_352M:
			stolen = 352 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_384M:
			stolen = 384 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_416M:
			stolen = 416 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_448M:
			stolen = 448 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_480M:
			stolen = 480 * 1024 * 1024;
			break;
		case SNB_GMCH_GMS_STOLEN_512M:
			stolen = 512 * 1024 * 1024;
			break;
		default:
			DRM_ERROR("unexpected GMCH_GMS value: 0x%02x\n",
				  tmp & SNB_GMCH_GMS_STOLEN_MASK);
			return -1;
		}
	} else {
		switch (tmp & INTEL_GMCH_GMS_MASK) {
		case INTEL_855_GMCH_GMS_DISABLED:
			DRM_ERROR("video memory is disabled\n");
			return -1;
		case INTEL_855_GMCH_GMS_STOLEN_1M:
			stolen = 1 * 1024 * 1024;
			break;
		case INTEL_855_GMCH_GMS_STOLEN_4M:
			stolen = 4 * 1024 * 1024;
			break;
		case INTEL_855_GMCH_GMS_STOLEN_8M:
			stolen = 8 * 1024 * 1024;
			break;
		case INTEL_855_GMCH_GMS_STOLEN_16M:
			stolen = 16 * 1024 * 1024;
			break;
		case INTEL_855_GMCH_GMS_STOLEN_32M:
			stolen = 32 * 1024 * 1024;
			break;
		case INTEL_915G_GMCH_GMS_STOLEN_48M:
			stolen = 48 * 1024 * 1024;
			break;
		case INTEL_915G_GMCH_GMS_STOLEN_64M:
			stolen = 64 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_128M:
			stolen = 128 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_256M:
			stolen = 256 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_96M:
			stolen = 96 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_160M:
			stolen = 160 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_224M:
			stolen = 224 * 1024 * 1024;
			break;
		case INTEL_GMCH_GMS_STOLEN_352M:
			stolen = 352 * 1024 * 1024;
			break;
		default:
			DRM_ERROR("unexpected GMCH_GMS value: 0x%02x\n",
				  tmp & INTEL_GMCH_GMS_MASK);
			return -1;
		}
	}

	*preallocated_size = stolen - overhead;
	*start = overhead;
	DRM_INFO("preallocated_size = (%d)\n", *preallocated_size);
	DRM_INFO("start = (%d)\n", *start);

	return 0;
}

#define PTE_ADDRESS_MASK		0xfffff000
#define PTE_ADDRESS_MASK_HIGH		0x000000f0 /* i915+ */
#define PTE_MAPPING_TYPE_UNCACHED	(0 << 1)
#define PTE_MAPPING_TYPE_DCACHE		(1 << 1) /* i830 only */
#define PTE_MAPPING_TYPE_CACHED		(3 << 1)
#define PTE_MAPPING_TYPE_MASK		(3 << 1)
#define PTE_VALID			(1 << 0)

/**
 * i915_gtt_to_phys - take a GTT address and turn it into a physical one
 * @dev: drm device
 * @gtt_addr: address to translate
 *
 * Some chip functions require allocations from stolen space but need the
 * physical address of the memory in question.  We use this routine
 * to get a physical address suitable for register programming from a given
 * GTT address.
 */
static unsigned long i915_gtt_to_phys(struct drm_device *dev,
				      unsigned long gtt_addr)
{
	unsigned long *gtt;
	unsigned long entry, phys;
	int gtt_bar = IS_I9XX(dev) ? 0 : 1;
	int gtt_offset, gtt_size;

	if (IS_I965G(dev)) {
		if (IS_G4X(dev) || IS_IRONLAKE(dev) || IS_GEN6(dev)) {
			gtt_offset = 2*1024*1024;
			gtt_size = 2*1024*1024;
		} else {
			gtt_offset = 512*1024;
			gtt_size = 512*1024;
		}
	} else {
		gtt_bar = 3;
		gtt_offset = 0;
#ifdef __linux__
		gtt_size = pci_resource_len(dev->pdev, gtt_bar);
#else
		gtt_size = drm_get_resource_len(dev, gtt_bar);
#endif
	}
#ifndef __linux__ /* legacy change porting debug */
	DRM_INFO("i915_gtt_to_phys gtt_size = (%d)\n", gtt_size);
#endif

#ifdef __linux__
	gtt = ioremap_wc(pci_resource_start(dev->pdev, gtt_bar) + gtt_offset,
			 gtt_size);
#else
	gtt = ioremap_wc(drm_get_resource_start(dev, gtt_bar) + gtt_offset,
			 gtt_size);
#endif
	if (!gtt) {
		DRM_ERROR("ioremap of GTT failed\n");
		return 0;
	}

	entry = *(volatile u32 *)(gtt + (gtt_addr / 1024));

	DRM_DEBUG_DRIVER("GTT addr: 0x%08lx, PTE: 0x%08lx\n", gtt_addr, entry);

	/* Mask out these reserved bits on this hardware. */
	if (!IS_I9XX(dev) || IS_I915G(dev) || IS_I915GM(dev) ||
	    IS_I945G(dev) || IS_I945GM(dev)) {
		entry &= ~PTE_ADDRESS_MASK_HIGH;
	}

	/* If it's not a mapping type we know, then bail. */
	if ((entry & PTE_MAPPING_TYPE_MASK) != PTE_MAPPING_TYPE_UNCACHED &&
	    (entry & PTE_MAPPING_TYPE_MASK) != PTE_MAPPING_TYPE_CACHED)	{
#ifdef __linux__
		iounmap(gtt);
#else
		ioremapfree(gtt, gtt_size);
#endif
		return 0;
	}

	if (!(entry & PTE_VALID)) {
		DRM_ERROR("bad GTT entry in stolen space\n");
#ifdef __linux__
		iounmap(gtt);
#else
		ioremapfree(gtt, gtt_size);
#endif
		return 0;
	}

#ifdef __linux__
	iounmap(gtt);
#else
	ioremapfree(gtt, gtt_size);
#endif

	phys =(entry & PTE_ADDRESS_MASK) |
		((uint64_t)(entry & PTE_ADDRESS_MASK_HIGH) << (32 - 4));

#ifdef __linux__
	DRM_DEBUG_DRIVER("GTT addr: 0x%08lx, phys addr: 0x%08lx\n", gtt_addr, phys);
#else /* legacy change debug */
	DRM_INFO("GTT addr: 0x%08lx, phys addr: 0x%08lx\n", gtt_addr, phys);
#endif

	return phys;
}

static void i915_warn_stolen(struct drm_device *dev)
{
	DRM_ERROR("not enough stolen space for compressed buffer, disabling\n");
	DRM_ERROR("hint: you may be able to increase stolen memory size in the BIOS to avoid this\n");
}

static void i915_setup_compression(struct drm_device *dev, int size)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct drm_mm_node *compressed_fb, *compressed_llb;
	unsigned long cfb_base;
	unsigned long ll_base = 0;

	/* Leave 1M for line length buffer & misc. */
	compressed_fb = drm_mm_search_free(&dev_priv->vram, size, 4096, 0);
	if (!compressed_fb) {
		dev_priv->no_fbc_reason = FBC_STOLEN_TOO_SMALL;
		i915_warn_stolen(dev);
		return;
	}

	compressed_fb = drm_mm_get_block(compressed_fb, size, 4096);
	if (!compressed_fb) {
		i915_warn_stolen(dev);
		dev_priv->no_fbc_reason = FBC_STOLEN_TOO_SMALL;
		return;
	}

	cfb_base = i915_gtt_to_phys(dev, compressed_fb->start);
	if (!cfb_base) {
		DRM_ERROR("failed to get stolen phys addr, disabling FBC\n");
		drm_mm_put_block(compressed_fb);
	}

	if (!IS_GM45(dev)) {
		compressed_llb = drm_mm_search_free(&dev_priv->vram, 4096,
						    4096, 0);
		if (!compressed_llb) {
			i915_warn_stolen(dev);
			return;
		}

		compressed_llb = drm_mm_get_block(compressed_llb, 4096, 4096);
		if (!compressed_llb) {
			i915_warn_stolen(dev);
			return;
		}

		ll_base = i915_gtt_to_phys(dev, compressed_llb->start);
		if (!ll_base) {
			DRM_ERROR("failed to get stolen phys addr, disabling FBC\n");
			drm_mm_put_block(compressed_fb);
			drm_mm_put_block(compressed_llb);
		}
	}

	dev_priv->cfb_size = size;

	dev_priv->compressed_fb = compressed_fb;

	if (IS_GM45(dev)) {
		g4x_disable_fbc(dev);
		I915_WRITE(DPFC_CB_BASE, compressed_fb->start);
	} else {
		i8xx_disable_fbc(dev);
		I915_WRITE(FBC_CFB_BASE, cfb_base);
		I915_WRITE(FBC_LL_BASE, ll_base);
		dev_priv->compressed_llb = compressed_llb;
	}

	DRM_DEBUG("FBC base 0x%08lx, ll base 0x%08lx, size %dM\n", cfb_base,
		  ll_base, size >> 20);
}

static void i915_cleanup_compression(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

	drm_mm_put_block(dev_priv->compressed_fb);
	if (!IS_GM45(dev))
		drm_mm_put_block(dev_priv->compressed_llb);
}

/* true = enable decode, false = disable decoder */
static unsigned int i915_vga_set_decode(void *cookie, bool state)
{
#ifdef __linux__
	struct drm_device *dev = cookie;

	intel_modeset_vga_set_state(dev, state);
	if (state)
		return VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM |
		       VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
	else
		return VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
#else
	return false;
#endif /* __linux__ */
}

#ifdef __linux__
static void i915_switcheroo_set_state(struct pci_dev *pdev, enum vga_switcheroo_state state)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	pm_message_t pmm = { .event = PM_EVENT_SUSPEND };
	if (state == VGA_SWITCHEROO_ON) {
		printk(KERN_INFO "i915: switched off\n");
		/* i915 resume handler doesn't set to D0 */
		pci_set_power_state(dev->pdev, PCI_D0);
		i915_resume(dev);
	} else {
		printk(KERN_ERR "i915: switched off\n");
		i915_suspend(dev, pmm);
	}
}
#endif /* __linux__ */

static bool i915_switcheroo_can_switch(struct pci_dev *pdev)
{
#ifdef __linux__
	struct drm_device *dev = pci_get_drvdata(pdev);
	bool can_switch;

	spin_lock(&dev->count_lock);
	can_switch = (dev->open_count == 0);
	spin_unlock(&dev->count_lock);
	return can_switch;
#else
	return 0;
#endif
}

static int i915_load_modeset_init(struct drm_device *dev,
				  unsigned long prealloc_start,
				  unsigned long prealloc_size,
				  unsigned long agp_size)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	int fb_bar = IS_I9XX(dev) ? 2 : 0;
	int ret = 0;

	dev->mode_config.fb_base = drm_get_resource_start(dev, fb_bar) &
		0xff000000;

	/* Basic memrange allocator for stolen space (aka vram) */
	drm_mm_init(&dev_priv->vram, 0, prealloc_size);
	DRM_INFO("set up %ldM of stolen space\n", prealloc_size / (1024*1024));

	/* We're off and running w/KMS */
	dev_priv->mm.suspended = 0;

	/* Let GEM Manage from end of prealloc space to end of aperture.
	 *
	 * However, leave one page at the end still bound to the scratch page.
	 * There are a number of places where the hardware apparently
	 * prefetches past the end of the object, and we've seen multiple
	 * hangs with the GPU head pointer stuck in a batchbuffer bound
	 * at the last page of the aperture.  One page should be enough to
	 * keep any prefetching inside of the aperture.
	 */
	i915_gem_do_init(dev, prealloc_size, agp_size - 4096);

	mutex_lock(&dev->struct_mutex);
	ret = i915_gem_init_ringbuffer(dev);
	mutex_unlock(&dev->struct_mutex);
	if (ret)
		goto out;

	/* Try to set up FBC with a reasonable compressed buffer size */
	if (I915_HAS_FBC(dev) && i915_powersave) {
		int cfb_size;

		/* Try to get an 8M buffer... */
		if (prealloc_size > (9*1024*1024))
			cfb_size = 8*1024*1024;
		else /* fall back to 7/8 of the stolen space */
			cfb_size = prealloc_size * 7 / 8;
		i915_setup_compression(dev, cfb_size);
	}

	/* Allow hardware batchbuffers unless told otherwise.
	 */
	dev_priv->allow_batchbuffer = 1;

	ret = intel_init_bios(dev);
	if (ret)
		DRM_INFO("failed to find VBIOS tables\n");

#ifdef __linux__
	/* if we have > 1 VGA cards, then disable the radeon VGA resources */
	ret = vga_client_register(dev->pdev, dev, NULL, i915_vga_set_decode);
	if (ret)
		goto destroy_ringbuffer;

	ret = vga_switcheroo_register_client(dev->pdev,
					     i915_switcheroo_set_state,
					     i915_switcheroo_can_switch);
#endif /* __linux__ */

	if (ret)
		goto destroy_ringbuffer;

	/* IIR "flip pending" bit means done if this bit is set */
	if (IS_GEN3(dev) && (I915_READ(ECOSKPD) & ECO_FLIP_DONE))
		dev_priv->flip_pending_is_done = true;

	intel_modeset_init(dev);

	ret = drm_irq_install(dev);
	if (ret)
		goto destroy_ringbuffer;

	/* Always safe in the mode setting case. */
	/* FIXME: do pre/post-mode set stuff in core KMS code */
	dev->vblank_disable_allowed = 1;

	/*
	 * Initialize the hardware status page IRQ location.
	 */

	I915_WRITE(INSTPM, (1 << 5) | (1 << 21));

	drm_helper_initial_config(dev);

	return 0;

destroy_ringbuffer:
	mutex_lock(&dev->struct_mutex);
	i915_gem_cleanup_ringbuffer(dev);
	mutex_unlock(&dev->struct_mutex);
out:
	return ret;
}

int i915_master_create(struct drm_device *dev, struct drm_master *master)
{
	struct drm_i915_master_private *master_priv;

	master_priv = malloc(sizeof(*master_priv), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (!master_priv)
		return -ENOMEM;

	master->driver_priv = master_priv;
	return 0;
}

void i915_master_destroy(struct drm_device *dev, struct drm_master *master)
{
	struct drm_i915_master_private *master_priv = master->driver_priv;

	if (!master_priv)
		return;

	free(master_priv, DRM_MEM_DRIVER);

	master->driver_priv = NULL;
}

static void i915_get_mem_freq(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	u32 tmp;

	if (!IS_PINEVIEW(dev))
		return;

	tmp = I915_READ(CLKCFG);

	switch (tmp & CLKCFG_FSB_MASK) {
	case CLKCFG_FSB_533:
		dev_priv->fsb_freq = 533; /* 133*4 */
		break;
	case CLKCFG_FSB_800:
		dev_priv->fsb_freq = 800; /* 200*4 */
		break;
	case CLKCFG_FSB_667:
		dev_priv->fsb_freq =  667; /* 167*4 */
		break;
	case CLKCFG_FSB_400:
		dev_priv->fsb_freq = 400; /* 100*4 */
		break;
	}

	switch (tmp & CLKCFG_MEM_MASK) {
	case CLKCFG_MEM_533:
		dev_priv->mem_freq = 533;
		break;
	case CLKCFG_MEM_667:
		dev_priv->mem_freq = 667;
		break;
	case CLKCFG_MEM_800:
		dev_priv->mem_freq = 800;
		break;
	}
}

/**
 * i915_driver_load - setup chip and create an initial config
 * @dev: DRM device
 * @flags: startup flags
 *
 * The driver load routine has to do several things:
 *   - drive output discovery via intel_modeset_init()
 *   - initialize the memory manager
 *   - allocate initial config memory
 *   - setup the DRM framebuffer with the allocated memory
 */
int i915_driver_load(struct drm_device *dev, unsigned long flags)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	resource_size_t base, size;
	int ret = 0, mmio_bar;
	uint32_t agp_size, prealloc_size, prealloc_start;

	/* i915 has 4 more counters */
	dev->counters += 4;
	dev->types[6] = _DRM_STAT_IRQ;
	dev->types[7] = _DRM_STAT_PRIMARY;
	dev->types[8] = _DRM_STAT_SECONDARY;
	dev->types[9] = _DRM_STAT_DMA;

	dev_priv = malloc(sizeof(drm_i915_private_t), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	if (dev_priv == NULL)
		return -ENOMEM;

	dev->dev_private = (void *)dev_priv;
	dev_priv->dev = dev;
#ifdef DRM_NEWER_PCIID
	dev_priv->info = (struct intel_device_info *) flags;
#endif /* DRM_NEWER_PCIID */

	/* Add register map (needed for suspend/resume) */
	mmio_bar = IS_I9XX(dev) ? 0 : 1;
	base = drm_get_resource_start(dev, mmio_bar);
	size = drm_get_resource_len(dev, mmio_bar);

	if (i915_get_bridge_dev(dev)) {
#ifdef DRM_NEWER_REGMAP
		DRM_ERROR("failed i915_get_bridge_dev\n");
		ret = -EIO;
		goto free_priv;
#else
		DRM_ERROR("failed i915_get_bridge_dev\n");
#endif
	}

#ifdef DRM_NEWER_REGMAP 
	dev_priv->regs_size = size;
	dev_priv->regs = ioremap(base, size);
	if (!dev_priv->regs) {
		DRM_ERROR("failed to map registers\n");
		ret = -EIO;
		goto put_bridge;
	}
#else
	ret = drm_addmap(dev, base, size, _DRM_REGISTERS,
	    _DRM_KERNEL | _DRM_DRIVER, &dev_priv->mmio_map);
	if (ret) {
		DRM_ERROR("failed to map registers\n");
	}
#endif

        dev_priv->mm.gtt_mapping =
		io_mapping_create_wc(dev->agp->base,
				     dev->agp->agp_info.aper_size * 1024*1024);
	if (dev_priv->mm.gtt_mapping == NULL) {
#ifdef DRM_NEWER_REGMAP
		DRM_ERROR("io_mapping_create_wc mm.gtt_mapping NULL\n");
		ret = -EIO;
		goto out_rmmap;
#else
		DRM_ERROR("io_mapping_create_wc mm.gtt_mapping NULL\n");
#endif
	}

#ifdef __linux__ /* UNIMPLEMENTED */
	/* Set up a WC MTRR for non-PAT systems.  This is more common than
	 * one would think, because the kernel disables PAT on first
	 * generation Core chips because WC PAT gets overridden by a UC
	 * MTRR if present.  Even if a UC MTRR isn't present.
	 */
	dev_priv->mm.gtt_mtrr = mtrr_add(dev->agp->base,
					 dev->agp->agp_info.aper_size *
					 1024 * 1024,
					 MTRR_TYPE_WRCOMB, 1);
	if (dev_priv->mm.gtt_mtrr < 0) {
		DRM_INFO("MTRR allocation failed.  Graphics "
			 "performance may suffer.\n");
	}
#endif /* __linux__ */

	ret = i915_probe_agp(dev, &agp_size, &prealloc_size, &prealloc_start);
	if (ret)
#ifdef DRM_NEWER_REGMAP
		DRM_ERROR("i915_probe_agp failed\n");
		goto out_iomapfree;
#else
		DRM_ERROR("i915_probe_agp failed\n");
#endif

#ifdef __linux__ /* UNIMPLEMENTED */
	dev_priv->wq = create_singlethread_workqueue("i915");
	if (dev_priv->wq == NULL) {
		DRM_ERROR("Failed to create our workqueue.\n");
		ret = -ENOMEM;
		goto out_iomapfree;
	}
#else
	dev_priv->wq_legacy = taskqueue_create("i915", M_WAITOK,
		taskqueue_thread_enqueue, &dev_priv->wq_legacy);
#endif /* __linux__ */

	/* enable GEM by default */
#ifdef __linux__ /* UNIMPLEMENTED */
	dev_priv->has_gem = 1;
#else
	dev_priv->has_gem = 0;
#endif /* __linux__ */

	if (prealloc_size > agp_size * 3 / 4) {
		DRM_ERROR("Detected broken video BIOS with %d/%dkB of video "
			  "memory stolen.\n",
			  prealloc_size / 1024, agp_size / 1024);
		DRM_ERROR("Disabling GEM. (try reducing stolen memory or "
			  "updating the BIOS to fix).\n");
		dev_priv->has_gem = 0;
	}

	dev->driver->get_vblank_counter = i915_get_vblank_counter;
	dev->max_vblank_count = 0xffffff; /* only 24 bits of frame count */
	if (IS_G4X(dev) || IS_IRONLAKE(dev) || IS_GEN6(dev)) {
		dev->max_vblank_count = 0xffffffff; /* full 32 bit counter */
		dev->driver->get_vblank_counter = gm45_get_vblank_counter;
	}

#ifdef __linux__ /* UNIMPLEMENTED */
	/* Try to make sure MCHBAR is enabled before poking at it */
	intel_setup_mchbar(dev);
#endif /* __linux__ */

#ifdef DRM_NEWER_IGEM
	i915_gem_load(dev);
#endif
	/* Init HWS */
	if (!I915_NEED_GFX_HWS(dev)) {
		ret = i915_init_phys_hws(dev);
		if (ret != 0) {
#ifdef __linux__
			goto out_workqueue_free;
#else
#ifdef DRM_NEWER_REGMAP
			goto out_workqueue_free;
#else
			drm_free(dev_priv, sizeof(struct drm_i915_private),
			    DRM_MEM_DRIVER);
			return ret;
#endif
#endif
		}
	}

	i915_get_mem_freq(dev);

#ifdef __linux__ /* UNIMPLEMENTED */
	/* On the 945G/GM, the chipset reports the MSI capability on the
	 * integrated graphics even though the support isn't actually there
	 * according to the published specs.  It doesn't appear to function
	 * correctly in testing on 945G.
	 * This may be a side effect of MSI having been made available for PEG
	 * and the registers being closely associated.
	 *
	 * According to chipset errata, on the 965GM, MSI interrupts may
	 * be lost or delayed, but we use them anyways to avoid
	 * stuck interrupts on some machines.
	 */
	if (!IS_I945G(dev) && !IS_I945GM(dev))
		pci_enable_msi(dev->pdev);
#endif

	spin_lock_init(&dev_priv->user_irq_lock);
	spin_lock_init(&dev_priv->error_lock);
	dev_priv->user_irq_refcount = 0;
	dev_priv->trace_irq_seqno = 0;

	ret = drm_vblank_init(dev, I915_NUM_PIPE);

	if (ret) {
		(void) i915_driver_unload(dev);
		return ret;
	}

#ifdef __linux__ /* UNIMPLEMENTED */
	/* Start out suspended */
	dev_priv->mm.suspended = 1;

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		ret = i915_load_modeset_init(dev, prealloc_start,
					     prealloc_size, agp_size);
		if (ret < 0) {
			DRM_ERROR("failed to init modeset\n");
			goto out_workqueue_free;
		}
	}

	/* Must be done after probing outputs */
	intel_opregion_init(dev, 0);
#endif

#ifdef __linux__
	setup_timer(&dev_priv->hangcheck_timer, i915_hangcheck_elapsed,
		    (unsigned long) dev);
#else
	callout_init(&dev_priv->hangcheck_timer);
#endif

#ifdef __linux__
	return 0;

out_workqueue_free:
	destroy_workqueue(dev_priv->wq);
out_iomapfree:
	io_mapping_free(dev_priv->mm.gtt_mapping);
out_rmmap:
	iounmap(dev_priv->regs);
put_bridge:
	pci_dev_put(dev_priv->bridge_dev);
free_priv:
	kfree(dev_priv);
#else /* !__linux__ */
#ifdef DRM_NEWER_REGMAP
	return 0;
out_workqueue_free:
	;
out_iomapfree:
	drm_io_mapping_free(dev->agp->base,
			    dev->agp->agp_info.aper_size * 1024*1024);
out_rmmap:
	pmap_unmapdev((vm_offset_t)dev_priv->regs, dev_priv->regs_size);
put_bridge:
	;
free_priv:
	free(dev_priv, DRM_MEM_DRIVER);
#endif /* DRM_NEWER_REGMAP */
	return ret;
#endif /* !__linux__ */
}

int i915_driver_unload(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;

#ifdef __linux__
	i915_destroy_error_state(dev);
#endif

#ifdef __linux__
	destroy_workqueue(dev_priv->wq);
	del_timer_sync(&dev_priv->hangcheck_timer);
#else
	taskqueue_free(dev_priv->wq_legacy);
#endif

#ifdef __linux__
	io_mapping_free(dev_priv->mm.gtt_mapping);
#else
	drm_io_mapping_free(dev_priv->mm.gtt_mapping,
		dev->agp->agp_info.aper_size * 1024*1024);
#endif

#ifdef __linux__
	if (dev_priv->mm.gtt_mtrr >= 0) {
		mtrr_del(dev_priv->mm.gtt_mtrr, dev->agp->base,
			 dev->agp->agp_info.aper_size * 1024 * 1024);
		dev_priv->mm.gtt_mtrr = -1;
	}

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		/*
		 * free the memory space allocated for the child device
		 * config parsed from VBT
		 */
		if (dev_priv->child_dev && dev_priv->child_dev_num) {
			kfree(dev_priv->child_dev);
			dev_priv->child_dev = NULL;
			dev_priv->child_dev_num = 0;
		}
		drm_irq_uninstall(dev);
		vga_switcheroo_unregister_client(dev->pdev);
		vga_client_register(dev->pdev, NULL, NULL, NULL);
	}

	if (dev->pdev->msi_enabled)
		pci_disable_msi(dev->pdev);
#endif /* __linux__ */

#ifdef DRM_NEWER_REGMAP
	if (dev_priv->regs != NULL)
#ifdef __linux__
		iounmap(dev_priv->regs);
#else
		pmap_unmapdev((vm_offset_t)dev_priv->regs, dev_priv->regs_size);
#endif
#else /* !__DRM_NEWER_REGMAP */
	drm_rmmap(dev, dev_priv->mmio_map);
#endif /* !DRM_NEWER_REGMAP */

#ifdef __linux__
	intel_opregion_free(dev, 0);

	if (drm_core_check_feature(dev, DRIVER_MODESET)) {
		intel_modeset_cleanup(dev);

		i915_gem_free_all_phys_object(dev);

		mutex_lock(&dev->struct_mutex);
		i915_gem_cleanup_ringbuffer(dev);
		mutex_unlock(&dev->struct_mutex);
		if (I915_HAS_FBC(dev) && i915_powersave)
			i915_cleanup_compression(dev);
		drm_mm_takedown(&dev_priv->vram);
		i915_gem_lastclose(dev);

		intel_cleanup_overlay(dev);
	}

	intel_teardown_mchbar(dev);

	pci_dev_put(dev_priv->bridge_dev);
#endif /* __linux__ */

#ifdef __linux__
	kfree(dev->dev_private);
#else
	DRM_SPINUNINIT(&dev_priv->user_irq_lock);

	drm_free(dev->dev_private, sizeof(drm_i915_private_t),
		 DRM_MEM_DRIVER);
#endif /* __linux__ */

	return 0;
}

int i915_driver_open(struct drm_device *dev, struct drm_file *file_priv)
{
	struct drm_i915_file_private *i915_file_priv;

	DRM_DEBUG_DRIVER("\n");
	i915_file_priv = (struct drm_i915_file_private *)
	    drm_alloc(sizeof(*i915_file_priv), DRM_MEM_FILES);

	if (!i915_file_priv)
		return -ENOMEM;

	file_priv->driver_priv = i915_file_priv;

	INIT_LIST_HEAD(&i915_file_priv->mm.request_list);

#ifndef __linux__ /* legacy change debug */
	DRM_INFO("i915_driver_open initialized mm.request_list as empty list\n");
#endif /* !__linux__ */

	return 0;
}

/**
 * i915_driver_lastclose - clean up after all DRM clients have exited
 * @dev: DRM device
 *
 * Take care of cleaning up after all DRM clients have exited.  In the
 * mode setting case, we want to restore the kernel's initial mode (just
 * in case the last client left us in a bad state).
 *
 * Additionally, in the non-mode setting case, we'll tear down the AGP
 * and DMA structures, since the kernel won't be using them, and clea
 * up any GEM state.
 */
void i915_driver_lastclose(struct drm_device * dev)
{
	drm_i915_private_t *dev_priv = dev->dev_private;

#ifdef __linux__
	if (!dev_priv || drm_core_check_feature(dev, DRIVER_MODESET)) {
		drm_fb_helper_restore();
		vga_switcheroo_process_delayed_switch();
		return;
	}
#else
	if (!dev_priv)
		return;
#endif

#ifdef DRM_NEWER_IGEM
	i915_gem_lastclose(dev);
#endif
	if (dev_priv->agp_heap)
		i915_mem_takedown(&(dev_priv->agp_heap));

	i915_dma_cleanup(dev);
}

void i915_driver_preclose(struct drm_device * dev, struct drm_file *file_priv)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
#ifdef DRM_NEWER_IGEM
	i915_gem_release(dev, file_priv);
#endif
	if (!drm_core_check_feature(dev, DRIVER_MODESET))
		i915_mem_release(dev, file_priv, dev_priv->agp_heap);
}

void i915_driver_postclose(struct drm_device *dev, struct drm_file *file_priv)
{
	struct drm_i915_file_private *i915_file_priv = file_priv->driver_priv;

	drm_free(i915_file_priv, sizeof(*i915_file_priv), DRM_MEM_FILES);
}

struct drm_ioctl_desc i915_ioctls[] = {
	DRM_IOCTL_DEF(DRM_I915_INIT, i915_dma_init, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_I915_FLUSH, i915_flush_ioctl, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_FLIP, i915_flip_bufs, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_BATCHBUFFER, i915_batchbuffer, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_IRQ_EMIT, i915_irq_emit, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_IRQ_WAIT, i915_irq_wait, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_GETPARAM, i915_getparam, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_SETPARAM, i915_setparam, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_I915_ALLOC, i915_mem_alloc, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_FREE, i915_mem_free, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_INIT_HEAP, i915_mem_init_heap, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF(DRM_I915_CMDBUFFER, i915_cmdbuffer, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_DESTROY_HEAP,  i915_mem_destroy_heap, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY ),
	DRM_IOCTL_DEF(DRM_I915_SET_VBLANK_PIPE,  i915_vblank_pipe_set, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY ),
	DRM_IOCTL_DEF(DRM_I915_GET_VBLANK_PIPE,  i915_vblank_pipe_get, DRM_AUTH ),
	DRM_IOCTL_DEF(DRM_I915_VBLANK_SWAP, i915_vblank_swap, DRM_AUTH),
	DRM_IOCTL_DEF(DRM_I915_HWS_ADDR, i915_set_status_page, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
#ifdef DRM_NEWER_IGEM
	DRM_IOCTL_DEF(DRM_I915_GEM_INIT, i915_gem_init_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_EXECBUFFER, i915_gem_execbuffer, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_EXECBUFFER2, i915_gem_execbuffer2, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_PIN, i915_gem_pin_ioctl, DRM_AUTH|DRM_ROOT_ONLY|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_UNPIN, i915_gem_unpin_ioctl, DRM_AUTH|DRM_ROOT_ONLY|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_BUSY, i915_gem_busy_ioctl, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_THROTTLE, i915_gem_throttle_ioctl, DRM_AUTH|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_ENTERVT, i915_gem_entervt_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_LEAVEVT, i915_gem_leavevt_ioctl, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_CREATE, i915_gem_create_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_PREAD, i915_gem_pread_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_PWRITE, i915_gem_pwrite_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_MMAP, i915_gem_mmap_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_MMAP_GTT, i915_gem_mmap_gtt_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_SET_DOMAIN, i915_gem_set_domain_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_SW_FINISH, i915_gem_sw_finish_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_SET_TILING, i915_gem_set_tiling, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_GET_TILING, i915_gem_get_tiling, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_GET_APERTURE, i915_gem_get_aperture_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GET_PIPE_FROM_CRTC_ID, intel_get_pipe_from_crtc_id, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_GEM_MADVISE, i915_gem_madvise_ioctl, DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_OVERLAY_PUT_IMAGE, intel_overlay_put_image, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
	DRM_IOCTL_DEF(DRM_I915_OVERLAY_ATTRS, intel_overlay_attrs, DRM_MASTER|DRM_CONTROL_ALLOW|DRM_UNLOCKED),
#endif
};

int i915_max_ioctl = DRM_ARRAY_SIZE(i915_ioctls);

/**
 * Determine if the device really is AGP or not.
 *
 * All Intel graphics chipsets are treated as AGP, even if they are really
 * PCI-e.
 *
 * \param dev   The device to be tested.
 *
 * \returns
 * A value of 1 is always retured to indictate every i9x5 is AGP.
 */
int i915_driver_device_is_agp(struct drm_device * dev)
{
	return 1;
}
