/*
 * Copyright David Shao 
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    David Shao <davshao@gmail.com>
 *
 */

#include "drmP.h"
#include "drm.h"
#include "i915_drm.h"
#include "i915_drv.h"

#include "intel_drv.h"

static __inline__ void
trace_i915_ring_wait_begin(struct drm_device *dev) {
	;
}

static __inline__ void
trace_i915_ring_wait_end(struct drm_device *dev) {
	;
}

static __inline__ void
trace_i915_gem_object_change_domain(
	struct drm_gem_object *obj,
	uint32_t read_domains,
	uint32_t write_domain
) {
	;
}

static __inline__ void
trace_i915_gem_request_retire(
	struct drm_device *dev,
	uint32_t seqno
) {
	;
}

static __inline__ void
trace_i915_gem_request_wait_begin(
	struct drm_device *dev,
	uint32_t seqno
) {
	;
}

static __inline__ void
trace_i915_gem_request_wait_end(
	struct drm_device *dev,
	uint32_t seqno
) {
	;
}

static __inline__ void
trace_i915_gem_request_flush(
	struct drm_device *dev,
	uint32_t seqno,
	uint32_t invalidate_domains,
	uint32_t flush_domains
) {
	;
}

static __inline__ void
trace_i915_gem_object_bind(
	struct drm_gem_object *obj,
	uint32_t gtt_offset
) {
	;
}

static __inline__ void
trace_i915_gem_object_unbind(
	struct drm_gem_object *obj
) {
	;
}

static __inline__ void
trace_i915_gem_object_get_fence(
	struct drm_gem_object *obj,
	int fence_reg,
	uint32_t tiling_mode
) {
	;
}

static __inline__ void
trace_i915_gem_object_clflush(
	struct drm_gem_object *obj
) {
	;
}

static __inline__ void
trace_i915_gem_request_submit(
	struct drm_device *dev,
	uint32_t seqno
) {
	;
}


static __inline__ void
trace_i915_gem_object_create(
	struct drm_gem_object *obj
) {
	;
}

static __inline__ void
trace_i915_gem_object_destroy(
	struct drm_gem_object *obj
) {
	;
}
