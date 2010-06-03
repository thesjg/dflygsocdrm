/**
 * \file drm_porting_transition.h
 * Header for obsoleted declarations for the Direct Rendering Manager
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 *
 * \par Acknowledgments:
 * Dec 1999, Richard Henderson <rth@twiddle.net>, move to generic \c cmpxchg.
 */

/*-
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All rights reserved.
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
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * \mainpage
 *
 * The Direct Rendering Manager (DRM) is a device-independent kernel-level
 * device driver that provides support for the XFree86 Direct Rendering
 * Infrastructure (DRI).
 *
 * The DRM supports the Direct Rendering Infrastructure (DRI) in four major
 * ways:
 *     -# The DRM provides synchronized access to the graphics hardware via
 *        the use of an optimized two-tiered lock.
 *     -# The DRM enforces the DRI security policy for access to the graphics
 *        hardware by only allowing authenticated X11 clients access to
 *        restricted regions of memory.
 *     -# The DRM provides a generic DMA engine, complete with multiple
 *        queues and the ability to detect the need for an OpenGL context
 *        switch.
 *     -# The DRM is extensible via the use of small device-specific modules
 *        that rely extensively on the API exported by the DRM module.
 *
 */

#ifndef _DRM_PORT_TRANSITION_H_
#define _DRM_PORT_TRANSITION_H_

/************************************************
 * Old version of drm.h
 ************************************************/

#include "dev/drm/drm_atomic.h"

#define DRM_MAX_MINOR   15

#define DRM_FENCE_FLAG_EMIT                0x00000001
#define DRM_FENCE_FLAG_SHAREABLE           0x00000002
/**
 * On hardware with no interrupt events for operation completion,
 * indicates that the kernel should sleep while waiting for any blocking
 * operation to complete rather than spinning.
 *
 * Has no effect otherwise.
 */
#define DRM_FENCE_FLAG_WAIT_LAZY           0x00000004
#define DRM_FENCE_FLAG_NO_USER             0x00000010

/* Reserved for driver use */
#define DRM_FENCE_MASK_DRIVER              0xFF000000

#define DRM_FENCE_TYPE_EXE                 0x00000001

struct drm_fence_arg {
	unsigned int handle;
	unsigned int fence_class;
	unsigned int type;
	unsigned int flags;
	unsigned int signaled;
	unsigned int error;
	unsigned int sequence;
	unsigned int pad64;
	uint64_t expand_pad[2]; /*Future expansion */
};

/* Buffer permissions, referring to how the GPU uses the buffers.
 * these translate to fence types used for the buffers.
 * Typically a texture buffer is read, A destination buffer is write and
 *  a command (batch-) buffer is exe. Can be or-ed together.
 */

#define DRM_BO_FLAG_READ        (1ULL << 0)
#define DRM_BO_FLAG_WRITE       (1ULL << 1)
#define DRM_BO_FLAG_EXE         (1ULL << 2)

/*
 * All of the bits related to access mode
 */
#define DRM_BO_MASK_ACCESS	(DRM_BO_FLAG_READ | DRM_BO_FLAG_WRITE | DRM_BO_FLAG_EXE)
/*
 * Status flags. Can be read to determine the actual state of a buffer.
 * Can also be set in the buffer mask before validation.
 */

/*
 * Mask: Never evict this buffer. Not even with force. This type of buffer is only
 * available to root and must be manually removed before buffer manager shutdown
 * or lock.
 * Flags: Acknowledge
 */
#define DRM_BO_FLAG_NO_EVICT    (1ULL << 4)

/*
 * Mask: Require that the buffer is placed in mappable memory when validated.
 *       If not set the buffer may or may not be in mappable memory when validated.
 * Flags: If set, the buffer is in mappable memory.
 */
#define DRM_BO_FLAG_MAPPABLE    (1ULL << 5)

/* Mask: The buffer should be shareable with other processes.
 * Flags: The buffer is shareable with other processes.
 */
#define DRM_BO_FLAG_SHAREABLE   (1ULL << 6)

/* Mask: If set, place the buffer in cache-coherent memory if available.
 *       If clear, never place the buffer in cache coherent memory if validated.
 * Flags: The buffer is currently in cache-coherent memory.
 */
#define DRM_BO_FLAG_CACHED      (1ULL << 7)

/* Mask: Make sure that every time this buffer is validated,
 *       it ends up on the same location provided that the memory mask is the same.
 *       The buffer will also not be evicted when claiming space for
 *       other buffers. Basically a pinned buffer but it may be thrown out as
 *       part of buffer manager shutdown or locking.
 * Flags: Acknowledge.
 */
#define DRM_BO_FLAG_NO_MOVE     (1ULL << 8)

/* Mask: Make sure the buffer is in cached memory when mapped.  In conjunction
 * with DRM_BO_FLAG_CACHED it also allows the buffer to be bound into the GART
 * with unsnooped PTEs instead of snooped, by using chipset-specific cache
 * flushing at bind time.  A better name might be DRM_BO_FLAG_TT_UNSNOOPED,
 * as the eviction to local memory (TTM unbind) on map is just a side effect
 * to prevent aggressive cache prefetch from the GPU disturbing the cache
 * management that the DRM is doing.
 *
 * Flags: Acknowledge.
 * Buffers allocated with this flag should not be used for suballocators
 * This type may have issues on CPUs with over-aggressive caching
 * http://marc.info/?l=linux-kernel&m=102376926732464&w=2
 */
#define DRM_BO_FLAG_CACHED_MAPPED    (1ULL << 19)


/* Mask: Force DRM_BO_FLAG_CACHED flag strictly also if it is set.
 * Flags: Acknowledge.
 */
#define DRM_BO_FLAG_FORCE_CACHING  (1ULL << 13)

/*
 * Mask: Force DRM_BO_FLAG_MAPPABLE flag strictly also if it is clear.
 * Flags: Acknowledge.
 */
#define DRM_BO_FLAG_FORCE_MAPPABLE (1ULL << 14)
#define DRM_BO_FLAG_TILE           (1ULL << 15)

/*
 * Memory type flags that can be or'ed together in the mask, but only
 * one appears in flags.
 */

/* System memory */
#define DRM_BO_FLAG_MEM_LOCAL  (1ULL << 24)
/* Translation table memory */
#define DRM_BO_FLAG_MEM_TT     (1ULL << 25)
/* Vram memory */
#define DRM_BO_FLAG_MEM_VRAM   (1ULL << 26)
/* Up to the driver to define. */
#define DRM_BO_FLAG_MEM_PRIV0  (1ULL << 27)
#define DRM_BO_FLAG_MEM_PRIV1  (1ULL << 28)
#define DRM_BO_FLAG_MEM_PRIV2  (1ULL << 29)
#define DRM_BO_FLAG_MEM_PRIV3  (1ULL << 30)
#define DRM_BO_FLAG_MEM_PRIV4  (1ULL << 31)
/* We can add more of these now with a 64-bit flag type */

/*
 * This is a mask covering all of the memory type flags; easier to just
 * use a single constant than a bunch of | values. It covers
 * DRM_BO_FLAG_MEM_LOCAL through DRM_BO_FLAG_MEM_PRIV4
 */
#define DRM_BO_MASK_MEM         0x00000000FF000000ULL
/*
 * This adds all of the CPU-mapping options in with the memory
 * type to label all bits which change how the page gets mapped
 */
#define DRM_BO_MASK_MEMTYPE     (DRM_BO_MASK_MEM | \
				 DRM_BO_FLAG_CACHED_MAPPED | \
				 DRM_BO_FLAG_CACHED | \
				 DRM_BO_FLAG_MAPPABLE)

/* Driver-private flags */
#define DRM_BO_MASK_DRIVER      0xFFFF000000000000ULL

/*
 * Don't block on validate and map. Instead, return EBUSY.
 */
#define DRM_BO_HINT_DONT_BLOCK  0x00000002
/*
 * Don't place this buffer on the unfenced list. This means
 * that the buffer will not end up having a fence associated
 * with it as a result of this operation
 */
#define DRM_BO_HINT_DONT_FENCE  0x00000004
/**
 * On hardware with no interrupt events for operation completion,
 * indicates that the kernel should sleep while waiting for any blocking
 * operation to complete rather than spinning.
 *
 * Has no effect otherwise.
 */
#define DRM_BO_HINT_WAIT_LAZY   0x00000008
/*
 * The client has compute relocations refering to this buffer using the
 * offset in the presumed_offset field. If that offset ends up matching
 * where this buffer lands, the kernel is free to skip executing those
 * relocations
 */
#define DRM_BO_HINT_PRESUMED_OFFSET 0x00000010

#define DRM_BO_INIT_MAGIC 0xfe769812
#define DRM_BO_INIT_MAJOR 1
#define DRM_BO_INIT_MINOR 0
#define DRM_BO_INIT_PATCH 0


struct drm_bo_info_req {
	uint64_t mask;
	uint64_t flags;
	unsigned int handle;
	unsigned int hint;
	unsigned int fence_class;
	unsigned int desired_tile_stride;
	unsigned int tile_info;
	unsigned int pad64;
	uint64_t presumed_offset;
};

struct drm_bo_create_req {
	uint64_t flags;
	uint64_t size;
	uint64_t buffer_start;
	unsigned int hint;
	unsigned int page_alignment;
};


/*
 * Reply flags
 */

#define DRM_BO_REP_BUSY 0x00000001

struct drm_bo_info_rep {
	uint64_t flags;
	uint64_t proposed_flags;
	uint64_t size;
	uint64_t offset;
	uint64_t arg_handle;
	uint64_t buffer_start;
	unsigned int handle;
	unsigned int fence_flags;
	unsigned int rep_flags;
	unsigned int page_alignment;
	unsigned int desired_tile_stride;
	unsigned int hw_tile_stride;
	unsigned int tile_info;
	unsigned int pad64;
	uint64_t expand_pad[4]; /*Future expansion */
};

struct drm_bo_arg_rep {
	struct drm_bo_info_rep bo_info;
	int ret;
	unsigned int pad64;
};

struct drm_bo_create_arg {
	union {
		struct drm_bo_create_req req;
		struct drm_bo_info_rep rep;
	} d;
};

struct drm_bo_handle_arg {
	unsigned int handle;
};

struct drm_bo_reference_info_arg {
	union {
		struct drm_bo_handle_arg req;
		struct drm_bo_info_rep rep;
	} d;
};

struct drm_bo_map_wait_idle_arg {
	union {
		struct drm_bo_info_req req;
		struct drm_bo_info_rep rep;
	} d;
};

struct drm_bo_op_req {
	enum {
		drm_bo_validate,
		drm_bo_fence,
		drm_bo_ref_fence,
	} op;
	unsigned int arg_handle;
	struct drm_bo_info_req bo_req;
};


struct drm_bo_op_arg {
	uint64_t next;
	union {
		struct drm_bo_op_req req;
		struct drm_bo_arg_rep rep;
	} d;
	int handled;
	unsigned int pad64;
};


#define DRM_BO_MEM_LOCAL 0
#define DRM_BO_MEM_TT 1
#define DRM_BO_MEM_VRAM 2
#define DRM_BO_MEM_PRIV0 3
#define DRM_BO_MEM_PRIV1 4
#define DRM_BO_MEM_PRIV2 5
#define DRM_BO_MEM_PRIV3 6
#define DRM_BO_MEM_PRIV4 7

#define DRM_BO_MEM_TYPES 8 /* For now. */

#define DRM_BO_LOCK_UNLOCK_BM       (1 << 0)
#define DRM_BO_LOCK_IGNORE_NO_EVICT (1 << 1)

struct drm_bo_version_arg {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
};

struct drm_mm_type_arg {
	unsigned int mem_type;
	unsigned int lock_flags;
};

struct drm_mm_init_arg {
	unsigned int magic;
	unsigned int major;
	unsigned int minor;
	unsigned int mem_type;
	uint64_t p_offset;
	uint64_t p_size;
};

struct drm_mm_info_arg {
	unsigned int mem_type;
	uint64_t p_size;
};

#define DRM_IOCTL_MM_INIT               DRM_IOWR(0xc0, struct drm_mm_init_arg)
#define DRM_IOCTL_MM_TAKEDOWN           DRM_IOWR(0xc1, struct drm_mm_type_arg)
#define DRM_IOCTL_MM_LOCK               DRM_IOWR(0xc2, struct drm_mm_type_arg)
#define DRM_IOCTL_MM_UNLOCK             DRM_IOWR(0xc3, struct drm_mm_type_arg)

#define DRM_IOCTL_FENCE_CREATE          DRM_IOWR(0xc4, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_REFERENCE       DRM_IOWR(0xc6, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_UNREFERENCE     DRM_IOWR(0xc7, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_SIGNALED        DRM_IOWR(0xc8, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_FLUSH           DRM_IOWR(0xc9, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_WAIT            DRM_IOWR(0xca, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_EMIT            DRM_IOWR(0xcb, struct drm_fence_arg)
#define DRM_IOCTL_FENCE_BUFFERS         DRM_IOWR(0xcc, struct drm_fence_arg)

#define DRM_IOCTL_BO_CREATE             DRM_IOWR(0xcd, struct drm_bo_create_arg)
#define DRM_IOCTL_BO_MAP                DRM_IOWR(0xcf, struct drm_bo_map_wait_idle_arg)
#define DRM_IOCTL_BO_UNMAP              DRM_IOWR(0xd0, struct drm_bo_handle_arg)
#define DRM_IOCTL_BO_REFERENCE          DRM_IOWR(0xd1, struct drm_bo_reference_info_arg)
#define DRM_IOCTL_BO_UNREFERENCE        DRM_IOWR(0xd2, struct drm_bo_handle_arg)
#define DRM_IOCTL_BO_SETSTATUS          DRM_IOWR(0xd3, struct drm_bo_map_wait_idle_arg)
#define DRM_IOCTL_BO_INFO               DRM_IOWR(0xd4, struct drm_bo_reference_info_arg)
#define DRM_IOCTL_BO_WAIT_IDLE          DRM_IOWR(0xd5, struct drm_bo_map_wait_idle_arg)
#define DRM_IOCTL_BO_VERSION          DRM_IOR(0xd6, struct drm_bo_version_arg)
#define DRM_IOCTL_MM_INFO               DRM_IOWR(0xd7, struct drm_mm_info_arg)

typedef struct drm_fence_arg drm_fence_arg_t;
typedef struct drm_mm_type_arg drm_mm_type_arg_t;
typedef struct drm_mm_init_arg drm_mm_init_arg_t;
typedef enum drm_bo_type drm_bo_type_t;

#endif
