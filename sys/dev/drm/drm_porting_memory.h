/* drm_porting_memory.h -- Header for Direct Rendering Manager other OS -*- linux-c -*-
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
 * ... AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    David Shao <davshao@gmail.com>
 *
 */

#ifndef _DRM_PORTING_MEMORY_H_
#define _DRM_PORTING_MEMORY_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#ifdef GFP_ATOMIC
#undef GFP_ATOMIC
#endif
#define GFP_ATOMIC   M_NOWAIT

#ifdef GFP_KERNEL
#undef GFP_KERNEL
#endif
#define GFP_KERNEL   M_WAITOK

#define drm_kmalloc(ptr, flag)    malloc(ptr, DRM_MEM_DEFAULT, flag)

#define drm_kfree(ptr)            free(ptr, DRM_MEM_DEFAULT)

#define kmalloc(ptr, flag, ...)   kmalloc(ptr, DRM_MEM_DEFAULT, flag)

#define kfree(ptr, ...)           kfree(ptr, DRM_MEM_DEFAULT)

/* Every use of kzalloc() in Linux 2.6.34 drm is with flag GFP_KERNEL */
#define kzalloc(sizealloc, flag) kmalloc(sizealloc, M_WAITOK|M_ZERO)

/* file drm_memory_util.h */
#define kcalloc(n, sizealloc, flag) kmalloc((n * sizealloc), M_WAITOK|M_ZERO)

#endif /* __KERNEL__ */
#endif
