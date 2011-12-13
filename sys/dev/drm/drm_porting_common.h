/* drm_porting_common.h -- Header for Direct Rendering Manager other OS -*- linux-c -*-
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

#ifndef _DRM_PORTING_COMMON_H_
#define _DRM_PORTING_COMMON_H_

#if defined(_KERNEL) || defined(__KERNEL__)

#include "dev/drm/drm_porting_include.h"
#include "dev/drm/drm_linux_list.h"
#include "dev/drm/drm_atomic.h"

/* For current implementation of idr */
#include <sys/tree.h>

/* From previous version of drm.h */

#define EXPORT_SYMBOL(sym)

/* substitute for struct module which has another definition */
typedef void *DRM_MODULE_T;
/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
/* file drm_drv.c, struct drm_stub_fops */
#if 0
struct module {
	int placeholder;
};
#endif

/* file ttm/ttm_module.c, epilogue */
/* file drm_stub.c */
#define MODULE_AUTHOR(arg, ...)

/* file drm_stub.c */
#define MODULE_DESCRIPTION(arg, ...)

/* file drm_stub.c */
#define MODULE_LICENSE(arg, ...)

/* file drm_stub.c */
#define MODULE_PARM_DESC(arg, ...)

/* file drm_stub.c */
#define module_param_named(arg, ...)

/* file i915_drv.c */
#define MODULE_DEVICE_TABLE(arg, ...)

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
request_module(char *modalias) {
	return 0;
}

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
try_module_get(DRM_MODULE_T module) {
	return 1;
}

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
module_put(DRM_MODULE_T module) {
	return 0;
}

#define THIS_MODULE (DRM_MODULE_T)NULL

/* file _drv.c and ttm_module.c epilogue */
/*
 * The functions initialize a module's callback for load and unload.
 * The callbacks for legacy BSD can instead be called in the
 * module MOD_LOAD / MOD_UNLOAD handler.
 */
#if 0
static __inline__ void
module_init(int (*func)(void)) {
	;
}

static __inline__ void
module_exit(void (*func)(void)) {
	;
}
#endif

/* Called in drm_drawable.c, function drm_update_drawable_info().
 * Negative of error indicators sometimes assigned to (void *).
 * Tests return value from idr_replace().
 * Assume pointers are no more than 64-bit and
 * that the last page of possible virtual memory is unmapped.
 */
#define IS_ERR(ptr) (((uintptr_t)ptr) > ((uintptr_t)((intptr_t)(-0x0800))))

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
/* What else can it be but the actual error? */
#define PTR_ERR(ptr) ((int)(-((intptr_t)ptr)))

/* drm_mm.c function drm_mm_takedown() */
/* file ttm/ttm_global.c, function ttm_global_release() */

#define BUG_ON(cond) KKASSERT(!(cond))

/* file ttm/ttm_bo.c, function ttm_bo_ref_bug() */
#define BUG()  /* UNIMPLEMENTED */

/*
 * Annotations
 */

#ifndef __user
#define __user
#endif

/* file ttm/ttm_module.c, function  ttm_init() */
/* file drm_drv.c, function  drm_core_init */
#ifndef __init
#define __init
#endif

/* file ttm/ttm_module.c, function  ttm_init() */
/* file drm_drv.c, function  drm_core_exit */
#ifndef __exit
#define __exit
#endif

#ifndef __iomem
#define __iomem
#endif

/* file i915_drv.c, function i915_pci_probe() */
#ifndef __devinit
#define __devinit
#endif

/* Used in older version of radeon_drm.h */
#ifdef __GNUC__
# define DEPRECATED  __attribute__ ((deprecated))
#else
# define DEPRECATED
#endif

/* file drm_edid.c, function drm_cvt_modes() */
#define unitialized_var(width)  width=0

/* From legacy older version of drmP.h */

/**********************************************************
 * C declarations and extensions                          *
 **********************************************************/

/* radeon_cp.c, function */
#define max_t(type, a, b) ((type)(a) > (type)(b)) ? (type)(a) : (type)(b)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

#define unlikely(x)            __builtin_expect(!!(x), 0)

/* DragonFly BSD sys/cdefs.h __predict_true */
#define likely(x)              __builtin_expect(!!(x), 1)

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	__typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

/*
 * Integer types
 */

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;

/* typedef int32_t __s32 in drm.h */
/* i915/i915.drv.h, struct drm_i915_error_buffer */
typedef int32_t s32;

/* radeon_drm.h typedef drm_radeon_setparam_t, member value
 * Linux version has __s64
 * BSD version has int64_t
 */

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

/* file drm_fixed.h, function dfixed_div,
 * extend interpretation of upper_32_bits */
/* 2.6.34.7, file radeon_fixed.h, function rfixed_div() return value */
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffff))

/* file drm_fixed.h, function dfixed_div,
 * extend interpretation of upper_32_bits */
/* 2.6.34.7, file radeon_fixed.h, function rfixed_div() */
#define do_div(a, b) (a = (uint64_t)(((uint64_t)(a)) / ((uint64_t)(b))))

/* drmP.h, declaration of function drm_read() */
#define loff_t	off_t

/* evidently now defined in DragonFly in libprop/prop_object.h */
#if 0
typedef boolean_t bool;
#endif

/* file drm_agpsupport.c, function drm_agp_bind_pages() */
#ifndef true
#define true (bool)1
#endif

#ifndef false
#define false (bool)0
#endif

/* On DragonFly at least
 * sizeof(size_t) == sizeof(unsigned long)
 */

/* This is beyond ugly, and only works on GCC.  However, it allows me to use
 * drm.h in places (i.e., in the X-server) where I can't use size_t.  The real
 * fix is to use uint32_t instead of size_t, but that fix will break existing
 * LP64 (i.e., PowerPC64, SPARC64, IA-64, Alpha, etc.) systems.  That *will*
 * eventually happen, though.  I chose 'unsigned long' to be the fallback type
 * because that works on all the platforms I know about.  Hopefully, the
 * real fix will happen before that bites us.
 */

/*
#ifdef __SIZE_TYPE__
# define DRM_SIZE_T __SIZE_TYPE__
#else
# warning "__SIZE_TYPE__ not defined.  Assuming sizeof(size_t) == sizeof(unsigned long)!"
# define DRM_SIZE_T unsigned long
#endif
*/

/*
 * Endian considerations
 */

/* vmwgfx */
#ifndef __le32
#define __le32 uint32_t
#endif

/* file drm_edid.h, struct detailed_data_monitor_range */
#ifndef __le16
#define __le16 uint16_t
#endif

#define cpu_to_le32(x) htole32(x)
#define le32_to_cpu(x) le32toh(x)

/* file drm_edid.c, function drm_mode_detailed() */
/* On DragonFly sys/endian.h */
#define le16_to_cpu(x) le16toh(x)

/* file drm_edid.c, function drm_mode_detailed() */
#define cpu_to_le16(x) htole16(x)

/* drmP.h struct drm_local_map */
/* file drm_bufs.c, function drm_get_resource_start() */
typedef unsigned long resource_size_t;

/* file drm_bufs.c, function drm_map_handle() */
#ifdef __x86_64__
#define BITS_PER_LONG  64
#else
#define BITS_PER_LONG  32
#endif

#define BITS_TO_LONGS(b) (((b) + BITS_PER_LONG - 1) / BITS_PER_LONG)

/* file intel_display.c, function ironlake_compute_m_n() */
/* gmch_m and link_m are defined to be u32, but
 * temp is defined to be u64
 */
static __inline__ uint32_t
div_u64(uint64_t temp, uint32_t link_clock) {
	return (uint32_t)(temp / link_clock);
}

/* file intel_display.c, function ironlake_update_wm() */
#define DIV_ROUND_UP(x, y)  ((x) + (y) - 1) / (y)

/* file i915/intel_sdvo.c, function intel_sdvo_select_ddc_bus() */
static __inline__ unsigned int
hweight16(uint16_t mask) {
	unsigned int num_bits = 0;
	int i;
	for (i = 0; i < 16; i++) {
		if ((mask & (1 << i)) != 0) {
			num_bits++;
		}
	}
	return num_bits;
}

/* file drm_mode.c, function drm_mode_equal() */
/* Convert kilohertz to picos */
#define KHZ2PICOS(clock) (1000000000ul / (clock))

/**********************************************************
 * C LIBRARY equivalents                                  *
 **********************************************************/

/*
 * Errors
 */

/* file intel_dp.c, function intel_dp_i2c_aux_ch() */
#define EREMOTEIO    EIO

/* file ttm/ttm_bo.c, function ttm_bo_mem_space() */
/* Positive, larger than any in sys/errno.h */
#define ERESTARTSYS  ERESTART 

/* DragonFlyBSD defines ERESTART -1 */

/*
 * Memory management
 */

#define sscanf	ksscanf
#define malloc	kmalloc
#define realloc	krealloc
#define reallocf krealloc	/* XXX XXX XXX */

__inline static void
free(void *addr, struct malloc_type *type)
{
	if (addr != NULL)
		kfree(addr, type);
}

/*
 * Print functions
 */

/* For file drm_stub.c, function drm_ut_debug_printk() */
#define printk    printf
#define vprintk   kvprintf

#define printf	kprintf
#define snprintf ksnprintf

/* file drm_edid.c, function edid_block_valid() */
#define print_hex_dump_bytes(arg, ...) /* UNIMPLEMENTED */

/*
 * Print messages
 */

/* For file drm_stub.c, function drm_ut_debug_printk() */
/* DRM_MEM_ERROR appears unused and so is drm_mem_stats */

#define KERN_DEBUG   "debug::"
#define KERN_ERR     "error::"
#define KERN_INFO    "info::"

/* file drm_edid.c, function drm_mode_detailed() */
#define KERN_WARNING "warning::"

/* file drm_crtc_helper, function drm_encoder_crtc_ok() */
#define WARN(cond, ...)  do { if (cond) DRM_ERROR(__VA_ARGS__); } while (0)

/* file i915_gem.c */
#define WARN_ON(cond)  do { if (cond) DRM_ERROR("\n"); } while (0)

/* file i915_gem.c */
/* file drm_cache.c, function drm_clflush_pages() */
#define WARN_ON_ONCE(cond) WARN_ON(cond)

/* file ttm/ttm_page_alloc.h, function ttm_page_alloc_debugfs() */
struct seq_file {
/* file drm_info.c, function drm_name_info() */
	void *private;
};

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_debugfs() */
#define seq_printf(seq_file, ...) kprintf(__VA_ARGS__) /* UNIMPLEMENTED */

/*
 * File mode permissions
 */
/* In analogy to sys/stats.h, interpret
 * R to mean read
 * UGO to mean user, group, other
 */
#define S_IRUGO  S_IRUSR|S_IRGRP|S_IROTH

/*
 * String
 */

/* file drm_fb_helper.c, function drm_fb_helper_connector_parse_command_line() */
static __inline__ long
simple_strtol(const char *nptr, char **endptr, int base) {
	return strtol(nptr, endptr, base);
}

/**********************************************************
 * MATH                                                   *
 **********************************************************/

/* file drm_edid.c, macro MODE_REFRESH_DIFF() */
#define abs(x) (x) > 0 ? (x) : (-(x))

/**********************************************************
 * Atomic instructions                                    *
 **********************************************************/

/* Uses functions from drm_atomic.h */
static __inline__ void
__set_bit(int bit, volatile void *bytes) {
	set_bit(bit, bytes);
}

static __inline__ void
__clear_bit(int bit, volatile void *bytes) {
	clear_bit(bit, bytes);
}

/* Uses of atomic functions defined below all appear
 * to use constant n for addition or subtraction
 */

/* file ttm/ttm_page_alloc.c, function ttm_pool_mm_shrink() */
static __inline__ uint32_t
atomic_add_return(uint32_t n, atomic_t *v) {
	return n + atomic_fetchadd_int(v, n);
}

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_fini() */
static __inline__ uint32_t
atomic_sub_return(uint32_t n, atomic_t *v) {
	return (uint32_t)(-n) + atomic_fetchadd_int(v, (uint32_t)(-n));
}

/* file ttm/ttm_bo.c, function ttm_bo_reserve_locked() */
static __inline__ uint32_t
atomic_cmpxchg(atomic_t *reserved, uint32_t v0, uint32_t v1){
	return atomic_cmpset_int(reserved, v0, v1);
}

/* file drm_irq.c, function drm_vblank_put() */
static __inline__ uint32_t
atomic_dec_and_test(atomic_t *refcount){
	return atomic_fetchadd_int(refcount, -1) == 1;
}

/* file ttm/ttm_page_alloc.c, struct ttm_pool_manager */
#define ATOMIC_INIT(n)  (n)

/**********************************************************
 * HASH                                                   *
 **********************************************************/

/* file drm_hashtab.c */
/* return value unsigned long from drm_ht_just_insert_please */
static __inline__ unsigned int
hash_long(unsigned long key, int bits) {
	unsigned long val;
#ifdef __x86_64__
/* Prime close to golden ratio obtained from
 * Bob Jenkins, Public Domain code
 * http://burtleburtle.net/bob/c/lookup8.c */
	val = key * 0x9e3779b97f4a7c13L;
#else
/* Prime close to golden ratio obtained from
 * Bob Jenkins, Public Domain code
 * http://burtleburtle.net/bob/c/lookup2.c */
	val = key * 0x9e3779b9;
#endif
	return (unsigned int)((val >> (BITS_PER_LONG - bits))
		& ((1 << bits) - 1)); 
}

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

/*
 * Lists
 */

/* file i915_gem.c */
#define DRM_LIST_HEAD(arg)  struct list_head arg

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_free() */
#define __list_del(entry, list) /* UNIMPLEMENTED */

/* Extension of function in drm_linux_list.h */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, __typeof(*pos), member);	\
	    &pos->member != (head);					\
	    pos = list_entry(pos->member.prev, __typeof(*pos), member))

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_filled_lock() */
static __inline__ void
list_splice(struct list_head* newp, struct list_head* head) {
	if (!list_empty(newp)) {
		(head)->next->prev = (newp)->prev;
		(newp)->prev->next = (head)->next;
		(newp)->next->prev = (head)->next;
		(head)->next = (newp)->next;
	}
}

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_get_pages() */
static __inline__ void
list_splice_init(struct list_head* newp, struct list_head* head) {
	list_splice(newp, head);
	list_empty(newp);
}

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_get_pages() */
static __inline__ void
list_cut_position(struct list_head *pages, struct list_head *list, struct list_head *p) {
	pages->next = list->next;
	list->next->prev = p;
	pages->prev = p;
	p->next = list->next;
}

/*
 * red-black trees
 */

/* file ttm_bo.c, function ttm_bo_vm_insert() */
struct rb_node {
/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
	struct rb_node *rb_left;
	struct rb_node *rb_right;
	struct rb_node *rb_parent;
	int color;
};

/* file ttm/ttm_bo.c, function ttm_bo_release() */
struct rb_root {
/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
    struct rb_node *rb_node;
};

#define DRM_RB_ROOT  {                        \
.rb_node =	{                             \
	.rb_left =   (struct rb_node *)NULL,  \
	.rb_right =  (struct rb_node *)NULL,  \
	.rb_parent = (struct rb_node *)NULL,  \
	.color =     0                        \
		}                             \
}

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
/* Used implementation from drm_linux_list.h */
#define rb_entry(ptr, type, member) container_of(ptr,type,member)

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
static __inline__ void
rb_link_node(struct rb_node *vm_rb, struct rb_node *parent, struct rb_node **cur) {
	;
}

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
static __inline__ void
rb_insert_color(struct rb_node *vm_rb, struct rb_root *addr_space_rb) {
	;
}

/* file ttm/ttm_bo.c, function ttm_bo_release() */
static __inline__ void
rb_erase(struct rb_node * vm_node, struct rb_root * addr_space_rb) {
	;
}

#endif /* __KERNEL__ */
#endif
