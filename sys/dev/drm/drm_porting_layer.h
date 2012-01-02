/* drm_porting_layer.h -- Header for Direct Rendering Manager other OS -*- linux-c -*-
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

#ifndef _DRM_PORTING_LAYER_H_
#define _DRM_PORTING_LAYER_H_

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

/* For DragonFly BSD on i386 or x86_64 assume little endian */
#ifndef __le32
#define __le32 uint32_t
#endif

#ifndef __le16
#define __le16 uint16_t
#endif

#define cpu_to_le32(x) htole32(x)
#define le32_to_cpu(x) le32toh(x)

/* On DragonFly sys/endian.h */
#define le16_to_cpu(x) le16toh(x)

/* file drm_edid.c, function drm_mode_detailed() */
#define cpu_to_le16(x) htole16(x)

typedef unsigned long resource_size_t;

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
/* from sys/param.h equivalent is howmany */
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

/*
 * Alignment
 * Safest is to use memcpy(void *dst, void*src, size_t num);
 */

/*
 * file radeon/atom.c, function 
 * get_unaligned_le32()
 */

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

MALLOC_DECLARE(DRM_MEM_DMA);
MALLOC_DECLARE(DRM_MEM_SAREA);
MALLOC_DECLARE(DRM_MEM_DRIVER);
MALLOC_DECLARE(DRM_MEM_MAGIC);
MALLOC_DECLARE(DRM_MEM_IOCTLS);
MALLOC_DECLARE(DRM_MEM_MAPS);
MALLOC_DECLARE(DRM_MEM_BUFS);
MALLOC_DECLARE(DRM_MEM_SEGS);
MALLOC_DECLARE(DRM_MEM_PAGES);
MALLOC_DECLARE(DRM_MEM_FILES);
MALLOC_DECLARE(DRM_MEM_QUEUES);
MALLOC_DECLARE(DRM_MEM_CMDS);
MALLOC_DECLARE(DRM_MEM_MAPPINGS);
MALLOC_DECLARE(DRM_MEM_BUFLISTS);
MALLOC_DECLARE(DRM_MEM_AGPLISTS);
MALLOC_DECLARE(DRM_MEM_CTXBITMAP);
MALLOC_DECLARE(DRM_MEM_SGLISTS);
MALLOC_DECLARE(DRM_MEM_DRAWABLE);
MALLOC_DECLARE(DRM_MEM_MM);
MALLOC_DECLARE(DRM_MEM_HASHTAB);
MALLOC_DECLARE(DRM_MEM_DEFAULT);
MALLOC_DECLARE(DRM_MEM_STUB);
MALLOC_DECLARE(DRM_MEM_IDR);
MALLOC_DECLARE(DRM_MEM_FENCE);

#define malloc	kmalloc
#define realloc	krealloc
#define reallocf krealloc	/* XXX XXX XXX */

__inline static void
free(void *addr, struct malloc_type *type)
{
	if (addr != NULL)
		kfree(addr, type);
}

/* For now just treat the same as regular allocation */
/* file drm_memory.c, function agp_remap() */
/* file vmwgfx_fifo.c, function vmw_fifo_init() */
static __inline__ void *
vmalloc(size_t size) {
	return malloc(size, DRM_MEM_DEFAULT, M_WAITOK | M_ZERO);
}

/* For now just treat the same as regular allocation */
/* file drm_scatter.c, function drm_vmalloc_dma() */
static __inline__ void *
vmalloc_32(size_t size) {
	return malloc(size, DRM_MEM_DEFAULT, M_WAITOK | M_ZERO);
}

#if 0 /* UNIMPLEMENTED */
/* For _DRM_SHM are special methods necessary to obtain memory mappable to user space */
/* file drm_bufs.c, function drm_addmap_core() */
static __inline__ void *
vmalloc_user(unsigned long size) {
	return malloc(size, DRM_MEM_DEFAULT, M_WAITOK | M_ZERO);
}
#endif

/* file drm_bufs.c, function drm_rmmap_locked() */
/* file vmwgfx_fifo.c, function vmw_fifo_init() */
static __inline__ void
vfree(void *handle) {
	free(handle, DRM_MEM_DEFAULT);
}

/* file ttm/ttm_page_alloc.c, function ttm_pool_mm_shrink() */
typedef uint32_t gfp_t;

#ifdef GFP_ATOMIC
#undef GFP_ATOMIC
#endif
#define GFP_ATOMIC        M_NOWAIT

#ifdef GFP_KERNEL
#undef GFP_KERNEL
#endif
#define GFP_KERNEL        M_WAITOK

/* UNIMPLEMENTED */
#define __GFP_COLD        0x0004
#define __GFP_COMP        0x0008
#define __GFP_DMA32       0x0010
/* file vmwgfx_gmr.c, function vmw_gmr_build_descriptors() */
#define __GFP_HIGHMEM     0x0020
#define __GFP_NORETRY     0x0040
#define __GFP_NOWARN      0x0080
#define __GFP_ZERO        M_ZERO 
#define __GFP_RECLAIMABLE 0x0200

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
#define GFP_DMA32         0x0400

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_init() */
#define GFP_HIGHUSER      0x0800
#define GFP_USER          0x01000

/*
 * Print functions
 */

#define sscanf	ksscanf

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

/********************************************************************
 * TIME                                                             *
 ********************************************************************/

#define DRM_HZ			hz
#define HZ	hz

/* ticks defined in kern_clock.c as only int */
#define jiffies	ticks

static __inline__ unsigned long
msecs_to_jiffies(unsigned long msecs) {
	return DIV_ROUND_UP(msecs, (1000 / hz));
}

static __inline__ unsigned long
usecs_to_jiffies(unsigned long usecs) {
	unsigned long msecs = DIV_ROUND_UP(usecs, 1000);
	return DIV_ROUND_UP(msecs, (1000 / hz));
}

typedef unsigned long cycles_t;

/* define as macros for sign extension of int ticks */
#define time_after(timeout, _end)    ((long)(_end) - (long)(timeout) < 0)

#define time_after_eq(timeout, _end) ((long)(timeout) - (long)(_end) >= 0)

/* file drm_irq., function drm_handle_vblank_events() */
static __inline__ void
do_gettimeofday(struct timeval *now) {
	microtime(now);
}

#define DRM_UDELAY(udelay)	DELAY(udelay)

/* spin delay in microseconds */
static __inline__ void
udelay(int delay) {
	DELAY(delay);
}

/* spin delay in milliseconds */
static __inline__ void
mdelay(int delay) {
	DELAY(1000 * delay);
}

#if 0
static __inline__ void
schedule(void) {
	;
}
#endif

/* have current process sleep in HZ,
 * can have sleep interrupted by signal
 * return 0 if successful sleep for full time 
 */
int
schedule_timeout(signed long timo);

/* have current process sleep in HZ,
 * sleep cannot be interrupted by signal
 * return 0 if successful sleep for full time 
 */
int
schedule_timeout_interruptible(signed long timo);

/* noninterruptible process sleep in milliseconds */
void
msleep(unsigned int millis);

/* signal-interruptible process sleep in milliseconds */
void
msleep_interruptible(unsigned int millis);

/* Convert kilohertz to picos */
#define KHZ2PICOS(clock) (1000000000ul / (clock))

/**********************************************************
 * LOCKING                                                *
 **********************************************************/

/* Locking idiom from BSD drmP.h */

#define DRM_SPINTYPE		struct lock
#define DRM_SPININIT(l,name)	lockinit(l, name, 0, LK_CANRECURSE)
#define DRM_SPINUNINIT(l)
#define DRM_SPINLOCK(l)		lockmgr(l, LK_EXCLUSIVE|LK_RETRY|LK_CANRECURSE)
#define DRM_SPINUNLOCK(u)	lockmgr(u, LK_RELEASE)
#define DRM_SPINLOCK_IRQSAVE(l, irqflags) do {		\
	DRM_SPINLOCK(l);				\
	(void)irqflags;					\
} while (0)
#define DRM_SPINUNLOCK_IRQRESTORE(u, irqflags) DRM_SPINUNLOCK(u)
#define DRM_SPINLOCK_ASSERT(l)

/*
 * At the moment DRM_LOCK is only used for graphics card driver ioctls
 * not for any other code.
 */
#define DRM_LOCK()		DRM_SPINLOCK(&dev->dev_lock)
#define DRM_UNLOCK()		DRM_SPINUNLOCK(&dev->dev_lock)
#define DRM_SYSCTL_HANDLER_ARGS	(SYSCTL_HANDLER_ARGS)

/* file i915_gem.c */
#define DEFINE_SPINLOCK(l)	struct lock l = { \
	.lk_spinlock = {0}, \
	.lk_flags = LK_CANRECURSE & LK_EXTFLG_MASK, \
	.lk_wmesg = "gem", \
	.lk_timo = 0}

/* Locking replacements for Linux drm functions */

#define spinlock_t	struct lock
#define spin_lock(l)   lockmgr(l, LK_EXCLUSIVE | LK_RETRY | LK_CANRECURSE)
#define spin_unlock(u) lockmgr(u, LK_RELEASE)
#define spin_lock_init(l) lockinit(l, "slinit", 0, LK_CANRECURSE)

static __inline__ unsigned long 
drm_read_flags(void) {
#if defined( __x86_64__)
	return read_rflags();
#elif defined(__i386__)
	return read_eflags();
#else
	return 0;
#endif
}

static __inline__ void
drm_write_flags(unsigned long flags) {
#if defined(__i386__)
	write_eflags(flags);
#elif defined(__x86_64__)
	write_rflags(flags);
#else
	(void)flags;
#endif
}

/* save flags, disable hard interrupts, lock */
#define spin_lock_irqsave(l, irqflags)       \
        do {                                 \
		irqflags = drm_read_flags(); \
		cpu_disable_intr();          \
                spin_lock(l);                \
        } while (0)

/* unlock, enable hard interrupts, restore flags */
#define spin_unlock_irqrestore(l, irqflags)  \
	do {                                 \
		spin_unlock(l);              \
		cpu_enable_intr();           \
		drm_write_flags(irqflags);   \
	} while (0)

/* UNIMPLEMENTED enabling or disabling soft interrupts */
#define spin_lock_bh(l)    spin_lock(l)
#define spin_unlock_bh(l)  spin_unlock(l)

/********************************************************************
 * MUTEX                                                            *
 ********************************************************************/

#define mutex lock

#define mutex_init(l)               lockinit(l, "lmutex", 0, LK_CANRECURSE)
#define mutex_lock(l)               lockmgr(l, LK_EXCLUSIVE | LK_RETRY  | LK_CANRECURSE)
#define mutex_lock_interruptible(l) lockmgr(l, LK_EXCLUSIVE | LK_RETRY  | LK_CANRECURSE | LK_PCATCH)
#define mutex_trylock(l)           !lockmgr(l, LK_EXCLUSIVE | LK_NOWAIT | LK_CANRECURSE)
#define mutex_unlock(u)             lockmgr(u, LK_RELEASE)
#define mutex_is_locked(l)          lockstatus(l, NULL)

/*
 * Combines lock_init() from kern/kern_lock.c
 * and spin_init() from sys/spinlock2.h
 */
#define DEFINE_MUTEX(mut) struct lock mut = {  \
	.lk_spinlock = {                       \
		.counta = 0,                   \
                .countb = 0,                   \
	},                                     \
	.lk_flags = 0,                         \
	.lk_sharecount = 0,                    \
	.lk_waitcount = 0,                     \
	.lk_exclusivecount = 0,                \
	.lk_wmesg = "drmglo",                  \
	.lk_timo = 0,                          \
	.lk_lockholder = LK_NOTHREAD,          \
}

/********************************************************************
 * READER WRITER SPINLOCKS                                          *
 ********************************************************************/

typedef struct lock rwlock_t;

#define rwlock_init(l)   lockinit(l, "lrwspi", 0, LK_CANRECURSE)
#define read_lock(l)     lockmgr(l, LK_SHARED | LK_RETRY)
#define read_unlock(l)   lockmgr(l, LK_RELEASE)
#define write_lock(l)    lockmgr(l, LK_EXCLUSIVE | LK_RETRY)
#define write_unlock(l)  lockmgr(l, LK_RELEASE)

/* save flags, disable hard interrupts, lock */
#define read_lock_irqsave(l, irqflags)                            \
        do {                                                      \
		irqflags = drm_read_flags();                      \
		cpu_disable_intr();                               \
                lockmgr(l, LK_SHARED | LK_RETRY | LK_CANRECURSE); \
        } while (0)

/* unlock, enable hard interrupts, restore flags */
#define read_unlock_irqrestore(l, irqflags)                       \
	do {                                                      \
		lockmgr(l, LK_RELEASE);                           \
		cpu_enable_intr();                                \
		drm_write_flags(irqflags);                        \
	} while (0)

/* save flags, disable hard interrupts, lock */
#define write_lock_irqsave(l, irqflags)                           \
        do {                                                      \
		irqflags = drm_read_flags();                      \
		cpu_disable_intr();                               \
                lockmgr(l, LK_EXCLUSIVE | LK_RETRY);              \
        } while (0)

/* unlock, enable hard interrupts, restore flags */
#define write_unlock_irqrestore(l, irqflags)                      \
	do {                                                      \
		lockmgr(l, LK_RELEASE);                           \
		cpu_enable_intr();                                \
		drm_write_flags(irqflags);                        \
	} while (0)

/********************************************************************
 * SEMAPHORES                                                       *
 ********************************************************************/

/* Obviously this is not a rw-semaphore */
/* but all downs seem to be matched with ups */
#define rw_semaphore lock

static __inline__ void
init_rwsem(struct rw_semaphore *rwlock) {
	lockinit(rwlock, "lrwsem", 0, LK_CANRECURSE);
}

static __inline__ void
down_read(struct rw_semaphore *sem) {
	lockmgr(sem, LK_SHARED | LK_RETRY);
}

static __inline__ void
up_read(struct rw_semaphore *sem) {
	lockmgr(sem, LK_RELEASE);
}

static __inline__ void
down_write(struct rw_semaphore *rwlock) {
	lockmgr(rwlock, LK_EXCLUSIVE | LK_RETRY);
}

static __inline__ void
up_write(struct rw_semaphore *rwlock) {
	lockmgr(rwlock, LK_RELEASE);
}


/********************************************************************
 * IRQ                                                              *
 ********************************************************************/

/* Used for return value,
 * should probably rewrite IRQ handlers for DragonflyBSD
 * to not have a return value
 */
typedef int			irqreturn_t;

/* UNIMPLEMENTED
 * Arbitrarily defined to compile,
 * values only used for return not for comparison in drm
 */
#define IRQ_HANDLED		0x00
#define IRQ_NONE		0x01

#define DRM_IRQ_ARGS		void *arg

/* save flags, disable hard interrupts */
#define local_irq_save(irqflags)                                  \
        do {                                                      \
		irqflags = drm_read_flags();                      \
		cpu_disable_intr();                               \
        } while (0)

/* enable hard interrupts, restore flags */
#define local_irq_restore(irqflags)                               \
	do {                                                      \
		cpu_enable_intr();                                \
		drm_write_flags(irqflags);                        \
	} while (0)

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

/*
 * Lists
 */

/* LIST_HEAD already defined in DragonFly */
#define DRM_LIST_HEAD(arg)  struct list_head arg

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_free() */
/* acts on member list lru of struct page */
#define __list_del(entry, list) /* UNIMPLEMENTED */

/**********************************************************
 * RED-BLACK TREES                                        *
 **********************************************************/

/* file ttm_bo.c, function ttm_bo_vm_insert() */
struct rb_node {
/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
	struct rb_node *rb_left;
	struct rb_node *rb_right;
	struct rb_node *rb_parent;
/* Arbitrarily choose 0 == red, 1 == black */
	int color;
};

/* file ttm/ttm_bo.c, function ttm_bo_release() */
struct rb_root {
/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
    struct rb_node *rb_node;
};

/* file ttm/ttm_bo.c, function ttm_bo_device_init() */
/* RB_ROOT already defined for DragonFly in sys/tree.h */
#define DRM_RB_ROOT    (struct rb_root) \
{                                       \
	.rb_node = NULL                 \
}

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
/* Used implementation from drm_linux_list.h */
#define rb_entry(ptr, type, member) container_of(ptr,type,member)

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
void
rb_link_node(struct rb_node *node, struct rb_node *parent, struct rb_node **cur);

/* file ttm/ttm_bo.c, function ttm_bo_vm_insert_rb() */
void
rb_insert_color(struct rb_node *node, struct rb_root *root);

/* file ttm/ttm_bo.c, function ttm_bo_release() */
void
rb_erase(struct rb_node *node, struct rb_root *root);

/**********************************************************
 * idr                                                    *
 **********************************************************/

/* Brute force implementation of idr API
 * using current red-black tree backing
 *
 * Adapted from FreeBSD port of drm_drawable.c
 */

struct drm_rb_info {
	void *data;
	int handle;
	RB_ENTRY(drm_rb_info) tree;
};

int
drm_rb_compare(struct drm_rb_info *a, struct drm_rb_info *b);

RB_HEAD(drm_rb_tree, drm_rb_info);

RB_PROTOTYPE(drm_rb_tree, drm_rb_info, tree, drm_rb_compare);

struct idr {
	struct drm_rb_tree tree;
	spinlock_t idr_lock;
	struct drm_rb_info *available;
	int filled_below;
};

void idr_init(struct idr *pidr);

void *idr_find(struct idr *pidr, int id);

/* Every mention of idr_pre_get has GPP_KERNEL */
int
idr_pre_get(struct idr *pidr, unsigned int flags);

int
idr_get_new_above(struct idr * pidr, void *data, int floor, int *id);

int
idr_get_new(struct idr *pidr, void *data, int *id);

void
idr_remove(struct idr *pidr, int id);

void
idr_remove_all(struct idr *pidr);

void
idr_for_each(struct idr *pidr,
	int (*func)(int id, void *ptr, void *data), void * data);

void *
idr_replace(struct idr *pidr, void *newData, int id);

void
idr_destroy(struct idr *pidr);

/**********************************************************
 * ida                                                    *
 **********************************************************/

/* Brute force implementation of ida API
 * using current red-black tree backing
 *
 * Adapted from FreeBSD port of drm_drawable.c
 */

struct drm_ida_info {
	int handle;
	RB_ENTRY(drm_ida_info) tree;
};

int
drm_ida_compare(struct drm_ida_info *a, struct drm_ida_info *b);

RB_HEAD(drm_ida_tree, drm_ida_info);

RB_PROTOTYPE(drm_ida_tree, drm_ida_info, tree, drm_ida_compare);

struct ida {
	struct drm_ida_tree tree;
	spinlock_t ida_lock;
	struct drm_ida_info *available;
	int filled_below;
};

void ida_init(struct ida *pida);

int
ida_pre_get(struct ida *pida, unsigned int flags);

int
ida_get_new_above(struct ida * pida, int floor, int *id);

int
ida_get_new(struct ida *pida, int *id);

void
ida_remove(struct ida *pida, int id);

void
ida_destroy(struct ida *pida);

/**********************************************************
 * GLOBAL DATA                                            *
 **********************************************************/

#define DRM_CURPROC		curthread
#define DRM_STRUCTPROC		struct thread

#define DRM_CURRENTPID		curthread->td_proc->p_pid
#define DRM_CURRENTUID		curthread->td_proc->p_ucred->cr_svuid

/* effective user id */
#define DRM_CURRENTEUID		curthread->td_proc->p_ucred->cr_uid
/* saved effective user id */
#define DRM_CURRENTSVUID	curthread->td_proc->p_ucred->cr_svuid
/* real user id */
#define DRM_CURRENTRUID		curthread->td_proc->p_ucred->cr_ruid

/* current is either the current thread or current process */
/* DragonFly BSD has curthread of type struct thread *     */

#define current curthread

typedef struct thread *DRM_CURRENT_T;

/********************************************************************
 * PERMISSIONS AND CREDENTIALS                                      *
 ********************************************************************/

/*
 * File mode permissions
 */

#define DRM_DEV_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define DRM_DEV_UID	0
#define DRM_DEV_GID	0

/* In analogy to sys/stats.h, interpret
 * R to mean read
 * UGO to mean user, group, other
 */
#define S_IRUGO  S_IRUSR|S_IRGRP|S_IROTH

/* equivalent to DRM_CURRENTPID */
static __inline__ pid_t
task_pid_nr(DRM_CURRENT_T cur) {
	if (cur->td_proc) {
		return cur->td_proc->p_pid;
	}
	return 0;
}

/* returns saved uid not effective uid */
static __inline__ uid_t
current_euid(void) {
	if (curthread->td_proc) {
		return curthread->td_proc->p_ucred->cr_svuid;
	}
	return 0;
}

/* DRM_SUSER returns true if the user is superuser */
#define DRM_SUSER(p)		(priv_check(p, PRIV_DRIVER) == 0)

#define CAP_SYS_ADMIN  PRIV_DRIVER 

/* same role as DRM_SUSER
 * Positive return value for success
 * Only argument used appears to be CAP_SYS_ADMIN
 */
static __inline__ int
capable(int capacity) {
	return (0 == priv_check(curthread, capacity));
}

/********************************************************************
 * WAIT QUEUES                                                      *
 ********************************************************************/

#define wait_queue_head_t atomic_t

#define DECLARE_WAIT_QUEUE_HEAD(var) wait_queue_head_t var

static __inline__ void
init_waitqueue_head(wait_queue_head_t *wqh) {
	;
}

/* UNIMPLEMENTED no real way to tell with this implementation */
static __inline__ int
waitqueue_active(wait_queue_head_t *wqh) {
	return 0;
}

#define DRM_NEWER_RATLOCK 1
#if 0
#define DRM_NEWER_NOCOUNT 1
#endif

/* Instead of sleeping potentially forever, wait 1/10 seconds */
#define DRM_TIMEOUT  (HZ / 10)

/*
 * Assert that in Linux 2.6.34.7 drm, DRM_WAIT_ON is
 * only called in a graphics device driver ioctl,
 * so that DRM_LOCK is held when called,
 * with one exception in drm_irq.c that needs to be changed.
 * Called in mga_driver_fence_wait() in mga_irq.c, which is
 * only called by mga_wait_fence() in mga_state.c, which in turn
 * services mga driver ioctl DRM_MGA_WAIT_FENCE.
 * Called in i915_wait_irq() in i915_irq.c, which is
 * only called by i915_irq_wait(), which in turn
 * services i915 driver ioctl DRM_I915_IRQ_WAIT.
 * Called in radeon_wait_irq() in radeon_irq.c, which is
 * only called by radeon_irq_wait(), which in turn
 * services (non-KMS) DRM_RADEON_IRQ_WAIT.
 */
/* Returns -errno to shared code */

#if 1
#ifdef DRM_NEWER_RATLOCK
#define DRM_WAIT_ON( ret, queue, timeout, condition )                      \
do {                                                                       \
	int _end = jiffies + (timeout);                                    \
	int _wait = ((HZ / 100) > 1) ? (HZ / 100) : 2;                     \
	lwkt_serialize_enter(&dev->irq_lock);                              \
	ret = 0;                                                           \
	for (;;) {                                                         \
		if (!(condition)) {					   \
	        	tsleep_interlock(&(queue), PCATCH);                \
			mutex_unlock(&drm_global_mutex);                   \
	            	ret = -zsleep(&(queue), &dev->irq_lock,            \
				PCATCH | PINTERLOCKED, "drmwtq", (_wait)); \
			mutex_lock(&drm_global_mutex);                     \
			if ((ret == -ERESTART) || (ret == -EINTR)) {       \
				ret = -EINTR;                              \
				break;                                     \
			} else if (time_after(jiffies, _end)) {            \
				ret = -EBUSY;                              \
				break;                                     \
			}                                                  \
		}                                                          \
		else {                                                     \
			ret = 0;                                           \
			break;                                             \
		}                                                          \
	}                                                                  \
	lwkt_serialize_exit(&dev->irq_lock);                               \
}                                                                          \
while (0)
#else
#define DRM_WAIT_ON( ret, queue, timeout, condition )                   \
do {                                                                    \
	int _end = jiffies + (timeout);                                 \
	int _wait = ((HZ / 100) > 1) ? (HZ / 100) : 2;                  \
	lwkt_serialize_enter(&dev->irq_lock);                           \
	ret = 0;                                                        \
	for (;;) {                                                      \
		if (!(condition)) {					\
	        	tsleep_interlock(&(queue), PCATCH);             \
			lwkt_serialize_exit(&dev->irq_lock);		\
			DRM_UNLOCK();                                   \
	            	ret = -tsleep(&(queue), PCATCH | PINTERLOCKED,	\
				"drmwtq", (_wait));			\
			DRM_LOCK();					\
			lwkt_serialize_enter(&dev->irq_lock);           \
			if ((ret == -ERESTART) || (ret == -EINTR)) {    \
				ret = -EINTR;                           \
				break;                                  \
			} else if (time_after(jiffies, _end)) {         \
				ret = -EBUSY;                           \
				break;                                  \
			}                                               \
		}                                                       \
		else {                                                  \
			ret = 0;                                        \
			break;                                          \
		}							\
	}                                                               \
	lwkt_serialize_exit(&dev->irq_lock);                            \
}                                                                       \
while (0)
#endif
#else
#define DRM_WAIT_ON( ret, queue, timeout, condition )		\
for ( ret = 0 ; !ret && !(condition) ; ) {			\
	DRM_UNLOCK();						\
	lwkt_serialize_enter(&dev->irq_lock);			\
	if (!(condition)) {					\
            tsleep_interlock(&(queue), PCATCH);			\
            lwkt_serialize_exit(&dev->irq_lock);		\
            ret = -tsleep(&(queue), PCATCH | PINTERLOCKED,	\
			  "drmwtq", (timeout));			\
	} else {						\
		lwkt_serialize_exit(&dev->irq_lock);		\
	}							\
	DRM_LOCK();						\
}
#endif

/* GCC extension for statement expression */

/* sleep for condition without time limit */
#define wait_event(wqh, condition)                         \
({                                                         \
	while (!(condition)) {                             \
		tsleep(&(wqh), 0, "wtev", 0);              \
	}                                                  \
})

/* sleep for condition without time limit, interruptible by signal */
#define wait_event_interruptible(wqh, condition)           \
({                                                         \
	int retval = 0;                                    \
	while (!retval && !(condition)) {                  \
		retval = tsleep(&(wqh), PCATCH, "wei", 0); \
	}                                                  \
	if ((retval == ERESTART) || (retval == EINTR)){    \
		retval = -ERESTART;                        \
	}                                                  \
	retval;                                            \
})

/* sleep for condition with time limit in HZ
 * return time left if condition satisfied
 */
#define wait_event_timeout(wqh, condition, timeout)        \
({                                                         \
	long retval = 0;                                   \
	unsigned long toend = (unsigned long)(timeout);    \
	unsigned long left = (toend == 0) ? 1 : toend;     \
	for (;;)) {                                        \
		left--;                                    \
		retval = tsleep(&(wqh), 0, "wetimu", 1);   \
		if ((condition) || (left == 0)) {          \
			retval = left;                     \
			break;                             \
		}                                          \
	}                                                  \
	retval;                                            \
})

/* signal-interruptible sleep for condition with time limit in HZ
 * return time left if condition satisfied
 */
#define wait_event_interruptible_timeout(wqh, condition, timeout) \
({                                                                \
	long retval = 0;                                          \
	unsigned long toend = (unsigned long)(timeout);           \
	unsigned long left = (toend == 0) ? 1 : toend;            \
	for (;;)) {                                               \
		left--;                                           \
		retval = tsleep(&(wqh), PCATCH, "wetimi", 1);     \
		if ((retval == ERESTART) || (retval == EINTR)) {  \
			retval = -ERESTART;                       \
			break;                                    \
		}                                                 \
		else if ((condition) || (left == 0)) {            \
			retval = left;                            \
			break;                                    \
		}                                                 \
	}                                                         \
	retval;                                                   \
})

static __inline__ void
wake_up(void *wqh) {
	wakeup(wqh);
}

static __inline__ void
wake_up_all(void *wqh) {
	wakeup(wqh);
}

static __inline__ void
wake_up_interruptible(void *wqh) {
	wakeup(wqh);
}

static __inline__ void
wake_up_interruptible_all(void *wqh) {
	wakeup(wqh);
}

/* file drm_fops.c, function drm_cpu_valid() */
/* boot_cpu_data.x86 appears to be an int sometimes 3 */

/* defined for DragonFly BSD in sys/sys/poll.h */
/* #define POLLIN      0x0001 */
/* #define POLLRDNORM  0x0040 */

#define _IOC_NR(n) ((n) & 0xff)

/* file drm_drv.c, function drm_ioctl() */
#define _IOC_SIZE(cmd) sizeof(unigned long)

/* Appears to be used nowhere */
struct sigset_t {
	int placeholder;
};

/* file ttm/ttm_lock.c, function __ttm_read_lock() */
/* UNIMPLEMENTED */
static __inline__ void
send_sig(uint32_t signal, DRM_CURRENT_T cur, uint32_t flags) {
	;
}

typedef struct proc *DRM_PROCESS_T;

/* file ttm/ttm_lock.c, function __ttm_read_lock() */
static __inline__ void
DRM_SEND_SIG(uint32_t signal, DRM_PROCESS_T proc, uint32_t flags) {
	if (proc != NULL)
		ksignal(proc, signal);
}

/* file ttm/ttm_tt.c, function ttm_tt_swapin.c */
static __inline__ void
preempt_disable(void) {
	;
}

static __inline__ void
preempt_enable(void) {
	;
}

/**********************************************************
 * kref reference counting                                *
 **********************************************************/

/* file ttm_object.c, function ttm_object_file() */
struct kref {
	uint32_t refcount;
};

/* file ttm_object.c, function ttm_base_object_init() */
static __inline__ void
kref_init(struct kref *kref) {
	atomic_set_int(&kref->refcount, 1);
}

/* file ttm_object.c, function ttm_object_file_ref() */
static __inline__ void
kref_get(struct kref *kref) {
	atomic_add_int(&kref->refcount, 1);
}

/* file ttm_object.c, function ttm_object_file_ref() */
static __inline__ void
kref_put(struct kref *kref, void (*release)(struct kref *kref)) {
	atomic_subtract_int(&kref->refcount, 1);
	if (0 >= kref->refcount) {
		(*release)(kref);
	}
}

void default_kref_release(struct kref *kref);

/*
 * kobject
 */

/* ttm/ttm_memory.c */
struct kobject {
	struct kref kref;
	struct kobj_type *ktype;
	struct kobject *parent;
	const char *fmt;
};

/* file ttm/ttm_memory.c,
 * static structs such as ttm_mem_sys */
struct attribute {
	char *name;
	uint32_t mode;
};

/* file ttm/ttm_memory.c, static struct such as ttm_mem_zone_ops */
struct sysfs_ops {
	ssize_t (*show)(
		struct kobject *kobj,
		struct attribute *attr,
		char *buffer
	);
	ssize_t (*store)(
		struct kobject *kobj,
		struct attribute *attr,
		const char *buffer,
		size_t size
	);
};

/* file ttm/ttm_memory.c, static struct such as ttm_mem_zone_kobj_type */
struct kobj_type {
	void (*release) (struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
};

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_init() */
static __inline__ void
kobject_init(struct kobject *kobj, struct kobj_type *type) {
	kref_init(&kobj->kref);
	kobj->ktype = type;
}

/* file ttm/ttm_memory.c, function ttm_mem_init_kernel_zone() */
static __inline__ int
kobject_init_and_add(
	struct kobject *zone,
	struct kobj_type *type,
	struct kobject *glob,
	const char *name
) {
	kobject_init(zone, type);
	zone->parent = glob;
	zone->fmt = name;
	return 0;
}

/* file ttm/ttm_memory.c, static struct such as ttm_mem_zone_kobj_type */
static __inline__ void
kobject_put(struct kobject *kobj) {
	kref_put(&kobj->kref, default_kref_release);
}

/* file ttm_memory.c, function ttm_mem_global_release() */
/* UNIMPLEMENTED */
static __inline__ void
kobject_del(struct kobject *kobj) {
	;
}

/* file i915/i915_irq.c, function i915_error_work_func() */
#define KOBJ_CHANGE 0x01

static __inline__ void
kobject_uevent_env(struct kobject *kobj, uint32_t flags, char *event[]) {
	;
}

/*
 * Tasks
 */

/* file i915_gem.c, function i915_gem_wait_for_pending_flip() */

#define TASK_RUNNABLE		0x01
#define TASK_INTERRUPTIBLE	0x02

struct DRM_WAIT_STRUCT {
	int placeholder;
};

typedef struct DRM_WAIT_STRUCT	DRM_WAIT_T;

#define DEFINE_WAIT(wait)	struct DRM_WAIT_STRUCT wait = {0};

static __inline__ void
prepare_to_wait(
	wait_queue_head_t *queue,
	DRM_WAIT_T *wait,
	int flags
) {
	;
}

static __inline__ void
finish_wait(
	wait_queue_head_t *queue,
	DRM_WAIT_T *wait
) {
	;
}

struct work_struct {
	struct task task;
	void (*work_fn)(struct work_struct *work);
};

/* file ttm_bo_c, function ttm_bo_cleanup_refs() */
struct delayed_work {
	struct work_struct work;
	struct callout callout;
	unsigned long delay;
	struct taskqueue *tq;
	int cancel;
};

#define DRM_DELAYED_WORK delayed_work 

void convert_work(void *context, int pending);

/* file intel_display.c, function intel_crtc_page_flip() */
#define INIT_WORK(pwork, funct)                                      \
	do {                                                         \
		TASK_INIT(&(pwork)->task, 0, convert_work, (pwork)); \
		(pwork)->work_fn = (funct);                          \
	}                                                            \
	while (0)

/* file intel_display.c, function intel_crtc_page_flip() */
#define INIT_DELAYED_WORK(pwork, funct)                                          \
	do {                                                                     \
		TASK_INIT(&(pwork)->work.task, 0, convert_work, &(pwork)->work); \
		(pwork)->work.work_fn = (funct);                                 \
		callout_init(&(pwork)->callout);                                 \
		(pwork)->delay = 0;                                              \
		(pwork)->cancel = 0;                                             \
	}                                                                        \
	while (0)

/* file ttm_memory.c, function ttm_mem_global_reserve() */

#define workqueue_struct  taskqueue

/* file ttm_memory.c, function ttm_mem_global_init() */
/* context should be a pointer to the taskqueue pointer */
static __inline__ struct workqueue_struct *
DRM_CREATE_WORKQUEUE(const char *name, void *context) {
	struct taskqueue *tsq = taskqueue_create(name, M_WAITOK,
		taskqueue_thread_enqueue, context);
	if (tsq == NULL) {
		goto failalloc;
	}
	if (taskqueue_start_threads(&tsq, 1, TDPRI_KERN_DAEMON, -1,
		"%s taskq", "drmstq")) {
		goto failthread;
	}
	return (tsq);

failthread:
	taskqueue_free(tsq);
	return NULL;

failalloc:
	return NULL;
}

/* file ttm_memory.c, function ttm_mem_global_init() */
/* context should be a pointer to the taskqueue pointer */
static __inline__ struct workqueue_struct *
DRM_CREATE_SINGLETHREAD_WORKQUEUE(const char *name, void *context) {
	struct taskqueue *tsq = taskqueue_create(name, M_WAITOK,
		taskqueue_thread_enqueue, context);
	if (tsq == NULL) {
		goto failalloc;
	}
	if (taskqueue_start_threads(&tsq, 1, TDPRI_KERN_DAEMON, -1,
		"%s taskq", "drmstq")) {
		goto failthread;
	}
	return (tsq);

failthread:
	taskqueue_free(tsq);
	return NULL;

failalloc:
	return NULL;
}

/* file ttm_memory.c, function ttm_mem_global_init() */
static __inline__ struct workqueue_struct *
create_singlethread_workqueue(const char *name) {
	return NULL;
}

/* Insert delayed_work onto workqueue after a delay */
void call_delayed(void *arg);

/* file radeon_pm.c, function radeon_pm_compute_clocks() */
static __inline__ int
queue_delayed_work(
	struct workqueue_struct *wq,
	struct delayed_work *work,
	unsigned long delayed 
) {
	work->tq = wq;
	callout_reset(&work->callout, delayed, call_delayed, work);
	return 0;
}

/* file ttm_memory.c, function ttm_check_swapping() */
/* file intel_display.c, function intel_gpu_idle_timer() */
/* return value of queue_work does not appear to be used
 * but apparently is supposed to be nonzero if normal return,
 * 0 if already queued
 */
static __inline__ int
queue_work(struct workqueue_struct *queue, struct work_struct *work) {
	return taskqueue_enqueue(queue, &work->task);
}

/* file ttm_memory.c, function ttm_mem_global_release() */
static __inline__ void 
flush_workqueue(struct workqueue_struct *queue) {
#if 0
	taskqueue_run(queue);
#endif
	;
}

/* file ttm_memory.c, function ttm_mem_global_release() */
static __inline__ void 
destroy_workqueue(struct workqueue_struct *swap_queue) {
	taskqueue_free(swap_queue);
}

/* file ttm_bo_c, function ttm_bo_lock_delayed_workqueue() */
/* file i915_gem.c */
static __inline__ int
cancel_delayed_work_sync(struct delayed_work *work) {
	work->cancel = 1;
	taskqueue_drain(work->tq, &work->work.task);
	work->cancel = 0;
	return 0;
}

/* defined out: file drm_fb_helper.c, function drm_fb_helper.sysrq() */
/* intel_display.c, function intel_finish_page_flip() */
static __inline__ int
schedule_work(struct work_struct *work) {
	return taskqueue_enqueue(taskqueue_swi, &work->task);
}

/* file ttm_bo_c,
 * function ttm_bo_cleanup_refs() */
static __inline__ int
schedule_delayed_work(
    struct delayed_work *work,
    unsigned long delayed 
) {
	work->tq = taskqueue_swi;
	callout_reset(&work->callout, delayed, call_delayed, work);
	return 0;
}

/* file ttm_bo_c, function ttm_vm_fault() */
static __inline__ int
set_need_resched(void) {
	return 0;
}

/* file ttm_bo_c, function ttm_bo_device_release() */
/* file radeon_pm.c, function radeon_set_pm_method() */
/* file radeon_pm.c, function radeon_pm_compute_clocks() */
static __inline__ int
cancel_delayed_work(struct delayed_work *wq) {
	return 0;
}

/* file ttm_bo_c, function ttm_bo_device_release() */
static __inline__ int
flush_scheduled_work(void) {
	return 0;
}

/* drm_crtc_helper.c, function output_poll_output() */
struct slow_work {
	int placeholder;
};

/* drm_crtc.h, struct drm_mode_config, field output_poll_slow_work */
/* drm_crtc_helper.c, function output_poll_execute() */
struct delayed_slow_work {
	struct slow_work work;
};

/* drm_crtc_helper.c, struct output_poll_ops */
struct slow_work_ops {
	void (*execute)(struct slow_work *work);
};

/* drm_crtc_helper.c, function output_poll_execute() */
static __inline__ int
delayed_slow_work_enqueue(struct delayed_slow_work *delayed_work, uint32_t flags) {
	return 0;
}

#if 0
/* drm_crtc_helper.c, function output_poll_execute() */
static __inline__ int
slow_work_register_user(struct module *thisModule) {
	return 0;
}

/* drm_crtc_helper.c, function output_poll_fini() */
static __inline__ int
slow_work_unregister_user(struct module *thisModule) {
	return 0;
}
#endif

/* drm_crtc_helper.c, function drm_kms_helper_poll_init() */
static __inline__ int
delayed_slow_work_init(struct delayed_slow_work *delayed_work, struct slow_work_ops *ops) {
	return 0;
}

/* drm_crtc_helper.c, function drm_kms_helper_poll_fini() */
static __inline__ int
delayed_slow_work_cancel(struct delayed_slow_work *delayed_work) {
	return 0;
}

/* drm_fb_helper.c, struct sysrq_drm_fb_helper_restore_op */
struct tty_struct {
	int placeholder;
};

/* drm_fb_helper.c, struct sysrq_drm_fb_helper_restore_op */
struct sysrq_key_op {
	void (*handler)(int dummy1, struct tty_struct *dummy3);
	const char *help_msg;
	const char *action_msg;
};

/* drm_fb_helper.c, function drm_fb_helper_fini() */
static __inline__ int
register_sysrq_key(char v, struct sysrq_key_op *op) {
	return 0;
}

/* drm_fb_helper.c, function drm_fb_helper_fini() */
static __inline__ int
unregister_sysrq_key(char v, struct sysrq_key_op *op) {
	return 0;
}

/* file ttm/ttm_page_alloc.c, function ttm_pool_manager() */
/* file i915/i915_gem.c, function i915_gem_shrinker_init() */
struct shrinker {
	int (*shrink)(int shrink_pages, gfp_t gfp_mask);
	unsigned long seeks;
};

/* file ttm/ttm_page_alloc.c, function ttm_pool_mm_shrink_init() */
static __inline__ void
register_shrinker(struct shrinker *shrink) {
	;
}

static __inline__ void
unregister_shrinker(struct shrinker *shrink) {
	;
}

#define DEFAULT_SEEKS  0x0001

/**********************************************************
 * VIRTUAL MEMORY                                         *
 **********************************************************/

/*
 * pages
 */

/*
 * PAGE_ALIGN defined in legacy drmP.h in turn
 * depends on round_page from <machine/param.h>
 */

#define PAGE_ALIGN(addr) round_page(addr)

/* i915_gem.c, function slow_shmem_bit17_copy() */
#define DRM_ALIGN(x, y)	roundup(x, y)

/* i915_gem.c, function i915_gem_fault() */
typedef unsigned long	pgoff_t;

/* file ttm/ttm_memory.c, function ttm_mem_zone_show(),
 * Are zones the number of pages divided by 2^10?
 */

struct page {
/* file ttm/ttm_page_alloc.c, function ttm_handle_caching_state() */
	struct list_head lru;
};

typedef vm_page_t	DRM_PAGE_T;

/* file ttm/ttm_tt.c, function ttm_tt_swapin() */
struct address_space {
	int placeholder;
};

/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
/* file ttm/ttm_tt.c, function __ttm_tt_get_page() */
static __inline__ int
PageHighMem(struct page *page) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_free_user_pages() */
static __inline__ int
PageReserved(struct page *page) {
	return 0;
}

/* file drm_pci.c, function drm_pci_alloc() */
/* file drm_scatter.c, function drm_sg_alloc() */
static __inline__ void
SetPageReserved(struct page *page) {
	;
}

/* file drm_pci.c, function __drm_pci_free() */
static __inline__ void
ClearPageReserved(struct page *page) {
	;
}

/* file i915/i195_gem.c */
static __inline__ void
SetPageDirty(struct page *page) {
	;
}

/* file ttm/ttm_page_alloc.c, function ttm_handle_caching_state() */
/* file ttm/ttm_bo.c, function ttm_bo_global_kobj_release() */
/* file ttm/ttm_tt.c, function ttm_tt_free_alloced_pages() */
/* file vmwgfx_gmr.c, function vmw_gmr_free_descriptors() */
static __inline__ void
__free_page(struct page *page) {
	;
}

/* file ttm/ttm_bo.c, function ttm_bo_global_init() */
/* file ttm/ttm_page_alloc.c, function ttm_alloc_new_pages() */
/* file ttm/ttm_tt.c, function ttm_tt_alloc_page() */
/* file vmwgfx_gmr.c, function vmw_gmr_build_descriptors() */
/* file radeon_device.c, function radeon_dummy_page_init() */
static __inline__ struct page *
alloc_page(int gfp_flags) {
	return NULL;
}

/* file ttm/ttm_tt.c, function ttm_free_user_pages() */
static __inline__ int
put_page(struct page *page) {
	return 0;
}

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
/* file drm_scatter.c, function drm_sg_alloc() */
static __inline__ unsigned long
page_address(struct page *page) {
	return 0;
}

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
static __inline__ void
clear_page(unsigned long handle) {
	;
}

/* file drm_pci.c, function __drm_pci_free() */
static __inline__ struct page *
virt_to_page(unsigned long addr) {
	return (struct page *)NULL;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
static __inline__ void
mark_page_accessed(struct page *to_page) {
	;
}

/* file i915_gem.c, i915_gem_object_get_pages() */
/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
static __inline__ void
page_cache_release(struct page *to_page) {
	;
}

static __inline__ void
drm_page_cache_release(DRM_PAGE_T page) {
	vm_page_unhold(page);
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
/* file i915/i915_gem_tiling.c, function i915_gem_object_do_bit_17_swizzle() */
static __inline__ void
set_page_dirty(struct page *to_page) {
	;
}

static __inline__ void
drm_set_page_dirty(DRM_PAGE_T page) {
	vm_page_dirty(page);
}

/* file ttm/ttm_tt.c, function ttm_tt_free_user_pages() */
static __inline__ void
set_page_dirty_lock(struct page *page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_page_caching() */
static __inline__ int
set_pages_wb(struct page *p, uint32_t val) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_page_caching() */
static __inline__ int
set_pages_uc(struct page *p, uint32_t val) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_page_caching() */
static __inline__ int
set_memory_wc(unsigned long page_address, uint32_t val) {
	return 0;
}

/* file radeon_gart.c, function radeon_gart_table_ram_alloc() */
static __inline__ void
set_memory_uc(unsigned long ptr, unsigned long size) {
	;
}

/* file radeon_gart.c, function radeon_gart_table_ram_free() */
static __inline__ void
set_memory_wb(unsigned long ptr, unsigned long size) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapin() */
/* Fourth argument NULL all calls in drm */
static __inline__ struct page *
read_mapping_page(struct address_space *swap_space, int i, void *ptr) {
	return NULL;
}

/* file i915_gem.c, function i915_gem_object_get_pages() */
static __inline__ int
mapping_gfp_mask(struct address_space *mapping) {
	return 0;
}

/* file i915_gem.c, function i915_gem_object_get_pages() */
static __inline__ struct page *
read_cache_page_gfp(
	struct address_space *mapping,
	int i,
	int gfp_mask)
{
	return NULL;
}

/* file ttm/ttm_bo.c, function ttm_bo_unmap_virtual() */
/* UNIMPLEMENTED */
static __inline__ void
unmap_mapping_range(
    struct address_space *dev_mapping,
    loff_t offset,
    loff_t holelen,
    uint32_t value
){
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
struct mm_struct {
	struct rw_semaphore mmap_sem;
};

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
struct task_struct {
	struct mm_struct *mm;
};

/* file i915_gem.c */
static __inline__ struct mm_struct *
DRM_GET_CURRENT_MM(void) {
	return NULL;
}

static __inline__ struct task_struct *
DRM_GET_CURRENT(void) {
	return NULL;
}

/* file i915_gem.c, function i915_gem_wait_for_pending_flip() */
static __inline__ int
signal_pending(struct task_struct *currenttask) {
	return 0;
}

/* file i915_gem.c */
/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
static __inline__ int
get_user_pages(
	struct task_struct * tsk,
	struct mm_struct * mm,
	unsigned long start,
	unsigned long num_pages,
	uint32_t write_flag,
	uint32_t isZero,
	struct page ** pages,
	void * isNULL
) {
	return 1;
}

static __inline__ int
drm_get_user_pages(
	unsigned long start,
	unsigned long num_pages,
	uint32_t vmprot,
	DRM_PAGE_T *pages
) {
/* For DragonFly BSD see xio_init_ubuf() in kern_xio.c */
	vm_offset_t addr = trunc_page((vm_offset_t)start);
	vm_page_t m = NULL;
	int error;
	int i;
	int pinned_pages = 0;
	for (i = 0; i < num_pages; i++) {
		m = vm_fault_page_quick(addr, vmprot, &error);
		if (m == NULL) {
			return pinned_pages;
		}
		pages[i] = m;
		addr += PAGE_SIZE;
		pinned_pages++;
	}
	return pinned_pages;
}

typedef struct lwbuf DRM_LWBUF_T;

/* file i915_gem_tiling.c, function i915_gem_swizzle_page() */
static __inline__ char *
drm_kmap(DRM_PAGE_T page, DRM_LWBUF_T *plwb_cache, DRM_LWBUF_T **plwb) {
	*plwb = lwbuf_alloc(page, plwb_cache);
	return (char *)lwbuf_kva(*plwb);
}

static __inline__ void
drm_kunmap(void *vaddr, DRM_LWBUF_T *lwb) {
	lwbuf_free(lwb);
}

static __inline__ char *
drm_kmap_atomic(DRM_PAGE_T page, DRM_LWBUF_T *plwb_cache, DRM_LWBUF_T **plwb) {
	*plwb = lwbuf_alloc(page, plwb_cache);
	return (char *)lwbuf_kva(*plwb);
}

static __inline__ void
drm_kunmap_atomic(void *vaddr, DRM_LWBUF_T *lwb) {
	lwbuf_free(lwb);
}

static __inline__ vm_paddr_t
drm_page_to_phys(DRM_PAGE_T page) {
	return page->phys_addr;
}

/* file i915_gem.c, function slow_shmem_bit17_copy() */
static __inline__ int
page_to_phys(struct page *gpu_page) {
	return 0;
}

/*
 * sysinfo
 */

/* file ttm/ttm_memory.c, function ttm_mem_init_highmem_zone() */
struct sysinfo {
    uint64_t totalram;
    uint64_t totalhigh;
    uint64_t mem_unit;
};

/* file ttm/ttm_memory.c, function ttm_mem_global_init() */
static __inline__ void
si_meminfo(struct sysinfo *si) {
	;
}
/**********************************************************
 * SYNCHRONIZATION                                        *
 **********************************************************/

/* file drm_cache.c, function drm_cache_flush_clflush() */
/* DragonFly BSD only runs so far on i386 and x64_86 */
#define CONFIG_X86 1

/* file drm_fops.c, function drm_stub_open() */
static __inline__ void
lock_kernel(void) {
	get_mplock();
}

/* file drm_fops.c, function drm_stub_open() */
static __inline__ void
unlock_kernel(void) {
	rel_mplock();
}

/* file drm_cache.c, function drm_cache_flush_clflush() */
/* Previous version of drmP.h for DRM_MEMORYBARRIER() */
#if 0
#if defined(__i386__)
#define mb()				__asm __volatile( \
					"lock; addl $0,0(%%esp)" : : : "memory");
#elif defined(__alpha__)
#define mb()				alpha_mb();
#elif defined(__x86_64__)
#define mb()				__asm __volatile( \
					"lock; addl $0,0(%%rsp)" : : : "memory");
#endif
#endif

/* file vmwgfx_fifo.c, function vmw_fifo_init() */
#ifndef mb
#define mb()   cpu_mfence()
#endif

/* file vmwgfx_fifo.c, function vmw_fifo_init() */
#ifndef wmb
#define wmb()  cpu_sfence()
#endif

#if 0
/* file drm_cache.c, function drm_clflush_pages() */
#define wbinvd()	__asm __volatile( \
			"wbinvd");
#endif

#if 0
/* file drm_cache.c, function drm_clflush_pages() */
static __inline__ void
clflush(uint32_t location) {
	;
}
#endif

/* file drm_cache.c, function drm_clflush_pages() */
#define cpu_has_clflush 1

/* file drm_cache.c, function drm_clflush_pages() */
static __inline__ int
on_each_cpu(void (*handler)(void *data), void *data, uint32_t flags) {
	return 1;
}

/**********************************************************
 * timer                                                  *
 **********************************************************/

/*
 * There is a problem that a callout requires void * arguments
 * whereas a Linux timer_list requires unsigned long arguments
 * (arguments which are then cast to pointers)
 */

/* &dev->vblank_disable_timer is being used in drm_irq.c */
#define timer_list callout

/* file drm_drv.c, function drm_lastclose() */
static __inline__ void
init_timer(struct timer_list *timer){
	;
}

/* file drm_irq.c, function drm_vblank_init() */
/* CHANGE vblank_disable_fn() in drm_irq.c to void * arg */
/* CHANGE i915_hangcheck_elapsed() in i915_irq.c to void * arg */
/* CHANGE r600_audio_update_hdmi() in r600_audio.c to void * arg */
/* CHANGE intel_gpu_idle_timer() in intel_display.c to void * arg */
/* CHANGE intel_crtc_idle_timer() in intel_display.c to void * arg */
/* CHANGE via_dmablit_timer() in via_dmablit.c to void * arg */
static __inline__ void
setup_timer(
	struct timer_list *timer,
	void (*func)(void *arg),
	void *arg
){
	;
}

/* file drm_irq.c, function drm_vblank_put() */
static __inline__ void
mod_timer(struct timer_list *timer, unsigned long delta){
	;
}

/* file drm_drv.c, function drm_lastclose() */
static __inline__ void
del_timer(struct timer_list *timer){
	;
}

/* file i915/intel_display.c */
static __inline__ void
del_timer_sync(struct timer_list *timer){
	;
}

/**********************************************************
 * I/O                                                    *
 **********************************************************/

/*
 * PAGE PROTECTION
 */

/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
typedef unsigned long pgprot_t; /* UNIMPLEMENTED */

/* file drm_info.c, function drm_vma_info() */
/* file drm_vm.c, function drm_mmap_lock() needs to return lvalue? */
/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
/* UNIMPLEMENTED */
#define pgprot_val(prot) prot

/* file drm_gem.c, function drm_gem_mmap() */
/* file ttm/ttm_bo_util.c, function ttm_io_prot() */
/* UNIMPLEMENTED */
static __inline__ pgprot_t
pgprot_writecombine(pgprot_t prot) {
	return 0;
}

/* file ttm/ttm_bo_util.c, function ttm_io_prot() */
/* UNIMPLEMENTED */
static __inline__ pgprot_t
pgprot_noncached(pgprot_t prot) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapin() */
#define KM_USER0 0x0001
#define KM_USER1 0x0002
#define KM_IRQ0  0x0004

/* file ttm/ttm_bo_util.c, function ttm_io_prot() */
#define PAGE_KERNEL 0x0001

/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
static __inline__ void *
kmap_atomic_prot(struct page *page, uint32_t flag, pgprot_t prot)
{
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
static __inline void *
kmap(struct page *page) {
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
static __inline void *
kmap_atomic(struct page *page, int flags) {
	return (void *)NULL;
}

static __inline__ void
kunmap(struct page *page) {
	;
}

static __inline__ void
kunmap_atomic(void *dst, uint32_t flag) {
	;
}

#if 0
/* file i915_gem.c, function fast_user_write() */
struct io_mapping {
	int placeholder;
};
#endif

struct io_mapping;

/* file i915_dma.c, function i915_driver_load() */
static __inline__ struct io_mapping *
io_mapping_create_wc(unsigned long base, unsigned long offset) {
#if 0 /* variant to iomap only on __x86_64__ */
	return pmap_mapdev(base, offset);
#endif
	return (void *)base;
}

/* file i915_dma.c, function i915_driver_unload() */
static __inline__ void
drm_io_mapping_free(struct io_mapping *mapping, unsigned long size) {
#if 0 /* variant iomapped possibly only on __x86_64__ */
	pmap_unmapdev((vm_offset_t)base, size);
#endif
	;
}

/* file i915_gem.c, function fast_user_write() */
/* file i915_gem.c, function slow_kernel_write() */
/* file intel_overlay.c, function intel_overlay_map_regs_atomic() */
static __inline__ void *
io_mapping_map_atomic_wc(
	struct io_mapping *mapping,
	unsigned long page_base
) {
	return (void *)((unsigned long)mapping + page_base);
#if 0
	return kmalloc(PAGE_SIZE, M_TEMP, M_WAITOK | M_ZERO);
#endif
}

/* file i915_gem.c, function fast_user_write() */
/* file i915_gem.c, function slow_kernel_write() */
static __inline__ void
io_mapping_unmap_atomic(
	void *vaddr
) {
	;
#if 0
	kfree(vaddr, M_TEMP);
#endif
}

/*
 * Kernel to / from user
 */

#define VERIFY_READ  VM_PROT_READ
#define VERIFY_WRITE VM_PROT_WRITE

/* file drm_ioc32.c, function compat_drm_version() */
/* Allocate on user stack? */
static __inline__ void *
compat_alloc_user_space(size_t size) {
	return NULL;
}

/* file i915_gem.c, function i915_gem_gtt_pwrite_fast() */
static __inline__ int
access_ok(int flags, void *ptr, int size) {
	return useracc(__DECONST(caddr_t, ptr), size, flags);
}

/* file drm_crtc.c, function drm_mode_setcrtc() */
#define get_user(dest, src)  copyin(&dest, src, sizeof(dest))

/* file drm_crtc.c, function drm_mode_setcrtc() */
#define __get_user(dest, src)  copyin(&dest, src, sizeof(dest))

/* file drm_crtc.c, function drm_mode_getresources() */
#define put_user(src, dest)  copyout(&src, dest, sizeof(src))

/* file drm_ioc32.c, function compat_drm_version() */
#define __put_user(src, dest)  copyout(&src, dest, sizeof(src))

/* file ttm/ttm_bo_vm.c, function ttm_bo_io() */
/* file drm_bufs.c, function drm_freebufs() */
/* legacy drmP.h DRM_COPY_FROM_USER() */
/* file drm_crtc.c, function drm_mode_gamma_set_ioctl() */
static __inline__ int
copy_from_user(
	void *kaddr,
	const void __user *uaddr,
	size_t iosize
) {
	return copyin(uaddr, kaddr, iosize);
}

/* file ttm/ttm_bo_vm.c, function ttm_bo_io() */
/* file drm_bufs.c, function drm_mapbufs() */
/* legacy drmP.h DRM_COPY_TO_USER() */
/* file drm_crtc.c, function drm_mode_getblob_ioctl() */
static __inline__ int
copy_to_user(
	void *uaddr,
	const void *kaddr,
	size_t iosize
) {
	return copyout(kaddr, uaddr, iosize);
}

/* file i915_gem.c, function fast_shmem_read() */
static __inline__ int
__copy_to_user_inatomic(
	void *uaddr,
	void *kaddr,
	int iosize
) {
	return copyout(kaddr, uaddr, iosize);
}

/* file i915_gem.c, function slow_kernel_write() */
static __inline__ int
__copy_from_user_inatomic_nocache(
	void *kaddr,
	void *uaddr,
	int iosize
) {
	return copyin(uaddr, kaddr, iosize);
}

/* file i915_gem.c, function slow_kernel_write() */
static __inline__ int
__copy_from_user_inatomic(
	void *kaddr,
	void *uaddr,
	int iosize
) {
	return copyin(uaddr, kaddr, iosize);
}

/* file drm_bufs.c, function drm_addbufs_agp() */
/* memset() declared in sys/libkern.h on DragonFly */
#if 0
static __inline__ void
memset(void * handle, uint32_t zero, int size) {
	;
}
#endif

/* file drm_bufs.c, function drm_addbufs_pci() */
/* memcpy() declared in sys/systm.h on DragonFly */
#if 0
static __inline__ void *
memcpy(void *src, void *dst, size_t size) {
	return NULL;
}
#endif

/* file ati_pcigart.c, function drm_ati_pcigart_init() */
/* directive __iomem */
static __inline__ void
memset_io(void * handle, uint32_t value, int size) {
	memset(handle, value, size);
}

/* vmwgfx_fifo.c, function vmw_fifo_res_copy() */
/* QUESTION: is dst src guaranteed non-overlapping for memcpy? */
static __inline__ void
memcpy_fromio(void *dst, void *src, unsigned long size) {
	memcpy(dst, src, size);
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_page() */
/* vmwgfx_fifo.c, function vmw_fifo_res_copy() */
/* QUESTION: is dst src guaranteed non-overlapping for memcpy? */
static __inline__ void
memcpy_toio(void *dst, void *src, unsigned long size) {
	memcpy(dst, src, size);
}

/*
 * I/O and virtual memory
 */

/* file ttm_bo.c, function ttm_vm_fault() */
/* file radeon_ttm.c, function radeon_ttm_fault() */
#define VM_FAULT_NOPAGE 0x0001
#define VM_FAULT_SIGBUS 0x0002
#define VM_FAULT_OOM    0x0004

/* file ttm_bo_c, function ttm_bo_mmap() */
#define VM_RESERVED     0x0008
#define VM_IO           0x0010
#define VM_MIXEDMAP     0x0020
#define VM_DONTEXPAND   0x0040

/* file drm_memory.c, function agp_remap() */
#define VM_IOREMAP      0x0080
#define VM_WRITE        0x0100
#define VM_MAYWRITE     0x0200

/*file drm_gem.c, function drm_gem_object_init() */
#define VM_NORESERVE    0x0400
#define VM_PFNMAP       0x0800

/* file i915_gem.c, function i915_gem_shrink() */
extern int sysctl_vfs_cache_pressure;

/* file ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
/* file vmwgfx_fifo.c, function vmw_fifo_vm_fault() */
struct vm_area_struct {
/* file drm_vm.c, function drm_mmap_locked() */
	pgprot_t vm_page_prot;
	uint32_t vm_flags;
/* file drm_vm.c, function drm_do_vm_fault() */
	struct file *vm_file;
/* file drm_vm.c, function drm_do_vm_fault() */
/* file drm_gem.c, function drm_gem_mmap() */
/* file radeon_mmap.c, function radeon_mmap() */
	unsigned long vm_pgoff;
/* file vmwgfx_fifo.c, function vmw_fifo_vm_fault() */
	unsigned long vm_start;
/* file drm_vm.c, function drm_do_shm_close() */
	unsigned long vm_end;
/* file drm_vm.c, function drm_do_shm_fault() */
/* file drm_gem.c, function drm_gem_vm_close() */
/* file radeon_ttm.c, function radeon_ttm_fault() */
	void *vm_private_data;
	const struct vm_operations_struct *vm_ops;
};

/* file i915_gem.c, function i915_gem_fault() */
#define FAULT_FLAG_WRITE  0x0001

/* file drm_vm.c, function drm_do_vm_fault() */
/* file vmwgfx_fifo.c, function vmw_fifo_vm_fault() */
struct vm_fault {
	void *virtual_address;
	struct page* page;
/* file i915_gem.c, function i915_gem_fault() */
	int flags;
};

/* file drm_vm.c, struct drm_vm_ops */
/* file i915_drv.c, struct i915_gem_vm_ops */
/* file radeon_ttm.c, function radeon_ttm_fault() */
/* file vmwgfx_fifo.c, struct vm_ops */
struct vm_operations_struct {
	int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf);
	void (*open)(struct vm_area_struct *vma);
	void (*close)(struct vm_area_struct *vma);
};

/* file ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
static __inline__ int
vm_insert_mixed(
	struct vm_area_struct *vma,
	unsigned long address,
	unsigned long pfn
) {
	return 0;
}

/* file i915_gem.c, function i915_gem_fault() */
/* file vmwgfx_fifo.c, function vmw_fifo_vm_fault() */
/* pfn stands for "page frame number" */
static __inline__ int
vm_insert_pfn(
	struct vm_area_struct *vma,
	unsigned long address,
	unsigned long pfn
) {
	return 0;
}

/*
 * Physical memory
 */

/* file drm_vm.c, function drm_do_vm_fault () */
static __inline__ void
get_page(struct page *page) {
	;
}

/* file drm_vm.c, function drm_do_shm_fault () */
static __inline__ struct page *
vmalloc_to_page(void *handle) {
	return NULL;
}

/* file drm_vm.c, function drm_do_vm_fault () */
static __inline__ int
page_count(struct page *page) {
	return 0;
}

/*
 * MTRR
 */

/* It appears that DRM_MTRR_WC is always used as the flag */
#define MTRR_TYPE_WRCOMB MDF_WRITECOMBINE

#if 0
static inline int mtrr_cookie(struct mem_range_desc *mrd) {
	int nd = 0;
	int ndesc;
	int error;
	struct mem_range_desc *md;
	struct mem_range_desc *cand;
	int match = -1;
	int i;

	error = mem_range_attr_get(mrd, &nd);
	if (error) {
		kprintf("ERROR (%d) mem_range_attr_get ZERO mtrr regions configured\n", error);
		return -error;
	}
	ndesc = nd;
	if (ndesc <= 0) {
		kprintf("ERROR (%d) mem_range_attr_get claimed (%d) mtrr regions configured\n", error, ndesc);
		return -1;
	}
	md = kmalloc(ndesc * sizeof(struct mem_range_desc), M_TEMP, M_WAITOK);
	if (!md) {
		return -ENOMEM;
	}
	error = mem_range_attr_get(md, &nd);
	if (error) {
		kprintf("ERROR (%d) mem_range_attr_get for offset (%016lx), size (%016lx)\n", error, mrd->mr_base, mrd->mr_len);
		kfree(md, M_TEMP);
		return -error;
	}
	cand = md;
	for (i = 0; i < ndesc; i++, cand++) {
		if ((mrd->mr_base == cand->mr_base) && (mrd->mr_len == cand->mr_len)) {
			match = i;
		}
	}
	kfree(md, M_TEMP);
	kprintf("mtrr_add reg (%d) for offset (%016lx), size (%016lx)\n", match, mrd->mr_base, mrd->mr_len);
	if (match < 0) {
		return match;
	}
	return match;
}
#endif

static __inline__ int
mtrr_add(
	unsigned long offset,
	unsigned long size,
	unsigned int flags,
	boolean_t flagsOne
) {
	int act;
	struct mem_range_desc mrdesc;
	int error;

	mrdesc.mr_base = offset;
	mrdesc.mr_len = size;
	mrdesc.mr_flags = flags;
	act = MEMRANGE_SET_UPDATE;
	strlcpy(mrdesc.mr_owner, "drm", sizeof(mrdesc.mr_owner));
	error = mem_range_attr_set(&mrdesc, &act);
	if (error) {
		kprintf("mtrr_add FAILED for offset (%016lx), size (%016lx), error (%d)\n", offset, size, error);
		if (error > 0) {
			return -error;
		}
		else {
			return error;
		}
	}
	kprintf("mtrr_add SUCCESS for offset (%016lx), size (%016lx)\n", offset, size);
	return error;
}

static __inline__ int
mtrr_del(
	int reg, /*unused */
	unsigned long base,
	unsigned long size
) {
	int act;
	struct mem_range_desc mrdesc;

	mrdesc.mr_base = base;
	mrdesc.mr_len = size;
	mrdesc.mr_flags = MDF_WRITECOMBINE;
	act = MEMRANGE_SET_REMOVE;
	strlcpy(mrdesc.mr_owner, "drm", sizeof(mrdesc.mr_owner));
	return mem_range_attr_set(&mrdesc, &act);
}

/*
 * mmap
 */

/* MAP_SHARED defined in sys/mman.h on DragonFly */

/* file drm_bufs.c, function drm_mapbufs() */
static __inline__ unsigned long
do_mmap(
	struct file *filp,
	uint32_t offset,
	unsigned long size,
	uint32_t protFlags,
	uint32_t mapFlags,
	unsigned long token
) {
	return 0;
}

/*
 * I/O and memory
 */

/* file drm_bufs.c, function drm_addmap_core() */
static __inline__ void *
ioremap(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_ioremap() */
/* file i915_gem.c, function i915_gtt_to_phys() */
static __inline__ void *
ioremap_wc(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_ioremap() */
static __inline__ void *
ioremap_nocache(unsigned long offset, unsigned long size) {
	return pmap_mapdev(offset, size);
}

static __inline__ void ioremapfree(void *handle, unsigned long size)
{
	pmap_unmapdev((vm_offset_t)handle, size);
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_iounmap() */
/* file drm_bufs.c, function drm_rmmap_locked() */
static __inline__ void
iounmap(void *virtual) {
	;
}

/* nouveau_drv.h */
#define ioread8(reg) (readb(reg))

/* nouveau_drv.h */
#define ioread16(reg) (readw(reg))

/* file vmwgfx_fifo.c, function vmw_fifo_is_full() */
/* file vmwgfx_irq.c, function vmw_fence_signaled() */
#define ioread32(reg) (readl(reg))

/* nouveau_drv.h */
#define iowrite8(value, reg) writeb(reg, value)

/* nouveau_drv.h */
#define iowrite16(value, reg) writew(reg, value)

/* file ttm/ttm_bo_util.c, function ttm_copy_io_page() */
#define iowrite32(value, reg) writel(reg, value)

/* file drm_vm.c, function drm_mmap_locked() */
static __inline__ pgprot_t
io_remap_pfn_range(
	struct vm_area_struct *vma,
	unsigned long vm_start,
	unsigned long offset,
	unsigned long end,
	pgprot_t vm_page_prot
) {
	return 0;
}

/* File ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
/* UNIMPLEMENTED */
static __inline__ unsigned long
page_to_pfn(struct page *page) {
	return 0;
}

/* file drm_vm.c, function drm_mmap_locked() */
static __inline__ pgprot_t
remap_pfn_range(
	struct vm_area_struct *vma,
	unsigned long vm_start,
	unsigned long pfn,
	unsigned long end,
	pgprot_t vm_page_prot
) {
	return 0;
}

/*
 * I/O with files and inodes
 */

/* file drm_fops.c, function drm_open() */
struct inode {
	struct address_space *i_mapping;
	struct DRM_INODE_IOP *i_op;
};

/* file i915_gem.c, function i915_gem_object_truncate() */
struct DRM_INODE_IOP {
	int (*truncate)(struct inode *inode);
};

/* file drm_fops.c, function drm_open() */
static __inline__ int
iminor(struct inode *inode) {
	return 0;
}

/* file drm_fops.c, function drm_stub_open() */
struct file_operations {
/* file drm_drv.c, struct drm_stub_fops */
	DRM_MODULE_T owner;
	int (*open)(struct inode *inode, struct file *file);
};

/* file drm_stub.c */
/* Substitite for struct class */
struct DRM_CLASS {
	int placeholder;
};

/* drmP.h drm_stub.h */
struct proc_dir_entry {
	int placeholder;
};

/* drmP.h drm_stub.h */
struct dentry {
	struct inode *d_inode;
};

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
struct DRM_FILE_PATH {
	struct dentry *dentry;
};

/* file drm_fops.c, function drm_open() */
struct file {
/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
	struct DRM_FILE_PATH f_path;
/* file drm_fops.c, function drm_stub_open() */
	struct file_operations *f_op;
/* file drm_fops.c, function drm_open_helper() */
	void *private_data;
/* file drm_fops.c, function drm_open_helper () */
	uint32_t f_flags;
};

/* file drm_gem.c, function drm_gem_object_alloc() */
/* file ttm/ttm_tt.c, function ttm_tt_destroy() */
static __inline__ void
fput(struct file *filp) {
	;
}

/* file drm_fops.c, function drm_stub_open() */
static __inline__ struct file_operations *
fops_get(struct file_operations *fops) {
	return (struct file_operations *)NULL;
}

/* file drm_fops.c, function drm_stub_open() */
static __inline__ void
fops_put(struct file_operations *fops) {
	;
}

/* file drm_drv.c, function drm_core_init() */
static __inline__ int
register_chrdev(
	uint32_t flags,
	const char *name,
	struct file_operations *fops
) {
	return 0;
}

/* file drm_drv.c, function drm_core_init() */
static __inline__ int
unregister_chrdev(
	uint32_t flags,
	const char *name
) {
	return 0;
}

/* file drm_fops.c, function drm_poll() */
struct poll_table_struct {
	int placeholder;
};

/* UNIMPLEMENTED */
static __inline__ void
poll_wait(
	struct file *filp,
	wait_queue_head_t *event_wait,
	struct poll_table_struct *wait
) {
	;
}

/* file drm_fops.c, function drm_fasync() */
struct fasync_struct {
	int placeholder;
};

static __inline__ int
fasync_helper(
	int fd,
	struct file *filp,
	int on,
	struct fasync_struct **buf_async
) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
static __inline__ struct file *
shmem_file_setup(char *name, unsigned long num_pages, uint32_t flags) {
	return (struct file *)NULL;
}
/* file drm_memory.c, function agp_remap() */
/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
static __inline__ void *
vmap(
	struct page **pages,
	size_t num_pages,
	uint32_t vm_flags,
	pgprot_t type
) {
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_ttm_page() */
static __inline__ void
vunmap(void *dst) {
	;
}

/* file ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
/* file drm_gem.c, function drm_gem_mmap() */
static __inline__ pgprot_t
vm_get_page_prot(uint32_t flags){
	return 0;
}

/*
 * General device abstraction
 */

/* file ttm_module.c, struct ttm_drm_class_device */

struct device_type {
    char *name;
};

struct device {
	struct kobject kobj;
	struct device_type *type;
	void (*release)(struct device *dev);
	struct device *parent;
};

/* file i915/intel_sdvo.c, function intel_sdvo_output_setup() */
static __inline__ int
device_is_registered(struct device *dev) {
	return 0;
}

/* file drm_edid.c, function do_get_edid() */
/*
 * Function actually takes
 *    struct device *dev,
 *    const char *format,
 *    variable number of arguments
 */
#define dev_warn(arg, ...) /* UNIMPLEMENTED */

/* file radeon_device.c, function radeon_vram_location() */
#define dev_info(arg, ...) /* UNIMPLEMENTED */

/* file ttm/ttm_module.c, function ttm_init() */
static __inline__ int
dev_set_name(struct device *device, char *name) {
	return 0;
}

/* file drm_stub.c, function drm_get_minor() */
/* minor generated by drm_get_minor_id for DRM_MINOR_RENDER
 * not in convenient range for BSD
 */
static __inline__ dev_t
MKDEV(int major, int minor) {
	return (major << 8) | (minor & 0x00FF) | ((minor & 0xFFFFFF00) << 8);
}

/* file drm_fops.c, function drm_fasync() */
static __inline__ long
old_encode_dev(dev_t device) {
	return 0;
}

/* file radeon_object.h, function radeon_bo_reserve() */
/* takes struct device *dev as first argument */
#define dev_err(arg, ...) /* UNIMPLEMENTED */

/* drm_crtc.h, struct drm_connector, field attr */
/* radeon_pm.c, function radeon_set_pm_method(), unused arg */
/* file radeon_pm.c, struct power_profile */
struct device_attribute {
	uint32_t perm;
	ssize_t (*get)(struct device *dev, struct device_attribute *attr, char *buf);
	ssize_t (*set)(struct device *dev, struct device_attribute *attr, char *buf, size_t count);
};

/* file radeon_pm.c, struct power_profile */
#define DEVICE_ATTR(name, perms, getter, setter) \
struct device_attribute dev_attr_##name { \
	.perm = perms; \
	.get = getter; \
	.set = setter; \
};
/* file radeon_pm.c, function radeon_pm_init() */
static __inline__ int
device_create_file(
	struct device *dev,
	struct device_attribute *attr
) {
	return 0;
}

/* file radeon_pm.c, function radeon_pm_fini() */
static __inline__ int
device_remove_file(
	struct device *dev,
	struct device_attribute *attr
) {
	return 0;
}

/**********************************************************
 * BUS AND DEVICE CLASSES                                 *
 **********************************************************/

/**********************************************************
 * DMA                                                    *
 **********************************************************/

typedef bus_addr_t dma_addr_t;

/* From legacy older version of drmP.h */

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : (1ULL<<(n)) - 1)
#endif

#if 0
/* file drm_pci.c, function __drm_pci_free() */
/* UNIMPLEMENTED */
static __inline__ void *
dma_alloc_coherent(
	struct device *dev,
	size_t size,
	dma_addr_t *busaddr,
	gfp_t flag
) {
	return NULL;
}

/* file drm_pci.c, function __drm_pci_free() */
/* UNIMPLEMENTED */
static __inline__ void
dma_free_coherent(
	struct device *dev,
	size_t size,
	void *vaddr,
	dma_addr_t busaddr
) {
	;
}
#endif

/**********************************************************
 * PCI                                                    *
 **********************************************************/

/* file ati_pcigart.c, function drm_ati_pcigart_cleanup() */
/* file radeon_gart.c, function radeon_gart_unbind() */
#define PCI_DMA_BIDIRECTIONAL 0x0001

/* file drm_vm.c, function drm_mmap_locked() */
#define PCI_VENDOR_ID_APPLE 0x0001

/* i915_drv.c */
#define PCI_ANY_ID            0xffff
#define PCI_CLASS_DISPLAY_VGA 0x0000
#define PCI_D3hot             0x0002

/* drmP.h drm_stub.h */
/* file drm_drv.c, function drm_init() */
struct pci_device_id {
	int vendor;
	int device;
	int subvendor;
	int subdevice;
	uint32_t class;
	uint32_t class_mask;
/* file drm_stub.c, function drm_get_dev() */
	unsigned long driver_data;
};

/* file drm_drv.c, function drm_init() */
struct pci_driver {
	struct pci_device_id *id_table;
/* file drm_info.c, function drm_name_info() */
	char *name;
};

struct pci_dev {
/* drmP.h, return value from drm_dev_to_irq() */
	struct device dev;
	int irq;
/* file drm_drv.c, function drm_init() */
	uint32_t class;
	uint32_t vendor;
	uint32_t device;
	void *devfn;
};

/* file ati_pcigart.c, function drm_ati_pcigart_init() */
/* file radeon_device.c, function radeon_device_init() */
/* UNIMPLEMENTED */
static __inline__ int
pci_set_dma_mask(struct pci_dev *pdev, dma_addr_t table_mask) {
	return 0;
}

/* file ati_pcigart.c, function drm_ati_pcigart_init() */
/* file radeon_gart.c, function radeon_gart_bind() */
/* UNIMPLEMENTED */
static __inline__ dma_addr_t
pci_map_page(
	struct pci_dev *pdev,
	struct page *page,
	unsigned long offset,
	unsigned long pagesize,
	uint32_t flags
) {
	return 0;
}

/* file ati_pcigart.c, function drm_ati_pcigart_cleanup() */
/* file radeon_gart.c, function radeon_gart_unbind() */
/* UNIMPLEMENTED */
static __inline__ int
pci_unmap_page(
	struct pci_dev *pdev,
	dma_addr_t pages_addr,
	unsigned long pagesize,
	uint32_t flags
) {
	return 0;
}

/* file radeon_gart.c, function radeon_gart_table_ram_alloc() */
static __inline__ void *
pci_alloc_consistent(
	struct pci_dev *dev,
	unsigned table_size,
	dma_addr_t table_addr
) {
	return (void *)NULL;
}

/* file radeon_gart.c, function radeon_gart_table_ram_alloc() */
static __inline__ void
pci_free_consistent(
	struct pci_dev *dev,
	unsigned table_size,
	dma_addr_t table_addr
) {
	return;
}

/* file radeon_pm.c, function radeon_get_pm_method() */
static __inline__ void *
pci_get_drvdata(struct pci_dev *pdev) {
	return NULL;
}

/* file radeon_pm.c, function radeon_get_pm_method() */
#define to_pci_dev(dev) container_of(dev, struct pci_dev, dev)

/* file drm_drv.c, function drm_init() */
static __inline__ int
pci_register_driver(struct pci_driver *driver) {
	return -1;
}

/* file drm_drv.c, function drm_init() */
static __inline__ int
pci_unregister_driver(struct pci_driver *driver) {
	return -1;
}

/* file drm_drv.c, function drm_init() */
static __inline__ void
pci_dev_get(struct pci_dev *pdev) {
	;
}

/* file drm_drv.c, function drm_init() */
static __inline__ struct pci_dev *
pci_get_subsys(
	uint32_t vendor,
	uint32_t device,
	uint32_t subvendor,
	uint32_t subdevice
) {
	return NULL;
}

/* file drm_stub.c, function drm_get_dev() */
static __inline__ int
pci_enable_device(struct pci_dev *pdev) {
	return 0;
}

/* file drm_stub.c, function drm_get_dev() */
static __inline__ int
pci_disable_device(struct pci_dev *pdev) {
	return 0;
}

/* file drm_drv.c, function drm_init() */
static __inline__ void
pci_set_master(struct pci_dev *pdev) {
	;
}

/* file drm_stub.c, function drm_get_dev() */
static __inline__ void
pci_set_drvdata(struct pci_dev *pdev, void *data) {
	;
}

/* file drm_stub.c, function drm_get_dev() */
static __inline__ char *
pci_name(struct pci_dev *pdev) {
	return "0";
}

/* file i915_drv.c, function i915_drm_freeze() */
static __inline__ void
pci_save_state(struct pci_dev *pdev) {
	;
}

/* file intel_bios.c, function intel_init_bios() */
static __inline__ u8 __iomem*
pci_map_rom(
	struct pci_dev *pdev,
	size_t *psize
) {
	return NULL;
}

/* file intel_bios.c, function intel_init_bios() */
static __inline__ void
pci_unmap_rom(
	struct pci_dev *pdev,
	u8 *bios
) {
	;
}

/* file i915_drv.c, function i915_suspend() */
static __inline__ void
pci_set_power_state(struct pci_dev *pdev, uint32_t flag) {
	;
}

/* file radeon_gart.c, function radeon_gart_bind() */
static __inline__ int
pci_dma_mapping_error(struct pci_dev *pdev, dma_addr_t pages_addr) {
	return 0;
}

/* file drm_irq.c, function drm_irq_by_busid() */
static __inline__ int
PCI_SLOT(void *devfn) {
	return 0;
}

/* file drm_irq.c, function drm_irq_by_busid() */
static __inline__ int
PCI_FUNC(void *devfn) {
	return 0;
}

/**********************************************************
 * AGP                                                    *
 **********************************************************/

/* file ttm/ttm_agp_backend.c, function ttm_agp_populate() */
/* file drm_agpsupport.c, function drm_agp_allocate_memory() */
enum agp_memory_type {
	AGP_USER_CACHED_MEMORY,
	AGP_USER_MEMORY
};

/* ttm/ttm_agp_backend.c */
/* DragonFly BSD already has defined a struct agp_memory */
#if 0
struct agp_memory {
	unsigned long page_count;
	bool is_flushed;
	bool is_bound;
	enum agp_memory_type type;
	struct page *pages[];
};
#endif

struct agp_memory;

#ifdef __linux__
typedef struct agp_bridge_data *DRM_AGP_BRIDGE_DATA_T;
#else
typedef device_t                DRM_AGP_BRIDGE_DATA_T;
#endif

struct agp_bridge_data {
	int placeholder;
};

/* file ttm/ttm_agp_backend.c, function ttm_agp_populate() */
/* UNIMPLEMENTED */
static __inline__ struct agp_memory *
agp_allocate_memory(
	struct agp_bridge_data *bridge,
	size_t pages,
	uint32_t type
){
	return (struct agp_memory *)NULL;
}

/* file ttm/ttm_agp_backend.c, function ttm_agp_bind() */
/* file drm_agpsupport.c, function drm_agp_bind_memory */

/* On DragonFly BSD already defined in dev/agp/agpvar.h */
#if 0
static __inline__ int
agp_bind_memory(struct agp_memory *handle, off_t start) {
	return 0;
}

/* file ttm/ttm_agp_backend.c, function ttm_agp_unbind() */
static __inline__ int
agp_unbind_memory(struct agp_memory *handle) {
	return 0;
}

/* file ttm/ttm_agp_backend.c, function ttm_agp_clear() */
static __inline__ int
agp_free_memory(struct agp_memory *handle) {
	return 0;
}

/* file drm_agpsupport.c, function drm_agp_enable() */
static __inline__ void
agp_enable(struct agp_bridge_data *bridge, unsigned long mode) {
	;
}

#endif

/* file drm_agpsupport.c, function drm_agp_init() */
static __inline__ struct agp_bridge_data *
agp_find_bridge(struct pci_dev *pdev) {
	return (struct agp_bridge_data *)NULL;
}

/* file drm_agpsupport.c, function drm_agp_acquire() */
static __inline__ struct agp_bridge_data *
agp_backend_acquire(struct pci_dev *pdev) {
	return (struct agp_bridge_data *)NULL;
}

/* file drm_agpsupport.c, function drm_agp_acquire() */
static __inline__ void
agp_backend_release(struct agp_bridge_data *bridge) {
	;
}

/* legacy drm drm_agpsupport.c gets information from
 * agp_info
 */

/* file drm_agpsupport.c, function drm_agp_info() */
struct DRM_AGP_VERSION {
	int major;
	int minor;
};

/* file drm_agpsupport.c, function drm_agp_info() */
struct DRM_AGP_DEVICE {
	unsigned short vendor;
	unsigned short device;
};

/* file drm_agpsupport.c, function drm_agp_info() */
typedef struct DRM_AGP_KERN {
	struct DRM_AGP_VERSION version;
	unsigned long mode;
	unsigned long aper_base;
/* DIFFERENCE units of 1024 x 1024 bytes */
	unsigned long aper_size;
/* units of pages */
	unsigned long max_memory;
/* changed implementation */
	uint16_t id_vendor;
	uint16_t id_device;
/* units of pages */
	unsigned long current_memory;
	int cant_use_aperture;
	unsigned long page_mask;
} DRM_AGP_KERN;

/* file drm_agpsupport.c, function drm_agp_alloc() */
/* agp_memory_info() argument */
typedef struct DRM_AGP_MEM {
	struct agp_memory *memory;
/* file drm_agpsupport.c, function drm_agp_bind_pages() */
	unsigned long page_count;
	bool is_flushed;
	struct page **pages;
	int key;
	uint32_t physical;
	device_t bridge;
	vm_object_t object;
} DRM_AGP_MEM;

/* file drm_agpsupport.c, function drm_agp_alloc() */
/* DRM_AGP_MEM should also have some extra members
 *     void *key since cast (unsigned long)memory->key
 *     unsigned long physical
 */

/* file drm_agpsupport.c, function drm_agp_init() */
static __inline__ void
agp_copy_info(struct agp_bridge_data *bridge, DRM_AGP_KERN * agp_info) {
	;
}

/* file drm_agpsupport.c, function drm_agp_chipset_flush() */
static __inline__ void
agp_flush_chipset(struct agp_bridge_data *bridge) {
	;
}

/* file ttm/ttm_page_alloc.c, function set_pages_array_wb() */
static __inline__ void
unmap_page_from_agp(struct page *page) {
	;
}

/* file ttm/ttm_page_alloc.c, function set_pages_array_wb() */
static __inline__ void
map_page_into_agp(struct page *page) {
	;
}

/**********************************************************
 * VGA                                                    *
 **********************************************************/

enum vga_switcheroo_state {
	VGA_SWITCHEROO_ON
};

/* file drm_irq.c, function drm_irq_install() */
/* file i915/i915_dma.c, function i915_load_modeset_init() */
static __inline__ int
vga_client_register(
	struct pci_dev *pdev,
	void *cookie,
	void (*func)(void *cookie, bool state),
	unsigned (*decode)(void *cookie, bool state)
) {
	return 0;
}

/* file i915/i915_dma.c, function i915_load_modeset_init() */
static __inline__ int
vga_switcheroo_register_client(
	struct pci_dev *pdev,
	void (*set_state)(struct pci_dev *pdev, enum vga_switcheroo_state state),
	bool (*can_switch)(struct pci_dev *pdev)
) {
	return 0;
}

/* file i915/i915_dma.c, function i915_driver_unload() */
static __inline__ void 
vga_switcheroo_unregister_client(
	struct pci_dev *pdev
) {
	;
}

/* file i915/i915_dma.c, function i915_driver_lastclose() */
/* file radeon_kms.c, function radeon_driver_firstopen_kms() */
static __inline__ int
vga_switcheroo_process_delayed_switch(void) {
	return 0;
}

struct fb_info;

/* file intel_fb.c, function intelfb_create() */
static __inline__ void
vga_switcheroo_client_fb_set(
	struct pci_dev *pdev,
	struct fb_info *info
) {
	;
}


/**********************************************************
 * POWER MANAGEMENT                                       *
 **********************************************************/

typedef struct pm_message {
	uint32_t event;
} pm_message_t;

#define PM_EVENT_SUSPEND        0x0001
#define PM_EVENT_PRETHAW        0x0002

/* file i915_drv.c */
struct dev_pm_ops {
	int (*suspend)(struct device *dev);
	int (*resume)(struct device *dev);
	int (*freeze)(struct device *dev);
	int (*thaw)(struct device *dev);
	int (*poweroff)(struct device *dev);
	int (*restore)(struct device *dev);
};

/**********************************************************
 * FRAMEBUFFER                                            *
 **********************************************************/

/* file drm_fb_helper.c, function drm_fb_helper_blank() */
#define FB_BLANK_UNBLANK        0x0001
#define FB_BLANK_NORMAL         0x0002
#define FB_BLANK_HSYNC_SUSPEND  0x0004
#define FB_BLANK_VSYNC_SUSPEND  0x0008
#define FB_BLANK_POWERDOWN      0x0010

/* file drm_fb_helper.c, function setcolreg() */
#define FB_VISUAL_TRUECOLOR     0x0020

/* file drm_fb_helper.c, function drm_helper_fill_fix() */
#define FB_VISUAL_PSEUDOCOLOR   0x0040
#define FB_TYPE_PACKED_PIXELS   0x0080
#define FB_ACCEL_NONE           0x0100

/* file drm_fb_helper.c, function drm_fb_helper_fill_var() */
#define FB_ACTIVATE_NOW         0x0200

/* file radeon_fb.c, function radeonfb_create() */
#define FBINFO_DEFAULT          0x0400

/* file intelfb.c, function intelfb_create() */
#define FB_PIXMAP_SYSTEM	0x0800

struct DRM_FB_COLOR {
	uint16_t offset;
	uint16_t length;
};

/* file drm_fb_helper.c, function setcolreg() */
struct fb_fix_screeninfo {
	int bits_per_pixel;
	int xres;
	int yres;
	long pixclock;
/* file drm_fb_helper.c, function drm_fb_helper_pan_display() */
	uint32_t xoffset;
	uint32_t yoffset;
	struct DRM_FB_COLOR red;
	struct DRM_FB_COLOR green;
	struct DRM_FB_COLOR blue;
	struct DRM_FB_COLOR transp;
/* file drm_fb_helper.c, function drm_fb_helper_single_fb_probe() */
	char *id;
/* file drm_fb_helper.c, function drm_helper_fill_fix() */
	uint32_t type;
	uint32_t type_aux;
	uint32_t xpanstep;
	uint32_t ypanstep;
	uint32_t xwrapstep;
	uint32_t ywrapstep;
	uint32_t visual;
	uint32_t accel;
	uint32_t line_length;
/* file radeon_fb.c, function radeonfb_create() */
	unsigned long mmio_start;
	unsigned long mmio_len;
	unsigned long smem_start;
	unsigned long smem_len;
};

/* file drm_fb_helper.c, function setcolreg() */
struct fb_var_screeninfo {
	int bits_per_pixel;
	int xres;
	int yres;
	long pixclock;
/* file drm_fb_helper.c, function drm_fb_helper_pan_display() */
	uint32_t xoffset;
	uint32_t yoffset;
	struct DRM_FB_COLOR red;
	struct DRM_FB_COLOR green;
	struct DRM_FB_COLOR blue;
	struct DRM_FB_COLOR transp;
/* file drm_fb_helper.c, function drm_fb_helper_single_fb_probe() */
	char *id;
/* file drm_fb_helper.c, function drm_helper_fill_fix() */
	uint32_t type;
	uint32_t visual;
	uint32_t type_aux;
	uint32_t xpanstep;
	uint32_t ypanstep;
	uint32_t xwrapstep;
	uint32_t ywrapstep;
	uint32_t line_length;
/* file drm_fb_helper.c, function drm_fb_helper_fill_var() */
	uint32_t xres_virtual;
	uint32_t yres_virtual;
	uint32_t activate;
	uint32_t height;
	uint32_t width;
/* file intel_fb.c, function intelfb_resize() */
	int hsync_len;
	int vsync_len;
	int right_margin;
	int left_margin;
	int lower_margin;
	int upper_margin;
};

/* file radeon_fb.c, function radeonfb_create() */
/* file intel_fb.c, function intelfb_create() */
struct DRM_FB_PIXMAP {
	unsigned long size;
	uint32_t buf_align;
	uint32_t access_align;
	uint32_t flags;
	uint32_t scan_align;
};

/*file drm_fb_helper.h, function drm_fb_helper_setcmap() */
struct fb_cmap {
	uint16_t *red;
	uint16_t *green;
	uint16_t *blue;
	uint16_t *transp;
	int start;
	int len;
};

struct fb_ops;

/*file drm_fb_helper.h, function drm_fb_helper_blank() */
struct fb_info {
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	void *pseudo_palette;
	uint32_t node;
/* file radeon_fb.c, function radeonfb_create() */
	uint32_t flags;
/* file intel_fb.c, function intelfb_create() */
	void *screen_base;
	unsigned long screen_size;
	struct DRM_FB_PIXMAP pixmap;
/* file drm_fb_helper.h and drm_fb_helper.c */
	struct fb_cmap cmap;
	struct fb_ops *fbops;
/* file intel_fb.c, function intelfb_create() */
	resource_size_t aperture_base;
	resource_size_t aperture_size;
/* file vmwgfx_fb.c, function vmw_fb_dirty_mark() */
	struct delayed_work deferred_work;
/* file drm_fb_helper.c, function drm_fb_helper_single_fb_probe() */
	void *par;
};

/* file drm_fb_helper.c, function drm_fb_helper_parse_command_line() */
static __inline__ int
fb_get_options(const char *name, char **option) {
	return 0;
}

/* file drm_fb_helper.c, function drm_fb_helper_single_fb_probe() */
static __inline__ int
register_framebuffer(struct fb_info *info) {
	return 0;
}

/* file radeon/radeon_fb.c */
/* file i915/intel_fb.c */
static __inline__ int
unregister_framebuffer(struct fb_info *info) {
	return 0;
}

/* file radeon_fb.c, function radeonfb_create() */
/* file intel_fb.c, function intelfb_create() */
static __inline__ struct fb_info *
framebuffer_alloc(unsigned long extra, struct device *device) {
	return malloc(sizeof(struct fb_info) + extra, DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
}

/* file i915/intel_fb.c, function intelfb_remove() */
static __inline__ void
framebuffer_release(struct fb_info *info) {
	;
}

/* file drm_fb_helper.c, function drm_fb_helper_single_fb_probe */
static __inline__ int
fb_alloc_cmap(
	struct fb_cmap *cmap,
	uint32_t gamma_size,
	uint32_t flags
) {
	return 0;
}

static __inline__ void
fb_dealloc_cmap(struct fb_cmap *cmap) {
}

/* vmwgfx_fb.c, vmw_fb_fillrect() */
struct fb_fillrect {
	unsigned dx;
	unsigned dy;
	unsigned width;
	unsigned height;
};

/* vmwgfx_fb.c, vmw_fb_copyarea() */
struct fb_copyarea {
	unsigned dx;
	unsigned dy;
	unsigned width;
	unsigned height;
};

/* vmwgfx_fb.c, vmw_fb_imageblit() */
struct fb_image {
	unsigned dx;
	unsigned dy;
	unsigned width;
	unsigned height;
};

/* vmwgfx_fb.c, vmw_fb_fillrect() */
static __inline__ void
cfb_fillrect(struct fb_info *info, const struct fb_fillrect *rect) {
	;
}

static __inline__ void
cfb_copyarea(struct fb_info *info, const struct fb_copyarea *region) {
	;
}

static __inline__ void
cfb_imageblit(struct fb_info *info, const struct fb_image *image) {
	;
}

/* file intel_fb.c, struct intelfb_ops */
/* file vmwgfx_fb.c, struct vmw_fb_ops */
struct fb_ops {
	DRM_MODULE_T owner;
	int (*fb_check_var)(struct fb_var_screeninfo *var, struct fb_info *info);
	int (*fb_set_par)(struct fb_info *info);
	int (*fb_setcolreg)(unsigned regno, unsigned red, unsigned green,
		unsigned blue, unsigned transp, struct fb_info *info);
	void (*fb_fillrect)(struct fb_info *info, const struct fb_fillrect *rect);
	void (*fb_copyarea)(struct fb_info *info, const struct fb_copyarea *region);
	void (*fb_imageblit)(struct fb_info *info, const struct fb_image *image);
	int (*fb_pan_display)(struct fb_var_screeninfo *var, struct fb_info *info);
	int (*fb_blank)(int blank, struct fb_info *info);
	int (*fb_setcmap)(struct fb_cmap *cmap, struct fb_info *info);
};


/* vmwgfx_fb.c */
struct fb_deferred_io {
	unsigned long delay;
	void (*deferred_io)(struct fb_info *info, struct list_head *pagelist);
};

/*
 * Framebuffer global variables
 */
#define DEFAULT_FB_MODE_OPTION "default fb mode option"

extern const char *fb_mode_option;

struct edi {
	int placeholder;
};

/*
 * Non-Linux from drmP.h
 */

/* Don't want to deal with seq_printf in
 * drm_mm.c function drm_mm_dump_table
 */
#ifdef CONFIG_DEBUG_FS
#undef CONFIG_DEBUG_FS
#endif

#define _PAGE_NO_CACHE  0x0400

/* file drm_memory.c, function agp_remap() */
#define PAGE_AGP 0x0001

/* file drm_vm.c, function drm_mmap_dma() */
#define _PAGE_RW 0x0080

/**********************************************************
 * I2C                                                    *
 **********************************************************/

/* file drm_dp_i2c_helper.c, function i2c_algo_dp_aux_functionality() */
/* file drm_encoder_slave.c, function i2c_algo_dp_aux_functionality() */
/* file radeon_i2c.c, function radeon_hw_i2c_func() */
#define I2C_FUNC_I2C                    0x0001
#define I2C_FUNC_SMBUS_EMUL             0x0002
/* file drm_encoder_slave.c, function i2c_algo_dp_aux_functionality() */
#define I2C_FUNC_SMBUS_READ_BLOCK_DATA  0x0004
#define I2C_FUNC_SMBUS_BLOCK_PROC_CALL  0x0008
#define I2C_FUNC_10BIT_ADDR             0x0010

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
#define I2C_MODULE_PREFIX "iic"
#define I2C_NAME_SIZE 50 

/* file drm_edid.c, function drm_do_probe_ddc_edid() */
/* file radeon_i2c.c, function r500_hw_i2c_xfer() */
#define I2C_M_RD       IIC_M_RD 
/* file dvo_ivch.c */
#define I2C_M_NOSTART  0x0004

/* file intel_dp.c, function intel_dp_i2c_init() */
#define I2C_CLASS_DDC  0x0001

struct i2c_algorithm;

#define i2c_msg  iic_msg
#if 0
/* file drm_edid.c, function drm_do_probe_ddc_edid() */
struct i2c_msg {
/* spec seems to say 10-bit addresses possible */
/* file radeon_i2c.c, function radeon_i2c_get_byte() */
/* file drm_dp_i2c_helper.c, function i2c_algo_dp_aux_xfer() */
	uint16_t addr;
	uint32_t flags;
/* file drm_dp_i2c_helper.c, function i2c_algo_dp_aux_xfer() */
	uint16_t len;
	char *buf;
};
#endif

/* file drm_crtc.h, function drm_get_edid() */
/* file drm_edid.c, function drm_do_probe_ddc_edid() */
struct i2c_adapter {
/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
	DRM_MODULE_T owner;
/* file drm_dp_i2c_helper.c, function i2c_algo_dp_aux_transaction() */
	void *algo_data;
/* file drm_dp_i2c_helper.c, function i2c_dp_aux_prepare_bus() */
	uint32_t retries;
	const struct i2c_algorithm *algo;
/* file dvo_ch7017.c */
	char name[I2C_NAME_SIZE + 1];
/* file intel_dp.c, function intel_dp_i2c_init() */
	int class;
/* file intel_dp.c, function intel_dp_i2c_init() */
	struct device dev;
/* legacy BSD for use in i2c_transfer */
	device_t iicbb;
/* legacy BSD for use in i2c_transfer */
	device_t iicbus;
/* legacy BSD for use in i2c_transfer */
	device_t iicdrm;
/* legacy BSD for use in i2c_transfer */
	void *iic_private;
	int (*iicbus_request_bus)(device_t bus, device_t dev, int how);
	int (*iicbus_release_bus)(device_t bus, device_t dev);
	int (*iicbus_transfer)(device_t bus, struct iic_msg *msgs, uint32_t nmsgs);
};

/* file radeon_i2c.c, function pre_xfer() */
static __inline__ void *
i2c_get_adapdata(struct i2c_adapter *i2c_adap) {
	return i2c_adap->algo_data;
}

/* file radeon_i2c.c, function radeon_i2c_create() */
/* file intel_i2c.c, function intel_i2c_create() */
static __inline__ void
i2c_set_adapdata(struct i2c_adapter *i2c_adap, void *data) {
	i2c_adap->algo_data = data;
}

/* file drm_dp_i2c_helper.c, struct i2c_dp_aux_algo */
/* file radeon_i2c.c, struct radeon_i2c_algo */
struct i2c_algorithm {
	int (*master_xfer)(struct i2c_adapter *adapter, struct i2c_msg *msgs, int num);
	uint32_t (*functionality)(struct i2c_adapter *adapter);
};

/* file radeon_i2c.c, function radeon_i2c_create() */
/* file intel_i2c.c, function intel_i2c_create() */
struct i2c_algo_bit_data {
	int (*pre_xfer)(struct i2c_adapter *i2c_adap);
	int (*post_xfer)(struct i2c_adapter *i2c_adap);
	void (*setsda)(void *i2c_priv, int data);
	void (*setscl)(void *i2c_priv, int clock);
	int (*getsda)(void *i2c_priv);
	int (*getscl)(void *i2c_priv);
	unsigned long udelay;
	unsigned long timeout;
	void *data;
};

/* file radeon_i2c.c, function radeon_i2c_create() */
/* file intel_i2c.c, function intel_i2c_create() */
static __inline__ int
i2c_bit_add_bus(struct i2c_adapter *adapter) {
	return 0;
}

/* file drm_crtc.h, function drm_get_edid() */
/* file drm_edid.c, function drm_do_probe_ddc_edid() */
/* file radeon_i2c.c, function radeon_ddc_probe() */
int
i2c_transfer(struct i2c_adapter *adapter, struct i2c_msg *msgs, int num);

/* file drm_encoder_slave.h, function drm_i2c_encoder_init */
struct i2c_board_info {
	char *type;
};

/* file drm_encoder_slave.h, function drm_i2c_encoder_driver */
struct i2c_driver {
/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
	struct i2c_adapter driver;
};

/* file drm_encoder_slave.h, function drm_i2c_encoder_driver */
struct i2c_client {
/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
	struct i2c_driver *driver;
	struct i2c_adapter *adap;
	const struct i2c_board_info *info;
};

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ struct i2c_client *
i2c_new_device(struct i2c_adapter *adap, const struct i2c_board_info *info) {
	struct i2c_client *client = kmalloc(sizeof(*client), M_TEMP, M_WAITOK);
	if (client == NULL)
		return NULL;
	client->driver = kmalloc(sizeof(struct i2c_driver), M_TEMP, M_WAITOK);
	if (client->driver == NULL)
		goto failed;
	client->adap = adap;
	client->info = info;
	return client;

failed:
	kfree(client, M_TEMP);
	return NULL;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
static __inline__ int
i2c_unregister_device(struct i2c_client *client) {
	if (client == NULL)
		return 1;
	kfree(client->driver, M_TEMP);
	kfree(client, M_TEMP);
	return 0;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
static __inline__ int
i2c_register_driver(DRM_MODULE_T owner, struct i2c_driver *driver) {
	return 0;
}

/* file drm_encoder_slave.c, function i2c_dp_aux_add_bus() */
/* file radeon_i2c.c, function radeon_i2c_create() */
static __inline__ int
i2c_add_adapter(struct i2c_adapter *adapter) {
	return 0;
}

/* file intel_i2c.c, function intel_i2c_destroy() */
static __inline__ void
i2c_del_adapter(struct i2c_adapter *adapter) {
	;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_unregister() */
static __inline__ int
i2c_del_driver(struct i2c_driver *driver) {
	return 0;
}

/**********************************************************
 * MSI                                                    *
 **********************************************************/

/* file i915_dma.c, function () */
/* file radeon_irq_kms.c, function radeon_irq_kms_init() */
static __inline__ int
pci_enable_msi(struct pci_dev *pdev) {
	return 0;
}

/* file radeon_irq_kms.c, function radeon_irq_kms_fini() */
static __inline__ int
pci_disable_msi(struct pci_dev *pdev) {
	return 0;
}

/**********************************************************
 * FIRMWARE                                               *
 **********************************************************/

/* file radeon_drv.h, struct drm_radeon_private */
struct firmware {
	int placeholder;
};

/**********************************************************
 * POWER                                                  *
 **********************************************************/

/* file radeon_pm.c, function radeon_acpi_event() */
static __inline__ int
power_supply_is_system_supplied(void) {
	return 0;
}

/**********************************************************
 * NOTIFIER                                               *
 **********************************************************/

/* file i915_opregion.c, function intel_opregion_video_event */
#define NOTIFY_OK	0x000
#define NOTIFY_DONE	0x001

/* drm_fb_helper.c, struct block_paniced */
/* radeon_pm.c, function radeon_pm_init() */
/* file i915_opregion.c, function intel_opregion_video_event */
struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long val, void *data);
};

/* file drm_fp_helper.c, function drm_fb_helper_single_fb_probe */
struct atomic_notifier_head {
	int placeholder;
};

extern struct atomic_notifier_head panic_notifier_list;

static __inline__ void
atomic_notifier_chain_register(
	struct atomic_notifier_head *panic_notifier_list,
	struct notifier_block *paniced
) {
	;
}

static __inline__ void
atomic_notifier_chain_unregister(
	struct atomic_notifier_head *panic_notifier_list,
	struct notifier_block *paniced
) {
	;
}

/**********************************************************
 * ACPI                                                   *
 **********************************************************/

static __inline__ int
register_acpi_notifier(struct notifier_block *nb) {
	return 0;
}

/* radeon_pm.c, function radeon_pm_fini() */
static __inline__ int
unregister_acpi_notifier(struct notifier_block *nb) {
	return 0;
}

/* file i915_opregion.c, function intel_didl_outputs */
typedef unsigned long	acpi_handle;
typedef unsigned long	acpi_status;

static __inline__ int
ACPI_FAILURE(acpi_status status) {
	return 1;
}

static __inline__ int
ACPI_SUCCESS(acpi_status status) {
	return 1;
}

struct acpi_device {
	struct list_head children;
	struct list_head node;
	acpi_handle handle;
};

static __inline__ acpi_handle
DEVICE_ACPI_HANDLE(struct device *dev) {
	return 0;
}

/* file i915_opregion.c, function intel_opregion_init */
static __inline__ void
acpi_video_register(void) {
	;
}

/* file i915_opregion.c, function intel_opregion_free */
static __inline__ void
acpi_video_unregister(void) {
	;
}

/* file i915_opregion.c, function intel_didl_outputs */
static __inline__ acpi_status
acpi_bus_get_device(
	acpi_handle handle,
	struct acpi_device **pacpi_dev
) {
	return 1;
}

static __inline__ int
acpi_video_device(struct acpi_device *acpi_dev) {
	return 0;
}

static __inline__ acpi_status
acpi_evaluate_integer(
	acpi_handle handle,
	const char *suffix,
	void *isZero,
	unsigned long long *device_id
) {
	return 0;
}

/* file intel_lvds.c, function intel_lid_notify() */
static __inline__ int
acpi_lid_open(void) {
	return 1;
}

/* file intel_lvds.c, function intel_lvds_init() */
static __inline__ int
acpi_lid_notifier_register(struct notifier_block *lid_notifier) {
	return 0;
}

/* file intel_lvds.c, function intel_lid_notify() */
static __inline__ void
acpi_lid_notifier_unregister(struct notifier_block *lid_notifier) {
	;
}

/**********************************************************
 * DMI                                                    *
 **********************************************************/

/* file i915/intel_sdvo.c */
struct drm_dmi_match {
	uint32_t attribute;
	char *value;
};

#define DMI_MATCH(attr, val) \
{ \
	.attribute = attr, \
	.value = val, \
}

#define DMI_SYS_VENDOR		0x01
#define DMI_PRODUCT_NAME	0x02

/* file i915/intel_sdvo.c */
struct dmi_system_id {
	int (*callback)(const struct dmi_system_id *id);
	char *ident;
	struct drm_dmi_match matches[2];
};

/* file i915/intel_sdvo.c, function intel_sdvo_output_setup() */
static __inline__ int
dmi_check_system(struct dmi_system_id intel_sdvo_bad_tv[]) {
	return 1;
}

#endif /* __KERNEL__ */
#endif
