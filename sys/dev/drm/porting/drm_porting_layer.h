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

#include "dev/drm/porting/drm_porting_include.h"
#include "dev/drm/drm_linux_list.h"
#include "dev/drm/drm_atomic.h"

/* For current implementation of idr */
#include <sys/tree.h>

/* From previous version of drm.h */

#define EXPORT_SYMBOL(sym)

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

/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
/* file drm_drv.c, struct drm_stub_fops */
struct module {
	int placeholder;
};

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
request_module(char *modalias) {
	return 0;
}

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
try_module_get(struct module *module) {
	return 0;
}

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ int
module_put(struct module *module) {
	return 0;
}

#define THIS_MODULE (struct module *)NULL

/* file ttm/ttm_module.c, epilogue */
#if 0
static __inline__ void
module_init(int (*func)(void)) {
	;
}
#endif
#define module_init(arg) /* UNIMPLEMENTED */

#if 0
/* file ttm/ttm_module.c, epilogue */
static __inline__ void
module_exit(void (*func)(void)) {
	;
}
#endif
#define module_exit(arg) /* UNIMPLEMENTED */

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
#define BUG() /* UNIMPLEMENTED */

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

#define container_of(ptr, type, member) ({			\
	__typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
/*
 * Integer types
 */

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;

/* i915/i915.drv.h, struct drm_i915_error_buffer */
typedef int32_t s32;

/* radeon_drm.h typedef drm_radeon_setparam_t, member value
 * Linux version has __s64
 * BSD version has int64_t
 */

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

/* file drm_fixed.h, function dfixed_div,
 * extend interpretation of upper_32_bits */
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffff))

/* file drm_fixed.h, function dfixed_div,
 * extend interpretation of upper_32_bits */
#define do_div(a, b) (a = (uint64_t)(((uint64_t)(a)) / ((uint64_t)(b))))

/* drmP.h, declaration of function drm_read() */
#define loff_t	off_t

/* i915_drv.h */
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

/* vmware */
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

/**********************************************************
 * Atomic instructions                                    *
 **********************************************************/

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
 * C standard library equivalents                         *
 **********************************************************/

/*
 * Math
 */

/* file drm_edid.c, macro MODE_REFRESH_DIFF() */
#define abs(x) (x) > 0 ? (x) : -(x)

/* file drm_fb_helper.c, function drm_fb_helper_connector_parse_command_line() */
static __inline__ long
simple_strtol(const char *nptr, char **endptr, int base) {
	return strtol(nptr, endptr, base);
}

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
/* file drm_cache.c, function drm_clflush_pages() */
#define WARN_ON_ONCE() /* UNIMPLEMENTED */

/* file drm_crtc_helper, function drm_encoder_crtc_ok() */
#define WARN(cond, ...) if (cond) kprintf(__VA_ARGS__)

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

/**********************************************************
 * DATA STRUCTURES                                        *
 **********************************************************/

/*
 * Lists
 */

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

/* file ttm/ttm_bo.c, function ttm_bo_delayed_delete() */
#define list_first_entry(ptr, type, member) list_entry(((ptr)->next), type, member)

/* file ttm/ttm_page_alloc.c, function ttm_page_pool_get_pages() */
static __inline__ void
list_cut_position(struct list_head *pages, struct list_head *list, struct list_head *p) {
	pages->next = list->next;
	list->next->prev = p;
	pages->prev = p;
	p->next = list->next;
}

/* file drm_irq.c, function drm_handle_vblank_events() */
static __inline__ void
list_move_tail(struct list_head *link, struct list_head *list) {
	list->prev = link->prev;
	link->prev->next = list->next;
	list->prev->next = link->next;
	link->next->prev = list->prev;
	list_empty(link);
}

/* file drm_modes.c, function drm_mode_sort() */
static __inline__ void
list_sort(
	void *priv,
	struct list_head *list,
	int (*compare)(void *priv, struct list_head *lh_a, struct list_head *lh_b)
) {
	;
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
/**********************************************************
 * GLOBAL DATA                                            *
 **********************************************************/

/* file ttm/ttm_lock.c, function __ttm_read_lock() */
/* current is either the current thread or current process */
/* DragonFly BSD has curthread of type struct thread *     */

typedef struct thread DRM_CURRENT_THREAD;

#define current curthread

/* file drm_vm.c, function drm_vm_open_locked() */
/* Need to find pid associated with current, current->pid */

/* file drm_fops.c, function drm_open_helper() */
static __inline__ pid_t
task_pid_nr(DRM_CURRENT_THREAD *cur) {
	return 0;
}

/* file drm_fops.c, function drm_open_helper() */
static __inline__ uid_t
current_euid(void) {
	return 0;
}

/* file drm_fops.c, function drm_cpu_valid() */
/* boot_cpu_data.x86 appears to be an int sometimes 3 */

/**********************************************************
 * PERMISSIONS AND SECURITY                               *
 **********************************************************/

/* file ttm_memory.c, function ttm_mem_global_reserve() */
#define capable(CAP_SYS_ADMIN) 1 /* UNIMPLEMENTED */

/* defined for DragonFly BSD in sys/sys/poll.h */
/* #define POLLIN      0x0001 */
/* #define POLLRDNORM  0x0040 */

/* file ttm/ttm_page_alloc.c, function ttm_pool_mm_shrink() */
typedef uint32_t gfp_t;

#ifdef GFP_ATOMIC
#undef GFP_ATOMIC
#endif
#define GFP_ATOMIC   M_NOWAIT

#ifdef GFP_KERNEL
#undef GFP_KERNEL
#endif
#define GFP_KERNEL   M_WAITOK

#define __GFP_COLD      0x0004
#define __GFP_COMP      0x0008
#define __GFP_DMA32     0x0010
#define __GFP_HIGHMEM   0x0020
#define __GFP_NORETRY   0x0040
#define __GFP_NOWARN    0x0080
#define __GFP_ZERO      0x0100

/* file ttm/ttm_page_alloc.c, function ttm_get_pages() */
#define GFP_DMA32       0x0200

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_init() */
#define GFP_HIGHUSER    0x0400
#define GFP_USER        0x0800

/**********************************************************
 * SIGNALS AND INTERRUPTS                                 *
 **********************************************************/

/*
 * IRQ
 */
/* legacy drm drmP.h */

typedef int			irqreturn_t;
#define IRQ_HANDLED		0x00
#define IRQ_NONE		0x01

#define DRM_IRQ_ARGS		void *arg

/* file drm_irq.c, function drm_irq_install() */
static __inline__ int
request_irq(
	int irq,
	irqreturn_t (*irqhandler)(DRM_IRQ_ARGS),
	uint32_t flags,
	char *name,
	void *dev
) {
	return 0;
}

/* file drm_irq.c, function drm_irq_uninstall() */
static __inline__ int
free_irq(
	int irq,
	void *dev
) {
	return 0;
}

/* file i915_irq.c, function i915_error_object_create() */
static __inline__ void
local_irq_save(unsigned long flags) {
	;
}

/* file i915_irq.c, function i915_error_object_create() */
static __inline__ void
local_irq_restore(unsigned long flags) {
	;
}

/* file ttm/ttm_bo.c, function ttm_bo_mem_space() */
/* Positive, larger than any in sys/errno.h */
#define ERESTARTSYS 110

/* DragonFlyBSD defines ERESTART -1 */

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
send_sig(uint32_t signal, DRM_CURRENT_THREAD *cur, uint32_t flags) {
	;
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

#define DRM_LOCK()		DRM_SPINLOCK(&dev->dev_lock)
#define DRM_UNLOCK()		DRM_SPINUNLOCK(&dev->dev_lock)
#define DRM_SYSCTL_HANDLER_ARGS	(SYSCTL_HANDLER_ARGS)

/* Locking replacements for Linux drm functions */

#define spinlock_t	struct lock
#define spin_lock(l)   lockmgr(l, LK_EXCLUSIVE | LK_RETRY | LK_CANRECURSE)
#define spin_unlock(u) lockmgr(u, LK_RELEASE)
#define spin_lock_init(l) lockinit(l, "spin_lock_init", 0, LK_CANRECURSE)

/* drm_drawable.c drm_addraw() and previous drmP.h */
#define spin_lock_irqsave(l, irqflags) \
        do {                           \
                spin_lock(l);          \
                (void)irqflags;        \
        } while (0)

#define spin_unlock_irqrestore(u, irqflags) spin_unlock(u)

/* file drm_fops.c, function drm_reclaim_locked_buffers() */
#define spin_lock_bh(l)    spin_lock(l)    /* UNIMPLEMENTED */
#define spin_unlock_bh(l)  spin_unlock(l)  /* UNIMPLEMENTED */

/**********************************************************
 * MUTEX                                                  *
 **********************************************************/

/* drm_crtc.h, struct drm_mode_config, field mutex and idr_mutex */
/* file ttm/ttm_global.c, function ttm_global_init() */

#define mutex lock

/* file ttm/ttm_global.c, function ttm_global_item_ref() */
#define mutex_init(l)      lockinit(l, "linux_mutex", 0, LK_CANRECURSE)
#define mutex_lock(l)      lockmgr(l, LK_EXCLUSIVE | LK_RETRY | LK_CANRECURSE)
#define mutex_unlock(u)    lockmgr(u, LK_RELEASE)

/* file drm_gem.c, function drm_gem_object_free() */
#define mutex_is_locked(l) lockstatus(l, NULL)

/* file ttm/ttm_object.c,
 * function ttm_object_file() */
typedef struct lock rwlock_t;

/* file ttm/ttm_object.c,
 * function ttm_object_file_init() */
#define rwlock_init(l)  mutex_init(l)

/* file ttm/ttm_object.c, function ttm_base_object_init() */
#define write_lock(l)   mutex_lock(l)
#define write_unlock(l) mutex_unlock(l)

/* file ttm/ttm_object.c, function ttm_base_object_lookup() */
#define read_lock(l)    mutex_lock(l)
#define read_unlock(l)  mutex_unlock(l)

/* file radeon_pm.c, function radeon_dynpm_idle_work_handler() */
static __inline__ void
read_lock_irqsave(rwlock_t *lock, unsigned long flags) {
	;
}

/* file radeon_pm.c, function radeon_dynpm_idle_work_handler() */
static __inline__ void
read_lock_irqrestore(rwlock_t *lock, unsigned long flags) {
	;
}

/* file radeon_fence.c, function radeon_fence_emit() */
static __inline__ void
write_lock_irqsave(rwlock_t *lock, unsigned long flags) {
	;
}

/* file radeon_fence.c, function radeon_fence_emit() */
static __inline__ void
write_lock_irqrestore(rwlock_t *lock, unsigned long flags) {
	;
}

/*
 * Semaphores
 */

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
/* Obviously this is not a rw-semaphore */
/* but all downs seem to be matched with ups */
typedef struct lock DRM_RWSEMAPHORE;

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
static __inline__ void
down_read(DRM_RWSEMAPHORE *rwlock) {
	mutex_lock(rwlock);
}

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
static __inline__ void
up_read(DRM_RWSEMAPHORE *rwlock) {
	mutex_unlock(rwlock);
}

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
static __inline__ void
down_write(DRM_RWSEMAPHORE *rwlock) {
	mutex_lock(rwlock);
}

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
static __inline__ void
up_write(DRM_RWSEMAPHORE *rwlock) {
	mutex_unlock(rwlock);
}

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

/*
 * kobject
 */

/* ttm/ttm_memory.c */
struct kobject {
	int placeholder;
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
/* UNIMPLEMENTED */
static __inline__ void
kobject_init(struct kobject *kobj, struct kobj_type *type) {
	;
}

/* file ttm/ttm_page_alloc.c, function ttm_page_alloc_init() */
/* UNIMPLEMENTED */
static __inline__ int
kobject_add(struct kobject *kobj, struct kobject *glob, char *name) {
	return 0;
}

/* file ttm/ttm_memory.c, function ttm_mem_init_kernel_zone() */
/* UNIMPLEMENTED */
static __inline__ int
kobject_init_and_add(
	struct kobject *zone,
	struct kobj_type *type,
	struct kobject *glob,
	const char *name
) {
	return 1;
}

/* file ttm/ttm_memory.c, static struct such as ttm_mem_zone_kobj_type */
/* UNIMPLEMENTED */
static __inline__ void
kobject_put(struct kobject *kobj) {
	;
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

/*
 * Wait queues
 */

#define wait_queue_head_t atomic_t

/* file ttm/ttm_module.c, preamble */
#define DECLARE_WAIT_QUEUE_HEAD(var) wait_queue_head_t var /* UNIMPLEMENTED */

/* file ttm/ttm_lock.c, function ttm_lock_init() */
static __inline__ void
init_waitqueue_head(wait_queue_head_t *wqh) {
	;
}

/* file drm_dma.c, function drm_free_buffer() */
static __inline__ int
waitqueue_active(wait_queue_head_t *wqh) {
	return 0;
}

/* file ttm/ttm_lock.c, function ttm_read_lock() */
/* file ttm/ttm_bo.c, function ttm_bo_wait_unreserved() */
static __inline__ int
wait_event(wait_queue_head_t wqh, int condition) {
	return 0;
}

/* file ttm/ttm_lock.c, function ttm_read_lock() */
/* file ttm/ttm_bo.c, function ttm_bo_wait_unreserved() */
/* file drm_fops.c, function drm_read() */
static __inline__ int
wait_event_interruptible(wait_queue_head_t wqh, int condition) {
	return 0;
}

/* file drm_context.c, function drm_context_switch_complete() */
static __inline__ void
wake_up(wait_queue_head_t *wqh) {
	;
}

/* file ttm/ttm_lock.c, function ttm_read_unlock() */
/* file radeon_fence.c, function radeon_fence_process() */
static __inline__ void
wake_up_all(wait_queue_head_t *wqh) {
	;
}

/* file drm_fops.c, function drm_release() */
static __inline__ void
wake_up_interruptible(wait_queue_head_t *wqh) {
	;
}

/* file drm_fops.c, function drm_release() */
static __inline__ void
wake_up_interruptible_all(wait_queue_head_t *wqh) {
	;
}

/* file ttm_memory.c, function ttm_mem_global_init() */
struct work {
	int placeholder;
};

struct work_struct {
	int placeholder;
};

/* file ttm_memory.c, function ttm_mem_global_init() */

#if 0
INIT_WORK(
    struct *work_struct work,
    void (*func)( struct work_struct *work)
);
#endif
#define INIT_WORK(a, b) /* UNIMPLEMENTED */

/* file drm_fb_helper.c, function drm_fb_helper.sysrq() */
static __inline__ int
schedule_work(struct work *work) {
	return 0;
}

struct workqueue {
	int placeholder;
};

/* file ttm_memory.c, function ttm_mem_global_reserve() */
struct workqueue_struct {
	int placeholder;
};

/* file ttm_memory.c, function ttm_mem_global_init() */
static __inline__ struct workqueue_struct *
create_singlethread_workqueue(const char *name) {
	return NULL;
}

/* file ttm_memory.c, function ttm_check_swapping() */
static __inline__ int
queue_work(struct workqueue_struct *swap_queue, struct work_struct *work) {
	return 0;
}

/* file ttm_memory.c, function ttm_mem_global_release() */
static __inline__ int
flush_workqueue(struct workqueue_struct *swap_queue) {
	return 0;
}

/* file ttm_memory.c, function ttm_mem_global_release() */
static __inline__ int
destroy_workqueue(struct workqueue_struct *swap_queue) {
	return 0;
}

/* file ttm_bo_c, function ttm_bo_cleanup_refs() */
struct delayed_work {
	struct work_struct work;
};

/* file ttm_bo_c, function ttm_bo_cleanup_refs() */
#if 0
void INIT_DELAYED_WORK(
    struct delayed_work *wq,
    void (*callback)(struct work_struct *work)
);
#endif
#define INIT_DELAYED_WORK(a, b) /* UNIMPLEMENTED */

/* file ttm_bo_c,
 * function ttm_bo_cleanup_refs() */
static __inline__ int
schedule_delayed_work(
    struct delayed_work *wq,
    unsigned long time
) {
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

/* file ttm_bo_c, function ttm_bo_lock_delayed_workqueue() */
static __inline__ int
cancel_delayed_work_sync(struct delayed_work *wq) {
	return 0;
}

/* file ttm_bo_c, function ttm_bo_device_release() */
static __inline__ int
flush_scheduled_work(void) {
	return 0;
}

/* file radeon_pm.c, function radeon_pm_compute_clocks() */
static __inline__ int
queue_delayed_work(
	struct workqueue_struct *wq,
	struct delayed_work *dynpm_idle_work,
	unsigned long jiffies
) {
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

/* file ttm/ttm_memory.c, function ttm_mem_zone_show(),
 * Are zones the number of pages divided by 2^10?
 */

struct page {
/* file ttm/ttm_page_alloc.c, function ttm_handle_caching_state() */
	struct list_head lru;
};

/* file ttm/ttm_tt.c, function ttm_tt_swapin() */
struct address_space {
	int placeholder;
};

/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
static __inline__ int
PageHighMem(struct page *page) {
	return 0;
}

/* file ttm/ttm_tt.c, function ttm_tt_free_user_pages() */
static __inline__ int
PageReserved(struct page *page) {
	return 0;
}

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
static __inline__ void
__free_page(struct page *page) {
	;
}

/* file ttm/ttm_page_alloc.c, function ttm_alloc_new_pages() */
/* file ttm/ttm_bo.c, function ttm_bo_global_init() */
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

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
static __inline__ void
page_cache_release(struct page *to_page) {
	;
}

/* file ttm/ttm_tt.c, function ttm_tt_swapout() */
static __inline__ void
set_page_dirty(struct page *to_page) {
	;
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

/* file ttm/ttm_bo.c, function ttm_bo_unmap_virtual() */
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
	DRM_RWSEMAPHORE mmap_sem;
};

/* file ttm/ttm_tt.c, function ttm_tt_set_user() */
struct task_struct {
	struct mm_struct *mm;
};

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

/*
 * TIME Time
 */

#define HZ	hz
#define jiffies			ticks

typedef unsigned long cycles_t;

/* file drm_fops.c, function drm_reclaim_locked_buffers() */
static __inline__ void
schedule(void) {
	;
}

/* file drm_fops.c, function drm_reclaim_locked_buffers() */
static __inline__ int
time_after_eq(unsigned long jiffies, unsigned long _end) {
	return 0;
}

/* file radeon_fence.c, function radeon_fence_poll_locked() */
static __inline__ int
time_after(unsigned long jiffies, unsigned long _end) {
	return 0;
}

/* file drm_irq., function drm_handle_vblank_events() */
/* On DragonFly include sys/time.h */
/* man gettimeofday, but how.tv_sec and how.tv_usec are long? */
static __inline__ int
do_gettimeofday(struct timeval *now) {
#if 0
	return gettimeofday(now, NULL);
#endif
	return 0;
}

/* file radeon_i2c.c, function r500_hw_i2c_xfer() */
static __inline__ void
udelay(int delay) {
	DELAY(delay);
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
#if defined(__i386__)
#define mb()				__asm __volatile( \
					"lock; addl $0,0(%%esp)" : : : "memory");
#elif defined(__alpha__)
#define mb()				alpha_mb();
#elif defined(__x86_64__)
#define mb()				__asm __volatile( \
					"lock; addl $0,0(%%rsp)" : : : "memory");
#endif

/* file drm_cache.c, function drm_clflush_pages() */
#define wbinvd()	__asm __volatile( \
			"wbinvd");

/* file drm_cache.c, function drm_clflush_pages() */
static __inline__ void
clflush(uint32_t location) {
	;
}

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

/*
 * Processes and threads
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
MALLOC_DECLARE(DRM_MEM_GEM);
MALLOC_DECLARE(DRM_MEM_TTM);
MALLOC_DECLARE(DRM_MEM_KMS);
MALLOC_DECLARE(DRM_MEM_FENCE);

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
#define pgprot_val(prot) prot

/* file ttm/ttm_bo_util.c, function ttm_io_prot() */
/* file drm_gem.c, function drm_gem_mmap() */
static __inline__ pgprot_t
pgprot_writecombine(pgprot_t prot) {
	return 0;
}

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

/*
 * Kernel to / from user
 */

#define VERIFY_WRITE 0x0002 /* UNIMPLEMENTED */

/* file drm_ioc32.c, function compat_drm_version() */
/* Allocate on user stack? */
static __inline__ void *
compat_alloc_user_space(size_t size) {
	return NULL;
}

static __inline__ int
access_ok(uint32_t flags, void *ptr, size_t size) {
	return 0;
}

/* file drm_ioc32.c, function compat_drm_version() */
static __inline__ int
__put_user(void * src, void *dest) {
	return 0;
}

/* file drm_crtc.c, function drm_mode_getresources() */
static __inline__ int
put_user(long src, void *dest) {
	return 0;
}

/* file drm_crtc.c, function drm_mode_setcrtc() */
static __inline__ int
__get_user(void *dest, void *src) {
	return 0;
}

/* file drm_crtc.c, function drm_mode_setcrtc() */
static __inline__ int
get_user(long dest, void *src) {
	return 0;
}

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
memset_io(void * handle, uint32_t zero, int size) {
	;
}

static __inline__ void
memcpy_fromio(void *dst, void *src, unsigned long size) {
	;
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_page() */
static __inline__ void
memcpy_toio(void *dst, void *src, unsigned long value) {
	;
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

/* file ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
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
	unsigned long vm_start;
/* file drm_vm.c, function drm_do_shm_close() */
	unsigned long vm_end;
/* file drm_vm.c, function drm_do_shm_fault() */
/* file drm_gem.c, function drm_gem_vm_close() */
/* file radeon_ttm.c, function radeon_ttm_fault() */
	void *vm_private_data;
	const struct vm_operations_struct *vm_ops;
};

/* file drm_vm.c, function drm_do_vm_fault() */
struct vm_fault {
	void *virtual_address;
	struct page* page;
};

/* file drm_vm.c, struct drm_vm_ops */
/* file radeon_ttm.c, function radeon_ttm_fault() */
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

/* file drm_bufs.c, function drm_addmap_core() */
#define MTRR_TYPE_WRCOMB	0x0001

static __inline__ int
mtrr_add(
	unsigned long offset,
	unsigned long size,
	uint32_t type,
	uint32_t flagsOne
) {
	return 0;
}

static __inline__ int
mtrr_del(
	int mtrr,
	unsigned long offset,
	unsigned long size
) {
	return 0;
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
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_ioremap() */
static __inline__ void *
ioremap_wc(unsigned long basePlusOffset, unsigned long size) {
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_ioremap() */
static __inline__ void *
ioremap_nocache(unsigned long basePlusOffset, unsigned long size) {
	return (void *)NULL;
}

/* file ttm/ttm_bo_util.c, function ttm_mem_reg_iounmap() */
/* file drm_bufs.c, function drm_rmmap_locked() */
static __inline__ void
iounmap(void *virtual) {
	;
}

/* file vmwgfx_fifo.c, function vmw_fifo_is_full() */
static __inline__ uint32_t
ioread32(uint32_t *location) {
	return 0;
}

/* file ttm/ttm_bo_util.c, function ttm_copy_io_page() */
static __inline__ void
iowrite32(uint32_t src, uint32_t *dstP) {
	;
}

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

/* File ttm/ttm_memory.c, function ttm_mem_global_alloc_page() */
/* File ttm/ttm_bo_vm.c, function ttm_bo_vm_fault() */
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
};

/* file drm_fops.c, function drm_open() */
static __inline__ int
iminor(struct inode *inode) {
	return 0;
}

/* file drm_fops.c, function drm_stub_open() */
struct file_operations {
/* file drm_drv.c, struct drm_stub_fops */
	struct module *owner;
	int (*open)(struct inode *inode, struct file *file);
};

/* file drm_stub.c */
struct class {
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

/*
 * Large memory allocation
 */

/* For now just treat the same as regular allocation */
/* file drm_memory.c, function agp_remap() */
static __inline__ void *
vmalloc(size_t size) {
	return malloc(size, DRM_MEM_DEFAULT, M_WAITOK);
}

/* For now just treat the same as regular allocation */
/* file drm_scatter.c, function drm_vmalloc_dma() */
static __inline__ void *
vmalloc_32(size_t size) {
	return malloc(size, DRM_MEM_DEFAULT, M_WAITOK);
}


/* file drm_bufs.c, function drm_rmmap_locked() */
static __inline__ void
vfree(void *handle) {
	free(handle, DRM_MEM_DEFAULT);
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
};

/* file drm_edid.c, function do_get_edid() */
/*
 * Function actually takes
 *    struct device *dev,
 *    const char *format,
 *    variable number of arguments
 */
#define dev_warn(arg, ...) /* UNIMPLEMENTED */

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

/*
 * DMA
 */

typedef unsigned long dma_addr_t;

/* From legacy older version of drmP.h */

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : (1ULL<<(n)) - 1)
#endif

/* file drm_pci.c, function __drm_pci_free() */
static __inline__ void
dma_free_coherent(
	struct device *dev,
	size_t size,
	void *vaddr,
	dma_addr_t busaddr
) {
	;
}

/**********************************************************
 * PCI                                                    *
 **********************************************************/

/* file drm_vm.c, function drm_mmap_locked() */
#define PCI_VENDOR_ID_APPLE 0x0001

/* i915_drv.c */
#define PCI_ANY_ID 0xffff
#define PCI_CLASS_DISPLAY_VGA 0x0000

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

/* file ati_pcigart.c, function drm_ati_pcigart_cleanup() */
/* file radeon_gart.c, function radeon_gart_unbind() */
#define PCI_DMA_BIDIRECTIONAL 0x0001

/* file ati_pcigart.c, function drm_ati_pcigart_init() */
/* file radeon_gart.c, function radeon_gart_bind() */
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
static __inline__ int
pci_unmap_page(
	struct pci_dev *pdev,
	dma_addr_t pages_addr,
	unsigned long pagesize,
	uint32_t flags
) {
	return 0;
}

/* file radeon_gart.c, function radeon_gart_bind() */
static __inline__ int
pci_dma_mapping_error(struct pci_dev *pdev, dma_addr_t pages_addr) {
	return 0;
}

/* file ati_pcigart.c, function drm_ati_pcigart_init() */
static __inline__ int
pci_set_dma_mask(struct pci_dev *pdev, dma_addr_t table_mask) {
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
	unsigned long aper_size;
	unsigned long max_memory;
	unsigned long current_memory;
	struct DRM_AGP_DEVICE *device;
} DRM_AGP_KERN;

/* file drm_agpsupport.c, function drm_agp_alloc() */
/* agp_memory_info() argument */
typedef struct DRM_AGP_MEM {
	struct agp_memory *memory;
/* file drm_agpsupport.c, function drm_agp_bind_pages() */
	unsigned long page_count;
	bool is_flushed;
	struct page **pages;
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

/* file radeon_kms.c, function radeon_driver_firstopen_kms() */
static __inline__ int
vga_switcheroo_process_delayed_switch(void) {
	return 0;
}

/**********************************************************
 * FRAMEBUFFER                                            *
 **********************************************************/

/* file drm_fb_helper.c */
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

/* file drm_mode.c, function drm_mode_equal() */
#define KHZ2PICOS(clock) (clock) /* UNIMPLEMENTED */

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
};

/* file radeon_fb.c, function radeonfb_create() */
struct DRM_FB_PIXMAP {
	int placeholder;
};

/*file drm_fb_helper.h, function drm_fb_helper_blank() */
struct fb_info {
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	void *pseudo_palette;
	void *par;
	uint32_t node;
/* file radeon_fb.c, function radeonfb_create() */
	uint32_t flags;
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
static __inline__ int
unregister_framebuffer(struct fb_info *info) {
	return 0;
}

/* file radeon_fb.c, function radeonfb_create() */
static __inline__ struct fb_info *
framebuffer_alloc(unsigned long isZero, struct device *device) {
	return NULL;
}

/*
 * Framebuffer global variables
 */
#define DEFAULT_FB_MODE_OPTION "default fb mode option"

extern const char *fb_mode_option;

struct edi {
	int placeholder;
};

typedef unsigned long pm_message_t;

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
#define I2C_NAME_SIZE 32

/* file drm_edid.c, function drm_do_probe_ddc_edid() */
/* file radeon_i2c.c, function r500_hw_i2c_xfer() */
#define I2C_M_RD 0x0001

struct i2c_algorithm;

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

/* file drm_crtc.h, function drm_get_edid() */
/* file drm_edid.c, function drm_do_probe_ddc_edid() */
struct i2c_adapter {
/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
	struct module *owner;
/* file drm_dp_i2c_helper.c, function i2c_algo_dp_aux_transaction() */
	void *algo_data;
/* file drm_dp_i2c_helper.c, function i2c_dp_aux_prepare_bus() */
	uint32_t retries;
	const struct i2c_algorithm *algo;
};

/* file radeon_i2c.c, function pre_xfer() */
static __inline__ void *
i2c_get_adapdata(struct i2c_adapter *i2c_adap) {
	return i2c_adap->algo_data;
}

/* file radeon_i2c.c, function radeon_i2c_create() */
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
static __inline__ int
i2c_bit_add_bus(struct i2c_adapter *adapter) {
	return 0;
}

/* file drm_crtc.h, function drm_get_edid() */
/* file drm_edid.c, function drm_do_probe_ddc_edid() */
/* file radeon_i2c.c, function radeon_ddc_probe() */
static __inline__ int
i2c_transfer(struct i2c_adapter *adapter, struct i2c_msg *msgs, int num) {
	return 0;
}

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
};

/* file drm_encoder_slave.c, function drm_i2c_encoder_init() */
static __inline__ struct i2c_client *
i2c_new_device(struct i2c_adapter *adap, const struct i2c_board_info *info) {
	return NULL;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
static __inline__ int
i2c_register_driver(struct module *owner, struct i2c_driver *driver) {
	return 0;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_register() */
static __inline__ int
i2c_unregister_device(struct i2c_client *client) {
	return 0;
}

/* file drm_encoder_slave.c, function i2c_dp_aux_add_bus() */
/* file radeon_i2c.c, function radeon_i2c_create() */
static __inline__ int
i2c_add_adapter(struct i2c_adapter *adapter) {
	return 0;
}

/* file drm_encoder_slave.h, function drm_i2c_encoder_unregister() */
static __inline__ int
i2c_del_driver(struct i2c_driver *driver) {
	return 0;
}

/**********************************************************
 * MSI                                                    *
 **********************************************************/

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

/* file radeon_pm.c, function radeon_sync_with_vblank() */
/* file radeon_fence.c, function radeon_fence_wait() */
static __inline__ void
wait_event_timeout(
	wait_queue_head_t vblank_queue,
	bool vblank_sync,
	unsigned long jiffies
) {
	;
}

/* file radeon_pm.c, function radeon_sync_with_vblank() */
static __inline__ unsigned long
msecs_to_jiffies(unsigned long msecs) {
	return 0;
}

/* file radeon_pm.c, function radeon_pm_set_clocks() */
/* file radeon_fence.c, function radeon_fence_wait() */
static __inline__ void
wait_event_interruptible_timeout(
	wait_queue_head_t idle_queue,
	bool gui_idle,
	unsigned long jiffies
) {
	;
}

/**********************************************************
 * ACPI                                                   *
 **********************************************************/

/* drm_fb_helper.c, struct block_paniced */
/* radeon_pm.c, function radeon_pm_init() */
struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long val, void *data);
};

static __inline__ int
register_acpi_notifier(struct notifier_block *nb) {
	return 0;
}

/* radeon_pm.c, function radeon_pm_fini() */
static __inline__ int
unregister_acpi_notifier(struct notifier_block *nb) {
	return 0;
}

#endif /* __KERNEL__ */
#endif
