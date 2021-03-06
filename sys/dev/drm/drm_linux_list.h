/* drm_linux_list.h -- linux list functions for the BSDs.
 * Created: Mon Apr 7 14:30:16 1999 by anholt@FreeBSD.org
 */
/*-
 * Copyright 2003 Eric Anholt
 * All Rights Reserved.
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
 *
 * Authors:
 *    Eric Anholt <anholt@FreeBSD.org>
 *
 */

#include <sys/cdefs.h>

#ifndef _DRM_LINUX_LIST_H_
#define _DRM_LINUX_LIST_H_

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	__typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct list_head {
	struct list_head *next, *prev;
};

#define list_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

static __inline__ void
INIT_LIST_HEAD(struct list_head *head) {
	(head)->next = head;
	(head)->prev = head;
}

static __inline__ int
list_empty(struct list_head *head) {
	return (head)->next == head;
}

static __inline__ void
list_add(struct list_head *new, struct list_head *head) {
        (head)->next->prev = new;
        (new)->next = (head)->next;
        (new)->prev = head;
        (head)->next = new;
}

static __inline__ void
list_add_tail(struct list_head *entry, struct list_head *head) {
	(entry)->prev = (head)->prev;
	(entry)->next = head;
	(head)->prev->next = entry;
	(head)->prev = entry;
}

static __inline__ void
list_del(struct list_head *entry) {
	(entry)->next->prev = (entry)->prev;
	(entry)->prev->next = (entry)->next;
}

static __inline__ void
list_del_init(struct list_head *entry) {
	(entry)->next->prev = (entry)->prev;
	(entry)->prev->next = (entry)->next;
	INIT_LIST_HEAD(entry);
}

#define list_for_each(entry, head)				\
    for (entry = (head)->next; entry != head; entry = (entry)->next)

#define list_for_each_prev(entry, head) \
        for (entry = (head)->prev; entry != (head); \
                entry = entry->prev)

#define list_for_each_safe(entry, temp, head)			\
    for (entry = (head)->next, temp = (entry)->next;		\
	entry != head; 						\
	entry = temp, temp = entry->next)

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:        the type * to use as a loop cursor.
 * @n:          another type * to use as temporary storage
 * @head:       the head for your list.
 * @member:     the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, __typeof(*pos), member),	\
	    n = list_entry(pos->member.next, __typeof(*pos), member);	\
	    &pos->member != (head);					\
	    pos = n, n = list_entry(n->member.next, __typeof(*n), member))

/** extension of previous, needed for new drm_mm.c
 * list_for_each_entry - iterate over list of given type
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)			\
	for (pos = list_entry((head)->next, __typeof(*pos), member);	\
	    &pos->member != (head);					\
	    pos = list_entry(pos->member.next, __typeof(*pos), member))

/** list_move_tail - remove entry from one list and add to tail of another
 * @entry:	entry to be removed from first list
 * @toadd:	second list
 */
static __inline__ void
list_move_tail(struct list_head *entry, struct list_head *toadd) {
	list_del(entry);
	list_add_tail(entry, toadd);
}

#define list_first_entry(ptr, type, member) list_entry(((ptr)->next), type, member)

/** list_splice - splice list at head of another list
 * @newp:	list whose elements are to be spliced in
 * @head:	list at whose head new list is to be spliced into
 */
static __inline__ void
list_splice(struct list_head* newp, struct list_head* head) {
	if (!list_empty(newp)) {
		(head)->next->prev = (newp)->prev;
		(newp)->prev->next = (head)->next;
		(newp)->next->prev = (head);
		(head)->next = (newp)->next;
	}
}

/** list_splice_init - splice list at head of another list and empty
 * @newp:	list whose elements are to be spliced in then emptied
 * @head:	list at whose head new list is to be spliced into
 */
static __inline__ void
list_splice_init(struct list_head* newp, struct list_head* head) {
	list_splice(newp, head);
	list_empty(newp);
}

/* Extension of function in drm_linux_list.h */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, __typeof(*pos), member);	\
	    &pos->member != (head);					\
	    pos = list_entry(pos->member.prev, __typeof(*pos), member))

/** list_cut_position
 * @store - list presumed empty that will receive removed entries
 * @head - list from whose some initial segment is to be removed
 * @entry - entry marking end of segment to be removed, inclusive
 */
static __inline__ void
list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry) {
	(list)->next = (head)->next;
	(list)->prev = (entry);
	(head)->next = (entry)->next;
	(entry)->next->prev = (head);
	(head)->next->prev = (list);
	(entry)->next = (list);
}

/** list_sort - sort list using the crudest algorithm possible 
 * @priv:	to be passed to the comparison function	
 * @head:	list to be sorted
 * @comparer:	comparison function	
 */
static __inline__ void
list_sort(void *priv, struct list_head *head,
	int (*comparer)(void *priv, struct list_head *lh_a, struct list_head *lh_b)) {
	struct list_head *cursor = head;
	struct list_head *highest;
	struct list_head *seek;
	if (list_empty(head))
		return;
	while (cursor->next != head) {
		highest = cursor;
		seek = cursor;
		while (seek->next != head) {
			if ((*comparer)(priv, seek, seek->next) > 0) {
				highest = seek->next;
			}
			seek = seek->next;
		}
		if (cursor == highest) {
			cursor = cursor->next;
		}
		else {
			list_del(highest);
			cursor->prev->next = highest;
			highest->prev = cursor->prev;
			highest->next = cursor;
			cursor->prev = highest;
		}
	}
}

#endif /* _DRM_LINUX_LIST_H_ */
