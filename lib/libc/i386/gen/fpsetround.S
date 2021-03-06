/*
 * Written by Charles M. Hannum, Apr 9, 1995
 * Public domain.
 *
 * $NetBSD: fpsetround.S,v 1.3 2002/01/13 21:45:43 thorpej Exp $
 * $DragonFly: src/lib/libc/i386/gen/fpsetround.S,v 1.1 2005/07/26 21:15:19 joerg Exp $
 */

#include <machine/asm.h>

#ifdef WEAK_ALIAS
WEAK_ALIAS(fpsetround, _fpsetround)
ENTRY(_fpsetround)
#else
ENTRY(fpsetround)
#endif
	subl $4,%esp

	fnstcw (%esp)
	movl (%esp),%eax

	rorl $10,%eax
	movl %eax,%edx
	andl $3,%eax

	subl %eax,%edx
	movl 8(%esp),%ecx
	andl $3,%ecx
	orl %ecx,%edx
	roll $10,%edx
	movl %edx,(%esp)
	fldcw (%esp)

	addl $4,%esp
	ret
