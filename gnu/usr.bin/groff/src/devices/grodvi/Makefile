# $FreeBSD: src/gnu/usr.bin/groff/src/devices/grodvi/Makefile,v 1.4 2003/05/01 13:22:18 ru Exp $
# $DragonFly: src/gnu/usr.bin/groff/src/devices/grodvi/Makefile,v 1.3 2005/09/01 20:47:13 asmodai Exp $

PROG_CXX=	grodvi
SRCS=		dvi.cpp
DPADD=		${LIBDRIVER} ${LIBGROFF} ${LIBM}
LDADD=		${LIBDRIVER} ${LIBGROFF} -lm
CLEANFILES=	${MAN}

.include <bsd.prog.mk>
