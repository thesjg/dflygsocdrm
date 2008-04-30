# $NetBSD: Makefile.inc,v 1.1 2006/03/13 19:45:36 tnozaki Exp $
# $DragonFly: src/share/i18n/csmapper/APPLE/Makefile.inc,v 1.1 2008/04/10 10:21:02 hasso Exp $

.PATH: ${.CURDIR}/APPLE

SRCS_mapper.dir+=	mapper.dir.APPLE
SRCS_charset.pivot+=	charset.pivot.APPLE
CLEANFILES+=		mapper.dir.APPLE charset.pivot.APPLE
PART_MAC!=		sed '/^\#/d;/^$$/d;' ${.CURDIR}/APPLE/MAC.part

.for i in ${PART_MAC}
.if exists(${.CURDIR}/APPLE/$i%UCS.src)
FILES+=			$i%UCS.mps
CLEANFILES+=		$i%UCS.mps
FILESDIR_$i%UCS.mps=	${BINDIR}/APPLE
.endif
.if exists(${.CURDIR}/APPLE/UCS%$i.src)
FILES+=			UCS%$i.mps
CLEANFILES+=		UCS%$i.mps
FILESDIR_UCS%$i.mps=	${BINDIR}/APPLE
.endif
.endfor

mapper.dir.APPLE: ${.CURDIR}/APPLE/MAC.part
	${_MKTARGET_CREATE}
	( \
	    echo "# APPLE"; \
	    for i in ${PART_MAC}; do \
		printf "%-32s%-32s%s\n" $$i/UCS mapper_std \
		    APPLE/$$i%UCS.mps; \
		printf "%-32s%-32s%s\n" UCS/$$i mapper_std \
		    APPLE/UCS%$$i.mps; \
	    done; \
	    echo; \
	) > ${.TARGET}

charset.pivot.APPLE: ${.CURDIR}/APPLE/MAC.part
	${_MKTARGET_CREATE}
	( \
	    echo "# APPLE"; \
	    for i in ${PART_MAC}; do \
		printf "%-32s%-32s%d\n" $$i UCS 1; \
		printf "%-32s%-32s%d\n" UCS $$i 1; \
	    done; \
	    echo; \
	) > ${.TARGET}