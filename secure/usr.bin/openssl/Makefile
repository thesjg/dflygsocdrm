# $FreeBSD: src/secure/usr.bin/openssl/Makefile,v 1.11.2.6 2003/02/14 22:38:22 nectar Exp $
# $DragonFly: src/secure/usr.bin/openssl/Makefile,v 1.6 2005/07/07 12:18:30 corecode Exp $

PROG=	openssl
WARNS?=	2

DPADD=	${LIBSSL} ${LIBCRYPTO}
LDADD=	-lssl -lcrypto

.if exists(Makefile.man)
.include "Makefile.man"
.endif
.include "../../lib/libcrypto/Makefile.inc"

CFLAGS+= -DMONOLITH -I${.CURDIR}

SRCS=	openssl.c
SRCS+=	verify.c asn1pars.c req.c dgst.c dh.c dhparam.c enc.c passwd.c gendh.c errstr.c \
	ca.c pkcs7.c crl2p7.c crl.c \
	rsa.c rsautl.c dsa.c dsaparam.c ec.c ecparam.c \
	x509.c genrsa.c gendsa.c genpkey.c s_server.c s_client.c speed.c \
	s_time.c apps.c s_cb.c s_socket.c app_rand.c version.c sess_id.c \
	ciphers.c nseq.c pkcs12.c pkcs8.c pkey.c pkeyparam.c pkeyutl.c \
	spkac.c smime.c cms.c rand.c engine.c ocsp.c prime.c ts.c srp.c

.include <bsd.prog.mk>

.PATH:	${LCRYPTO_SRC}/apps \
	${.CURDIR}/man
