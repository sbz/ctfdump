
PROG=		ctfdump
MAN=

DEBUG=-g

CFLAGS+=	-DZLIB
CFLAGS+=	-Wall -Wno-unused -Werror

LDADD+=	-lz
DPADD+=	${LIBZ}

.include <bsd.prog.mk>
