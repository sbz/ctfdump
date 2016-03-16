
PROG=		ctfdump

CFLAGS+=	-Wall -Wno-unused -Werror

CFLAGS+=	-DZLIB
LDADD+=		-lz
DPADD+=		${LIBZ}

.include <bsd.prog.mk>
