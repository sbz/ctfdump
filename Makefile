
PROG=		ctfdump
SRCS=		ctfdump.c elf.c

CFLAGS+=	-W -Wall -Wno-unused -Wstrict-prototypes -Wno-unused-parameter

CFLAGS+=	-DZLIB
LDADD+=		-lz
DPADD+=		${LIBZ}

.include <bsd.prog.mk>
