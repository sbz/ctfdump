
PROG=		ctfdump
SRCS=		ctfdump.c elf.c

CFLAGS+=	-Wall -Wno-unused -Werror

CFLAGS+=	-DZLIB
LDADD+=		-lz
DPADD+=		${LIBZ}

.include <bsd.prog.mk>
