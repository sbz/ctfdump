/*
 * Copyright (c) 2016 Martin Pieuchot <mpi@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/exec_elf.h>
#include <sys/mman.h>

#include <err.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ZLIB
#include <zlib.h>
#endif /* ZLIB */

#include "ctf.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define SUNW_CTF	".SUNW_ctf"

#define DUMP_OBJECT	(1 << 0)
#define DUMP_FUNCTION	(1 << 1)
#define DUMP_HEADER	(1 << 2)
#define DUMP_LABEL	(1 << 3)
#define DUMP_STRTAB	(1 << 4)
#define DUMP_STATISTIC	(1 << 5)
#define DUMP_TYPE	(1 << 6)

int		 dump(const char *, uint8_t);
int		 iself(const char *, size_t);
int		 isctf(const char *, size_t);
__dead void	 usage(void);

int		 ctf_dump(const char *, size_t, uint8_t);
unsigned int	 ctf_dump_type(struct ctf_header *, const char *, off_t,
		     unsigned int, unsigned int);
const char	*ctf_kind2name(unsigned short);
const char	*ctf_off2name(struct ctf_header *, const char *, off_t,
		     unsigned int);

int		 elf_dump(const char *, size_t, uint8_t);
int		 elf_getshstrtab(const char *, size_t, const char **, size_t *);
int		 elf_getsymtab(const char *, const char *, size_t,
		     const Elf_Sym **, size_t *);
int		 elf_getstrtab(const char *, const char *, size_t,
		     const char **, size_t *);

#ifdef ZLIB
char		*decompress(const char *, size_t, off_t);
#endif /* ZLIB */

int
main(int argc, char *argv[])
{
	const char *filename;
	uint8_t flags = 0;
	int ch, error = 0;

	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "dfhlst")) != -1) {
		switch (ch) {
		case 'd':
			flags |= DUMP_OBJECT;
			break;
		case 'f':
			flags |= DUMP_FUNCTION;
			break;
		case 'h':
			flags |= DUMP_HEADER;
			break;
		case 'l':
			flags |= DUMP_LABEL;
			break;
		case 's':
			flags |= DUMP_STRTAB;
			break;
		case 't':
			flags |= DUMP_TYPE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* Dump everything by default */
	if (flags == 0)
		flags = 0xff;

	while ((filename = *argv++) != NULL)
		error |= dump(filename, flags);

	return error;
}

int
dump(const char *path, uint8_t flags)
{
	struct stat		 st;
	int			 fd, error = 1;
	char			*p;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		warn("open");
		return 1;
	}
	if (fstat(fd, &st) == -1) {
		warn("fstat");
		return 1;
	}
	if (st.st_size < (off_t)sizeof(struct ctf_header)) {
		warnx("file too small to be CTF");
		return 1;
	}
	if ((uintmax_t)st.st_size > SIZE_MAX) {
		warnx("file too big to fit memory");
		return 1;
	}

	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "mmap");

	if (iself(p, st.st_size)) {
		error = elf_dump(p, st.st_size, flags);
	} else if (isctf(p, st.st_size)) {
		error = ctf_dump(p, st.st_size, flags);
	}

	munmap(p, st.st_size);
	close(fd);

	return error;
}

int
iself(const char *p, size_t filesize)
{
	Elf_Ehdr		*eh = (Elf_Ehdr *)p;

	if (eh->e_ehsize < sizeof(Elf_Ehdr) || !IS_ELF(*eh))
		return 0;

	if (eh->e_ident[EI_CLASS] != ELFCLASS) {
		warnx("unexpected word size %u", eh->e_ident[EI_CLASS]);
		return 0;
	}
	if (eh->e_ident[EI_VERSION] != ELF_TARG_VER) {
		warnx("unexpected version %u", eh->e_ident[EI_VERSION]);
		return 0;
	}
	if (eh->e_ident[EI_DATA] >= ELFDATANUM) {
		warnx("unexpected data format %u", eh->e_ident[EI_DATA]);
		return 0;
	}
	if (eh->e_shoff > filesize) {
		warnx("bogus section table offset 0x%llx", (off_t)eh->e_shoff);
		return 0;
	}
	if (eh->e_shentsize < sizeof(Elf_Shdr)) {
		warnx("bogus section header size %u", eh->e_shentsize);
		return 0;
	}
	if (eh->e_shnum > (filesize - eh->e_shoff) / eh->e_shentsize) {
		warnx("bogus section header count %u", eh->e_shnum);
		return 0;
	}
	if (eh->e_shstrndx >= eh->e_shnum) {
		warnx("bogus string table index %u", eh->e_shstrndx);
		return 0;
	}

	return 1;
}

int
elf_getshstrtab(const char *p, size_t filesize, const char **shstrtab,
    size_t *shstrtabsize)
{
	Elf_Ehdr		*eh = (Elf_Ehdr *)p;
	Elf_Shdr		*sh;

	sh = (Elf_Shdr *)(p + eh->e_shoff + eh->e_shstrndx * eh->e_shentsize);
	if (sh->sh_type != SHT_STRTAB) {
		warnx("unexpected string table type");
		return 1;
	}
	if (sh->sh_offset > filesize) {
		warnx("bogus string table offset");
		return 1;
	}
	if (sh->sh_size > filesize - sh->sh_offset) {
		warnx("bogus string table size");
		return 1;
	}
	if (shstrtab != NULL)
		*shstrtab = p + sh->sh_offset;
	if (shstrtabsize != NULL)
		*shstrtabsize = sh->sh_size;

	return 0;
}

int
elf_getsymtab(const char *p, const char *shstrtab, size_t shstrtabsize,
    const Elf_Sym **symtab, size_t *nsymb)
{
	Elf_Ehdr	*eh = (Elf_Ehdr *)p;
	Elf_Shdr	*sh;
	size_t		 i;

	for (i = 0; i < eh->e_shnum; i++) {
		sh = (Elf_Shdr *)(p + eh->e_shoff + i * eh->e_shentsize);

		if (sh->sh_type != SHT_SYMTAB)
			continue;

		if ((sh->sh_link >= eh->e_shnum) ||
		    (sh->sh_name >= shstrtabsize))
			continue;

		if (strncmp(shstrtab + sh->sh_name, ELF_SYMTAB,
		    strlen(ELF_SYMTAB)) == 0) {
			if (symtab != NULL)
				*symtab = (Elf_Sym *)(p + sh->sh_offset);
			if (nsymb != NULL)
				*nsymb = (sh->sh_size / sh->sh_entsize);

			return 0;
		}
	}

	return 1;
}

int
elf_getstrtab(const char *p, const char *shstrtab, size_t shstrtabsize,
    const char **strtab, size_t *strtabsize)
{
	Elf_Ehdr	*eh = (Elf_Ehdr *)p;
	Elf_Shdr	*sh;
	size_t		 i;

	for (i = 0; i < eh->e_shnum; i++) {
		sh = (Elf_Shdr *)(p + eh->e_shoff + i * eh->e_shentsize);

		if (sh->sh_type != SHT_STRTAB)
			continue;

		if ((sh->sh_link >= eh->e_shnum) ||
		    (sh->sh_name >= shstrtabsize))
			continue;

		if (strncmp(shstrtab + sh->sh_name, ELF_STRTAB,
		    strlen(ELF_STRTAB)) == 0) {
			if (strtab != NULL)
				*strtab = p + sh->sh_offset;
			if (strtabsize != NULL)
				*strtabsize = sh->sh_size;

			return 0;
		}
	}

	return 1;
}

const char		*strtab;
const Elf_Sym		*symtab;
size_t			 strtabsize, nsymb;

const char *
elf_idx2sym(size_t *idx, unsigned char type)
{
	const Elf_Sym	*st;
	size_t		 i;

	for (i = *idx + 1; i < nsymb; i++) {
		st = &symtab[i];

		if (ELF_ST_TYPE(st->st_info) != type)
			continue;

		*idx = i;
		return strtab + st->st_name;
	}

	return NULL;
}

int
elf_dump(const char *p, size_t filesize, uint8_t flags)
{
	Elf_Ehdr		*eh = (Elf_Ehdr *)p;
	Elf_Shdr		*sh;
	const char		*shstrtab;
	size_t			 i, shstrtabsize;

	/* Find section header string table location and size. */
	if (elf_getshstrtab(p, filesize, &shstrtab, &shstrtabsize))
		return 1;

	/* Find symbol table location and number of symbols. */
	if (elf_getsymtab(p, shstrtab, shstrtabsize, &symtab, &nsymb))
		warnx("symbol table not found");

	/* Find string table location and size. */
	if (elf_getstrtab(p, shstrtab, shstrtabsize, &strtab, &strtabsize))
		warnx("string table not found");

	/* Find CTF section and dump it. */
	for (i = 0; i < eh->e_shnum; i++) {
		sh = (Elf_Shdr *)(p + eh->e_shoff + i * eh->e_shentsize);

		if ((sh->sh_link >= eh->e_shnum) ||
		    (sh->sh_name >= shstrtabsize))
			continue;

		if (strncmp(shstrtab + sh->sh_name, SUNW_CTF, strlen(SUNW_CTF)))
			continue;

		if (!isctf(p + sh->sh_offset, sh->sh_size))
			break;

		return ctf_dump(p + sh->sh_offset, sh->sh_size, flags);
	}

	warnx("%s section not found", SUNW_CTF);
	return 1;
}

int
isctf(const char *p, size_t filesize)
{
	struct ctf_header	*cth = (struct ctf_header *)p;
	off_t 			 dlen = cth->cth_stroff + cth->cth_strlen;

	if (cth->cth_magic != CTF_MAGIC || cth->cth_version != CTF_VERSION)
		return 0;

	if (dlen > filesize && !(cth->cth_flags & CTF_F_COMPRESS)) {
		warnx("bogus file size");
		return 0;
	}

	if ((cth->cth_lbloff & 3) || (cth->cth_objtoff & 1) ||
	    (cth->cth_funcoff & 1) || (cth->cth_typeoff & 3)) {
		warnx("wrongly aligned offset");
		return 0;
	}

	if ((cth->cth_lbloff >= dlen) || (cth->cth_objtoff >= dlen) ||
	    (cth->cth_funcoff >= dlen) || (cth->cth_typeoff >= dlen)) {
		warnx("truncated file");
		return 0;
	}

	if ((cth->cth_lbloff > cth->cth_objtoff) ||
	    (cth->cth_objtoff > cth->cth_funcoff) ||
	    (cth->cth_funcoff > cth->cth_typeoff) ||
	    (cth->cth_typeoff > cth->cth_stroff)) {
		warnx("corrupted file");
		return 0;
	}

	return 1;
}

int
ctf_dump(const char *p, size_t size, uint8_t flags)
{
	struct ctf_header	*cth = (struct ctf_header *)p;
	char			*data = (char *)p;
	off_t 			 dlen = cth->cth_stroff + cth->cth_strlen;

	if (cth->cth_flags & CTF_F_COMPRESS) {
		data = decompress(p + sizeof(*cth), size - sizeof(*cth), dlen);
		if (data == NULL)
			return 1;
	}

	if (flags & DUMP_HEADER) {
		printf("cth_magic    = 0x%04x\n", cth->cth_magic);
		printf("cth_version  = %d\n", cth->cth_version);
		printf("cth_flags    = 0x%02x\n", cth->cth_flags);
		printf("cth_parlabel = %s\n",
		    ctf_off2name(cth, data, dlen, cth->cth_parname));
		printf("cth_parname  = %s\n",
		    ctf_off2name(cth, data, dlen, cth->cth_parname));
		printf("cth_lbloff   = %d\n", cth->cth_lbloff);
		printf("cth_objtoff  = %d\n", cth->cth_objtoff);
		printf("cth_funcoff  = %d\n", cth->cth_funcoff);
		printf("cth_typeoff  = %d\n", cth->cth_typeoff);
		printf("cth_stroff   = %d\n", cth->cth_stroff);
		printf("cth_strlen   = %d\n", cth->cth_strlen);
	}

	if (flags & DUMP_LABEL) {
		unsigned int		 lbloff = cth->cth_lbloff;
		struct ctf_lblent	*ctl;

		while (lbloff < cth->cth_objtoff) {
			ctl = (struct ctf_lblent *)(data + lbloff);

			printf("%5u %s\n", ctl->ctl_typeidx,
			    ctf_off2name(cth, data, dlen, ctl->ctl_label));

			lbloff += sizeof(*ctl);
		}
	}

	if (flags & DUMP_OBJECT) {
		unsigned int		 objtoff = cth->cth_objtoff;
		size_t			 idx = 0, i = 0;
		unsigned short		*dsp;
		const char		*s;
		int			 l;

		while (objtoff < cth->cth_funcoff) {
			dsp = (unsigned short *)(data + objtoff);

			l = printf("[%zu] %u", i++, *dsp);
			if ((s = elf_idx2sym(&idx, STT_OBJECT)) != NULL)
				printf("%*s %s (%zu)\n", (12 - l), "", s, idx);
			else
				printf("\n");

			objtoff += sizeof(*dsp);
		}
	}

	if (flags & DUMP_FUNCTION) {
		unsigned short		*fsp, kind, vlen;
		size_t			 idx = 0, i = 0;
		const char		*s;
		int			 l;

		fsp = (unsigned short *)(data + cth->cth_funcoff);
		while (fsp < (unsigned short *)(data + cth->cth_typeoff)) {
			kind = CTF_INFO_KIND(*fsp);
			vlen = CTF_INFO_VLEN(*fsp);
			fsp++;

			if (kind == CTF_K_UNKNOWN && vlen == 0)
				continue;

			l = printf("%u [%zu] FUNC", vlen, i++);
			if ((s = elf_idx2sym(&idx, STT_FUNC)) != NULL)
				printf(" (%s)", s);
			printf(" returns: %u args: (", *fsp++);
			while (vlen-- > 0)
				printf("%u%s", *fsp++, (vlen > 0) ? ", " : "");
			printf(")\n");
		}
	}

	if (flags & DUMP_STRTAB) {
		unsigned int		 offset = 0;
		const char		*str;

		while (offset < cth->cth_strlen) {
			str = data + cth->cth_stroff + offset;

			printf("[%u] ", offset);
			if (*str != '\0')
				offset += printf("%s\n", str);
			else {
				printf("\\0\n");
				offset++;
			}
		}
	}

	if (flags & DUMP_TYPE) {
		unsigned int		 idx = 1, offset = 0;

		while (offset < cth->cth_stroff)
			offset += ctf_dump_type(cth, data, dlen, offset, idx++);

	}

	if (cth->cth_flags & CTF_F_COMPRESS)
		free(data);

	return 0;
}

unsigned int
ctf_dump_type(struct ctf_header *cth, const char *data, off_t dlen,
    unsigned int offset, unsigned int idx)
{
	const struct ctf_type	*ctt;
	unsigned short		 kind, vlen, root;
	unsigned int		 toff, tlen = 0;
	uint64_t		 size;
	const char		*name, *kname;

	ctt = (struct ctf_type *)(data + cth->cth_typeoff + offset);
	kind = CTF_INFO_KIND(ctt->ctt_info);
	vlen = CTF_INFO_VLEN(ctt->ctt_info);
	root = CTF_INFO_ISROOT(ctt->ctt_info);
	name = ctf_off2name(cth, data, dlen, ctt->ctt_name);

	if (root)
		printf("<%u> ", idx);
	else
		printf("[%u] ", idx);

	if ((kname = ctf_kind2name(kind)) != NULL)
		printf("%s %s", kname, name);

	if (ctt->ctt_size <= CTF_MAX_SIZE) {
		size = ctt->ctt_size;
		toff = sizeof(struct ctf_stype);
	} else {
		size = CTF_TYPE_LSIZE(ctt);
		toff = sizeof(struct ctf_type);
	}

	switch (kind) {
	case CTF_K_UNKNOWN:
	case CTF_K_FORWARD:
		break;
	case CTF_K_INTEGER:
		tlen = sizeof(unsigned int);
		break;
	case CTF_K_FLOAT:
		break;
	case CTF_K_ARRAY:
		tlen = sizeof(struct ctf_array);
		break;
	case CTF_K_FUNCTION:
		tlen = (vlen + (vlen & 1)) * sizeof(unsigned short);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		printf(" (%llu bytes)", size);
		if (size < CTF_LSTRUCT_THRESH)
			tlen = vlen * sizeof(struct ctf_member);
		else
			tlen = vlen * sizeof(struct ctf_lmember);
		break;
	case CTF_K_ENUM:
		tlen = vlen * sizeof(struct ctf_enum);
		break;
	case CTF_K_POINTER:
		vlen = sizeof(unsigned int);
		/* FALLTHROUGH */
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_CONST:
	case CTF_K_RESTRICT:
		printf(" refers to %u", ctt->ctt_type);
		break;
	default:
		errx(1, "incorrect type %u at offset %u", kind, offset);
	}

	printf("\n");

	return toff + tlen;
}

const char *
ctf_kind2name(unsigned short kind)
{
	static const char *kind_name[] = { NULL, "INTEGER", "FLOAT", "POINTER",
	   "ARRAYS", "FUNCTION", "STRUCT", "UNION", "ENUM", "FORWARD",
	   "TYPEDEF", "VOLATILE", "CONST", "RESTRICT" };

	if (kind >= nitems(kind_name))
		return NULL;

	return kind_name[kind];
}

const char *
ctf_off2name(struct ctf_header *cth, const char *data, off_t dlen,
    unsigned int offset)
{
	const char		*name;

	if (CTF_NAME_STID(offset) != CTF_STRTAB_0)
		return "external";

	if (CTF_NAME_OFFSET(offset) >= cth->cth_strlen)
		return "exceeds strlab";

	if (cth->cth_stroff + CTF_NAME_OFFSET(offset) >= dlen)
		return "invalid";

	name = data + cth->cth_stroff + CTF_NAME_OFFSET(offset);
	if (*name == '\0')
		return "(anon)";

	return name;
}

char *
decompress(const char *buf, size_t size, off_t len)
{
#ifdef ZLIB
	z_stream		 stream;
	char			*data;
	int			 error;

	data = malloc(len);
	if (data == NULL) {
		warn(NULL);
		return NULL;
	}

	memset(&stream, 0, sizeof(stream));
	stream.next_in = (void *)buf;
	stream.avail_in = size;
	stream.next_out = data;
	stream.avail_out = len;

	if ((error = inflateInit(&stream)) != Z_OK) {
		warnx("zlib inflateInit failed: %s", zError(error));
		goto exit;
	}

	if ((error = inflate(&stream, Z_FINISH)) != Z_STREAM_END) {
		warnx("zlib inflate failed: %s", zError(error));
		goto exit;
	}

	if ((error = inflateEnd(&stream)) != Z_OK) {
		warnx("zlib inflateEnd failed: %s", zError(error));
		goto exit;
	}

	if (stream.total_out != len) {
		warnx("decompression failed: %llu != %llu",
		    stream.total_out, len);
		goto exit;
	}

	return data;

exit:
	free(data);
#endif /* ZLIB */
	return NULL;
}

__dead void
usage(void)
{
	extern char		*__progname;

	fprintf(stderr, "usage: %s [-dfhlst] [file ...]\n",
	    __progname);
	exit(1);
}

