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

#define SUNW_CTF	".SUNW_ctf"

#define DUMP_OBJECT	(1 << 0)
#define DUMP_FUNCTION	(1 << 1)
#define DUMP_HEADER	(1 << 2)
#define DUMP_LABEL	(1 << 3)

int		 dump(const char *, uint32_t);
int		 iself(const char *, size_t);
int		 isctf(const char *, size_t);
__dead void	 usage(void);

int		 ctf_dump(const char *, size_t, uint32_t);
const char	*ctf_off2name(struct ctf_header *, const char *, off_t,
		     unsigned int);

int		 elf_dump(const char *, size_t, uint32_t);
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
	uint32_t flags = 0;
	int ch, error = 0;

	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "dfhlsSt")) != -1) {
		switch (ch) {
		case 'h':
			flags |= DUMP_HEADER;
			break;
		case 'l':
			flags |= DUMP_LABEL;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	while ((filename = *argv++) != NULL)
		error |= dump(filename, flags);

	return error;
}

int
dump(const char *path, uint32_t flags)
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

	if (eh->e_ehsize < sizeof(Elf_Ehdr) || !IS_ELF(*eh)) {
		warnx("file is not ELF");
		return 0;
	}
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
		warnx("bogus section table offset 0x%llx", eh->e_shoff);
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

int
elf_dump(const char *p, size_t filesize, uint32_t flags)
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
ctf_dump(const char *p, size_t size, uint32_t flags)
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

	if (cth->cth_flags & CTF_F_COMPRESS)
		free(data);

	return 0;
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

	fprintf(stderr, "usage: %s [-dfhlsSt] [file ...]\n",
	    __progname);
	exit(1);
}

