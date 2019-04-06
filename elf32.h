/*-
 * Copyright (c) 1996-1998 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: releng/9.2/sys/sys/elf32.h 163457 2006-10-17 05:43:30Z jkoshy $
 */

/* simplified by Gilles Mouchard & Franck Vedrine (franck.vedrine@cea.fr)
 * This file originally comes from FreeBSD (sys/elf32.h)
 * We have replaced u_int*_t by uint*_t everywhere and removed all
 * non necessary material for the CHARIOT needs.
*/

/*
 * ELF definitions common to all 32-bit architectures.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t        Elf32_Addr;
typedef uint16_t        Elf32_Half;
typedef uint32_t        Elf32_Off;
typedef int32_t         Elf32_Sword;
typedef uint32_t        Elf32_Word;
typedef uint64_t        Elf32_Lword;
typedef Elf32_Word      Elf32_Hashelt;

/* Non-standard class-dependent datatype used for abstraction. */
typedef Elf32_Word      Elf32_Size;
typedef Elf32_Sword     Elf32_Ssize;

/*
 * ELF header.
 */

#define EI_NIDENT       16      /* Size of e_ident array. */

typedef struct {
        unsigned char   e_ident[EI_NIDENT];     /* File identification. */
        Elf32_Half      e_type;         /* File type. */
        Elf32_Half      e_machine;      /* Machine architecture. */
        Elf32_Word      e_version;      /* ELF format version. */
        Elf32_Addr      e_entry;        /* Entry point. */
        Elf32_Off       e_phoff;        /* Program header file offset. */
        Elf32_Off       e_shoff;        /* Section header file offset. */
        Elf32_Word      e_flags;        /* Architecture-specific flags. */
        Elf32_Half      e_ehsize;       /* Size of ELF header in bytes. */
        Elf32_Half      e_phentsize;    /* Size of program header entry. */
        Elf32_Half      e_phnum;        /* Number of program header entries. */
        Elf32_Half      e_shentsize;    /* Size of section header entry. */
        Elf32_Half      e_shnum;        /* Number of section header entries. */
        Elf32_Half      e_shstrndx;     /* Section name strings section. */
} Elf32_Ehdr;

/*
 * Section header.
 */

typedef struct {
        Elf32_Word      sh_name;        /* Section name (index into the
                                           section header string table). */
        Elf32_Word      sh_type;        /* Section type. */
        Elf32_Word      sh_flags;       /* Section flags. */
        Elf32_Addr      sh_addr;        /* Address in memory image. */
        Elf32_Off       sh_offset;      /* Offset in file. */
        Elf32_Word      sh_size;        /* Size in bytes. */
        Elf32_Word      sh_link;        /* Index of a related section. */
        Elf32_Word      sh_info;        /* Depends on section type. */
        Elf32_Word      sh_addralign;   /* Alignment in bytes. */
        Elf32_Word      sh_entsize;     /* Size of each entry in section. */
} Elf32_Shdr;

/*
 * Symbol table entries.
 */

typedef struct {
        Elf32_Word      st_name;        /* String table index of name. */
        Elf32_Addr      st_value;       /* Symbol value. */
        Elf32_Word      st_size;        /* Size of associated object. */
        unsigned char   st_info;        /* Type and binding information. */
        unsigned char   st_other;       /* Reserved (not used). */
        Elf32_Half      st_shndx;       /* Section index of symbol. */
} Elf32_Sym;

#ifdef __cplusplus
}
#endif

