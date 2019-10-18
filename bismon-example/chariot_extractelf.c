#include <stdbool.h>
#include <string.h>
#include "chariot_extractelf.h"

const char *Chariot_Section_names[] = { ".chariotmeta.rodata", ".suppldata" };

#define EI_DATA         5	/* Data format. */
#define ELFDATA2MSB     2	/* 2's complement big-endian. */
#define SHN_UNDEF       0	/* Undefined, missing, irrelevant. */
#define SHT_SYMTAB      2	/* symbol table section */

typedef enum
{ EELS_Ident = EI_NIDENT, EELS_Type = 2, EELS_Machine = 2, EELS_Version =
    4, EELS_Entry = 4,
  EELS_PHOff = 4, EELS_SHOff = 4, EELS_Flags = 4, EELS_EHSize =
    2, EELS_PHEntSize = 2,
  EELS_PHNum = 2, EELS_SHEntSize = 2, EELS_SHNum = 2, EELS_SHStrNdx = 2
} Elf32_Ehdr_LocalSizes;

static const int Elf32_Ehdr_Size =
  EELS_Ident + EELS_Type + EELS_Machine + EELS_Version + EELS_Entry +
  EELS_PHOff + EELS_SHOff + EELS_Flags + EELS_EHSize + EELS_PHEntSize +
  EELS_PHNum + EELS_SHEntSize + EELS_SHNum + EELS_SHStrNdx;

typedef enum
{ ESLS_Name = 4, ESLS_Type = 4, ESLS_Flags = 4, ESLS_Addr = 4, ESLS_Offset =
    4, ESLS_SSize = 4, ESLS_Link = 4, ESLS_Info = 4,
  ESLS_AddrAlign = 4, ESLS_EntSize = 4
} Elf32_Shdr_LocalSizes;

static const int Elf32_Shdr_Size =
  ESLS_Name + ESLS_Type + ESLS_Flags + ESLS_Addr + ESLS_Offset + ESLS_SSize +
  ESLS_Link + ESLS_Info + ESLS_AddrAlign + ESLS_EntSize;

typedef enum
{ ESYLS_Name = 4, ESYLS_Value = 4, ESYLS_SSize = 4, ESYLS_Info =
    1, ESYLS_Other = 1, ESYLS_Shndx = 2
}
Elf32_Sym_LocalSizes;

static const int Elf32_Sym_Size =
  ESYLS_Name + ESYLS_Value + ESYLS_SSize + ESYLS_Info + ESYLS_Other +
  ESYLS_Shndx;

static inline bool
is_target_little_endian (const Elf32_Ehdr * result)
{
  return (result->e_ident[EI_DATA] != ELFDATA2MSB);
}

union _endianess_test
{
  uint32_t i;
  char c[4];
};

static inline bool
is_host_little_endian ()
{
  union _endianess_test bint;
  bint.i = 0x01020304;
  return bint.c[0] == 4;
}

static inline void
reverse_half (Elf32_Half * word)
{
  *word = (*word >> 8) | (*word << 8);
}

static inline void
reverse_word (Elf32_Word * word)
{
  *word =
    ((*word >> 24) & 0xff) | ((*word << 8) & 0xff0000) | ((*word >> 8) &
							  0xff00) | ((*word <<
								      24) &
								     0xff000000);
}

static inline void
reverse_addr (Elf32_Addr * word)
{
  *word =
    ((*word >> 24) & 0xff) | ((*word << 8) & 0xff0000) | ((*word >> 8) &
							  0xff00) | ((*word <<
								      24) &
								     0xff000000);
}

static inline void
reverse_off (Elf32_Addr * word)
{
  *word =
    ((*word >> 24) & 0xff) | ((*word << 8) & 0xff0000) | ((*word >> 8) &
							  0xff00) | ((*word <<
								      24) &
								     0xff000000);
}

static inline bool
is_symtab (const Elf32_Shdr * section_header)
{
  return section_header->sh_type == SHT_SYMTAB;
}

int
fill_exe_header (Elf32_Ehdr * result, const char *buffer_exe,
		 size_t buffer_len, const char **error_message)
{
  if (buffer_len < Elf32_Ehdr_Size)
    {
      *error_message = "not enough bytes to be a valid elf content";
      return false;
    }
  // if ((char*) (&result->e_shstrndx+1) - (char*) result != Elf32_Ehdr_Size)
  if (sizeof (Elf32_Ehdr) != Elf32_Ehdr_Size)
    {
      *error_message =
	"internal error: Elf32_Ehdr structure may have padding";
      return false;
    }
  // memset(result, 0, sizeof(*result));
  memcpy (result, buffer_exe, Elf32_Ehdr_Size);	// [TODO] copy every field if internal error
  if (is_target_little_endian (result) != is_host_little_endian ())
    {
      reverse_half (&result->e_type);
      reverse_half (&result->e_machine);
      reverse_word (&result->e_version);
      reverse_addr (&result->e_entry);
      reverse_off (&result->e_phoff);
      reverse_off (&result->e_shoff);
      reverse_word (&result->e_flags);
      reverse_half (&result->e_ehsize);
      reverse_half (&result->e_phentsize);
      reverse_half (&result->e_phnum);
      reverse_half (&result->e_shentsize);
      reverse_half (&result->e_shnum);
      reverse_half (&result->e_shstrndx);
    }
  return true;
}

void
reverse_section_header (Elf32_Shdr * section)
{
  reverse_word (&section->sh_name);
  reverse_word (&section->sh_type);
  reverse_word (&section->sh_flags);
  reverse_addr (&section->sh_addr);
  reverse_off (&section->sh_offset);
  reverse_word (&section->sh_size);
  reverse_word (&section->sh_link);
  reverse_word (&section->sh_info);
  reverse_word (&section->sh_addralign);
  reverse_word (&section->sh_entsize);
}

void
reverse_symbol_header (Elf32_Sym * symbol)
{
  reverse_word (&symbol->st_name);
  reverse_addr (&symbol->st_value);
  reverse_word (&symbol->st_size);
  reverse_half (&symbol->st_shndx);
}

int
retrieve_section_header (Elf32_Shdr * section_header,
			 const Elf32_Ehdr * elf_header,
			 const char *buffer_exe, size_t buffer_len,
			 Chariot_Section section, const char **error_message)
{
  if (section < 0 || section > CS_Extra)
    {
      *error_message = "bad CHARIOT section description";
      return false;
    }
  const char *section_name = Chariot_Section_names[section];
  const char *section_start = buffer_exe + elf_header->e_shoff;
  if (Elf32_Shdr_Size != elf_header->e_shentsize)
    {
      *error_message = "size of section header is not as expected";
      return false;
    }
  if (sizeof (Elf32_Shdr) != Elf32_Shdr_Size)
    {
      *error_message =
	"internal error: Elf32_Shdr structure may have padding";
      return false;
    }

  if (elf_header->e_shstrndx == SHN_UNDEF)
    {
      *error_message = "no string table to find CHARIOT sections";
      return false;
    }
  const char *section_string_table_start = buffer_exe + elf_header->e_shoff
    + elf_header->e_shstrndx * Elf32_Shdr_Size;
  Elf32_Shdr section_string_table;
  if (section_string_table_start - buffer_exe + Elf32_Shdr_Size > buffer_len)
    {
      *error_message = "unable to read section string table";
      return false;
    }
  memcpy (&section_string_table, section_string_table_start, Elf32_Shdr_Size);	// [TODO] copy every field if internal error
  if (is_target_little_endian (elf_header) != is_host_little_endian ())
    reverse_section_header (&section_string_table);

  int section_index = elf_header->e_shnum;
  while (--section_index >= 0)
    {
      if (section_start - buffer_exe + Elf32_Shdr_Size > buffer_len)
	{
	  *error_message =
	    "unable to read a section header: buffer is too small";
	  return false;
	}
      Elf32_Word sh_name = 0;
      memcpy (&sh_name, section_start, sizeof (Elf32_Word));
      if (is_target_little_endian (elf_header) != is_host_little_endian ())
	reverse_word (&sh_name);
      const char *cur_section_name =
	buffer_exe + section_string_table.sh_offset + sh_name;
      if (sh_name < 0 || sh_name > section_string_table.sh_size
	  || (cur_section_name - buffer_exe > buffer_len))
	{
	  *error_message =
	    "unable to read a section name: buffer is too small";
	  return false;
	}
      if (strcmp (section_name, cur_section_name) == 0)
	{
	  memcpy (section_header, section_start, Elf32_Shdr_Size);	// [TODO] copy every field if internal error
	  if (is_target_little_endian (elf_header) !=
	      is_host_little_endian ())
	    reverse_section_header (section_header);
	  return true;
	}
      section_start += Elf32_Shdr_Size;
    };

  if (section == CS_Meta)
    *error_message = "unable to find CHARIOT metadata section in elf buffer";
  else if (section == CS_Extra)
    *error_message = "unable to find CHARIOT extra section in elf buffer";
  else
    *error_message = "unable to find CHARIOT section in elf buffer";
  return false;
}

void
set_metadata_localization (Chariot_Metadata_localizations *
			   chariot_metadata_localizations,
			   const char *symbol_name, Elf32_Sym * symbol_header)
{
  Chariot_Metadata_Symbols cms_location = CMS_END;
  if (strcmp (symbol_name, "chariotmeta_mainboot_sha256") == 0)
    cms_location = CMS_Mainboot_sha256;
  else if (strcmp (symbol_name, "chariotmeta_format_typeinfo") == 0)
    cms_location = CMS_Format_typeinfo;
  else if (strcmp (symbol_name, "chariotmeta_mainboot_offsetnum") == 0)
    cms_location = CMS_Mainboot_offsetnum;
  else if (strcmp (symbol_name, "chariotmeta_mainboot_sizesnum") == 0)
    cms_location = CMS_Mainboot_sizesnum;
  else if (strcmp (symbol_name, "chariotmeta_extraboot_sha256") == 0)
    cms_location = CMS_Extraboot_sha256;
  else if (strcmp (symbol_name, "chariotmeta_extraboot_offsetnum") == 0)
    cms_location = CMS_Extraboot_offsetnum;
  else if (strcmp (symbol_name, "chariotmeta_extraboot_sizenum") == 0)
    cms_location = CMS_Extraboot_sizenum;
  else if (strcmp (symbol_name, "chariotmeta_extraboot_typeinfo") == 0)
    cms_location = CMS_Extraboot_typeinfo;
  else if (strcmp (symbol_name, "chariotmeta_codanalys_typeinfo") == 0)
    cms_location = CMS_Codanalys_typeinfo;
  else if (strcmp (symbol_name, "chariotmeta_version_data") == 0)
    cms_location = CMS_Version_data;
  else if (strcmp (symbol_name, "chariotmeta_firmware_path") == 0)
    cms_location = CMS_Firmware_path;
  else if (strcmp (symbol_name, "chariotmeta_firmware_license") == 0)
    cms_location = CMS_Firmware_license;
  else if (strcmp (symbol_name, "chariotmeta_codanalys_data") == 0)
    cms_location = CMS_Codanalys_data;
  if (cms_location != CMS_END)
    {
      chariot_metadata_localizations->chariot_symbols[cms_location] =
	*symbol_header;
      chariot_metadata_localizations->valid_entries |= (1U << cms_location);
    };
}

int
fill_metadata_dict (Chariot_Metadata_localizations *
		    chariot_metadata_localizations,
		    const char **error_message)
{
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  const char *section_start = buffer_exe + elf_header->e_shoff;
  int section_index = elf_header->e_shnum;
  bool has_found_symtab = false;
  if (sizeof (Elf32_Shdr) != Elf32_Shdr_Size)
    {
      *error_message =
	"internal error: Elf32_Shdr structure may have padding";
      return false;
    }
  if (sizeof (Elf32_Sym) != Elf32_Sym_Size)
    {
      *error_message = "internal error: Elf32_Sym structure may have padding";
      return false;
    }
  while (--section_index >= 0)
    {
      if (section_start - buffer_exe + Elf32_Shdr_Size > buffer_len)
	{
	  *error_message =
	    "unable to read a section header: buffer is too small";
	  return false;
	}
      Elf32_Shdr cur_section_header;
      memcpy (&cur_section_header, section_start, Elf32_Shdr_Size);
      if (is_target_little_endian (elf_header) != is_host_little_endian ())
	reverse_section_header (&cur_section_header);

      if (is_symtab (&cur_section_header))
	{
	  Elf32_Shdr linked_section_header;
	  if (cur_section_header.sh_link >= 0
	      && cur_section_header.sh_link < elf_header->e_shnum)
	    {
	      memcpy (&linked_section_header,
		      buffer_exe + elf_header->e_shoff +
		      cur_section_header.sh_link * Elf32_Shdr_Size,
		      Elf32_Shdr_Size);
	      if (is_target_little_endian (elf_header) !=
		  is_host_little_endian ())
		reverse_section_header (&linked_section_header);
	    };

	  has_found_symtab = true;
	  const char *symbol_section_start =
	    buffer_exe + cur_section_header.sh_offset;
	  if (symbol_section_start - buffer_exe + cur_section_header.sh_size >
	      buffer_len)
	    {
	      *error_message =
		"unable to read the symbol table: buffer is too small";
	      return false;
	    }
	  size_t symbols_number = cur_section_header.sh_size / Elf32_Sym_Size;
	  for (int symbol_index = 0; symbol_index < symbols_number;
	       ++symbol_index)
	    {
	      Elf32_Word st_name;
	      memcpy (&st_name,
		      symbol_section_start + symbol_index * Elf32_Sym_Size,
		      sizeof (Elf32_Word));
	      if (is_target_little_endian (elf_header) !=
		  is_host_little_endian ())
		reverse_word (&st_name);
	      const char *cur_symbol_name =
		buffer_exe + linked_section_header.sh_offset + st_name;
	      if (st_name < 0 || st_name > linked_section_header.sh_size
		  || (cur_symbol_name - buffer_exe > buffer_len))
		{
		  *error_message =
		    "unable to read a symbol: buffer is too small";
		  return false;
		}
	      if (strncmp
		  ("chariotmeta_", cur_symbol_name,
		   strlen ("chariotmeta_")) == 0)
		{
		  Elf32_Sym symbol_header;
		  memcpy (&symbol_header, symbol_section_start + symbol_index * Elf32_Sym_Size, Elf32_Sym_Size);	// [TODO] copy every field if internal error
		  if (is_target_little_endian (elf_header) !=
		      is_host_little_endian ())
		    reverse_symbol_header (&symbol_header);
		  set_metadata_localization (chariot_metadata_localizations,
					     cur_symbol_name, &symbol_header);
		}
	    };
	}
      section_start += Elf32_Shdr_Size;
    };
  if (!has_found_symtab)
    {
      *error_message = "unable to find a symbol table in the elf buffer";
      return false;
    };
  return true;
}

static inline bool
add_hex_digit (char ch, uint32_t * res)
{
  *res <<= 4;
  bool result = true;
  if (ch >= '0' && ch <= '9')
    *res |= ch - '0';
  else if (ch >= 'a' && ch <= 'f')
    *res |= 10 + (ch - 'a');
  else if (ch >= 'A' && ch <= 'F')
    *res |= 10 + (ch - 'A');
  else
    result = false;
  return result;
}

bool
fill_sha256 (uint32_t result[8], const char *start)
{
  int target_index = 7;
  for (int index = 0; index < 64; ++index)
    {
      if (!add_hex_digit (start[index], &result[target_index]))
	return false;
      if ((index & 0x7) == 0x7)
	--target_index;
    }
  return true;
}

int
retrieve_mainboot_sha256 (uint32_t result[8],
			  const Chariot_Metadata_localizations *
			  chariot_metadata_localizations,
			  const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Mainboot_sha256];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of mainboot_sha256: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message = "unable to read mainboot_sha256: buffer is too small";
      return false;
    }
  if (symbol->st_size != strlen ("mainboot") + 1 + 64
      || strncmp (start + 64, " mainboot", strlen (" mainboot")) != 0)
    {
      *error_message = "invalid field mainboot_sha256";
      return false;
    }
  if (!fill_sha256 (result, start))
    {
      *error_message = "invalid sha256 for mainboot_sha256";
      return false;
    };
  return true;
}

int
retrieve_format_typeinfo (const char **result, size_t *result_len,
			  const Chariot_Metadata_localizations *
			  chariot_metadata_localizations,
			  const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Format_typeinfo];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of format_typeinfo: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message = "unable to read format_typeinfo: buffer is too small";
      return false;
    }
  *result = start;
  *result_len = symbol->st_size;
  return true;
}

int
retrieve_codanalys_typeinfo (const char **result, size_t *result_len,
			     const Chariot_Metadata_localizations *
			     chariot_metadata_localizations,
			     const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Codanalys_typeinfo];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of codanalys_typeinfo: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message =
	"unable to read codanalys_typeinfo: buffer is too small";
      return false;
    }
  *result = start;
  *result_len = symbol->st_size;
  return true;
}

int
retrieve_version_data (const char **result, size_t *result_len,
		       const Chariot_Metadata_localizations *
		       chariot_metadata_localizations,
		       const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Version_data];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of version_data: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message = "unable to read version_data: buffer is too small";
      return false;
    }
  *result = start;
  *result_len = symbol->st_size;
  return true;
}

int
retrieve_firmware_path (const char **result, size_t *result_len,
			const Chariot_Metadata_localizations *
			chariot_metadata_localizations,
			const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Firmware_path];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of firmware_path: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message = "unable to read firmware_path: buffer is too small";
      return false;
    }
  if (strncmp
      (start, "CHARIOTMETA_FIRMWARE_PATH=",
       strlen ("CHARIOTMETA_FIRMWARE_PATH=")) != 0)
    {
      *error_message = "invalid firmware_path";
      return false;
    }
  *result = start + strlen ("CHARIOTMETA_FIRMWARE_PATH=");
  *result_len = symbol->st_size - strlen ("CHARIOTMETA_FIRMWARE_PATH=");
  return true;
}

int
retrieve_firmware_license (const char **result, size_t *result_len,
			   const Chariot_Metadata_localizations *
			   chariot_metadata_localizations,
			   const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Firmware_license];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of firmware_license: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message = "unable to read firmware_license: buffer is too small";
      return false;
    }
  if (strncmp
      (start, "CHARIOTMETA_FIRMWARE_LICENSE=",
       strlen ("CHARIOTMETA_FIRMWARE_LICENSE=")) != 0)
    {
      *error_message = "invalid firmware_license";
      return false;
    }
  *result = start + strlen ("CHARIOTMETA_FIRMWARE_LICENSE=");
  *result_len = symbol->st_size - strlen ("CHARIOTMETA_FIRMWARE_LICENSE=");
  return true;
}

int
retrieve_codanalys_data (const char **result, size_t *result_len,
			 const Chariot_Metadata_localizations *
			 chariot_metadata_localizations,
			 const char **error_message)
{
  const Elf32_Sym *symbol =
    &chariot_metadata_localizations->chariot_symbols[CMS_Codanalys_data];
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t buffer_len = chariot_metadata_localizations->metadata_buffer_len;

  if (elf_header->e_shoff + (symbol->st_shndx + 1) * Elf32_Shdr_Size >
      buffer_len || symbol->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of code analysis data: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  buffer_exe + elf_header->e_shoff +
	  symbol->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start =
    buffer_exe + section_container.sh_offset + symbol->st_value;
  if (start - buffer_exe + symbol->st_size > buffer_len
      || symbol->st_value < 0)
    {
      *error_message =
	"unable to read code analysis data: buffer is too small";
      return false;
    }
  if (strncmp
      (start, "CHARIOTMETA_CODANALYS_DATA= ",
       strlen ("CHARIOTMETA_CODANALYS_DATA= ")) != 0)
    {
      *error_message = "invalid code analysis data";
      return false;
    }
  *result = start + strlen ("CHARIOTMETA_CODANALYS_DATA= ");
  *result_len = symbol->st_size - strlen ("CHARIOTMETA_CODANALYS_DATA= ") - 1;
  return true;
}

int
retrieve_extraboot (Chariot_Metadata_extraboot * result,
		    const Chariot_Metadata_localizations *
		    chariot_metadata_localizations,
		    const char **error_message)
{
  const Elf32_Ehdr *elf_header =
    chariot_metadata_localizations->metadata_header;
  const Elf32_Sym *symbol_sha256 =
    &chariot_metadata_localizations->chariot_symbols[CMS_Extraboot_sha256];
  const Elf32_Sym *symbol_offsetnum =
    &chariot_metadata_localizations->chariot_symbols[CMS_Extraboot_offsetnum];
  const Elf32_Sym *symbol_sizenum =
    &chariot_metadata_localizations->chariot_symbols[CMS_Extraboot_sizenum];
  const Elf32_Sym *symbol_typeinfo =
    &chariot_metadata_localizations->chariot_symbols[CMS_Extraboot_typeinfo];
  // const Elf32_Shdr* metadata_section = chariot_metadata_localizations->metadata_section;
  const char *metadata_buffer_exe =
    chariot_metadata_localizations->metadata_buffer_exe;
  size_t metadata_buffer_len =
    chariot_metadata_localizations->metadata_buffer_len;
  const char *suppldata_buffer_exe = result->suppldata_buffer_exe;
  size_t suppldata_buffer_len = result->suppldata_buffer_len;
  const Elf32_Shdr *suppldata_section = result->suppldata_section;

  if (elf_header->e_shoff +
      (symbol_offsetnum->st_shndx + 1) * Elf32_Shdr_Size > metadata_buffer_len
      || symbol_offsetnum->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of extraboot offsetnum: buffer is too small";
      return false;
    }
  Elf32_Shdr section_container;
  memcpy (&section_container,
	  metadata_buffer_exe + elf_header->e_shoff +
	  symbol_offsetnum->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start_offset =
    metadata_buffer_exe + section_container.sh_offset +
    symbol_offsetnum->st_value;
  if (start_offset - metadata_buffer_exe + symbol_offsetnum->st_size >
      metadata_buffer_len || symbol_offsetnum->st_value < 0)
    {
      *error_message =
	"unable to read extraboot offsetnum: buffer is too small";
      return false;
    }

  if (elf_header->e_shoff + (symbol_sizenum->st_shndx + 1) * Elf32_Shdr_Size >
      metadata_buffer_len || symbol_sizenum->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of extraboot sizenum: buffer is too small";
      return false;
    }
  memcpy (&section_container,
	  metadata_buffer_exe + elf_header->e_shoff +
	  symbol_sizenum->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start_size =
    metadata_buffer_exe + section_container.sh_offset +
    symbol_sizenum->st_value;
  if (start_size - metadata_buffer_exe + symbol_sizenum->st_size >
      metadata_buffer_len || symbol_sizenum->st_value < 0)
    {
      *error_message =
	"unable to read extraboot sizenum: buffer is too small";
      return false;
    }
  uint32_t start = 0, size = 0;

  if (symbol_offsetnum->st_size != 8)
    {
      *error_message = "invalid size for extraboot offsetnum";
      return false;
    }
  for (int index = 0; index < symbol_offsetnum->st_size; ++index)
    {
      if (!add_hex_digit (start_offset[index], &start))
	{
	  *error_message = "invalid value for extraboot offsetnum";
	  return false;
	};
    }
  if (symbol_sizenum->st_size != 8)
    {
      *error_message = "invalid size for extraboot sizenum";
      return false;
    }
  for (int index = 0; index < symbol_sizenum->st_size; ++index)
    {
      if (!add_hex_digit (start_size[index], &size))
	{
	  *error_message = "invalid value for extraboot sizenum";
	  return false;
	};
    }

  if (suppldata_section->sh_offset + start + size > suppldata_buffer_len
      || start < 0 || start + size > suppldata_section->sh_size)
    {
      *error_message =
	"unable to read extraboot content: buffer is too small";
      return false;
    };
  result->start = suppldata_buffer_exe + suppldata_section->sh_offset + start;
  result->len = size;

  if (elf_header->e_shoff + (symbol_sha256->st_shndx + 1) * Elf32_Shdr_Size >
      metadata_buffer_len || symbol_sha256->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of extraboot sha256: buffer is too small";
      return false;
    }
  memcpy (&section_container,
	  metadata_buffer_exe + elf_header->e_shoff +
	  symbol_sha256->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start_sha256 =
    metadata_buffer_exe + section_container.sh_offset +
    symbol_sha256->st_value;
  if (start_sha256 - metadata_buffer_exe + symbol_sha256->st_size >
      metadata_buffer_len || symbol_sha256->st_value < 0)
    {
      *error_message = "unable to read extraboot sha256: buffer is too small";
      return false;
    }
  if (symbol_sha256->st_size < 64)
    {
      *error_message = "sha256 is not long enough for extraboot sha256";
      return false;
    };
  if (!fill_sha256 (result->sha256, start_sha256))
    {
      *error_message = "invalid sha256 for extraboot sha256";
      return false;
    };

  if (elf_header->e_shoff +
      (symbol_typeinfo->st_shndx + 1) * Elf32_Shdr_Size > metadata_buffer_len
      || symbol_typeinfo->st_shndx < 0)
    {
      *error_message =
	"unable to find the section having the content of extraboot typeinfo: buffer is too small";
      return false;
    }
  memcpy (&section_container,
	  metadata_buffer_exe + elf_header->e_shoff +
	  symbol_typeinfo->st_shndx * Elf32_Shdr_Size, Elf32_Shdr_Size);
  const char *start_typeinfo =
    metadata_buffer_exe + section_container.sh_offset +
    symbol_typeinfo->st_value;
  if (start_typeinfo - metadata_buffer_exe + symbol_typeinfo->st_size >
      metadata_buffer_len || symbol_typeinfo->st_value < 0)
    {
      *error_message =
	"unable to read extraboot typeinfo: buffer is too small";
      return false;
    }
  result->typeinfo = start_typeinfo;
  result->typeinfo_len = symbol_typeinfo->st_size;
  return true;
}
