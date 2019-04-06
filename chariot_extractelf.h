/*
 * Chariot specific metadata extraction API from elf buffer
 */

#pragma once

#include "elf32.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
   CMS_Mainboot_sha256, CMS_Format_typeinfo, CMS_Mainboot_offsetnum, CMS_Mainboot_sizesnum,
   CMS_Extraboot_sha256, CMS_Extraboot_offsetnum, CMS_Extraboot_sizenum, CMS_Extraboot_typeinfo,
   CMS_Codanalys_typeinfo, CMS_Version_data, CMS_Firmware_path, CMS_Firmware_license,
   CMS_Codanalys_data, CMS_END
} Chariot_Metadata_Symbols;

typedef enum {
   CS_Meta, CS_Extra
} Chariot_Section;

int fill_exe_header(Elf32_Ehdr* result, const char* buffer_exe, size_t buffer_len, const char** error_message);
int retrieve_section_header(Elf32_Shdr* section_header, const Elf32_Ehdr* elf_header,
      const char* buffer_exe, size_t buffer_len, Chariot_Section section, const char** error_message);

typedef struct {
   Elf32_Sym chariot_symbols[CMS_END];
   uint32_t valid_entries;
   const Elf32_Ehdr* metadata_header;
   Elf32_Shdr* metadata_section;
   const char* metadata_buffer_exe;
   size_t metadata_buffer_len;
} Chariot_Metadata_localizations;

int fill_metadata_dict(Chariot_Metadata_localizations* chariot_metadata_localizations,
      const char** error_message);

int retrieve_mainboot_sha256(uint32_t result[8],
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_format_typeinfo(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_codanalys_typeinfo(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_version_data(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_firmware_path(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_firmware_license(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);
int retrieve_codanalys_data(const char** result, size_t* result_len,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);

typedef struct {
   uint32_t sha256[8];
   const char* typeinfo;
   Elf32_Word typeinfo_len;
   const char* start;
   Elf32_Word len;
   const Elf32_Ehdr* suppldata_header;
   Elf32_Shdr* suppldata_section;
   const char* suppldata_buffer_exe;
   size_t suppldata_buffer_len;
} Chariot_Metadata_extraboot;

int retrieve_extraboot(Chariot_Metadata_extraboot* result,
      const Chariot_Metadata_localizations* chariot_metadata_localizations, const char** error_message);

#ifdef __cplusplus
}
#endif


