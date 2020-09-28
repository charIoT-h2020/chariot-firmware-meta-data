/*
 *  Copyright (c) 2019-2020,
 *  Commissariat a l'Energie Atomique (CEA)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   - Neither the name of CEA nor the names of its contributors may be used to
 *     endorse or promote products derived from this software without specific 
 *     prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY 
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  Authors: Franck Vedrine (franck.vedrine@cea.fr)
 *  Funding: European Union’s Horizon 2020 RIA programme
 *     under grant agreement No 780075
 *     CHARIOT - Cognitive Heterogeneous Architecture for Industrial IoT
 */

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


