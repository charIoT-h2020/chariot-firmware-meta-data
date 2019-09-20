#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdbool.h>

#include "chariot_extractelf.h"

typedef struct _InputParser {
  const char* exe_name;
  bool requires_help : 1;
  bool requires_all : 1;
  bool requires_verbose : 1;
  bool requires_sha : 1;
  bool requires_blockchain_path : 1;
  bool requires_license : 1;
  bool requires_static_analysis : 1;
  bool requires_additional : 1;
  const char* output_file;
} InputParser;

void
input_parser_usage()
{
  printf("usage: chariot_extractelf_meta_data.py [-h] [--all] [--verbose] [--sha]\n"
         "                                       [--blockchain_path] [--license]\n"
         "                                       [--static-analysis] [--add]\n"
         "                                       [--output OUTPUT]\n"
         "                                       exe_name\n"
         "\n");
}

bool
fill_input_parser_fields(InputParser* parser, int argc, const char** argv)
{
  memset(parser, 0, sizeof(InputParser));
  for (int i = 1; i < argc; ++i)
  {
    if (argv[i][0] == '-')
    {
      if (strcmp(argv[i], "-h") == 0)
        parser->requires_help = true;
      else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0)
        parser->requires_all = true;
      else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        parser->requires_verbose = true;
      else if (strcmp(argv[i], "-sha") == 0 || strcmp(argv[i], "--sha") == 0)
        parser->requires_sha = true;
      else if (strcmp(argv[i], "-bp") == 0 || strcmp(argv[i], "--blockchain_path") == 0)
        parser->requires_blockchain_path = true;
      else if (strcmp(argv[i], "-lic") == 0 || strcmp(argv[i], "--license") == 0)
        parser->requires_license = true;
      else if (strcmp(argv[i], "-sa") == 0 || strcmp(argv[i], "--static-analysis") == 0)
        parser->requires_static_analysis = true;
      else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
      {
        if (++i >= argc)
          return false;
        parser->output_file = argv[i];
      }
      else
        return false;
    }
    else
      parser->exe_name = argv[i];
  }
  if (!parser->exe_name || strlen(parser->exe_name) == 0)
    return parser->requires_help;
  return true;
}

int main(int argc, const char** argv) {
  InputParser parser;
  if (!fill_input_parser_fields(&parser, argc, argv))
  {
    input_parser_usage();
    return 1;
  }

  if (parser.requires_help)
  {
    input_parser_usage();
    printf("\n"
           "Extract Chariot meta-data from an elf firmware\n"
           "\n"
           "positional arguments:\n"
           "  exe_name              the name of the executable elf file\n"
           "\n"
           "optional arguments:\n"
           "  -h, --help            show this help message and exit\n"
           "  --all, -a             equivalent to -sha -sa -bp -lic -add\n"
           "  --verbose, -v         verbose mode: echo every command on terminal\n"
           "  --sha, -sha           print the sha256 of the boot section\n"
           "  --blockchain_path, -bp\n"
           "                        print the path to the targeted blockchain\n"
           "  --license, -lic       print the license of the firmware\n"
           "  --static-analysis, -sa\n"
           "                        print the result of the static analysis as file/format\n"
           "  --add, -add           print content of the additional section\n"
           "  --output OUTPUT, -o OUTPUT\n"
           "                        print into the output file instead of stdout\n"
           "\n");
    return 0;
  }

  char* buffer = (char*) NULL;
  long int buffer_size = 0;
  {
    FILE* file = fopen(parser.exe_name, "rb");
    if (!file)
    {
      fprintf(stderr, "Cannot open file %s\n", parser.exe_name);
      return 1;
    }
    fseek(file, 0, SEEK_END);
    long int len = ftell(file);
    if (len <= 0 || len >= 20000000L)
    {
      fprintf(stderr, "file %s is too large to be allocated in memory\n", parser.exe_name);
      return 1;
    }
    buffer = malloc(len);
    if (!buffer)
    {
      fprintf(stderr, "buffer not allocated\n");
      return 1;
    }
    fseek(file, 0, SEEK_SET);
    buffer_size = fread(buffer, 1, len, file);
    fclose(file);
  }

  FILE* out_file = NULL;
  bool is_valid_out_file = false;
  if (parser.output_file && strlen(parser.output_file) > 0)
  {
    out_file = fopen(parser.output_file, "w");
    is_valid_out_file = out_file != NULL;
  }
  FILE* out = is_valid_out_file ? out_file : stdout;

  Elf32_Ehdr elf_header;
  const char* error_message = NULL;
  if (parser.requires_verbose)
    printf("call fill_exe_header -> elf_header\n");
  if (!fill_exe_header(&elf_header, &buffer[0], buffer_size, &error_message))
  {
    fprintf(stderr, "Cannot read elf header of %s\n", parser.exe_name);
    fprintf(stderr, "  %s\n", error_message);
    if (out_file) fclose(out_file);
    free(buffer);
    return 1;
  }

  Elf32_Shdr metadata_section;
  if (parser.requires_verbose)
    printf("call retrieve_section_header -> metadata_section\n");
  if (!retrieve_section_header(&metadata_section, &elf_header, &buffer[0], buffer_size,
      CS_Meta, &error_message))
  {
    fprintf(stderr, "Cannot find CHARIOT metadata inside %s\n", parser.exe_name);
    fprintf(stderr, "  %s\n", error_message);
    if (out_file) fclose(out_file);
    free(buffer);
    return 1;
  }

  Elf32_Ehdr metadata_elf_header;
  if (parser.requires_verbose)
    printf("call fill_exe_header -> metadata_elf_header\n");
  if (!fill_exe_header(&metadata_elf_header, &buffer[0] + metadata_section.sh_offset,
      metadata_section.sh_size, &error_message))
  {
    fprintf(stderr, "section .chariotmeta.rodata should also follow the elf format %s\n", parser.exe_name);
    fprintf(stderr, "  %s\n", error_message);
    if (out_file) fclose(out_file);
    free(buffer);
    return 1;
  }

  Chariot_Metadata_localizations metadata_dict;
  metadata_dict.valid_entries = 0;
  metadata_dict.metadata_header = &metadata_elf_header;
  metadata_dict.metadata_section = &metadata_section;
  metadata_dict.metadata_buffer_exe = &buffer[0] + metadata_section.sh_offset;
  metadata_dict.metadata_buffer_len = metadata_section.sh_size;

  if (parser.requires_verbose)
    printf("call fill_metadata_dict -> CHARIOT symbols\n");
  if (!fill_metadata_dict(&metadata_dict, &error_message))
  {
    fprintf(stderr, "Cannot find CHARIOT symbols inside %s\n", parser.exe_name);
    fprintf(stderr, "  %s\n", error_message);
    if (out_file) fclose(out_file);
    free(buffer);
    return 1;
  }

  if (parser.requires_all || parser.requires_sha)
  {
    if (!(metadata_dict.valid_entries & (1U << CMS_Mainboot_sha256)))
      printf("main boot sha256 symbol not assigned\n");
    else
    {
      if (parser.requires_verbose)
        printf("call retrieve_mainboot_sha256 -> sha256\n");
      uint32_t sha256[8];
      if (!retrieve_mainboot_sha256(sha256, &metadata_dict, &error_message))
      {
        fprintf(stderr, "Cannot find mainboot_sha256 inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }
      for (int i = 8; --i >= 0; )
        fprintf(out, "%08x", sha256[i]);
      fprintf(out, " mainboot\n");
    }
  }

  if (parser.requires_all || parser.requires_blockchain_path)
  {
    if (!(metadata_dict.valid_entries & (1U << CMS_Firmware_path)))
      fprintf(out, "firmware path symbol not assigned\n");
    else {
      if (parser.requires_verbose)
        printf("call retrieve_firmware_path -> firmware_path\n");
      const char* firmware_path = NULL;
      size_t firmware_path_len = 0;
      if (!retrieve_firmware_path(&firmware_path, &firmware_path_len, &metadata_dict, &error_message))
      {
        fprintf(stderr, "Cannot find firmware path inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }
      fprintf(out, "CHARIOTMETA_FIRMWARE_PATH=");
      fwrite(firmware_path, 1, firmware_path_len, out);
      fprintf(out, "\n");
    }
  };

  if (parser.requires_all || parser.requires_license)
  {
    if (!(metadata_dict.valid_entries & (1U << CMS_Firmware_license)))
      fprintf(out, "license file symbol not assigned\n");
    else {
      if (parser.requires_verbose)
        printf("call retrieve_firmware_license -> license\n");
      const char* license = NULL;
      size_t license_len = 0;
      if (!retrieve_firmware_license(&license, &license_len, &metadata_dict, &error_message))
      {
        fprintf(stderr, "Cannot find firmware license inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }
      fprintf(out, "CHARIOTMETA_FIRMWARE_LICENSE=");
      fwrite(license, 1, license_len, out);
      fprintf(out, "\n");
    }
  };

  if (parser.requires_all || parser.requires_static_analysis)
  {
    if (!(metadata_dict.valid_entries & (1U << CMS_Codanalys_data)))
      fprintf(out, "code analysis data symbol not assigned\n");
    else {
      if (parser.requires_verbose)
        printf("call retrieve_codanalys_data -> static analysis data\n");
      const char* codanalys_data = NULL;
      size_t codanalys_data_len = 0;
      if (!retrieve_codanalys_data(&codanalys_data, &codanalys_data_len, &metadata_dict, &error_message))
      {
        fprintf(stderr, "Cannot find static code analysis data inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }
      fprintf(out, "CHARIOTMETA_CODANALYS_DATA=");
      fwrite(codanalys_data, 1, codanalys_data_len, out);
      fprintf(out, "\n");
    }
  };

  if (parser.requires_all || parser.requires_additional)
  {
    if (!(metadata_dict.valid_entries & (1U << CMS_Extraboot_offsetnum))
        || !(metadata_dict.valid_entries & (1U << CMS_Extraboot_sizenum)))
      fprintf(out, "extra boot symbol not assigned\n");
    else
    {
      Elf32_Shdr suppldata_section;
      if (parser.requires_verbose)
        printf("call retrieve_section_header -> suppldata_section\n");
      if (!retrieve_section_header(&suppldata_section, &elf_header, &buffer[0], buffer_size, 
            CS_Extra, &error_message))
      {
        fprintf(stderr, "Cannot find CHARIOT metadata inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }

      Elf32_Ehdr suppldata_elf_header;
      if (parser.requires_verbose)
        printf("call fill_exe_header -> suppldata_elf_header\n");
      if (!fill_exe_header(&suppldata_elf_header, &buffer[0] + suppldata_section.sh_offset,
            suppldata_section.sh_size, &error_message))
      {
        fprintf(stderr, "section .suppldata of %s should also follow the elf format\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }

      Elf32_Shdr suppldata_inside_section;
      if (parser.requires_verbose)
        printf("call retrieve_section_header -> suppldata_inside_section\n");
      if (!retrieve_section_header(&suppldata_inside_section, &suppldata_elf_header,
            &buffer[0] + suppldata_section.sh_offset, suppldata_section.sh_size,
            CS_Extra, &error_message))
      {
        fprintf(stderr, "Cannot find CHARIOT suppldata inside suppldata inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      }

      Chariot_Metadata_extraboot extractboot_info;
      extractboot_info.suppldata_header = &suppldata_elf_header;
      extractboot_info.suppldata_section = &suppldata_inside_section;
      extractboot_info.suppldata_buffer_exe = &buffer[0] + suppldata_section.sh_offset;
      extractboot_info.suppldata_buffer_len = suppldata_section.sh_size;
      if (parser.requires_verbose)
        printf("call retrieve_extraboot -> extra boot section\n");
      if (!retrieve_extraboot(&extractboot_info, &metadata_dict, &error_message))
      {
        fprintf(stderr, "Cannot find CHARIOT extra data inside %s\n", parser.exe_name);
        fprintf(stderr, "  %s\n", error_message);
        if (out_file) fclose(out_file);
        free(buffer);
        return 1;
      };
      fwrite(extractboot_info.start, 1, extractboot_info.len, out);
      fprintf(out, "\n");
    }
  };

  if (out_file) fclose(out_file);
  free(buffer);
  return 0;
}

