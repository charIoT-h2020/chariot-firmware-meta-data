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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

typedef struct _InputParser {
  const char* exe_name;
  bool requires_help : 1;
  bool requires_all : 1;
  bool requires_verbose : 1;
  bool requires_sha : 1;
  bool requires_format : 1;
  bool requires_version : 1;
  bool requires_blockchain_path : 1;
  bool requires_license : 1;
  bool requires_software_id : 1;
  bool requires_additional : 1;
  bool requires_cut : 1;
  const char* output_file;
  const char* output_exe_file;
  const char* static_analysis_file;
} InputParser;

int
standard_error(FILE* out_file, FILE* hexm_file, InputParser* parser) {
  printf("original file %s has not expected hybrid format\n", parser->exe_name);
  if (out_file) fclose(out_file);
  fclose(hexm_file);
  return 1;
}

void
ensure_endianness(u_int32_t* value) {
  int hostEndianness = 0x1234;
  if (*(char*)(&hostEndianness) == 0x34) { // little endian
    u_int32_t res = 0;
    res |= (*value & 0xff) << 24;
    res |= ((*value >> 8) & 0xff) << 16;
    res |= ((*value >> 16) & 0xff) << 8;
    res |= ((*value >> 24) & 0xff);
    *value = res;
  }
}

int
retrieve_size_number(const char* buffer, u_int32_t* res) { /* buffer has at least 8 chars */
  *res = 0;
  for (int i = 0; i < 4; ++i) {
    char ch = buffer[2*i];
    if (ch >= '0' && ch <= '9')
      *res |= (ch - '0') << (i*8+4);
    else if (ch >= 'a' && ch <= 'f')
      *res |= (ch - 'a' + 10) << (i*8+4);
    else if (ch >= 'A' && ch <= 'F')
      *res |= (ch - 'A' + 10) << (i*8+4);
    else
      return 1;
    ch = buffer[2*i+1];
    if (ch >= '0' && ch <= '9')
      *res |= (ch - '0') << (i*8);
    else if (ch >= 'a' && ch <= 'f')
      *res |= (ch - 'a' + 10) << (i*8);
    else if (ch >= 'A' && ch <= 'F')
      *res |= (ch - 'A' + 10) << (i*8);
    else
      return 1;
  }
  ensure_endianness(res);
  return 0;
}

int
locate_line_from_end(FILE* hexm_file, InputParser* parser) {
  int expected_last_line = 80;
  const char* last_line = ":00000001FF";
  const char* pattern_line_number = ":0a0000003a3axxxxxxxyyyyyyyyyzz";
  char buffer[80];
  if (fseek(hexm_file, 0, SEEK_END)) {
    printf("impossible to find metadata, error code = %d", errno);
    return 1;
  }
  size_t file_size = ftell(hexm_file);
  while (expected_last_line < file_size) {
    if (fseek(hexm_file, file_size-expected_last_line, SEEK_SET)) {
      printf("impossible to find metadata, error code = %d", errno);
      return 1;
    }
    int len = fread(buffer, 1, 80, hexm_file);
    int i = len;
    bool first = true;
    while (--i >= 0) {
      if (buffer[i] == '\n' || first) {
        if (first)
          first = false;
        int j = (buffer[i] == '\n') ? i : i+1;
        int k = strlen(last_line);
        while (--k >= 0) {
          --j;
          if (buffer[j] != last_line[k])
            break;
        }
        if (k > 0 || buffer[j-1] != '\n')
          continue;
        --j;
        i = j;
        k = strlen(pattern_line_number);
        while (--k >= 0) {
          --j;
          if ((pattern_line_number[k] != 'x' && pattern_line_number[k] != 'y'
                  && pattern_line_number[k] != 'z' && buffer[j] != pattern_line_number[k]))
            break;
        }
        if (k > 0 || buffer[j-1] != '\n') {
          printf("original file %s has not expected hybrid format", parser->exe_name);
          return 1;
        }

        u_int32_t total_line, add_line;
        int error_code;
        if ((error_code = retrieve_size_number(&buffer[j+13], &total_line)) != 0)
          return error_code;
        if ((error_code = retrieve_size_number(&buffer[j+21], &add_line)) != 0)
          return error_code;

        fseek(hexm_file, 0, SEEK_SET);
        char buffer[4096];
        size_t result = 0, result_add = 0;
        while (total_line > 0 || add_line > 0) {
          int count = fread(buffer, 1, 4096, hexm_file);
          if (count <= 0)
            break;
          int start_add = 0;
          for (int i = 0; i < count; ++i) {
            if (buffer[i] == '\n') {
              if (total_line > 0) {
                --total_line;
                if (total_line == 0) {
                  result += i+1;
                  start_add = i+1;
                }
              }
              else if (add_line > 0) {
                --add_line;
                if (add_line == 0) {
                  result_add += i+1-start_add;
                  break;
                }
              }
            }
          }
          if (total_line > 0)
            result += count;
          else if (add_line > 0)
            result_add += count-start_add;
        }
        if (fseek(hexm_file, result + result_add, SEEK_SET)) {
          printf("impossible to locate meta-data = %d", errno);
          return 1;
        }
        int count = fread(buffer, 1, strlen(last_line)+1, hexm_file);
        if (count >= strlen(last_line)) {
          if (count == strlen(last_line) || buffer[strlen(last_line)] == '\n')
            buffer[strlen(last_line)] = '\0';
          else
            buffer[count] = '\0';
          if (strcmp(buffer, last_line) != 0) {
            printf("impossible to locate meta-data = %d", errno);
            return 1;
          }
        }
        else {
          printf("impossible to locate meta-data = %d", errno);
          return 1;
        }
        fseek(hexm_file, result, SEEK_SET);
        return 0;
      }
    }
    expected_last_line += 40;
  }
  printf("original file %s has not expected hybrid format", parser->exe_name);
  return 1;
}

int
convert_hex_line(FILE* hexm_file, FILE* out_file, size_t* bytes_number,
    char buffer[512], int* len_header, bool* does_start_line, int* len,
    int* checksum, InputParser* parser) {
  size_t line;
  if (*does_start_line)
     line = (*bytes_number > 0) ? ((*bytes_number+0xff-1) / 0xff) : 1;
  else {
     line = 1;
     if (*bytes_number > (size_t) *len)
        line += (((*bytes_number - *len)+0xff-1) / 0xff);
  }
  int cur_bytes = *bytes_number;
  if (*bytes_number > 512) {
    *bytes_number -= 512;
    cur_bytes = 512;
  }
  else
    *bytes_number = 0;

  int start = 0;
  while (line > 0) {
    if (*does_start_line) {
      if (fgetc(hexm_file) != ':')
        return standard_error(out_file, hexm_file, parser);
      *len=0;
      char ch = fgetc(hexm_file);
      if (ch >= '0' && ch <= '9')
        *len |= (ch - '0') << 4;
      else if (ch >= 'a' && ch <= 'f')
        *len |= (ch - 'a' + 10) << 4;
      else if (ch >= 'A' && ch <= 'F')
        *len |= (ch - 'A' + 10) << 4;
      else
        return standard_error(out_file, hexm_file, parser);
      ch = fgetc(hexm_file);
      if (ch >= '0' && ch <= '9')
        *len |= (ch - '0');
      else if (ch >= 'a' && ch <= 'f')
        *len |= (ch - 'a' + 10);
      else if (ch >= 'A' && ch <= 'F')
        *len |= (ch - 'A' + 10);
      else
        return standard_error(out_file, hexm_file, parser);
      for (int i=0; i < 6; ++i)
        if (fgetc(hexm_file) != '0')
          return standard_error(out_file, hexm_file, parser);
      *checksum = *len;
    }
    for (int i = 0; i < *len; ++i) {
      int byte = 0;
      char ch = fgetc(hexm_file);
      if (ch >= '0' && ch <= '9')
        byte |= (ch - '0') << 4;
      else if (ch >= 'a' && ch <= 'f')
        byte |= (ch - 'a' + 10) << 4;
      else if (ch >= 'A' && ch <= 'F')
        byte |= (ch - 'A' + 10) << 4;
      else
        return standard_error(out_file, hexm_file, parser);
      ch = fgetc(hexm_file);
      if (ch >= '0' && ch <= '9')
        byte |= (ch - '0');
      else if (ch >= 'a' && ch <= 'f')
        byte |= (ch - 'a' + 10);
      else if (ch >= 'A' && ch <= 'F')
        byte |= (ch - 'A' + 10);
      else
        return standard_error(out_file, hexm_file, parser);
      buffer[start+i] = byte;
      *checksum += byte;
      if (len_header && (start+i == 0) && buffer[start+i] != ':')
        return standard_error(out_file, hexm_file, parser);
      if ((--cur_bytes == 0 && (i+1 < *len))
            || (len_header && (!*len_header ? (i > 0 && buffer[start+i] == ':')
                                            : (i > *len_header)))) {
        if (!len_header && *bytes_number == 0)
          return standard_error(out_file, hexm_file, parser);
        if (len_header) {
           buffer[start+i+1] = '\0';
           *len_header = i+1;
        }
        *len -= (i+1);
        *bytes_number += cur_bytes;
        *does_start_line = false;
        return 0;
      }
    }
    *checksum = -*checksum;
    *checksum &= 0xff;
    int verif_checksum = 0;
    char ch = fgetc(hexm_file);
    if (ch >= '0' && ch <= '9')
      verif_checksum |= (ch - '0') << 4;
    else if (ch >= 'a' && ch <= 'f')
      verif_checksum |= (ch - 'a' + 10) << 4;
    else if (ch >= 'A' && ch <= 'F')
      verif_checksum |= (ch - 'A' + 10) << 4;
    else
      return standard_error(out_file, hexm_file, parser);
    ch = fgetc(hexm_file);
    if (ch >= '0' && ch <= '9')
      verif_checksum |= (ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      verif_checksum |= (ch - 'a' + 10);
    else if (ch >= 'A' && ch <= 'F')
      verif_checksum |= (ch - 'A' + 10);
    else
      return standard_error(out_file, hexm_file, parser);
    while ((ch = fgetc(hexm_file)) == ' ' || ch == '\t') {}
    if (verif_checksum != *checksum)
      return standard_error(out_file, hexm_file, parser);
    if (ch != '\n')
      return standard_error(out_file, hexm_file, parser);
    --line;
    *does_start_line = true;
    start += *len;
  }
  return 0;
}

void
input_parser_usage()
{
  printf("usage: chariot_extracthex_meta_data [-h] [--all] [--verbose] [--sha]\n"
         "                                    [--blockchain_path] [--license]\n"
         "                                    [--static-analysis FILE] [--add]\n"
         "                                    [--format] [--output OUTPUT]\n"
         "                                    [--cut OUTPUT_HEX]\n"
         "                                    hex_name\n"
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
      else if (strcmp(argv[i], "-format") == 0 || strcmp(argv[i], "--format") == 0)
        parser->requires_format = true;
      else if (strcmp(argv[i], "-format") == 0 || strcmp(argv[i], "--format") == 0)
        parser->requires_format = true;
      else if (strcmp(argv[i], "-ver") == 0 || strcmp(argv[i], "--version") == 0)
        parser->requires_version = true;
      else if (strcmp(argv[i], "-bp") == 0 || strcmp(argv[i], "--blockchain_path") == 0)
        parser->requires_blockchain_path = true;
      else if (strcmp(argv[i], "-lic") == 0 || strcmp(argv[i], "--license") == 0)
        parser->requires_license = true;
      else if (strcmp(argv[i], "-soft") == 0 || strcmp(argv[i], "--software_ID") == 0)
        parser->requires_software_id = true;
      else if (strcmp(argv[i], "-sa") == 0 || strcmp(argv[i], "--static-analysis") == 0)
      {
        if (++i >= argc)
          return false;
        parser->static_analysis_file = argv[i];
      }
      else if (strcmp(argv[i], "-add") == 0 || strcmp(argv[i], "--add") == 0)
        parser->requires_additional = true;
      else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
      {
        if (++i >= argc)
          return false;
        parser->output_file = argv[i];
      }
      else if (strcmp(argv[i], "-cut") == 0 || strcmp(argv[i], "--cut") == 0)
      {
        if (++i >= argc)
          return false;
        parser->requires_cut = true;
        parser->output_exe_file = argv[i];
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

int
extract_firmware(FILE* hexm_file, FILE* out_file, InputParser* parser) {
  if (parser->requires_cut) {
    if (parser->requires_verbose)
      printf("extract firmware\n");

    size_t seek_val = ftell(hexm_file);
    if (!parser->output_exe_file) {
      printf("extraction of all firmware requires an input file\n");
      if (out_file) fclose(out_file);
      fclose(hexm_file);
      return 1;
    }
    char buffer[4096];
    size_t count = 0;
    FILE* out_exe_file = fopen(parser->output_exe_file, "w");
    if (!out_exe_file) {
      printf("unable to create firmware file\n");
      if (out_file) fclose(out_file);
      fclose(hexm_file);
      return 1;
    }
    fseek(hexm_file, 0, SEEK_SET);

    while (count < seek_val) {
      int len = fread(buffer, 1,
          (count + 4096 > seek_val) ? (seek_val-count) : 4096, hexm_file);
      count += len;
      if (len > 0)
        fwrite(buffer, 1, len, out_exe_file);
      else
        break;
    }
    fwrite(":00000001FF\n", 1, strlen(":00000001FF\n"), out_exe_file);
    fclose(out_exe_file);
  }
  return 0;
}

int
extract_all_metadata(FILE* hexm_file, FILE* out_file, InputParser* parser) {
  if (!out_file) {
    printf("extraction of all meta-data requires an output file\n");
    if (out_file) fclose(out_file);
    fclose(hexm_file);
    return 1;
  }
  char buffer[4096];
  while (true) {
    int len = fread(buffer, 1, 4096, hexm_file);
    if (len > 0)
      fwrite(buffer, 1, len, out_file);
    else
      break;
  }
  return 0;
}

int
extract_header(FILE* hexm_file, FILE* out_file, char buffer[512],
      InputParser* parser) {
  int error_code;
  size_t bytes_number = strlen(":chariot_md:");
  int len = 0, checksum = 0;
  bool does_start_line = true;
  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      buffer, NULL /* len_header */, &does_start_line, &len,
      &checksum, parser)) != 0)
    return standard_error(out_file, hexm_file, parser);
  buffer[len] = '\0';
  if (strcmp(buffer, ":chariot_md:") != 0)
    return standard_error(out_file, hexm_file, parser);
  return 0;
}

int
extract_sha(FILE* hexm_file, FILE* out_file, char buffer[512],
      InputParser* parser) {
  if (parser->requires_sha && parser->requires_verbose)
    printf("extract sha256 of %s\n", parser->exe_name);
  int error_code;
  size_t bytes_number = strlen(":sha256:");
  int len = 0, checksum = 0;
  bool does_start_line = true;
  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      buffer, NULL /* len_header */, &does_start_line, &len, &checksum,
      parser)) != 0)
    return standard_error(out_file, hexm_file, parser);
  buffer[len] = '\0';
  if (strcmp(buffer, ":sha256:") != 0)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_sha) {
    bytes_number = 256/8; len = 0; checksum = 0;
    does_start_line = true;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        buffer, NULL /* len_header */, &does_start_line, &len, &checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    if (!does_start_line || bytes_number != 0)
      return standard_error(out_file, hexm_file, parser);

    for (int i = 256/8-1; i >= 0; --i) {
      int val = buffer[i] & 0xf;
      buffer[2*i+1] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
      val = (buffer[i] >> 4) & 0xf;
      buffer[2*i] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
    }
    buffer[256/4] = '\n',
    fwrite(buffer, 1, 256/4+1, out_file);
  }
  else {
    char ch;
    while (((ch = fgetc(hexm_file)) != EOF) && ch != '\n') {}
  }
  return 0;
}

int
extract_format(FILE* hexm_file, FILE* out_file, char buffer[512],
      InputParser* parser) {
  if (parser->requires_verbose && parser->requires_format)
    printf("extract chariot format");
  int error_code;
  size_t bytes_number = strlen(":fmt:")+4;
  int len = 0, checksum = 0;
  bool does_start_line = true;
  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      buffer, NULL /* len_header */, &does_start_line, &len, &checksum,
      parser)) != 0)
    return standard_error(out_file, hexm_file, parser);
  if (strncmp(buffer, ":fmt:", strlen(":fmt:")) != 0)
    return standard_error(out_file, hexm_file, parser);
  u_int32_t fmt_size = 0;
  memcpy(&fmt_size, &buffer[strlen(":fmt:")], 4);
  ensure_endianness(&fmt_size);

  bytes_number = fmt_size; len = 0; checksum = 0;
  does_start_line = true;
  do {
    int nb_bytes = bytes_number;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        buffer, NULL /* len_header */, &does_start_line, &len, &checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    if (parser->requires_format)
      fwrite(buffer, 1, nb_bytes - bytes_number, out_file);
  } while (!does_start_line || bytes_number > 0);
  if (parser->requires_format)
    fputc('\n', out_file);
  return 0;
}

int
extract_field_head(FILE* hexm_file, FILE* out_file, char buffer[512],
    int* len_field, int* len, int* checksum, InputParser* parser) {
  size_t bytes_number = 0xff;
  int error_code;
  bool does_start_line = true;

  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      buffer, len_field, &does_start_line, len, checksum,
      parser)) != 0)
    return standard_error(out_file, hexm_file, parser);
  if (does_start_line)
    return standard_error(out_file, hexm_file, parser);
  return 0;
}

int
extract_additional_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":add:") == 0) {
    if (parser->requires_verbose && parser->requires_additional)
      printf("extract chariot additional file\n");
    if (*len != 4)
      return standard_error(out_file, hexm_file, parser);
    u_int32_t additional_size = 0;
    int error_code;
    bool does_start_line = false;
    size_t bytes_number = *len;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        field_buffer, NULL, &does_start_line, len, checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    memcpy(&additional_size, field_buffer, 4);
    ensure_endianness(&additional_size);

    bytes_number = additional_size;
    { does_start_line = true;
      /* int len_header = additional_size; */
      do {
        int nb_bytes = bytes_number;
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_additional)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, out_file);
      } while (!does_start_line || bytes_number > 0);
      if (parser->requires_additional)
        fputc('\n', out_file);
    }
    bytes_number = 5;
    does_start_line = true;
    if ((error_code = convert_hex_line(hexm_file, out_file,
        &bytes_number, field_buffer, NULL, &does_start_line, len,
        checksum, parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    if (field_buffer[0] != ':')
      return standard_error(out_file, hexm_file, parser);
    u_int32_t additional_mime_size = 0;
    memcpy(&additional_mime_size, &field_buffer[1], 4);
    ensure_endianness(&additional_mime_size);
    bytes_number = additional_mime_size;
    { does_start_line = true;
      /* int len_header = additional_size; */
      do {
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
      } while (!does_start_line || bytes_number > 0);
    }
    int return_code;
    *len_field = 0;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, len, checksum, parser)) != 0)
      return return_code;
  }
  else if (parser->requires_additional) {
    if (out_file == stdout)
      putchar('\n');
  }
  return 0;
}

int
extract_version_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":version:") != 0)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_verbose && parser->requires_format)
    printf("extract chariot version");
  if (*len != 0)
    return standard_error(out_file, hexm_file, parser);
  int error_code;
  bool does_start_line = false;
  size_t bytes_number = *len;
  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      field_buffer, NULL, &does_start_line, len, checksum,
      parser)) != 0)
    return standard_error(out_file, hexm_file, parser);

  bytes_number = 20;
  *len = 0; *checksum = 0;
  does_start_line = true;
  if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
      field_buffer, NULL /* len_header */, &does_start_line, len, checksum,
      parser)) != 0)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_version) {
    for (int i = 20-1; i >= 0; --i) {
      int val = field_buffer[i] & 0xf;
      field_buffer[2*i+1] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
      val = (field_buffer[i] >> 4) & 0xf;
      field_buffer[2*i] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
    }
    field_buffer[40] = '\n',
    fwrite(field_buffer, 1, 40+1, out_file);
  }
  return 0;
}

int
extract_license_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":lic:") == 0) {
    if (parser->requires_verbose && parser->requires_license)
      printf("extract chariot license file\n");
    u_int32_t license_size = 0;
    int error_code;
    bool does_start_line = false;
    size_t bytes_number = *len;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        field_buffer, NULL, &does_start_line, len, checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    memcpy(&license_size, field_buffer, 4);
    ensure_endianness(&license_size);

    bytes_number = license_size;
    { does_start_line = true;
      do {
        int nb_bytes = bytes_number;
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_license)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, out_file);
      } while (!does_start_line || bytes_number > 0);
      if (parser->requires_license)
        fputc('\n', out_file);
    }

    int return_code;
    *len_field = 0;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, len, checksum, parser)) != 0)
      return return_code;
  }
  else if (parser->requires_license) {
    if (out_file == stdout)
      putchar('\n');
  }
  return 0;
}

int
extract_software_id_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":soft:") == 0) {
    if (parser->requires_verbose && parser->requires_software_id)
      printf("extract chariot software_id file\n");
    u_int32_t software_id_size = 0;
    int error_code;
    bool does_start_line = false;
    size_t bytes_number = *len;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        field_buffer, NULL, &does_start_line, len, checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    memcpy(&software_id_size, field_buffer, 4);
    ensure_endianness(&software_id_size);

    bytes_number = software_id_size;
    { does_start_line = true;
      do {
        int nb_bytes = bytes_number;
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_software_id)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, out_file);
      } while (!does_start_line || bytes_number > 0);
      if (parser->requires_software_id)
        fputc('\n', out_file);
    }

    int return_code;
    *len_field = 0;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, len, checksum, parser)) != 0)
      return return_code;
  }
  else if (parser->requires_software_id) {
    if (out_file == stdout)
      putchar('\n');
  }
  return 0;
}

int
extract_blockchain_path_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":bcpath:") == 0) {
    if (parser->requires_verbose && parser->requires_blockchain_path)
      printf("extract chariot blockchain path\n");
    u_int32_t blockchain_path_size = 0;
    int error_code;
    bool does_start_line = false;
    size_t bytes_number = *len;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        field_buffer, NULL, &does_start_line, len, checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    memcpy(&blockchain_path_size, field_buffer, 4);
    ensure_endianness(&blockchain_path_size);

    bytes_number = blockchain_path_size;
    { does_start_line = true;
      do {
        int nb_bytes = bytes_number;
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_blockchain_path)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, out_file);
      } while (!does_start_line || bytes_number > 0);
      if (parser->requires_blockchain_path)
        fputc('\n', out_file);
    }

    int return_code;
    *len_field = 0;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, len, checksum, parser)) != 0)
      return return_code;
  }
  else if (parser->requires_blockchain_path) {
    if (out_file == stdout)
      putchar('\n');
  }
  return 0;
}

int
extract_static_analysis_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[512], int* len_field, int* len, int* checksum,
    InputParser* parser) {
  if (strcmp(field_buffer, ":sca:") == 0) {
    FILE* static_file = NULL;
    if (parser->static_analysis_file)
      static_file = fopen(parser->static_analysis_file, "wb");
    if (parser->requires_verbose && parser->static_analysis_file)
      printf("extract chariot static analysis results\n");
    if (*len != 4)
      return standard_error(out_file, hexm_file, parser);
    u_int32_t static_analysis_size = 0;
    int error_code;
    bool does_start_line = false;
    size_t bytes_number = *len;
    if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
        field_buffer, NULL, &does_start_line, len, checksum,
        parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    memcpy(&static_analysis_size, field_buffer, 4);
    ensure_endianness(&static_analysis_size);

    bytes_number = static_analysis_size;
    { does_start_line = true;
      /* int len_header = static_analysis_size; */
      do {
        int nb_bytes = bytes_number;
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
        if (static_file)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, static_file);
        else if (parser->static_analysis_file)
          fwrite(field_buffer, 1, nb_bytes - bytes_number, out_file);
      } while (!does_start_line || bytes_number > 0);
      if (parser->static_analysis_file)
        fputc('\n', out_file);
    }
    bytes_number = 5;
    does_start_line = true;
    if ((error_code = convert_hex_line(hexm_file, out_file,
        &bytes_number, field_buffer, NULL, &does_start_line, len,
        checksum, parser)) != 0)
      return standard_error(out_file, hexm_file, parser);
    if (static_file)
      fclose(static_file);
    if (field_buffer[0] != ':')
      return standard_error(out_file, hexm_file, parser);
    u_int32_t static_analysis_mime_size = 0;
    memcpy(&static_analysis_mime_size, &field_buffer[1], 4);
    ensure_endianness(&static_analysis_mime_size);
    bytes_number = static_analysis_mime_size;
    { does_start_line = true;
      /* int len_header = static_analysis_size; */
      do {
        if ((error_code = convert_hex_line(hexm_file, out_file, &bytes_number,
            field_buffer, NULL /* &len_header */, &does_start_line, len, checksum,
            parser)) != 0)
          return standard_error(out_file, hexm_file, parser);
      } while (!does_start_line || bytes_number > 0);
    }
  }
  else if (parser->static_analysis_file) {
    if (out_file == stdout)
      putchar('\n');
  }
  return 0;
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
           "Extract Chariot meta-data from a hex firmware\n"
           "\n"
           "positional arguments:\n"
           "  hex_name              the name of the executable hex file\n"
           "\n"
           "optional arguments:\n"
           "  -h, --help            show this help message and exit\n"
           "  --all, -a             equivalent to -sha -sa -bp -lic -add\n"
           "  --verbose, -v         verbose mode: echo every command on terminal\n"
           "  --sha, -sha           print the sha256 of the bin file\n"
           "  --format, -format     print the format\n"
           "  --blockchain_path, -bp\n"
           "                        print the path to the targeted blockchain\n"
           "  --license, -lic       print the license of the firmware\n"
           "  --static-analysis, -sa FILE\n"
           "                        print the result of the static analysis in file\n"
           "  --add, -add           print content of the additional section\n"
           "  --output OUTPUT, -o OUTPUT\n"
           "                        print into the output file instead of stdout\n"
           "\n");
    return 0;
  }

  FILE* out_file = NULL;
  bool is_valid_out_file = false;
  if (parser.output_file && strlen(parser.output_file) > 0)
  {
    out_file = fopen(parser.output_file, "wb");
    is_valid_out_file = out_file != NULL;
  }
  if (!is_valid_out_file)
    out_file = stdout;

  FILE* hexm_file = fopen(parser.exe_name, "r");
  if (!hexm_file)
  {
    fprintf(stderr, "Cannot open file %s\n", parser.exe_name);
    return 1;
  }
  int error_code;
  if ((error_code = locate_line_from_end(hexm_file, &parser)) != 0)
    return standard_error(out_file, hexm_file, &parser);

  if ((error_code = extract_firmware(hexm_file, out_file, &parser)) != 0)
    return error_code;
  if (parser.requires_all) {
    if ((error_code = extract_all_metadata(hexm_file, out_file, &parser)) != 0)
      return error_code;
    if (out_file) fclose(out_file);
    fclose(hexm_file);
    return 0;
  }

  if (parser.requires_verbose)
    printf("extract meta-data section\n");
  char buffer[512]; 
  if ((error_code = extract_header(hexm_file, out_file, buffer, &parser)) != 0)
    return error_code;
  /* hexm_file has advanced */
  if ((error_code = extract_sha(hexm_file, out_file, buffer, &parser)) != 0)
    return error_code;
  if ((error_code = extract_format(hexm_file, out_file, buffer, &parser)) != 0)
    return error_code;

  int len_field=0;
  int state_len = 0, state_checksum = 0;
  if ((error_code = extract_field_head(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_additional_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_version_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  len_field = 0;
  if ((error_code = extract_field_head(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_blockchain_path_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_license_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_software_id_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;
  if ((error_code = extract_static_analysis_from_field(hexm_file, out_file, buffer,
          &len_field, &state_len, &state_checksum, &parser)) != 0)
    return error_code;

  if (out_file) fclose(out_file);
  fclose(hexm_file);
  return 0;
}

