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
  bool requires_static_analysis : 1;
  bool requires_additional : 1;
  bool requires_cut : 1;
  const char* output_file;
  const char* output_exe_file;
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

void
input_parser_usage()
{
  printf("usage: chariot_extractbin_meta_data.py [-h] [--all] [--verbose] [--sha]\n"
         "                                       [--format] [--version]\n"
         "                                       [--blockchain_path] [--license]\n"
         "                                       [--software_ID] [--static-analysis]\n"
         "                                       [--add] [--output OUTPUT]\n"
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
        parser->requires_static_analysis = true;
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
    FILE* out_exe_file = fopen(parser->output_exe_file, "wb");
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
extract_header(FILE* hexm_file, FILE* out_file, char buffer[100], InputParser* parser) {
  int len = fread(buffer, 1, strlen(":chariot_md:"), hexm_file);
  buffer[len] = '\0';
  if (strcmp(buffer, ":chariot_md:") != 0)
    return standard_error(out_file, hexm_file, parser);
  return 0;
}

int
extract_sha(FILE* hexm_file, FILE* out_file, char buffer[100], InputParser* parser) {
  if (parser->requires_sha && parser->requires_verbose)
    printf("extract sha256 of %s\n", parser->exe_name);
  int len = fread(buffer, 1, strlen(":sha256:"), hexm_file);
  buffer[len] = '\0';
  if (strcmp(buffer, ":sha256:") != 0)
    return standard_error(out_file, hexm_file, parser);
  len = fread(buffer, 1, 256/8, hexm_file);
  if (len != 256/8)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_sha) {
    for (int i = 256/8-1; i >= 0; --i) {
      int val = buffer[i] & 0xf;
      buffer[2*i+1] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
      val = (buffer[i] >> 4) & 0xf;
      buffer[2*i] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
    }
    buffer[256/4] = '\n',
    fwrite(buffer, 1, 256/4+1, out_file);
  }
  return 0;
}

int
extract_format(FILE* hexm_file, FILE* out_file, char buffer[100], InputParser* parser) {
  if (parser->requires_verbose && parser->requires_format)
    printf("extract chariot format");
  int len = fread(buffer, 1, strlen(":fmt:"), hexm_file);
  buffer[len] = '\0';
  if (strcmp(buffer, ":fmt:") != 0)
    return standard_error(out_file, hexm_file, parser);
  u_int32_t fmt_size = 0;
  if (fread(&fmt_size, 1, 4, hexm_file) != 4)
    return standard_error(out_file, hexm_file, parser);
  ensure_endianness(&fmt_size);
  { char buffer[4096];
    do {
      u_int32_t size = fmt_size > 4096 ? 4096 : fmt_size;
      len = fread(buffer, 1, size, hexm_file);
      if (len != size)
        return standard_error(out_file, hexm_file, parser);
      if (parser->requires_format)
        fwrite(buffer, 1, size, out_file);
      fmt_size -= size;
    } while (fmt_size > 0);
  }
  return 0;
}

int
extract_field_head(FILE* hexm_file, FILE* out_file, char buffer[100],
    int* len_field, InputParser* parser) {
  int ch;
  if ((ch = fgetc(hexm_file) != ':') && ch != EOF)
    return standard_error(out_file, hexm_file, parser);
  if (ch == EOF) {
    buffer[0] = '\0';
    *len_field = 0;
    return 0;
  }

  int index = 0;
  while ((ch = fgetc(hexm_file) != ':') && ch != EOF && index < 100-1)
    buffer[index++] = ch;
  if (ch == EOF || index >= 100-1)
    return standard_error(out_file, hexm_file, parser);
  buffer[index] = '\0';
  *len_field = index;
  return 0;
}

int
extract_additional_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "add") == 0) {
    if (parser->requires_verbose && parser->requires_additional)
      printf("extract chariot additional file");
    u_int32_t additional_size = 0;
    if (fread(&additional_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&additional_size);
    if (parser->requires_additional)
    { char buffer[4096];
      do {
        u_int32_t size = additional_size > 4096 ? 4096 : additional_size;
        size_t len = fread(buffer, 1, size, hexm_file);
        if (len != size)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_additional)
          fwrite(buffer, 1, size, out_file);
        additional_size -= size;
      } while (additional_size > 0);
    }
    else if (fseek(hexm_file, additional_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    if (fgetc(hexm_file) != ':')
      return standard_error(out_file, hexm_file, parser);
    u_int32_t additional_mime_size = 0;
    if (fread(&additional_mime_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&additional_mime_size);
    if (fseek(hexm_file, additional_mime_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    int return_code;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, parser)) != 0)
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
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "version") != 0)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_version && parser->requires_verbose)
    printf("extract chariot version\n");
  int len = fread(field_buffer, 1, 256/8, hexm_file);
  if (len != 256/8)
    return standard_error(out_file, hexm_file, parser);
  if (parser->requires_version) {
    for (int i = 256/8-1; i >= 0; --i) {
      int val = field_buffer[i] & 0xf;
      field_buffer[2*i+1] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
      val = (field_buffer[i] >> 4) & 0xf;
      field_buffer[2*i] = (val >= 10) ? (char) (val-10+'a') : (char) (val+'0');
    }
    field_buffer[256/4] = '\n',
    fwrite(field_buffer, 1, 256/4+1, out_file);
  }
  return 0;
}

int
extract_license_from_field(FILE* hexm_file, FILE* out_file,
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "lic") == 0) {
    if (parser->requires_verbose && parser->requires_license)
      printf("extract chariot license file");
    u_int32_t license_size = 0;
    if (fread(&license_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&license_size);
    if (parser->requires_license)
    { char buffer[4096];
      do {
        u_int32_t size = license_size > 4096 ? 4096 : license_size;
        size_t len = fread(buffer, 1, size, hexm_file);
        if (len != size)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_license)
          fwrite(buffer, 1, size, out_file);
        license_size -= size;
      } while (license_size > 0);
    }
    else if (fseek(hexm_file, license_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    int return_code;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, parser)) != 0)
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
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "soft") == 0) {
    if (parser->requires_verbose && parser->requires_software_id)
      printf("extract chariot software_id file");
    u_int32_t software_id_size = 0;
    if (fread(&software_id_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&software_id_size);
    if (parser->requires_software_id)
    { char buffer[4096];
      do {
        u_int32_t size = software_id_size > 4096 ? 4096 : software_id_size;
        size_t len = fread(buffer, 1, size, hexm_file);
        if (len != size)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_software_id)
          fwrite(buffer, 1, size, out_file);
        software_id_size -= size;
      } while (software_id_size > 0);
    }
    else if (fseek(hexm_file, software_id_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    int return_code;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, parser)) != 0)
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
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "bcpath") == 0) {
    if (parser->requires_verbose && parser->requires_blockchain_path)
      printf("extract chariot blockchain path");
    u_int32_t blockchain_size = 0;
    if (fread(&blockchain_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&blockchain_size);
    if (parser->requires_blockchain_path)
    { char buffer[4096];
      do {
        u_int32_t size = blockchain_size > 4096 ? 4096 : blockchain_size;
        size_t len = fread(buffer, 1, size, hexm_file);
        if (len != size)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_blockchain_path)
          fwrite(buffer, 1, size, out_file);
        blockchain_size -= size;
      } while (blockchain_size > 0);
    }
    else if (fseek(hexm_file, blockchain_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    int return_code;
    if ((return_code = extract_field_head(hexm_file, out_file, field_buffer,
            len_field, parser)) != 0)
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
    char field_buffer[100], int* len_field, InputParser* parser) {
  if (strcmp(field_buffer, "sca") == 0) {
    if (parser->requires_verbose && parser->requires_static_analysis)
      printf("extract chariot static_analysis file");
    u_int32_t static_analysis_size = 0;
    if (fread(&static_analysis_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&static_analysis_size);
    if (parser->requires_static_analysis)
    { char buffer[4096];
      do {
        u_int32_t size = static_analysis_size > 4096 ? 4096 : static_analysis_size;
        size_t len = fread(buffer, 1, size, hexm_file);
        if (len != size)
          return standard_error(out_file, hexm_file, parser);
        if (parser->requires_static_analysis)
          fwrite(buffer, 1, size, out_file);
        static_analysis_size -= size;
      } while (static_analysis_size > 0);
    }
    else if (fseek(hexm_file, static_analysis_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
    if (fgetc(hexm_file) != ':')
      return standard_error(out_file, hexm_file, parser);
    u_int32_t static_analysis_mime_size = 0;
    if (fread(&static_analysis_mime_size, 1, 4, hexm_file) != 4)
      return standard_error(out_file, hexm_file, parser);
    ensure_endianness(&static_analysis_mime_size);
    if (fseek(hexm_file, static_analysis_mime_size, SEEK_CUR))
      return standard_error(out_file, hexm_file, parser);
  }
  else if (parser->requires_static_analysis) {
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
           "Extract Chariot meta-data from a bin firmware\n"
           "\n"
           "positional arguments:\n"
           "  exe_name              the name of the executable bin file\n"
           "\n"
           "optional arguments:\n"
           "  -h, --help            show this help message and exit\n"
           "  --all, -a             equivalent to -sha -sa -bp -lic -soft -add\n"
           "  --verbose, -v         verbose mode: echo every command on terminal\n"
           "  --sha, -sha           print the sha256 of the bin file\n"
           "  --format, -format     print the format\n"
           "  --blockchain_path, -bp\n"
           "                        print the path to the targeted blockchain\n"
           "  --license, -lic       print the license of the firmware\n"
           "  --software_ID, -soft  print the software id of the firmware\n"
           "  --static-analysis, -sa\n"
           "                        print the result of the static analysis as file/format\n"
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

  FILE* hexm_file = fopen(parser.exe_name, "rb");
  if (!hexm_file)
  {
    fprintf(stderr, "Cannot open file %s\n", parser.exe_name);
    return 1;
  }
  u_int32_t metadata_size = 0;
  if (fseek(hexm_file, -4, SEEK_END)) {
    printf("impossible to find metadata, error code = %d", errno);
    return 1;
  }
  if (fread(&metadata_size, 1, 4, hexm_file) != 4) {
    printf("impossible to find metadata, error code = %d", errno);
    return 1;
  }
  ensure_endianness(&metadata_size);
  if (fseek(hexm_file, -(long) metadata_size, SEEK_END)) {
    printf("impossible to find metadata, error code = %d", errno);
    return 1;
  }

  int return_code;
  if ((return_code = extract_firmware(hexm_file, out_file, &parser)) != 0)
    return return_code;
  if (parser.requires_all) {
    if ((return_code = extract_all_metadata(hexm_file, out_file, &parser)) != 0)
      return return_code;
    if (out_file) fclose(out_file);
    fclose(hexm_file);
    return 0;
  }

  if (parser.requires_verbose)
    printf("extract meta-data section\n");
  char buffer[100]; 
  if ((return_code = extract_header(hexm_file, out_file, buffer, &parser)) != 0)
    return return_code;
  /* hexm_file has advanced */
  if ((return_code = extract_sha(hexm_file, out_file, buffer, &parser)) != 0)
    return return_code;
  if ((return_code = extract_format(hexm_file, out_file, buffer, &parser)) != 0)
    return return_code;

  if (fgetc(hexm_file) != ':')
    return standard_error(out_file, hexm_file, &parser);
  int len_field=0;
  if ((return_code = extract_field_head(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_additional_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_version_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_field_head(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_blockchain_path_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_license_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_software_id_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;
  if ((return_code = extract_static_analysis_from_field(hexm_file, out_file, buffer,
          &len_field, &parser)) != 0)
    return return_code;

  if (out_file) fclose(out_file);
  fclose(hexm_file);
  return 0;
}

