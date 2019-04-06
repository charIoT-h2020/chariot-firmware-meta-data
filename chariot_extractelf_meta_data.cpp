#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>

#include "chariot_extractelf.h"

class InputParser{
  public:
   InputParser (int& argc, char** argv)
      :  requires_help(false), requires_all(false), requires_verbose(false),
         requires_sha(false), requires_blockchain_path(false), requires_license(false),
         requires_static_analysis(false), requires_additional(false)
      {  for (int i=1; i < argc; ++i)
            _tokens.push_back(argv[i]);
      }
   static void usage()
      {  std::cout << "usage: chariot_extractelf_meta_data.py [-h] [--all] [--verbose] [--sha]\n"
                   << "                                       [--blockchain_path] [--license]\n"
                   << "                                       [--static-analysis] [--add]\n"
                   << "                                       [--output OUTPUT]\n"
                   << "                                       exe_name\n"
                   << "\n";
      }
   bool fillFields()
      {  auto itr = _tokens.begin();
         while (itr != _tokens.end()) {
            if ((*itr)[0] == '-') {
               if (*itr == "-h")
                  requires_help = true;
               else if (*itr == "-a" || *itr == "--all")
                  requires_all = true;
               else if (*itr == "-v" || *itr == "--verbose")
                  requires_verbose = true;
               else if (*itr == "-sha" || *itr == "--sha")
                  requires_sha = true;
               else if (*itr == "-bp" || *itr == "--blockchain_path")
                  requires_blockchain_path = true;
               else if (*itr == "-lic" || *itr == "--license")
                  requires_license = true;
               else if (*itr == "-sa" || *itr == "--static-analysis")
                  requires_static_analysis = true;
               else if (*itr == "-o" || *itr == "--output") {
                  if (++itr == _tokens.end())
                     return false;
                  output_file = *itr;
               }
               else
                  return false;
            }
            else
               exe_name = *itr;
            ++itr;
         }
         if (exe_name.size() == 0)
            return requires_help;
         return true;
      }

  public:
   std::string exe_name;
   bool requires_help : 1;
   bool requires_all : 1;
   bool requires_verbose : 1;
   bool requires_sha : 1;
   bool requires_blockchain_path : 1;
   bool requires_license : 1;
   bool requires_static_analysis : 1;
   bool requires_additional : 1;
   std::string output_file;

  private:
   std::vector <std::string> _tokens;

};

int main(int argc, char** argv) {
   InputParser parser(argc, argv);
   if (!parser.fillFields()) {
      parser.usage();
      return 1;
   }

   if (parser.requires_help) {
      parser.usage();
      std::cout << '\n';
      std::cout << "Extract Chariot meta-data from an elf firmware\n"
                << "\n"
                << "positional arguments:\n"
                << "  exe_name              the name of the executable elf file\n"
                << "\n"
                << "optional arguments:\n"
                << "  -h, --help            show this help message and exit\n"
                << "  --all, -a             equivalent to -sha -sa -bp -lic -add\n"
                << "  --verbose, -v         verbose mode: echo every command on terminal\n"
                << "  --sha, -sha           print the sha256 of the boot section\n"
                << "  --blockchain_path, -bp\n"
                << "                        print the path to the targeted blockchain\n"
                << "  --license, -lic       print the license of the firmware\n"
                << "  --static-analysis, -sa\n"
                << "                        print the result of the static analysis as file/format\n"
                << "  --add, -add           print content of the additional section\n"
                << "  --output OUTPUT, -o OUTPUT\n"
                << "                        print into the output file instead of stdout\n"
                << "\n";
      return 0;
   }

   std::vector<char> buffer;
   {  std::ifstream file(parser.exe_name.c_str(), std::ios::binary|std::ios::ate);
      if (!file.is_open()) {
         std::cerr << "Cannot open file " << parser.exe_name << std::endl;
         return 1;
      }
      std::ifstream::pos_type len = file.tellg();
      buffer.resize(len);
      file.seekg(0, std::ios::beg);
      file.read(&buffer[0], len);
   }
   std::ofstream out_file;
   bool is_valid_out_file = false;
   if (parser.output_file.size() > 0) {
      out_file.open(parser.output_file.c_str());
      is_valid_out_file = out_file.good();
   }
   std::ostream& out = is_valid_out_file ? (std::ostream&) out_file : (std::ostream&) std::cout;

   Elf32_Ehdr elf_header;
   const char* error_message = nullptr;
   if (parser.requires_verbose)
      std::cout << "call fill_exe_header -> elf_header\n";
   if (!fill_exe_header(&elf_header, &buffer[0], buffer.size(), &error_message)) {
      std::cerr << "Cannot read elf header of " << parser.exe_name << std::endl;
      std::cerr << "  " << error_message << std::endl;
      return 1;
   }

   Elf32_Shdr metadata_section;
   if (parser.requires_verbose)
      std::cout << "call retrieve_section_header -> metadata_section\n";
   if (!retrieve_section_header(&metadata_section, &elf_header, &buffer[0], buffer.size(),
            CS_Meta, &error_message)) {
      std::cerr << "Cannot find CHARIOT metadata inside " << parser.exe_name << std::endl;
      std::cerr << "  " << error_message << std::endl;
      return 1;
   }

   Elf32_Ehdr metadata_elf_header;
   if (parser.requires_verbose)
      std::cout << "call fill_exe_header -> metadata_elf_header\n";
   if (!fill_exe_header(&metadata_elf_header, &buffer[0] + metadata_section.sh_offset,
            metadata_section.sh_size, &error_message)) {
      std::cerr << "section .chariotmeta.rodata should also follow the elf format" << parser.exe_name << std::endl;
      std::cerr << "  " << error_message << std::endl;
      return 1;
   }

   Chariot_Metadata_localizations metadata_dict;
   metadata_dict.valid_entries = 0;
   metadata_dict.metadata_header = &metadata_elf_header;
   metadata_dict.metadata_section = &metadata_section;
   metadata_dict.metadata_buffer_exe = &buffer[0] + metadata_section.sh_offset;
   metadata_dict.metadata_buffer_len = metadata_section.sh_size;

   if (parser.requires_verbose)
      std::cout << "call fill_metadata_dict -> CHARIOT symbols\n";
   if (!fill_metadata_dict(&metadata_dict, &error_message)) {
      std::cerr << "Cannot find CHARIOT symbols inside " << parser.exe_name << std::endl;
      std::cerr << "  " << error_message << std::endl;
      return 1;
   }

   if (parser.requires_all || parser.requires_sha) {
      if (!(metadata_dict.valid_entries & (1U << CMS_Mainboot_sha256)))
         out << "main boot sha256 symbol not assigned\n";
      else {
         if (parser.requires_verbose)
            std::cout << "call retrieve_mainboot_sha256 -> sha256\n";
         uint32_t sha256[8];
         if (!retrieve_mainboot_sha256(sha256, &metadata_dict, &error_message)) {
            std::cerr << "Cannot find mainboot_sha256 inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }
         out << std::hex;
         for (int i = 8; --i >= 0; )
            out << std::setfill('0') << std::setw(8) << sha256[i];
         out << std::dec;
         out << " mainboot\n";
      };
   };

   if (parser.requires_all || parser.requires_blockchain_path) {
      if (!(metadata_dict.valid_entries & (1U << CMS_Firmware_path)))
         out << "firmware path symbol not assigned\n";
      else {
         if (parser.requires_verbose)
            std::cout << "call retrieve_firmware_path -> firmware_path\n";
         const char* firmware_path = nullptr;
         size_t firmware_path_len = 0;
         if (!retrieve_firmware_path(&firmware_path, &firmware_path_len, &metadata_dict, &error_message)) {
            std::cerr << "Cannot find firmware path inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }
         out << "CHARIOTMETA_FIRMWARE_PATH=" << std::string(firmware_path, firmware_path_len) << '\n';
      }
   };

   if (parser.requires_all || parser.requires_license) {
      if (!(metadata_dict.valid_entries & (1U << CMS_Firmware_license)))
         out << "license file symbol not assigned\n";
      else {
         if (parser.requires_verbose)
            std::cout << "call retrieve_firmware_license -> license\n";
         const char* license = nullptr;
         size_t license_len = 0;
         if (!retrieve_firmware_license(&license, &license_len, &metadata_dict, &error_message)) {
            std::cerr << "Cannot find firmware license inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }
         out << "CHARIOTMETA_FIRMWARE_LICENSE=" << std::string(license, license_len) << '\n';
      }
   };

   if (parser.requires_all || parser.requires_static_analysis) {
      if (!(metadata_dict.valid_entries & (1U << CMS_Codanalys_data)))
         out << "code analysis data symbol not assigned\n";
      else {
         if (parser.requires_verbose)
            std::cout << "call retrieve_codanalys_data -> static analysis data\n";
         const char* codanalys_data = nullptr;
         size_t codanalys_data_len = 0;
         if (!retrieve_codanalys_data(&codanalys_data, &codanalys_data_len, &metadata_dict, &error_message)) {
            std::cerr << "Cannot find static code analysis data inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }
         out << "CHARIOTMETA_CODANALYS_DATA=" << std::string(codanalys_data, codanalys_data_len) << '\n';
      }
   };

   if (parser.requires_all || parser.requires_additional) {
      if (!(metadata_dict.valid_entries & (1U << CMS_Extraboot_offsetnum))
            || !(metadata_dict.valid_entries & (1U << CMS_Extraboot_sizenum)))
         out << "extra boot symbol not assigned\n";
      else {
         Elf32_Shdr suppldata_section;
         if (parser.requires_verbose)
            std::cout << "call retrieve_section_header -> suppldata_section\n";
         if (!retrieve_section_header(&suppldata_section, &elf_header, &buffer[0], buffer.size(), 
                  CS_Extra, &error_message)) {
            std::cerr << "Cannot find CHARIOT metadata inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }

         Elf32_Ehdr suppldata_elf_header;
         if (parser.requires_verbose)
            std::cout << "call fill_exe_header -> suppldata_elf_header\n";
         if (!fill_exe_header(&suppldata_elf_header, &buffer[0] + suppldata_section.sh_offset,
                  suppldata_section.sh_size, &error_message)) {
            std::cerr << "section .suppldata should also follow the elf format" << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }

         Elf32_Shdr suppldata_inside_section;
         if (parser.requires_verbose)
            std::cout << "call retrieve_section_header -> suppldata_inside_section\n";
         if (!retrieve_section_header(&suppldata_inside_section, &suppldata_elf_header,
                  &buffer[0] + suppldata_section.sh_offset, suppldata_section.sh_size,
                  CS_Extra, &error_message)) {
            std::cerr << "Cannot find CHARIOT suppldata inside suppldata inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         }

         Chariot_Metadata_extraboot extractboot_info;
         extractboot_info.suppldata_header = &suppldata_elf_header;
         extractboot_info.suppldata_section = &suppldata_inside_section;
         extractboot_info.suppldata_buffer_exe = &buffer[0] + suppldata_section.sh_offset;
         extractboot_info.suppldata_buffer_len = suppldata_section.sh_size;
         if (parser.requires_verbose)
            std::cout << "call retrieve_extraboot -> extra boot section\n";
         if (!retrieve_extraboot(&extractboot_info, &metadata_dict, &error_message)) {
            std::cerr << "Cannot find CHARIOT extra data inside " << parser.exe_name << std::endl;
            std::cerr << "  " << error_message << std::endl;
            return 1;
         };
         out << std::string(extractboot_info.start, extractboot_info.len) << std::endl;
      }
   };

   return 0;
}

