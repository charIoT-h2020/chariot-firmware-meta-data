CHARIOT Insertion & extraction of metadata in elf files
=======================================================

This project provides tools for inserting CHARIOT metadata into
a firmware and tools for extracting it from the firmware.

# Insertion of metadata

We suppose that the firmware is developped on a standard workstation
with a crosscompiler for the target architecture. The workstation
should have many tools like a python interpreter, and some gnu-like
utilities like size, objcopy supporting add-section option, gcc
(at least gnu-as), sha256sum, git, hexdump

The mainstream way to insert the CHARIOT metadata consists in
modifying the makefile that builds the firmware to insert the metadata.
An example of such modification is done in the directory
[example/Chariot_metadata_example](example/Chariot_metadata_example).

A lightweight possibility consists in modifying the built firmware
with utilities like objcopy supporting add-section. The python
script [chariot_addelf_meta_data.py](chariot_addelf_meta_data.py)
can do this job.

# Extraction of metadata

The extraction of metadata can be tested on a developer
workstation with the python script
[chariot_extractelf_meta_data.py](chariot_extractelf_meta_data.py).

The gateway needs to do this job locally to accept or not a
firmware update. For that, the gateway (host) has to extract
the metadata for the firmware of the sensors (target).

The library `libchariot_extractelf.a` provides C functions
to do this. It is built with the command `make lib`.


The file [chariot_extractelf_meta_data.cpp]([chariot_extractelf_meta_data.cpp)
is just an example of usage of this library. It does the same job
than [chariot_extractelf_meta_data.py](chariot_extractelf_meta_data.py).
So to check the library, just compiles `chariot_extractelf.exe` with 
`make exe` and check on an example (see [example/commands.txt](example/commands.txt)
if `chariot_extractelf_meta_data.py` and `chariot_extractelf_meta_data.exe`
return the same results.

Then you can check the integrity of the firmware at the gateway level
with the functions provided by the API `libchariot_extractelf.h`
and implemented in the library `libchariot_extractelf.a`.

# Basic principles

All these scripts/programs/library are based on the elf format.

The CHARIOT meta-data are in a specific section `.chariotmeta.rodata`. It is
itself built over the elf format, with an elf header and sections. The fields
like `chariotmeta_mainboot_sha256`, `chariotmeta_version_data`, ... are
present in the symbol table of the section `.chariotmeta.rodata`. Their
content can be retrieved with the section, offset and size associated to
the symbol.

CHARIOT elf extensions also support additional data. Their existence is defined
in the meta-data. If defined, they are in a specific section named `.suppldata`.
This section if also built over the elf format, with an elf header and sections.
One of its section has also the name `.suppldata`. It contains the CHARIOT
additional data.

# Demo

An example is provided in the directory [example](example).

The commands in the file [example/obj/commands.txt](example/obj/commands.txt)
help to build it, to insert and extract chariot metadata from the python scripts.

```sh
cd example/obj
gcc -ffreestanding -m32 -O -Wall -c ../boot.s -o boot.o
gcc -ffreestanding -m32 -O -Wall -c ../hello-chariot.c -o hello-chariot.o
gcc -ffreestanding -m32 -O -Wall -c ../kernel.c -o kernel.o
gcc -ffreestanding -m32 -O -Wall -static -T linker.ld -nostdlib boot.o hello-chariot.o kernel.o -lgcc -o hello-world-plain-kernel
```

builds an executable `hello-world-plain-kernel` without any meta-data.
If the directory [example/Chariot_metadata_example](example/Chariot_metadata_example)
provides modifications (in particular for the files `linker.ld` and `Makefile`)
to compile with CHARIOT meta-data, the demo just uses python scripts.


```sh
../../chariot_addelf_meta_data.py --boot text --add ../Flag-of-Europe-64x64.png image/png --blockchain_path "http://" --license "GPl" --static-analysis commands.txt plain/txt  hello-world-plain-kernel -o hello-world-plain-kernel2
```

inserts the following meta-data in the binary file:

* it computes the sha256 of the `.text` segment and adds it as `chariotmeta_mainboot_sha256` field (`--boot` option).
* it adds the existence of a additional data as a metadata field (`--add` option).
* it adds the blockchain path `"http://"` as `chariotmeta_firmware_path` field (`--blockchain_path` option).
* it adds the firmware licencse `GPl"` as `chariotmeta_firmware_license` field (`--license` option).
* it adds the content of the file `commands.txt` with format `plain/txt` as `chariotmeta_codanalys_data` field (`--static-analysis` option).
* it adds the content of file `../Flag-of-Europe-64x64.png` with format `image/png` as additional data in the `.suppldata` section
* it regenerates `hello-world-plain-kernel2` as a new binary firmware containing the meta and extra CHARIOT data.


Then the command

```sh
../../chariot_extractelf_meta_data.py -a hello-world-plain-kernel2
```

extracts these fields and displays them on the console.

Now, to check if the extraction library correctly works, we need to build it, to create an extraction executable upon it, to display the meta and extra CHARIOT data with the new executable and finally to compare the displayed results with the ouputs of the python script.

The following commands will do this job:

```sh
cd ../..
make lib # build the library
make exe # build the executable chariot_extractelf_meta_data.exe
cd example/obj
../../chariot_extractelf_meta_data.exe -a hello-world-plain-kernel2 # display results
../../chariot_extractelf_meta_data.py -a hello-world-plain-kernel2 # to compare displayed results
```

# Usage of the API of the extraction library

A basic usage is displayed in the file `chariot_extractelf_meta_data.cpp`
that is used to display the metadata.

The API suggests to load the entire firmware binary in memory before calling the library.
It can be corrected with callback functions that could navigate in the firmware file.

```c
#include "chariot_extractelf.h"

...

  Elf32_Ehdr elf_header; // <- the global elf header
  const char* error_message = 0; // if an error occurs, this field then contains the message
  fill_exe_header(&elf_header, &buffer[0], buffer.size(), &error_message);

  Elf32_Shdr metadata_section; // <- the meta-data section
  retrieve_section_header(&metadata_section, &elf_header, &buffer[0], buffer.size(),
        CS_Meta, &error_message);

  Elf32_Ehdr metadata_elf_header; // <- the elf header in the meta-data section
  fill_exe_header(&metadata_elf_header, &buffer[0] + metadata_section.sh_offset,
        metadata_section.sh_size, &error_message);

  Chariot_Metadata_localizations metadata_dict; // <- dictionary to locate CHARIOT meta data
  metadata_dict.valid_entries = 0;
  metadata_dict.metadata_header = &metadata_elf_header;
  metadata_dict.metadata_section = &metadata_section;
  metadata_dict.metadata_buffer_exe = &buffer[0] + metadata_section.sh_offset;
  metadata_dict.metadata_buffer_len = metadata_section.sh_size;

  fill_metadata_dict(&metadata_dict, &error_message);

  if (metadata_dict.valid_entries & (1U << CMS_Mainboot_sha256)) { // if mainboot_sha256 is present
    uint32_t sha256[8];
    retrieve_mainboot_sha256(sha256, &metadata_dict, &error_message);
    // do something with sha256
  };

  if (metadata_dict.valid_entries & (1U << CMS_Firmware_path)) {
    const char* firmware_path = nullptr;
    size_t firmware_path_len = 0;
    retrieve_firmware_path(&firmware_path, &firmware_path_len, &metadata_dict, &error_message);
    // do something with firmware_path and firmware_path_len = blockchain path, to be discussed
  }

  if (metadata_dict.valid_entries & (1U << CMS_Firmware_license)) {
    const char* license = nullptr;
    size_t license_len = 0;
    retrieve_firmware_license(&license, &license_len, &metadata_dict, &error_message);
    // do something with license and license_len
  }

  if (metadata_dict.valid_entries & (1U << CMS_Codanalys_data)) {
    const char* codanalys_data = nullptr;
    size_t codanalys_data_len = 0;
    retrieve_codanalys_data(&codanalys_data, &codanalys_data_len, &metadata_dict, &error_message);
    // do something with codanalys_data and codanalys_data_len
  }

  if ((metadata_dict.valid_entries & (1U << CMS_Extraboot_offsetnum))
      && !(metadata_dict.valid_entries & (1U << CMS_Extraboot_sizenum))) {
    Elf32_Shdr suppldata_section; // the additional data section
    retrieve_section_header(&suppldata_section, &elf_header, &buffer[0], buffer.size(), 
          CS_Extra, &error_message);

    Elf32_Ehdr suppldata_elf_header; // <- the elf header in the additional data section
    fill_exe_header(&suppldata_elf_header, &buffer[0] + suppldata_section.sh_offset,
          suppldata_section.sh_size, &error_message);

    Elf32_Shdr suppldata_inside_section; // <- the section .suppldata in the .suppldata section
    retrieve_section_header(&suppldata_inside_section, &suppldata_elf_header,
          &buffer[0] + suppldata_section.sh_offset, suppldata_section.sh_size,
          CS_Extra, &error_message);

    Chariot_Metadata_extraboot extractboot_info; // <- arguments to extract data from the section
    extractboot_info.suppldata_header = &suppldata_elf_header;
    extractboot_info.suppldata_section = &suppldata_inside_section;
    extractboot_info.suppldata_buffer_exe = &buffer[0] + suppldata_section.sh_offset;
    extractboot_info.suppldata_buffer_len = suppldata_section.sh_size;
    retrieve_extraboot(&extractboot_info, &metadata_dict, &error_message);
    // do something with extractboot_info.start and extractboot_info.len
  }
```

