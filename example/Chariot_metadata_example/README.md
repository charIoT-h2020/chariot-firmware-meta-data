# an example of meta-data for CHARIOT

This example software, done above a "hello world" kernel like fetched
from [http://osdev.org/](http://osdev.org/), demonstrates how the
CHARIOT metadata could be embedded in some ELF firmware, and gives the
scripts to extract this meta-data.

Since the original "hello world" is not written at CEA, we keep its
original copyright mention and license (and more precisely, the lack
of them). We just are adding "with contributions from CEA by ..."
mentions in these files.

The utilities and scripts files entirely written at CEA have a CEA
copyright notice, and, when possible some weak open source license.

The files taken elsewhere keep their original license and
copyright. If we have to add a few code lines in them, we are adding a
comment "with contribution by CEA from <xxxx.yyyy@cea.fr>"

Some files are available on the Web without a clear copyright notice.
Then we are adding a comment such as
"taken from http://some-url.somewhere/some/path" and a notice
"copyright notice unspecified. Some CEA folks believe it is some kind of open source code, but we don't know."

## Building

Just run `make`. With luck, you should get a `hello-world-kernel` ELF
file (statically linked) for x86 in 32 bits.

## Testing with `qemu`

With luck, `make run` should run that kernel thru Qemnu

## Notice

Several files are taken from [http://osdev.org/](http://osdev.org/)
and more precisely from
[https://wiki.osdev.org/Bare_Bones](https://wiki.osdev.org/Bare_Bones)
on mid-February 2019 and in good faith are supposed to be public
domain. However, see
[https://forum.osdev.org/viewtopic.php?t=13270](https://forum.osdev.org/viewtopic.php?t=13270)
and
[https://forum.osdev.org/viewtopic.php?t=13810](https://forum.osdev.org/viewtopic.php?t=13810)
and
[https://wiki.osdev.org/OSDev_Wiki:License](https://wiki.osdev.org/OSDev_Wiki:License). Your
responsability is to assess the legality of this example (we at CEA
believe in good faith it is legal).

To help users of this example, we are slightly adapting the
[wiki.osdev.org/Bare_Bones](https://wiki.osdev.org/Bare_Bones) to
avoid requiring building a cross-compiler for it (as mentioned in that
wikipage). It should be compilable with a recent `gcc-8` on a
Linux/x86-64 workstation. Our Linux distribution is a Debian/Sid (or
Ubuntu 18).

## Terminology

The main boot data is the firmware code and related data.

The supplementary data is some extra "file" or sequence of bytes
needed by the firmware. For example (in the case of Linux kernel), the
`initrd`. For a simpler firmware needing some message catalog (e.g. in
French, in Greek, etc...), that supplementary data might be that
message catalog. In some cases, that supplementary data might even be
the content of some read-only sqlite database, or a pixmap, etc. In
this particular example, the supplementary data is the European flag in PNG
format.

## Summary of meta-data conventions

In an ELF firmware, the meta-data would sit in some specific ELF
segment of p_type being `PT_CHARIOT_METADATA` (which should be
0x52414843) outside of the main boot data segment and of the
supplementary boot data segment.

Here is the list of all the possible CHARIOT metadata with their name
(in an ELF firmware, that name would be in some symbol table; in some
other formats, that name is just a documented convention). We describe
these in C notation. Since they are UTF-8 strings, each of them is NUL
byte terminated. If using ELF, there is some redundancy. But more
primitive firmware formats don't define any notion of section or
segment, and in those cases they are needed.

* `char chariotmeta_mainboot_sha256[80];` starts with the hexencoded
  sha256 hashcode of the main boot data. it is a mandatory fixedwidth
  string, for example:
  `"8a73c14ecec2580aced17c35279cf02df6c418f7c5a7fde3182884ddb573e5d2 XXX"`
  
* `char chariotmeta_mainboot_offsetnum[16];` is the mandatory ASCII
   encoded decimal byte-offset in the firmware file of the start of
   the main boot data.  for example: `"14532"`

* `char chariotmeta_mainboot_sizenum[16];` is the mandatory ASCII
   encoded decimal byte-size in the firmware file of the size of the
   main boot data. for example: `"522240"`

* `char chariotmeta_extraboot_sha256[80];` starts with the hexencoded
   sha256 hashcode of the main boot data. it is a mandatory fixedwidth
   string, for example:
   `"8a73c14ecec2580aced17c35279cf02df6c418f7c5a7fde3182884ddb573e5d2 XXX"`
   but when no extra boot data is present it should be left empty
   (NUL or space filled).

* `char chariotmeta_extraboot_offsetnum[16];` is the mandatory ASCII
  encoded decimal byte-offset in the firmware file of the start of the
  main boot data.  for example: "14532" but when no extra boot data is
  given it should be left empty

* `char chariotmeta_extraboot_sizenum[16];` is the mandatory ASCII
  encoded decimal byte-size in the firmware file of the size of the
  extra boot data. If no extra boot data is provided, it should be
  left empty (no digits, possibly spaces). for example: `"45612"` but
  when no extra boot data is given it should be left empty
    
 * `char chariotmeta_extraboot_typeinfo[64];` is the mandatory
   typeinfo of the extra boot data (or left empty). For example
   `"!ext4 label=root"` in the case of an ext4 root file system.
 
 * `char chariotmeta_codanalys_typeinfo[64];` is the mandatory
   typeinfo of the optional code analysis data (or left empty). For
   example `"application/json; bismon results/FMT2019C"` in the case of
   some data, in JSON format, related to the code analysis by
   [bismon](http://github.com/bstarynk/bismon/).
 
* `char chariotmeta_version_data[128];` is some mandatory free-format
  version related data. An organization using git to version its
  source code might use the git commit identifier in it.

After these fixedwidth strings we have variable-width strings (UTF-8
encoded, NUL terminated), each starting with some prefix matching
`CHARIOTMETA_*=` where the `*` is in shell globbing notation. The
first variable-width string is the firmware path.

* `char chariotmeta_firmware_path[]="CHARIOTMETA_FIRMWARE_PATH=` *some
  firmware path* `";` is mandatory and should be the first
  variable-length string (maximal size is 1024+28 bytes). It gives the
  firmware path, exactly as registered in the CHARIOT blockchain.

* `char chariotmeta_firmware_copyright[]="CHARIOTMETA_FIRMWARE_COPYRIGHT=`
*some copyright notice* `";` is optional, at most 1024+32 bytes. It could give some copyright notice. We recommend it to contain the UTF-8 copyright sign.

* `char chariotmeta_firmware_license[]="CHARIOTMETA_FIRMWARE_LICENSE=`
  *some license notice* `";` is optional, at most 1024+32 bytes. It
  could give some license notice.
    
* `char chariotmeta_codanalys_data[]="CHARIOTMETA_CODANALYS_DATA=`
*some code analysis data* `";` is some optional static source code
analysis, up to 64 kilobytes. The typeinfo
`chariotmeta_codanalys_typeinfo` is describing it.

The names and orders above are particularly useful for a firmware in a
format more primitive than ELF. Where they appear and how to access
them is firmware-format (so implementation-) specific.

### Metadata duplicated in the CHARIOT blockchain

Some of the data above is duplicated in the blockchain. Of course, `chariotmeta_firmware_path` but also all the sizenum, typeinfo, offsetnum.

### Organization of an ELF CHARIOT firmware.

The metadata is in a `PT_CHARIOT_METADATA` segment. That segment
contains the `".chariotmeta.rodata"` section for the metadata, and the
`".chariotmeta.sym"` section for the symbols (such as
`chariotmeta_firmware_path`, etc...). Of course there is a lot of
redundancy. If some extra data is given, it should sit in a
`PT_CHARIOT_EXTRADATA` (of `p_type` being `0x0a544f49`) segment. If that
segment needs to be organized in ELF sections, their section name
should start with `.chariotextra` As noticed above, the ELF format
will entail some redundancy, which should also be checked by the
CHARIOT gateway.

## Implementation details

We generate *twice* the metadata object file, by generating two
assembler files of *same* layout and symbol offsets and size. The first
file is the `_chariot-fake-metadata.s` and contains some fixed-length
fields with `"00000000"` strings. The second file the
`_chariot-real-metadata.s` file and contains these fixed-length field
with the actual numbers (in ASCII format, decimal encoded).

We link two kernels, one being `hello-world-plain-kernel` (with the
fake metadata `_chariot-fake-metadata.o`) and the other being
`hello-world-metadated-kernel` which contains the genuine metadata
(`_chariot-real-metadata.o`).