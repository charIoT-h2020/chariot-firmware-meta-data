## Makefile contributed by CEA for CHARIOT.
## a 'hello-world' kernel for x86 (not by CEA, found on the web)
## with a variant containing Chariot metadata.
## 
## Probably (to be checked) this Makefile is under GPLv3+ license.
## But there might be reasons to avoid that license.
##
## in the copyright notice below, "program" means this Makefile only,
## not the entire hello-world kernel (which seems in the public domain)
## see the README.md

## Copyright © 2019 CEA (Commissariat à l'énergie atomique et aux énergies alternatives)

##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <http://www.gnu.org/licenses/>.

## See https://wiki.osdev.org/Bare_Bones


CC= gcc

RM= rm -vf
## on Debian, in python-markdown package
MARKDOWN= markdown_py
## the global options passed to gcc; to debug that Makefile, consider adding -v below
CCOPTION= -ffreestanding -m32
## the fictitious source checksum. Later would be computed at compile time.
## for the demo, just the sha512sum of all C source and header files.
CHARIOT_SOURCE_CHECKSUM=$(shell cat *.c *.h | sha512sum | cut -d\  -f1)
MAINBOOT_OBJECT_FILES= boot.o kernel.o hello-chariot.o

## as a proof of concept, the supplementary data is ...
SUPPLEMENTARY_DATA_FILE= Flag-of-Europe-64x64.png
SUPPLEMENTARY_DATA_MIME= image/png
##
CODANALYS_MIME= application/json; DEMO

CHARIOT_FIRMWARE_BLOCKCHAIN_PATH= osdev.org/DEMO/FirmwarePath_V1
CHARIOT_FIRMWARE_LICENSE= Probably Public Domain but not sure
## ... But of course our hello-world kernel is not capable of displaying a
## png image on the screen.
## the compilation flag
CFLAGS=  $(CCOPTION) -O -Wall

.PHONY: all  clean run

all: hello-world-plain-kernel hello-world-metadated-kernel README.html


## the plain kernel containing fake metadata
hello-world-plain-kernel: $(MAINBOOT_OBJECT_FILES) _supplementary-data.o _chariot-fake-metadata.o | linker.ld Makefile
	$(LINK.c) -static -T linker.ld -nostdlib  $(MAINBOOT_OBJECT_FILES) _supplementary-data.o _chariot-fake-metadata.o -lgcc -o $@
	@echo CHARIOT_SOURCE_CHECKSUM= $(CHARIOT_SOURCE_CHECKSUM)

## the metadated kernel containing real metadata
hello-world-metadated-kernel: $(MAINBOOT_OBJECT_FILES) _supplementary-data.o _chariot-real-metadata.o | linker.ld Makefile
	$(LINK.c) -static -T linker.ld -nostdlib $(MAINBOOT_OBJECT_FILES) _supplementary-data.o _chariot-real-metadata.o  -lgcc -o $@
	@echo CHARIOT_SOURCE_CHECKSUM= $(CHARIOT_SOURCE_CHECKSUM)

boot.o: boot.s
	$(CC) $(CFLAGS) -c $^ -o $@

kernel.o: kernel.c chariot-example.h
hello-chariot.o: kernel.c chariot-example.h
_chariot-fake-metadata.o: _chariot-fake-metadata.s
	$(CC) $(CFLAGS) -c $^ -o $@
_supplementary-data.o: _supplementary-data.c

_supplementary-data.c: $(SUPPLEMENTARY_DATA_FILE) | Makefile
	echo '// generated file $@ from $^ - DO NOT EDIT' > $@-tmp
	echo '// see also https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html' >> $@-tmp
	echo 'const char boot_supplementary_data[] __attribute__((section(".suppldata"))) = {' >> $@-tmp
	hexdump -v -e '/1 " %#x,"' $^ | fmt >> $@-tmp
	echo '}; // end of  boot_supplementary_data' >> $@-tmp
	echo '// end of generated file $@' >> $@-tmp
	mv $@-tmp $@

## this is the generated assembler file with some fake metadata and
## also some real one. The fake metadata would be replaced by real
## metadata of the same size to give the assembler file
## _chariot-real-metadata.s, and both chariot-fake-metadata.o and
## chariot-real-metadata.o should have symbols of same offset and
## size.
_chariot-fake-metadata.s: boot.o kernel.o hello-chariot.o _supplementary-data.o | Makefile
	date +'/* generated file $@ on %c - DO NOT EDIT */' > $@-tmp
	echo '  .section .chariotmeta.rodata,"a"' >> $@-tmp
## chariotmeta_mainboot_sha256
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_mainboot_sha256' >> $@-tmp
	echo ' chariotmeta_mainboot_sha256:' >> $@-tmp
	(echo -n '  .string "'; cat $(MAINBOOT_OBJECT_FILES) | sha256sum | sed s/-/mainboot\"/g ) >> $@-tmp
	echo '  .type	chariotmeta_mainboot_sha256, @object' >> $@-tmp
	echo '  .size	chariotmeta_mainboot_sha256, 80' >> $@-tmp
## chariotmeta_format_typeinfo
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_format_typeinfo' >> $@-tmp
	echo ' chariotmeta_format_typeinfo:' >> $@-tmp
	echo '  .string "!CHARIOTMETAFORMAT_2019a"' >> $@-tmp
	echo '  .type	chariotmeta_format_typeinfo, @object' >> $@-tmp
	echo '  .size	chariotmeta_format_typeinfo, 64' >> $@-tmp
## chariotmeta_mainboot_offsetnum
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_mainboot_offsetnum' >> $@-tmp
	echo ' chariotmeta_mainboot_offsetnum:' >> $@-tmp
	echo '  .string "00000000" /*@mainboot_offsetnum*/' >> $@-tmp
	echo '  .type	chariotmeta_mainboot_offsetnum, @object' >> $@-tmp
	echo '  .size	chariotmeta_mainboot_offsetnum, 16' >> $@-tmp
## chariotmeta_mainboot_sizenum
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_mainboot_sizenum' >> $@-tmp
	echo ' chariotmeta_mainboot_sizenum:' >> $@-tmp
	echo '  .string "00000000" /*@mainboot_sizenum*/' >> $@-tmp
	echo '  .type	chariotmeta_mainboot_sizenum, @object' >> $@-tmp
	echo '  .size	chariotmeta_mainboot_sizenum, 16' >> $@-tmp
## chariotmeta_extraboot_sha256
	echo '  .align 16'
	echo '  .globl chariotmeta_extraboot_sha256' >> $@-tmp
	echo ' chariotmeta_extraboot_sha256:' >> $@-tmp
	(echo -n '  .string "'; sha256sum $(SUPPLEMENTARY_DATA_FILE) | cut --bytes=1-80 | sed 's/$$/"/g') >> $@-tmp
	echo '  .size	chariotmeta_extraboot_sha256, 80' >> $@-tmp
## chariotmeta_extraboot_offsetnum
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_extraboot_offsetnum' >> $@-tmp
	echo ' chariotmeta_extraboot_offsetnum:' >> $@-tmp
	echo '  .string "00000000" /*@extraboot_offsetnum*/' >> $@-tmp
	echo '  .type	chariotmeta_extraboot_offsetnum, @object' >> $@-tmp
	echo '  .size	chariotmeta_extraboot_offsetnum, 16' >> $@-tmp
## chariotmeta_extraboot_sizenum
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_extraboot_sizenum' >> $@-tmp
	echo ' chariotmeta_extraboot_sizenum:' >> $@-tmp
	echo '  .string "00000000" /*@extraboot_sizenum*/' >> $@-tmp
	echo '  .type	chariotmeta_extraboot_sizenum, @object' >> $@-tmp
	echo '  .size	chariotmeta_extraboot_sizenum, 16' >> $@-tmp
## chariotmeta_extraboot_typeinfo
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_extraboot_typeinfo' >> $@-tmp
	echo ' chariotmeta_extraboot_typeinfo:' >> $@-tmp
	(echo -n '  .string "'; echo -n $(SUPPLEMENTARY_DATA_MIME); echo '"') >> $@-tmp
	echo '  .type	chariotmeta_extraboot_typeinfo, @object' >> $@-tmp
	echo '  .size	chariotmeta_extraboot_typeinfo, 64' >> $@-tmp
## chariotmeta_codanalysis_typeinfo
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_codanalys_typeinfo' >> $@-tmp
	echo ' chariotmeta_codanalys_typeinfo:' >> $@-tmp
	(echo -n '  .string "'; echo -n $(CODANALYS_MIME); echo '"') >> $@-tmp
	echo '  .type	chariotmeta_codanalys_typeinfo, @object' >> $@-tmp
	echo '  .size	chariotmeta_codanalys_typeinfo, 64' >> $@-tmp
## chariotmeta_version_data
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_version_data' >> $@-tmp
	echo ' chariotmeta_version_data:' >> $@-tmp
	(echo -n '  .string "'; git log --format=oneline --abbrev=12 --abbrev-commit -q | head -1 \
           | tr -d '\n\r\f\"\\\\' ; echo '"') >> $@-tmp
	echo '  .type	chariotmeta_version_data, @object' >> $@-tmp
	echo '  .size	chariotmeta_version_data, 64' >> $@-tmp
####### variable sized strings
#######
## chariotmeta_firmware_path
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_firmware_path' >> $@-tmp
	echo ' chariotmeta_firmware_path:' >> $@-tmp
	(echo -n '  .string "CHARIOTMETA_FIRMWARE_PATH='; echo -n $(CHARIOT_FIRMWARE_BLOCKCHAIN_PATH); echo '"') >> $@-tmp
	echo '  .type chariotmeta_firmware_path,  @object'  >> $@-tmp
	echo '  .size chariotmeta_firmware_path,     . - chariotmeta_firmware_path' >> $@-tmp
## chariotmeta_firmware_license
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_firmware_license' >> $@-tmp
	echo ' chariotmeta_firmware_license:' >> $@-tmp
	(echo -n '  .string "CHARIOTMETA_FIRMWARE_LICENSE='; echo -n $(CHARIOT_FIRMWARE_LICENSE); echo '"') >> $@-tmp
	echo '  .type chariotmeta_firmware_license,  @object' >> $@-tmp
	echo '  .size chariotmeta_firmware_license,     . - chariotmeta_firmware_license' >> $@-tmp
## chariotmeta_codanalys_data
	echo '  .align 16' >> $@-tmp
	echo '  .globl chariotmeta_codanalys_data' >> $@-tmp
	echo ' chariotmeta_codanalys_data:' >> $@-tmp
	(echo -n '  .string "CHARIOTMETA_CODANALYS_DATA='; echo  ' { \"fictional\" : \"$(CHARIOT_SOURCE_CHECKSUM)\" } "') >> $@-tmp
	echo '  .type chariotmeta_codanalys_data,  @object'  >> $@-tmp
	echo '  .size chariotmeta_codanalys_data,     . - chariotmeta_codanalys_data'  >> $@-tmp
	echo '/* end of generated file $@ */' >> $@-tmp
	mv  $@-tmp $@

_chariot-real-metadata.o: _chariot-real-metadata.s
	$(CC) $(CFLAGS) -c $^ -o $@


_chariot-real-metadata.s: _chariot-fake-metadata.s hello-world-plain-kernel | rewrite-chariot-real-metadata.bash
	./rewrite-chariot-real-metadata.bash _chariot-fake-metadata.s hello-world-plain-kernel _chariot-real-metadata.s

clean:
	$(RM) *.o hello-world-*-kernel *~ README.html _chariot-*-metadata.[cso] _supplementary-data.c *tmp

run: hello-world-metadated-kernel
	qemu-system-i386 -kernel $^

README.html: README.md
	$(MARKDOWN) $^ > $@
