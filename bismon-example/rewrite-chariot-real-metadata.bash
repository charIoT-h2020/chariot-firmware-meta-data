#!/bin/bash -x
## Bash shell-script rewrite-chariot-real-metadata.bash contributed by CEA for CHARIOT.
## invoked by make as: ./rewrite-chariot-real-metadata.bash _chariot-fake-metadata.s hello-world-plain-kernel _chariot-real-metadata.s

## A script to modify an assembler file containing some fake
## fixed-size metadata such as "00000000" strings into the real,
## same-sized, metadata.
## 
## Probably (to be checked) this rewrite-chariot-real-metadata.sh is
## under GPLv3+ license.  But there might be reasons to avoid that
## license.
##
## in the copyright notice below, "program" means this shell script only,
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
fake_assembler=$1
plain_firmware=$2
real_assembler=$3

echo $0 fake_assembler= $fake_assembler plain_firmware= $plain_firmware real_assembler= $real_assembler

mainboot_size=$(nm $plain_firmware \
		    | awk '/__mainboot_end/{e= 0+ strtonum("0x" $1);} \
                           /__mainboot_start/{s= 0+ strtonum("0x" $1);} \
                           END { print e - s; \
                                 print "mainboot start=", s, " end=", e > "/dev/stderr" }')
echo mainboot_size= $mainboot_size

mainboot_start_address=$(nm $plain_firmware \
		    | awk '/__mainboot_start/{s=  0+ strtonum("0x" $1);} \
                           END { print s; \
			         print "mainboot startaddr=", s > "/dev/stderr" }')
echo mainboot_start_address= $mainboot_start_address


extraboot_start_address=$(nm $plain_firmware \
		    | awk '/__supplboot_start/{s=  0+ strtonum("0x" $1);} \
                           END { print s; \
			         print "extraboot startaddr=", s > "/dev/stderr" }')
echo extraboot_start_address= $extraboot_start_address

extraboot_end_address=$(nm $plain_firmware \
		    | awk '/__supplboot_end/{s=  0+ strtonum("0x" $1);} \
                           END { print s; \
			         print "extraboot endaddr=", s > "/dev/stderr" }')
echo extraboot_end_address= $extraboot_end_address

extraboot_size=$(nm -S $plain_firmware | awk '/boot_supplementary_data/ {print  0+ strtonum("0x" $2); \
                                                                print "extraboot size=", $2 > "/dev/stderr" ; }')
echo extraboot_size= $extraboot_size

chariotmeta_size=$(objdump -h $plain_firmware | awk '/chariotmeta.rodata/{print 0+ strtonum("0x" $3); \
  print "chariotmeta size ", $3 > "/dev/stderr" ; }')
echo chariotmeta_size= $chariotmeta_size

chariotmeta_mem_addr=$(objdump -h $plain_firmware | awk '/chariotmeta.rodata/{print 0+ strtonum("0x" $4); \
  print "chariotmeta memaddr ", $6 > "/dev/stderr" ; }')
echo chariotmeta_memaddr= $chariotmeta_memaddr

chariotmeta_file_offset=$(objdump -h $plain_firmware | awk '/chariotmeta.rodata/{print 0+ strtonum("0x" $6); \
  print "chariotmeta offset ", $6 > "/dev/stderr" ; }')
echo chariotmeta_file_offset= $chariotmeta_file_offset

mainboot_startoffset=$[$mainboot_start_address - $chariotmeta_memaddr + $chariotmeta_file_offset]
extraboot_startoffset=$[$mainboot_start_address - $chariotmeta_memaddr + $chariotmeta_file_offset]

sed -e s/$fake_assembler/$real_assembler/g \
    -e "s:\"0*\" /\*@mainboot_sizenum\*/:\"$mainboot_size\" /*!!mainboot_sizenum*/:g" \
    -e "s:\"0*\" /\*@mainboot_offsetnum\*/:\"$mainboot_startoffset\" /*!!mainboot_offsetnum*/:g" \
    -e "s:\"0*\" /\*@extraboot_offsetnum\*/:\"$extraboot_startoffset\" /*!!extraboot_offsetnum*/:g" \
    -e "s:\"0*\" /\*@extraboot_sizenum\*/:\"$extraboot_size\" /*!!extraboot_sizenum*/:g" \
    < $fake_assembler > $real_assembler
date +"// end of $real_assembler patched on %c%n" >> $real_assembler
