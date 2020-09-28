#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import binascii

__author__ = "Franck Vedrine"
__copyright__ = "Copyright (c) 2019-2020, Commissariat a l'Energie Atomique CEA. All rights reserved."
__credits__ = ["""
    European Union’s Horizon 2020 RIA programme
    under grant agreement No 780075
    CHARIOT - Cognitive Heterogeneous Architecture for Industrial IoT
    """]
__license__ = """
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:

   - Redistributions of source code must retain the above copyright notice, 
     this list of conditions and the following disclaimer.

   - Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

   - Neither the name of CEA nor the names of its contributors may be used to
     endorse or promote products derived from this software without specific 
     prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED.
  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY 
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
__version__ = "1.0.0"
__maintainer__ = "Franck Vedrine"
__email__ = "franck.vedrine@cea.fr"
__status__ = "Prototype"

# CHARIOT: extract meta-data from firmware

parser = argparse.ArgumentParser(description='Extract Chariot meta-data from an elf firmware')
parser.add_argument('exe_name', help='the name of the executable elf file')
parser.add_argument('--all', '-a', action='store_true',
                   help='separate meta-data from firmware file')
parser.add_argument('--verbose', '-v', action='store_true',
                   help='verbose mode: echo every command on terminal')
parser.add_argument('--sha', '-sha', action='store_true',
                   help='print the sha256 of the boot section')
parser.add_argument('--format', action='store_true',
                   help='print the chariot format')
parser.add_argument('--version', '-ver', action='store_true',
                   help='print the version')
parser.add_argument('--blockchain_path', '-bp', action='store_true',
                   help='print the path to the targeted blockchain')
parser.add_argument('--license', '-lic', action='store_true',
                   help='print the license of the firmware')
parser.add_argument('--software_ID', '-soft', action='store_true',
                   help='print the software id of the firmware')
parser.add_argument('--static-analysis', '-sa', nargs=1,
                   help='print the result of the static analysis in file')
parser.add_argument('--add', '-add', action='store_true',
                   help='print content of the additional section')
parser.add_argument('--output', '-o', nargs=1,
                   help='print into the output file instead of stdout')
args = parser.parse_args()

if args.output is not None:
    output_file = open(args.output[0],'wb')
else:
    output_file = None

print ("extract meta-data from binm file")
try:
    with open(args.exe_name,'rb') as hexm_file:
        hexm_file.seek(-4, os.SEEK_END)
        metadata_size = int.from_bytes(hexm_file.read(4), byteorder='big')
        hexm_file.seek(-metadata_size, os.SEEK_END)
        if args.all:
            if output_file is None:
                print ("extraction of all meta-data requires an output file")
                raise OSError(1)
            while True:
                buf = hexm_file.read(4096)
                if buf: 
                    output_file.write(buf)
                else:
                    break
        else:
            if args.verbose:
                print ("extract meta-data section") 
            if hexm_file.read(len(":chariot_md:")) != b":chariot_md:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            if args.sha and args.verbose:
                print ("extract sha256 of " + args.exe_name)
            if hexm_file.read(len(":sha256:")) != b":sha256:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            sha_256 = hexm_file.read(int(256/8))
            if args.sha:
                result = binascii.hexlify(sha_256).decode("ascii")
                if output_file is not None:
                    output_file.write(result.encode())
                else:
                    print(result)

            if args.verbose and args.format:
                print ("extract chariot format")
            if hexm_file.read(len(":fmt:")) != b":fmt:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            format_size = int.from_bytes(hexm_file.read(4), byteorder='big')
            format_string = hexm_file.read(format_size)
            if args.format:
                if output_file is not None:
                    output_file.write(format_string)
                else:
                    print(str(format_string.decode()))

            if hexm_file.read(1) != b':':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            next_header = ""
            ch = hexm_file.read(1)
            while ch != b':' and ch != '':
                next_header += chr(ch[0])
                ch = hexm_file.read(1)
            if ch == '':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
                
            if args.add and (next_header != "add"):
                if output_file is None:
                    print("")
            elif next_header == "add":
                if args.verbose and (args.add is not None):
                    print ("extract chariot additional file")
                additional_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                additional_string = hexm_file.read(additional_size)
                if args.add:
                    if output_file is not None:
                        output_file.write(additional_string)
                    else:
                        print(additional_string)
                if hexm_file.read(1) != b':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                additional_mime_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                additional_mime_string = hexm_file.read(additional_mime_size)

            if args.verbose and args.version:
                print ("extract chariot version")
            if next_header != "version":
                if hexm_file.read(len(":version:")) != b":version:":
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
            version_string = hexm_file.read(int(32))
            if args.version:
                result = binascii.hexlify(version_string).decode("ascii")
                if output_file is not None:
                    output_file.write(version_string)
                else:
                    print(result)

            if hexm_file.read(1) != b':':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            next_header = ""
            ch = hexm_file.read(1)
            while ch != b':' and ch != '':
                next_header += chr(ch[0])
                ch = hexm_file.read(1)
            if ch == '':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)

            if args.blockchain_path and (next_header != "bcpath"):
                if output_file is None:
                    print("")
            elif next_header == "bcpath":
                if args.verbose and args.blockchain_path is not None:
                    print ("extract chariot blockchain path")
                blockchain_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                blockchain_string = hexm_file.read(blockchain_size)
                if args.blockchain_path:
                    if output_file is not None:
                        output_file.write(blockchain_string)
                    else:
                        print(str(blockchain_string.decode()))
                if hexm_file.read(1) != b':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                next_header = ""
                ch = hexm_file.read(1)
                while ch != b':' and ch != '':
                    next_header += chr(ch[0])
                    ch = hexm_file.read(1)
                if ch == '':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

            if args.license and (next_header != "lic"):
                if output_file is None:
                    print("")
            elif next_header == "lic":
                if args.verbose and args.license is not None:
                    print ("extract chariot license")
                license_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                license_string = hexm_file.read(license_size)
                if args.license:
                    if output_file is not None:
                        output_file.write(license_string)
                    else:
                        print(str(license_string.decode()))
                if hexm_file.read(1) != b':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                next_header = ""
                ch = hexm_file.read(1)
                while ch != b':' and ch != '':
                    next_header += chr(ch[0])
                    ch = hexm_file.read(1)
                if ch == '':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

            if args.software_ID and (next_header != "soft"):
                if output_file is None:
                    print("")
            elif next_header == "soft":
                if args.verbose and args.software_ID is not None:
                    print ("extract chariot software id")
                soft_id_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                soft_id_string = hexm_file.read(soft_id_size)
                if args.software_ID:
                    if output_file is not None:
                        output_file.write(soft_id_string)
                    else:
                        print(str(soft_id_string.decode()))
                if hexm_file.read(1) != b':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                next_header = ""
                ch = hexm_file.read(1)
                while ch != b':' and ch != '':
                    next_header += chr(ch[0])
                    ch = hexm_file.read(1)
                if ch == '':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

            if args.static_analysis and (next_header != "sca"):
                if output_file is None:
                    print("")
            elif next_header == "sca":
                if args.verbose and args.static_analysis is not None:
                    print ("extract chariot static_analysis path")
                static_analysis_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                static_analysis_string = hexm_file.read(static_analysis_size)
                if args.static_analysis:
                    if args.static_analysis[0] is not None:
                        with open(args.static_analysis[0],'wb') as static_file:
                            static_file.write(static_analysis_string)
                    elif output_file is not None:
                        output_file.write(static_analysis_string)
                    else:
                        print(static_analysis_string)

                if hexm_file.read(1) != b':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                static_analysis_mime_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                static_analysis_mime_string = hexm_file.read(static_analysis_mime_size)
except OSError as err:
    if output_file is not None:
        output_file.close()
    sys.exit(err.errno)

if output_file is not None:
    output_file.close()
