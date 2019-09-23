#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import binascii

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
parser.add_argument('--static-analysis', '-sa', action='store_true',
                   help='print the result of the static analysis as file/format')
parser.add_argument('--add', '-add', action='store_true',
                   help='print content of the additional section')
parser.add_argument('--output', '-o', nargs=1,
                   help='print into the output file instead of stdout')
args = parser.parse_args()

if args.output is not None:
    output_file = open(args.output[0],'wb')
else:
    output_file = None

print ("extract meta-data from hexm file")
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
            version_string = hexm_file.read(int(256/8))
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
                    print ("extract chariot license path")
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

            if args.static_analysis and (next_header != "sca"):
                if output_file is None:
                    print("")
            elif next_header == "sca":
                if args.verbose and args.static_analysis is not None:
                    print ("extract chariot static_analysis path")
                static_analysis_size = int.from_bytes(hexm_file.read(4), byteorder='big')
                static_analysis_string = hexm_file.read(static_analysis_size)
                if args.static_analysis:
                    if output_file is not None:
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
