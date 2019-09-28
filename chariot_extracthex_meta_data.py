#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import binascii

# CHARIOT: extract meta-data from firmware

def locate_line_from_end(hexm_file, file_size):
    expected_last_line = 80
    last_line = ":00000001FF"
    pattern_line_number = ":0a0000003a3axxxxxxxyyyyyyyyyzz"
    while expected_last_line < file_size:
        hexm_file.seek(file_size-expected_last_line)
        buf = hexm_file.read(80)
        i = len(buf)
        first = True
        while i > 0:
            i = i-1
            if buf[i] == '\n' or first:
                first = False
                if buf[i] == '\n':
                    j = i
                else:
                    j = i+1
                k = len(last_line)
                while k > 0:
                    j = j-1
                    k = k-1
                    if buf[j] != last_line[k]:
                        break
                if k > 0 or buf[j-1] != '\n':
                    continue
                i = j-1
                j = j-1
                k = len(pattern_line_number)
                while k > 0:
                    j = j-1
                    k = k-1
                    if (pattern_line_number[k] != 'x' and pattern_line_number[k] != 'y'
                            and pattern_line_number[k] != 'z' and buf[j] != pattern_line_number[k]):
                        break
                if k > 0 or buf[j-1] != '\n':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                total_line = int.from_bytes(binascii.unhexlify(buf[j+13:j+21]), byteorder='big')
                add_line = int.from_bytes(binascii.unhexlify(buf[j+21:j+29]), byteorder='big')

                hexm_file.seek(0)
                while total_line > 0:
                    line = hexm_file.readline()
                    if line == '':
                        print ("original file " + args.exe_name + " has not expected hybrid format")
                        raise OSError(1)
                    total_line = total_line-1
                result = hexm_file.tell()
                while add_line > 0:
                    line = hexm_file.readline()
                    if line == '':
                        print ("original file " + args.exe_name + " has not expected hybrid format")
                        raise OSError(1)
                    add_line = add_line-1
                line = hexm_file.readline()
                if (line != last_line) and (line != last_line+'\n'):
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                hexm_file.seek(result)
                return

        expected_last_line += 40
    print ("original file " + args.exe_name + " has not expected hybrid format")
    raise OSError(1)

def convert_hex_line(hexm_file, bytes_number : int) -> bytes:
    line = ((bytes_number+0xff-1) // 0xff) if (bytes_number > 0) else 1
    result = b''
    while line > 1:
        curline = hexm_file.readline()
        if (curline[0:9] != ":FF000000"):
            print ("original file " + args.exe_name + " has not expected hybrid format")
            raise OSError(1)
        converted_line = binascii.unhexlify(curline[9:9+0xff*2])
        result += converted_line
        checksum = 0
        for ch in converted_line:
            checksum = checksum + ch
        checksum = (checksum +
            int.from_bytes(binascii.unhexlify(curline[1:3]), byteorder='big') +
            int.from_bytes(binascii.unhexlify(curline[3:5]), byteorder='big') +
            int.from_bytes(binascii.unhexlify(curline[5:7]), byteorder='big') +
            int.from_bytes(binascii.unhexlify(curline[7:9]), byteorder='big'))
        checksum = -checksum
        if binascii.unhexlify(curline[9+0xff*2:9+0xff*2+2])[0] != checksum & 0xff:
            print ("original file " + args.exe_name + " has not expected hybrid format")
            raise OSError(1)
        line = line-1
    curline = hexm_file.readline()
    if (curline[0:1] != ":") or (curline[3:9] != "000000"):
        print ("original file " + args.exe_name + " has not expected hybrid format")
        raise OSError(1)
    line_length = int.from_bytes(binascii.unhexlify(curline[1:3]), byteorder='big')
    converted_line = binascii.unhexlify(curline[9:9+line_length*2])
    result += converted_line
    checksum = 0
    for ch in converted_line:
        checksum = checksum + ch
    checksum = (checksum +
        int.from_bytes(binascii.unhexlify(curline[1:3]), byteorder='big') +
        int.from_bytes(binascii.unhexlify(curline[3:5]), byteorder='big') +
        int.from_bytes(binascii.unhexlify(curline[5:7]), byteorder='big') +
        int.from_bytes(binascii.unhexlify(curline[7:9]), byteorder='big'))
    checksum = -checksum
    if (binascii.unhexlify(curline[9+line_length*2:9+line_length*2+2])[0]
            != checksum & 0xff):
        print ("original file " + args.exe_name + " has not expected hybrid format")
        raise OSError(1)
    return result

parser = argparse.ArgumentParser(description='Extract Chariot meta-data from an elf firmware')
parser.add_argument('exe_name', help='the name of the executable elf file')
parser.add_argument('--all', '-a', action='store_true',
                   help='separate meta-data from firmware file')
parser.add_argument('--verbose', '-v', action='store_true',
                   help='verbose mode: echo every command on terminal')
parser.add_argument('--sha', '-sha', action='store_true',
                   help='print the sha256 of the boot section')
parser.add_argument('--format', '-format', action='store_true',
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

try:
    file_size = os.path.getsize(args.exe_name)
    with open(args.exe_name,'r') as hexm_file:
        locate_line_from_end(hexm_file, file_size)
        if args.all:
            if output_file is None:
                print ("extraction of all meta-data requires an output file")
                raise OSError(1)
            while True:
                line = hexm_file.readline()
                if line == '':
                    break
                if line == ":00000001FF\n" or line == ":00000001FF":
                    output_file.write(line)
                    break
                output_file.write(line)

        else:
            if args.verbose:
                print ("extract meta-data section") 
            val = convert_hex_line(hexm_file, len(":chariot_md:"))
            if val != b":chariot_md:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            if args.sha and args.verbose:
                print ("extract sha256 of " + args.exe_name)
            if convert_hex_line(hexm_file, len(":sha256:")) != b":sha256:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            if args.sha:
                sha_256 = convert_hex_line(hexm_file, 256//8)
                result = binascii.hexlify(sha_256).decode("ascii")
                if output_file is not None:
                    output_file.write(result.encode())
                    output_file.write(b'\n')
                else:
                    print(result)
            else:
                hexm_file.readline()

            if args.verbose and args.format:
                print ("extract chariot format")
            line_convert = convert_hex_line(hexm_file, len(":fmt:")+4)
            if line_convert[0:len(":fmt:")] != b":fmt:":
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            format_size = int.from_bytes(line_convert[len(":fmt:"):len(line_convert)], byteorder='big')
            format_string = convert_hex_line(hexm_file, format_size)
            if args.format:
                if output_file is not None:
                    output_file.write(format_string)
                    output_file.write(b'\n')
                else:
                    print(str(format_string.decode()))

            line_convert = convert_hex_line(hexm_file, -1)
            if chr(line_convert[0]) != ':':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            next_header = ""
            index_ch = 1
            size_line_convert = len(line_convert)
            while index_ch < size_line_convert and chr(line_convert[index_ch]) != ':':
                next_header += chr(line_convert[index_ch])
                index_ch = index_ch + 1
            if index_ch >= size_line_convert:
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
                
            if args.add and (next_header != "add"):
                if output_file is None:
                    print("")
            elif next_header == "add":
                if args.verbose and (args.add is not None):
                    print ("extract chariot additional file")
                additional_size = int.from_bytes(
                    line_convert[index_ch+1:index_ch+5], byteorder='big')
                additional_string = convert_hex_line(hexm_file, additional_size)
                if args.add:
                    if output_file is not None:
                        output_file.write(additional_string)
                        output_file.write(b'\n')
                    else:
                        print(additional_string)

                line_convert = convert_hex_line(hexm_file, -1)
                if chr(line_convert[0]) != ':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                additional_mime_size = int.from_bytes(line_convert[1:5], byteorder='big')
                additional_mime_string = convert_hex_line(hexm_file, additional_mime_size)

            if args.verbose and args.version:
                print ("extract chariot version")
            if next_header != "version":
                if convert_hex_line(hexm_file, len(":version:")) != b":version:":
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
            version_string = convert_hex_line(hexm_file, 256 // 8)
            if args.version:
                result = binascii.hexlify(version_string).decode("ascii")
                if output_file is not None:
                    output_file.write(version_string)
                    output_file.write(b'\n')
                else:
                    print(result)

            line_convert = convert_hex_line(hexm_file, -1)
            if chr(line_convert[0]) != ':':
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)
            next_header = ""
            index_ch = 1
            size_line_convert = len(line_convert)
            while index_ch < size_line_convert and chr(line_convert[index_ch]) != ':':
                next_header += chr(line_convert[index_ch])
                index_ch = index_ch + 1
            if index_ch >= size_line_convert:
                print ("original file " + args.exe_name + " has not expected hybrid format")
                raise OSError(1)

            if args.blockchain_path and (next_header != "bcpath"):
                if output_file is None:
                    print("")
            elif next_header == "bcpath":
                if args.verbose and args.blockchain_path is not None:
                    print ("extract chariot blockchain path")
                blockchain_size = int.from_bytes(
                    line_convert[index_ch+1:index_ch+5], byteorder='big')
                blockchain_string = convert_hex_line(hexm_file, blockchain_size)

                if args.blockchain_path:
                    if output_file is not None:
                        output_file.write(blockchain_string)
                        output_file.write(b'\n')
                    else:
                        print(str(blockchain_string.decode()))
                line_convert = convert_hex_line(hexm_file, -1)
                if chr(line_convert[0]) != ':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                next_header = ""
                index_ch = 1
                size_line_convert = len(line_convert)
                while index_ch < size_line_convert and chr(line_convert[index_ch]) != ':':
                    next_header += chr(line_convert[index_ch])
                    index_ch = index_ch + 1
                if index_ch >= size_line_convert:
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

            if args.license and (next_header != "lic"):
                if output_file is None:
                    print("")
            elif next_header == "lic":
                if args.verbose and args.license is not None:
                    print ("extract chariot license path")
                license_size = int.from_bytes(
                    line_convert[index_ch+1:index_ch+5], byteorder='big')
                license_string = convert_hex_line(hexm_file, license_size)

                if args.license:
                    if output_file is not None:
                        output_file.write(license_string)
                        output_file.write(b'\n')
                    else:
                        print(str(license_string.decode()))
                line_convert = convert_hex_line(hexm_file, -1)
                if chr(line_convert[0]) != ':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)
                next_header = ""
                index_ch = 1
                size_line_convert = len(line_convert)
                while index_ch < size_line_convert and chr(line_convert[index_ch]) != ':':
                    next_header += chr(line_convert[index_ch])
                    index_ch = index_ch + 1
                if index_ch >= size_line_convert:
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

            if args.static_analysis and (next_header != "sca"):
                if output_file is None:
                    print("")
            elif next_header == "sca":
                if args.verbose and args.static_analysis is not None:
                    print ("extract chariot static_analysis path")
                static_analysis_size = int.from_bytes(
                    line_convert[index_ch+1:index_ch+5], byteorder='big')
                static_analysis_string = convert_hex_line(hexm_file, static_analysis_size)

                if args.static_analysis:
                    if output_file is not None:
                        output_file.write(static_analysis_string)
                        output_file.write(b'\n')
                    else:
                        print(str(static_analysis_string.decode()))
                line_convert = convert_hex_line(hexm_file, -1)
                if chr(line_convert[0]) != ':':
                    print ("original file " + args.exe_name + " has not expected hybrid format")
                    raise OSError(1)

                static_analysis_mime_size = int.from_bytes(
                    line_convert[1:5], byteorder='big')
                static_analysis_mime_string = convert_hex_line(hexm_file, static_analysis_mime_size)

except OSError as err:
    if output_file is not None:
        output_file.close()
    sys.exit(err.errno)

if output_file is not None:
    output_file.close()
