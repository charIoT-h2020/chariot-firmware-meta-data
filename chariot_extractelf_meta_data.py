#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import tempfile

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
# requires readelf, objcopy supporting add-section option

elf_offset_section = 64

def close_fd_and_file(*args, **kwargs):
    is_fd = True
    for ar in args:
        if is_fd:
            os.close(ar)
        else:
            os.remove(ar)
        is_fd = not is_fd

def extract_section(exe_name, section_name, out_filename, verbose):
    returncode = os.system("objcopy --dump-section .%s=%s %s"
             % (section_name, out_filename, exe_name))
    if args.verbose or returncode:
        command = "objcopy --dump-section ." + section_name + '=' + out_filename + " " + exe_name
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)

def query_start_size(metadata_filename, verbose):
    readelf_proc = subprocess.Popen(['readelf', '-s', metadata_filename], stdout=subprocess.PIPE)
    result = {}
    while True:
        line = readelf_proc.stdout.readline()
        if not line:
            break
        partition = line.split()
        if (len(partition) >= 8 and partition[0][0] >= ord('0') and partition[0][0] <= ord('9')
                and partition[0][len(partition[0])-1] == ord(':')):
            try:
                key = partition[7]
                if len(key) >= 25:
                    key = key[0:25]
                result[key] = (int(partition[1], 16), int(partition[2]))
            except:
                continue
    returncode = readelf_proc.wait()
    if verbose or returncode:
        command = "readelf -s " + metadata_filename
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)
    return result

def print_meta_data_result(condition, field, metadata_file, start_size_dict, output_file):
    if condition:
        key = field
        if len(key) >= 25:
            key = key[0:25]
        try:
            (start, size) = start_size_dict[key]
            if size > 0:
                metadata_file.seek(start+elf_offset_section)
                if output_file is not None:
                    output_file.write(metadata_file.read(size))
                else:
                    print(str(metadata_file.read(size), "utf-8"))
            else:
                print("no output for metadata ", key, file=sys.stderr)
        except:
            print("no output for metadata ", key, file=sys.stderr)

def get_meta_data_result(field, metadata_file, start_size_dict):
    key = field
    if len(key) >= 25:
        key = key[0:25]
    try:
        (start, size) = start_size_dict[key]
        result = 0
        if size > 0:
            metadata_file.seek(start+elf_offset_section)
            content = metadata_file.read(size)
            if size != 8:
                print ("[error] corrupted int for " + field + " in metadata section of exe file")
                raise OSError(0)
            result = int(content, 16)
        else:
            print ("no output for metadata ", key, file=sys.stderr)
            raise OSError(0)
    except:
        print ("no output for metadata ", key, file=sys.stderr)
        raise OSError(0)
    return result

def print_additional_result(additions_file, start, size):
    if size > 0:
        additions_file.seek(start+elf_offset_section)
        if output_file is not None:
            output_file.write(additions_file.read(size))
        else:
            print(additions_file.read(size))
    else:
        print >> sys.stderr, "no output for additions at address %d", start

parser = argparse.ArgumentParser(description='Extract Chariot meta-data from an elf firmware')
parser.add_argument('exe_name', help='the name of the executable elf file')
parser.add_argument('--all', '-a', action='store_true',
                   help='equivalent to -sha -sa -bp -lic -add')
parser.add_argument('--verbose', '-v', action='store_true',
                   help='verbose mode: echo every command on terminal')
parser.add_argument('--sha', '-sha', action='store_true',
                   help='print the sha256 of the boot section')
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
    output_file = args.output[0]
else:
    output_file = None

fd_metadata, metadata_filename = tempfile.mkstemp()
try:
    extract_section(args.exe_name, "chariotmeta.rodata", metadata_filename, args.verbose)
except OSError as err:
    close_fd_and_file(fd_metadata, metadata_filename)
    sys.exit(err.errno)

try:
    start_size_dict = query_start_size(metadata_filename, args.verbose)
except OSError as err:
    close_fd_and_file(fd_metadata, metadata_filename)
    sys.exit(err.errno)

metadata_file = open(metadata_filename, 'rb')
print_meta_data_result(args.sha or args.all, b"chariotmeta_mainboot_sha256", metadata_file, start_size_dict, output_file)
print_meta_data_result(args.blockchain_path or args.all, b"chariotmeta_firmware_path", metadata_file, start_size_dict, output_file)
print_meta_data_result(args.license or args.all, b"chariotmeta_firmware_license", metadata_file, start_size_dict, output_file)
print_meta_data_result(args.static_analysis or args.all, b"chariotmeta_codanalys_data", metadata_file, start_size_dict, output_file)
if args.add or args.all:
    fd_additions, additions_filename = tempfile.mkstemp()
    try:
        extract_section(args.exe_name, "suppldata", additions_filename, args.verbose)
        start = get_meta_data_result(b"chariotmeta_extraboot_offsetnum", metadata_file, start_size_dict)
        size = get_meta_data_result(b"chariotmeta_extraboot_sizenum", metadata_file, start_size_dict)
        additions_file = open(additions_filename, 'rb')
        print_additional_result(additions_file, start, size)
        additions_file.close()
    except OSError as err:
        close_fd_and_file(fd_metadata, metadata_filename, fd_additions, additions_filename)
        sys.exit(err.errno)
    
    close_fd_and_file(fd_additions, additions_filename)

metadata_file.close()
close_fd_and_file(fd_metadata, metadata_filename)

