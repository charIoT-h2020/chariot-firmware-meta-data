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

# CHARIOT: Add meta-data into firmware
# requires sha256sum, git, hexdump

def close_fd_and_file(*args, **kwargs):
    is_fd = True
    for ar in args:
        if is_fd:
            os.close(ar)
        else:
            os.remove(ar)
        is_fd = not is_fd

def compute_sha_256(in_file_name, verbose):
    sha_256_proc = subprocess.Popen(['sha256sum', in_file_name], stdout=subprocess.PIPE)
    sha_result = sha_256_proc.stdout.read().decode("utf-8").partition(' ')[0]
    returncode = sha_256_proc.wait()
    if verbose or returncode:
        command = "sha256sum " + in_file_name
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)
    return bytes.fromhex(sha_result)

def compute_git_version(in_file_name, verbose):
    git_log_proc = subprocess.Popen(
            ['git', 'log', '--format=oneline', '--abbrev=40', '--abbrev-commit', '-q',
                in_file_name], stdout=subprocess.PIPE)
    git_version_result = git_log_proc.stdout.read().decode("utf-8").partition(' ')[0]
    returncode = git_log_proc.wait()
    if verbose or returncode or (len(git_version_result) == 0):
        command = "git log --format=oneline -q -1 " + in_file_name + " | cut '-d '  -f1"
        if returncode or (len(git_version_result) == 0):
            if returncode:
                print ("[warning] the command " + command + " has failed with return code " + str(returncode))
            elif verbose:
                print ("[warning] the command " + command + " has not returned any result")
            git_version_result = "0000000000000000000000000000000000000000000000000000000000000000"
        else:
            print (command)
    if (len(git_version_result) == 40):
        git_version_result += "000000000000000000000000"
    return bytes.fromhex(git_version_result)

parser = argparse.ArgumentParser(description='Add Chariot meta-data into a binary firmware')
parser.add_argument('bin_name', help='the name of the executable binary file')
parser.add_argument('--all', '-all', nargs=1,
                   help='meta-data file')
parser.add_argument('--add', '-add', nargs=2,
                   help='additional file/mime to encode in the Chariot supplementary section')
parser.add_argument('--verbose', '-v', action='store_true',
                   help='verbose mode: echo every command on terminal')
parser.add_argument('--blockchain_path', '-bp', nargs=1,
                   help='the targeted blockchain identification')
parser.add_argument('--license', '-lic', nargs=1,
                   help='the license of the firmware')
parser.add_argument('--software_ID', '-soft', nargs=1,
                   help='the software_id of the firmware')
parser.add_argument('--static-analysis', '-sa', nargs=2,
                   help='result of the static analysis as file/format')
parser.add_argument('--sha', '-sha', nargs=1,
                   help='if provided, replace the computation of sha256')
parser.add_argument('--output', '-o', nargs=1, required=True,
                   help='output file if different from the original file')
args = parser.parse_args()

# produces additional temporary files
if args.add is not None:
    additional_data_file = args.add[0]
    additional_data_mime = args.add[1]
else:
    additional_data_file = None
    additional_data_mime = None

if args.static_analysis is not None:
    static_code_analysis_file = args.static_analysis[0]
    static_code_analysis_mime = args.static_analysis[0]
else:
    static_code_analysis_file = None
    static_code_analysis_mime = None

if args.blockchain_path is not None:
    blockchain_path = args.blockchain_path[0]
else:
    blockchain_path = None

if args.license is not None:
    license = args.license[0]
else:
    license = None

if args.software_ID is not None:
    soft_id = args.software_ID[0]
else:
    soft_id = None

if args.sha is not None:
    sha_provided = args.sha[0]
else:
    sha_provided = None

output_file = args.output[0]

print ("add meta-data in binm file")
try:
    total_size = 0
    with open(args.bin_name,'rb') as hex_file, open(output_file,'wb') as hexm_file:
        if args.verbose:
            print ("copy binary file " + args.bin_name) 
        while True:
            buf=hex_file.read(4096)
            if buf: 
                total_size += hexm_file.write(buf)
            else:
                break
        hex_file.close();

        add_size = 0;
        if args.all is not None:
            if args.verbose:
                print ("copy meta-data file " + args.all) 
            with open(args.all[0],'rb') as meta_file:
                while True:
                    buf=meta_file.read(4096)
                    if buf: 
                        add_size += hexm_file.write(buf)
                    else:
                        break
                meta_file.close();
        else:
            if args.verbose:
                print ("generate meta-data section") 
            hexm_file.write(":chariot_md:".encode())
            add_size += len(":chariot_md:")
            if args.verbose:
                print ("generate sha256 of " + args.bin_name)
            hexm_file.write(":sha256:".encode())
            add_size += len(":sha256:")
            if sha_provided is None:
                hexm_file.write(compute_sha_256(args.bin_name, args.verbose))
            else:
                hexm_file.write(bytes.fromhex(sha_provided))
            add_size += int(256/8)
            if args.verbose:
                print ("generate chariot format")
            hexm_file.write(":fmt:".encode())
            add_size += len(":fmt:")
            hexm_file.write(
                (len("!CHARIOTMETAFORMAT_2019a"))
                    .to_bytes(4, byteorder='big', signed=False))
            add_size += 4
            hexm_file.write("!CHARIOTMETAFORMAT_2019a".encode())
            add_size += len("!CHARIOTMETAFORMAT_2019a")

            if additional_data_file is not None:
                if args.verbose:
                    print ("add additional file " + additional_data_file)
                hexm_file.write(":add:".encode())
                add_size += len(":add:")
                hexm_file.write(
                    (os.path.getsize(additional_data_file))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                with open(additional_data_file,'rb') as add_file:
                    while True:
                        buf=add_file.read(4096)
                        if buf: 
                            add_size += hexm_file.write(buf)
                        else:
                            break
                    add_file.close();
                hexm_file.write(":".encode())
                add_size += 1
                hexm_file.write(
                    (len(additional_data_mime))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                hexm_file.write(additional_data_mime.encode())
                add_size += len(additional_data_mime)

            if args.verbose:
                print ("generate version of " + args.bin_name)
            hexm_file.write(":version:".encode())
            add_size += len(":version:")
            hexm_file.write(compute_git_version(args.bin_name, args.verbose))
            add_size += int(32)

            if blockchain_path is not None:
                if args.verbose:
                    print ("add blockchain path")
                hexm_file.write(":bcpath:".encode())
                add_size += len(":bcpath:")
                hexm_file.write(
                    (len(blockchain_path))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                hexm_file.write(blockchain_path.encode())
                add_size += len(blockchain_path)

            if license is not None:
                if args.verbose:
                    print ("add license")
                hexm_file.write(":lic:".encode())
                add_size += len(":lic:")
                hexm_file.write(
                    (len(license))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                hexm_file.write(license.encode())
                add_size += len(license)

            if soft_id is not None:
                if args.verbose:
                    print ("add software id")
                hexm_file.write(":soft:".encode())
                add_size += len(":soft:")
                hexm_file.write(
                    (len(soft_id))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                hexm_file.write(soft_id.encode())
                add_size += len(soft_id)

            if static_code_analysis_file is not None:
                if args.verbose:
                    print ("add static analysis results")
                hexm_file.write(":sca:".encode())
                add_size += len(":sca:")
                hexm_file.write(
                    (os.path.getsize(static_code_analysis_file))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                with open(static_code_analysis_file,'rb') as add_file:
                    while True:
                        buf=add_file.read(4096)
                        if buf: 
                            add_size += hexm_file.write(buf)
                        else:
                            break
                    add_file.close();
                hexm_file.write(":".encode())
                add_size += 1
                hexm_file.write(
                    (len(static_code_analysis_mime))
                        .to_bytes(4, byteorder='big', signed=False))
                add_size += 4
                hexm_file.write(static_code_analysis_mime.encode())
                add_size += len(static_code_analysis_mime)

            if args.verbose:
                print ("add additional size info")
            hexm_file.write("::".encode())
            add_size += 2
            add_size += 4
            hexm_file.write(
               (add_size).to_bytes(4, byteorder='big', signed=False))

        if args.verbose:
            print ("close file and check")
        hexm_file.close();
        if os.path.getsize(output_file) != add_size + total_size:
            print ("[error] internal size computation is not correct: "
                    + "file size = " + str(os.path.getsize(output_file))
                    + ", original size = " + str(total_size)
                    + ", additional size = " + str(add_size))
            raise OSError(1)
        if args.verbose:
            print ("check is ok")

except OSError as err:
    sys.exit(err.errno)

