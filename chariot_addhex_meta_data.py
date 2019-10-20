#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import binascii

# CHARIOT: Add meta-data into firmware
# requires sha256sum, git, hexdump

def convert_hex_line(content : bytes, add_line : int):
    length = len(content)
    line = 0
    result = ""
    while length > 0xff:
        checksum = 0xff
        result += ":ff000000"
        subline = content[line*0xff:line*0xff+0xff]
        result += binascii.hexlify(subline).decode("ascii")
        for ch in subline:
            checksum += ch
        checksum = -checksum
        result += binascii.hexlify(bytes([checksum & 0xff])).decode("ascii")
        result += "\n"
        length -= 0xff
        line = line+1
    checksum = length
    result += ":" + binascii.hexlify(bytes([length])).decode("ascii")+ "000000"
    if line > 0:
        subline = content[line*0xff:line*0xff+length]
        result += binascii.hexlify(subline).decode("ascii")
        for ch in subline:
            checksum = checksum + ch
    else:
        result += binascii.hexlify(content).decode("ascii")
        for ch in content:
            checksum = checksum + ch
    checksum = -checksum
    result += binascii.hexlify(bytes([checksum & 0xff])).decode("ascii")
    result += "\n"
    return result, add_line+line+1

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
        command = "git log --format=oneline --abbrev=40 --abbrev-commit -q " + in_file_name + ""
        if returncode or (len(git_version_result) == 0):
            if returncode:
                print ("[warning] the command " + command + " has failed with return code " + str(returncode))
            elif verbose:
                print ("[warning] the command " + command + " has not returned any result")
            git_version_result = "0000000000000000000000000000000000000000"
        else:
            print (command)
    return bytes.fromhex(git_version_result)

parser = argparse.ArgumentParser(description='Add Chariot meta-data into an hex firmware')
parser.add_argument('hex_name', help='the name of the executable hex file')
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
    software_id = args.software_ID[0]
else:
    software_id = None

if args.sha is not None:
    sha_provided = args.sha[0]
else:
    sha_provided = None

output_file = args.output[0]

print ("add meta-data in hexm file")
try:
    total_line = 0
    with open(args.hex_name,'r') as hex_file, open(output_file,'w') as hexm_file:
        if args.verbose:
            print ("copy hex file " + args.hex_name) 
        while True:
            line = hex_file.readline()
            if line == '':
                break
            if line == ":00000001FF\n" or line == ":00000001FF":
                break
            total_line = total_line+1
            hexm_file.write(line)
        hex_file.close();

        add_line = 0;
        if args.all is not None:
            if args.verbose:
                print ("copy meta-data file " + args.all) 
            with open(args.all[0],'r') as meta_file:
                while True:
                    line = meta_file.readline()
                    if line == '':
                        break
                    if line == ":00000001FF\n" or line == ":00000001FF":
                        break
                    hexm_file.write(line)
                    add_line = add_line+1
                res, add_line = hexm_file.write(convert_hex_line(
                    str(add_line+2).encode()), add_line)
                add_line = add_line+1
                hexm_file.write(":00000001FF\n")
                meta_file.close();
        else:
            if args.verbose:
                print ("generate meta-data section") 
            res, add_line = convert_hex_line(":chariot_md:".encode(), add_line)
            hexm_file.write(res)
            if args.verbose:
                print ("generate sha256 of " + args.hex_name)
            res, add_line = convert_hex_line(":sha256:".encode(), add_line)
            hexm_file.write(res)
            if sha_provided is None:
                res, add_line = convert_hex_line(
                    compute_sha_256(args.hex_name, args.verbose), add_line)
            else:
                res, add_line = convert_hex_line(
                    bytes.fromhex(sha_provided), add_line)
            hexm_file.write(res)
            if args.verbose:
                print ("generate chariot format")
            res, add_line = convert_hex_line(":fmt:".encode() +
                (len("!CHARIOTMETAFORMAT_2019a"))
                    .to_bytes(4, byteorder='big', signed=False), add_line)
            hexm_file.write(res)
            res, add_line = convert_hex_line("!CHARIOTMETAFORMAT_2019a".encode(), add_line)
            hexm_file.write(res)

            if additional_data_file is not None:
                if args.verbose:
                    print ("add additional file " + additional_data_file)
                res, add_line = convert_hex_line(":add:".encode()
                    + (os.path.getsize(additional_data_file))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                with open(additional_data_file,'rb') as add_file:
                    while True:
                        buf=add_file.read(4096)
                        if buf:
                            res, add_line = convert_hex_line(buf, add_line)
                            hexm_file.write(res)
                        else:
                            break
                    add_file.close();
                res, add_line = convert_hex_line(":".encode()
                    + (len(additional_data_mime))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                res, add_line = convert_hex_line(additional_data_mime.encode(), add_line)
                hexm_file.write(res)

            if args.verbose:
                print ("generate version of " + args.hex_name)
            res, add_line = convert_hex_line(":version:".encode(), add_line)
            hexm_file.write(res)
            res, add_line = convert_hex_line(compute_git_version(
                    args.hex_name, args.verbose), add_line)
            hexm_file.write(res)

            if blockchain_path is not None:
                if args.verbose:
                    print ("add blockchain path")
                res, add_line = convert_hex_line(":bcpath:".encode()
                    + (len(blockchain_path))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                res, add_line = convert_hex_line(blockchain_path.encode(), add_line)
                hexm_file.write(res)

            if license is not None:
                if args.verbose:
                    print ("add license")
                res, add_line = convert_hex_line(":lic:".encode()
                    + (len(license))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                res, add_line = convert_hex_line(license.encode(), add_line)
                hexm_file.write(res)

            if software_id is not None:
                if args.verbose:
                    print ("add software id")
                res, add_line = convert_hex_line(":soft:".encode()
                    + (len(software_id))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                res, add_line = convert_hex_line(software_id.encode(), add_line)
                hexm_file.write(res)

            if static_code_analysis_file is not None:
                if args.verbose:
                    print ("add static analysis results")
                res, add_line = convert_hex_line(":sca:".encode()
                    + (os.path.getsize(static_code_analysis_file))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                with open(static_code_analysis_file,'rb') as add_file:
                    while True:
                        buf=add_file.read(4080)
                        if buf:
                            res, add_line = convert_hex_line(buf, add_line)
                            hexm_file.write(res)
                        else:
                            break
                    add_file.close();
                res, add_line = convert_hex_line(":".encode()
                    + (len(static_code_analysis_mime))
                        .to_bytes(4, byteorder='big', signed=False), add_line)
                hexm_file.write(res)
                res, add_line = convert_hex_line(static_code_analysis_mime.encode(), add_line)
                hexm_file.write(res)

            if args.verbose:
                print ("add additional size info")
            res, add_line = convert_hex_line("::".encode() +
               (total_line).to_bytes(4, byteorder='big', signed=False) +
               (add_line+1).to_bytes(4, byteorder='big', signed=False), add_line)
            hexm_file.write(res)
            hexm_file.write(":00000001FF")

        if args.verbose:
            print ("close file and check")
        hexm_file.close();

except OSError as err:
    sys.exit(err.errno)

