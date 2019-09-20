#!/usr/bin/python3
import os
import sys
import argparse
import subprocess
import tempfile

# CHARIOT: Add meta-data into firmware
# requires size, objcopy supporting add-section option
#          gcc (at least gnu-as)
#          sha256sum, git, hexdump

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
    sha_result = sha_256_proc.stdout.read().partition(' ')[0]
    returncode = sha_256_proc.wait()
    if verbose or returncode:
        command = "sha256sum " + in_file_name
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)
    return sha_result

def compute_sha_256_content(elf_name, mainboot, verbose):
    fd_content_s, content_s_path = tempfile.mkstemp()
    try:
        returncode = os.system('objcopy --dump-section .%s=%s %s' % (mainboot, content_s_path, elf_name))
        if args.verbose or returncode:
            command = "objcopy --dump-section ." + mainboot + "=" + content_s_path + " " + elf_name
            if returncode:
                print ("[error] the command " + command + " has failed with return code " + str(returncode))
                raise OSError(returncode)
            print (command)
        sha_result = compute_sha_256(content_s_path, verbose);
    finally:
        close_fd_and_file(fd_content_s, content_s_path)
    return sha_result

def compute_git_version(in_file_name, verbose):
    git_log_proc = subprocess.Popen(
            ['git', 'log', '--format=oneline', '--abbrev=12', '--abbrev-commit', '-q',
                in_file_name], stdout=subprocess.PIPE)
    git_version_result = git_log_proc.stdout.read().partition(' ')[0]
    returncode = git_log_proc.wait()
    if verbose or returncode:
        command = "git log --format=oneline --abbrev=12 --abbrev-commit -q " + in_file_name + ""
        if returncode:
            print ("[warning] the command " + command + " has failed with return code " + str(returncode))
            git_version_result = "0000000000000000000000000000000000000000000000000000000000000000"
        else:
            print (command)
    return git_version_result

def generate_metadata_as_assembly(out_as_file, elf_file_name, mainboot,
        in_additional_file_name, in_additional_mime,
        in_static_code_analysis_file, in_static_code_analysis_mime,
        in_block_chain_path, in_license, verbose, mainboot_size=0, mainboot_offset=0,
        additional_size=0, additional_offset=0):
    content = [
               ".section .chariotmeta.rodata,\"a\"",
               " .align 16",
               " .globl chariotmeta_mainboot_sha256",
               "chariotmeta_mainboot_sha256:",
               " .string \"" + compute_sha_256_content(elf_file_name, mainboot, verbose) + " mainboot\"",
               " .type  chariotmeta_mainboot_sha256, @object",
               " .size  chariotmeta_mainboot_sha256, 73",
               # " .align 16",
               " .globl chariotmeta_format_typeinfo",
               "chariotmeta_format_typeinfo:",
               " .string \"!CHARIOTMETAFORMAT_2019a\"",
               " .type  chariotmeta_format_typeinfo, @object",
               " .size  chariotmeta_format_typeinfo, 24",
               # " .align 16",
               " .globl chariotmeta_mainboot_offsetnum",
               "chariotmeta_mainboot_offsetnum:",
               " .string \"" + '{0:08x}'.format(int(mainboot_offset)) + "\" /*@mainboot_offsetnum*/",
               " .type  chariotmeta_mainboot_offsetnum, @object",
               " .size  chariotmeta_mainboot_offsetnum, 8",
               # " .align 16",
               " .globl chariotmeta_mainboot_sizenum",
               "chariotmeta_mainboot_sizenum:",
               " .string \"" + '{0:08x}'.format(int(mainboot_size)) + "\" /*@mainboot_sizenum*/",
               " .type  chariotmeta_mainboot_sizenum, @object",
               " .size  chariotmeta_mainboot_sizenum, 8"
               # " .align 16"
              ]
    if in_additional_file_name is not None:
        content+= [
                   " .globl chariotmeta_extraboot_sha256",
                   "chariotmeta_extraboot_sha256:",
                   " .string \""
                       + compute_sha_256(in_additional_file_name, verbose)
                       + ' ' + in_additional_file_name + "\"",
                   " .type  chariotmeta_extraboot_sha256, @object",
                   " .size chariotmeta_extraboot_sha256,     . - chariotmeta_extraboot_sha256",
                   # " .align 16",
                   " .globl chariotmeta_extraboot_offsetnum",
                   "chariotmeta_extraboot_offsetnum:",
                   " .string \"" + '{:08x}'.format(int(additional_offset)) + "\" /*@extraboot_offsetnum*/",
                   " .type  chariotmeta_extraboot_offsetnum, @object",
                   " .size  chariotmeta_extraboot_offsetnum, 8",
                   # " .align 16",
                   " .globl chariotmeta_extraboot_sizenum",
                   "chariotmeta_extraboot_sizenum:",
                   " .string \"" + '{:08x}'.format(int(additional_size)) + "\" /*@extraboot_sizenum*/",
                   " .type  chariotmeta_extraboot_sizenum, @object",
                   " .size  chariotmeta_extraboot_sizenum, 8",
                   # " .align 16",
                   " .globl chariotmeta_extraboot_typeinfo",
                   "chariotmeta_extraboot_typeinfo:",
                   " .string \"" + in_additional_mime + "\"",
                   " .type  chariotmeta_extraboot_typeinfo, @object",
                   " .size  chariotmeta_extraboot_typeinfo, " + str(len(in_additional_mime))
                   # " .align 16"
                  ]
    if in_static_code_analysis_file is not None:
        content+= [
                   " .globl chariotmeta_codanalys_typeinfo",
                   "chariotmeta_codanalys_typeinfo:",
                   " .string \"" + in_static_code_analysis_mime + "\"",
                   " .type  chariotmeta_codanalys_typeinfo, @object",
                   " .size  chariotmeta_codanalys_typeinfo, " + str(len(in_static_code_analysis_mime))
                   # " .align 16"
                  ]
    content+= [
               " .globl chariotmeta_version_data",
               "chariotmeta_version_data:",
               " .string \"" + compute_git_version(elf_file_name, verbose) + "\"",
               " .type  chariotmeta_version_data, @object",
               " .size chariotmeta_version_data,     . - chariotmeta_version_data"
               # " .align 16"
              ]
    if in_block_chain_path is not None:
        content+= [
                   " .globl chariotmeta_firmware_path",
                   "chariotmeta_firmware_path:",
                   " .string \"CHARIOTMETA_FIRMWARE_PATH=" + in_block_chain_path + "\"",
                   " .type chariotmeta_firmware_path,  @object",
                   " .size chariotmeta_firmware_path,     . - chariotmeta_firmware_path"
                   # " .align 16"
                  ]
    if in_license is not None:
        content+= [
                   " .globl chariotmeta_firmware_license",
                   "chariotmeta_firmware_license:",
                   " .string \"CHARIOTMETA_FIRMWARE_LICENSE=" + in_license + "\"",
                   " .type chariotmeta_firmware_license,  @object",
                   " .size chariotmeta_firmware_license,     . - chariotmeta_firmware_license"
                   # " .align 16"
                  ]
    if in_static_code_analysis_file is not None:
        with open(in_static_code_analysis_file, 'r') as ana_file:
            static_code_analysis = ana_file.read()
            static_code_analysis = static_code_analysis.replace(
                    '\\', '\\\\').replace('\n', '\\n').replace('\t', '\\t').replace('"', '\\"')
            content+= [
                       " .globl chariotmeta_codanalys_data",
                       "chariotmeta_codanalys_data:",
                       " .string \"CHARIOTMETA_CODANALYS_DATA= " + static_code_analysis + " \"",
                       " .type chariotmeta_codanalys_data,  @object",
                       " .size chariotmeta_codanalys_data,     . - chariotmeta_codanalys_data"
                      ]
    for line in content:
        out_as_file.write(line);
        out_as_file.write('\n');

def generate_additional_as_c_file(c_file_with_additional, additional_data_file, additional_data_mime, verbose):
    c_file_with_additional.write('const char boot_supplementary_data[] __attribute__((section(".suppldata"))) = {\n')
    hexdump_proc = subprocess.Popen(['hexdump', '-v', '-e', '/1 \" %#x,\"', additional_data_file], stdout=subprocess.PIPE)
    hex_result = hexdump_proc.stdout.read()
    returncode = hexdump_proc.wait()
    if verbose or returncode:
        command = "hexdump -v -e '/1 \" %#x,\"' " + additional_data_file
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)
    c_file_with_additional.write(hex_result)
    c_file_with_additional.write("};\n")

def extract_info(output_file, section):
    size_proc = subprocess.Popen(['size', '-A', '-d', output_file], stdout=subprocess.PIPE)
    partition = None
    while True:
        line = size_proc.stdout.readline()
        if line == '':
            break
        if line[0] == '.' and line[1:len(section)+1] == section:
            partition = line.split()
            break
    returncode = size_proc.wait()
    if args.verbose or returncode or partition is None or len(partition) < 3:
        command = "size -A -d " + output_file
        if returncode or partition is None:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            if partition is None:
                print ("section ." + section + " not found")
            raise OSError(returncode)
        print (command)
    return (partition[1], partition[2])

def extract_sub_info(output_file, section):
    fd_content_s, content_s_path = tempfile.mkstemp()
    try:
        returncode = os.system('objcopy --dump-section .%s=%s %s' % (section, content_s_path, output_file))
        if args.verbose or returncode:
            command = "objcopy --dump-section ." + section + "=" + content_s_path + " " + output_file
            if returncode:
                print ("[error] the command " + command + " has failed with return code " + str(returncode))
                raise OSError(returncode)
            print (command)
        return extract_info(content_s_path, section)
    finally:
        close_fd_and_file(fd_content_s, content_s_path)

def has_section(output_file, section):
    size_proc = subprocess.Popen(['size', '-A', output_file], stdout=subprocess.PIPE)
    result = False
    while not result:
        line = size_proc.stdout.readline()
        if line == '':
            break
        if line[0] == '.' and line[1:len(section)+1] == section:
            result = True
    returncode = size_proc.wait()
    if args.verbose or returncode:
        command = "size -A " + output_file
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            raise OSError(returncode)
        print (command)
    return result

parser = argparse.ArgumentParser(description='Add Chariot meta-data into an elf firmware')
parser.add_argument('exe_name', help='the name of the executable elf file')
# parser.add_argument('--march', '-march', nargs=2, required=True,
#                    help='option passed to gcc')
parser.add_argument('--boot', '-boot', nargs=1, required=True,
                   help='name of the main boot section of the elf file')
parser.add_argument('--add', '-add', nargs=2,
                   help='additional file/mime to encode in the Chariot supplementary section')
parser.add_argument('--verbose', '-v', action='store_true',
                   help='verbose mode: echo every command on terminal')
parser.add_argument('--blockchain_path', '-bp', nargs=1,
                   help='the targeted blockchain identification')
parser.add_argument('--license', '-lic', nargs=1,
                   help='the license of the firmware in the Chariot format')
parser.add_argument('--static-analysis', '-sa', nargs=2,
                   help='result of the static analysis as file/format')
parser.add_argument('--output', '-o', nargs=1,
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

mainboot = args.boot[0]

print ("generate section containing metadata as an assembly file")
fd_metadata_s, metadata_s_path = tempfile.mkstemp(suffix=".s")
try:
    assembly_file_without_data = open(metadata_s_path, 'w')
    generate_metadata_as_assembly(assembly_file_without_data, args.exe_name, args.boot[0],
            additional_data_file, additional_data_mime,
            static_code_analysis_file, static_code_analysis_mime,
            blockchain_path, license, args.verbose)
    assembly_file_without_data.close()
except OSError as err:
    os.close(fd_metadata_s)
    os.remove(metadata_s_path)
    sys.exit(err.errno)

print ("compile metadata assembly file into an elf object file")
fd_metadata_o, metadata_o_path = tempfile.mkstemp()
# could use as instead of gcc: as --32
gcc_option = "-m32" # -m32
# as_option = "" # --32
returncode = os.system('gcc -ffreestanding %s -c -O %s -Wall -o %s' % (gcc_option, metadata_s_path, metadata_o_path))
# os.system('as %s %s -o %s' % (as_option, metadata_s_path, metadata_o_path))
if args.verbose or returncode:
    command = "gcc -ffreestanding " + gcc_option + " -c -O " + metadata_s_path + " -Wall -o " + metadata_o_path + " \""
    if returncode:
        print ("[error] the command " + command + " has failed with return code " + str(returncode))
        close_fd_and_file(fd_metadata_s, metadata_s_path)
        os.close(fd_metadata_o)
        sys.exit(returncode)
    print (command)

if args.output is not None:
    output_file = args.output[0]
else:
    fd_output, output_file = tempfile.mkstemp()

if additional_data_file is not None:
    print ("compile extra-data file into an elf object file")
    fd_additional_c, additional_c_path = tempfile.mkstemp(suffix = ".c")
    c_file_with_additional = open(additional_c_path, 'w')
    try:
        generate_additional_as_c_file(c_file_with_additional, additional_data_file, additional_data_mime, args.verbose)
    except OSError as err:
        c_file_with_additional.close()
        close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
        if args.output is None:
            os.close(fd_output)
        sys.exit(err.errno)
    c_file_with_additional.close()
    fd_additional_o, additional_o_path = tempfile.mkstemp()
    returncode = os.system('gcc -ffreestanding %s -O -c %s -Wall -o %s' % (gcc_option, additional_c_path, additional_o_path))
    if args.verbose or returncode:
        command = "gcc -ffreestanding " + gcc_option + " -O -c " + additional_c_path + " -Wall -o " + additional_o_path + " \""
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            close_fd_and_file(fd_metadata_s, metadata_s_path, fd_additional_c, additional_c_path,
                    fd_additional_o, additional_o_path, fd_metadata_o, metadata_o_path)
            if args.output is None:
                os.close(fd_output)
            sys.exit(returncode)
        print (command)
    close_fd_and_file(fd_additional_c, additional_c_path)

    print ("add meta-data and extra-data into the elf executable file")
    fstAction = "add-section" if not has_section(args.exe_name, "chariotmeta.rodata") else "update-section"
    sndAction = "add-section" if not has_section(args.exe_name, "suppldata") else "update-section"
    returncode = os.system("objcopy --%s .chariotmeta.rodata=%s "
            "--%s .suppldata=%s "
            "--set-section-flags .chariotmeta.rodata=noload,readonly "
            "--set-section-flags .suppldata=noload,readonly "
            "%s %s" % (fstAction, metadata_o_path, sndAction, additional_o_path, args.exe_name, output_file))
    if args.verbose or returncode:
        command = "objcopy --" + fstAction + " .chariotmeta.rodata=" + metadata_o_path + " --" + sndAction + " .suppldata=" + additional_o_path + " --set-section-flags .chariotmeta.rodata=noload,readonly --set-section-flags .suppldata=noload,readonly " + args.exe_name + " " + output_file
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            close_fd_and_file(fd_metadata_s, metadata_s_path, fd_additional_o, additional_o_path,
                    fd_metadata_o, metadata_o_path)
            if args.output is None:
                os.close(fd_output)
            sys.exit(returncode)
        print (command)
else:
    print ("add meta-data into the elf executable file")
    action = "add-section" if not has_section(args.exe_name, "chariotmeta.rodata") else "update-section" 
    returncode = os.system("objcopy --%s .chariotmeta.rodata=%s "
            "--set-section-flags .chariotmeta.rodata=noload,readonly "
            "%s %s" % (action, metadata_o_path, args.exe_name, output_file))
    if args.verbose or returncode:
        command = "objcopy --" + action + " .chariotmeta.rodata=" + metadata_o_path + " --set-section-flags .chariotmeta.rodata=noload,readonly " + args.exe_name + " " + output_file
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
            if args.output is None:
                os.close(fd_output)
            sys.exit(returncode)
        print (command)

print ("update meta-data assembly file")
try:
    (mainboot_size, mainboot_offset) = extract_info(output_file, mainboot)
    (additional_size, additional_offset) = (0, 0)
    if additional_data_file is not None:
        additional_size, additional_offset = extract_sub_info(output_file, "suppldata")
    assembly_file_without_data = open(metadata_s_path, 'w')
    generate_metadata_as_assembly(assembly_file_without_data, args.exe_name, mainboot,
            additional_data_file, additional_data_mime,
            static_code_analysis_file, static_code_analysis_mime,
            blockchain_path, license, args.verbose, mainboot_size, mainboot_offset,
            additional_size, additional_offset)
    assembly_file_without_data.close()
    print ("recompile metadata assembly file after update")
    returncode = os.system('gcc -ffreestanding %s -c -O %s -Wall -o %s' % (gcc_option, metadata_s_path, metadata_o_path))
    if args.verbose or returncode:
        command = "gcc -ffreestanding " + gcc_option + " -c -O " + metadata_s_path + " -Wall -o " + metadata_o_path + " \""
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
            if additional_data_file is not None:
                close_fd_and_file(fd_additional_o, additional_o_path)
            if args.output is None:
                close_fd_and_file(fd_output, output_file)
            sys.exit(returncode)
        print (command)
    if additional_data_file is not None:
        print ("add again meta-data and extra-data into the elf executable file")
        fstAction = "add-section" if not has_section(args.exe_name, "chariotmeta.rodata") else "update-section"
        sndAction = "add-section" if not has_section(args.exe_name, "suppldata") else "update-section"
        returncode = os.system("objcopy --%s .chariotmeta.rodata=%s "
                "--%s .suppldata=%s "
                "--set-section-flags .chariotmeta.rodata=noload,readonly "
                "--set-section-flags .suppldata=noload,readonly "
                "%s %s" % (fstAction, metadata_o_path, sndAction, additional_o_path, args.exe_name, output_file))
        if args.verbose or returncode:
            command = "objcopy --" + fstAction + " .chariotmeta.rodata=" + metadata_o_path + " --" + sndAction + " .suppldata=" + additional_o_path + " --set-section-flags .chariotmeta.rodata=noload,readonly --set-section-flags .suppldata=noload,readonly " + args.exe_name + " " + output_file
            if returncode:
                print ("[error] the command " + command + " has failed with return code " + str(returncode))
                close_fd_and_file(fd_metadata_s, metadata_s_path,
                        fd_additional_o, additional_o_path, fd_metadata_o, metadata_o_path)
                if args.output is None:
                    close_fd_and_file(fd_output, output_file)
                sys.exit(returncode)
            print (command)
        close_fd_and_file(fd_additional_o, additional_o_path)
    else:
        print ("add again meta-data into the elf executable file")
        action = "add-section" if not has_section(args.exe_name, "chariotmeta.rodata") else "update-section"
        returncode = os.system("objcopy --%s .chariotmeta.rodata=%s "
                "--set-section-flags .chariotmeta.rodata=noload,readonly "
                "%s %s" % (action, metadata_o_path, args.exe_name, output_file))
        if args.verbose or returncode:
            command = "objcopy --" + action + " .chariotmeta.rodata=" + metadata_o_path + " --set-section-flags .chariotmeta.rodata=noload,readonly " + args.exe_name + " " + output_file
            if returncode:
                print ("[error] the command " + command + " has failed with return code " + str(returncode))
                close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
                if args.output is None:
                    close_fd_and_file(fd_output, output_file)
                sys.exit(returncode)
            print (command)

except OSError as err:
    close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
    if args.output is None:
        close_fd_and_file(fd_output, output_file)
    sys.exit(err.errno)

close_fd_and_file(fd_metadata_s, metadata_s_path, fd_metadata_o, metadata_o_path)
# also done by the gc at the end of the program

if args.output is None:
    returncode = os.system("cp %s %s" % (output_file, args.exe_name))
    if args.verbose or returncode:
        command = "mv " + output_file + " " + args.exe_name
        if returncode:
            print ("[error] the command " + command + " has failed with return code " + str(returncode))
            close_fd_and_file(fd_output, output_file)
            sys.exit(returncode)
        print (command)
    close_fd_and_file(fd_output, output_file)

