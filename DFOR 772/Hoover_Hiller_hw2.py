""" DFOR 772
    Hiller Hoover """

version = '0.0'

""" Change Log:
    01/27/2026: began writing file 
    01/28/2026 restructured partition info method, created print_info method
    02/1/2026 verified output, submitted for grade"""

import argparse
import os
import hashlib


def open_image(image_path):
    if not os.path.isfile(image_path):
        print(f'Cannot find {image_path}; exiting program.')
        exit()
    image_file = open (image_path, 'rb')
    return image_file

def retrieve_partition_info(image_file,outfile):
    #reads the bytes of the VBR sequentially
    #sets jump_bytes to second byte in jump_instruction. It appears to be the case that jump_bytes turns the hex bytes into decimal automatically.

    jump_instruction = image_file.read(3)
    jump_bytes = jump_instruction[1]
    oem_name = image_file.read(8)
    sector_size = image_file.read(2)
    sectors_per_cluster = image_file.read(1)
    reserved_sectors = image_file.read(2)
    number_of_FATs = image_file.read(1)
    max_roots = image_file.read(2)
    total_sec = image_file.read(2)
    descriptor_ID = image_file.read(1)
    sec_per_fat = image_file.read(2)
    sectors_per_track = image_file.read(2)
    number_of_heads = image_file.read(2)
    number_of_hidden_sectors = image_file.read(4)
    total_sectors = image_file.read(4)
    sectors_per_fat = image_file.read(4)
    active_fat = image_file.read(2)
    filesystem_version = image_file.read(2)
    first_cluster = image_file.read(4)
    info_sector = image_file.read(2)
    backup_boot_sector = image_file.read(2)
    reserved = image_file.read(12)
    physical_id = image_file.read(1)
    reserved_for_NT = image_file.read(1)
    boot_signature = image_file.read(1)
    volume_serial_number = image_file.read(4)
    volume_label = image_file.read(11)
    filesystem_id = image_file.read(8)
    boot_code = image_file.read(420)

    #prints VBR info, using a secondary function to cast the raw bytes into hex and decimal with little endian.

    print(f'Jump instruction: 0x{jump_instruction.hex()}')
    print(f'OEM name (ASCII): {oem_name.decode()}')
    print_info("Sector size", sector_size)
    print_info("Sectors per cluster", sectors_per_cluster)
    print_info("Reserved sectors",reserved_sectors)
    print_info("Number of FATs", number_of_FATs)
    print_info("Maximum Root Directory Entries", max_roots)
    print_info("Total Sectors (0 for FAT32)", total_sec)
    print_info("Media Descriptor ID", descriptor_ID, "hex")
    print_info("Sectors per FAT (0 for FAT32)", sec_per_fat)
    print_info("Sectors per track", sectors_per_track)
    print_info("Number of heads", number_of_heads)
    print_info("Number of hidden sectors", number_of_hidden_sectors)
    print_info("Total sectors", total_sectors)
    print_info("Sectors per FAT", sectors_per_fat)
    active_fat_bitstring = "{:08b}".format(int(active_fat.hex(), base=16))
    print(f'Active FAT (value is a bitstring): 0x{active_fat.hex()} = {active_fat_bitstring}')
    print_info("Active FAT", active_fat)
    print_info("Filesystem version", filesystem_version)
    print_info("First cluster in root directory", first_cluster)
    print_info("Filesystem info sector", info_sector)
    print_info("Backup boot sector", backup_boot_sector)
    print_info("Reserved 0s (0 for FAT32)", reserved)
    print_info("Physical disk drive ID", physical_id)
    print_info("Reserved for NT (0 for FAT32)", reserved_for_NT)
    print_info("Extended boot signature", boot_signature, "hex")
    print_info("Volume serial number", volume_serial_number, "hex")
    print_info("Volume Label (ASCII)", volume_label, "ascii")
    print_info("Filesystem ID (ASCII)", filesystem_id, "ascii")

    print(f'\nBoot code SHA-256 hash value: {(hashlib.sha256(boot_code)).hexdigest()}')
    save_boot_code(boot_code, outfile)
    print(f'Saving boot code to: {outfile}')

def print_info(text,value,flag="both"):
    #This function allows setting a flag to determine output level. By default, it shows hex and decimal but using "hex" shows only hex. Using "ascii" decodes the bytes to ascii.
    #Note: I would have used match and case except they are only available in Python >=3.10; and I wanted as much compatibility as possible.
    if flag == "both":
        print(f'{text}: 0x{value.hex()} = {int.from_bytes(value, byteorder="little")}')
    elif flag == "ascii":
        print(f'{text}: "{value.decode("ascii")}"')
    elif flag == "hex":
        print(f'{text}: 0x{value.hex()}')

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 FAT32 VBR parser, version {version}')
    parser.add_argument("-i", "--image", help="image file path and name; assumes the first sector in the image is the VBR", required=True)
    parser.add_argument("-o", "--outfile", help="file path and name to store the boot code *only* (not the BPB values)", required=True)
    return parser.parse_args()

def save_boot_code(boot_code, outfile):
    # check that path exists
    outfile_path = os.path.dirname(outfile)
    if not os.path.isdir(outfile_path):
        print(f'Target folder ({outfile_path}) does not exist.')
        exit()
    with open(outfile, 'wb') as f:
        f.write(boot_code)
    return()

def main():
    arguments = parse_arguments()
    print(f'\nInfile: {arguments.image}')
    print(f'Outfile: {arguments.outfile}\n')
    image_file= open_image(arguments.image)
    retrieve_partition_info(image_file, arguments.outfile)
    image_file.close()

if __name__ == '__main__':
    main()
