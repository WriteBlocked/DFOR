""" DFOR 772
    Hiller Hoover """

version = '1.0'

''' Change Log:

    '''

import argparse
import os
import hashlib

def open_image(image_path):
    if not os.path.isfile(image_path):
        print(f'Cannot find {image_path}; exiting program.')
        exit()
    image_file = open(image_path, 'rb')
    return image_file

def get_partition_offset(image_file):
    image_file.seek(454)
    partition_offset = int.from_bytes(image_file.read(4), byteorder='little')
    return partition_offset  # NOTE: this is a good place for a breakpoint so you can check that the values are correct

def get_vbr_data(image_file, partition_offset):
    bytes_per_sector = 512  # should always be this value for a classic MBR
    image_file.seek(partition_offset * bytes_per_sector)  # jump to start of VBR
    image_file.seek(11,1)  # relative seek, so jump forward 11 bytes from start of VBR to get to the sector size
    sector_size = int.from_bytes(image_file.read(2), byteorder='little')
    sectors_per_cluster = int.from_bytes(image_file.read(1), byteorder='little')
    image_file.seek(14,1)  # relative seek, so jump forward 14 bytes after reading sectors per cluster to get to hidden sectors
    hidden_sectors = int.from_bytes(image_file.read(4), byteorder='little')
    image_file.seek(16,1)  # relative seek, so jump forward 16 bytes after reading hidden sectors to get to the MFT location
    mft_sector = (int.from_bytes(image_file.read(8), byteorder='little') * sectors_per_cluster) + hidden_sectors
    return sector_size, sectors_per_cluster, hidden_sectors, mft_sector  # NOTE: this is a good place for a breakpoint so you can check that the values are correct

def get_file_data(image_file, sector_size, sectors_per_cluster, hidden_sectors, mft_sector, searchfile):
    image_file.seek(mft_sector * sector_size) #go to start of MFT
    # read an MFT record, check for filename, loop until find target filename or end of file is reached
    mft_record_offset = 0  # so we know the offset into the image_file of the MFT record we want to process
    while True:
        try:
            mft_record = image_file.read(
                1024)  # read in one complete MFT record
            mft_record_offset += 1024  # track where we are in the full image file
            if 'FILE'.encode() in mft_record:  # make sure it's an MFT record
                if searchfile.encode("utf-16-le") in mft_record:  # search for filename in unicode bytes
                    print(f'\nFile {searchfile} found in MFT')
                    mft_record_offset -= 1024  # back up so we'll be at the beginning of this record in the image file
                    break  # since found the record we want
        except EOFError:
            print(
                f'File {searchfile} not found.')  # exit if we get to end of file without finding filename in an MFT record
            exit()
    image_file.seek((mft_sector * sector_size) + mft_record_offset) # extract values needed from the searchfile's mft_record
    image_file.seek(240,1)
    filename_length = int.from_bytes(image_file.read(1), byteorder='little')
    image_file.seek(1 + filename_length, 1)  # +1 is for the filetype byte
    while int.from_bytes(image_file.read(1), byteorder='little') != int('0x80', 16):
        continue  # keep reading until we read a 0x80

    #read file size on disk and actual file size.
    image_file.seek(39, 1)  # 39 b/c 40 less the one (0x80) we just read
    file_disk_size = int.from_bytes(image_file.read(8), byteorder='little')
    file_actual_size = int.from_bytes(image_file.read(8), byteorder='little')

    # read sizes of cluster run offset and cluster run length; byte to nibbles to integers
    image_file.seek(8, 1)  # move forward 8 bytes
    b = bytes(image_file.read(1))  # read the one byte
    b1 = b.hex()[0]  # high nibble as string
    b2 = b.hex()[1]  # low nibble as string
    cluster_run_offset_size = int(b1, base=16)  # convert to int
    cluster_run_length_size = int(b2, base=16)  # convert to int
    # read cluster run length and cluster run offset
    cluster_run_length = int.from_bytes(image_file.read(cluster_run_length_size), byteorder='little')  # not needed
    cluster_run_offset = int.from_bytes(image_file.read(cluster_run_offset_size), byteorder='little')
    # compute file start in bytes
    file_start = (cluster_run_offset * sectors_per_cluster * sector_size) + (hidden_sectors * sector_size)
    return file_start, file_actual_size, file_disk_size

def extract_slack(image_file, file_start, file_actual_size, file_disk_size, outfile):
    image_file.seek(file_start + file_actual_size)  # go to end of file;
    slack_data = image_file.read(file_disk_size - file_actual_size)# read from end of file to end of cluster;
    slack_data_size = int((file_disk_size - file_actual_size)/1024)
    print(f'\nSlack data size: {slack_data_size} Kb')
    print(f'Slack data SHA-256 hash value: {(hashlib.sha256(slack_data)).hexdigest()}')
    # check that path exists (file does not have to exist, but we will overwrite it if it does)
    outfile_path = os.path.dirname(outfile)
    if not os.path.isdir(outfile_path):
        print(f'Target folder ({outfile_path}) does not exist.')
        exit()
    # open the outfile and write the boot code bytes to it
    with open(outfile, 'wb') as f:
        f.write(slack_data)
    print(f'Writing slack data to {outfile}')
    return

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 NTFS slack extractor, version {version}')
    parser.add_argument("-i", "--image", help="image file path and name; assumes the first sector in the image is the MBR", required=True)
    parser.add_argument("-f", "--searchfile", help="filename to search for; case sensitive; expecting ASCII (not unicode)", required=True)
    parser.add_argument("-o", "--outfile", help="file path and name to store the slack data", required=True)
    return parser.parse_args()

def main():
    args = parse_arguments()
    image_file = open_image(args.image)
    partition_offset = get_partition_offset(image_file)
    sector_size, sectors_per_cluster, hidden_sectors, mft_sector = get_vbr_data(image_file, partition_offset)
    file_start, file_actual_size, file_disk_size = get_file_data(image_file, sector_size, sectors_per_cluster, hidden_sectors, mft_sector, args.searchfile)
    extract_slack(image_file, file_start, file_actual_size, file_disk_size, args.outfile)
    pass

if __name__ == '__main__':
    main()