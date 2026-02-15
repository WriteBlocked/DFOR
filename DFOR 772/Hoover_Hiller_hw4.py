""" DFOR 772
    Hiller Hoover """

# EXT4 dump inodes
version = '0.1'

""" Change Log:
    2/14/2026:     
    """

import argparse
import os
import hashlib

def open_image(image_path):
    # check that file exists; exit if not
    if not os.path.isfile(image_path):
        print(f'Cannot find {image_path}; exiting program.')
        exit()
    # open the file
    image_file = open(image_path, 'rb')
    # return the file handle
    return image_file

def get_partition_offset(image_file):
    image_file.seek(EDIT)  # two sectors (0 and 1) + 32 bytes into sector 2; see class 4 slides 14-15
    partition_offset_sectors = int.from_bytes(image_file.read(EDIT), byteorder='little') # how many bytes are in the first LBA value?
    return partition_offset_sectors # in sectors

def get_inode_offset(image_file,partition_offset,block_size,sector_size):
    inode_table_offset_hi = (partition_offset * sector_size) + block_size + EDIT # see class 4 slide 16; (comment continued next lines)
    # the value "(partition_offset * sector_size) + block_size" gets us to the start of sector 2056 in this image;
    # how many bytes more until we get to the inode table UPPER 32 bits? (typo in the slide 16 image fixed in latest posted slides)
    image_file.seek(inode_table_offset_hi)
    inode_table_offset_hi_bytes = image_file.read(EDIT) # how many bytes in the inode table upper bits?
    inode_table_offset_lo = (partition_offset * sector_size) + block_size + EDIT # see class 4 slide 16; (comment continued next lines)
    # the value "(partition_offset * sector_size) + block_size" gets us to the start of sector 2056 in this image;
    # how many bytes more until we get to the inode table LOWER 32 bits? (typo in the slide 16 image fixed in latest posted slides)
    image_file.seek(inode_table_offset_lo)
    inode_table_offset_lo_bytes = image_file.read(EDIT) # how many bytes in the inode table lower bits?
    inode_table_offset_blocks = int.from_bytes(inode_table_offset_lo_bytes + inode_table_offset_hi_bytes, byteorder='little') #intuitively, this should be hi + lo, but that doesn't work
    inode_table_offset_sectors = partition_offset + (inode_table_offset_blocks * int(block_size / sector_size))
    return inode_table_offset_sectors # in sectors

def dump_inodes(image_file,inode_offset_sectors,inode_num,sector_size):
    if(inode_num == 0): # if the user wants to dump *all* inodes
        while(True):
            inode_num +=1
            specific_inode_location = ((inode_offset_sectors * sector_size) + ((inode_num - 1) * EDIT)) # the value here should be the size of an inode in bytes
            image_file.seek(specific_inode_location)
            inode = image_file.read(EDIT) # same as above, the value here should be the size of an inode in bytes
            if(all(byte == 0 for byte in inode)): # if the inode data is all zeros, we're at the end of the active inode list
                break
            else:
                print(f'\nContents of inode {inode_num} are:\n{inode.hex('\n',16)}\n') # for nice formatting
                print(f'Contents of inode {inode_num} SHA-256 hash value: {(hashlib.sha256(inode)).hexdigest()}')
    else:
        specific_inode_location = ((inode_offset_sectors * sector_size) + ((inode_num - 1) * EDIT)) # same as above, the value here should be the size of an inode in bytes
        image_file.seek(specific_inode_location)
        inode = image_file.read(EDIT) # same as above, the value here should be the size of an inode in bytes, (continued next line)
        # which begs the question: why not set the inode size once as a variable? good idea, just be sure to do it *outside* of the if loop
        print(f'Contents of inode {inode_num} are:\n{inode.hex('\n',16)}\n')
        print(f'Contents of inode {inode_num} SHA-256 hash value: {(hashlib.sha256(inode)).hexdigest()}')
    return

# TBD: parse inode data to find data locations and collect sector slack

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 EXT4 inode extractor, version {version}')
    parser.add_argument("-i", "--image",
                        help="image file path and name; assumes the first sector in the image is the MBR/GPT",
                        required=True)
    parser.add_argument("-n", "--inode", help="the ID number of the inode to extract; use 0 to extract all inodes", required=True)
    parser.add_argument("-b", "--blocksize", help="EXT4 blocksize in bytes", required=True)
    parser.add_argument("-s", "--sectorsize", help="media sectorsize in bytes", required=True)
    return parser.parse_args()

def main():
    args = parse_arguments()
    image_file = open_image(args.image)
    partition_offset_sectors = get_partition_offset(image_file)
    inode_offset_sectors = get_inode_offset(image_file, partition_offset_sectors, int(args.blocksize), int(args.sectorsize))
    dump_inodes(image_file,inode_offset_sectors,int(args.inode),int(args.sectorsize))
    image_file.close()

if __name__ == '__main__':
    main()
