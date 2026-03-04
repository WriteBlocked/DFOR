""" DFOR 772
    Hiller Hoover """

# extract slack from an image, save as mp3 files, and play extracted files

''' Change Log:
    12/1/24: version 1.0
    2/26/25: version 1.1; fixed offset bug; fixed recursion
    '''

# module imports
import argparse
import pytsk3
import os
import shutil
import time
from playsound3 import playsound

version = '1.1'

def process_directory(directory,path,fs_info):
    cluster_size = int(args.cluster)
    output_dir = args.outdir
    for entry in directory:
        if entry.info.name.name.decode("ascii") not in [".", ".."]:
            # Process the entry
            # If it's a directory, call the function recursively
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                # path is tricky; we have to build and track it ourselves because it's not an attribute of the file object, so...
                # we keep passing the path we have, and it gets appended to at each call
                new_dir = fs_info.open_dir(path + entry.info.name.name.decode("ascii"))
                process_directory(new_dir,path + new_dir.info.fs_file.name.name.decode("ascii") + '/',fs_info)
            # If it's a file, open and process
            elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                fs_file = fs_info.open(path + entry.info.name.name.decode("ascii"))
                file_size = fs_file.info.meta.size
                if (file_size % cluster_size) == 0: # modulo operation; if 0, then the file size is a multiple of the cluster size and there is no slack
                    slack_size = 0
                else:
                    allocated_size = ((file_size // cluster_size) + 1) * cluster_size # this rounds up the file size to the next cluster boundary
                    slack_size = (allocated_size - file_size) # EDIT: given allocated_size (size on disk) and file_size (actual bytes of the file), what should this formula be?
                if slack_size > 0:
                    slack_data = fs_file.read_random(file_size, slack_size, 1,0,1) # TSK_FS_ATTR_TYPE_DEFAULT,0,TSK_FS_FILE_READ_FLAG_SLACK <--- this last parameter is key; allows reading past EOF
                    if all(x == 0x00 for x in slack_data): # don't output if slack data is all 0x00
                        continue
                    else:
                        file_name = fs_file.info.name.name.decode("ascii")
                        output_dir_full = output_dir + path
                        output_path = os.path.join(output_dir_full, f"{file_name}_slack.mp3")
                        isExist = os.path.exists(output_dir_full)
                        if not isExist: # check if the output path exists and create it if not
                            os.makedirs(output_dir_full)
                        with open(output_path, 'wb') as outfile:
                            outfile.write(slack_data)
                            print(f"Extracted {slack_size} bytes of slack from {file_name} to {output_path}")

def play_mp3():
    outdir = args.outdir # where our extracted possible MP3 fragment files are located
    # create SAVE_ folder
    epoch_time_int = int(time.time()) # using current time to name the SAVE_ folder
    save_folder = 'SAVE_' +  str(epoch_time_int) # this will make the SAVE_ folder a peer of the output folder
    os.makedirs(save_folder) # we're assuming this folder does not exist
    # for all files in outdir (assumes we want to try and play all the files), loop: play, save?, continue
    for root, dirs, files in os.walk(outdir):
        for file in files:
            file_path = os.path.join(root, file)
            print(f'\nPlaying: {str(file_path)}')
            playsound(str(file_path), block=False)
            save = input(f'Do you want to copy this file to the {save_folder} folder? (y/n) ')
            if save == 'y':
                shutil.copy(str(file_path),save_folder)
    return

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 MP3 fragment extractor and player, version {version}')
    parser.add_argument("-i", "--infile",
                        help="image file path and name",
                        required=True)
    parser.add_argument("-o", "--outdir",
                        help="output directory path",
                        required=True)
    parser.add_argument("-c", "--cluster",
                        help="cluster size in bytes",
                        required=True)
    parser.add_argument("-x", "--offset",
                        help="offset to partition in image in bytes",
                        required=True)
    return parser.parse_args()

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    img_info = pytsk3.Img_Info(args.infile)
    fs_info = pytsk3.FS_Info(img_info, offset=int(args.offset)) # Parse the MBR/VBR by hand or use FTK Imager to find the offset of the partition; check against the questions on Canvas
    root_dir = fs_info.open_dir('/',2) # cluster 2 is location of root directory; this is default, but including for clarity
    process_directory(root_dir,'/',fs_info) # root_dir is a directory object; also need to pass the path as a string for recursive calls later
    play_mp3()

if __name__ == '__main__':
    main()
