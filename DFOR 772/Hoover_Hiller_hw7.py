""" DFOR 772
    Hiller Hoover """


# extract and parse eprocess blocks from a Windows memory image

''' Change Log:
    12/1/24: version 1.0
    3/4/25: version 1.1; added EPROCESS block detection method options
    EDIT as appropriate
'''

# module imports
import argparse
import re

# version; EDIT as appropriate
version = '1.1'

def extract_eprocess_fields():
    # track hits as EPROCESS blocks or not
    counter_yes = 0
    counter_no = 0
    # read the image file in as data (raw bytes)
    with open(args.image, 'rb') as image_file:
        image_data = image_file.read()
    matches = [] # initialize the hits list
    position = 0 # start at beginning
    pattern_bytes = bytes.fromhex(args.block) # set EPROCESS block header bytes
    pattern = re.compile(pattern_bytes) # create an re object
    while True:
        m = pattern.search(image_data[position:]) # m is a match object; search from current position to end, stopping at each hit
        if m is None: break # done if no more matches
        offset = position + m.start() # offset in bytes from the start of the image; current position plus the current match offset
        # parse executable name and pid based on known offsets
        executable_bytes = image_data[offset + int(args.executable):offset + int(args.executable) + 15] # the executable name; max 15 characters
        executable_stripped = executable_bytes.split(b'\x00')[0] # strip the trailing NULLs in executable name; it is padded with NULLs to 15 characters and truncated if longer than 15 characters
        pid_bytes = image_data[offset + int(args.pid):offset + int(args.pid) + 2] # the executable PID as little endian bytes
        pid = int.from_bytes(pid_bytes, byteorder='little') # pid as decimal
        # test if valid EPROCESS block; two methods (ascii and prefix)
        if args.method == 'ascii': # if executable name is ascii, then probably is a valid eprocess block
            if executable_stripped.isascii():
                counter_yes += 1
                print(f'Executable: {executable_stripped.decode("ascii")}, PID: {pid}')
            else:
                counter_no +=1
                print(f'Offset {offset} not an EPROCESS block')
        elif args.method == 'prefix': # if prefix bytes are before EPROCESS block header, then probably a valid eprocess block
            prefix_bytes = bytes.fromhex(args.prefix) # string to bytes
            if bytes(image_data[offset - 16:offset - 9]) == prefix_bytes:
                counter_yes += 1
                print(f'Executable: {executable_stripped.decode("ascii")}, PID: {pid}')
            else:
                counter_no += 1
                print(f'Offset {offset} not an EPROCESS block')
        position += m.end() # move to the end of the hit to continue searching
    # for a quick check against Volatility
    print(f'\nEPROCESS blocks: {counter_yes}')
    print(f'Non-EPROCESS blocks: {counter_no}')

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 eprocess block executable name and PID extractor, version {version}')
    parser.add_argument("-m", "--method",
                        help="method to test for valid EPROCESS block; use \"ascii\" (alone) or \"prefix\" (requires -f)",
                        required=True)
    parser.add_argument("-f", "--prefix",
                        help="prefix header bytes; required for METHOD prefix",
                        required=False)
    parser.add_argument("-i", "--image",
                        help="image file path and name",
                        required=True)
    parser.add_argument("-b", "--block",
                        help="block header bytes",
                        required=True)
    parser.add_argument("-e", "--executable",
                        help="offset from header start to executable name in bytes",
                        required=True)
    parser.add_argument("-p", "--pid",
                        help="offset from header start to PID in bytes",
                        required=True)
    return parser.parse_args()

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    extract_eprocess_fields()

if __name__ == '__main__':
    main()
