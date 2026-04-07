''' DFOR 772
    Hiller Hoover '''

# file extractor. Takes file name/path, offset, size, and outfile as inputs.

''' Change Log:
    4/6/2026: Created and finished version 1
'''

# module imports
import os
import argparse

# version; EDIT as appropriate
version = '1'

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 firmware data searcher, version {version}')
    parser.add_argument("-i", "--image",
                        help="bin file path and name.",
                        required=True)
    parser.add_argument("-o", "--offset",
                        help="byte offset to start extraction.",
                        required=True)
    parser.add_argument("-n", "--number",
                        help="number of bytes to extract.",
                        required=True)
    parser.add_argument("-w", "--write",
                        help="filename to write bytes to.",
                        required=True)
    return parser.parse_args()

def extract_bytes():
    image_file = open(args.image, 'rb')
    image_file.seek(int(args.offset), 0)
    data = image_file.read(int(args.number))
    with open(args.write, 'wb') as out_file:
        out_file.write(data)
    image_file.close()
    # optional
    print(f'Wrote {args.number} bytes starting at offset {args.offset} to file {args.write}.')

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    print(f'Image file: {args.image}')
    extract_bytes()

if __name__ == '__main__':
    main()