''' DFOR 772
    Hiller Hoover '''

# find bytes after JPG trailer

''' Change Log:
    5/15/2015: version 1.0
    1/15/2025: version 2.0
    4/10/2025: version 2.1: simplified search logic
    
    Hiller edits:
    4/13/2025: filled in EDITs
'''

import re
import argparse
import urllib.request

# version; EDIT as appropriate
version = '2.1'

def getFile():
    data = urllib.request.urlopen(args.file).read()
    # the structure of the code to get a file from a URL is: urllib.request.urlopen(full url with filename).read()
    return data

def checkJpg(data_header):
    jpgHeader = b'\xff\xD8'
    if data_header == jpgHeader:
        return True
    else:
        return False

def checkTrailer(data):
    # do a quick check
    jpgTrailer = b'\xff\xd9' # jpg trailer bytes (2 bytes) as hex characters with hex prefix
    if data[-2:] == jpgTrailer: # using the negative indexing trick to read the last 2 bytes of data
        print(f'\n{args.file} is a JPG file but does not have data after the trailer.\n')
    else: # last two bytes are not the JPG trailer bytes, so we need to find the trailer and read what comes after
        jpgTrailer_compiled = re.compile(jpgTrailer)
        m = jpgTrailer_compiled.search(data)
        trailer_bytes = data[data.rfind(jpgTrailer)+2:].decode('utf-8')
        trailer_bytes2 = data[data.rfind(jpgTrailer) + 2:].hex()
        # using rfind to search from end of bytes for last occurence of jpgTrailer
        # decoding to UTF-8 and raw hex. In future versions, might want to output with different encodings.

        print(f'\n{args.file} is a JPG file and has bytes after the trailer.\n')
        print(f'Unicode Bytes: {trailer_bytes}')
        print(f'Raw Bytes: {trailer_bytes2}\n')
    return

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 JPG trailer bytes checker, version {version}')
    parser.add_argument("-f", "--file",
                        help="file location (URL and filename)",
                        required=True)
    return parser.parse_args()

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    data = getFile()
    jpg = checkJpg(data[:2]) # just pass the first two bytes of the array "data"
    if jpg:
        checkTrailer(data)
    else:
        print(f'\n{args.file} is not a JPG file.\n')

if __name__ == '__main__':
    main()
