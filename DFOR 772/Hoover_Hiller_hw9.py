''' DFOR 772
    EDIT (your name) '''

# search for encoded versions of a search string: base64, unicode UTF-16 little endian (2 byte ASCII), IP address in hex, big endian

''' Change Log:
    12/30/24: version 1.0
    3/25/25: version 1.1; adapted for homework exercise
    EDIT as appropriate
'''

# module imports
import argparse
import re
import base64

# version; EDIT as appropriate
version = '1.1'

def search_image(search, search_converted):
    # open the image file but don't read into a variable; this way we can process arbitrarily large image files sequentially
    image_file = open(args.image, 'rb')
    # compile a search pattern
    search_pattern_compiled = re.compile(re.escape(search_converted)) # note about re.escape here...
    position = 0  # start at beginning
    counter = 0 # count the hits
    # search the image sequentially and process hits as we find them
    while True:
        image_file.seek(position,0)
        m = search_pattern_compiled.search(image_file.read()) # m is a match object; search from current position to end, stopping at each hit to process
        if m is None: break # done if no more matches
        print(f'Found search term "{search}" after conversion to bytes {search_converted} (hex: {search_converted.hex()}) at offset {position + m.start()} bytes.')
        position += m.end() # move to the end of the hit to continue searching
        counter +=1
    image_file.close() # close the image file
    print(f'\nFound {counter} hits of {search} converted to {search_converted}.')

def convert_base64(search):
    search_converted = base64.b64encode(search.encode('utf-8'))
    print(f'Converted (to base64): {search_converted}')
    return search_converted

def convert_utf16(search):
    search_converted = search.encode('utf-16')[2:] # we ignore the first two bytes - they are added to indicate UTF-16 encoding
    print(f'Converted (to utf-16): {search_converted} (hex: {search_converted.hex()})')
    return search_converted

def convert_ipaddress(search):
    search_converted = (int((search.split('.')[0]))).to_bytes()+(int((search.split('.')[1]))).to_bytes()+(int((search.split('.')[2]))).to_bytes()+(int((search.split('.')[3]))).to_bytes()
    print(f'Converted (to ipaddress in hex): {search_converted} (hex: {search_converted.hex()})')
    return search_converted

def convert_little_endian(search):
    # next two lines compute number of bytes needed to store the integer so we search for the *minimum* bytes (e.g., the non-NULL bytes of the search integer converted to little endian)
    num_bits = int(search).bit_length()
    num_bytes = (num_bits // 8) + (1 if num_bits % 8 != 0 else 0)
    search_converted = int(search).to_bytes(num_bytes, 'little')
    print(f'Converted (to little endian): {search_converted} (hex: {search_converted.hex()})')
    return search_converted

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 encoded data searcher, version {version}')
    parser.add_argument("-i", "--image",
                        help="image file path and name",
                        required=True)
    parser.add_argument("-s", "--search",
                        help="search term",
                        required=True)
    parser.add_argument("-e", "--encoding",
                        help="encoding (b=base64, u=utf-16, i=ip address, l=(el)little endian)",
                        required=True)
    return parser.parse_args()

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    print(f'Search term: {args.search}')
    match args.encoding:
        case 'b':
            search_converted = convert_base64(args.search)
        case 'u':
            search_converted = convert_utf16(args.search)
        case 'i':
            search_converted = convert_ipaddress(args.search)
        case 'l':
            search_converted = convert_little_endian(args.search)
        case _:
            print(f'Invalid encoding argument; exiting.')
            exit()
    search_image(args.search, search_converted)

if __name__ == '__main__':
    main()