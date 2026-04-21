''' DFOR 772
    Hiller Hoover '''

# extract and check ICMP packet payload bytes from pcap file

''' Change Log:
    5/2/2016: version 1.0
    4/15/2025: version 2.0: reworked logic
    4/20/2026: updated EDITs
'''

import hashlib
import argparse

# version; EDIT as appropriate
version = '2.0'


def extractData(infile, outfile):
    '''
    Extracts data from a pcap file.
    Writes extracted data bytes to outfile.
    Infile must be pcap.
    Outfile will be raw bytes.
    Code assumes packets of interest have the following properties:
        (Note: offsets are from the start of the pcap packet record, not the actual packet data)
        offset 8: XX XX (full packet size in bytes)
        offset 16: XX ... (start of actual packet data)
    '''
    with open(outfile, 'wb') as fo:
        with open(infile, "rb") as fi:
            fi.seek(24, 0)  # skip the global pcap file header; this is a seek from the start of the file; see class slides for global header size
            byte = fi.read(1)  # we'll use this to make sure we're not at the end of the file
            counter = 1
            while byte:  # evaluates to False if EOF
                fi.seek(7, 1)  # skip to packet size field; offset 8 (7 + 1 we already read); these are relative seeks
                packetSize = int.from_bytes(fi.read(4), byteorder='little')  # reading 4...
                fi.seek(4, 1)  # skip to start of actual packet, offset 16; these are relative seeks
                packetContents = fi.read(packetSize)  # read the packet contents
                # Console output
                print('Packet # ' + str(counter) + ' at offset ' + str(fi.tell()) + ' size ' + str(packetSize))
                counter += 1
                # we only care about ICMP packets for this code
                data = ifIcmpPacket(packetContents)
                if (data):
                    fo.write(data)
                byte = fi.read(1)  # as above, make sure we're not at the end of the file

def ifTcpPacket(contents): # just keeping this for future use
    '''
    Checks fields to identify tcp data packets
    Returns data contents if so, None if not
    '''
    # offsets (contents indices) are based on the actual packet, not the pcap file record
    if contents[23:24] == b'\x06':  # TCP packet
        ipLength = int.from_bytes(contents[16:18], byteorder='little')
        dataLength = ipLength - 40  # ip header is 20 bytes, tcp header is 20 bytes
        data = contents[54:54 + dataLength]
        return data
    else:  # not a packet we're interested in
        return None

def ifIcmpPacket(contents):
    '''
    Checks fields to identify icmp data packets
    Returns data contents if not default, None if not
    '''
    # offsets (contents indices) are based on the actual packet, not the pcap file record
    if contents[23:24] == b'\x01':  # ICMP packet
        ipLength = int.from_bytes(contents[16:18], byteorder='little')
        dataLength = ipLength - 28  # ip header is 20 bytes, icmp header is 8 bytes
        data = contents[42:42 + dataLength]
        if (hashlib.md5(data).hexdigest()).upper() != 'B97D6CFCE32659677B4B801CAA1754B8': # this is the md5 hash of "abcdefghijkl...ghi"; open pcap file in HxD, highlight ICMP normal payload bytes (e.g., see packets 44+ in wireshark), and compute MD5 checksum; should start with B97D; put that checksum here in ALLCAPS
            return data
        else:  # default contents so don't return any data
            return None
    else:  # not a packet we're interested in
        return None

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 ICMP packet payload extractor and checker, version {version}')
    parser.add_argument("-i", "--infile",
                        help="infile path and name (should be a pcap file)",
                        required=True)
    parser.add_argument("-o", "--outfile",
                        help="outfile path and name (will be overwritten if it exists)",
                        required=True)
    return parser.parse_args()

def main():
    global args # makes args accessible in all functions without passing; don't overuse global, but sometimes useful
    args = parse_arguments()
    extractData(args.infile, args.outfile)

if __name__ == '__main__':
    main()
