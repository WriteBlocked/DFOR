""" DFOR 772
    Hiller Hoover """

""" Change Log:
    2/17/2026:
    """
version=1.0

import argparse
import sqlite3

def list_peeridhashes(infile):
    # connect to the db and create a cursor object for access
    conn_c = sqlite3.connect(infile)  # creates connection object
    c = conn_c.cursor()  # creates cursor object

    # build and execute query
    fields = "ckzone,octagonpeerid" # see Lab 5, file3.db queries and questions
    table = "ckdevicestate" # see Lab 5, file3.db queries and questions
    query = "SELECT " +fields+ " FROM " +table+ " WHERE ckzone='ApplePay'"
    for row in c.execute(query):
        print(f'{row[0]} - {row[1]}') # write output to console
    conn_c.close()

def list_tickers(infile): # see Class 5 slide 15
    # connect to the db and create a cursor object for access
    conn_c = sqlite3.connect(infile)  # creates connection object
    c = conn_c.cursor()  # creates cursor object

    # build and execute query
    fields = "COUNT(id)"  # see Lab 5, file3.db queries and questions
    table = "quotes"  # see Lab 5, file3.db queries and questions
    query = "SELECT COUNT(id) FROM quotes"# + fields + " FROM " + table
    for row in c.execute(query):
        print(f'{row[0]}')  # write output to console
    conn_c.close()

def parse_arguments():
    parser = argparse.ArgumentParser(description=f'DFOR 772 sqlite db field extractor, version {version}')
    parser.add_argument("-i", "--infile",
                        help="sqlite db file path and name",
                        required=True)
    parser.add_argument("-e", "--extract",
                        help="use p to dump peerid hashes from a keychain db file, use t to dump ticker symbols from a stocks app cache db file")
    return parser.parse_args()

def main():
    args = parse_arguments()
    if (args.extract == 'p'): # extract password hashes
        list_peeridhashes(args.infile)
    elif (args.extract == 't'): # extract password hashes
        list_tickers(args.infile)
    else:
        print(f'\nExtract option not supported or not provided\n')
        exit()

if __name__ == '__main__':
    main()
