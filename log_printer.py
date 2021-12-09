#!/usr/bin/python3
import os
import re
import pickle  # for storing some data
import gzip
import ipaddress as ip

# own modules
import log_patterns as lp
import cli

def print_log(log_file, paranoia_lvl):
    FILTER_MODSECURITY = re.compile(r".*ModSecurity:.*$")
    FILTER_PARANOIA = re.compile(r".*paranoia-level/" + str(paranoia_lvl) + ":.*$")
    # Open input file in 'read' mode and in raw byte encoding (issues wit "rt")
    with gzip.open(log_file, "rb") as in_file:
        # Loop over each log line
        for line in in_file:
            try:
                line = line.decode('utf-8')
                # If log line matches our regex, print to console, and output file
                if FILTER_MODSECURITY.search(line):
                    print(line)
            except UnicodeDecodeError:
                continue

def get_filepaths(directory):
    """
    This function will generate the file names in a directory
    tree by walking the tree either top-down or bottom-up. For each
    directory in the tree rooted at directory top (including top itself),
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            # Join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)  # Add it to the list.

    return file_paths  # Self-explanatory.

def main():
    print_log("input/apache/tellme_error.log.2.gz", 2)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
