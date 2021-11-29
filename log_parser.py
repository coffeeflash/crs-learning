import os
import re
import pickle  # for storing some data

# Regex used to match relevant loglines (in this case, a specific IP address)
FILTER_MODSECURITY = re.compile(r".*ModSecurity.*$")
LINE_PATTERN_NGINX_ERROR = re.compile(
    r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg \"(.+)\"].*, server: (\S+), request: \"(\S+) (\S+) .*$")
LINE_PATTERN_temp = '(\S+) (\S+) [(\S+)] (\S+) ModSecurity: (\S+) [file "(\S+).conf(\S+) [id "(\S+)"(\S+) [msg "(\S+)"]' \
                    ' (\S+)[ver "(\S+)"](\S+)] [tag (\S+)] [host<_>, client: (\S+), server: (\S+), request: "(\S+) (\S+) '

# Output file, where the matched loglines will be copied to
output_filename = os.path.normpath("output/parsed_lines.log")
# Overwrites the file, ensure we're starting out with a blank file
# with open(output_filename, "w") as out_file:
# out_file.write("")

# Open output file in 'append' mode
with open(output_filename, "a") as out_file:
    # Open input file in 'read' mode
    with open("input/cloud.error.log", "r") as in_file:
        # Loop over each log line
        for line in in_file:
            # If log line matches our regex, print to console, and output file
            if FILTER_MODSECURITY.search(line):
                match = LINE_PATTERN_NGINX_ERROR.search(line)
                print(line)

                print(match.group(1))
                print(match.group(2))
                print(match.group(3))
                print(match.group(4))
                print(match.group(5))
                print(match.group(6))
                print(match.group(7))
                print(match.group(8))
                print(match.group(9))
                print(match.group(10))

                out_file.write(line)
