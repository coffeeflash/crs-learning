import os
import re
import pickle  # for storing some data
import gzip

# Regex used to match relevant loglines (in this case, a specific IP address)
FILTER_MODSECURITY = re.compile(r".*ModSecurity:.*$")
LINE_PATTERN_NGINX_ERROR = re.compile(
    r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg "
    r"\"(.+)\"] \[data.* \[uri \"(\S+)\"].*, client: (\S+), server: (\S+), request: \"(\S+) (\S+) .*$")
TRUNC_RULE_SET = re.compile(r"\S+\/rules\/(\S+)$")
HEALTHY_IPS = ('10.0.0.1', '80.238.210.166')
ngx_fields = {
        "date": 1,
        "time": 2,
        "level": 3,
        "summary": 4,
        "rule_set": 5,
        "rule_id": 6,
        "msg": 7,
        "uri": 8,
        "client": 9,
        "server": 10,
        "method": 11,
        "request": 12
    }

client_ips = set()
excl_rules_attributes = set()
excl_rule_id = 10000

# Open input file in 'read' mode and in raw byte encoding (issues wit "rt")
with gzip.open("input/nginx/cloud.error.log-20211129.gz", "rb") as in_file:
    # Loop over each log line
    for line in in_file:
        try:
            line = line.decode('utf-8')
            # If log line matches our regex, print to console, and output file
            if FILTER_MODSECURITY.search(line):
                match = LINE_PATTERN_NGINX_ERROR.search(line)
                client_ips.add(match.group(ngx_fields['client']))
                if match.group(ngx_fields['client']) in HEALTHY_IPS:
                    # Include parameters to the exclusion rules:
                    if match.group(ngx_fields['request']) != match.group(ngx_fields['uri']):
                        param = "abc"

                    excl_rules_attributes.add((match.group(ngx_fields['server']),
                                               match.group(ngx_fields['uri']),
                                               match.group(ngx_fields['rule_id']),
                                               match.group(ngx_fields['rule_set']),
                                               match.group(ngx_fields['msg']),
                                               param))
        except UnicodeDecodeError:
            print('skipped')
            continue

# out_file.write(line)

# 0 server, 1 uri, 2 rule_id, 3 rule_set, 4 msg
for excl_rule_attributes in excl_rules_attributes:
    excl_rule_set = TRUNC_RULE_SET.search(excl_rule_attributes[3])
    if excl_rule_set.group(1) != 'REQUEST-949-BLOCKING-EVALUATION':
        comment = '# RULE_SET: ' + excl_rule_set.group(1) + ' MSG: ' + excl_rule_attributes[4]
        rule = 'SecRule REQUEST_URI "@beginsWith ' + match.group(ngx_fields['uri'])\
               + '" "id:' + str(excl_rule_id) + ', phase:2, pass, nolog, ctl:ruleRemoveById=' +\
               excl_rule_attributes[2] + '"'
        print(comment, '\n', rule)
        excl_rule_id += 1

print(excl_rules_attributes)
print('HEALTHY: ', len(excl_rules_attributes))

if set(HEALTHY_IPS).issubset(client_ips):
    print('no healthy ips found')

# pot_ecl_rule = 'SecRule REQUEST_URI "@beginsWith ' + match.group(ngx_fields['request']) \
#                + '" "id:' + str(excl_rule_id) + ', phase:1, pass, nolog, ctl:ruleRemoveById=930130"'
# if pot_ecl_rule not in exclusion_rules:
#     exclusion_rules.add(pot_ecl_rule)
#     excl_rule_id += 1

# # Output file, where the matched loglines will be copied to
# output_filename = os.path.normpath("output/parsed_lines.log")
# # Overwrites the file, ensure we're starting out with a blank file
# with open(output_filename, "w") as out_file:
#     out_file.write("")
# # Open output file in 'append' mode
# with open(output_filename, "a") as out_file:

