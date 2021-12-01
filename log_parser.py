import os
import re
import pickle  # for storing some data
import gzip

# Output file, where the matched loglines will be copied to
output_filename = os.path.normpath("output/exclusion_rules.conf")
# Regex used to match relevant loglines (in this case, a specific IP address)
FILTER_MODSECURITY = re.compile(r".*ModSecurity:.*$")
LINE_PATTERN_NGINX_ERROR = re.compile(
    r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg "
    r"\"(.+)\"] \[data.* \[uri \"(\S+)\"].*, client: (\S+), server: (\S+), request: \"(\S+) (\S+) .*$")
TRUNC_RULE_SET = re.compile(r"\S+\/rules\/(\S+)$")
HEALTHY_IPS = ['10.0.0.1', '80.238.210.166']
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

RULEID_DEFAULT = 10000
ADVISORY_RULES = ["911100", "920360", "920370", "920380", "920390", "920400", "920410", "920420", "920430", "920440", "920450", "920480", "949110", "949111", "959100", "980130"]

# load data from pers. layer
try:
    with open('data/learned.data', 'rb') as learned_data:
        # Call load method to deserialze
        learned = pickle.load(learned_data)
        excl_rule_id = learned['excl_rule_id']
        old_excl_rules_attributes = learned['excl_rules_attributes']
        print(excl_rule_id)
except FileNotFoundError:
    excl_rule_id = RULEID_DEFAULT
    old_excl_rules_attributes = {}
    # Overwrites the file, ensure we're starting out with a blank file
    with open(output_filename, "w") as out_file:
        out_file.write("")

excl_rules_attributes = {}

# Open input file in 'read' mode and in raw byte encoding (issues wit "rt")
with gzip.open("input/nginx/cloud.error.log-20211130.gz", "rb") as in_file:
    # Loop over each log line
    for line in in_file:
        try:
            line = line.decode('utf-8')
            # If log line matches our regex, print to console, and output file
            if FILTER_MODSECURITY.search(line):
                match = LINE_PATTERN_NGINX_ERROR.search(line)
                client_ips.add(match.group(ngx_fields['client']))
                if match.group(ngx_fields['client']) in HEALTHY_IPS:
                    key = (match.group(ngx_fields['server']),
                                               match.group(ngx_fields['uri']),
                                               match.group(ngx_fields['rule_id']),
                                               match.group(ngx_fields['rule_set']),
                                               match.group(ngx_fields['msg']),
                                               match.group(ngx_fields['client']))
                    if key in excl_rules_attributes:
                        excl_rules_attributes[key] += 1
                    else:
                        excl_rules_attributes[key] = 1
        except UnicodeDecodeError:
            continue

# Sort after number of requests
excl_rules_attributes_sorted = sorted(excl_rules_attributes.items(), key=lambda x: x[1])

# Open output file in 'append' mode
with open(output_filename, "a") as out_file:
    # 0 server, 1 uri, 2 rule_id, 3 rule_set, 4 msg
    for excl_rule_attributes, num in excl_rules_attributes_sorted:
        excl_rule_set = TRUNC_RULE_SET.search(excl_rule_attributes[3])
        if excl_rule_attributes[2] not in ADVISORY_RULES:
            if excl_rule_attributes not in old_excl_rules_attributes:
                comment = '# NOQ ' + str(num) + ' RULE_SET: ' + excl_rule_set.group(1) + ' MSG: '\
                          + excl_rule_attributes[4]
                # URI gets logged wrong some times, therefore replacing // with /
                rule = 'SecRule REQUEST_URI "@beginsWith ' + re.sub("//", "/", excl_rule_attributes[1])\
                       + '" "id:' + str(excl_rule_id) + ', phase:2, pass, nolog, ctl:ruleRemoveById=' +\
                       excl_rule_attributes[2] + '"'
                rule_tot = comment + '\n' + rule
                # print(rule_tot)
                rule_tot += '\n'

                out_file.write(rule_tot)
                excl_rule_id += 1

print('HEALTHY: ', len(excl_rules_attributes))

if set(HEALTHY_IPS).issubset(client_ips):
    print('no healthy ips found')

# dump data into pers. layer
with open('data/learned.data', 'wb') as data:
    excl_rules_attributes.update(old_excl_rules_attributes)
    mem_data = {
        'excl_rules_attributes': excl_rules_attributes,
        'excl_rule_id': excl_rule_id
     }
    pickle.dump(mem_data, data)

print(excl_rule_id)

