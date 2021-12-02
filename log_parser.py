import os
import re
import pickle  # for storing some data
import gzip


def reset_conf_file(output_filename=os.path.normpath("output/exclusion_rules.conf")):
    # Overwrites the file, ensure we're starting out with a blank file
    with open(output_filename, "w") as out_file:
        out_file.write("")


def print_dict(dictionary):
    for key in dictionary:
        print(key)


def get_line_pattern(webserver='ngx'):
    line_fields_ngx = {
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
    line_pattern_ngx = re.compile(
        r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg "
        r"\"(.+)\"] \[data.* \[uri \"(\S+)\"].*, client: (\S+), server: (\S+), request: \"(\S+) (\S+) .*$")
    if webserver == 'ngx':
        return (line_pattern_ngx, line_fields_ngx)
    else:# apache
        return ()


def extract_rules_from_log(log_file, line_pattern_fields, append_rules=False):
    line_pattern = line_pattern_fields[0]
    line_fields = line_pattern_fields[1]
    output_filename = os.path.normpath("output/exclusion_rules.conf")
    FILTER_MODSECURITY = re.compile(r".*ModSecurity:.*$")
    TRUNC_RULE_SET = re.compile(r"\S+\/rules\/(\S+)$")
    HEALTHY_IPS = ['10.0.0.1', '80.238.210.166']
    client_ips = set()
    RULEID_DEFAULT = 10000
    ADVISORY_RULES = ["911100", "920360", "920370", "920380", "920390", "920400", "920410", "920420", "920430", "920440", "920450", "920480", "949110", "949111", "959100", "980130"]
    excl_rules_attributes = {}

    # load data from pers. layer
    try:
        with open('data/learned.data', 'rb') as learned_data:
            # Call load method to deserialize
            learned = pickle.load(learned_data)
            excl_rule_id = learned['excl_rule_id']
            old_excl_rules_attributes = learned['excl_rules_attributes']
            print(excl_rule_id)
            if not append_rules:
                print(".conf overwritten ...")
                reset_conf_file()
                excl_rule_id = RULEID_DEFAULT
                excl_rules_attributes = old_excl_rules_attributes
                old_excl_rules_attributes = {}

    except FileNotFoundError:
        excl_rule_id = RULEID_DEFAULT
        old_excl_rules_attributes = {}
        reset_conf_file()


    # Open input file in 'read' mode and in raw byte encoding (issues wit "rt")
    with gzip.open(log_file, "rb") as in_file:
        # Loop over each log line
        for line in in_file:
            try:
                line = line.decode('utf-8')
                # If log line matches our regex, print to console, and output file
                if FILTER_MODSECURITY.search(line):
                    match = line_pattern.search(line)
                    client_ips.add(match.group(line_fields['client']))
                    if match.group(line_fields['client']) in HEALTHY_IPS:
                        key = (match.group(line_fields['server']),
                                                   match.group(line_fields['uri']),
                                                   match.group(line_fields['rule_id']),
                                                   match.group(line_fields['rule_set']),
                                                   match.group(line_fields['msg']))
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
        if append_rules and old_excl_rules_attributes:
            out_file.write('############### Appending the rules ##############\n')
        # 0 server, 1 uri, 2 rule_id, 3 rule_set, 4 msg
        for excl_rule_attributes, num in excl_rules_attributes_sorted:
            if excl_rule_attributes[2] not in ADVISORY_RULES and excl_rule_attributes not in old_excl_rules_attributes:
                excl_rule_set = TRUNC_RULE_SET.search(excl_rule_attributes[3])
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
        mem_data = {
            'excl_rules_attributes': excl_rules_attributes,
            'excl_rule_id': excl_rule_id
         }
        pickle.dump(mem_data, data)


def main():
    append_rules = False
    log_file = 'input/nginx/cloud.error.log-20211129.gz'
    reset = False

    # reset learned.data
    if reset:
        os.remove('data/learned.data')

    extract_rules_from_log(log_file, get_line_pattern('ngx'), append_rules)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
