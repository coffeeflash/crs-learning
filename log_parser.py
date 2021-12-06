#!/usr/bin/python3
import os
import re
import pickle  # for storing some data
import gzip

# own modules
import log_patterns as lp
import cli


def reset_conf_file(output_filename=os.path.normpath("output/exclusion_rules.conf")):
    # Overwrites the file, ensure we're starting out with a blank file
    with open(output_filename, "w") as out_file:
        out_file.write("")


def print_dict(dictionary):
    for key in dictionary:
        print(key)


def prepare_uri(uri, max_location_depth):
    uri = re.sub("//", "/", uri)
    split_uri = uri.split('/')
    if len(split_uri) <= max_location_depth+1:
        # print('nothung to do', uri)
        return uri
    else:
        uri = ""
        for part in split_uri[1:max_location_depth+1]:
            uri += '/' + part
        return uri


def extract_rules_from_log(log_file, line_pattern_fields, max_location_depth, append_rules):
    line_pattern = line_pattern_fields[0]
    line_fields = line_pattern_fields[1]
    output_filename = os.path.normpath("output/exclusion_rules.conf")
    FILTER_MODSECURITY = re.compile(r".*ModSecurity:.*$")
    TRUNC_RULE_SET = re.compile(r"\S+\/rules\/(\S+)$")
    HEALTHY_IPS = ['10.0.0.1', '10.1.1.1', '10.1.2.1', '10.1.3.1', '192.168.1.1',  # default considered healthy
                   '80.238.210.166', '80.238.210.166', '84.75.158.225']  # special ip's to be asked in the cli...

    
    client_ips = set()
    RULEID_DEFAULT = 10000
    ADVISORY_RULES = ["911100", "920360", "920370", "920380", "920390", "920400", "920410", "920420", "920430",
                      "920440", "920450", "920480", "949110", "949111", "959100", "980130"]
    excl_rules_attributes = {}
    not_matched_log_lines = []

    # load data from pers. layer
    try:
        with open('data/learned.data', 'rb') as learned_data:
            # Call load method to deserialize
            learned = pickle.load(learned_data)
            excl_rule_id = learned['excl_rule_id']
            old_excl_rules_attributes = learned['excl_rules_attributes']
            cli.pretty_print('Already learned rules up to id: ' + str(excl_rule_id), "INFO")
            if not append_rules:
                reset_conf_file()
                excl_rule_id = RULEID_DEFAULT
                excl_rules_attributes = old_excl_rules_attributes
                old_excl_rules_attributes = {}

    except FileNotFoundError:
        excl_rule_id = RULEID_DEFAULT
        old_excl_rules_attributes = {}
        reset_conf_file()

    excl_rule_id_start = excl_rule_id
    # Open input file in 'read' mode and in raw byte encoding (issues wit "rt")
    with gzip.open(log_file, "rb") as in_file:
        # Loop over each log line
        for line in in_file:
            try:
                line = line.decode('utf-8')
                # If log line matches our regex, print to console, and output file
                if FILTER_MODSECURITY.search(line):
                    match = line_pattern.search(line)
                    if not match:
                        # print('############## NO MATCH ##############: ', line)
                        not_matched_log_lines.append(line)
                        continue
                    client_ips.add(match.group(line_fields['client']))
                    if match.group(line_fields['client']) in HEALTHY_IPS:
                        key = (match.group(line_fields['server']),
                                                   prepare_uri(match.group(line_fields['uri']), max_location_depth),
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
                rule = 'SecRule REQUEST_URI "@beginsWith ' + excl_rule_attributes[1]\
                    + '" "id:' + str(excl_rule_id) + ', phase:2, pass, nolog, ctl:ruleRemoveById=' +\
                    excl_rule_attributes[2] + '"'
                rule_tot = comment + '\n' + rule
                # print(rule_tot)
                rule_tot += '\n'
                out_file.write(rule_tot)
                excl_rule_id += 1
    cli.pretty_print('Following log lines could not be matched by the regex:', "WARNING")
    for not_matched_log_line in not_matched_log_lines:
        cli.pretty_print(not_matched_log_line[:-1], "WARNING")
    cli.pretty_print('Extracted ' + str(excl_rule_id - excl_rule_id_start) + ' healthy rules from ' + log_file, "INFO")

    if excl_rule_id - excl_rule_id_start == 0:
        with open(output_filename, "a") as out_file:
            text ="nothing new to learn from file: " + log_file + "\n"
            out_file.write(text)
            cli.pretty_print(text, "INFO")


    # dump data into pers. layer
    with open('data/learned.data', 'wb') as data:
        excl_rules_attributes.update(old_excl_rules_attributes)
        mem_data = {
            'excl_rules_attributes': excl_rules_attributes,
            'excl_rule_id': excl_rule_id
         }
        pickle.dump(mem_data, data)





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
    cli.pretty_print("Welcome to the OWASP - False Positive Learning Toolkit.", "INFO")
    reset = cli.get_true_or_false("Reset recently learned rules?")
    append_rules = cli.get_true_or_false("Operate in append mode?")
    if not append_rules:
        cli.pretty_print("Rules file will be overwritten, the learned rules are again there, but if\n"
                     "one made changes, they will be lost.", "WARNING")
        if cli.get_true_or_false("Do you want to restart?"):
            main()
    max_location_depth = 3

    # reset learned.data
    if reset:
        try:
            os.remove('data/learned.data')
        except FileNotFoundError:
            cli.pretty_print('nothing to delete', 'WARNING')

    web_server = cli.get_ngx_or_apache()

    for log_file in get_filepaths('input/' + web_server):
        extract_rules_from_log(log_file, lp.get_line_pattern(web_server), max_location_depth, append_rules)

    # extract_rules_from_log(log_file, get_line_pattern('ngx'), max_location_depth, append_rules)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
