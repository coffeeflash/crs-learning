import os
import re
import pickle  # for storing some data

# Regex used to match relevant loglines (in this case, a specific IP address)
FILTER_MODSECURITY = re.compile(r".*ModSecurity.*$")
LINE_PATTERN_NGINX_ERROR = re.compile(
    r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg \"(.+)\"].*, server: (\S+), request: \"(\S+) (\S+) .*$")
ngx_fields = {
        "date": 1,
        "time": 2,
        "level": 3,
        "summary": 4,
        "rule_set": 5,
        "rule_id": 6,
        "msg": 7,
        "server": 8,
        "method": 9,
        "request": 10
    }
LINE_PATTERN_temp = '(\S+) (\S+) [(\S+)] (\S+) ModSecurity: (\S+) [file "(\S+).conf(\S+) [id "(\S+)"(\S+) [msg "(\S+)"]' \
                    ' (\S+)[ver "(\S+)"](\S+)] [tag (\S+)] [host<_>, client: (\S+), server: (\S+), request: "(\S+) (\S+) '

# Output file, where the matched loglines will be copied to
output_filename = os.path.normpath("output/parsed_lines.log")
# Overwrites the file, ensure we're starting out with a blank file
# with open(output_filename, "w") as out_file:
# out_file.write("")

#make rules in steps with this object...
class Rule:
  def __init__(self, request, rule_id):
    self.request = request
    self.rule_id = rule

  def myfunc(self):
    print("Hello my name is " + self.request)


exclusion_rules = {""}
excl_rule_id = 10000

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
                pot_ecl_rule = 'SecRule REQUEST_URI "@beginsWith ' + match.group(ngx_fields['request']) \
                               + '" "id:' + str(excl_rule_id) + ', phase:1, pass, nolog, ctl:ruleRemoveById=930130"'
                if pot_ecl_rule not in exclusion_rules:
                    exclusion_rules.add(pot_ecl_rule)
                    excl_rule_id += 1
                out_file.write(line)

print(exclusion_rules)