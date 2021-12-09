import re

# TODO: convert the variable in some smart class hirarchy with enums
def get_line_pattern(webserver='nginx'):
    line_pattern_ngx = re.compile(
        r"(\S+) (\S+) \[(\S+)] .* ModSecurity: (.+) \[file \"(\S+).conf.* \[id \"(\S+)\"].* \[msg "
        r"\"(.+)\"] \[data.* \[uri \"(.+)\"] \[unique_id.*, client: (\S+), server: (\S+), request: \"(\S+) (\S+) .*$")
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
    line_pattern_apache = re.compile(
        r"^\[(.*) (\S+) (\d+)] \[:(\S+)].*\[client (\S+)] ModSecurity: (.*) \[file \"(\S+).conf\".* "
        r"\[id \"(\d+)\"] \[msg \"(.+)\"] \[data.* \[hostname \"(\S+)\"] \[uri \"(.+)\"] \[unique_id.*$")
    line_fields_apache = {
        "date_1": 1,
        "time": 2,
        "date_2": 3,
        "level": 4,
        "client": 5,
        "summary": 6,
        "rule_set": 7,
        "rule_id": 8,
        "msg": 9,
        "server": 10,
        "uri": 11
    }
    if webserver == 'nginx':
        return line_pattern_ngx, line_fields_ngx
    else:  # apache
        return line_pattern_apache, line_fields_apache
