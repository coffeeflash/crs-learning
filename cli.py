import enum


class Color(enum.Enum):
    HEADER = '\033[95m'
    INFO = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def pretty_print(text, color):
    print(f"{color.value}{text}{Color.ENDC.value}")


def get_true_or_false(text):
    text += ' [Y] for Yes, [N] for No'
    while True:
        pretty_print(text, Color.OKCYAN)
        var = input(f"{Color.INFO.value}{'> '}{Color.ENDC.value}")
        if var.lower() == 'y':
            return True
        elif var.lower() == 'n':
            return False


def get_ngx_or_apache():
    text = 'Choose the format of your logs, [a] for Apache24 or [n] for nginx'
    while True:
        pretty_print(text, Color.OKCYAN)
        var = input(f"{Color.INFO.value}{'> '}{Color.ENDC.value}")
        if var.lower() == 'a':
            return 'apache'
        elif var.lower() == 'n':
            return 'nginx'


def get_location_depth():
    text = 'Choose the deepness of the location e.g. /abc/efg/ has length 2.'
    while True:
        pretty_print(text, Color.OKCYAN)
        var = input(f"{Color.INFO.value}{'> '}{Color.ENDC.value}")
        if var.isdigit():
            return int(var)


def get_name():
    text = 'Choose a name for your exclusion rule set. The name will be used\n' \
           'to cache the learned rules for later use.  Furthermore also for\n' \
           'the filename to output the rules. (e.g. cloud.example.com)'
    pretty_print(text, Color.OKCYAN)
    return input(f"{Color.INFO.value}{'Name: '}{Color.ENDC.value}")
