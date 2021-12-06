
C = {
    'HEADER': '\033[95m',
    'INFO': '\033[94m',
    'OKCYAN': '\033[96m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
}


def pretty_print(text, color):
    print(f"{C[color]}{text}{C['ENDC']}")


def get_true_or_false(text):
    text += ' [Y] for Yes, [N] for No'
    while True:
        pretty_print(text, "OKCYAN")
        var = input()
        if var.lower() == 'y':
            var = True
            break
        elif var.lower() == 'n':
            var = False
            break
        else:
            continue
    return var


def get_ngx_or_apache():
    text = 'Choose the format of your logs, [a] for Apache24 or [n] for nginx'
    while True:
        pretty_print(text, "OKCYAN")
        var = input()
        if var.lower() == 'a':
            var = 'apache'
            break
        elif var.lower() == 'n':
            var = 'nginx'
            break
        else:
            continue
    return var
