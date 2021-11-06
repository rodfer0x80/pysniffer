from textwrap import wrap

TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

# format mac address to something like this: FF:FF:FF:FF:FF:FF
format_mac_addr = lambda byte_addr: ':'.join(map('{:02x}'.format, byte_addr)).upper()

# format ip address to something like this 127.0.0.1
format_ipv4 = lambda addr: '.'.join(map(str, addr))

# format multi line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in wrap(string, size)])