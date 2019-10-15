# Helper functions for parsing strings into numeric values

import re

class NumParseException(Exception):
    pass

def int_autobase(val):
    if val.startswith("0x"):
        return int(val, 16)
    if re.match(r'0[0-9]+', val):
        return int(val, 8)
    return int(val, 10)

def size_from_iec_str(s):
    m = re.match(r'((?:0x)?(?:[0-9A-Fa-f]+))([KMG]?)', s)
    if not m:
        raise NumParseException("size not in IEC format: '%s'" % s)
    size = int_autobase(m.group(1))
    suffix = m.group(2)
    if suffix == 'G':
        size <<= 30
    if suffix == 'M':
        size <<= 20
    if suffix == 'K':
        size <<= 10
    return size
