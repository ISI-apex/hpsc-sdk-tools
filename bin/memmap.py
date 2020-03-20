# Shared utilities for processing cross-platform memory map config file

import re
import os

from numparse import int_autobase, size_from_iec_str

class MemMap:
    # Special values of destination/address field
    DEST_ELF = '@ELF'

    FIELD_NULL = '-'

    class MemMapException(Exception):
        def __init__(self, msg, line):
            Exception.__init__(msg)
            self.line = line

    class Blob:
        def __init__(self, fname, slice_offset, slice_length):
            self.fname = fname
            self.slice_offset = slice_offset
            self.slice_length = slice_length
        def __repr__(self):
            return "%s:0x%x-%s" % (self.fname, self.slice_offset, \
                    (self.slice_length if self.slice_length else "END"))

    def not_comment(line):
        line = re.sub(r'\s*#.*', '', line.strip())
        if len(line) == 0:
            return None
        return line

    def iter(fmap, skip_undefined=True):
        line_num = 0
        for line in fmap:
            line_num += 1
            line = MemMap.not_comment(line)
            if line is None:
                continue
            tok = line.split()
            if len(tok) < 4:
                raise MemMap.MemMapException("syntax error", line_num)
            m = tok[0]
            k = tok[1]
            addr = tok[2] # it's not always a number, may be special '@' directive
            fname_str = tok[3] if len(tok) > 3 else MemMap.FIELD_NULL
            if addr == MemMap.FIELD_NULL or fname_str == MemMap.FIELD_NULL:
                if skip_undefined:
                    print(("NOTICE: line %u: skipped blob %s in mem %s: " + \
                           "undefined field(s)") % (line_num, k, m))
                    continue
            fname = os.path.expandvars(fname_str)
            slice_offset = size_from_iec_str(tok[4]) if len(tok) > 4 else 0x0
            slice_length_str = tok[5] if len(tok) > 5 else None
            if slice_length_str is not None and slice_length_str != '-':
                slice_length = size_from_iec_str(slice_length_str)
            else:
                slice_length = None
            blob = MemMap.Blob(fname, slice_offset, slice_length)
            yield line_num, m, k, addr, blob

    def iter_mem(fmap, mem):
        for line, m, k, addr, blob in MemMap.iter(fmap):
            if m == mem:
                yield line, k, addr, blob

    class Rules:
        """ Helpers for generating makefile rules from memory map"""

        def write_artifacts(fout, variable, *artifact_lists):
            """Writes an assignment of list of artifacts to a makefile variable"""
            print(variable, '+=\\', file=fout)
            for artifacts in artifact_lists:
                for p in artifacts:
                    print('\t%s' % p, '\\', file=fout)
            print(file=fout)

        def write_relations(fout, *relations_list):
            """"Writes makefile rules for one-to-many relationships given in dict"""
            for relations in relations_list:
                for art, deps in relations.items():
                    print(art, ':', '\\', file=fout)
                    for d in deps:
                        print('\t', d, '\\', file=fout)
                    print(file=fout)
