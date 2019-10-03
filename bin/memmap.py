# Shared utilities for processing cross-platform memory map config file

import re
import os

class MemMap:
    # Special values of destination/address field
    DEST_ELF = '@ELF'

    class MemMapException(Exception):
        pass

    def not_comment(line):
        line = re.sub(r'\s*#.*', '', line.strip())
        if len(line) == 0:
            return None
        return line

    def iter(fmap):
        line_num = 0
        for line in fmap:
            line_num += 1
            line = MemMap.not_comment(line)
            if line is None:
                continue
            tok = line.split()
            if len(tok) < 4:
                raise MemMap.MemMapException("syntax error on line: %u" % line_num)
            m = tok[0]
            k = tok[1]
            addr = tok[2] # it's not always a number, may be special '@' directive
            fname = os.path.expandvars(tok[3])
            yield line_num, m, k, addr, fname

    def iter_mem(fmap, mem):
        for line, m, k, addr, fname in MemMap.iter(fmap):
            if m == mem:
                yield line, k, addr, fname

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
