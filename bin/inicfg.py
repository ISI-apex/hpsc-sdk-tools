# Shared utilities for working with config files in INI format

import configparser

from numparse import int_autobase, size_from_iec_str

class IniCfg:
    """Helper for working with configuration in INI format"""
    INHERIT_OPT = 'inherit'

    class CfgException(Exception):
        pass

    def __init__(self, ini_file):
        self.cfg = configparser.ConfigParser()
        self.cfg.read(ini_file)
        self.collapsed = {} # cache

        # Hide all inherited nodes ("base classes are abstract")
        bases = []
        for s in self.cfg.sections():
            if self.cfg.has_option(s, self.INHERIT_OPT):
                base = self.cfg.get(s, self.INHERIT_OPT)
                bases.append(base)
        self.base_sections = [s for s in self.cfg.sections() if s not in bases]

    def collapse(self, sect):
        """Inherit properties from sections arranged in a hierarchy"""
        if not self.cfg.has_section(sect):
            raise IniCfg.CfgException(
                "ERROR: section does not exist: %s'" % sect)
        if self.cfg.has_option(sect, self.INHERIT_OPT):
            base = self.cfg.get(sect, self.INHERIT_OPT)
            if not self.cfg.has_section(base):
                raise IniCfg.CfgException(
                    "ERROR: merged section does not exist: %s" % base)
            d = dict(self.collapse(base))
            d.update(dict(self.cfg[sect]))
            return d
        else:
            return dict(self.cfg[sect])

    def get_collapsed(self, sect):
        if sect not in self.collapsed:
            self.collapsed[sect] = self.collapse(sect)
        return self.collapsed[sect]

    def get_props(self, sect, *props):
        scfg = self.get_collapsed(sect)
        values = []
        for p in props:
            if p not in scfg:
                raise IniCfg.CfgException(
                    "%s property not defined for section %s" % (p, sect))
            values.append(scfg[p])
        return values

    def has_props(self, sect, *props):
        scfg = self.get_collapsed(sect)
        for p in props:
            if p not in scfg:
                return False
        return True

    def get_prop_optional(self, sect, prop):
        scfg = self.get_collapsed(sect)
        if prop in scfg:
            return scfg[prop]
        return None

    def get_prop(self, sect, prop, fallback=None):
        str_val = self.get_prop_optional(sect, prop)
        if str_val is not None:
            return str_val
        elif fallback is not None:
            return fallback
        else:
            raise IniCfg.CfgException(
                "ERROR: section %s has no property %s" % (sect, prop))

    def get_prop_as(self, sect, prop, ctor, fallback=None):
        val = self.get_prop(sect, prop, fallback)
        return ctor(val)

    def get_prop_as_int(self, sect, prop, fallback=None):
        return self.get_prop_as(sect, prop, int_autobase, fallback)

    def get_prop_as_bool(self, sect, prop, fallback=None):
        return self.get_prop_as(sect, prop, IniCfg.boolean, fallback)

    def get_prop_as_size(self, sect, prop, fallback=None):
        return self.get_prop_as(sect, prop, size_from_iec_str, fallback)

    def sections(self):
        return self.base_sections

    def boolean(s):
        if type(s) is bool:
            return s
        s = s.strip().lower()
        if s == 'true' or s == 'yes' or s == '1':
            return True
        if s == 'false' or s == 'no' or s == '0':
            return False
        raise IniCfg.CfgException("invalid boolean value: %s" % s);
