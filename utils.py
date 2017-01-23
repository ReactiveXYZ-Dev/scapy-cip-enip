#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Useful routines and utilities which simplify code writing"""
from scapy import all as scapy_all

# New function for merging dictionaries together that is
# particularly helpful when building large dictionary for ITEM_ID values - MED
def merge_dicts(*dict_args):#from  http://stackoverflow.com/a/26853961
    '''
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    '''
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def hexdump(data, columns=16, indentlvl=""):
    """Return the hexadecimal representation of the data"""

    def do_line(line):
        return (
            indentlvl +
            " ".join("{:02x}".format(ord(b)) for b in line) +
            "   " * (columns - len(line)) +
            "  " +
            "".join(b if 32 <= ord(b) < 127 else "." for b in line))

    return "\n".join(do_line(data[i:i + columns]) for i in range(0, len(data), columns))


class LEShortLenField(scapy_all.FieldLenField):
    """A len field in a 2-byte integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        scapy_all.FieldLenField.__init__(self, name, default, fmt="<H",
                                         count_of=count_of, length_of=length_of)


class XBitEnumField(scapy_all.BitEnumField):
    """A BitEnumField with hexadecimal representation"""

    def __init__(self, name, default, size, enum):
        scapy_all.BitEnumField.__init__(self, name, default, size, enum)

    def i2repr_one(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return scapy_all.lhex(x)

# Classes for new fields: Hex representation of little endian ints & shorts - MED
class XLEIntField(scapy_all.LEIntField):
    """A Little Endian IntField with hexadecimal representation"""
    def i2repr(self, pkt, x):
        from scapy.utils import lhex
        return lhex(self.i2h(pkt, x))

class XLEShortField(scapy_all.LEShortField):
    """A Little Endian ShortField with hexadecimal representation"""
    def i2repr(self, pkt, x):
        from scapy.utils import lhex
        return lhex(self.i2h(pkt, x))