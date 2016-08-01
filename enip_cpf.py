#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, david.urbina@utdallas.edu
# Copyright (c) 2016 Andrey Dolgikh, Binghamton University
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
"""Ethernet/IP Common Packet Format Scapy dissector."""
import struct

from scapy import all as scapy_all

import utils

ITEM_ID_NUMBERS = utils.merge_dicts({
    0x0000 : "Null",  #(used for UCMM messages). Indicates that encapsulation routing is NOT needed. Target is either local (ethernet) or routing info is in a data Item.
    0x000C : "ListIdentity Response",  #
    0x0091 : "Reserved",  # for legacy (RA)
    0x00A1 : "Connected Address Item",  # (used for connected messages)
    0x00B1 : "Connected Data Item",  # Connected Transport packet
    0x00B2 : "Unconnected Data Item",  # Unconnected Messages (eg. used within CIP command SendRRData)
    0x0100 : "ListServices response",  #
    0x8000 : "Sockaddr Info, originator-to-target",  #
    0x8001 : "Sockaddr Info, target-to-originator",  #
    0x8002 : "Sequenced Address item",  #
    },
    {k: "Reserved for legacy (RA)" for k in range(0x0001, 0x000B + 1)}, # 0x0001 – 0x000B Reserved for legacy (RA)
    {k: "Reserved for legacy (RA)" for k in range(0x000D, 0x0083 + 1)}, # 0x000D – 0x0083 Reserved for legacy (RA)
    {k: "Reserved for future expansion" for k in range(0x0084, 0x0090 + 1)}, # 0x0084 – 0x0090 Reserved for future expansion
    {k: "Reserved for future expansion" for k in range(0x0092, 0x00A0 + 1)}, # 0x0092 – 0x00A0 Reserved for future expansion
    {k: "Reserved for legacy (RA)" for k in range(0x00A2, 0x00A4 + 1)}, # 0x00A2 – 0x00A4 Reserved for legacy (RA)
    {k: "Reserved for future expansion" for k in range(0x00A5, 0x00B0 + 1)}, # 0x00A5 – 0x00B0 Reserved for future expansion
    {k: "Reserved for future expansion" for k in range(0x00B3, 0x00FF + 1)}, # 0x00B3 – 0x00FF Reserved for future expansion
    {k: "Reserved for legacy (RA)" for k in range(0x0101, 0x010F + 1)}, # 0x0101 – 0x010F Reserved for legacy (RA)
    {k: "Reserved for future expansion" for k in range(0x0110, 0x7FFF + 1)}, # 0x0110 – 0x7FFF Reserved for future expansion
    {k: "Reserved for future expansion" for k in range(0x8003, 0xFFFF + 1)}, # 0x8003 – 0xFFFF Reserved for future expansion

    #regexps to produce dicts above
    #(0x[\d|{ABCDF}]{4}).{3}(0x[\d|{ABCDF}]{4}) (.*)
    #\{k\: \"$3\" for k in range\($1\, $2 \+ 1\)\}\, \#
)


class CPF_SequencedAddressItem(scapy_all.Packet):
    name = "CPF_SequencedAddressItem"
    fields_desc = [
        scapy_all.LEIntField("connection_id", 0),
        scapy_all.LEIntField("sequence_number", 0),
    ]


class CPF_Item(scapy_all.Packet):
    name = "CPF_Item"
    fields_desc = [
        scapy_all.LEShortEnumField('type_id', 0, ITEM_ID_NUMBERS),
        scapy_all.LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

class CPF_AddressDataItem(CPF_Item):
    name = "CPF_AddressDataItem"


class CPF_DataItem(CPF_Item):
    name = "CPF_DataItem"

class ENIP_CPF(scapy_all.Packet):
    name = "ENIP_CPF"
    fields_desc = [
        utils.LEShortLenField("count", 2, count_of="items"),
        scapy_all.PacketField("Address Item", CPF_AddressDataItem('', type_id=0x0, length=0), CPF_AddressDataItem),
        scapy_all.PacketField("Data Item", CPF_DataItem('', type_id=0x0, length=0), CPF_DataItem),
        scapy_all.ConditionalField(
            scapy_all.PacketListField("optional_items", None, CPF_Item, count_from=lambda p: p.count-2),
            lambda p: p.count>2
        ),
    ]

    def extract_padding(self, p):
        return '', p


scapy_all.bind_layers(CPF_AddressDataItem, CPF_SequencedAddressItem, type_id=0x8002)
