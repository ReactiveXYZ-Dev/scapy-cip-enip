#!/usr/bin/env python2
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
"""Ethernet/IP over UDP scapy dissector

This dissector only supports a "keep-alive" kind of packet which has been seen
in SUTD's secure water treatment testbed.
"""
import struct

from scapy import all as scapy_all
# from enip_tcp import *
import enip
import enip_cpf

import utils

# Keep-alive sequences
ENIP_UDP_KEEPALIVE = (
    b'\x01\x00\xff\xff\xff\xff' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00')


# Moved ENIP_UDP_SequencedAddress() to enip_cpf file with new name CPF_SequencedAddressItem

# Moved ENIP_UDP_ITEM into enip_cpf file as new class CPF_ITEM


# ENIP_UDP moved to new file enip.py --> Keeps all EtherNet/IP Level
# processing in the same file rather than splitting based on upper layer - MED

scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_PACKET, sport=2222, dport=2222)
scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_PACKET, dport=44818)
scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_PACKET, sport=44818)

# Added additional binding options for ENIP_UDP - MED; needed for scy-phy test case
# scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_UDP, sport=2222, dport=2222)
# scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_UDP, dport=44818)
# scapy_all.bind_layers(scapy_all.UDP, enip.ENIP_UDP, sport=44818)

scapy_all.bind_layers(enip.ENIP_UDP, enip.ENIP_RegisterSession, command_id=0x0065)
scapy_all.bind_layers(enip.ENIP_UDP, enip.ENIP_SendRRData, command_id=0x006f)
scapy_all.bind_layers(enip.ENIP_UDP, enip.ENIP_SendUnitData, command_id=0x0070)
scapy_all.bind_layers(enip.ENIP_UDP, enip.ENIP_ListServices, command_id=0x0004)
scapy_all.bind_layers(enip.ENIP_UDP, enip.ENIP_ListIdentity, command_id=0x0063)


# scapy_all.bind_layers(enip.ENIP_PACKET, ENIP_SequencedAddress, type_id=0x8002)

if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a keep-alive packet
    pkt = scapy_all.Ether(src='00:1d:9c:c8:13:37', dst='01:00:5e:40:12:34')
    pkt /= scapy_all.IP(src='192.168.1.42', dst='239.192.18.52')
    pkt /= scapy_all.UDP(sport=2222, dport=2222)
    # pkt /= enip.ENIP_PACKET(items=[
    #     enip.ENIP_SendUnitData_Item() / enip.ENIP_SequencedAddress(connection_id=1337, sequence=42),
    #     enip.ENIP_SendUnitData_Item(type_id=0x00b1) / scapy_all.Raw(load=ENIP_UDP_KEEPALIVE),
    # ])
    # Updated this section to reflect code modifications and moving of classes - MED
    pkt /= enip.ENIP_UDP(items = [
        enip_cpf.CPF_AddressDataItem() / enip_cpf.CPF_SequencedAddressItem(connection_id=1337, sequence_number=42),
        enip_cpf.CPF_DataItem(type_id=0x00b1) / scapy_all.Raw(load=ENIP_UDP_KEEPALIVE),
    ])

    # Build!
    data = str(pkt)
    print ' '.join("{:02x}".format(ord(c)) for c in data)
    pkt = scapy_all.Ether(data)
    pkt.show()

    # Test the value of some fields; new test setup due to moving classes - MED
    assert pkt[enip.ENIP_UDP].count == 2
    assert pkt[enip.ENIP_UDP].items[0].type_id == 0x8002
    assert pkt[enip.ENIP_UDP].items[0].length == 8
    assert pkt[enip_cpf.CPF_SequencedAddressItem].connection_id == 1337
    assert pkt[enip_cpf.CPF_SequencedAddressItem].sequence_number == 42
    assert pkt[enip.ENIP_UDP].items[0].payload == pkt[enip_cpf.CPF_SequencedAddressItem]
    assert pkt[enip.ENIP_UDP].items[1].type_id == 0x00b1
    assert pkt[enip.ENIP_UDP].items[1].length == 38
    assert pkt[enip.ENIP_UDP].items[1].payload.load == ENIP_UDP_KEEPALIVE
