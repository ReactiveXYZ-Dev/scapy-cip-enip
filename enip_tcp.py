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
"""Ethernet/IP over TCP scapy dissector"""
import struct

from scapy import all as scapy_all

import enip
import enip_cpf

scapy_all.bind_layers(scapy_all.TCP, enip.ENIP_PACKET, dport=44818)
scapy_all.bind_layers(scapy_all.TCP, enip.ENIP_PACKET, sport=44818)


if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a raw packet over ENIP
    pkt = scapy_all.Ether(src='01:23:45:67:89:ab', dst='ba:98:76:54:32:10')
    pkt /= scapy_all.IP(src='192.168.1.1', dst='192.168.1.42')
    pkt /= scapy_all.TCP(sport=10000, dport=44818)
    pkt /= ENIP_PACKET()
    pkt /= ENIP_SendUnitData()

    # Build!
    data = str(pkt)
    pkt = scapy_all.Ether(data)
    pkt.show()

    # Test the value of some fields
    assert pkt[enip.ENIP_PACKET].session == 0
    assert pkt[enip.ENIP_PACKET].status == 0
    assert pkt[enip.ENIP_PACKET].command_id == 0x70
    assert pkt[enip.ENIP_PACKET].length == 16 #26
    assert pkt[enip_cpf.ENIP_CPF].count == 2
    # assert pkt[enip.ENIP_SendUnitData].items[0].type_id == 0x00a1
    # assert pkt[enip.ENIP_SendUnitData].items[0].length == 4
    # assert pkt[enip.ENIP_SendUnitData].items[0].payload == pkt[enip.ENIP_ConnectionAddress]
    # assert pkt[enip.ENIP_ConnectionAddress].connection_id == 1337
    # assert pkt[enip.ENIP_SendUnitData].items[1].type_id == 0x00b1
    # assert pkt[enip.ENIP_SendUnitData].items[1].length == 6
    # assert pkt[enip.ENIP_SendUnitData].items[1].payload == pkt[enip.ENIP_ConnectionPacket]
    # assert pkt[enip.ENIP_ConnectionPacket].sequence == 4242
    # assert pkt[enip.ENIP_ConnectionPacket].payload.load == 'test'
