# -*- coding: utf-8 -*-
# Copyright (c) 2016 Andrey Dolgikh, Matthew Davis, Binghamton University
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

import struct
from scapy import all as scapy_all
import utils
import enip_cpf


DEVICE_PROFILES = {
    0x02 : "AC Drives",
    0x28 : "CIP Modbus Device",
    0x29 : "CIP Modbus Translator",
    0x25 : "CIP Motion Drive",
    0x2F : "CIP Motion Encoder",
    0x21 : "Turbomolecular Vacuum Pump",
    0x31 : "CIP Motion I/O",
    0x2D : "CIP Motion Safety Drive Device",
    0x0C : "Communications Adapter",
    0x26 : "CompoNet Repeater",
    0x15 : "Contactor",
    0x32 : "ControlNet Physical Layer Component",
    0x13 : "DC Drives",
    0x1F : "DC Power Generator",
    0xC8 : "Embedded Component",
    0x22 : "Encoder",
    0x27 : "Enhanced Mass Flow Controller",
    0x24 : "Fluid Flow Controller",
    0x07 : "General Purpose Discrete I/O",
    0x2B : "Generic Device, keyable",
    0x18 : "Human Machine Interface (HMI)",
    0x05 : "Inductive Proximity Switch",
    0x04 : "Limit Switch",
    0x2C : "Managed Ethernet Switch",
    0x1A : "Mass Flow Controller",
    0x27 : "Mass Flow Controller, Enhanced",
    0x03 : "Motor Overload Device",
    0x16 : "Motor Starter",
    0x06 : "Photoelectric Sensor",
    0x1B : "Pneumatic Valve(s)",
    0x10 : "Position Controller",
    0x1D : "Process Control Valve",
    0x0E : "Programmable Logic Controller",
    0x1E : "Residual Gas Analyzer",
    0x09 : "Resolver",
    0x20 : "RF Power Generator",
    0x2A : "Safety Analog I/O Device",
    0x2E : "Safety Drive Device",
    0x23 : "Safety Discrete I/O Device",
    0x17 : "Softstart Starter",
    0x1C : "Vacuum/Pressure Gauge"
}


ENCAPSULATION_COMMANDS = utils.merge_dicts({
        0x0000: "NOP",  #(may be sent only using TCP)
        0x0004: "ListServices",
        0x0005: "Reserved for legacy (RA)",
        0x0063: "ListIdentity",  # (may be sent using either UDP or TCP)
        0x0064: "ListInterfaces",  # optional (may be sent using either UDP or TCP)
        0x0065: "RegisterSession",  # (may be sent only using TCP)
        0x0066: "UnRegisterSession",  # (may be sent only using TCP)
        0x006F: "SendRRData",  # (may be sent only using TCP)
        0x0070: "SendUnitData",  # (may be sent only using TCP)
        0x0071: "Reserved for legacy (RA)",  #
        0x0072: "IndicateStatus",  # (may be sent only using TCP)
        0x0073: "Cancel",  # optional (may be sent only using TCP)
    },
    {k: "Reserved for legacy (RA)" for k in range(1,3+1)}, #0x0001: through 0x0003 "Reserved for legacy (RA)
    {k: "Reserved for future expansion" for k in range(0x6, 0x0062 + 1)}, # 0x0006: through 0x0062 "Reserved for future expansion"
    {k: "Reserved for legacy (RA)" for k in range(0x67, 0x6E + 1)},  # 0x0067: through 0x006E "Reserved for legacy (RA)"
    {k: "Reserved for legacy (RA)" for k in range(0x74, 0x00C7 + 1)}, #0x0074: through 0x00C7 "Reserved for legacy (RA)"
    {k: "Reserved for future expansion" for k in range(0xC8, 0xFFFF + 1)}, #0x00C8: through 0xFFFF "Reserved for future expansion"
)


# class ENIP_SequencedAddress(scapy_all.Packet):
#     name = "ENIP_UDP_SequencedAddress"
#     fields_desc = [
#         scapy_all.LEIntField("connection_id", 0),
#         scapy_all.LEIntField("sequence", 0),
#     ]


class ENIP_ConnectionAddress(scapy_all.Packet):
    name = "ENIP_ConnectionAddress"
    fields_desc = [scapy_all.LEIntField("connection_id", 0)]


class ENIP_ConnectionPacket(scapy_all.Packet):
    name = "ENIP_ConnectionPacket"
    fields_desc = [scapy_all.LEShortField("sequence", 0)]


class ENIP_SendUnitData(scapy_all.Packet):
    """Data in ENIP header specific to the specified command"""
    name = "ENIP_SendUnitData"
    fields_desc = [
        scapy_all.LEIntField("interface_handle", 0),
        scapy_all.LEShortField("timeout", 0),
        scapy_all.PacketField("Encapsulated CPF packet", enip_cpf.ENIP_CPF(), enip_cpf.ENIP_CPF ),
        # utils.LEShortLenField("count", None, count_of="items"),
        # scapy_all.PacketListField("items", [], ENIP_SendUnitData_Item,
        #                           count_from=lambda p: p.count),
    ]


class ENIP_SendRRData(scapy_all.Packet):
    name = "ENIP_SendRRData"
    fields_desc = ENIP_SendUnitData.fields_desc


class ENIP_RegisterSession(scapy_all.Packet):
    name = "ENIP_RegisterSession"
    fields_desc = [
        scapy_all.LEShortField("protocol_version", 1),
        scapy_all.LEShortField("options", 0),
    ]


class ENIP_ListServices_TargetItem(scapy_all.Packet):
    name="ENIP_ListServicesTarget_Item"

    fields_desc = [
        scapy_all.LEShortField("item_type_code", 0),
        scapy_all.LEShortField("length", 0),
        scapy_all.LEShortField("encapsulation_version", 1),
        scapy_all.LEShortField("capability_flags", 0),
        scapy_all.StrFixedLenField("name_of_service", "", 16),
    ]

    def extract_padding(self, p):
        return "", p


class ENIP_ListServices(scapy_all.Packet):
    name = "ENIP_ListServices"
    fields_desc = [
        utils.LEShortLenField("count", 1, count_of="TargetItems"),
        scapy_all.PacketListField("TargetItems", [], ENIP_ListServices_TargetItem, count_from=lambda p: p.count),
    ]


class ENIP_ListIdentity_SocketItem(scapy_all.Packet):
    name="Socket_Address"

    fields_desc = [
        scapy_all.ShortField("sin_family", 0),
        scapy_all.ShortField("sin_port", 0),
        scapy_all.IPField("sin_address", "0.0.0.0"),
        scapy_all.StrFixedLenField("name_of_service", "", 8),
    ]

    def extract_padding(self, p):
        # print self.__class__.__name__+": P="+str(p)
        return "", p


class ENIP_DeviceRevision(scapy_all.Packet):
    name = "ENIP_DeviceRevision"
    fields_desc = [
        scapy_all.ByteField("Major", 0),
        scapy_all.ByteField("Minor", 0),
            ]

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return "", p


class ENIP_ListIdentity_TargetItem(scapy_all.Packet):
    name="ENIP_ListIdentity_TargetItem"
    fields_desc = [
        scapy_all.LEShortField("item_type_code", 0),
        scapy_all.LEShortField("length", 0),
        scapy_all.LEShortField("encapsulation_version", 1),
        scapy_all.PacketField("ListIdentityItems", ENIP_ListIdentity_SocketItem(), ENIP_ListIdentity_SocketItem), #, count_from=1),
        scapy_all.LEShortField("vendor_ID", 0),
        scapy_all.LEShortEnumField("device_type", 0x21, DEVICE_PROFILES),
        scapy_all.LEShortField("product_code", 0),
        scapy_all.PacketField("ENIP_DeviceRevision", ENIP_DeviceRevision(), ENIP_DeviceRevision),
        scapy_all.XShortField("status", 0x0000),
        utils.XLEIntField("serial", 0x00000000),
        scapy_all.ByteField("product_name_length", 0),
        scapy_all.StrLenField("product_name", "", length_from=lambda p: p.product_name_length),
        scapy_all.XByteField("state", 0),
    ]

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return "", p


class ENIP_ListIdentity(scapy_all.Packet):
    name = "ENIP_ListIdentity"
    fields_desc = [
        utils.LEShortLenField("count", 1, count_of="IdentityItems"),
        scapy_all.PacketListField("IdentityItems", [], ENIP_ListIdentity_TargetItem, count_from=lambda p: p.count),
    ]


    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return "", p


class ENIP_PACKET(scapy_all.Packet):
    """Ethernet/IP packet over TCP"""
    name = "ENIP_PACKET"
    fields_desc = [
        scapy_all.LEShortEnumField("command_id", None, ENCAPSULATION_COMMANDS),
        scapy_all.LEShortField("length", None),
        utils.XLEIntField("session", 0),
        scapy_all.LEIntEnumField("status", 0, {0: "success"}),
        scapy_all.LELongField("sender_context", 0),
        scapy_all.LEIntField("options", 0),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

scapy_all.bind_layers(ENIP_PACKET, ENIP_ListServices, command_id=0x0004)
scapy_all.bind_layers(ENIP_PACKET, ENIP_RegisterSession, command_id=0x0065)
scapy_all.bind_layers(ENIP_PACKET, ENIP_SendRRData, command_id=0x006f)
scapy_all.bind_layers(ENIP_PACKET, ENIP_SendUnitData, command_id=0x0070)
scapy_all.bind_layers(ENIP_PACKET, ENIP_ListIdentity, command_id=0x0063)
# scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionAddress, type_id=0x00a1)
# scapy_all.bind_layers(ENIP_SendUnitData_Item, ENIP_ConnectionPacket, type_id=0x00b1)