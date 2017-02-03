#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD; David I. Urbina, UTD
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
"""Common Industrial Protocol dissector
Documentation:
* http://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf

Wireshark implementation:
https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=epan/dissectors/packet-cip.c
"""
import struct
import sys

from scapy import all as scapy_all

import enip
import enip_tcp
import enip_udp
import enip_cpf
import utils


class CIP_RespSingleAttribute(scapy_all.Packet):
    """An attribute... not much information about it"""
    fields_desc = [scapy_all.StrField("value", None)]


class CIP_RespAttributesAll(scapy_all.Packet):
    """Content of Get_Attribute_All response"""
    fields_desc = [
        scapy_all.StrField("value", None),
    ]

class CIP_RespAttributesList(scapy_all.Packet):
    """List of attributes in Get_Attribute_List responses

    There are "count" attributes in the "content" field, in the following format:
        * attribute ID (INT, LEShortField)
        * status (INT, LEShortField, 0 means success)
        * value, type and length depends on the attribute and thus can not be known here
    """
    fields_desc = [
        scapy_all.LEShortField("count", 0),
        # scapy_all.StrField("content", ""),
        scapy_all.LEShortField('attribute', 0),
        scapy_all.XShortField('status', 0),
        scapy_all.StrField("content", ""),
    ]

    def split_guess(self, attr_list, verbose=False):
        """Split the content of the Get_Attribute_List response with the known attribute list

        Return a list of (attr, value) tuples, or None if an error occurred
        """
        content = self.content
        offset = 0
        idx = 0
        result = []
        while offset < len(content):
            attr, status = struct.unpack("<HH", content[offset:offset + 4])
            if attr not in attr_list:
                if verbose:
                    sys.stderr.write("Error: Get_Attribute_List response contains an unknown attribute\n")
                    sys.stderr.write("... all attrs " + ','.join(hex(a) for a in attr_list) + '\n')
                    sys.stderr.write(utils.hexdump(content[offset:], indentlvl="... ") + "\n")
                return
            if attr != attr_list[idx]:
                if verbose:
                    sys.stderr.write("Error: attr {:#x} not in position {} of attr list\n".format(attr, idx))
                    sys.stderr.write("... all attrs " + ','.join(hex(a) for a in attr_list) + '\n')
                return
            offset += 4
            attr_len = None
            if idx == len(attr_list) - 1:
                # Last attribute
                attr_len = len(content) - offset
            else:
                # Find next attribute header
                nexthdr = struct.pack('<HH', attr_list[idx + 1], 0)
                for i in range(offset + 1, len(content) - 4):
                    if content[i:i + 4] == nexthdr:
                        attr_len = i - offset
                        break
            if attr_len is None:
                if verbose:
                    sys.stderr.write("Error: length not found. Here is the remaining\n")
                    sys.stderr.write("... all attrs " + ','.join(hex(a) for a in attr_list) + '\n')
                    sys.stderr.write(utils.hexdump(content[offset:], indentlvl="... ") + "\n")
                return
            result.append((attr, content[offset:offset + attr_len]))
            offset += attr_len
            idx += 1
        return result

    def split_guess_todict(self, attr_list, verbose=False):
        """Same as split_guess, but return a dict instead of a list of tuples"""
        result = self.split_guess(attr_list, verbose)
        if result is None:
            return
        # assert unicity of attributes IDs
        assert len(frozenset(x[0] for x in result)) == len(result)
        return dict(result)


class CIP_ReqGetAttributeList(scapy_all.Packet):
    """The list of requested attributes in a CIP Get_Attribute_List request"""
    fields_desc = [
        utils.LEShortLenField("count", None, count_of="attrs"),
        scapy_all.FieldListField("attrs", [], scapy_all.LEShortField("", 0),
                                 count_from=lambda pkt: pkt.count),
    ]


class CIP_ReqReadOtherTag(scapy_all.Packet):
    """Optional information to be sent with a Read_Tag_Service

    FIXME: this packet has been built from experiments, not from official doc
    """
    fields_desc = [
        scapy_all.LEShortField("start", 0),
        scapy_all.LEShortField("zero", 0),
        scapy_all.LEShortField("length", None),
    ]

# Added classes to deal with CIP Logical and CIP Port segments, as well
# as CIP path padding
# New Classes:
# CIP_PortSegment, CIP_LogicalSegment, CIP_PathPadded - MED

class CIP_PortSegment(scapy_all.Packet):
    name="CIP_PortSegment"

    PORT_IDENT={
        0: "Reserved",
        1: "Back-Plane",
        15: "Extended",
    }

    fields_desc = [
        scapy_all.BitField("extended_link_address_size", 0, 1),
        scapy_all.BitEnumField("port_identifier", 0, 4, PORT_IDENT),
        scapy_all.ByteField("link_address_size", 0),
        scapy_all.ConditionalField(
            scapy_all.LEIntField("extended_port_identifier", 0),
            lambda p: p.port_identifier == 0xf  # If the Port Identifier is 15, then a 16-bit field, called the Extended Port Identifier, shall be the next part of the Port Segment
        ),
        scapy_all.ConditionalField(
                scapy_all.FieldListField("Link_Address", [],
                                         scapy_all.XByteField("",0), length_from=lambda p: p.link_address_size
                                         ),
            lambda p: p.extended_link_address_size == 0x1 # If the Port Identifier is 15, then a 16-bit field, called the Extended Port Identifier, shall be the next part of the Port Segment
        )
    ]

    def extract_padding(self, p):
        #print self.__class__.__name__ + ": P=" + str(p)
        return "", p

class CIP_DataSegmentPadded(scapy_all.Packet):
    name='CIP_DataSegmentPadded'

    SEG_TYPE={
        0: "Simple Data Segment",
        17: "ANSI Extended Symbol Segment"
    }

    fields_desc = [
        scapy_all.BitEnumField("segment_subtype", 0, 5, SEG_TYPE),
        scapy_all.ConditionalField(scapy_all.ByteField("word_size", 0), lambda p: p.segment_subtype == 0),
        scapy_all.ConditionalField(scapy_all.ByteField("character_count", 0), lambda p: p.segment_subtype == 17),
        scapy_all.ConditionalField(scapy_all.FieldListField("data",0, scapy_all.LEShortField('',0), count_from = lambda p: p.word_size), lambda p: p.segment_subtype == 0),
        scapy_all.ConditionalField(scapy_all.FieldListField("data", 0, scapy_all.ByteField('', 0), count_from=lambda p: p.character_count),
            lambda p: p.segment_subtype == 17)
    ]

class CIP_Logical_SpecialSegment(scapy_all.Packet):
    name="Electronic_Key_Segment"

    fields_desc = [
        scapy_all.ByteField("key_format", 4),
        scapy_all.LEShortField("vendor_id", 0),
        scapy_all.LEShortField("device_type", 0),
        utils.XLEShortField("product_code", 0),
        scapy_all.BitField("compatibility", 0, 1),
        scapy_all.BitField("major_revision", 0, 7),
        scapy_all.ByteField("minor_revision", 0),
    ]

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return None, p

class CIP_LogicalSegmentPadded(scapy_all.Packet):
    name="CIP_LogicalSegmentPadded"

    LOGICAL_TYPE = {
        0: "Class ID",
        1: "Instance ID",
        2: "Member ID",
        3: "Connection Point",
        4: "Attribute ID",
        5: "Special",
        6: "Service ID",
        7: "Reserved"
    # The Special and Service ID Logical Types do not use the logical addressing definition for the Logical Format.
    }

    LOGICAL_FORMAT = {
        0: "8 - bit logical address",
        1: "16-bit logical address",
        2: "32-bit logical address",
        3: "Reserved for future use"
    }
    magic_value=5
    fields_desc = [
        scapy_all.BitEnumField("logical_type", 0, 3, LOGICAL_TYPE),
        scapy_all.ConditionalField(scapy_all.BitEnumField("logical_format", 0, 2, LOGICAL_FORMAT), lambda p: p.logical_type < 5),
        scapy_all.ConditionalField(scapy_all.BitField("unused", 0, 2), lambda p: p.logical_type >= 5),
        # When the logical segment is included within a Padded Path, the 16 - bit and 32 - bit
        # logical formats shall have a pad inserted between the segment type byte and the Logical Value
        # (the 8 - bit format is identical to the Packed Path).The    pad    byte    shall    be    set    to    zero.
        scapy_all.ConditionalField(scapy_all.ByteField("padding", 0), lambda p: p.logical_format > 0x0),### TODO This conditional field might depend on string size too.
        # scapy_all.ByteField("value", 0),
        scapy_all.ConditionalField(
            scapy_all.ByteField("value8bit", 0),
            lambda p:
                p.logical_format == 0x0
        ),
        scapy_all.ConditionalField(
            scapy_all.LEShortField("value16bit", 0),
            lambda p:
                p.logical_format == 0x1
        ),
        scapy_all.ConditionalField(
            scapy_all.LELongField("value32bit", 0),
            lambda p:
                p.logical_format == 0x2
        ),
    ]

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        # magic_value = 5: logic_value < 5 have no payload --> go to previous layer again; logic_value >=5 have payload --> process
        if self.logical_type < 5:
            return  '',p
        else:
            return p, ''

scapy_all.bind_layers(CIP_LogicalSegmentPadded, CIP_Logical_SpecialSegment, logical_type=5)  # Logical Key Segment


#
#
# class A_8bitValue(scapy_all.Packet):
#     fields_desc = [
#         scapy_all.ByteField("value", 0),
#     ]
#
#     def extract_padding(self, p):
#         # print self.__class__.__name__ + ": P=" + str(p)
#         return (), p
#
#
# class A_16bitValue(scapy_all.Packet):
#     fields_desc = [
#         scapy_all.LEShortField("value", 0),
#     ]
#
#     def extract_padding(self, p):
#         # print self.__class__.__name__ + ": P=" + str(p)
#         return (), p
#
# class A_32bitValue(scapy_all.Packet):
#     fields_desc = [
#         scapy_all.LELongField("value", 0),
#     ]
#
#     def extract_padding(self, p):
#         # print self.__class__.__name__ + ": P=" + str(p)
#         return (), p
#
# scapy_all.bind_layers(CIP_LogicalSegmentPadded, A_8bitValue, logical_format=0)
# scapy_all.bind_layers(CIP_LogicalSegmentPadded, A_16bitValue, logical_format=1)
# scapy_all.bind_layers(CIP_LogicalSegmentPadded, A_32bitValue, logical_format=2)

SEGMENT_TYPE={
    0:"Port Segment",   # 0 0 0 Port Segment
    1:"Logical Segment",   # 0 0 1 Logical Segment
    2:"Network Segment",   # 0 1 0 Network Segment
    3:"Symbolic Segment",   # 0 1 1 Symbolic Segment
    4:"Data Segment",   # 1 0 0 Data Segment
    5:"Data Type (constructed)",   # 1 0 1 Data Type (constructed, see section C-2.1)
    6:"Data Type (elementary)",   # 1 1 0 Data Type (elementary, see section C-2.1)
    7:"Reserved"   # 1 1 1 Reserved for future use
}


class CIP_PathPadded(scapy_all.Packet):
    name="CIP_PathPadded"
    fields_desc = [
        scapy_all.BitEnumField("segment_type", 0, 3, SEGMENT_TYPE),
        # scapy_all.PacketField("segment", CIP_PortSegment(),CIP_PortSegment),
        # scapy_all.BitEnumField("don't care", 0, 5, SEGMENT_TYPE),
        # scapy_all.LEShortField("zero", 0),
        # scapy_all.LEShortField("length", None),
    ]

    # def extract_padding(self, p):
    #     print self.__class__.__name__+": P="+str(p)
    #     # print self.__class__.__name__+": Length="+str(self.length)
    #     q,w=p
    #     # return "",(q,8-w,)
    #     # return (w,q[:2]), (q,  w,)
    #     # return p[:self.length], p[self.length:]
    #     return (q,w,),(q,8-w,)

    # def extract_padding(self, p):
    #     print self.__class__.__name__ + ": P=" + str(p)
    #     return '', p
    #     return p, None

# Additional bind_layers
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=0)   #Port Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_LogicalSegmentPadded, segment_type=1)   #Logical Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=2)   #Port Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=3)   #Port Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_DataSegmentPadded, segment_type=4)   #Data Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=5)   #Port Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=6)   #Port Segment
scapy_all.bind_layers(CIP_PathPadded, CIP_PortSegment, segment_type=7)   #Port Segment

class CIP_PathField(scapy_all.StrLenField):
    SEGMENT_TYPES = {
        0: "class",  # 0x20 = 8-bit class ID, 0x21 = 16-bit class ID
        1: "instance",  # 0x24 = 8-bit instance ID, 0x25 = 16-bit instance ID
        2: "element",  # 0x28 = 8-bit element ID, 0x29 = 16-bit element ID, 0x2a = 32-bit element ID
        3: "connection point",
        4: "attribute",  # 0x30 = 8-bit attribute ID, 0x31 = 16-bit attribute ID
    }
    KNOWN_CLASSES = {
        0x01: "Identity",
        0x02: "Message Router",
        0x06: "Connection Manager",
        0x6b: "Symbol",
        0x6c: "Template",
    }

    @classmethod
    def to_tuplelist(cls, val):
        """Return a list of tuples describing the content of the path encoded in val"""
        if ord(val[0]) == 0x91:
            # "ANSI Extended Symbolic", the path is a string
            # Don't check the second byte, which is the length (in bytes) of the strings.
            return {-1: val[2:].rstrip("\0")}

        pos = 0
        result = []
        while pos < len(val):
            header = struct.unpack('B', val[pos])[0]
            pos += 1
            if (header & 0xe0) != 0x20:  # 001 high bits is "Logical Segment"
                sys.stderr.write("WARN: unknown segment class of 0x{:02x}\n".format(header))

            seg_format = header & 3
            if seg_format == 0:  # 8-bit segment
                seg_value = struct.unpack('B', val[pos])[0]
                pos += 1
            elif seg_format == 1:  # 16-bit segment
                seg_value = struct.unpack('<H', val[pos + 1:pos + 3])[0]
                pos += 3
            else:
                # 2 is 32-bit segment, but alignment needs to be taken into account
                raise Exception("Unknown seg_format {}".format(seg_format))

            seg_type = (header >> 2) & 7
            result.append((seg_type, seg_value))
        return result

    @classmethod
    def tuplelist2repr(cls, val_tuplelist):
        """Represent a path tuplelist into a human-readable text"""
        if -1 in val_tuplelist and list(val_tuplelist.keys()) == [-1]:
            # String path
            return repr(val_tuplelist[-1])

        descriptions = []
        for type_id, value in val_tuplelist:
            desc = cls.SEGMENT_TYPES.get(type_id, "type{}".format(type_id))
            desc += " 0x{:x}".format(value)
            if type_id == 0 and value in cls.KNOWN_CLASSES:
                desc += "({})".format(cls.KNOWN_CLASSES[value])
            descriptions.append(desc)
        return ",".join(descriptions)

    @classmethod
    def i2repr(cls, pkt, val):
        """Decode the path "val" as human-readable text"""
        return cls.tuplelist2repr(cls.to_tuplelist(val))


class CIP_Path(scapy_all.Packet):
    name = "CIP_Path"
    fields_desc = [
        scapy_all.ByteField("wordsize", None),
        CIP_PathField("path", None, length_from=lambda p: 2 * p.wordsize),
    ]

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return "", p

    @classmethod
    def make(cls, class_id=None, instance_id=None, member_id=None, attribute_id=None):
        """Create a CIP_Path from its attributes"""
        content = b""
        if class_id is not None:
            if class_id < 256:  # 8-bit class ID
                content += b"\x20" + struct.pack("B", class_id)
            else:  # 16-bit class ID
                content += b"\x21\0" + struct.pack("<H", class_id)

        if instance_id is not None:
            # Always use 16-bit instance ID
            content += b"\x25\0" + struct.pack("<H", instance_id)

        if member_id is not None:
            if member_id < 256:  # 8-bit member ID
                content += b"\x28" + struct.pack("B", member_id)
            else:  # 16-bit attribute ID
                content += b"\x29\0" + struct.pack("<H", member_id)

        if attribute_id is not None:
            if attribute_id < 256:  # 8-bit attribute ID
                content += b"\x30" + struct.pack("B", attribute_id)
            else:  # 16-bit attribute ID
                content += b"\x31\0" + struct.pack("<H", attribute_id)

        return cls(wordsize=len(content) // 2, path=content)

    @classmethod
    def make_str(cls, name):
        content = struct.pack('BB', 0x91, len(name)) + name.encode('ascii')
        if len(content) & 1:
            content += b'\0'
        return cls(wordsize=len(content) // 2, path=content)

    def to_tuplelist(self):
        """Return a list of tuples describing the content of the path encoded in val"""
        return CIP_PathField.to_tuplelist(self.path)

    def to_repr(self):
        """Return a representation of the path, not of the packet (!= repr(path))"""
        return self.get_field("path").i2repr(self, self.path)


class CIP_ResponseStatus(scapy_all.Packet):
    """The response field of CIP headers"""
    name = "CIP_ResponseStatus"

    ERROR_CODES = {
        0x00: "Success",
        0x01: "Connection failure",
        0x02: "Resource unavailable",
        0x03: "Invalid parameter value",
        0x04: "Path segment error",
        0x05: "Path destination unknown",
        0x06: "Partial transfer",
        0x07: "Connection lost",
        0x08: "Service not supported",
        0x09: "Invalid attribute value",
        0x0a: "Attribute list error",
        0x0b: "Already in requested mode/state",
        0x0c: "Object state conflict",
        0x0d: "Object already exists",
        0x0e: "Attribute not settable",
        0x0f: "Privilege violation",
        0x10: "Device state conflict",
        0x11: "Reply data too large",
        0x12: "Fragmentation of a primitive value",
        0x13: "Not enough data",
        0x14: "Attribute not supported",
        0x15: "Too much data",
        0x16: "Object does not exist",
        0x17: "Service fragmentation sequence not in progress",
        0x18: "No stored attribute data",
        0x19: "Store operation failure",
        0x1a: "Routing failure, request packet too large",
        0x1b: "Routing failure, response packet too large",
        0x1c: "Missing attribute list entry data",
        0x1d: "Invalid attribute value list",
        0x1e: "Embedded service error",
        0x1f: "Vendor specific error",
        0x20: "Invalid parameter",
        0x21: "Write-once value or medium already written",
        0x22: "Invalid reply received",
        0x23: "Buffer overflow",
        0x24: "Invalid message format",
        0x25: "Key failure in path",
        0x26: "Path size invalid",
        0x27: "Unexpected attribute in list",
        0x28: "Invalid Member ID",
        0x29: "Member not settable",
        0x2a: "Group 2 only server general failure",
        0x2b: "Unknown Modbus error",
        0x2c: "Attribute not gettable",
    }

    fields_desc = [
        scapy_all.XByteField("reserved", 0),  # Reserved byte, always null
        scapy_all.ByteEnumField("status", 0, ERROR_CODES),
        scapy_all.XByteField("additional_size", 0),
        scapy_all.StrLenField("additional", "",  # additional status
                              length_from=lambda p: 2 * p.additional_size),
    ]


    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return "", p

    def __repr__(self):
        if self.reserved != 0:
            return scapy_all.Packet.__repr__(self)

        # Known status
        if self.status in self.ERROR_CODES and self.additional_size == 0:
            return "<CIP_ResponseStatus  status={}>".format(self.ERROR_CODES[self.status])

        # Simple status
        if self.additional_size == 0:
            return "<CIP_ResponseStatus  status=%#x>" % self.status

        # Forward Open failure
        if self.status == 1 and self.additional == b"\x00\x01":
            return "<CIP_ResponseStatus  status=Connection failure>"
        return scapy_all.Packet.__repr__(self)


class CIP(scapy_all.Packet):
    name = "CIP"

    SERVICE_CODES = {
        0x01: "Get_Attribute_All",
        0x02: "Set_Attribute_All",
        0x03: "Get_Attribute_List",
        0x04: "Set_Attribute_List",
        0x05: "Reset",
        0x06: "Start",
        0x07: "Stop",
        0x08: "Create",
        0x09: "Delete",
        0x0a: "Multiple_Service_Packet",
        0x0d: "Apply_attributes",
        0x0e: "Get_Attribute_Single",
        0x10: "Set_Attribute_Single",
        0x4b: "Execute_PCCC_Service",  # PCCC = Programmable Controller Communication Commands
        0x4c: "Read_Tag_Service",
        0x4d: "Write_Tag_Service",
        0x4e: "Forward_Close", # Forward Close/ "Read_Modify_Write_Tag_Service"
        0x4f: "Read_Other_Tag_Service",  # ???
        0x52: "Unconnected_Send", # Unconnected Send/Read_Tag_Fragmented_Service
        0x53: "Write_Tag_Fragmented_Service",
        0x54: "Forward_Open",
    }

    fields_desc = [
        scapy_all.BitEnumField("direction", None, 1, {0: "request", 1: "response"}),
        utils.XBitEnumField("service", 0, 7, SERVICE_CODES),
        scapy_all.PacketListField("path", [], CIP_Path,
                                  count_from=lambda p: 1 if p.direction == 0 else 0),
        scapy_all.PacketListField("status", [], CIP_ResponseStatus,
                                  count_from=lambda p: 1 if p.direction == 1 else 0),
    ]

    def post_build(self, p, pay):
        is_response = (self.direction == 1)
        if self.direction is None and not self.path:
            # Transform the packet into a response
            p = "\x01" + p[1:]
            is_response = True

        if is_response:
            # Add a success status field if there was none
            if not self.status:
                p = p[0:1] + b"\0\0\0" + p[1:]
        return p + pay


class _CIPMSPPacketList(scapy_all.PacketListField):
    """The list of packets in a CIP MultipleServicePacket message"""

    def getfield(self, pkt, remain):
        lst = []
        pkt_count = pkt.count
        cur_offset = 2 + 2 * pkt_count
        shift = pkt.offsets[0] - cur_offset
        if shift > 0:
            # There is some padding between the CIP MSP header and the first packet
            lst.append(scapy_all.conf.raw_layer(load=remain[:shift]))
            remain = remain[shift:]
        cur_offset += shift
        for off in pkt.offsets[1:]:
            # Decode packet remain[:off - cur_offset]
            try:
                p = self.m2i(pkt, remain[:off - cur_offset])
            except Exception:
                if scapy_all.conf.debug_dissector:
                    raise
                p = scapy_all.conf.raw_layer(load=remain[:off - cur_offset])
            remain = remain[off - cur_offset:]
            lst.append(p)
            cur_offset = off

        if remain:
            # Last packet contains all the remaining data
            try:
                p = self.m2i(pkt, remain)
            except Exception:
                if scapy_all.conf.debug_dissector:
                    raise
                p = scapy_all.conf.raw_layer(load=remain)
            lst.append(p)
        return "", lst


class CIP_ConnectionParam(scapy_all.Packet):
    """CIP Connection parameters"""
    name = "CIP_ConnectionParam"
    fields_desc = [
        scapy_all.BitEnumField("owner", 0, 1, {0: "exclusive", 1: "multiple"}),
        scapy_all.BitEnumField("connection_type", 2, 2,
                               {0: "null", 1: "multicast", 2: "point-to-point", 3: "reserved"}),
        scapy_all.BitField("reserved", 0, 1),
        scapy_all.BitEnumField("priority", 0, 2, {0: "low", 1: "high", 2: "scheduled", 3: "urgent"}),
        scapy_all.BitEnumField("connection_size_type", 0, 1, {0: "fixed", 1: "variable"}),
        scapy_all.BitField("connection_size", 500, 9),
    ]

    def pre_dissect(self, s):
        b = struct.unpack('<H', s[:2])[0]
        return struct.pack('>H', int(b)) + s[2:]

    def do_build(self):
        # p = ''
        # Corrected issue of malformed packet construction when attempting to
        # communicate with PLC - MED
        p = super(CIP_ConnectionParam, self).do_build()
        return p[::-1] # we have to flip the output

    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return '', p


class CIP_ReqForwardOpen(scapy_all.Packet):
    """Forward Open request"""
    name = "CIP_ReqForwardOpen"

    SEGMENT_TYPE = {
        0x00: "Port Segment",
        0x01: "Logical Segment",
        0x02: "Network Segment",
        0x03: "Symbolic Segment",
        0x04: "Data Segment",
        0x05: "Data Type (constructed)",
        0x06: "Data Type (elementary)",
        0x07: "Reserved for future use",
    }
    # Updated a few field descriptions to adjust how they are displayed
    # Altered fields start with utils. rather than scapy_all. - MED
    fields_desc = [
        scapy_all.BitField("priority", 0, 4),
        scapy_all.BitField("tick_time", 0, 4),
        scapy_all.ByteField("timeout_ticks", 249),
        utils.XLEIntField("OT_network_connection_id", 0x80000031),
        utils.XLEIntField("TO_network_connection_id", 0x80fe0030),
        scapy_all.LEShortField("connection_serial_number", 0x1337),
        utils.XLEShortField("vendor_id", 0x004d),
        utils.XLEIntField("originator_serial_number", 0xdeadbeef),
        scapy_all.ByteField("connection_timeout_multiplier", 0),
        scapy_all.X3BytesField("reserved", 0),
        utils.XLEIntField("OT_rpi", 0x007a1200),  # 8000 ms
        scapy_all.PacketField('OT_connection_param', CIP_ConnectionParam(), CIP_ConnectionParam),
        utils.XLEIntField("TO_rpi", 0x007a1200),
        scapy_all.PacketField('TO_connection_param', CIP_ConnectionParam(), CIP_ConnectionParam),
        scapy_all.XByteField("transport_type", 0xa3),  # direction server, application object, class 3
        # Changed  name - MED
        scapy_all.ByteField("Connection_Path_Size", None),  #The number of 16 bit words in the Connection_Path field.
        scapy_all.PacketListField("path_segment_items", [], CIP_PathPadded, length_from=lambda p: 2 * p.Connection_Path_Size),
        # Modified Implementation - MED
        # scapy_all.PacketListField("path_segment_items", [], CIP_PathPadded,
        #                           length_from=lambda p: 6),
        # scapy_all.PacketListField("path_segment_items", [], CIP_PathPadded,
        #                           length_from=lambda p: 10),
        # scapy_all.PacketField("path", CIP_Path1(), CIP_Path1)
        #CIP_PathField("path", None, length_from=lambda p: 2 * p.Connection_Path_Size),
    ]


    def extract_padding(self, p):
        # print self.__class__.__name__ + ": P=" + str(p)
        return  '', p


class CIP_RespForwardOpen(scapy_all.Packet):
    """Forward Open response"""
    name = "CIP_RespForwardOpen"
    fields_desc = [
        scapy_all.LEIntField("OT_network_connection_id", None),
        scapy_all.LEIntField("TO_network_connection_id", None),
        scapy_all.LEShortField("connection_serial_number", None),
        scapy_all.LEShortField("vendor_id", None),
        scapy_all.LEIntField("originator_serial_number", None),
        scapy_all.LEIntField("OT_api", None),
        scapy_all.LEIntField("TO_api", None),
        scapy_all.ByteField("application_reply_size", None),
        scapy_all.XByteField("reserved", 0),
    ]


class CIP_ReqForwardClose(scapy_all.Packet):
    """Forward Close request"""
    name = "CIP_ReqForwardClose"
    fields_desc = [
        scapy_all.XByteField("priority_ticktime", 0),
        scapy_all.ByteField("timeout_ticks", 249),
        scapy_all.LEShortField("connection_serial_number", 0x1337),
        scapy_all.LEShortField("vendor_id", 0x004d),
        scapy_all.LEIntField("originator_serial_number", 0xdeadbeef),
        scapy_all.ByteField("path_wordsize", None),
        scapy_all.XByteField("reserved", 0),
        # CIP_PathField("path", None, length_from=lambda p: 2 * p.path_wordsize), # Original Implementation by Scy-Phy
        scapy_all.PacketListField("path_segment_items", [], CIP_PathPadded, length_from=lambda p: 2 * p.path_wordsize)
    ]

class CIP_RespForwardClose(scapy_all.Packet):
    """Forward Close Response"""
    name = "CIP_RespForwardClose"
    fields_desc = [
        scapy_all.LEShortField('connection_serial_number',0x1337),
        scapy_all.LEShortField('vendor_id', 0x004d),
        scapy_all.LEIntField('originator_serial_number', 0xdeadbeef),
        scapy_all.ByteField('application_reply_size', 0),
        scapy_all.ByteField('reserved', 0),
        scapy_all.FieldListField('application_reply', 0, scapy_all.ShortField('',0), count_from=lambda p: p.application_reply_size)
    ]

class CIP_MultipleServicePacket(scapy_all.Packet):
    """Multiple_Service_Packet request or response"""
    name = "CIP_MultipleServicePacket"
    fields_desc = [
        utils.LEShortLenField("count", None, count_of="packets"),
        scapy_all.FieldListField("offsets", [], scapy_all.LEShortField("", 0),
                                 count_from=lambda pkt: pkt.count),
        # Assume the offsets are increasing, and no padding. FIXME: remove this assumption
        _CIPMSPPacketList("packets", [], CIP)
    ]

    def do_build(self):
        """Build the packet by concatenating packets and building the offsets list"""
        # Build the sub packets
        subpkts = [str(pkt) for pkt in self.packets]
        # Build the offset lists
        current_offset = 2 + 2 * len(subpkts)
        offsets = []
        for p in subpkts:
            offsets.append(struct.pack("<H", current_offset))
            current_offset += len(p)
        return struct.pack("<H", len(subpkts)) + "".join(offsets) + "".join(subpkts)


class CIP_ReqConnectionManager(scapy_all.Packet):
    fields_desc = [
        scapy_all.BitField("reserved", 0, 3),
        scapy_all.BitField("priority", 0, 1),
        scapy_all.BitField("ticktime", 5, 4),
        scapy_all.ByteField("timeout_ticks", 157),
        utils.LEShortLenField("message_size", None, length_of="message"),
        scapy_all.PacketLenField("message", None, CIP,
                                 length_from=lambda pkt: pkt.message_size),
        scapy_all.StrLenField("message_padding", None,
                              length_from=lambda pkt: pkt.message_size % 2),
        scapy_all.ByteField("route_path_size", 1),  # TODO: size in words
        scapy_all.ByteField("reserved2", 0),
        scapy_all.ByteField("route_path_size_port", 1),
        scapy_all.ByteField("route_path_size_addr", 0),
    ]

    def post_build(self, p, pay):
        # Autofill the padding
        if len(p) % 2:
            p = p[:-4] + b"\0" + p[-4:]
        return p + pay

class CIP_GenericClass(scapy_all.Packet):
    name = "CIP_GenericClass"
    fields_desc = [
        scapy_all.StrField("data", None)
    ]


# Updated to fit with new code organization
# scapy_all.bind_layers(enip.ENIP_ConnectionPacket, CIP)
scapy_all.bind_layers(enip_cpf.CPF_DataItem, CIP, type_id=0x00b2) #0x00B2 : "Unconnected Data Item"
scapy_all.bind_layers(enip_cpf.CPF_Item, CIP, type_id=0x00b2) #0x00B2 : "Unconnected Data Item"

scapy_all.bind_layers(enip.ENIP_SendUnitData_Item, CIP, type_id=0x00b2)
scapy_all.bind_layers(enip.ENIP_SendUnitData_Item, CIP, type_id=0x00b1)

scapy_all.bind_layers(enip.ENIP_ConnectionPacket, CIP)

scapy_all.bind_layers(CIP, CIP_RespAttributesAll, direction=1, service=0x01)
scapy_all.bind_layers(CIP, CIP_ReqGetAttributeList, direction=0, service=0x03)
scapy_all.bind_layers(CIP, CIP_RespAttributesList, direction=1, service=0x03)
scapy_all.bind_layers(CIP, CIP_MultipleServicePacket, service=0x0a)
scapy_all.bind_layers(CIP, CIP_RespSingleAttribute, direction=1, service=0x0e)
scapy_all.bind_layers(CIP, CIP_ReqReadOtherTag, direction=0, service=0x4c)
scapy_all.bind_layers(CIP, CIP_ReqForwardClose, direction=0, service=0x4e)
scapy_all.bind_layers(CIP, CIP_RespForwardClose, direction=1, service=0x4e)
scapy_all.bind_layers(CIP, CIP_ReqReadOtherTag, direction=0, service=0x4f)
scapy_all.bind_layers(CIP, CIP_ReqForwardOpen, direction=0, service=0x54)
scapy_all.bind_layers(CIP, CIP_RespForwardOpen, direction=1, service=0x54)

# Unknown services on network
scapy_all.bind_layers(CIP, CIP_GenericClass, service=0x4b)
scapy_all.bind_layers(CIP, CIP_GenericClass, service=0x4c)
scapy_all.bind_layers(CIP, CIP_GenericClass, service=0x5c)


# TODO: this is much imprecise :(
# Need class in path to be 6 (Connection Manager)
scapy_all.bind_layers(CIP, CIP_ReqConnectionManager, direction=0, service=0x52)

if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a CIP Get Attribute All request
    path = CIP_Path.make(class_id=1, instance_id=1)
    assert str(path) == b"\x03\x20\x01\x25\x00\x01\x00"
    pkt = CIP(service=1, path=path)
    pkt = CIP(str(pkt))
    pkt.show()
    assert pkt[CIP].direction == 0
    assert pkt[CIP].path[0] == path

    # Build a CIP Get_Attribute_List response
    pkt = CIP() / CIP_RespAttributesList(count=1, content="test")
    pkt = CIP(str(pkt))
    pkt.show()
    assert pkt[CIP].direction == 1
    assert pkt[CIP].service == 0x03
    assert pkt[CIP].status[0].reserved == 0
    assert pkt[CIP].status[0].status == 0
    assert pkt[CIP].status[0].additional_size == 0
    assert pkt[CIP].status[0].additional == ""
    assert pkt[CIP].payload == pkt[CIP_RespAttributesList]
    assert pkt[CIP_RespAttributesList].count == 1
    assert pkt[CIP_RespAttributesList].content == "test"

    # Build a Multiple Service Packet Request
    pkt = CIP(path=CIP_Path.make(class_id=2, instance_id=1))
    pkt /= CIP_MultipleServicePacket(packets=[
        CIP(path=CIP_Path.make(class_id=0x70, instance_id=1)) / CIP_ReqGetAttributeList(attrs=[1, 2]),
        CIP(service=0x0e, path=CIP_Path.make(class_id=0x8e, instance_id=1, attribute_id=0x1b)),
    ])
    pkt = CIP(str(pkt))
    pkt.show()
    assert pkt[CIP].direction == 0
    assert pkt[CIP].service == 0x0a
    assert pkt[CIP].path[0] == CIP_Path.make(class_id=2, instance_id=1)
    assert pkt[CIP].payload == pkt[CIP_MultipleServicePacket]
    assert pkt[CIP_MultipleServicePacket].count == 2
    assert pkt[CIP_MultipleServicePacket].offsets == [6, 20]
    assert pkt[CIP_MultipleServicePacket].packets[0].service == 0x03
    assert pkt[CIP_MultipleServicePacket].packets[0].payload.count == 2
    assert pkt[CIP_MultipleServicePacket].packets[0].payload.attrs == [1, 2]
    assert pkt[CIP_MultipleServicePacket].packets[1].service == 0x0e