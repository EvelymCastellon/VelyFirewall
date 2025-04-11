from scapy.fields import *
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
import struct

class Diameter(Packet):
    name = "Diameter"
    fields_desc = [
        ByteField("version", 1),
        ThreeBytesField("length", None),
        FlagsField("flags", 0, 8, ['R','P','E','T','r','r','r','r']),
        ThreeBytesField("command_code", 257),
        IntField("application_id", 0),
        IntField("hop_by_hop_id", 0),
        IntField("end_to_end_id", 0)
    ]
    
    def post_build(self, p, pay):
        if self.length is None:
            length = len(p) + len(pay)
            p = p[:1] + struct.pack("!I", length)[1:] + p[4:]
        return p + pay

class AVP(Packet):
    name = "AVP"
    fields_desc = [
        IntField("avp_code", 0),
        FlagsField("avp_flags", 0, 8, ['V','M','P','r','r','r','r','r']),
        ThreeBytesField("avp_length", None),
        IntField("vendor_id", 0),
        StrLenField("data", "", length_from=lambda x: x.avp_length - 12 if x.avp_flags & 0x80 == 0 else x.avp_length - 16)
    ]
    
    def post_build(self, p, pay):
        if self.avp_length is None:
            length = len(p) + len(pay)
            p = p[:4] + struct.pack("!I", length)[1:] + p[6:]
        return p + pay

bind_layers(TCP, Diameter, dport=3868)
bind_layers(TCP, Diameter, sport=3868)
bind_layers(Diameter, AVP)
bind_layers(AVP, AVP)

