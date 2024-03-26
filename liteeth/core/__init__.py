#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2020 Florent Kermarrec <florent@enjoy-digital.fr>
# SPDX-License-Identifier: BSD-2-Clause

from liteeth.common import *
from liteeth.mac import LiteEthMAC
from liteeth.core.arp import LiteEthARP
from liteeth.core.ip import LiteEthIP
from liteeth.core.udp import LiteEthUDP
from liteeth.core.icmp import LiteEthICMP

from liteeth.mac.common import LiteEthMACVLANCrossbar, LiteEthMACVLANPacketizer, LiteEthMACVLANDepacketizer

# IP Core ------------------------------------------------------------------------------------------

class LiteEthIPCore(Module, AutoCSR):
    def __init__(self, phy, mac_address, ip_address, clk_freq, with_icmp=True, dw=8):
        ip_address = convert_ip(ip_address)
        self.submodules.mac = LiteEthMAC(phy, dw, interface="crossbar", with_preamble_crc=True)
        self.submodules.arp = LiteEthARP(self.mac, mac_address, ip_address, clk_freq, dw=dw)
        self.submodules.ip  = LiteEthIP(self.mac, mac_address, ip_address, self.arp.table, dw=dw)
        if with_icmp:
            self.submodules.icmp = LiteEthICMP(self.ip, ip_address, dw=dw)

# VLAN CORE
class LiteEthVLANUDPIPCore(Module, AutoCSR):
    def __init__(self, phy, mac_address, ip_address, clk_freq, with_icmp=True, dw=8):
        self.mac_address = mac_address
        self.with_icmp = with_icmp
        self.clk_freq = clk_freq
        self.dw = dw
        ip_address = convert_ip(ip_address)
        self.submodules.mac = LiteEthMAC(phy, dw, interface="crossbar", with_preamble_crc=True)

        self.submodules.arp = LiteEthARP(self.mac, mac_address, ip_address, clk_freq, dw=dw)
        self.submodules.ip  = LiteEthIP(self.mac, mac_address, ip_address, self.arp.table, dw=dw)

        if with_icmp:
            self.submodules.icmp = LiteEthICMP(self.ip, ip_address, dw=dw)

        self.submodules.udp = LiteEthUDP(self.ip, ip_address, dw=dw)

        vlan_mac_port = self.mac.crossbar.get_port(ethernet_8021q_tpid, dw=dw)

        self.submodules.crossbar     = LiteEthMACVLANCrossbar(dw)
        self.submodules.packetizer   = LiteEthMACVLANPacketizer(dw)
        self.submodules.depacketizer = LiteEthMACVLANDepacketizer(dw)

        self.comb += [
            vlan_mac_port.sink.ethernet_type.eq(ethernet_8021q_tpid),
            self.crossbar.master.source.connect(self.packetizer.sink),
            self.packetizer.source.target_mac.eq(self.packetizer.sink.target_mac),
            self.packetizer.source.sender_mac.eq(self.packetizer.sink.sender_mac),
            self.packetizer.source.connect(vlan_mac_port.sink, omit={'ethernet_type'}),
            vlan_mac_port.source.connect(self.depacketizer.sink),
            self.depacketizer.source.connect(self.crossbar.master.sink),
        ]

    def add_vlan(self, vlan_ip="192.168.3.50", vlan_id=2001):
        vlan_ip_address = convert_ip(vlan_ip)
        arp = LiteEthARP(self, self.mac_address, vlan_ip_address,
                                              self.clk_freq, dw=self.dw, vlan_id=vlan_id)
        setattr(self.submodules, f"vlan_{vlan_id}_arp", arp)
        ip  = LiteEthIP(self, self.mac_address, vlan_ip_address,
                        arp.table, dw=self.dw, vlan_id=vlan_id)
        setattr(self.submodules, f"vlan_{vlan_id}_ip", ip)
        if self.with_icmp:
            icmp = LiteEthICMP(ip, vlan_ip_address, dw=self.dw)
            setattr(self.submodules, f"vlan_{vlan_id}_ip", icmp)

        udp = LiteEthUDP(ip, vlan_ip_address, dw=self.dw)
        setattr(self.submodules, f"vlan_{vlan_id}_udp", udp)
        return udp
# UDP IP Core --------------------------------------------------------------------------------------

class LiteEthUDPIPCore(LiteEthIPCore):
    def __init__(self, phy, mac_address, ip_address, clk_freq, with_icmp=True, dw=8):
        ip_address = convert_ip(ip_address)
        LiteEthIPCore.__init__(self, phy, mac_address, ip_address, clk_freq, dw=dw,
                               with_icmp=with_icmp)
        self.submodules.udp = LiteEthUDP(self.ip, ip_address, dw=dw)
