#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2020 Florent Kermarrec <florent@enjoy-digital.fr>
# Copyright (c) 2023 LumiGuide Fietsdetectie B.V. <goemansrowan@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

from litex.gen import *

from liteeth.common    import *
from liteeth.mac       import LiteEthMAC
from liteeth.core.arp  import LiteEthARP
from liteeth.core.ip   import LiteEthIP
from liteeth.core.udp  import LiteEthUDP
from liteeth.core.icmp import LiteEthICMP

from liteeth.mac.common import LiteEthMACVLANCrossbar, LiteEthMACVLANPacketizer, LiteEthMACVLANDepacketizer

# IP Core ------------------------------------------------------------------------------------------

class LiteEthIPCore(LiteXModule):
    def __init__(self, phy, mac_address, ip_address, clk_freq, arp_entries=1, dw=8,
        with_icmp         = True, icmp_fifo_depth=128,
        with_ip_broadcast = True,
        full_memory_we    = False,
        with_sys_datapath = False,
        tx_cdc_depth      = 32,
        tx_cdc_buffered   = True,
        rx_cdc_depth      = 32,
        rx_cdc_buffered   = True,
        interface         = "crossbar",
        endianness        = "big",
    ):
        # Parameters.
        # -----------
        ip_address = convert_ip(ip_address)

        # MAC.
        # ----
        self.mac = LiteEthMAC(
            phy               = phy,
            dw                = dw,
            interface         = interface,
            endianness        = endianness,
            hw_mac            = mac_address,
            with_preamble_crc = True,
            full_memory_we    = full_memory_we,
            with_sys_datapath = with_sys_datapath,
            tx_cdc_depth      = tx_cdc_depth,
            tx_cdc_buffered   = tx_cdc_buffered,
            rx_cdc_depth      = rx_cdc_depth,
            rx_cdc_buffered   = rx_cdc_buffered
        )

        # ARP.
        # ----
        self.arp = LiteEthARP(
            mac         = self.mac,
            mac_address = mac_address,
            ip_address  = ip_address,
            clk_freq    = clk_freq,
            entries     = arp_entries,
            dw          = dw,
        )

        # IP.
        # ---
        self.ip  = LiteEthIP(
            mac            = self.mac,
            mac_address    = mac_address,
            ip_address     = ip_address,
            arp_table      = self.arp.table,
            with_broadcast = with_ip_broadcast,
            dw             = dw,
        )
        # ICMP (Optional).
        # ----------------
        if with_icmp:
            self.icmp = LiteEthICMP(
                ip         = self.ip,
                ip_address = ip_address,
                dw         = dw,
                fifo_depth = icmp_fifo_depth,
            )

# VLAN CORE
class LiteEthVLANUDPIPCore(LiteXModule):
    def __init__(self, phy, mac_address, ip_address, clk_freq, with_icmp=True, dw=8):
        self.mac_address = mac_address
        self.with_icmp = with_icmp
        self.clk_freq = clk_freq
        self.dw = dw
        ip_address = convert_ip(ip_address)
        self.submodules.mac = LiteEthMAC(phy, dw, interface="crossbar", with_preamble_crc=True)

        self.submodules.arp = LiteEthARP(self.mac, mac_address, ip_address, clk_freq, dw=dw)
        self.submodules.ip  = LiteEthIP(self.mac, mac_address, ip_address, self.arp.table, dw=dw, with_broadcast=False)

        if with_icmp:
            self.submodules.icmp = LiteEthICMP(self.ip, ip_address, dw=dw)

        self.submodules.udp = LiteEthUDP(self.ip, ip_address, dw=dw)

        vlan_mac_port = self.mac.crossbar.get_port(ethernet_8021q_tpid, dw=dw)

        self.submodules.crossbar     = LiteEthMACVLANCrossbar(dw)
        self.submodules.packetizer   = stream.BufferizeEndpoints(
            {"sink": stream.DIR_SINK})(LiteEthMACVLANPacketizer(dw))
        self.submodules.depacketizer = stream.BufferizeEndpoints(
            {"source": stream.DIR_SOURCE})(LiteEthMACVLANDepacketizer(dw))

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
            setattr(self.submodules, f"vlan_{vlan_id}_icmp", icmp)

        udp = LiteEthUDP(ip, vlan_ip_address, dw=self.dw)
        setattr(self.submodules, f"vlan_{vlan_id}_udp", udp)
        return udp
# UDP IP Core --------------------------------------------------------------------------------------

class LiteEthUDPIPCore(LiteEthIPCore):
    def __init__(self, phy, mac_address, ip_address, clk_freq, arp_entries=1, dw=8,
        with_icmp         = True, icmp_fifo_depth=128,
        with_ip_broadcast = True,
        with_sys_datapath = False,
        full_memory_we    = False,
        tx_cdc_depth      = 32,
        tx_cdc_buffered   = True,
        rx_cdc_depth      = 32,
        rx_cdc_buffered   = True,
        interface         = "crossbar",
        endianness        = "big",
    ):
        # Parameters.
        # -----------
        ip_address = convert_ip(ip_address)

        # Core: MAC + ARP + IP + (ICMP).
        # ------------------------------
        LiteEthIPCore.__init__(self,
            phy               = phy,
            mac_address       = mac_address,
            ip_address        = ip_address,
            clk_freq          = clk_freq,
            arp_entries       = arp_entries,
            with_icmp         = with_icmp,
            icmp_fifo_depth   = icmp_fifo_depth,
            dw                = dw,
            interface         = interface,
            endianness        = endianness,
            with_ip_broadcast = with_ip_broadcast,
            with_sys_datapath = with_sys_datapath,
            full_memory_we    = full_memory_we,
            tx_cdc_depth      = tx_cdc_depth,
            tx_cdc_buffered   = tx_cdc_buffered,
            rx_cdc_depth      = rx_cdc_depth,
            rx_cdc_buffered   = rx_cdc_buffered,
        )
        # UDP.
        # ----
        self.udp = LiteEthUDP(
            ip         = self.ip,
            ip_address = ip_address,
            dw         = dw,
        )
