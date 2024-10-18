#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr>
# SPDX-License-Identifier: BSD-2-Clause

from litex.gen import *

from liteeth.common import *
from liteeth.crossbar import LiteEthCrossbar

from liteeth.packet import Depacketizer, Packetizer

# IP Crossbar --------------------------------------------------------------------------------------

class LiteEthIPV4MasterPort:
    def __init__(self, dw):
        self.dw     = dw
        self.source = stream.Endpoint(eth_ipv4_user_description(dw))
        self.sink   = stream.Endpoint(eth_ipv4_user_description(dw))


class LiteEthIPV4SlavePort:
    def __init__(self, dw):
        self.dw     = dw
        self.sink   = stream.Endpoint(eth_ipv4_user_description(dw))
        self.source = stream.Endpoint(eth_ipv4_user_description(dw))


class LiteEthIPV4UserPort(LiteEthIPV4SlavePort):
    def __init__(self, dw):
        LiteEthIPV4SlavePort.__init__(self, dw)


class LiteEthIPV4Crossbar(LiteEthCrossbar):
    def __init__(self, dw=8):
        LiteEthCrossbar.__init__(self, LiteEthIPV4MasterPort, "protocol", dw)

    def get_port(self, protocol, dw=8):
        if protocol in self.users.keys():
            raise ValueError("Protocol {0:#x} already assigned".format(protocol))
        port = LiteEthIPV4UserPort(dw)
        self.users[protocol] = port
        return port

# IP Checksum --------------------------------------------------------------------------------------

@ResetInserter()
@CEInserter()
class LiteEthIPV4Checksum(LiteXModule):
    def __init__(self, words_per_clock_cycle=1, skip_checksum=False):
        self.header = Signal(ipv4_header.length*8)
        self.value  = Signal(16)
        self.done   = Signal()

        # # #

        s = Signal(17, reset_less=True)
        r = Signal(17, reset_less=True)
        n_cycles = 0
        for i in range(ipv4_header.length//2):
            if skip_checksum and (i == ipv4_header.fields["checksum"].byte//2):
                pass
            else:
                s_next = Signal(17, reset_less=True)
                r_next = Signal(17, reset_less=True)
                self.comb += s_next.eq(r + self.header[i*16:(i+1)*16])
                r_next_eq = r_next.eq(Cat(s_next[:16]+s_next[16], Signal()))
                if (i%words_per_clock_cycle) != 0:
                    self.comb += r_next_eq
                else:
                    self.sync += If(~self.done, r_next_eq)
                    n_cycles += 1
                s, r = s_next, r_next
        self.comb += self.value.eq(~Cat(r[8:16], r[:8]))

        if not skip_checksum:
            n_cycles += 1
        counter    = Signal(max=n_cycles+1)
        counter_ce = Signal()
        self.sync += If(counter_ce, counter.eq(counter + 1))
        self.comb += counter_ce.eq(~self.done)
        self.comb += self.done.eq(counter == n_cycles)

# IP TX --------------------------------------------------------------------------------------------

class LiteEthIPV4Packetizer(Packetizer):
    def __init__(self, dw=8):
        Packetizer.__init__(self,
            eth_ipv4_description(dw),
            eth_mac_description(dw),
            ipv4_header
        )


class LiteEthIPV4Fragmenter(LiteXModule):
    '''
    IP Fragmenter that respects liteth.common.eth_mtu and breaking up data
    from sink into multiple packets, by manipulating the source which is
    tied into IPV4Packetizer
    TODO:
    1. Further investigate if the DELAY state is necessary.
    2. IP_MTU calculation -30 seems pretty arbitrary, need to find refs
    3. NextValue is it recommended?
    '''
    def __init__(self, dw=8):
        self.sink = sink = stream.Endpoint(eth_ipv4_user_description(dw))
        self.source = source = stream.Endpoint(eth_ipv4_user_description(dw))
        self.comb += sink.connect(source)
        ww = dw // 8
        # counter logic ;)
        counter = Signal(max=16384)
        counter_reset = Signal()
        counter_ce = Signal()
        self.sync += \
            If(counter_reset,
                counter.eq(0)
            ).Elif(counter_ce,
                counter.eq(counter + ww)
            )
        self.mf = mf = Signal(reset=0)  # mf == More Fragments
        self.fragment_offset = fragment_offset = Signal(13, reset=0)
        self.identification = identification = Signal(16, reset=0)
        bytes_in_fragment = Signal(16, reset=0)
        # Making sure we only fragment in blocks of 8 bytes
        IP_MTU = ((eth_mtu - 30 - ipv4_header_length) >> 3) << 3
        self.submodules.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
                sink.ready.eq(1),
                source.length.eq(sink.length),
                If(sink.valid,
                   If(sink.length < IP_MTU,
                       NextValue(mf, 0),
                       NextValue(fragment_offset, 0),
                       NextValue(identification, 0),
                       sink.connect(source)
                   ).Else(
                       sink.ready.eq(0),
                       counter_reset.eq(1),
                       source.length.eq(bytes_in_fragment),
                       NextValue(mf, 1),
                       NextValue(fragment_offset, 0),
                       NextValue(identification, identification + 1),
                       NextValue(bytes_in_fragment, IP_MTU),
                       NextState("FRAGMENTED_PACKET_SEND")
                   )
                )
            )

        fsm.act("FRAGMENTED_PACKET_SEND",
                sink.connect(source, omit={"length"}),
                source.length.eq(bytes_in_fragment),
                If(sink.valid & source.ready,
                   counter_ce.eq(1)
                ),
                If(counter == (bytes_in_fragment - ww),
                   NextValue(fragment_offset,
                             fragment_offset + (bytes_in_fragment >> 3)),
                   source.last.eq(1),
                   source.last_be.eq(0x80),
                   If(((fragment_offset << 3) + counter + ww) == sink.length,
                      NextValue(fragment_offset, 0),
                      NextState("IDLE")
                   ).Else(
                       counter_ce.eq(0),
                       NextState("NEXT_FRAGMENT")
                   )
                )
        )

        fsm.act("NEXT_FRAGMENT",
                counter_ce.eq(0),
                sink.ready.eq(0),
                source.valid.eq(0),
                source.length.eq(bytes_in_fragment),
                If((sink.length - (fragment_offset << 3)) > IP_MTU,
                    NextValue(bytes_in_fragment, IP_MTU),
                    counter_reset.eq(1)
                ).Else(
                    NextValue(bytes_in_fragment,
                              sink.length - (fragment_offset << 3)),
                    NextValue(mf, 0),
                    counter_reset.eq(1)
                ),
                NextState("FRAGMENTED_PACKET_SEND")
        )

        fsm.act("FLUSH_PIPELINE",
                counter_ce.eq(1),
                sink.ready.eq(0),
                source.valid.eq(0),
                source.length.eq(bytes_in_fragment),
                If(counter == (20 << 3),
                   counter_ce.eq(0),
                   counter_reset.eq(1),
                   NextState("FRAGMENTED_PACKET_SEND")
                )
        )



class LiteEthIPTX(LiteXModule):
    def __init__(self, mac_address, ip_address, arp_table, dw=8, with_fragmenter=True, with_buffer=True):

        self.sink   = sink   = stream.Endpoint(eth_ipv4_user_description(dw))
        self.source = source = stream.Endpoint(eth_mac_description(dw))
        self.target_unreachable = Signal()

        # # #
        # Fragmenter  .. TODO: Make it optional
        self.submodules.ip_fragmenter = ip_fragmenter = stream.BufferizeEndpoints(
            {"sink": stream.DIR_SINK})(LiteEthIPV4Fragmenter(dw))

        # Buffer.
        if with_buffer:
            self.buffer = buffer = stream.Buffer(eth_ipv4_user_description(dw))
            self.comb += sink.connect(buffer.sink)
            sink = buffer.source

        # Checksum.
        self.submodules.checksum = checksum = LiteEthIPV4Checksum(skip_checksum=True)
        self.comb += checksum.ce.eq(ip_fragmenter.source.valid)
        self.comb += checksum.reset.eq(source.valid & source.last & source.ready)

        # Packetizer.
        self.submodules.packetizer = packetizer = stream.BufferizeEndpoints(
            {"sink": stream.DIR_SINK,}, pipe_ready=True)(LiteEthIPV4Packetizer(dw))
        self.comb += [
            sink.connect(ip_fragmenter.sink),

            # ip_fragmenter.source.connect(packetizer.sink),

            packetizer.sink.valid.eq(ip_fragmenter.source.valid & checksum.done),
            packetizer.sink.last.eq(ip_fragmenter.source.last),
            packetizer.sink.last_be.eq(ip_fragmenter.source.last_be),
            ip_fragmenter.source.ready.eq(packetizer.sink.ready & checksum.done),
            packetizer.sink.target_ip.eq(ip_fragmenter.source.ip_address),
            packetizer.sink.protocol.eq(ip_fragmenter.source.protocol),
            packetizer.sink.total_length.eq(ip_fragmenter.source.length + ipv4_header.length),
            packetizer.sink.version.eq(0x4),     # ipv4
            packetizer.sink.ihl.eq(0x5),
            packetizer.sink.identification.eq(ip_fragmenter.identification),
            packetizer.sink.flags_offset.eq(Cat(ip_fragmenter.fragment_offset,
                                                ip_fragmenter.mf)),
            packetizer.sink.ttl.eq(0x80),
            packetizer.sink.data.eq(ip_fragmenter.source.data),
            packetizer.sink.sender_ip.eq(ip_address),
            checksum.header.eq(packetizer.header),
            packetizer.sink.checksum.eq(checksum.value)
        ]

        target_mac = Signal(48, reset_less=True)

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            If(packetizer.source.valid,
                # Broadcast.
                If(sink.ip_address[0:8] == bcast_ip_mask,
                    NextValue(target_mac, bcast_mac_address),
                    NextState("SEND")
                # Multicast.
                ).Elif(sink.ip_address[28:] == mcast_ip_mask,
                    NextValue(target_mac, Cat(sink.ip_address[:23], 0, mcast_oui)),
                    NextState("SEND")
                # Unicast.
                ).Else(
                    NextState("SEND_MAC_ADDRESS_REQUEST")
                )
            )
        )
        self.comb += arp_table.request.ip_address.eq(sink.ip_address)
        fsm.act("SEND_MAC_ADDRESS_REQUEST",
            arp_table.request.valid.eq(1),
            If(arp_table.request.valid & arp_table.request.ready,
                NextState("WAIT_MAC_ADDRESS_RESPONSE")
            )
        )
        fsm.act("WAIT_MAC_ADDRESS_RESPONSE",
            If(arp_table.response.valid,
                NextValue(target_mac, arp_table.response.mac_address),
                arp_table.response.ready.eq(1),
                If(arp_table.response.failed,
                    self.target_unreachable.eq(1),
                    NextState("DROP"),
                ).Else(
                    NextState("SEND")
                )
            )
        )
        fsm.act("SEND",
            packetizer.source.connect(source),
            source.ethernet_type.eq(ethernet_type_ip),
            source.target_mac.eq(target_mac),
            source.sender_mac.eq(mac_address),
            If(source.valid & source.last & source.ready,
                NextState("IDLE")
            )
        )
        fsm.act("DROP",
            packetizer.source.ready.eq(1),
            If(packetizer.source.valid &
               packetizer.source.last &
               packetizer.source.ready,
                NextState("IDLE")
            )
        )

# IP RX --------------------------------------------------------------------------------------------

class LiteEthIPV4Depacketizer(Depacketizer):
    def __init__(self, dw=8):
        Depacketizer.__init__(self,
            eth_mac_description(dw),
            eth_ipv4_description(dw),
            ipv4_header
        )


class LiteEthIPRX(LiteXModule):
    def __init__(self, mac_address, ip_address, with_broadcast=True, dw=8):
        self.sink   = sink   = stream.Endpoint(eth_mac_description(dw))
        self.source = source = stream.Endpoint(eth_ipv4_user_description(dw))

        # # #

        # Depacketizer.
        self.submodules.depacketizer = depacketizer = stream.BufferizeEndpoints(
            {"sink": stream.DIR_SINK})(LiteEthIPV4Depacketizer(dw))
        self.comb += sink.connect(depacketizer.sink)

        # Checksum.
        self.checksum = checksum = LiteEthIPV4Checksum(skip_checksum=False)
        self.comb += [
            checksum.header.eq(depacketizer.header),
            checksum.reset.eq(~depacketizer.source.valid),
            checksum.ce.eq(1)
        ]

        # FSM.
        self.fsm = fsm = FSM(reset_state="IDLE")
        fsm.act("IDLE",
            If(depacketizer.source.valid & checksum.done,
                NextState("DROP"),
                If(((depacketizer.source.target_ip == ip_address) | with_broadcast) &
                   (depacketizer.source.version == 0x4) &
                   (depacketizer.source.ihl == 0x5) &
                   (checksum.value == 0),
                   NextState("RECEIVE")
                )
            )
        )
        self.comb += [
            depacketizer.source.connect(source, keep={
                "last",
                "protocol",
                "data",
                "error",
                "last_be"}),
            source.length.eq(depacketizer.source.total_length - ipv4_header_length),
            source.ip_address.eq(depacketizer.source.sender_ip),
        ]
        fsm.act("RECEIVE",
            depacketizer.source.connect(source, keep={"valid", "ready"}),
            If(source.valid & source.ready,
                If(source.last,
                    NextState("IDLE")
                )
            )
        )
        fsm.act("DROP",
            depacketizer.source.ready.eq(1),
            If(depacketizer.source.valid &
               depacketizer.source.last &
               depacketizer.source.ready,
                NextState("IDLE")
            )
        )

# IP -----------------------------------------------------------------------------------------------

class LiteEthIP(LiteXModule):
    def __init__(self, mac, mac_address, ip_address, arp_table, dw=8, with_broadcast=True, vlan_id=False):
        self.submodules.tx = tx = LiteEthIPTX(mac_address, ip_address, arp_table, dw=dw)
        self.submodules.rx = rx = LiteEthIPRX(mac_address, ip_address, with_broadcast, dw=dw)
        if vlan_id:
            assert(type(vlan_id) is int)
            mac_port = mac.crossbar.get_port((vlan_id << 16) | ethernet_type_ip, dw=dw)
            self.comb += [
                mac_port.sink.vid.eq(vlan_id),
                tx.source.connect(mac_port.sink),
                mac_port.source.connect(rx.sink, omit={'dei', 'pcp', 'vid'})
            ]
        else:
            mac_port = mac.crossbar.get_port(ethernet_type_ip, dw)
            self.comb += [
                tx.source.connect(mac_port.sink),
                mac_port.source.connect(rx.sink)
            ]
        self.submodules.crossbar = crossbar = LiteEthIPV4Crossbar(dw)
        self.comb += [
            crossbar.master.source.connect(tx.sink),
            rx.source.connect(crossbar.master.sink)
        ]
