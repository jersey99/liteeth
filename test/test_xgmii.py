#!/usr/bin/env python3

import argparse

from migen import *
from migen.genlib.io import CRG

from litex.build.generic_platform import *
from litex.build.sim import SimPlatform
from litex.build.sim.config import SimConfig

from litex.soc.interconnect import wishbone
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder import *
from litex.soc.cores import uart

from liteeth.common import *
from liteeth.phy.model import LiteEthPHYModel
from liteeth.phy.xgmii import LiteEthPHYXGMII
from liteeth.core import LiteEthUDPIPCore
from liteeth.frontend.etherbone import LiteEthEtherbone

class SimPins(Pins):
    def __init__(self, n=1):
        Pins.__init__(self, "s "*n)


_io = [
    ("sys_clk", 0, SimPins(1)),
    ("sys_rst", 0, SimPins(1)),
    ("serial", 0,
        Subsignal("source_valid", SimPins()),
        Subsignal("source_ready", SimPins()),
        Subsignal("source_data", SimPins(8)),

        Subsignal("sink_valid", SimPins()),
        Subsignal("sink_ready", SimPins()),
        Subsignal("sink_data", SimPins(8)),
     ),
    ("eth_clocks", 0,
        Subsignal("none", SimPins()),
     ),
    ("eth", 0,
        Subsignal("source_valid", SimPins()),
        Subsignal("source_ready", SimPins()),
        Subsignal("source_data", SimPins(8)),

        Subsignal("sink_valid", SimPins()),
        Subsignal("sink_ready", SimPins()),
        Subsignal("sink_data", SimPins(8)),
     ),
    ("eth_clocks", 1,
        Subsignal("none", SimPins()),
     ),
    ("eth", 1,
        Subsignal("source_valid", SimPins()),
        Subsignal("source_ready", SimPins()),
        Subsignal("source_data", SimPins(8)),

        Subsignal("sink_valid", SimPins()),
        Subsignal("sink_ready", SimPins()),
        Subsignal("sink_data", SimPins(8)),
     ),
]


def xgmii_io(dw):
    return [
        ("sys_clk", 0, SimPins(1)),
        ("sys_rst", 0, SimPins(1)),
        ("serial", 0,
         Subsignal("source_valid", SimPins()),
         Subsignal("source_ready", SimPins()),
         Subsignal("source_data", SimPins(8)),
         Subsignal("sink_valid", SimPins()),
         Subsignal("sink_ready", SimPins()),
         Subsignal("sink_data", SimPins(8)),
        ),
        ("eth_clocks", 0,
         Subsignal("none", SimPins()),
        ),
        ("eth", 0,
         Subsignal("tx_data", SimPins(dw)),
         Subsignal("tx_ctl", SimPins(dw//8)),
         Subsignal("rx_data", SimPins(dw)),
         Subsignal("rx_ctl", SimPins(dw//8)),
        ),
        ("eth_clocks", 1,
         Subsignal("none", SimPins()),
        ),
        ("eth", 1,
         Subsignal("source_valid", SimPins()),
         Subsignal("source_ready", SimPins()),
         Subsignal("source_data", SimPins(8)),

         Subsignal("sink_valid", SimPins()),
         Subsignal("sink_ready", SimPins()),
         Subsignal("sink_data", SimPins(8)),
        ),
    ]

class Platform(SimPlatform):
    default_clk_name = "sys_clk"
    default_clk_period = 1000  # ~ 1MHz

    def __init__(self, io=_io):
        SimPlatform.__init__(self, "SIM", io)

    def do_finalize(self, fragment):
        pass

class SimSoC(SoCCore):
    def __init__(self,
                 with_udp=False,
                 mac_address=0x10e2d5000000, ip_address="192.168.1.50",
                 xgmii=False,
                 xgmii_dw=32,
                 platform=Platform(),
                 **kwargs):
        # platform = Platform()
        sys_clk_freq = int(1e6)
        SoCCore.__init__(self, platform, clk_freq=sys_clk_freq,
                          ident="LiteX Simulation", ident_version=True,
                          with_uart=False,
                          **kwargs)
        # crg
        self.submodules.crg = CRG(platform.request("sys_clk"))

        # serial
        self.submodules.uart_phy = uart.RS232PHYModel(
            platform.request("serial"))
        self.submodules.uart = uart.UART(self.uart_phy)
        self.add_csr("uart")
        self.add_interrupt("uart")

        if with_udp:
            # eth phy
            if xgmii:
                self.submodules.ethphy = LiteEthPHYXGMII(
                    self.platform.request("eth_clocks", 0),
                    self.platform.request("eth", 0),
                    model=True,
                    dw=xgmii_dw)
                self.submodules.core = LiteEthUDPIPCore(
                    self.ethphy, mac_address, convert_ip(ip_address),
                    sys_clk_freq, dw=xgmii_dw)
            else:
                self.submodules.ethphy = LiteEthPHYModel(self.platform.request("eth", 0))
                self.submodules.core = LiteEthUDPIPCore(
                    self.ethphy, mac_address, convert_ip(ip_address),
                    sys_clk_freq)
            self.add_csr("ethphy")
            # udp ip

def _udp_port(dw=32):
    return [
        ("udp_sink", 0,
         Subsignal("valid",   Pins(1)),
         Subsignal("last",    Pins(1)),
         Subsignal("ready",   Pins(1)),

         Subsignal("src_port", Pins(16)),
         Subsignal("dst_port", Pins(16)),
         Subsignal("ip_address", Pins(32)),
         Subsignal("length", Pins(16)),

         Subsignal("data", Pins(dw)),
         Subsignal("error", Pins(dw//8))
        ),

        ("udp_source", 0,
         Subsignal("valid",   Pins(1)),
         Subsignal("last",    Pins(1)),
         Subsignal("ready",   Pins(1)),
         Subsignal("src_port", Pins(16)),
         Subsignal("dst_port", Pins(16)),
         Subsignal("ip_address", Pins(32)),
         Subsignal("length", Pins(16)),
         # payload
         Subsignal("data", Pins(dw)),
         Subsignal("error", Pins(dw//8))
        ),
    ]

rgmii_io = [
    ("sys_clock", 0, Pins(1)),
    ("sys_reset", 1, Pins(1)),
    ("rgmii_eth_clocks", 0,
     Subsignal("tx", Pins(1)),
     Subsignal("rx", Pins(1))
    ),
    ("rgmii_eth", 0,
     # Subsignal("rst_n", Pins(1)),
     Subsignal("mdio", Pins(1)),
     Subsignal("mdc", Pins(1)),
     Subsignal("rx_ctl", Pins(1)),
     Subsignal("rx_data", Pins(4)),
     Subsignal("tx_ctl", Pins(1)),
     Subsignal("tx_data", Pins(4))
    ),
] + _udp_port()

def xgmii_io2(dw=32):
    return [
        ("sys_clock", 0, Pins(1)),
        ("sys_reset", 1, Pins(1)),
        ("xgmii_eth_clocks", 0,
         Subsignal("tx", Pins(1)),
         Subsignal("rx", Pins(1))
        ),
        ("xgmii_eth", 0,
         Subsignal("rx_ctl", Pins(dw//8)),
         Subsignal("rx_data", Pins(dw)),
         Subsignal("tx_ctl", Pins(dw//8)),
         Subsignal("tx_data", Pins(dw))
        ),
    ] + _udp_port(dw)

def sim_udp_port(dw=32):
    return [
        ("udp_sink", 0,
         Subsignal("valid",  SimPins(1)),
         Subsignal("last",   SimPins(1)),
         Subsignal("ready",  SimPins(1)),

         Subsignal("src_port", SimPins(16)),
         Subsignal("dst_port", SimPins(16)),
         Subsignal("ip_address", SimPins(32)),
         Subsignal("length", SimPins(16)),

         Subsignal("data", SimPins(dw)),
         Subsignal("error", SimPins(dw//8))
        ),

        ("udp_source", 0,
         Subsignal("valid",  SimPins(1)),
         Subsignal("last",   SimPins(1)),
         Subsignal("ready",  SimPins(1)),

         Subsignal("src_port", SimPins(16)),
         Subsignal("dst_port", SimPins(16)),
         Subsignal("ip_address", SimPins(32)),
         Subsignal("length", SimPins(16)),

         Subsignal("data", SimPins(dw)),
         Subsignal("error", SimPins(dw//8))
        ),
    ]


class UDPSimCore(SimSoC):
    def __init__(self,
                 mac_address,
                 ip_address,
                 port,
                 with_etherbone=False,
                 xgmii=True,
                 xgmii_dw=32,
                 **kwargs):
        if xgmii:
            XGMII_IO = xgmii_io(xgmii_dw) + sim_udp_port(xgmii_dw)
            platform = Platform(XGMII_IO)
            SimSoC.__init__(self,
                            with_udp=True,
                            platform=platform,
                            ip_address=ip_address,
                            mac_address=mac_address,
                            xgmii=xgmii,
                            xgmii_dw=xgmii_dw,
                            **kwargs)
        else:
            RGMII_IO = _io + sim_udp_port()
            platform = Platform(RGMII_IO)
            SimSoC.__init__(self,
                            ip_address=ip_address,
                            mac_address=mac_address,
                            with_udp=True,
                            platform=platform,
                            **kwargs)

        udp_port = self.core.udp.crossbar.get_port(port, xgmii_dw if xgmii else 32)

        if with_etherbone:
            self.submodules.etherbone = LiteEthEtherbone(self.core.udp, 6001, mode="master")
            self.add_wb_master(self.etherbone.wishbone.bus)
            self.submodules.sram = wishbone.SRAM(1024,
                                                 init=[0, 0, 0, 0, 100, 412,
                                                       36, 2**17, 192, 500,
                                                       100, 10, 6, 3])
            self.register_mem("wb_ram", 0x80000, self.sram.bus, size=1024)
        else:
                # XXX avoid manual connect
                udp_sink = self.platform.request("udp_sink")
                sink_length = 0x88
                self.comb += [udp_sink.data.eq(0xc0ffee00c0ffee11 if xgmii else 0xcafecafe),
                              udp_sink.dst_port.eq(7778),
                              udp_sink.length.eq(sink_length),
                              udp_sink.ip_address.eq(convert_ip("192.168.1.101"))]
                self.comb += [
                    # control
                    udp_port.sink.valid.eq(udp_sink.valid),
                    udp_port.sink.last.eq(udp_sink.last),
                    udp_sink.ready.eq(udp_port.sink.ready),

                    # param
                    udp_port.sink.src_port.eq(udp_sink.src_port),
                    udp_port.sink.dst_port.eq(udp_sink.dst_port),
                    udp_port.sink.ip_address.eq(udp_sink.ip_address),
                    udp_port.sink.length.eq(udp_sink.length),

                    # payload
                    udp_port.sink.data.eq(udp_sink.data),
                    udp_port.sink.error.eq(udp_sink.error)
                ]
                udp_source = self.platform.request("udp_source")
                self.comb += [
                    # control
                    udp_source.valid.eq(udp_port.source.valid),
                    udp_source.last.eq(udp_port.source.last),
                    udp_source.ready.eq(1),
                    udp_port.source.ready.eq(udp_source.ready),

                    # param
                    udp_source.src_port.eq(udp_port.source.src_port),
                    udp_source.dst_port.eq(udp_port.source.dst_port),
                    udp_source.ip_address.eq(udp_port.source.ip_address),
                    udp_source.length.eq(udp_port.source.length),

                    # payload
                    udp_source.data.eq(udp_port.source.data),
                    udp_source.error.eq(udp_port.source.error)
                ]

                send_pkt = Signal(reset=0)
                always_xmit = True
                dw = xgmii_dw if xgmii else 32
                shift = log2_int(dw // 8)  # bits required to represent bytes per word
                if always_xmit:
                    send_pkt_counter, send_pkt_counter_d = Signal(17), Signal()
                    self.sync += [send_pkt_counter.eq(send_pkt_counter + 1),
                                  send_pkt_counter_d.eq(send_pkt_counter[16]),
                                  send_pkt.eq(send_pkt_counter_d ^ send_pkt_counter[16])]

                sink_counter = Signal(16)
                self.comb += [udp_sink.valid.eq(sink_counter > 0),
                              udp_sink.last.eq(sink_counter == 1)]
                self.sync += [If(send_pkt, sink_counter.eq(sink_length >> shift)),
                              If((sink_counter > 0) & (udp_sink.ready == 1),
                                 sink_counter.eq(sink_counter - 1))
                ]



def main():
    parser = argparse.ArgumentParser(description="LiteEth core builder")
    builder_args(parser)
    soc_core_args(parser)
    parser.add_argument("--mac_address", default=0x10e2d5000000, help="MAC address")
    parser.add_argument("--ip_address", default="192.168.1.50", help="IP address")
    parser.add_argument("--sim-only", action='store_true', help="Simulation")
    parser.add_argument("--xgmii", action='store_true', help="Generate the XGMII interface")
    parser.add_argument("--with_etherbone", action='store_true', help="Etherbone interface")
    parser.add_argument("--xgmii-dw", type=int, help="32/64 bit width XGMII interface", default=64)
    parser.add_argument("--threads", default=4,
                        help="set number of threads (default=4)")
    parser.add_argument("--trace", action="store_true",
                        help="enable VCD tracing")
    args = parser.parse_args()

    name = "xgmii" if args.xgmii else "rgmii"

    if args.sim_only:
        soc_kwargs = soc_core_argdict(args)
        sim_config = SimConfig(default_clk="sys_clk")
        sim_config.add_module("serial2console", "serial")
        # soc_kwargs = soc_core_argdict(args)
        soc_kwargs["integrated_main_ram_size"] = 0x10000
        sim_config.add_module(
            'xgmii_ethernet' if args.xgmii else 'ethernet',
            "eth",
            args={"interface": "tap1",
                  "ip": "192.168.1.101",
                  "vcd_name": "foo.vcd"})
        soc = UDPSimCore(mac_address=args.mac_address,
                         ip_address="192.168.1.51",
                         port=6000,
                         with_etherbone=args.with_etherbone,
                         xgmii=args.xgmii,
                         xgmii_dw=args.xgmii_dw,
                         **soc_kwargs)
        builder_kwargs = builder_argdict(args)
        builder_kwargs["csr_csv"] = "csr.csv"
        builder = Builder(soc, **builder_kwargs)
        builder.build(
            build=True,
            threads=args.threads,
            trace=args.trace,
            sim_config=sim_config)

if __name__ == "__main__":
    main()
