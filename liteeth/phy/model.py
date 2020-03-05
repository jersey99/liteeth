# This file is Copyright (c) 2015-2018 Florent Kermarrec <florent@enjoy-digital.fr>
# License: BSD

from migen import *

from liteeth.common import *


class LiteEthPHYModelCRG(Module, AutoCSR):
    def __init__(self):
        self._reset = CSRStorage()

        # # #

        self.clock_domains.cd_eth_rx = ClockDomain()
        self.clock_domains.cd_eth_tx = ClockDomain()
        self.comb += [
            self.cd_eth_rx.clk.eq(ClockSignal()),
            self.cd_eth_tx.clk.eq(ClockSignal())
        ]

        reset = self._reset.storage
        self.comb += [
            self.cd_eth_rx.rst.eq(reset),
            self.cd_eth_tx.rst.eq(reset)
        ]


class LiteEthPHYModel(Module, AutoCSR):
    def __init__(self, pads, dw=8):
        self.dw = dw
        self.submodules.crg = LiteEthPHYModelCRG()
        self.sink = sink = stream.Endpoint(eth_phy_description(dw))
        self.source = source = stream.Endpoint(eth_phy_description(dw))

        self.comb += [
            pads.source_valid.eq(self.sink.valid),
            pads.source_data.eq(self.sink.data),
            self.sink.ready.eq(1)
        ]

        self.sync += [
            self.source.valid.eq(pads.sink_valid),
            self.source.data.eq(pads.sink_data),
        ]
        self.comb += [
            self.source.last.eq(~pads.sink_valid & self.source.valid),
        ]
