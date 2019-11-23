# This file is Copyright (c) 2015-2018 Florent Kermarrec <florent@enjoy-digital.fr>
# License: BSD

from liteeth.common import *
from liteeth.frontend.tty import LiteEthTTY

from targets.base import BaseSoC


class TTYSoC(BaseSoC):
    default_platform = "kc705"
    def __init__(self, platform):
        BaseSoC.__init__(self, platform,
            mac_address=0x10e2d5000000,
            ip_address="192.168.1.50")
        self.submodules.tty = LiteEthTTY(self.core.udp, convert_ip("192.168.1.100"), 10000)
        self.comb += self.tty.source.connect(self.tty.sink)


class TTYSoCDevel(TTYSoC):
    def __init__(self, platform):
        from litescope import LiteScopeAnalyzer
        TTYSoC.__init__(self, platform)
        debug = [
            self.tty.sink.valid,
            self.tty.sink.ready,
            self.tty.sink.data,

            self.tty.source.valid,
            self.tty.source.ready,
            self.tty.source.data
        ]
        self.submodules.analyzer = LiteScopeAnalyzer(debug, 4096, csr_csv="test/analyzer.csv")
        self.add_csr("analyzer")

default_subtarget = TTYSoC
