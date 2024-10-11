#
# This file is part of LiteEth.
#
# Copyright (c) 2015-2023 Florent Kermarrec <florent@enjoy-digital.fr>
# SPDX-License-Identifier: BSD-2-Clause

from collections import OrderedDict

from litex.gen import *

from liteeth.common import *

from litex.soc.interconnect.packet import Arbiter, Dispatcher

# Crossbar -----------------------------------------------------------------------------------------

class LiteEthCrossbar(LiteXModule):
    def __init__(self, master_port, dispatch_param, dw=8):
        self.users  = OrderedDict()
        self.master = master_port(dw)
        self.dispatch_param = dispatch_param

    # overload this in derived classes
    def get_port(self, *args, **kwargs):
        pass

    def do_finalize(self):
        # TX arbitrate
        sinks = [port.sink for port in self.users.values()]
        self.arbiter = Arbiter(sinks, self.master.source)

        # RX dispatch
        sources = [port.source for port in self.users.values()]
        self.dispatcher = Dispatcher(self.master.sink, sources, one_hot=True)
        dispatch_sig = getattr(self.master.sink, self.dispatch_param)
        cases = {}
        for i, (k, v) in enumerate(self.users.items()):
            cases[k] = self.dispatcher.sel.eq(2**i)
        if type(self.dispatch_param) is list:
            params = [getattr(self.master.sink, param) for param in self.dispatch_param]
            self.comb += Case(Cat(*params), cases)
        else:
            self.comb += Case(getattr(self.master.sink, self.dispatch_param), cases)
