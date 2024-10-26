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
    def __init__(self, master_port, dispatch_param, dw=8, users_is_dict=True):
        self.users  = OrderedDict() if users_is_dict else []
        self.master = master_port(dw)
        self.dispatch_param = dispatch_param

    # overload this in derived classes
    def get_port(self, *args, **kwargs):
        pass

    def do_finalize(self):
        # TX arbitrate
        values = self.users.values() if type(self.users) is OrderedDict else [v for _, v in self.users]
        sinks = [port.sink for port in values]
        self.arbiter = Arbiter(sinks, self.master.source)

        # RX dispatch
        sources = [port.source for port in values]
        self.dispatcher = Dispatcher(self.master.sink, sources, one_hot=True)

        iterable = self.users.items() if type(self.users) is OrderedDict else self.users
        if type(self.dispatch_param) is list:
            params = [getattr(self.master.sink, param) for param in self.dispatch_param]
            dispatch_sig = Cat(*params)
        else:
            dispatch_sig = getattr(self.master.sink, self.dispatch_param)

        for i, (k, v) in enumerate(iterable):
            self.comb += If(dispatch_sig == k, self.dispatcher.sel.eq(2**i))
