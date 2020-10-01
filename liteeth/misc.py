from functools import reduce
from operator import or_

from migen import Module, Signal, Array, If, bits_for

class FatHash(Module):
    """A resource consuming hash table
    Store key-value pairs and search them in a single clock cycle
    Use an array of memory, and search them with N comparators, where
    N is the size of the array

    Parameters
    ----------
    kw         : Width of the key
    vw         : Width of the values
    reset_vals : Reset time key-value pairs
    depth      : N

    Signals
    -------
    load       : Load the value from self.i into the memory
    load_index : A counter that maintains an index into the memory
    depth      : Number of keys
    search_val : Lookup key
    result     : The corresponding entry of search_val
    """
    def __init__(self, kw=32, vw=32, reset_vals=[0], depth=1):
        mem = Array(Signal(kw + vw, reset=reset_vals[i]) for i in range(depth))
        self.i = Signal(kw + vw)
        self.load = load = Signal(reset=0)
        self.search_val = Signal(kw)
        self.result = Signal(kw + vw)
        load_index = Signal(bits_for(depth))
        results_maybe = []
        for i in range(depth):
            value_maybe = Signal(vw+kw)
            self.comb += [
                If(mem[i][vw:] == self.search_val,
                   value_maybe.eq(mem[i]))
                .Else(value_maybe.eq(0))
            ]
            results_maybe.append(value_maybe)

        self.comb += self.result.eq(reduce(or_, results_maybe))

        self.sync += [
            If(load,
               load_index.eq(load_index+1),
               mem[load_index].eq(self.i)),
        ]


def fathash_test(dut):
    for cycle in range(20):
        yield dut.search_val.eq(0x12341235)
        if cycle == 3:
            yield dut.i.eq(0x1234123556785679abcd)
            yield dut.load.eq(1)
        if cycle == 4:
            yield dut.load.eq(0)
        if cycle == 5:
            yield dut.i.eq(0x234123556785679abcde)
            yield dut.load.eq(1)
        if cycle == 6:
            yield dut.load.eq(0)
        if cycle == 7:
            yield dut.search_val.eq(0x23412356)
        yield


if __name__ == "__main__":
    from migen import run_simulation
    dut = FatHash(vw=48, reset_vals=[0,0], depth=2)
    run_simulation(dut, fathash_test(dut), vcd_name="fathash.vcd")
