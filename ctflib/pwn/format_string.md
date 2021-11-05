# Format string exploits

This module supplements pwntools' [fmtstr](https://docs.pwntools.com/en/stable/fmtstr.html) module.

## `find_offset` function
Returns the format string offset

## `read_stack` function
Returns a list of integers corresponding to the elements on the stack indexed by indexes.

## `dump_stack` function
Returns a list of integers corresponding to the elements on the stack.

## `find_canary_offset` function
Finds the offset of the canary in the stack. The canary must be stored in rax and might not work for PIE enabled binaries.

## `leak_pie_base` function
Finds an item on the stack that has a constant offset from the PIE base address and returns its index and offset.
