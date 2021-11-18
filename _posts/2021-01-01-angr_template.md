---
layout: post
title: Angr template
categories: [Reversing, Template]
published: true
---

```python
import angr

import angr
import claripy
import logging
#logging.getLogger('angr').setLevel('INFO')

start_address = 0
success_address = 0

base_address = 0x0
input_length = 8

input_chars = [claripy.BVS('input_%d' % i, 8) for i in range(input_length)]
program_input = claripy.Concat( *input_chars + [claripy.BVV(b'\n')]) 

p = angr.Project("./src/binary", main_opts={'base_addr': base_address})

state = p.factory.entry_state(
        args=['./src/binary'],
        add_options=angr.options.unicorn,
        stdin=program_input,
        addr=start_address
)

#state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
#state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

# Has to be printable characters
for k in input_chars:
    state.solver.add(k <= ord('~'))
    state.solver.add(k >= ord('!'))

sm = p.factory.simulation_manager(state)

#sm.explore(find=success_address, avoid=avoid_address)
#sm.explore(find=success_address)
#sm.explore(find=lambda s: b"Thanks!" in s.posix.dumps(1))

if (len(sm.found) > 0):
    for found in sm.found:
        print(found.posix.dumps(0))
        print(sm.found.__str__())
else:
    print("not found")

print("done")
```
