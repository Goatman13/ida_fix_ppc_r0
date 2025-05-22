# ida_fix_ppc_r0
Fix PowerPC ld/std disassembly when RA = 0. According to PPC manuals "If GPR RA is 0, then the EA is Disp.", this is implemented for byte/half/word opcodes, this plugin adds support for ld/std.

Before:

![bef](https://github.com/user-attachments/assets/9585231c-5f73-4ad5-85a0-1d8e141ff65d)

After:

![aft](https://github.com/user-attachments/assets/93f03fbb-3063-402f-85ee-be7e8776a673)

Just throw into IDA plugins directory.
