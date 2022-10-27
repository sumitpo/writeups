#!/usr/bin/env python

import lief
from lief import ELF
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def decrypt(var, key, byteorder=sys.byteorder):
    int_var = int.from_bytes(var, byteorder)
    int_key = int.from_bytes(key, byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), byteorder)


def pd(code, vs):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(code, vs):
        print("0x%x:\t%-15s %s\t%s" %
              (i.address, i.bytes.hex(),
               i.mnemonic, i.op_str))


def addFuncSym(binary):
    symtab_section = ELF.Section()
    symtab_section.name = ".symtab"
    symtab_section.type = ELF.SECTION_TYPES.SYMTAB
    symtab_section.entry_size = 0x18
    symtab_section.alignment = 8
    symtab_section.link = len(binary.sections) + 1
    symtab_section.content = [0] * 200

    symstr_section = ELF.Section()
    symstr_section.name = ".strtab"
    symstr_section.type = ELF.SECTION_TYPES.STRTAB
    symstr_section.entry_size = 7
    symstr_section.alignment = 1
    symstr_section.content = [0] * 200

    symtab_section = binary.add(symtab_section, loaded=False)
    symstr_section = binary.add(symstr_section, loaded=False)

    symbol = ELF.Symbol()
    symbol.name = "xorCode"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x80480E2
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 34
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    symbol = ELF.Symbol()
    symbol.name = "getPassword"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x8048104
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 52
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    symbol = ELF.Symbol()
    symbol.name = "checkModified"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x8048194
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 57
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    symbol = ELF.Symbol()
    symbol.name = "write"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x80481CD
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 8
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    symbol = ELF.Symbol()
    symbol.name = "read"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x80481D5
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 8
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    symbol = ELF.Symbol()
    symbol.name = "exit"
    symbol.type = ELF.SYMBOL_TYPES.FUNC
    symbol.value = 0x80481DD
    symbol.binding = ELF.SYMBOL_BINDINGS.LOCAL
    symbol.size = 7
    symbol.shndx = 1
    symbol = binary.add_static_symbol(symbol)

    return 0


def main():
    binary = lief.parse("./ch13")

    textS = None
    for s in binary.sections:
        if s.name == ".text":
            textS = s

    print(textS.name, hex(textS.offset), hex(textS.size),
          hex(textS.virtual_address), textS.content.hex())

    opcode = textS.content.tobytes()
    vs = 0x8048104
    ve = 0x80482e8
    rs = vs - textS.virtual_address + textS.offset
    re = ve - textS.virtual_address + textS.offset

    xorv = b'\xc1\x8f\x04\x08'
    decoded = opcode[0:rs-textS.offset]
    for offset in range(rs - textS.offset, re - textS.offset, 4):
        '''
        print(offset, opcode[offset:offset+4].hex(),
              decrypt(opcode[offset:offset+4], xorv))
        '''
        decoded += decrypt(opcode[offset:offset+4], xorv)
    decoded += opcode[re - textS.offset:textS.size]

    pd(decoded, vs)

    textS.content = list(decoded)

    '''
    binary.add_exported_function(0x080480E2, "decode_binary")
    binary.add_exported_function(0x08048104, "read_password")
    binary.add_exported_function(0x080481CD, "write")
    binary.add_exported_function(0x080481D5, "read")
    binary.add_exported_function(0x080481DD, "exit")
    '''
    addFuncSym(binary)

    binary.write("./ch13.mod")


if __name__ == "__main__":
    main()
