# -*- coding: utf-8 -*-.

from __future__ import print_function
from elftools.elf.elffile import ELFFile
import sys

from capstone import *

sys.path[0:0] = ['.', '..']


def get_dwarfinfo(file_name):
    with open(file_name, 'rb') as f:
        elffile = ELFFile(f)
        dwarfinfo = elffile.get_dwarf_info()
        get_text_disassemble(elffile)
        return dwarfinfo


def print_debug(file_name):
    dwarfinfo = get_dwarfinfo(file_name)
    diedict = get_offset2DIE(dwarfinfo)
    print(dir(dwarfinfo))
    print(dir(dwarfinfo.structs))
    for compile_unit in dwarfinfo.iter_CUs():
        print('# CU ------------------------------')
        for die in compile_unit.iter_DIEs():
            # print('At offset ' + str(die.offset) + ':')
            if (die.tag == 'DW_TAG_subprogram'):
                print(dir(die.dwarfinfo))
                print(get_subprogram(die, diedict))


def get_offset2DIE(dwarfinfo):
    result = {}
    compile_unit_number = 0
    for compile_unit in dwarfinfo.iter_CUs():
        for die in compile_unit.iter_DIEs():
            result[die.offset] = die
        compile_unit_number += 1
        if compile_unit_number == 2:
            raise Exception
    return result


def get_type(die, diedict):
    """
    Only some tags matter. Recurse to parse full type modifiers.

    'diedict' is a mapping from offset -> DIE (obtained with 'get_offset2DIE')

    Returns the simplified name of the type (like int, void, or func_ptr)

    See DWARF Format Version 5 section "5 Type Entries"
    """

    # Setup
    typedict = {}
    typedict['pointer_level'] = 0
    typedict['func_ptr'] = False
    typedict['base_name'] = None

    def get_type_recursive(die, diedict, typedict):
        if die.tag == 'DW_TAG_base_type':
            typedict['base_name'] = die.attributes['DW_AT_name'].value

        elif die.tag == 'DW_TAG_pointer_type':
            typedict['pointer_level'] += 1
            get_type_recursive(diedict[die.attributes['DW_AT_type'].value],
                               diedict, typedict)

        elif die.tag == 'DW_TAG_typedef':
            get_type_recursive(diedict[die.attributes['DW_AT_type'].value],
                               diedict, typedict)

        elif die.tag == 'DW_TAG_structure_type':
            typedict['base_name'] = 'struct ' + \
                die.attributes['DW_AT_name'].value

        elif die.tag == 'DW_TAG_union_type':
            typedict['base_name'] = 'union ' + \
                die.attributes['DW_AT_name'].value

        elif die.tag == 'DW_TAG_enumeration_type':
            typedict['base_name'] = 'enum ' + \
                die.attributes['DW_AT_name'].value

        elif die.tag == 'DW_TAG_subroutine_type':
            typedict['func_ptr'] = True

        elif die.tag == 'DW_TAG_array_type':
            raise Exception('Should not find any array types')

        else:
            get_type_recursive(diedict[die.attributes['DW_AT_type'].value],
                               diedict, typedict)

    get_type_recursive(die, diedict, typedict)

    if (typedict['func_ptr']):
        return 'func_ptr'
    else:
        return typedict['base_name'] + '*'*typedict['pointer_level']


def get_subprogram(die, diedict):
    """
    'diedict' is a mapping from offset -> DIE (obtained with 'get_offset2DIE')
    """
    subroutine = {}
    subroutine['name'] = die.attributes['DW_AT_name'].value
    try:
        subroutine['ret_type'] = get_type(
            diedict[die.attributes['DW_AT_type'].value], diedict)
    except:
        subroutine['ret_type'] = 'void'
    subroutine['num_args'] = 0
    subroutine['args_type'] = []

    lowpc = die.attributes['DW_AT_low_pc'].value
    # high_pc may either be relative or absolute
    if die.attributes['DW_AT_high_pc'].form == 'DW_FORM_data8':
        highpc = lowpc + die.attributes['DW_AT_high_pc'].value - 1
    else:
        highpc = die.attributes['DW_AT_high_pc'].value - 1
    subroutine['boundaries'] = (lowpc, highpc)

    for parameter_die in die.iter_children():
        if parameter_die.tag == 'DW_TAG_formal_parameter':
            subroutine['num_args'] += 1
            subroutine['args_type'].append(get_type(parameter_die, diedict))

    return subroutine


def get_text_disassemble(elffile):
    code = elffile.get_section_by_name('.text')
    ops = code.data()
    addr = code['sh_addr']
    md = md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(ops, addr):
        bytes = []
        for byte in i.bytes:
            bytes.append(int(byte))
        print('0x{0:x}:\t{1}\t{2}\t{2}'.format(i.address, bytes, i.mnemonic, i.op_str))


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            print_debug(filename)
