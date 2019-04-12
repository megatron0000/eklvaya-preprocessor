# -*- coding: utf-8 -*-.

from __future__ import print_function
from elftools.elf.elffile import ELFFile
import sys

sys.path[0:0] = ['.', '..']


def process_file(file_name):
    base_types = {}
    subprograms = {}
    with open(file_name, 'rb') as f:
        elffile = ELFFile(f)
        # for section in elffile.iter_sections():
        #     print(section)
        #     # print(dir(section))
        #     try:
        #         for symbol in section.iter_symbols():
        #             print(symbol)
        #             print(symbol.entry)
        #             print(symbol.name)
        #     except:
        #         pass
        #     print('\n')
        # print('----------------------------------------------------')
        # for segment in elffile.iter_segments():
        #     print(segment)
        #     print(dir(segment))
        #     print(segment.header)
        #     print(segment.data.im_class)
        #     print(segment.data.im_func)
        #     print('\n')
        dwarfinfo = elffile.get_dwarf_info()
        print(dir(dwarfinfo))
        print(dwarfinfo.has_debug_info)
        print('--------------')
        for compile_unit in dwarfinfo.iter_CUs():
            print('#1 CU ------------------------------')
            for die in compile_unit.iter_DIEs():
                print('At offset ' + str(die.offset) + ':')
                print(die)
                  
                # print('### dir(die)')
                # print(dir(die))
                # print('\n')

                # print('### die.tag --------------------------')
                # print(die.tag)
                # print('\n')

                # print('### die.attributes ------------------------ ')
                # print(die.attributes)
                # print('\n')
                # if die.tag == 'DW_TAG_subprogram': # queremos só funções
                #     print(die)

            # get all types first
            types_processed = {}
            for die in compile_unit.iter_DIEs():
                if die.tag == 'DW_TAG_base_type':
                    # die.offset is an address and identifies this type (appears in DIEs
                    # of formal_parameters of this type)
                    # .value is the name string of the type
                    base_types[die.offset] = die.attributes['DW_AT_name'].value
                elif die.tag == '':
                  pass

            # get all subprograms
            subprogram = None
            building_function = False
            for die in compile_unit.iter_DIEs():
                if die.tag == 'DW_TAG_subprogram':
                    building_function = True
                    subprogram = {
                        'name': die.attributes['DW_AT_name'].value,
                        'args': [],  # only type names
                        'ret_type': base_types[die.attributes['DW_AT_type'].value]
                    }
                elif die.tag == 'DW_TAG_formal_parameter':
                    print(subprogram['name'])
                    print(base_types)
                    subprogram['args'].append(
                        base_types[die.attributes['DW_AT_type'].value])
                elif building_function:
                    building_function = False
                    subprograms[subprogram['name']] = {
                        'args_type': subprogram['args'],
                        'num_args': len(subprogram['args']),
                        'ret_type': subprogram['ret_type'],
                    }
                    subprogram = None


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)
