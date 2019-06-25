# -*- coding: utf-8 -*-.

from __future__ import print_function
from elftools.elf.elffile import ELFFile
import sys
from xprint import to_x

from capstone.x86 import X86_OP_IMM
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

import subprocess
import re

import pickle
import os
import os.path as path
import traceback

import random


def get_ELFFile(file_name):
    f = open(file_name, 'rb')
    return ELFFile(f)


def get_dwarfinfo(elffile):
    return elffile.get_dwarf_info()


def print_debug(file_name):
    elffile = get_ELFFile(file_name)
    dwarfinfo = get_dwarfinfo(elffile)
    diedict = get_offset2DIE(dwarfinfo)
    disassemble = get_text_disassemble(elffile)
    # print(dir(dwarfinfo))
    # print(dir(dwarfinfo.structs))
    print('init subprogram finding')
    for compile_unit in dwarfinfo.iter_CUs():
        for die in compile_unit.iter_DIEs():
            print('At offset ' + str(die.offset) + ':')
            print(die)
            if (die.tag == 'DW_TAG_subprogram'):
                # print(dir(die.dwarfinfo))
                print(get_subprogram(die, diedict, disassemble))


def get_all_subprograms_eklavya_format(file_name):
    elffile = get_ELFFile(file_name)
    dwarfinfo = get_dwarfinfo(elffile)
    diedict = get_offset2DIE(dwarfinfo)
    disassemble = get_text_disassemble(elffile)
    result = {}
    for compile_unit in dwarfinfo.iter_CUs():
        for die in compile_unit.iter_DIEs():
            if (die.tag == 'DW_TAG_subprogram'):
                subprogram = get_subprogram(die, diedict, disassemble)
                if subprogram is None:
                    continue
                result[subprogram['name']] = {
                    'ret_type': subprogram['ret_type'],
                    'args_type': subprogram['args_type'],
                    'inst_bytes': subprogram['inst_bytes'],
                    'boundaries': subprogram['boundaries'],
                    'num_args': subprogram['num_args'],
                    'inst_strings': None  # TODO: for the sake of completeness, fill this
                }
    return result


def get_func_call_locations(file_name):
    """
    Generates a list dicts of the form  {call_address: integer, function_name: string}
    which means that the instruction in address 'call_address' is a call to 'function_name'

    The returned list is sorted in ascending address
    """
    result = []
    disassemble_str = subprocess.check_output(
        ['objdump', '--disassemble', file_name])
    # look for lines like "0xblabla: byte byte byte byte... call address <function_name maybe@plt_something>"
    for groups in re.findall(r'([a-f0-9]+):[^\n]+call[^\n]+<([a-zA-Z_][a-zA-Z_0-9]*)(?:\@[^\n]+?)?>', disassemble_str):
        call_address = int(groups[0], 16)
        call_name = groups[1]
        # print(groups[0] + ' ' + groups[1])
        if call_address in result:
            raise Exception
        else:
            result.append({
                'call_address': call_address,
                'function_name': call_name
            })

    result.sort(lambda x, y: x['call_address'] - y['call_address'])
    return result


def get_offset2DIE(dwarfinfo):
    """
    Returns dict keyed by Compilation Unit offsets.
    Each dict-value is another dict mapping an offset to a DIE.
    """
    result = {}
    for compile_unit in dwarfinfo.iter_CUs():
        result[compile_unit.cu_offset] = {}
        # print('# CU ----------------------------')
        for die in compile_unit.iter_DIEs():
            # DIE attributes are CU-relative, thus the need for the subtraction
            result[compile_unit.cu_offset][die.offset -
                                           compile_unit.cu_offset] = die
    return result


def get_type(die, diedict):
    """
    Only some tags matter. Recurse to parse full type modifiers.

    'diedict' is obtained with 'get_offset2DIE'

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
            try:
                subtype = die.attributes['DW_AT_type'].value
            except:
                subtype = None
            if subtype is not None:
                get_type_recursive(diedict[die.cu.cu_offset][subtype],
                                   diedict, typedict)
            else:
                # We have a void* in our hands =)
                typedict['base_name'] = 'void'

        elif die.tag == 'DW_TAG_typedef':
            get_type_recursive(diedict[die.cu.cu_offset][die.attributes['DW_AT_type'].value],
                               diedict, typedict)

        elif die.tag == 'DW_TAG_structure_type':
            struct_name = '<unknown>'
            try:
                struct_name = die.attributes['DW_AT_name'].value
            except:
                struct_name = '<unknown>'
            typedict['base_name'] = 'struct ' + struct_name

        elif die.tag == 'DW_TAG_union_type':
            union_name = '<unknown>'
            try:
                union_name = die.attributes['DW_AT_name'].value
            except:
                union_name = '<unknown>'
            typedict['base_name'] = 'union ' + union_name

        elif die.tag == 'DW_TAG_enumeration_type':
            try:
                enum_name = die.attributes['DW_AT_name'].value
            except:
                enum_name = '<unknown>'
            typedict['base_name'] = 'enum ' + enum_name

        elif die.tag == 'DW_TAG_subroutine_type':
            typedict['func_ptr'] = True

        elif die.tag == 'DW_TAG_array_type':
            # raise Exception('Should not find any array types')
            # typedefs may lead to array types as arguments in function signatures
            # in practice, they are pointers
            typedict['pointer_level'] += 1
            get_type_recursive(diedict[die.cu.cu_offset][die.attributes['DW_AT_type'].value],
                               diedict, typedict)

        else:
            try:
                subtype = die.attributes['DW_AT_type'].value
            except:
                subtype = None
            if subtype is not None:
                get_type_recursive(diedict[die.cu.cu_offset][subtype],
                                   diedict, typedict)
            else:
                # We have a void* in our hands =)
                typedict['base_name'] = 'void'

    get_type_recursive(die, diedict, typedict)

    if (typedict['func_ptr']):
        return 'func_ptr'
    else:
        return typedict['base_name'] + '*'*typedict['pointer_level']


def get_subprogram(die, diedict, disassemble):
    """
    'diedict' is a mapping obtained with 'get_offset2DIE'.

    Returns a subprogram dict, or None if the subprogram is external (meaning
    its code is not present, hence we cannot know much about it)
    """

    if 'DW_AT_abstract_origin' not in die.attributes and 'DW_AT_low_pc' not in die.attributes:
        # print(die)
        return None

    def get_boundaries(subroutine_die):
        lowpc = subroutine_die.attributes['DW_AT_low_pc'].value
        # high_pc may either be relative or absolute
        if subroutine_die.attributes['DW_AT_high_pc'].form[:12] == 'DW_FORM_data':
            highpc = lowpc + \
                subroutine_die.attributes['DW_AT_high_pc'].value - 1
        else:
            highpc = subroutine_die.attributes['DW_AT_high_pc'].value - 1
        subroutine['boundaries'] = (lowpc, highpc)

        subroutine['inst_strings'] = []
        subroutine['inst_bytes'] = []
        # TODO: this is too inefficient
        for inst in disassemble:
            if inst.address >= lowpc and inst.address <= highpc:
                subroutine['inst_strings'].append(
                    inst.mnemonic + ' ' + inst.op_str)
                subroutine['inst_bytes'].append(inst.bytes)

    def get_arguments(subroutine_die):
        for parameter_die in subroutine_die.iter_children():
            if parameter_die.tag == 'DW_TAG_formal_parameter':
                subroutine['num_args'] += 1
                subroutine['args_type'].append(
                    get_type(parameter_die, diedict))

    subroutine = {}
    subroutine['num_args'] = 0
    subroutine['args_type'] = []

    if 'DW_AT_abstract_origin' in die.attributes:
        origin = diedict[die.cu.cu_offset][die.attributes['DW_AT_abstract_origin'].value]
        if 'DW_AT_inline' in origin.attributes and origin.attributes['DW_AT_inline'].value == 1:
            return None
        subroutine['name'] = origin.attributes['DW_AT_name'].value
        try:
            subroutine['ret_type'] = get_type(
                diedict[origin.cu.cu_offset][origin.attributes['DW_AT_type'].value], diedict)
        except:
            subroutine['ret_type'] = 'void'
        get_boundaries(die)
        get_arguments(origin)
    else:
        subroutine['name'] = die.attributes['DW_AT_name'].value
        try:
            subroutine['ret_type'] = get_type(
                diedict[die.cu.cu_offset][die.attributes['DW_AT_type'].value], diedict)
        except:
            subroutine['ret_type'] = 'void'
        get_boundaries(die)
        get_arguments(die)

    return subroutine


def get_function_calls_eklavya_format(file_name):
    """
    Returns a dict function_name -> callers

    in which 'callers' is an array of dicts with the form
    {
        "caller": string,
        "call_isntr_indices": array of integers
    }
    """
    call_locations = get_func_call_locations(file_name)
    subprograms = get_all_subprograms_eklavya_format(file_name)

    # auxiliary array. contains boundaries in ascending order
    subprogram_ranges = [{
        'boundaries': subprograms[name]['boundaries'],
        'name': name
    } for name in subprograms.keys()]
    subprogram_ranges.sort(
        lambda x, y: x['boundaries'][0] - y['boundaries'][0])

    # variable to be returned
    result = {}

    # filter out call locations which are not inside
    # any regular function (those that, for example, are inside _start function)
    tmp_call_locations = []
    for call in call_locations:
        caller = [subp for subp in subprogram_ranges if call['call_address']
                  >= subp['boundaries'][0] and call['call_address'] <= subp['boundaries'][1]]
        if len(caller) == 0:
            continue
        elif len(caller) > 1:
            raise Exception('It seems functions overlap')
        tmp_call_locations.append(call)
    call_locations = tmp_call_locations

    if len(call_locations) == 0:
        return result

    call_location_index = 0
    for caller in subprogram_ranges:
        appended = {}
        call_location = call_locations[call_location_index]
        while caller['boundaries'][0] <= call_location['call_address'] <= caller['boundaries'][1]:
            try:
                callers_array = result[call_location['function_name']]
            except:
                callers_array = result[call_location['function_name']] = []
            if call_location['function_name'] not in appended:
                appended[call_location['function_name']] = True
                callers_array.append({
                    'caller': caller['name'],
                    'call_instr_indices': []
                })
            # Find instruction index
            raw_inst_bytes = subprograms[caller['name']]['inst_bytes']
            curr_address = caller['boundaries'][0]
            index = 0
            while curr_address != call_location['call_address']:
                curr_address += len(raw_inst_bytes[index])
                index += 1
            callers_array[-1]['call_instr_indices'].append(index)
            call_location_index += 1
            if call_location_index == len(call_locations):
                break
            call_location = call_locations[call_location_index]
        if call_location_index == len(call_locations):
            break

    return result


def get_text_disassemble(elffile):
    code = elffile.get_section_by_name('.text')
    ops = code.data()
    addr = code['sh_addr']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return [i for i in md.disasm(ops, addr)]


def test_details():
    elffile = get_ELFFile('a.out')
    code = elffile.get_section_by_name('.text')
    ops = code.data()
    addr = code['sh_addr']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(ops, addr):
        print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        print(map(lambda x: to_x(int(x)), insn.bytes))
        imm_count = insn.op_count(X86_OP_IMM)
        if imm_count == 0:
            continue
        bytes_no_imm = []
        # Inclusive 'start' and 'end' indexes
        imm_start = insn.imm_offset
        imm_end = imm_start + insn.imm_size + 1
        for i in range(len(insn.bytes)):
            if imm_start <= i <= imm_end:
                continue
            bytes_no_imm.append(insn.bytes[i])
        print(map(lambda x: to_x(int(x)), bytes_no_imm))


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == '--debug':
            for filename in sys.argv[2:]:
                print_debug(filename)
        elif sys.argv[1] == '--objdump':
            for filename in sys.argv[2:]:
                get_func_call_locations(filename)
        elif sys.argv[1] == '--functioncalls':
            for filename in sys.argv[2:]:
                print(get_function_calls_eklavya_format(filename))
        elif sys.argv[1] == '--allsubprograms':
            for filename in sys.argv[2:]:
                print(get_all_subprograms_eklavya_format(filename))
        elif sys.argv[1] == '--compare-eklavya':
            if len(sys.argv) < 3:
                print(
                    'usage: python main.py --compare-eklavya /path/to/x64-pickles-dir-or-file')
                sys.exit(1)
            pickle_path = sys.argv[2]
            if path.isdir(pickle_path):
                pickle_list = [path.join(pickle_path, pickle_file)
                               for pickle_file in os.listdir(pickle_path)]
            else:
                pickle_list = [pickle_path]
            for pickle_file in pickle_list:
                file = open(pickle_file)
                eklavya_version = pickle.load(file)
                tmp_binary_path = '/tmp/tmp-binary-for-eklavya-conversion-test'
                tmp_binary = open(tmp_binary_path, 'wb')
                tmp_binary.write(eklavya_version['bin_raw_bytes'])
                tmp_binary.close()
                print('Processing ' + pickle_file + ':')
                try:
                    our_version = get_all_subprograms_eklavya_format(
                        tmp_binary_path)
                except Exception as err:
                    print('')
                    print('error when processing ' + pickle_file + ':')
                    print(err)
                    traceback.print_exc()
                    print('')
                    continue
                our_excess = [
                    func for func in our_version if func not in eklavya_version['functions']]
                print('Our excess count is ' +
                      str(len(our_excess)) + '. They are: ')
                print(sorted(our_excess))
                eklavya_excess = [
                    func for func in eklavya_version['functions'] if func not in our_version]
                print('Eklavya excess count is ' +
                      str(len(eklavya_excess)) + '. They are:')
                print(sorted(eklavya_excess))
        # eklavya version is not safe, but ours is:
        # concretely, this means we skip calls if the caller is not in our list of function bodies
        elif sys.argv[1] == '--gen-split-func':
            if len(sys.argv) < 4:
                print(
                    'usage: python main.py --gen-split-func /path/to/x86-or-x64-pickles-dir /path/where/put/output.pkl')
                sys.exit(1)
            pickle_path = sys.argv[2]
            output_path = sys.argv[3]
            output_file = open(output_path, 'wb')
            # According to eklavya paper, will be 80% train and 20% test
            output_obj = {
                'train': [],
                'test': []
            }
            pickle_list = [path.join(pickle_path, pickle_file)
                           for pickle_file in os.listdir(pickle_path)]
            for pickle_file in pickle_list:
                eklavya_obj = pickle.load(open(pickle_file))
                for callee_name in eklavya_obj['function_calls']:
                    callers = eklavya_obj['function_calls'][callee_name]
                    for caller_obj in callers:
                        caller_name = caller_obj['caller']
                        caller_indices = caller_obj['call_instr_indices']
                        if caller_name not in eklavya_obj['functions']:
                            continue
                        for caller_index in caller_indices:
                            call_hash = '#'.join(
                                [path.basename(pickle_file), callee_name, caller_name, str(caller_index)])
                            if random.randint(1, 100) <= 80:
                                output_obj['train'].append(call_hash)
                            else:
                                output_obj['test'].append(call_hash)

            pickle.dump(output_obj, output_file)
            output_file.close()
        elif sys.argv[1] == '--clean-pickles':
            if len(sys.argv) < 4:
                print(
                    'usage: python main.py --clean-pickles /path/to/x86-or-x64-pickles-dir /dirpath/where/put/clean_pickles/'
                )
                sys.exit(1)
            unclean_pickles_dir = sys.argv[2]
            output_dir = sys.argv[3]
            picklepath_list = [path.join(unclean_pickles_dir, pickle_file)
                               for pickle_file in os.listdir(unclean_pickles_dir)]
            pickleobj_list = [pickle.load(open(picklepath))
                              for picklepath in picklepath_list]
            function_name_cache = {}
            clean_pickleobj_list = []
            names = {}
            for pickleobj in pickleobj_list:
                duplicate = []
                for function_name in pickleobj['functions'].keys():
                    # duplicate !
                    if function_name_cache.has_key(function_name):
                        duplicate.append(function_name)
                        pickleobj['functions'].pop(function_name)
                        function_name_cache[function_name] += 1
                    else:
                        function_name_cache[function_name] = 1
                basename = os.path.basename(pickleobj['binary_filename'])
                if basename in names:
                    names[basename] += 1
                    basename = basename + '(' + str(names[basename]) + ')'
                else:
                    names[basename] = 0
                outpath = os.path.join(output_dir, basename)
                out = open(outpath, 'w')
                pickle.dump(pickleobj, out)
                out.close()
            print('Report: How many times each function name appears in all binaries taken together')
            for key in function_name_cache:
                print(key + ': ' + str(function_name_cache[key]))
    # processing of cpython. paths hardcoded
    else:
        tmp_path = '/tmp/eklavya-format-conversion-O2'
        if path.exists(tmp_path):
            subprocess.call(['rm', '-r', tmp_path])
        os.mkdir(tmp_path)
        result = []
        # test_details()
        o_files = [filename for filename in subprocess.check_output(
            ['find', '../cpython', '-name', '*.o']).split('\n') if filename != '']
        print('About to process ' + str(len(o_files)) + ' files')
        for filename in o_files:
            file_merged_text_sections = path.join(
                tmp_path, path.basename(filename))
            subprocess.call(['ld', '-r', '-o', file_merged_text_sections,
                             filename, '-T', './default_linker_script'])
        for filename in o_files:
            file_merged_text_sections = path.join(
                tmp_path, path.basename(filename))
            print('Processing ' + filename)
            bin_info = {
                'functions': get_all_subprograms_eklavya_format(file_merged_text_sections),
                'structures': None,
                'text_addr': None,
                'binRawBytes': None,
                'arch': 'x64',
                'binary_filename': filename,
                'function_calls': get_function_calls_eklavya_format(file_merged_text_sections)
            }
            result.append(bin_info)
            print(bin_info['functions'].keys())
        output_path = path.join(tmp_path, 'cpython-eklavya-format-dataset.pkl')
        output_file = open(output_path, 'w')
        pickle.dump(result, output_file)
        output_file.close()
