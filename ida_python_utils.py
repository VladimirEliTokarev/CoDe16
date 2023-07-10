import idautils
import math
import ida_bytes


def restring(start_addr, end_addr):
    curr_addr = start_addr
    print("started renaming strings.")
    while curr_addr < end_addr:
        ida_bytes.create_strlit(curr_addr, 0, ida_nalt.STRTYPE_TERMCHR)
        curr_addr += 4

    print("Finshed restring.")


def smart_restring(start_addr, end_addr, min_str_len=3):
    curr_addr = start_addr
    print("started smart renaming strings.")
    while curr_addr < end_addr:

        potential_len = ida_bytes.get_max_strlit_length(curr_addr, 0)
        if potential_len > min_str_len:
            ida_bytes.create_strlit(curr_addr, 0, ida_nalt.STRTYPE_TERMCHR)

        curr_addr += 1

    print("Finished smart renaimng strings")


def redefine_methods(start_addr, end_addr):
    curr_addr = start_addr
    print("started redefine methods.")
    while curr_addr < end_addr:
        if idc.get_func_name(curr_addr) == '':
            idc.add_func(curr_addr)

        curr_addr += 4

    print("Finshed redefine methods.")


def redefine_references(start_addr, end_addr):
    curr_addr = start_addr
    print("started redefine references.")
    while curr_addr < end_addr:
        ida_offset.op_offset(curr_addr, 0, idc.REF_OFF32)
        ida_offset.op_offset(curr_addr, 1, idc.REF_OFF32)
        ida_offset.op_offset(curr_addr, 2, idc.REF_OFF32)
        curr_addr += 4

    print("Finshed redefine references.")


def rename_methods_based_on_ref_table_v1(start_addr, end_addr):
    curr_addr = start_addr
    next_addr = curr_addr + 4
    while next_addr < end_addr:
        curr_addr_content = idc.Dword(curr_addr)
        curr_addr_string = idc.GetString(curr_addr_content + 2)  # NOTE: the +2 is for current firmware

        if curr_addr_string is None or curr_addr_string == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = idc.Dword(next_addr)
        next_addr_method_name = idc.GetFunctionName(next_addr_content)

        if next_addr_method_name is None or next_addr_method_name == '' or not next_addr_method_name.startswith("sub_"):
            curr_addr += 4
            next_addr += 4
            continue
        print("Renaming {src}->{dst} ".format(src=next_addr_method_name, dst=curr_addr_string))
        idc.MakeNameEx(next_addr_content, curr_addr_string, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


def rename_methods_based_on_ref_table_v2(start_addr, end_addr):
    curr_addr = start_addr
    next_addr = curr_addr + 4
    while next_addr < end_addr:
        curr_addr_content = ida_bytes.get_dword(curr_addr)
        print(curr_addr_content)
        curr_addr_string = str(ida_bytes.get_strlit_contents(curr_addr_content, -1,
                                                             STRTYPE_TERMCHR))  # NOTE: the +2 is for current firmware

        if curr_addr_string is None or curr_addr_string == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = ida_bytes.get_dword(next_addr)
        next_addr_method_name = idc.get_func_name(next_addr_content)

        if next_addr_method_name is None or next_addr_method_name == '' or not next_addr_method_name.startswith("sub_"):
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=next_addr_method_name, dst=curr_addr_string))
        idc.set_name(next_addr_content, curr_addr_string, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


def rename_methods_based_on_ref_table_v2_for_boabb(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should yuse get_func_name instead of the string one
    :param start_addr:
    :param end_addr:
    :return:
    """
    curr_addr = start_addr
    next_addr = curr_addr
    next_addr = next_addr + 4
    while next_addr < end_addr:

        curr_addr_content = ida_bytes.get_dword(curr_addr) - 1
        old_name = idc.get_func_name(curr_addr_content)  # NOTE: the +2 is for current firmware

        if old_name is None or old_name == '' or not old_name.startswith("sub"):
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = ida_bytes.get_dword(next_addr)
        new_name = str(ida_bytes.get_strlit_contents(next_addr_content, -1, STRTYPE_TERMCHR))

        if new_name is None or ' ' in new_name or new_name == b'U':
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        idc.set_name(curr_addr_content, new_name, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


# references

def rename_methods_by_references(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should use get_func_name instead of the string one
    NOTE: Tis good for 32 systems for 64 we should change get_dword to get_qword
    """
    current_address = start_addr
    next_address = current_address + 4

    while next_address < end_addr:

        current_address_content = ida_bytes.get_dword(current_address)
        new_name = ida_bytes.get_strlit_contents(current_address_content, -1, STRTYPE_TERMCHR)

        if new_name is None or new_name == '':
            current_address += 4
            next_address += 4
            continue

        next_address_content = ida_bytes.get_dword(next_address)
        old_name = idc.get_func_name(next_address_content)

        if old_name is not None and type(old_name) is not str:
            old_name = old_name.decode('ascii')

        if new_name is not None and type(new_name) is not str:
            new_name = new_name.decode('ascii')

        if old_name is None or ' ' in old_name:
            current_address += 4
            next_address += 4
            continue

        print(hex(current_address_content), new_name, old_name)

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        idc.set_name(next_address_content, str(new_name), 0x800)  # 0x800 SN_FORCE

        current_address += 4
        next_address += 4

def rename_methods_based_on_ref_for_old_boabb(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should yuse get_func_name instead of the string one
    :param start_addr:
    :param end_addr:
    :return:
    """
    curr_addr = start_addr
    next_addr = curr_addr
    next_addr = next_addr + 4
    while next_addr < end_addr:

        curr_addr_content = idc.Dword(curr_addr)
        old_name = ida_funcs.get_func_name(curr_addr_content)  # NOTE: the +2 is for current firmware

        if old_name is None or old_name == '' or not old_name.startswith("sub"):
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = idc.Dword(next_addr)
        new_name = idc.GetString(next_addr_content)

        if new_name is None:
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        idc.MakeNameEx(curr_addr_content, new_name, idc.SN_NOWARN)

        curr_addr += 8
        next_addr += 8


def rename_methods_based_on_ref_for_codesys_emulator(start_addr, end_addr):
    """
    NOTE: in case of number of segments you should yuse get_func_name instead of the string one
    NOTE: this is for x64 for x32 do + 4
    :param start_addr:
    :param end_addr:
    :return:
    """
    print("started renaming")
    curr_addr = start_addr
    next_addr = curr_addr
    next_addr = next_addr + 4
    while next_addr < end_addr:

        curr_addr_content = idc.get_wide_dword(curr_addr)
        old_name = str(ida_funcs.get_func_name(curr_addr_content))

        if old_name is None or old_name == '':
            curr_addr += 4
            next_addr += 4
            continue

        next_addr_content = idc.get_qword(next_addr)
        new_name = idc.get_strlit_contents(next_addr_content, -1, STRTYPE_TERMCHR)

        if new_name is None:
            curr_addr += 4
            next_addr += 4
            continue

        new_name = new_name.decode('ascii')

        if len(new_name) < 3:
            curr_addr += 4
            next_addr += 4
            continue

        print("Renaming {src}->{dst} ".format(src=old_name, dst=new_name))
        ret = idc.set_name(curr_addr_content, new_name, idc.SN_NOWARN)

        curr_addr += 4
        next_addr += 4


def find_setting_r1_to_10001(addr):
    """
    The ides is to find when we make
    mov R0, first_arg
    mov R1, second_arg
    branch addr
    :param addr:
    :param arg: the argument we are looking for
    :param register_id: 0x0 for R0 0x10 for R1 0x20 for R2
    :return:
    """
    print("__________________________________________________________________________")
    for xref in idautils.XrefsTo(addr):
        # print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        tar_addr = xref.frm
        target_prev = [0x01, 0x0, 0xa0, 0xe3]
        target_current = [0x01, 0x0, 0x40, 0xe3]
        for i in range(5):
            current_opcode = idc.GetManyBytes(PrevHead(tar_addr), ItemSize(PrevHead(tar_addr)))
            current_opcode_array = [int(ord(i)) for i in current_opcode]

            prev_tar_addr = PrevHead(tar_addr)
            prev_opcode = idc.GetManyBytes(PrevHead(prev_tar_addr), ItemSize(PrevHead(prev_tar_addr)))
            prev_opcode_array = [int(ord(i)) for i in prev_opcode]
            if prev_opcode_array[len(prev_opcode_array) - 1] == 0xe3 and prev_opcode_array[0] == 0x1:
                print(hex(prev_tar_addr), prev_opcode_array)
            if prev_opcode_array == target_prev and target_current == current_opcode_array:
                print(hex(tar_addr))

            tar_addr = prev_tar_addr


def find_all_refs(addr, arg_val=None, operand=0xE3):
    """
    Searches for x ref to given function address
    then for each xref gets last five opcodes
    and searches for 0x21 opcode which is the setting of R1
    checking the value if its 0x22
    then print the location
    :param addr:
    :return:
    """
    map = {}
    for xref in idautils.XrefsTo(addr):
        # print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
        tar_addr = xref.frm

        for i in range(5):
            opcode = idc.GetManyBytes(PrevHead(tar_addr), ItemSize(PrevHead(tar_addr)))
            array_opcode = [int(ord(i)) for i in opcode]
            if array_opcode[len(array_opcode) - 1] == operand:  # LDR = 0xE5,mov = 0xE3
                if arg_val is None:
                    map[tar_addr] = array_opcode
                else:
                    if array_opcode[0] == arg_val:
                        map[tar_addr] = array_opcode
            tar_addr = PrevHead(tar_addr)

        # args = idaapi.get_arg_addrs(xref.frm)
        # print(xref.frm, args)

    return map


def find_flow_of_commands(first_command_address, first_command_operand, first_command_arg, second_command_address,
                          second_command_operand, second_command_arg):
    first_command_map = find_all_refs(first_command_address, first_command_arg, first_command_operand)
    second_command_map = find_all_refs(second_command_address, second_command_arg, second_command_operand)

    for first_address, first_opcode in first_command_map.items():
        for second_address, second_opcode in second_command_map.items():
            if abs(first_address - second_address) <= 0x10:
                print("Found Match: " + hex(first_address) + " " + hex(second_address))


def rename_based_on_string_n_bytes_from_method_start(addr):
    for xref in idautils.XrefsTo(addr):
        tar_addr = xref.frm
        ioctl_num = None
        ioctl_name = None
        for i in range(30):
            # opcode = idc.GetManyBytes(PrevHead(tar_addr), ItemSize(PrevHead(tar_addr)))
            # print(GetDisasm(tar_addr))
            instruction = GetDisasm(tar_addr)
            if "push    offset aVhfioct" in instruction:
                parts = instruction.split("(")
                ioctl_name_plus_parts = parts[1]
                ioctl_name = ioctl_name_plus_parts.replace("\\n", "")
                ioctl_name = ioctl_name.replace(")", "")
                parts = ioctl_name.split(" ")
                ioctl_name = parts[0].replace("\"", "")
                # print("The ioctl name is: ", ioctl_name)

            if "push    0E000" in instruction:
                parts = instruction.split("    ")
                ioctl_num = parts[1].replace("h", "")
                ioctl_num = int(ioctl_num, 16)
                ioctl_num = str(hex(ioctl_num)).upper()
                # print("The ioctl num is: ", ioctl_num)

            tar_addr = PrevHead(tar_addr)

        if ioctl_num is not None and ioctl_name is not None:
            new_method_name = "ioctl_" + ioctl_num + "_aka_" + ioctl_name
            current_method_address = get_name_ea_simple(GetFunctionName(tar_addr))
            if GetFunctionName(tar_addr) is not None and new_method_name is not None:
                print("Rename " + GetFunctionName(tar_addr) + " -> " + new_method_name)
                idc.MakeNameEx(current_method_address, new_method_name, idc.SN_NOWARN)


def patch_bytes(start_addr, end_addr):
    """
    Replaces 0xD,0xA with with 00

    """
    curr_addr = start_addr
    while curr_addr < end_addr:
        if idc.get_bytes(curr_addr, 2, False) == bytes([0xd, 0xa]):
            idc.patch_byte(curr_addr, 0x0)
            idc.patch_byte(curr_addr + 1, 0x0)
            # ida_bytes.create_strlit(curr_addr, 0, ida_nalt.STRTYPE_TERMCHR)
        curr_addr += 1


def rename_if_name_contains(start_addr, end_addr):
    curr_addr = start_addr
    while curr_addr < end_addr:
        curr_addr += 1


def create_sturct_with_fields(struct_name, amount_of_qdwords):
    id = add_struc(-1, struct_name, 0)
    for i in range(amount_of_qdwords):
        print("added field field_%x" % i + " to struct " + struct_name)
        add_struc_member(id, "field_%x" % i, i, FF_DATA | FF_QWORD, -1, 8)
    print("Finished adding structs")


def rename_based_on_inheritance_strings():
    """
    For instance convert ipnet_nat_proxy_dns_parse_questions() :: could not add transaction to list
    """
    import idautils
    sc = idautils.Strings()
    for s in sc:
        if "::" in str(s):
            prev_address = s.ea - 4
            ref_to_prev_address = get_first_dref_to(prev_address)
            old_method_name = ida_funcs.get_func_name(ref_to_prev_address)

            if old_method_name is None:
                prev_address = s.ea - 8
                ref_to_prev_address = get_first_dref_to(prev_address)
                old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
                if old_method_name is None:
                    continue

            parts = str(s).split("::")
            relevant_part = parts[0]
            new_method_name = relevant_part.replace("(", "").replace(")", "")

            if "%" in new_method_name:
                new_method_name = new_method_name.split("%")[0]
            if "~" in new_method_name:
                new_method_name = new_method_name.replace("~", "")
            if ":" in new_method_name:
                new_method_name = new_method_name.replace(":", "")

            if new_method_name is not None and old_method_name is not None and old_method_name.startswith("sub_"):
                old_method_address = get_name_ea(0, old_method_name)
                if old_method_address is not None:
                    print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
                    idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)


def is_camel_case(s):
    return s != s.lower() and s != s.upper() and "_" not in s


def get_all_camel_case_words_in_image():
    """
    So the idea is that lets say we have a log that looks like
    ClassA::SendData() failed with error code %d ....
    and we have ref for this location we want to rename all the relevant methods
    with those names
    """
    print("SEarching for all camel case worlds")
    import idautils
    sc = idautils.Strings()
    for s in sc:
        parts = str(s).split(" ")
        if 2 < len(parts) and is_camel_case(parts[0]) and parts[1] == "not":
            print(parts[0])


def rename_based_on_logs():
    """
    The idea is to rename methods that got strings that looks like:
    'ProcessEventRequestState(Device:%d) action %p max pending actions'
    or
    'ServerInit: invalid parameter'
    """
    import idautils
    sc = idautils.Strings()
    new_method_name = None
    for s in sc:
        s_as_str = str(s)
        prev_address = s.ea
        ref_to_prev_address = get_first_dref_to(prev_address)
        old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
        old_method_address = get_name_ea(0, old_method_name)

        if "(" in s_as_str and ":" in s_as_str and s_as_str.find("c") < s_as_str.find(":"):
            # 'ProcessEventRequestState(Device:%d) action %p max pending actions' case
            parts = s_as_str.split(" ")
            name_with_extra_data = parts[0]
            name_parts = name_with_extra_data.split("(")
            parts[0] = parts[0].replace(":", "")
            new_method_name = name_parts[0] if len(name_parts[0]) > 4 else None

        elif ":" in s_as_str:
            # 'BACnetServerInit: invalid parameter' case
            parts = s_as_str.split(":")
            parts[0] = parts[0].replace(":", "")
            name_parts = parts[0].split(" ")

            if len(name_parts) > 1:
                continue
            new_method_name = parts[0] if len(parts[0]) > 4 else None

            if new_method_name is not None and new_method_name.startswith(" "):
                continue

        if new_method_name is not None and old_method_name is not None and old_method_name.startswith("sub_"):
            print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
            ret_code = idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)

        new_method_name = None


def rename_based_on_particular_suffix(suffix_to_renamed_based_on, prefix):
    import idautils
    sc = idautils.Strings()

    for s in sc:
        s_as_str = str(s)
        prev_address = s.ea
        ref_to_prev_address = get_first_dref_to(prev_address)
        old_method_name = ida_funcs.get_func_name(ref_to_prev_address)
        old_method_address = get_name_ea(0, old_method_name)

        if s_as_str.endswith(suffix_to_renamed_based_on) and old_method_name.startswith("sub"):
            s_as_str = s_as_str.replace(" ", "")
            new_method_name = "{prefix}{name}".format(prefix=prefix, name=s_as_str)
            print("Renaming {src}->{dst} ".format(src=old_method_name, dst=new_method_name))
            ret_code = idc.set_name(old_method_address, new_method_name, idc.SN_NOWARN)
            print("returned", ret_code)


def rename_based_on_bindiff_matched_functions(matched_functions_txt, min_similarity_level=0):
    """
    Long time i wanted the ability to rename based on bindiff matched functions !
    so lets begin
    rules:
    1. we rename functions from first file using the names in second file
    1. rename on iff the name in first file starts with sub_
    2. rename only iff the name in the second file doesnt starts with sub_
    3. rename only iff similar at least as min_similarity_level
    """
    raw_matched_functions = None
    with open(matched_functions_txt, "r") as matched_functions_file:
        raw_matched_functions = matched_functions_file.read().split("\n")

    for matched_function_str in raw_matched_functions:
        matched_functions_parts = matched_function_str.split("\t")
        similarity_percent = float(matched_functions_parts[0])
        this_file_name = matched_functions_parts[4]
        other_file_name = matched_functions_parts[6]

        if similarity_percent < min_similarity_level:
            continue

        if not this_file_name.startswith("sub_"):
            continue

        if other_file_name.startswith("sub_"):
            continue

        print("Renaming {src}->{dst} ".format(src=this_file_name, dst=other_file_name))
        old_method_address = get_name_ea_simple(this_file_name)
        print(type(other_file_name), hex(old_method_address), hex(get_name_ea_simple(this_file_name)))
        ret_code = idc.set_name(old_method_address, other_file_name, 0x800)
        print(ret_code)


def find_all_isntructions():
    print("_____________________________________JustDoIt____________________________________________")
    data = ""
    for function_ea in idautils.Functions():
        instructions = []

        for ins in idautils.FuncItems(function_ea):
            if idaapi.is_code(idaapi.get_full_flags(ins)):
                cmd = idc.GetDisasm(ins)
                instructions.append([cmd, ins])

        for i in range(len(instructions) - 5):
            print(instructions)
            if "BLX" in instructions[i + 4][0]:
                # ("R12" in instructions[i + 4][0] or \
                #  "R11" in instructions[i + 4][0] or  \
                #  "SP" in instructions[i + 4][0] or \
                #  "R4" in instructions[i + 4][0] or \
                #  "R5" in instructions[i + 4][0] or \
                #  "R6" in instructions[i + 4][0] or \
                #  "R1" in instructions[i + 4][0] or \
                #  "R2" in instructions[i + 4][0] or \):

                data += str(hex(instructions[i][1])) + \
                        "-> [" + "\n" + \
                        instructions[i][0] + "\n" + \
                        instructions[i + 1][0] + "\n" + \
                        instructions[i + 2][0] + "\n" + \
                        instructions[i + 3][0] + "\n" + \
                        instructions[i + 4][0] + "\n"

    with open(r"GadgetsWithBLX.txt", "w") as f:
        f.write(data)
